use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const LENGTH_PREFIX_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    X32dbg,
    X64dbg,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handshake {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub backend: BackendType,
    pub plugin_pid: u32,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeAck {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub accepted: bool,
    pub error_code: Option<String>,
    pub instance_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcRequest {
    pub request_id: Uuid,
    pub deadline_unix_ms: u64,
    pub operation_id: Option<Uuid>,
    pub method: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpcResponse {
    pub request_id: Uuid,
    pub state_generation: u64,
    #[serde(flatten)]
    pub outcome: IpcOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IpcOutcome {
    Ok { result: Value },
    Error { error: IpcErrorBody },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcErrorBody {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub details: Value,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame is missing its 4-byte length prefix")]
    MissingLengthPrefix,
    #[error("frame payload is empty")]
    EmptyPayload,
    #[error("frame payload exceeds the 1 MiB hard limit")]
    Oversized,
    #[error("frame length prefix does not match the available payload")]
    LengthMismatch,
    #[error("frame payload is not valid protocol JSON")]
    InvalidPayload,
    #[error("frame I/O failed: {0:?}")]
    Io(std::io::ErrorKind),
}

/// Serializes one protocol message with a little-endian bounded length prefix.
///
/// # Errors
///
/// Returns [`FrameError`] if serialization fails or the payload is empty or larger
/// than [`MAX_FRAME_BYTES`].
pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(message).map_err(|_| FrameError::InvalidPayload)?;
    if payload.is_empty() {
        return Err(FrameError::EmptyPayload);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::Oversized)?;
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes exactly one complete length-prefixed protocol message.
///
/// # Errors
///
/// Returns [`FrameError`] for missing, empty, oversized, truncated, trailing, or
/// invalid payloads. The decoder never scans ahead to resynchronize.
pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    let prefix_bytes = frame
        .get(..LENGTH_PREFIX_BYTES)
        .ok_or(FrameError::MissingLengthPrefix)?;
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    prefix.copy_from_slice(prefix_bytes);
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 {
        return Err(FrameError::EmptyPayload);
    }
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized);
    }
    let payload = frame
        .get(LENGTH_PREFIX_BYTES..)
        .ok_or(FrameError::LengthMismatch)?;
    if payload.len() != length {
        return Err(FrameError::LengthMismatch);
    }
    serde_json::from_slice(payload).map_err(|_| FrameError::InvalidPayload)
}

/// Writes exactly one bounded frame to an asynchronous byte stream.
///
/// # Errors
///
/// Returns [`FrameError`] if serialization, bounds validation, or stream I/O fails.
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + Sync,
{
    let frame = encode_frame(message)?;
    writer
        .write_all(&frame)
        .await
        .map_err(|error| FrameError::Io(error.kind()))
}

/// Reads exactly one bounded frame from an asynchronous byte stream.
///
/// The length is checked before allocating the payload buffer.
///
/// # Errors
///
/// Returns [`FrameError`] for stream I/O, invalid lengths, or invalid payloads.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    reader
        .read_exact(&mut prefix)
        .await
        .map_err(|error| FrameError::Io(error.kind()))?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 {
        return Err(FrameError::EmptyPayload);
    }
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized);
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| FrameError::Io(error.kind()))?;
    serde_json::from_slice(&payload).map_err(|_| FrameError::InvalidPayload)
}

/// Verifies the negotiated version, launch nonce, and plugin process identity.
///
/// # Errors
///
/// Returns a stable IPC error code when the major/minor version is unsupported,
/// authentication fails, or the plugin PID is invalid.
pub fn validate_handshake(handshake: &Handshake, expected_nonce: &str) -> Result<(), &'static str> {
    if handshake.protocol_major != PROTOCOL_MAJOR {
        return Err("VERSION_MISMATCH");
    }
    if handshake.protocol_minor > PROTOCOL_MINOR {
        return Err("VERSION_MISMATCH");
    }
    let nonce_matches = handshake.nonce.len() == expected_nonce.len()
        && handshake
            .nonce
            .as_bytes()
            .ct_eq(expected_nonce.as_bytes())
            .into();
    if handshake.nonce.len() < 32 || !nonce_matches {
        return Err("ACCESS_DENIED");
    }
    if handshake.plugin_pid == 0 {
        return Err("INVALID_ARGUMENT");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn handshake() -> Handshake {
        Handshake {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            backend: BackendType::X64dbg,
            plugin_pid: 4242,
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        }
    }

    fn next_u64(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    #[test]
    fn frame_round_trip_is_exact() {
        let message = handshake();
        let frame = encode_frame(&message).unwrap();
        assert_eq!(
            u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        assert_eq!(decode_frame::<Handshake>(&frame).unwrap(), message);
    }

    #[test]
    fn rejects_truncated_and_trailing_frames() {
        let frame = encode_frame(&handshake()).unwrap();
        assert_eq!(
            decode_frame::<Handshake>(&frame[..frame.len() - 1]),
            Err(FrameError::LengthMismatch)
        );
        let mut trailing = frame;
        trailing.push(0);
        assert_eq!(
            decode_frame::<Handshake>(&trailing),
            Err(FrameError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_empty_oversized_and_invalid_payloads() {
        assert_eq!(
            decode_frame::<Handshake>(&0_u32.to_le_bytes()),
            Err(FrameError::EmptyPayload)
        );
        assert_eq!(
            decode_frame::<Handshake>(&(u32::try_from(MAX_FRAME_BYTES).unwrap() + 1).to_le_bytes(),),
            Err(FrameError::Oversized)
        );
        assert_eq!(
            decode_frame::<Handshake>(&[1, 0, 0, 0, b'{']),
            Err(FrameError::InvalidPayload)
        );
    }

    #[test]
    fn deterministic_malformed_frame_corpus_stays_bounded_and_canonical() {
        const SEED: u64 = 0x5844_4247_4950_4331;
        const CASES: usize = 4_096;
        const MAX_CORPUS_BYTES: usize = 4_096;
        let mut state = SEED;
        for case in 0..CASES {
            let modulus = u64::try_from(MAX_CORPUS_BYTES + 1).unwrap();
            let length = usize::try_from(next_u64(&mut state) % modulus).unwrap();
            let mut frame = vec![0_u8; length];
            for byte in &mut frame {
                *byte = u8::try_from(next_u64(&mut state) & 0xff).unwrap();
            }
            if frame.len() >= LENGTH_PREFIX_BYTES {
                let available = frame.len() - LENGTH_PREFIX_BYTES;
                let declared = match case % 6 {
                    0 => available,
                    1 => available.saturating_add(1),
                    2 => available.saturating_sub(1),
                    3 => 0,
                    4 => MAX_FRAME_BYTES + 1,
                    _ => usize::try_from(
                        u32::try_from(next_u64(&mut state) & u64::from(u32::MAX)).unwrap(),
                    )
                    .unwrap(),
                };
                let declared = u32::try_from(declared).unwrap_or(u32::MAX);
                frame[..LENGTH_PREFIX_BYTES].copy_from_slice(&declared.to_le_bytes());
            }
            if let Ok(value) = decode_frame::<Value>(&frame) {
                let canonical = encode_frame(&value)
                    .unwrap_or_else(|error| panic!("seed={SEED:#x} case={case}: {error}"));
                let decoded: Value = decode_frame(&canonical)
                    .unwrap_or_else(|error| panic!("seed={SEED:#x} case={case}: {error}"));
                assert_eq!(decoded, value, "seed={SEED:#x} case={case}");
                assert!(canonical.len() <= MAX_FRAME_BYTES + LENGTH_PREFIX_BYTES);
            }
        }
    }

    #[test]
    fn handshake_requires_exact_supported_version_and_nonce() {
        let message = handshake();
        assert_eq!(validate_handshake(&message, &message.nonce), Ok(()));
        assert_eq!(
            validate_handshake(&message, "ffffffffffffffffffffffffffffffff"),
            Err("ACCESS_DENIED")
        );
        let mut wrong_version = message;
        wrong_version.protocol_major += 1;
        assert_eq!(
            validate_handshake(&wrong_version, &wrong_version.nonce),
            Err("VERSION_MISMATCH")
        );
    }

    #[test]
    fn request_and_response_preserve_operation_identity() {
        let operation_id = Uuid::parse_str("7b9207c9-4e50-48d7-8fac-09cf37ccf864").unwrap();
        let request = IpcRequest {
            request_id: Uuid::parse_str("83db0d7d-df01-40ac-bdfc-87bac1e60813").unwrap(),
            deadline_unix_ms: 1_788_000_000_000,
            operation_id: Some(operation_id),
            method: "memory.write".to_owned(),
            payload: json!({"address":"0x140001000","data_hex":"90"}),
        };
        let decoded = decode_frame::<IpcRequest>(&encode_frame(&request).unwrap()).unwrap();
        assert_eq!(decoded, request);

        let response = IpcResponse {
            request_id: request.request_id,
            state_generation: 8,
            outcome: IpcOutcome::Ok {
                result: json!({"bytes_written":1}),
            },
        };
        assert_eq!(
            decode_frame::<IpcResponse>(&encode_frame(&response).unwrap()).unwrap(),
            response
        );
    }

    #[tokio::test]
    async fn async_framing_handles_fragmented_duplex_io() {
        let (mut client, mut server) = tokio::io::duplex(32);
        let expected = handshake();
        let write = tokio::spawn(async move { write_frame(&mut client, &expected).await });
        let actual: Handshake = read_frame(&mut server).await.unwrap();
        write.await.unwrap().unwrap();
        assert_eq!(actual, handshake());
    }

    #[tokio::test]
    async fn async_reader_rejects_oversize_before_payload_allocation() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client
            .write_all(&(u32::try_from(MAX_FRAME_BYTES).unwrap() + 1).to_le_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_frame::<_, Handshake>(&mut server).await,
            Err(FrameError::Oversized)
        );
    }
}
