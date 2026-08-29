use std::time::Duration;

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};
use uuid::Uuid;

use crate::ipc::{
    Handshake, HandshakeAck, PROTOCOL_MAJOR, PROTOCOL_MINOR, read_frame, validate_handshake,
    write_frame,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("IPC configuration is missing or invalid")]
    InvalidConfiguration,
    #[error("IPC connection failed")]
    Connection,
    #[error("IPC handshake timed out")]
    Timeout,
    #[error("IPC handshake failed: {0}")]
    Rejected(&'static str),
}

/// Authenticates a connected plugin stream and returns its declared identity.
///
/// # Errors
///
/// Returns a bounded transport error when framing, authentication, version
/// negotiation, or the handshake deadline fails.
pub async fn authenticate_stream<S>(
    stream: &mut S,
    expected_nonce: &str,
    instance_id: Uuid,
) -> Result<Handshake, ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(
        HANDSHAKE_TIMEOUT,
        authenticate(stream, expected_nonce, instance_id),
    )
    .await
    .map_err(|_| ConnectError::Timeout)?
}

async fn authenticate<S>(
    stream: &mut S,
    expected_nonce: &str,
    instance_id: Uuid,
) -> Result<Handshake, ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake: Handshake = read_frame(stream)
        .await
        .map_err(|_| ConnectError::Connection)?;
    let validation = validate_handshake(&handshake, expected_nonce);
    let ack = HandshakeAck {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        accepted: validation.is_ok(),
        error_code: validation.err().map(str::to_owned),
        instance_id: validation.is_ok().then_some(instance_id),
    };
    write_frame(stream, &ack)
        .await
        .map_err(|_| ConnectError::Connection)?;
    validation.map_err(ConnectError::Rejected)?;
    Ok(handshake)
}

#[cfg(windows)]
/// Connects to the plugin-owned pipe and performs the authenticated handshake.
///
/// # Errors
///
/// Returns [`ConnectError`] for invalid configuration, connection failures,
/// timeout, authentication failure, or an incompatible protocol version.
pub async fn connect_named_pipe(
    pipe_name: &str,
    expected_nonce: &str,
    instance_id: Uuid,
) -> Result<(tokio::net::windows::named_pipe::NamedPipeClient, Handshake), ConnectError> {
    use std::io::ErrorKind;

    use tokio::net::windows::named_pipe::ClientOptions;

    if !pipe_name.starts_with(r"\\.\pipe\x64dbg-mcp-") || pipe_name.len() > 256 {
        return Err(ConnectError::InvalidConfiguration);
    }
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let mut stream = loop {
        match ClientOptions::new().open(pipe_name) {
            Ok(stream) => break stream,
            Err(error)
                if error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(231) =>
            {
                if tokio::time::Instant::now() >= deadline {
                    return Err(ConnectError::Timeout);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(_) => return Err(ConnectError::Connection),
        }
    };
    let handshake = authenticate_stream(&mut stream, expected_nonce, instance_id).await?;
    Ok((stream, handshake))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::BackendType;

    fn handshake(nonce: &str) -> Handshake {
        Handshake {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            backend: BackendType::X64dbg,
            plugin_pid: 42,
            nonce: nonce.to_owned(),
        }
    }

    #[tokio::test]
    async fn accepts_authenticated_peer_and_sends_ack() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let instance_id = Uuid::new_v4();
        let (mut client, mut server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            write_frame(&mut server, &handshake(nonce)).await.unwrap();
            read_frame::<_, HandshakeAck>(&mut server).await.unwrap()
        });
        let actual = authenticate_stream(&mut client, nonce, instance_id)
            .await
            .unwrap();
        let ack = peer.await.unwrap();
        assert_eq!(actual.backend, BackendType::X64dbg);
        assert!(ack.accepted);
        assert_eq!(ack.error_code, None);
        assert_eq!(ack.instance_id, Some(instance_id));
    }

    #[tokio::test]
    async fn rejects_wrong_nonce_without_disclosing_details_in_transport_error() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let instance_id = Uuid::new_v4();
        let (mut client, mut server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            write_frame(&mut server, &handshake("ffffffffffffffffffffffffffffffff"))
                .await
                .unwrap();
            read_frame::<_, HandshakeAck>(&mut server).await
        });
        assert!(matches!(
            authenticate_stream(&mut client, nonce, instance_id).await,
            Err(ConnectError::Rejected("ACCESS_DENIED"))
        ));
        let ack = peer.await.unwrap().unwrap();
        assert!(!ack.accepted);
        assert_eq!(ack.error_code.as_deref(), Some("ACCESS_DENIED"));
        assert_eq!(ack.instance_id, None);
    }

    #[tokio::test]
    async fn malformed_peer_fails_closed() {
        let (mut client, mut server) = tokio::io::duplex(32);
        tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut server, &[0, 0, 0, 0])
                .await
                .unwrap();
        });
        assert!(matches!(
            authenticate_stream(
                &mut client,
                "0123456789abcdef0123456789abcdef",
                Uuid::new_v4(),
            )
            .await,
            Err(ConnectError::Connection)
        ));
    }
}
