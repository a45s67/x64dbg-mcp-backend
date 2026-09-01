use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
    time::timeout,
};
use uuid::Uuid;

use crate::{
    adapter::{DebuggerAdapter, ToolError},
    ipc::{IpcOutcome, IpcRequest, IpcResponse, read_frame, write_frame},
    operation_ledger::{Admission, OperationLedger, fingerprint},
    tools,
};

const LEDGER_CAPACITY: usize = 1024;
const LEDGER_TTL: Duration = Duration::from_mins(10);

pub struct IpcAdapter<S> {
    stream: Mutex<S>,
    ready: AtomicBool,
    read_timeout: Duration,
    mutation_timeout: Duration,
    ledger: OperationLedger,
}

impl<S> IpcAdapter<S> {
    /// Creates an authenticated IPC adapter around an established stream.
    ///
    /// # Panics
    ///
    /// Panics only if the compile-time non-zero ledger constants are changed to
    /// invalid values.
    #[must_use]
    pub fn established(stream: S, read_timeout: Duration, mutation_timeout: Duration) -> Self {
        Self {
            stream: Mutex::new(stream),
            ready: AtomicBool::new(true),
            read_timeout,
            mutation_timeout,
            ledger: OperationLedger::new(LEDGER_CAPACITY, LEDGER_TTL)
                .expect("ledger constants are non-zero"),
        }
    }

    fn transport_error(&self, code: &'static str, message: &'static str) -> ToolError {
        self.ready.store(false, Ordering::Release);
        ToolError {
            code,
            message,
            retryable: true,
            details: json!({}),
        }
    }
}

#[async_trait]
impl<S> DebuggerAdapter for IpcAdapter<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    async fn call(&self, name: &str, arguments: &Value) -> Result<Value, ToolError> {
        let mutation = tools::is_mutation_call(name, arguments);
        let operation_timeout = if mutation {
            self.mutation_timeout
        } else {
            self.read_timeout
        };
        let operation_id = if mutation {
            Some(parse_operation_id(arguments)?)
        } else {
            None
        };

        if let Some(id) = operation_id {
            let key = fingerprint(name, arguments).map_err(|_| ToolError {
                code: "INVALID_ARGUMENT",
                message: "tool arguments cannot be fingerprinted",
                retryable: false,
                details: json!({}),
            })?;
            match self.ledger.begin(id, key).map_err(ledger_internal_error)? {
                Admission::Started => {}
                Admission::Completed(value) => return decode_recorded(value),
                Admission::InFlight => {
                    return Err(ToolError {
                        code: "BUSY",
                        message: "operation is already in flight",
                        retryable: true,
                        details: json!({ "operation_id": id }),
                    });
                }
                Admission::Unknown => return Err(unknown_outcome(id)),
                Admission::Conflict => {
                    return Err(ToolError {
                        code: "OPERATION_ID_CONFLICT",
                        message: "operation_id was already used with different arguments",
                        retryable: false,
                        details: json!({ "operation_id": id }),
                    });
                }
                Admission::Capacity => {
                    return Err(ToolError {
                        code: "BUSY",
                        message: "mutation operation ledger is full",
                        retryable: true,
                        details: json!({}),
                    });
                }
            }
        }

        if !self.is_ready() {
            return Err(ToolError::plugin_unavailable());
        }

        let request_id = Uuid::new_v4();
        let request = IpcRequest {
            request_id,
            deadline_unix_ms: unix_deadline_ms(operation_timeout),
            operation_id,
            method: name.to_owned(),
            payload: arguments.clone(),
        };

        let exchange = async {
            let mut stream = self.stream.lock().await;
            write_frame(&mut *stream, &request).await?;
            read_frame::<_, IpcResponse>(&mut *stream).await
        };
        let response = match timeout(operation_timeout, exchange).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                self.mark_unknown(operation_id);
                return Err(self.transport_error("PLUGIN_UNAVAILABLE", "IPC connection failed"));
            }
            Err(_) => {
                self.mark_unknown(operation_id);
                return Err(self.transport_error_with_details(
                    "TIMEOUT",
                    "debugger operation exceeded its deadline",
                    !mutation,
                    operation_id.map_or_else(
                        || json!({}),
                        |id| json!({ "operation_id": id, "outcome": "unknown" }),
                    ),
                ));
            }
        };

        if response.request_id != request_id {
            self.mark_unknown(operation_id);
            return Err(self.transport_error("INTERNAL", "IPC response correlation mismatch"));
        }

        let outcome = match response.outcome {
            IpcOutcome::Ok { result } => Ok(result),
            IpcOutcome::Error { error } => {
                let code = stable_error_code(&error.code);
                Err(ToolError {
                    code,
                    message: stable_error_message(code),
                    retryable: error.retryable,
                    details: error.details,
                })
            }
        };
        if let Some(id) = operation_id {
            let recorded = encode_recorded(&outcome);
            self.ledger
                .complete(id, recorded)
                .map_err(ledger_internal_error)?;
        }
        outcome
    }
}

fn parse_operation_id(arguments: &Value) -> Result<Uuid, ToolError> {
    arguments
        .get("operation_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(ToolError {
            code: "INVALID_ARGUMENT",
            message: "mutating tools require a valid UUID operation_id",
            retryable: false,
            details: json!({ "field": "operation_id" }),
        })
}

fn unix_deadline_ms(duration: Duration) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from((now + duration).as_millis()).unwrap_or(u64::MAX)
}

fn stable_error_code(code: &str) -> &'static str {
    match code {
        "INVALID_ARGUMENT" => "INVALID_ARGUMENT",
        "INVALID_DEBUGGER_STATE" => "INVALID_DEBUGGER_STATE",
        "NO_DEBUGGEE" => "NO_DEBUGGEE",
        "NOT_FOUND" => "NOT_FOUND",
        "ALREADY_EXISTS" => "ALREADY_EXISTS",
        "CONFLICT" => "CONFLICT",
        "RESOURCE_EXHAUSTED" => "RESOURCE_EXHAUSTED",
        "ACCESS_DENIED" => "ACCESS_DENIED",
        "BUSY" => "BUSY",
        "TIMEOUT" => "TIMEOUT",
        "STALE_CURSOR" => "STALE_CURSOR",
        "OUTPUT_LIMIT_EXCEEDED" => "OUTPUT_LIMIT_EXCEEDED",
        "CANCELLED" => "CANCELLED",
        "UNSUPPORTED" => "UNSUPPORTED",
        "SCYLLAHIDE_NOT_INSTALLED" => "SCYLLAHIDE_NOT_INSTALLED",
        "SCYLLAHIDE_CONFIG_INVALID" => "SCYLLAHIDE_CONFIG_INVALID",
        "PROFILE_NOT_FOUND" => "PROFILE_NOT_FOUND",
        "CONFIG_GENERATION_MISMATCH" => "CONFIG_GENERATION_MISMATCH",
        "PROFILE_WRITE_FAILED" => "PROFILE_WRITE_FAILED",
        "UNSUPPORTED_FILE_EXTENSION" => "UNSUPPORTED_FILE_EXTENSION",
        _ => "INTERNAL",
    }
}

fn stable_error_message(code: &str) -> &'static str {
    match code {
        "UNSUPPORTED_FILE_EXTENSION" => {
            "valid PE uses an extension unsupported by the bounded launch tool"
        }
        _ => "debugger rejected the operation",
    }
}

fn ledger_internal_error(_: crate::operation_ledger::LedgerError) -> ToolError {
    ToolError {
        code: "INTERNAL",
        message: "mutation ledger failure",
        retryable: false,
        details: json!({}),
    }
}

fn unknown_outcome(operation_id: Uuid) -> ToolError {
    ToolError {
        code: "TIMEOUT",
        message: "mutation outcome is unknown and will not be retried",
        retryable: false,
        details: json!({ "operation_id": operation_id, "outcome": "unknown" }),
    }
}

fn encode_recorded(outcome: &Result<Value, ToolError>) -> Value {
    match outcome {
        Ok(value) => json!({ "ok": true, "result": value }),
        Err(error) => json!({
            "ok": false,
            "error": {
                "code": error.code,
                "message": error.message,
                "retryable": error.retryable,
                "details": error.details
            }
        }),
    }
}

fn decode_recorded(value: Value) -> Result<Value, ToolError> {
    if value["ok"] == true {
        return Ok(value["result"].clone());
    }
    let code = stable_error_code(value["error"]["code"].as_str().unwrap_or("INTERNAL"));
    Err(ToolError {
        code,
        message: stable_error_message(code),
        retryable: value["error"]["retryable"].as_bool().unwrap_or(false),
        details: value["error"]["details"].clone(),
    })
}

impl<S> IpcAdapter<S> {
    fn mark_unknown(&self, operation_id: Option<Uuid>) {
        if let Some(id) = operation_id {
            let _ = self.ledger.mark_unknown(id);
        }
    }

    fn transport_error_with_details(
        &self,
        code: &'static str,
        message: &'static str,
        retryable: bool,
        details: Value,
    ) -> ToolError {
        self.ready.store(false, Ordering::Release);
        ToolError {
            code,
            message,
            retryable,
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use tokio::io::DuplexStream;

    use super::*;
    use crate::ipc::{IpcOutcome, IpcResponse};

    #[test]
    fn discovery_error_codes_remain_structured() {
        assert_eq!(stable_error_code("STALE_CURSOR"), "STALE_CURSOR");
        assert_eq!(
            stable_error_code("OUTPUT_LIMIT_EXCEEDED"),
            "OUTPUT_LIMIT_EXCEEDED"
        );
        assert_eq!(stable_error_code("ALREADY_EXISTS"), "ALREADY_EXISTS");
        assert_eq!(stable_error_code("CONFLICT"), "CONFLICT");
        assert_eq!(
            stable_error_code("UNSUPPORTED_FILE_EXTENSION"),
            "UNSUPPORTED_FILE_EXTENSION"
        );
        assert_eq!(
            stable_error_code("RESOURCE_EXHAUSTED"),
            "RESOURCE_EXHAUSTED"
        );
        assert_eq!(stable_error_code("untrusted-plugin-code"), "INTERNAL");
    }

    #[tokio::test]
    async fn correlated_response_is_returned() {
        let (client, mut plugin) = tokio::io::duplex(4096);
        let adapter =
            IpcAdapter::established(client, Duration::from_secs(1), Duration::from_secs(2));
        let plugin_task = tokio::spawn(async move {
            let request: IpcRequest = read_frame(&mut plugin).await.unwrap();
            write_frame(
                &mut plugin,
                &IpcResponse {
                    request_id: request.request_id,
                    state_generation: 3,
                    outcome: IpcOutcome::Ok {
                        result: json!({"debuggee_state":"paused"}),
                    },
                },
            )
            .await
            .unwrap();
        });
        let result = adapter.call("debugger.state", &json!({})).await.unwrap();
        plugin_task.await.unwrap();
        assert_eq!(result["debuggee_state"], "paused");
        assert!(adapter.is_ready());
    }

    #[tokio::test]
    async fn timed_out_mutation_is_not_sent_twice() {
        let (client, mut plugin): (DuplexStream, DuplexStream) = tokio::io::duplex(4096);
        let adapter = Arc::new(IpcAdapter::established(
            client,
            Duration::from_secs(1),
            Duration::from_millis(20),
        ));
        let operation_id = Uuid::new_v4();
        let arguments = json!({"operation_id":operation_id});
        let plugin_task = tokio::spawn(async move {
            let _: IpcRequest = read_frame(&mut plugin).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let first = adapter
            .call("debugger.resume", &arguments)
            .await
            .unwrap_err();
        assert_eq!(first.code, "TIMEOUT");
        assert!(!first.retryable);
        assert!(!adapter.is_ready());
        let second = adapter
            .call("debugger.resume", &arguments)
            .await
            .unwrap_err();
        assert_eq!(second.code, "TIMEOUT");
        assert_eq!(second.details["outcome"], "unknown");
        let read_after_timeout = adapter
            .call("debugger.state", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(read_after_timeout.code, "PLUGIN_UNAVAILABLE");
        plugin_task.await.unwrap();
    }

    #[tokio::test]
    async fn correlation_mismatch_fails_closed() {
        let (client, mut plugin) = tokio::io::duplex(4096);
        let adapter =
            IpcAdapter::established(client, Duration::from_secs(1), Duration::from_secs(2));
        tokio::spawn(async move {
            let _: IpcRequest = read_frame(&mut plugin).await.unwrap();
            write_frame(
                &mut plugin,
                &IpcResponse {
                    request_id: Uuid::new_v4(),
                    state_generation: 0,
                    outcome: IpcOutcome::Ok { result: json!({}) },
                },
            )
            .await
            .unwrap();
        });
        let error = adapter
            .call("debugger.state", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.code, "INTERNAL");
        assert!(!adapter.is_ready());
    }

    #[tokio::test]
    async fn peer_disconnect_marks_adapter_not_ready() {
        let (client, plugin) = tokio::io::duplex(64);
        let adapter =
            IpcAdapter::established(client, Duration::from_secs(1), Duration::from_secs(2));
        drop(plugin);
        let error = adapter
            .call("debugger.state", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.code, "PLUGIN_UNAVAILABLE");
        assert!(!adapter.is_ready());
    }

    #[tokio::test]
    async fn mutations_receive_the_separate_longer_deadline() {
        let (client, mut plugin) = tokio::io::duplex(4096);
        let adapter =
            IpcAdapter::established(client, Duration::from_millis(100), Duration::from_secs(2));
        let plugin_task = tokio::spawn(async move {
            let read: IpcRequest = read_frame(&mut plugin).await.unwrap();
            write_frame(
                &mut plugin,
                &IpcResponse {
                    request_id: read.request_id,
                    state_generation: 1,
                    outcome: IpcOutcome::Ok { result: json!({}) },
                },
            )
            .await
            .unwrap();
            let mutation: IpcRequest = read_frame(&mut plugin).await.unwrap();
            write_frame(
                &mut plugin,
                &IpcResponse {
                    request_id: mutation.request_id,
                    state_generation: 2,
                    outcome: IpcOutcome::Ok { result: json!({}) },
                },
            )
            .await
            .unwrap();
            (read.deadline_unix_ms, mutation.deadline_unix_ms)
        });
        adapter.call("debugger.state", &json!({})).await.unwrap();
        adapter
            .call("debugger.resume", &json!({"operation_id": Uuid::new_v4()}))
            .await
            .unwrap();
        let (read_deadline, mutation_deadline) = plugin_task.await.unwrap();
        assert!(mutation_deadline.saturating_sub(read_deadline) >= 1_800);
    }
}
