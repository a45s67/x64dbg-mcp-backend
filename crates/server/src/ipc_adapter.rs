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
    adapter::{ActionExecution, DebuggerAdapter, NextAction, ToolError},
    ipc::{IpcOutcome, IpcRequest, IpcResponse, read_frame, write_frame},
    operation_ledger::{Admission, OperationLedger, fingerprint},
    tools,
};

const LEDGER_CAPACITY: usize = 1024;
const LEDGER_TTL: Duration = Duration::from_mins(10);
// Reserve bounded time for the plugin executor to serialize its result and for
// the sidecar to read the response. Giving both layers the same deadline races
// a valid plugin TIMEOUT response against the transport timeout.
const MAX_IPC_RESPONSE_GRACE: Duration = Duration::from_secs(1);

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

    fn transport_error(
        &self,
        code: &'static str,
        message: &'static str,
        mutation: bool,
        details: Value,
    ) -> ToolError {
        self.ready.store(false, Ordering::Release);
        let mut error = ToolError::new(code, message, code != "INTERNAL", !mutation, details);
        if mutation && error.details.get("outcome").and_then(Value::as_str) == Some("unknown") {
            error = error.with_guidance(
                "Reconcile current debugger state before deciding whether to issue another mutation.",
                vec![NextAction::tool(
                    "REFRESH_DEBUGGER_STATE",
                    ActionExecution::RequiredBeforeRetry,
                    "Observe the current debugger state before another mutation.",
                    "debugger.state",
                    json!({}),
                )],
            );
        }
        error
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

        let mut admitted_key = None;
        if let Some(id) = operation_id {
            let key = fingerprint(name, arguments).map_err(|_| {
                ToolError::new(
                    "INVALID_ARGUMENT",
                    "tool arguments cannot be fingerprinted",
                    false,
                    false,
                    json!({}),
                )
            })?;
            match self
                .ledger
                .begin(id, key.clone())
                .map_err(ledger_internal_error)?
            {
                Admission::Started => admitted_key = Some(key),
                Admission::Completed(value) => return decode_recorded(value),
                Admission::InFlight => {
                    return Err(ToolError::new(
                        "BUSY",
                        "operation is already in flight",
                        true,
                        true,
                        json!({ "operation_id": id }),
                    )
                    .with_guidance(
                        "Wait for the in-flight operation to finish, then retry with the same operation_id.",
                        Vec::new(),
                    ));
                }
                Admission::Unknown => return Err(unknown_outcome(id)),
                Admission::Conflict => {
                    return Err(ToolError::new(
                        "OPERATION_ID_CONFLICT",
                        "operation_id was already used with different arguments",
                        true,
                        false,
                        json!({ "operation_id": id }),
                    )
                    .with_guidance(
                        "Use the original arguments, or use a new operation_id only for a distinct intended mutation.",
                        Vec::new(),
                    ));
                }
                Admission::Capacity => {
                    return Err(ToolError::new(
                        "BUSY",
                        "mutation operation ledger is full",
                        true,
                        true,
                        json!({}),
                    )
                    .with_guidance(
                        "Wait for admitted mutations to complete before retrying this request.",
                        Vec::new(),
                    ));
                }
            }
        }

        if !self.is_ready() {
            if let (Some(id), Some(key)) = (operation_id, admitted_key.as_deref()) {
                self.ledger
                    .abandon_unstarted(id, key)
                    .map_err(ledger_internal_error)?;
            }
            return Err(ToolError::plugin_unavailable());
        }

        let request_id = Uuid::new_v4();
        let request = IpcRequest {
            request_id,
            deadline_unix_ms: unix_deadline_ms(plugin_execution_budget(operation_timeout)),
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
                return Err(self.transport_error(
                    "PLUGIN_UNAVAILABLE",
                    "IPC connection failed",
                    mutation,
                    unknown_transport_details(operation_id),
                ));
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
            return Err(self.transport_error(
                "INTERNAL",
                "IPC response correlation mismatch",
                mutation,
                unknown_transport_details(operation_id),
            ));
        }

        let outcome = match response.outcome {
            IpcOutcome::Ok { result } => Ok(result),
            IpcOutcome::Error { error } => {
                let mut details = error.details;
                if let Some(object) = details.as_object_mut() {
                    object.insert("debugger_message".to_owned(), Value::String(error.message));
                } else {
                    details = json!({
                        "debugger_message": error.message,
                        "debugger_details": details
                    });
                }
                let code = stable_error_code(&error.code);
                let recoverable = plugin_error_recoverable(code, error.retryable);
                let safe_to_retry = !mutation && error.retryable;
                let mut tool_error = ToolError::new(
                    code,
                    "debugger rejected the operation",
                    recoverable,
                    safe_to_retry,
                    details,
                );
                apply_plugin_guidance(&mut tool_error, name, arguments, mutation);
                Err(tool_error)
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
        .ok_or_else(|| {
            ToolError::new(
                "INVALID_ARGUMENT",
                "mutating tools require a valid UUID operation_id",
                true,
                false,
                json!({ "field": "operation_id" }),
            )
        })
}

fn unix_deadline_ms(duration: Duration) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from((now + duration).as_millis()).unwrap_or(u64::MAX)
}

fn plugin_execution_budget(operation_timeout: Duration) -> Duration {
    let response_grace = (operation_timeout / 4).min(MAX_IPC_RESPONSE_GRACE);
    operation_timeout.saturating_sub(response_grace)
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
        _ => "INTERNAL",
    }
}

fn plugin_error_recoverable(code: &str, native_retryable: bool) -> bool {
    native_retryable || !matches!(code, "INTERNAL" | "UNSUPPORTED")
}

fn unknown_transport_details(operation_id: Option<Uuid>) -> Value {
    operation_id.map_or_else(
        || json!({}),
        |id| json!({ "operation_id": id, "outcome": "unknown" }),
    )
}

fn apply_plugin_guidance(error: &mut ToolError, name: &str, arguments: &Value, mutation: bool) {
    let pif_launch = name == "debuggee.launch"
        && arguments
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|path| path.to_ascii_lowercase().ends_with(".pif"));
    if error.code == "TIMEOUT" && pif_launch {
        error.suggested_action = Some(
            "Rename a hash-identical analysis copy to .exe, record its provenance, and try again."
                .to_owned(),
        );
        return;
    }
    if mutation && error.details.get("outcome").and_then(Value::as_str) == Some("unknown") {
        error.suggested_action = Some(
            "Reconcile current debugger state before deciding whether to issue another mutation."
                .to_owned(),
        );
        error.next_actions = vec![NextAction::tool(
            "REFRESH_DEBUGGER_STATE",
            ActionExecution::RequiredBeforeRetry,
            "Observe the current debugger state before another mutation.",
            "debugger.state",
            json!({}),
        )];
        return;
    }
    if error.code == "STALE_CURSOR" {
        error.suggested_action =
            Some("Restart the bounded discovery query without the stale cursor.".to_owned());
    } else if error.code == "NO_DEBUGGEE" {
        error.suggested_action =
            Some("Launch a binary or attach to a process before calling this tool.".to_owned());
    } else if error.code == "INVALID_DEBUGGER_STATE" {
        error.suggested_action = Some(
            "Call debugger.state and satisfy the tool's required state before retrying.".to_owned(),
        );
        error.next_actions = vec![NextAction::tool(
            "REFRESH_DEBUGGER_STATE",
            ActionExecution::Suggested,
            "Inspect the current debugger state before choosing the next operation.",
            "debugger.state",
            json!({}),
        )];
    }
}

fn ledger_internal_error(_: crate::operation_ledger::LedgerError) -> ToolError {
    ToolError::new(
        "INTERNAL",
        "mutation ledger failure",
        false,
        false,
        json!({}),
    )
}

fn unknown_outcome(operation_id: Uuid) -> ToolError {
    ToolError::new(
        "TIMEOUT",
        "mutation outcome is unknown and will not be retried",
        true,
        false,
        json!({ "operation_id": operation_id, "outcome": "unknown" }),
    )
    .with_guidance(
        "Reconcile current debugger state before deciding whether to issue another mutation.",
        vec![NextAction::tool(
            "REFRESH_DEBUGGER_STATE",
            ActionExecution::RequiredBeforeRetry,
            "Observe the current debugger state before another mutation.",
            "debugger.state",
            json!({}),
        )],
    )
}

fn encode_recorded(outcome: &Result<Value, ToolError>) -> Value {
    match outcome {
        Ok(value) => json!({ "ok": true, "result": value }),
        Err(error) => json!({
            "ok": false,
            "error": {
                "code": error.code,
                "message": error.message,
                "recoverable": error.recoverable,
                "safe_to_retry": error.safe_to_retry,
                "suggested_action": error.suggested_action,
                "next_actions": error.next_actions,
                "details": error.details
            }
        }),
    }
}

fn decode_recorded(value: Value) -> Result<Value, ToolError> {
    if value["ok"] == true {
        return Ok(value["result"].clone());
    }
    let next_actions = serde_json::from_value(value["error"]["next_actions"].clone())
        .unwrap_or_else(|_| Vec::new());
    Err(ToolError {
        code: stable_error_code(value["error"]["code"].as_str().unwrap_or("INTERNAL")),
        message: "replayed debugger operation result",
        recoverable: value["error"]["recoverable"].as_bool().unwrap_or(false),
        safe_to_retry: value["error"]["safe_to_retry"].as_bool().unwrap_or(false),
        suggested_action: value["error"]["suggested_action"]
            .as_str()
            .map(str::to_owned),
        next_actions,
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
        safe_to_retry: bool,
        details: Value,
    ) -> ToolError {
        self.ready.store(false, Ordering::Release);
        let recoverable = code != "INTERNAL";
        let mut error = ToolError::new(code, message, recoverable, safe_to_retry, details);
        if !safe_to_retry && error.details.get("outcome").and_then(Value::as_str) == Some("unknown")
        {
            error = error.with_guidance(
                "Reconcile current debugger state before deciding whether to issue another mutation.",
                vec![NextAction::tool(
                    "REFRESH_DEBUGGER_STATE",
                    ActionExecution::RequiredBeforeRetry,
                    "Observe the current debugger state before another mutation.",
                    "debugger.state",
                    json!({}),
                )],
            );
        }
        error
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use tokio::io::DuplexStream;

    use super::*;
    use crate::ipc::{IpcErrorBody, IpcOutcome, IpcResponse};

    #[test]
    fn plugin_budget_reserves_bounded_response_time() {
        assert_eq!(
            plugin_execution_budget(Duration::from_secs(30)),
            Duration::from_secs(29)
        );
        assert_eq!(
            plugin_execution_budget(Duration::from_millis(100)),
            Duration::from_millis(75)
        );
    }

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
        assert!(first.recoverable);
        assert!(!first.safe_to_retry);
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
    async fn plugin_timeout_response_preserves_ipc_for_follow_up_calls() {
        let (client, mut plugin): (DuplexStream, DuplexStream) = tokio::io::duplex(4096);
        let adapter = IpcAdapter::established(
            client,
            Duration::from_millis(100),
            Duration::from_millis(300),
        );
        let operation_id = Uuid::new_v4();
        let plugin_task = tokio::spawn(async move {
            let launch: IpcRequest = read_frame(&mut plugin).await.unwrap();
            // The 300 ms transport budget gives the plugin 225 ms after the
            // response reserve. Reply well inside that deadline so this test
            // cannot race the sidecar's transport timeout on a busy runner.
            tokio::time::sleep(Duration::from_millis(150)).await;
            write_frame(
                &mut plugin,
                &IpcResponse {
                    request_id: launch.request_id,
                    state_generation: 0,
                    outcome: IpcOutcome::Error {
                        error: IpcErrorBody {
                            code: "TIMEOUT".to_owned(),
                            message: "launch did not reach an actionable pause".to_owned(),
                            retryable: false,
                            details: json!({"outcome":"unknown"}),
                        },
                    },
                },
            )
            .await
            .unwrap();

            let state: IpcRequest = read_frame(&mut plugin).await.unwrap();
            write_frame(
                &mut plugin,
                &IpcResponse {
                    request_id: state.request_id,
                    state_generation: 0,
                    outcome: IpcOutcome::Ok {
                        result: json!({"debuggee_state":"absent"}),
                    },
                },
            )
            .await
            .unwrap();
        });

        let error = adapter
            .call(
                "debuggee.launch",
                &json!({"operation_id": operation_id, "path":"sample.pif"}),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, "TIMEOUT");
        assert!(error.recoverable);
        assert!(!error.safe_to_retry);
        assert_eq!(
            error.details["debugger_message"],
            "launch did not reach an actionable pause"
        );
        assert!(adapter.is_ready());

        let state = adapter.call("debugger.state", &json!({})).await.unwrap();
        assert_eq!(state["debuggee_state"], "absent");
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
            IpcAdapter::established(client, Duration::from_millis(100), Duration::from_secs(4));
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
        assert!(mutation_deadline.saturating_sub(read_deadline) >= 2_800);
    }
}
