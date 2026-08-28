use async_trait::async_trait;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq)]
pub struct ToolError {
    pub code: &'static str,
    pub message: &'static str,
    pub retryable: bool,
    pub details: Value,
}

impl ToolError {
    #[must_use]
    pub fn plugin_unavailable() -> Self {
        Self {
            code: "PLUGIN_UNAVAILABLE",
            message: "x64dbg plugin is not connected",
            retryable: true,
            details: json!({}),
        }
    }
}

#[async_trait]
pub trait DebuggerAdapter: Send + Sync {
    fn is_ready(&self) -> bool;

    /// Dispatches one validated backend-local tool call.
    ///
    /// # Errors
    ///
    /// Returns a structured debugger error when the adapter cannot execute or
    /// confirm the requested operation.
    async fn call(&self, name: &str, arguments: &Value) -> Result<Value, ToolError>;
}

#[derive(Debug, Default)]
pub struct DisconnectedAdapter;

#[async_trait]
impl DebuggerAdapter for DisconnectedAdapter {
    fn is_ready(&self) -> bool {
        false
    }

    async fn call(&self, _name: &str, _arguments: &Value) -> Result<Value, ToolError> {
        Err(ToolError::plugin_unavailable())
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct FakeAdapter;

#[cfg(test)]
#[async_trait]
impl DebuggerAdapter for FakeAdapter {
    fn is_ready(&self) -> bool {
        true
    }

    async fn call(&self, name: &str, arguments: &Value) -> Result<Value, ToolError> {
        match name {
            "debugger.state" => Ok(json!({
                "backend": "x64dbg",
                "plugin_state": "ready",
                "debuggee_state": "paused",
                "state_generation": 7,
                "architecture": "x86_64",
                "process_id": 4242,
                "active_thread_id": 4343,
                "instruction_pointer": "0x0000000140001000",
                "pause_reason": { "kind": "breakpoint", "address": "0x0000000140001000" }
            })),
            "expression.evaluate" => arguments
                .get("expression")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(
                    |expression| json!({ "expression": expression, "value": "0x0000000140001000" }),
                )
                .ok_or_else(|| ToolError {
                    code: "INVALID_ARGUMENT",
                    message: "expression must be a non-empty string",
                    retryable: false,
                    details: json!({}),
                }),
            _ => Err(ToolError {
                code: "UNSUPPORTED",
                message: "tool is not implemented by the fake adapter",
                retryable: false,
                details: json!({ "tool": name }),
            }),
        }
    }
}
