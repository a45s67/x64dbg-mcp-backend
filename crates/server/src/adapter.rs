use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionExecution {
    Suggested,
    RequiredBeforeRetry,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NextAction {
    pub code: String,
    pub execution: ActionExecution,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments_patch: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserve_arguments: Vec<String>,
}

impl NextAction {
    #[must_use]
    pub fn tool(
        code: &str,
        execution: ActionExecution,
        reason: &str,
        tool: &str,
        arguments: Value,
    ) -> Self {
        Self {
            code: code.to_owned(),
            execution,
            reason: reason.to_owned(),
            tool: Some(tool.to_owned()),
            arguments: Some(arguments),
            arguments_patch: None,
            preserve_arguments: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_bounded(&self) -> bool {
        let valid_code = (3..=64).contains(&self.code.len())
            && self.code.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_uppercase() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
            });
        let valid_reason = !self.reason.is_empty()
            && self.reason.len() <= 256
            && !self.reason.chars().any(char::is_control);
        let valid_tool = self.tool.as_deref().is_none_or(valid_tool_name);
        let valid_arguments = self
            .arguments
            .as_ref()
            .is_none_or(|value| value.as_object().is_some_and(|object| object.len() <= 32));
        let valid_patch = self
            .arguments_patch
            .as_ref()
            .is_none_or(|value| value.as_object().is_some_and(|object| object.len() <= 16));
        let valid_preserved = self.preserve_arguments.len() <= 16
            && self
                .preserve_arguments
                .iter()
                .all(|value| !value.is_empty() && value.len() <= 64);
        let arguments_require_tool = self.tool.is_some()
            || (self.arguments.is_none()
                && self.arguments_patch.is_none()
                && self.preserve_arguments.is_empty());
        valid_code
            && valid_reason
            && valid_tool
            && valid_arguments
            && valid_patch
            && valid_preserved
            && arguments_require_tool
            && serde_json::to_vec(self).is_ok_and(|encoded| encoded.len() <= 4096)
    }
}

fn valid_tool_name(value: &str) -> bool {
    let mut segments = value.split('.');
    let mut count = 0usize;
    let valid = segments.all(|segment| {
        count += 1;
        !segment.is_empty()
            && segment.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase() || (index > 0 && (byte.is_ascii_digit() || byte == b'_'))
            })
    });
    valid && count >= 2
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolError {
    pub code: &'static str,
    pub message: &'static str,
    pub recoverable: bool,
    pub safe_to_retry: bool,
    pub suggested_action: Option<String>,
    pub next_actions: Vec<NextAction>,
    pub details: Value,
}

impl ToolError {
    #[must_use]
    pub fn new(
        code: &'static str,
        message: &'static str,
        recoverable: bool,
        safe_to_retry: bool,
        details: Value,
    ) -> Self {
        Self {
            code,
            message,
            recoverable,
            safe_to_retry,
            suggested_action: None,
            next_actions: Vec::new(),
            details,
        }
    }

    #[must_use]
    pub fn with_guidance(mut self, suggested_action: &str, next_actions: Vec<NextAction>) -> Self {
        self.suggested_action = Some(suggested_action.to_owned());
        self.next_actions = next_actions;
        self
    }

    #[must_use]
    pub fn plugin_unavailable() -> Self {
        Self::new(
            "PLUGIN_UNAVAILABLE",
            "x64dbg plugin is not connected",
            true,
            true,
            json!({}),
        )
        .with_guidance(
            "Start the matching x32dbg or x64dbg host and wait for its plugin to connect.",
            Vec::new(),
        )
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
                "instance_id": "11111111-2222-4333-8444-555555555555",
                "backend": "x64dbg",
                "plugin_state": "ready",
                "debuggee_state": "paused",
                "state_generation": 7,
                "architecture": "x86_64",
                "process_id": 4242,
                "active_thread_id": 4343,
                "instruction_pointer": "0x0000000140001000",
                "pause_reason": { "kind": "breakpoint", "address": "0x0000000140001000" },
                "diagnostic_code": null,
                "next_actions": []
            })),
            "debugger.wait_for_pause" => Ok(json!({
                "debuggee_state": "paused",
                "state_generation": 8,
                "architecture": "x86_64",
                "active_thread_id": "0x10f7",
                "instruction_pointer": "0x0000000140001000",
                "pause_reason": {
                    "kind": "breakpoint",
                    "address": "0x0000000140001000",
                    "breakpoint_type": "software",
                    "hit_count": 1
                }
            })),
            "expression.evaluate" => arguments
                .get("expression")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(|expression| {
                    json!({
                        "expression": expression,
                        "value": "0x0000000140001000",
                        "state_generation": 7
                    })
                })
                .ok_or_else(|| ToolError {
                    code: "INVALID_ARGUMENT",
                    message: "expression must be a non-empty string",
                    recoverable: true,
                    safe_to_retry: false,
                    suggested_action: None,
                    next_actions: Vec::new(),
                    details: json!({}),
                }),
            "address.resolve" => Ok(json!({
                "address": "0x0000000140001000",
                "module": "sample.exe",
                "module_base": "0x0000000140000000",
                "rva": "0x1000",
                "state_generation": 7
            })),
            _ => Err(ToolError {
                code: "UNSUPPORTED",
                message: "tool is not implemented by the fake adapter",
                recoverable: false,
                safe_to_retry: false,
                suggested_action: None,
                next_actions: Vec::new(),
                details: json!({ "tool": name }),
            }),
        }
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct FakeAbsentAdapter;

#[cfg(test)]
#[async_trait]
impl DebuggerAdapter for FakeAbsentAdapter {
    fn is_ready(&self) -> bool {
        true
    }

    async fn call(&self, name: &str, _arguments: &Value) -> Result<Value, ToolError> {
        if name == "debugger.state" {
            Ok(json!({
                "instance_id": "11111111-2222-4333-8444-555555555555",
                "backend": "x64dbg",
                "plugin_state": "ready",
                "debuggee_state": "absent",
                "state_generation": 1,
                "architecture": "x86_64",
                "process_id": null,
                "active_thread_id": null,
                "instruction_pointer": null,
                "pause_reason": null,
                "diagnostic_code": "NO_DEBUGGEE",
                "next_actions": [{
                    "code": "CALL_DEBUGGEE_LAUNCH",
                    "tool": "debuggee.launch"
                }]
            }))
        } else {
            Err(ToolError {
                code: "UNSUPPORTED",
                message: "tool is not implemented by the fake adapter",
                recoverable: false,
                safe_to_retry: false,
                suggested_action: None,
                next_actions: Vec::new(),
                details: json!({ "tool": name }),
            })
        }
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct FakeMismatchedAdapter;

#[cfg(test)]
#[async_trait]
impl DebuggerAdapter for FakeMismatchedAdapter {
    fn is_ready(&self) -> bool {
        true
    }

    async fn call(&self, name: &str, _arguments: &Value) -> Result<Value, ToolError> {
        if name == "debugger.state" {
            Ok(json!({
                "instance_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "backend": "x64dbg",
                "debuggee_state": "paused"
            }))
        } else {
            Err(ToolError {
                code: "UNSUPPORTED",
                message: "tool is not implemented by the fake adapter",
                recoverable: false,
                safe_to_retry: false,
                suggested_action: None,
                next_actions: Vec::new(),
                details: json!({ "tool": name }),
            })
        }
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn next_action_bounds_are_enforced() {
        let valid = NextAction::tool(
            "REFRESH_DEBUGGER_STATE",
            ActionExecution::RequiredBeforeRetry,
            "Observe current debugger state.",
            "debugger.state",
            json!({}),
        );
        assert!(valid.is_bounded());

        let mut invalid_tool = valid.clone();
        invalid_tool.tool = Some("Debugger.State".to_owned());
        assert!(!invalid_tool.is_bounded());

        let mut oversized_reason = valid;
        oversized_reason.reason = "x".repeat(257);
        assert!(!oversized_reason.is_bounded());
    }
}
