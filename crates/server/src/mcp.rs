use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    adapter::{ActionExecution, DebuggerAdapter, NextAction, ToolError},
    content, tools,
};

pub const PROTOCOL_VERSION: &str = "2025-11-25";
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_STRING_BYTES: usize = 8_192;
const MAX_JSON_CONTAINER_ITEMS: usize = 512;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

pub async fn handle(body: &[u8], adapter: &dyn DebuggerAdapter, instance_id: Uuid) -> Response {
    let value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return rpc_error(None, -32700, "Parse error"),
    };
    if value.is_array() {
        return rpc_error(None, -32600, "JSON-RPC batches are not supported");
    }
    if !within_json_limits(&value, 0) {
        return rpc_error(None, -32600, "Invalid Request");
    }
    let has_id = value.get("id").is_some();
    let request: Request = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(_) => return rpc_error(None, -32600, "Invalid Request"),
    };
    if request.jsonrpc != "2.0" {
        return rpc_error(request.id, -32600, "Invalid Request");
    }
    if request.method.is_empty() || request.method.len() > 128 {
        return rpc_error(request.id, -32600, "Invalid Request");
    }
    if has_id
        && request
            .id
            .as_ref()
            .is_some_and(|id| !id.is_null() && !id.is_string() && !id.is_i64() && !id.is_u64())
    {
        return rpc_error(None, -32600, "Invalid Request");
    }
    if !has_id {
        return StatusCode::ACCEPTED.into_response();
    }

    let id = request.id.unwrap_or(Value::Null);
    let result = match request.method.as_str() {
        "initialize" => initialize(&request.params, instance_id),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools::catalog() })),
        "tools/call" => call_tool(&request.params, adapter, instance_id).await,
        _ => Err((-32601, "Method not found")),
    };
    match result {
        Ok(value) => Json(json!({ "jsonrpc": "2.0", "id": id, "result": value })).into_response(),
        Err((code, message)) => rpc_error(Some(id), code, message),
    }
}

fn within_json_limits(value: &Value, depth: usize) -> bool {
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    match value {
        Value::String(value) => value.len() <= MAX_JSON_STRING_BYTES,
        Value::Array(values) => {
            values.len() <= MAX_JSON_CONTAINER_ITEMS
                && values
                    .iter()
                    .all(|value| within_json_limits(value, depth + 1))
        }
        Value::Object(values) => {
            values.len() <= MAX_JSON_CONTAINER_ITEMS
                && values
                    .iter()
                    .all(|(key, value)| key.len() <= 128 && within_json_limits(value, depth + 1))
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

async fn call_tool(
    params: &Value,
    adapter: &dyn DebuggerAdapter,
    instance_id: Uuid,
) -> Result<Value, (i32, &'static str)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "Missing tool name"))?;
    if !tools::exists(name) {
        return Err((-32602, "Unknown tool name"));
    }
    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    if !arguments.is_object() {
        return Err((-32602, "Tool arguments must be an object"));
    }
    if let Err(error) = tools::validate_arguments(name, arguments) {
        return Ok(tool_failure(
            name,
            ToolError {
                code: "INVALID_ARGUMENT",
                message: error.message,
                recoverable: true,
                safe_to_retry: false,
                suggested_action: Some(
                    "Correct the reported field before calling the tool again.".to_owned(),
                ),
                next_actions: Vec::new(),
                details: json!({ "field": error.field }),
            },
        ));
    }
    let mut dispatched_arguments = arguments.clone();
    if tools::is_mutation_call(name, arguments) {
        let supplied = arguments
            .get("instance_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .expect("validated mutation instance_id must be a UUID");
        if supplied != instance_id {
            return Ok(tool_failure(
                name,
                ToolError {
                    code: "BACKEND_RESTARTED",
                    message: "backend instance changed; mutation was not dispatched",
                    recoverable: true,
                    safe_to_retry: false,
                    suggested_action: Some(
                        "Refresh debugger state and use its current instance_id before deciding whether to issue the mutation."
                            .to_owned(),
                    ),
                    next_actions: vec![NextAction::tool(
                        "REFRESH_DEBUGGER_STATE",
                        ActionExecution::RequiredBeforeRetry,
                        "Obtain the current backend identity before another mutation.",
                        "debugger.state",
                        json!({}),
                    )],
                    details: json!({
                        "outcome": "not_started",
                        "expected_instance_id": supplied,
                        "current_instance_id": instance_id
                    }),
                },
            ));
        }
        dispatched_arguments
            .as_object_mut()
            .expect("validated arguments are an object")
            .remove("instance_id");
    }
    let expected_instance_id = instance_id.hyphenated().to_string();
    Ok(match adapter.call(name, &dispatched_arguments).await {
        Ok(value)
            if name == "debugger.state"
                && value.get("instance_id").and_then(Value::as_str)
                    != Some(expected_instance_id.as_str()) =>
        {
            tool_failure(
                name,
                ToolError {
                    code: "BACKEND_IDENTITY_MISMATCH",
                    message: "plugin and sidecar instance identities do not match",
                    recoverable: true,
                    safe_to_retry: false,
                    suggested_action: Some(
                        "Restart the debugger host so the plugin and sidecar establish one identity."
                            .to_owned(),
                    ),
                    next_actions: Vec::new(),
                    details: json!({ "instance_id": instance_id }),
                },
            )
        }
        Ok(value) => tool_success(name, value),
        Err(error) => tool_failure(name, error),
    })
}

fn tool_success(name: &str, value: Value) -> Value {
    let text = content::success_summary(name, &value);
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": false
    })
}

fn tool_failure(name: &str, error: ToolError) -> Value {
    let debugger_message = error
        .details
        .get("debugger_message")
        .and_then(Value::as_str)
        .filter(|message| message.len() <= 512 && !message.chars().any(char::is_control));
    let mut text = debugger_message.map_or_else(
        || {
            format!(
                "{name} failed: {}: {}; recoverable={}; safeToRetry={}.",
                error.code, error.message, error.recoverable, error.safe_to_retry
            )
        },
        |message| {
            format!(
                "{name} failed: {}: {message}; recoverable={}; safeToRetry={}.",
                error.code, error.recoverable, error.safe_to_retry
            )
        },
    );
    let suggested_action = error.suggested_action.filter(|value| {
        !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
    });
    let next_actions: Vec<_> = error
        .next_actions
        .into_iter()
        .filter(NextAction::is_bounded)
        .take(4)
        .collect();
    let has_guidance = suggested_action.is_some() || !next_actions.is_empty();
    if let Some(state) = error
        .details
        .get("current_state")
        .or_else(|| error.details.get("debuggee_state"))
        .and_then(Value::as_str)
        .filter(|state| {
            !state.is_empty() && state.len() <= 64 && !state.chars().any(char::is_control)
        })
    {
        text.push_str("\nCurrent state: ");
        text.push_str(state);
        text.push('.');
    }
    let mut displayed_actions = 0_usize;
    if let Some(action) = suggested_action.as_deref() {
        text.push_str("\nNext: ");
        text.push_str(action);
        displayed_actions += 1;
    }
    for action in next_actions
        .iter()
        .take(2_usize.saturating_sub(displayed_actions))
    {
        text.push_str("\nNext (");
        text.push_str(&action.code);
        text.push_str("): ");
        if let Some(tool) = action.tool.as_deref() {
            text.push_str("call ");
            text.push_str(tool);
            text.push_str(" — ");
        }
        text.push_str(&action.reason);
    }
    let mut error_value = json!({
        "code": error.code,
        "message": error.message,
        "recoverable": error.recoverable,
        "safeToRetry": error.safe_to_retry,
        "details": error.details
    });
    let error_object = error_value
        .as_object_mut()
        .expect("tool error serialization is an object");
    if let Some(suggested_action) = suggested_action {
        error_object.insert(
            "suggestedAction".to_owned(),
            Value::String(suggested_action),
        );
    }
    if !next_actions.is_empty() {
        error_object.insert("nextActions".to_owned(), json!(next_actions));
    }
    if has_guidance {
        error_object.insert(
            "adviceSource".to_owned(),
            Value::String("x64dbg-mcp-backend".to_owned()),
        );
    }
    let value = json!({ "ok": false, "error": error_value });
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": true
    })
}

fn initialize(params: &Value, instance_id: Uuid) -> Result<Value, (i32, &'static str)> {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    if requested != Some(PROTOCOL_VERSION) {
        return Err((-32602, "Unsupported protocol version"));
    }
    Ok(json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "x64dbg-mcp-backend", "version": env!("CARGO_PKG_VERSION") },
        "_meta": { "x64dbg-mcp-backend/instance_id": instance_id }
    }))
}

fn rpc_error(id: Option<Value>, code: i32, message: &'static str) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": { "code": code, "message": message }
    }))
    .into_response()
}

#[cfg(test)]
mod contract_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use axum::body::to_bytes;
    use serde_json::{Value, json};

    use super::{handle, tool_failure};
    use crate::adapter::{
        ActionExecution, DebuggerAdapter, DisconnectedAdapter, NextAction, ToolError,
    };

    fn instance_id() -> uuid::Uuid {
        uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap()
    }

    struct RecordingAdapter {
        calls: AtomicUsize,
    }

    struct MemoryRecordingAdapter {
        calls: AtomicUsize,
        result: Value,
    }

    #[async_trait]
    impl DebuggerAdapter for RecordingAdapter {
        fn is_ready(&self) -> bool {
            true
        }

        async fn call(&self, name: &str, arguments: &Value) -> Result<Value, ToolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(name, "debugger.resume");
            assert!(arguments.get("instance_id").is_none());
            Ok(json!({"debuggee_state":"running","state_generation":8}))
        }
    }

    #[async_trait]
    impl DebuggerAdapter for MemoryRecordingAdapter {
        fn is_ready(&self) -> bool {
            true
        }

        async fn call(&self, name: &str, _arguments: &Value) -> Result<Value, ToolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(name, "memory.read");
            Ok(self.result.clone())
        }
    }

    fn next_u64(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(2_862_933_555_777_941_757)
            .wrapping_add(3_037_000_493);
        *state
    }

    fn generated_json(state: &mut u64, depth: usize) -> Value {
        let choice = next_u64(state) % if depth >= 5 { 4 } else { 7 };
        match choice {
            0 => Value::Null,
            1 => Value::Bool(next_u64(state) & 1 == 1),
            2 => json!(next_u64(state)),
            3 => {
                let length = (next_u64(state) % 96) as usize;
                Value::String(
                    (0..length)
                        .map(|_| char::from(0x20 + (next_u64(state) % 95) as u8))
                        .collect(),
                )
            }
            4 => Value::Array(
                (0..(next_u64(state) % 6))
                    .map(|_| generated_json(state, depth + 1))
                    .collect(),
            ),
            _ => {
                let mut values = serde_json::Map::new();
                for index in 0..(next_u64(state) % 6) {
                    values.insert(
                        format!("k{depth}_{index}"),
                        generated_json(state, depth + 1),
                    );
                }
                Value::Object(values)
            }
        }
    }

    async fn assert_golden(request: &str, expected: &str) {
        let response = handle(request.as_bytes(), &DisconnectedAdapter, instance_id()).await;
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let actual: Value = serde_json::from_slice(&bytes).unwrap();
        let expected: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn initialize_matches_golden_contract() {
        assert_golden(
            include_str!("../../../contracts/mcp/initialize.request.json"),
            include_str!("../../../contracts/mcp/initialize.response.json"),
        )
        .await;
    }

    #[tokio::test]
    async fn disconnected_tool_error_matches_golden_contract() {
        assert_golden(
            include_str!("../../../contracts/mcp/disconnected-state.request.json"),
            include_str!("../../../contracts/mcp/disconnected-state.response.json"),
        )
        .await;
    }

    #[test]
    fn checked_in_error_schema_has_one_non_legacy_contract() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../contracts/mcp/tool-error.schema.json"
        ))
        .unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("recoverable")));
        assert!(required.contains(&json!("safeToRetry")));
        assert!(schema["properties"].get("retryable").is_none());
        assert_eq!(schema["properties"]["nextActions"]["maxItems"], 4);
        assert_eq!(
            schema["properties"]["adviceSource"]["const"],
            "x64dbg-mcp-backend"
        );
    }

    #[test]
    fn bounded_debugger_diagnostic_is_included_in_content() {
        let result = tool_failure(
            "debuggee.launch",
            ToolError {
                code: "TIMEOUT",
                message: "debugger rejected the operation",
                recoverable: true,
                safe_to_retry: false,
                suggested_action: Some("Rename the analysis copy and try again.".to_owned()),
                next_actions: Vec::new(),
                details: json!({
                    "debugger_message": "x32dbg handles .PIF with ResolveShortcut before CreateProcessW; rename and try again",
                    "outcome": "unknown"
                }),
            },
        );
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("ResolveShortcut before CreateProcessW")
        );
        assert_eq!(result["structuredContent"]["error"]["recoverable"], true);
        assert_eq!(result["structuredContent"]["error"]["safeToRetry"], false);
        assert!(
            result["structuredContent"]["error"]
                .get("retryable")
                .is_none()
        );
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Next: Rename the analysis copy and try again.")
        );
    }

    #[test]
    fn invalid_or_oversized_guidance_is_omitted_at_the_serialization_boundary() {
        let mut action = NextAction::tool(
            "REFRESH_DEBUGGER_STATE",
            ActionExecution::Suggested,
            "Inspect state",
            "debugger.state",
            json!({}),
        );
        action.reason = "bad\nreason".to_owned();
        let result = tool_failure(
            "debugger.resume",
            ToolError {
                code: "BUSY",
                message: "debugger is busy",
                recoverable: true,
                safe_to_retry: true,
                suggested_action: Some("x".repeat(513)),
                next_actions: vec![action],
                details: json!({}),
            },
        );
        let error = &result["structuredContent"]["error"];
        assert!(error.get("suggestedAction").is_none());
        assert!(error.get("nextActions").is_none());
        assert!(error.get("adviceSource").is_none());
        assert!(
            !result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains(&"x".repeat(513))
        );
    }

    #[tokio::test]
    async fn memory_read_has_readable_content_and_unchanged_structured_result() {
        let exact = json!({
            "address":"0x1e56090",
            "location":{
                "address":"0x1e56090",
                "module":"checksum.exe",
                "module_base":"0x1e40000",
                "rva":"0x16090",
                "state_generation":42
            },
            "data_hex":"347f25a55f0d85dc650f6bbd24ad2f2a4142434400010203",
            "bytes_read":24,
            "complete":true,
            "state_generation":42
        });
        let adapter = MemoryRecordingAdapter {
            calls: AtomicUsize::new(0),
            result: exact.clone(),
        };
        let request = json!({
            "jsonrpc":"2.0",
            "id":5,
            "method":"tools/call",
            "params":{
                "name":"memory.read",
                "arguments":{"address":"0x1e56090","length":24}
            }
        });
        let response = handle(
            &serde_json::to_vec(&request).unwrap(),
            &adapter,
            instance_id(),
        )
        .await;
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["result"]["structuredContent"], exact);
        let content = value["result"]["content"][0]["text"].as_str().unwrap();
        assert!(content.starts_with("24 bytes at checksum.exe+0x16090 (0x1e56090)"));
        assert!(content.contains("34 7F 25 A5 5F 0D 85 DC  65 0F 6B BD 24 AD 2F 2A"));
        assert!(!content.contains("347f25a55f0d85dc650f6bbd24ad2f2a"));
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_mutation_is_rejected_before_adapter_dispatch() {
        let adapter = RecordingAdapter {
            calls: AtomicUsize::new(0),
        };
        let stale_id = uuid::Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap();
        let request = json!({
            "jsonrpc":"2.0",
            "id":3,
            "method":"tools/call",
            "params":{
                "name":"debugger.resume",
                "arguments":{
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "instance_id":stale_id
                }
            }
        });
        let response = handle(
            &serde_json::to_vec(&request).unwrap(),
            &adapter,
            instance_id(),
        )
        .await;
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["result"]["isError"], true);
        assert_eq!(
            value["result"]["structuredContent"]["error"]["code"],
            "BACKEND_RESTARTED"
        );
        assert_eq!(
            value["result"]["structuredContent"]["error"]["recoverable"],
            true
        );
        assert_eq!(
            value["result"]["structuredContent"]["error"]["safeToRetry"],
            false
        );
        assert!(
            value["result"]["structuredContent"]["error"]
                .get("retryable")
                .is_none()
        );
        assert_eq!(
            value["result"]["structuredContent"]["error"]["details"]["outcome"],
            "not_started"
        );
        assert!(
            value["result"]["structuredContent"]["error"]["details"]
                .get("diagnostic_code")
                .is_none()
        );
        assert_eq!(
            value["result"]["structuredContent"]["error"]["nextActions"][0]["tool"],
            "debugger.state"
        );
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn current_mutation_dispatches_without_public_identity_field() {
        let adapter = RecordingAdapter {
            calls: AtomicUsize::new(0),
        };
        let request = json!({
            "jsonrpc":"2.0",
            "id":4,
            "method":"tools/call",
            "params":{
                "name":"debugger.resume",
                "arguments":{
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "instance_id":instance_id()
                }
            }
        });
        let response = handle(
            &serde_json::to_vec(&request).unwrap(),
            &adapter,
            instance_id(),
        )
        .await;
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["result"]["isError"], false);
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn request_shape_and_json_complexity_are_bounded() {
        let extra = handle(
            br#"{"jsonrpc":"2.0","id":1,"method":"ping","extra":true}"#,
            &DisconnectedAdapter,
            instance_id(),
        )
        .await;
        let bytes = to_bytes(extra.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["error"]["code"], -32600);

        let invalid_id = handle(
            br#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
            &DisconnectedAdapter,
            instance_id(),
        )
        .await;
        let bytes = to_bytes(invalid_id.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["error"]["code"], -32600);

        let mut params = serde_json::json!({});
        for _ in 0..40 {
            params = serde_json::json!({"nested": params});
        }
        let request = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "ping", "params": params
        });
        let deep = handle(
            &serde_json::to_vec(&request).unwrap(),
            &DisconnectedAdapter,
            instance_id(),
        )
        .await;
        let bytes = to_bytes(deep.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn deterministic_mcp_body_corpus_returns_bounded_protocol_responses() {
        const SEED: u64 = 0x4d43_505f_4a53_4f4e;
        const CASES: usize = 2_048;
        let mut state = SEED;
        for case in 0..CASES {
            let method = match case % 5 {
                0 => "ping",
                1 => "initialize",
                2 => "tools/list",
                3 => "tools/call",
                _ => "unknown.method",
            };
            let request = json!({
                "jsonrpc": if case % 17 == 0 { "1.0" } else { "2.0" },
                "id": case,
                "method": method,
                "params": generated_json(&mut state, 0),
            });
            let response = handle(
                &serde_json::to_vec(&request).unwrap(),
                &DisconnectedAdapter,
                instance_id(),
            )
            .await;
            let bytes = to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap_or_else(|error| panic!("seed={SEED:#x} case={case}: {error}"));
            assert!(bytes.len() <= 64 * 1024, "seed={SEED:#x} case={case}");
            let value: Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("seed={SEED:#x} case={case}: {error}"));
            assert_eq!(value["jsonrpc"], "2.0", "seed={SEED:#x} case={case}");
            assert!(
                value.get("result").is_some() || value.get("error").is_some(),
                "seed={SEED:#x} case={case}"
            );
        }

        for case in 0..CASES {
            let length = (next_u64(&mut state) % 4_097) as usize;
            let mut body = vec![0_u8; length];
            for byte in &mut body {
                *byte = u8::try_from(next_u64(&mut state) & 0xff).unwrap();
            }
            let response = handle(&body, &DisconnectedAdapter, instance_id()).await;
            let bytes = to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap_or_else(|error| panic!("seed={SEED:#x} raw_case={case}: {error}"));
            let value: Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("seed={SEED:#x} raw_case={case}: {error}"));
            assert_eq!(value["jsonrpc"], "2.0", "seed={SEED:#x} raw_case={case}");
        }
    }
}
