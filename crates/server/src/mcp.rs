use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

use crate::{
    adapter::{ActionExecution, DebuggerAdapter, NextAction, ToolError},
    tools,
};

pub const PROTOCOL_VERSION: &str = "2025-11-25";
pub const CODEX_PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_STRING_BYTES: usize = 8_192;
const MAX_JSON_CONTAINER_ITEMS: usize = 512;

#[must_use]
pub fn is_supported_protocol_version(version: &str) -> bool {
    version == PROTOCOL_VERSION || version == CODEX_PROTOCOL_VERSION
}

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
    handle_inner(body, adapter, instance_id, None).await
}

pub async fn handle_with_log(
    body: &[u8],
    adapter: &dyn DebuggerAdapter,
    instance_id: Uuid,
    log: &Arc<crate::audit_log::AuditLog>,
) -> Response {
    let call_id = Uuid::new_v4();
    let request = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
    let name = request.pointer("/params/name").and_then(Value::as_str);
    let metadata_only = matches!(name, Some("logs.read" | "logs.status"));
    let metadata = json!({"call_id":call_id,"rpc_id":request.get("id"),"method":request.get("method"),"tool":name,"operation_id":request.pointer("/params/arguments/operation_id"),"request_bytes":body.len()});
    log.record(
        "request",
        if metadata_only {
            metadata.clone()
        } else {
            json!({"metadata":metadata,"request":request})
        },
    );
    let response = handle_inner(body, adapter, instance_id, Some(Arc::clone(log))).await;
    let (parts, body) = response.into_parts();
    if let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await {
        let mut response = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        if let Some(result) = response.get_mut("result")
            && let Some(decoded) = result
                .pointer("/content/0/text")
                .and_then(Value::as_str)
                .and_then(|text| serde_json::from_str::<Value>(text).ok())
        {
            *result = json!({"payload":decoded,"isError":result.get("isError")});
        }
        log.record(
            "response",
            if metadata_only {
                json!({"metadata":metadata,"output_bytes":bytes.len(),"metadata_only":true})
            } else {
                json!({"metadata":metadata,"output_bytes":bytes.len(),"response":response})
            },
        );
        Response::from_parts(parts, bytes.into())
    } else {
        log.record("response_failure", metadata);
        rpc_error(None, -32603, "Response serialization failed")
    }
}

async fn handle_inner(
    body: &[u8],
    adapter: &dyn DebuggerAdapter,
    instance_id: Uuid,
    log: Option<Arc<crate::audit_log::AuditLog>>,
) -> Response {
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
        "tools/call" => call_tool(&request.params, adapter, instance_id, log.as_ref()).await,
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
    log: Option<&Arc<crate::audit_log::AuditLog>>,
) -> Result<Value, (i32, &'static str)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "Missing tool name"))?;
    if !tools::exists(name) && !matches!(name, "logs.read" | "logs.status") {
        return Err((-32602, "Unknown tool name"));
    }
    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    if !arguments.is_object() {
        return Err((-32602, "Tool arguments must be an object"));
    }
    if let Err(error) = tools::validate_arguments(name, arguments) {
        return Ok(tool_failure(ToolError {
            code: "INVALID_ARGUMENT",
            message: error.message,
            recoverable: true,
            safe_to_retry: false,
            suggested_action: Some(
                "Correct the reported field before calling the tool again.".to_owned(),
            ),
            next_actions: Vec::new(),
            details: json!({ "field": error.field }),
        }));
    }
    if name == "events.wait"
        && let Some(log) = log
    {
        let wait = log.arm_event_wait();
        let barrier = match adapter.call("events.list", &json!({"limit":1})).await {
            Ok(value) => value,
            Err(error) => return Ok(tool_failure(error)),
        };
        let Some(after_sequence) = barrier.get("latest_sequence").and_then(Value::as_u64) else {
            return Ok(tool_failure(ToolError::new(
                "INTERNAL",
                "native event barrier omitted latest_sequence",
                false,
                false,
                json!({}),
            )));
        };
        let Some(session_id) = barrier.get("session_id").and_then(Value::as_str) else {
            return Ok(tool_failure(ToolError::new(
                "INTERNAL",
                "native event barrier omitted session_id",
                false,
                false,
                json!({}),
            )));
        };
        return Ok(
            match log
                .wait_event(wait, arguments, after_sequence, session_id)
                .await
            {
                Ok(value) => tool_success(value),
                Err(error) => tool_failure(error),
            },
        );
    }
    if matches!(name, "logs.read" | "logs.status") {
        let Some(log) = log else {
            return Ok(tool_failure(ToolError::new(
                "LOG_STORE_UNAVAILABLE",
                "audit store is unavailable",
                true,
                false,
                json!({}),
            )));
        };
        let log = Arc::clone(log);
        let arguments = arguments.clone();
        let status = name == "logs.status";
        let task = tokio::task::spawn_blocking(move || {
            if status {
                Ok(log.status())
            } else {
                log.read(&arguments)
            }
        });
        return Ok(
            match tokio::time::timeout(Duration::from_secs(2), task).await {
                Ok(Ok(Ok(value))) => tool_success(value),
                Ok(Ok(Err(error))) => tool_failure(error),
                Ok(Err(_)) => tool_failure(ToolError::new(
                    "INTERNAL",
                    "audit log worker failed",
                    false,
                    false,
                    json!({}),
                )),
                Err(_) => tool_failure(ToolError::new(
                    "TIMEOUT",
                    "audit log operation exceeded its deadline",
                    true,
                    true,
                    json!({}),
                )),
            },
        );
    }
    let mut dispatched_arguments = if name == "memory.read" {
        crate::memory_view::native_arguments(arguments)
    } else {
        arguments.clone()
    };
    if tools::is_mutation_call(name, arguments) {
        let supplied = arguments
            .get("instance_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .expect("validated mutation instance_id must be a UUID");
        if supplied != instance_id {
            return Ok(tool_failure(
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
            tool_failure(ToolError {
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
            })
        }
        Ok(value) if name == "memory.read" => match crate::memory_view::apply(arguments, value) {
            Ok(value) => tool_success(value),
            Err(error) => tool_failure(error),
        },
        Ok(value) => tool_success(value),
        Err(error) => tool_failure(error),
    })
}

fn tool_success(value: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": value.to_string() }],
        "isError": false
    })
}

fn tool_failure(error: ToolError) -> Value {
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
        "content": [{ "type": "text", "text": value.to_string() }],
        "isError": true
    })
}

fn initialize(params: &Value, instance_id: Uuid) -> Result<Value, (i32, &'static str)> {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    if !requested.is_some_and(is_supported_protocol_version) {
        return Err((-32602, "Unsupported protocol version"));
    }
    let negotiated = requested.expect("supported protocol version is present");
    Ok(json!({
        "protocolVersion": negotiated,
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

    use super::{CODEX_PROTOCOL_VERSION, handle, tool_failure};
    use crate::adapter::{
        ActionExecution, DebuggerAdapter, DisconnectedAdapter, NextAction, ToolError,
    };

    fn instance_id() -> uuid::Uuid {
        uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap()
    }

    fn content_payload(result: &Value, is_error: bool) -> Value {
        assert!(result.get("structuredContent").is_none());
        let payload: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(
            result,
            &json!({
                "content": [{"type": "text", "text": payload.to_string()}],
                "isError": is_error
            })
        );
        payload
    }

    struct RecordingAdapter {
        calls: AtomicUsize,
    }

    struct MemoryRecordingAdapter {
        calls: AtomicUsize,
        result: Value,
        expected_arguments: Value,
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

        async fn call(&self, name: &str, arguments: &Value) -> Result<Value, ToolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(name, "memory.read");
            assert_eq!(arguments, &self.expected_arguments);
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
    async fn initialize_negotiates_codex_protocol_version() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": CODEX_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "codex", "version": "test" }
            }
        });
        let response = handle(
            &serde_json::to_vec(&request).unwrap(),
            &DisconnectedAdapter,
            instance_id(),
        )
        .await;
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["result"]["protocolVersion"], CODEX_PROTOCOL_VERSION);
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
    fn debugger_diagnostic_and_guidance_are_preserved_in_json_content() {
        let result = tool_failure(ToolError {
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
        });
        assert_eq!(
            content_payload(&result, true),
            json!({
                "ok": false,
                "error": {
                    "code": "TIMEOUT",
                    "message": "debugger rejected the operation",
                    "recoverable": true,
                    "safeToRetry": false,
                    "suggestedAction": "Rename the analysis copy and try again.",
                    "adviceSource": "x64dbg-mcp-backend",
                    "details": {
                        "debugger_message": "x32dbg handles .PIF with ResolveShortcut before CreateProcessW; rename and try again",
                        "outcome": "unknown"
                    }
                }
            })
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
        let result = tool_failure(ToolError {
            code: "BUSY",
            message: "debugger is busy",
            recoverable: true,
            safe_to_retry: true,
            suggested_action: Some("x".repeat(513)),
            next_actions: vec![action],
            details: json!({}),
        });
        let payload = content_payload(&result, true);
        let error = &payload["error"];
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
    async fn memory_read_has_one_json_content_item_with_unchanged_payload() {
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
            expected_arguments: json!({"address":"0x1e56090","length":24}),
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
        assert_eq!(content_payload(&value["result"], false), exact);
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn memory_read_presentation_options_are_server_local() {
        let adapter = MemoryRecordingAdapter {
            calls: AtomicUsize::new(0),
            result: json!({"data_hex":"01020304","bytes_read":4,"complete":true}),
            expected_arguments: json!({"address":"0x1000","length":4}),
        };
        let request = json!({
            "jsonrpc":"2.0",
            "id":6,
            "method":"tools/call",
            "params":{
                "name":"memory.read",
                "arguments":{
                    "address":"0x1000",
                    "length":4,
                    "format":"word",
                    "byte_order":"big"
                }
            }
        });
        let response = handle(
            &serde_json::to_vec(&request).unwrap(),
            &adapter,
            instance_id(),
        )
        .await;
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let payload = content_payload(&value["result"], false);
        assert_eq!(payload["data_hex"], "01020304");
        assert_eq!(
            payload["view"],
            json!({"format":"word","byte_order":"big","values":["0x0102","0x0304"]})
        );
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn guidance_filtering_keeps_byte_limits_action_order_and_four_action_cap() {
        let actions: Vec<_> = (0..6)
            .map(|index| {
                NextAction::tool(
                    &format!("ACTION_{index}"),
                    ActionExecution::RequiredBeforeRetry,
                    "Inspect \u{754c} state",
                    "debugger.state",
                    json!({"index":index,"nested":{"text":"\u{754c}\n\0"}}),
                )
            })
            .collect();
        let mut invalid = actions[0].clone();
        invalid.reason = "bad\nreason".to_owned();
        let mut supplied = vec![invalid.clone(), actions[0].clone(), invalid];
        supplied.extend_from_slice(&actions[1..]);

        for (guidance, accepted) in [
            (None, false),
            (Some(String::new()), false),
            (Some("bad\nreason".to_owned()), false),
            (Some("bad\u{85}reason".to_owned()), false),
            (Some("x".repeat(513)), false),
            (Some("\u{754c}".repeat(171)), false),
            (Some("x".repeat(512)), true),
            (Some(format!("{}ab", "\u{754c}".repeat(170))), true),
        ] {
            for next_actions in [vec![], supplied.clone()] {
                let has_actions = !next_actions.is_empty();
                let result = tool_failure(ToolError {
                    code: "BUSY",
                    message: "debugger is busy",
                    recoverable: true,
                    safe_to_retry: true,
                    suggested_action: guidance.clone(),
                    next_actions,
                    details: json!({"diagnostic":"unchanged\n\0\u{754c}"}),
                });
                let mut expected = json!({
                    "code":"BUSY","message":"debugger is busy","recoverable":true,
                    "safeToRetry":true,"details":{"diagnostic":"unchanged\n\0\u{754c}"}
                });
                if accepted {
                    expected["suggestedAction"] = json!(guidance);
                }
                if has_actions {
                    expected["nextActions"] = json!(&actions[..4]);
                }
                if accepted || has_actions {
                    expected["adviceSource"] = json!("x64dbg-mcp-backend");
                }
                assert_eq!(
                    content_payload(&result, true),
                    json!({"ok":false,"error":expected})
                );
            }
        }
    }

    #[test]
    fn next_action_serialized_byte_boundary_is_preserved() {
        let mut action = NextAction::tool(
            "INSPECT_STATE",
            ActionExecution::Suggested,
            "Inspect state",
            "debugger.state",
            json!({"text":"\u{754c}\n\0\"\\","padding":""}),
        );
        let overhead = serde_json::to_vec(&action).unwrap().len();
        for size in [4096, 4097] {
            action.arguments.as_mut().unwrap()["padding"] = json!("x".repeat(size - overhead));
            assert_eq!(serde_json::to_vec(&action).unwrap().len(), size);
            let result = tool_failure(
                ToolError::new("BUSY", "debugger is busy", true, false, json!({}))
                    .with_guidance("", vec![action.clone()]),
            );
            let mut expected = json!({"ok":false,"error":{
                "code":"BUSY","message":"debugger is busy","recoverable":true,
                "safeToRetry":false,"details":{}
            }});
            if size == 4096 {
                expected["error"]["nextActions"] = json!([action]);
                expected["error"]["adviceSource"] = json!("x64dbg-mcp-backend");
            }
            assert_eq!(content_payload(&result, true), expected);
        }
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
        let payload = content_payload(&value["result"], true);
        assert_eq!(payload["error"]["code"], "BACKEND_RESTARTED");
        assert_eq!(payload["error"]["recoverable"], true);
        assert_eq!(payload["error"]["safeToRetry"], false);
        assert!(payload["error"].get("retryable").is_none());
        assert_eq!(payload["error"]["details"]["outcome"], "not_started");
        assert!(payload["error"]["details"].get("diagnostic_code").is_none());
        assert_eq!(payload["error"]["nextActions"][0]["tool"], "debugger.state");
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
        assert_eq!(
            content_payload(&value["result"], false),
            json!({
                "debuggee_state": "running", "state_generation": 8
            })
        );
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
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap_or_else(|error| panic!("seed={SEED:#x} case={case}: {error}"));
            assert!(bytes.len() <= 1024 * 1024, "seed={SEED:#x} case={case}");
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
