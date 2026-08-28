use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    adapter::{DebuggerAdapter, ToolError},
    tools,
};

const PROTOCOL_VERSION: &str = "2025-06-18";
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

pub async fn handle(body: &[u8], adapter: &dyn DebuggerAdapter) -> Response {
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
        "initialize" => initialize(&request.params),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools::catalog() })),
        "tools/call" => call_tool(&request.params, adapter).await,
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
        return Ok(tool_failure(ToolError {
            code: "INVALID_ARGUMENT",
            message: error.message,
            retryable: false,
            details: json!({ "field": error.field }),
        }));
    }
    Ok(match adapter.call(name, arguments).await {
        Ok(value) => tool_success(value),
        Err(error) => tool_failure(error),
    })
}

fn tool_success(value: Value) -> Value {
    let text = serde_json::to_string(&value).expect("serializing a JSON value cannot fail");
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": false
    })
}

fn tool_failure(error: ToolError) -> Value {
    let value = json!({
        "ok": false,
        "error": {
            "code": error.code,
            "message": error.message,
            "retryable": error.retryable,
            "details": error.details
        }
    });
    let text = serde_json::to_string(&value).expect("serializing a JSON value cannot fail");
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": true
    })
}

fn initialize(params: &Value) -> Result<Value, (i32, &'static str)> {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    if requested != Some(PROTOCOL_VERSION) {
        return Err((-32602, "Unsupported protocol version"));
    }
    Ok(json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "x64dbg-mcp-backend", "version": env!("CARGO_PKG_VERSION") }
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
    use axum::body::to_bytes;
    use serde_json::{Value, json};

    use super::handle;
    use crate::adapter::DisconnectedAdapter;

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
        let response = handle(request.as_bytes(), &DisconnectedAdapter).await;
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

    #[tokio::test]
    async fn request_shape_and_json_complexity_are_bounded() {
        let extra = handle(
            br#"{"jsonrpc":"2.0","id":1,"method":"ping","extra":true}"#,
            &DisconnectedAdapter,
        )
        .await;
        let bytes = to_bytes(extra.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["error"]["code"], -32600);

        let invalid_id = handle(
            br#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
            &DisconnectedAdapter,
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
        let deep = handle(&serde_json::to_vec(&request).unwrap(), &DisconnectedAdapter).await;
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
            let response =
                handle(&serde_json::to_vec(&request).unwrap(), &DisconnectedAdapter).await;
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
            let response = handle(&body, &DisconnectedAdapter).await;
            let bytes = to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap_or_else(|error| panic!("seed={SEED:#x} raw_case={case}: {error}"));
            let value: Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("seed={SEED:#x} raw_case={case}: {error}"));
            assert_eq!(value["jsonrpc"], "2.0", "seed={SEED:#x} raw_case={case}");
        }
    }
}
