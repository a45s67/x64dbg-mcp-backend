use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    Json, Router,
    body::{Bytes, to_bytes},
    extract::{DefaultBodyLimit, State, rejection::BytesRejection},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    adapter::{DebuggerAdapter, DisconnectedAdapter},
    config::Config,
    error::HttpError,
    mcp,
};

#[derive(Clone)]
pub struct AppState {
    config: Arc<Config>,
    in_flight: Arc<Semaphore>,
    adapter: Arc<dyn DebuggerAdapter>,
    rate_window: Arc<Mutex<RateWindow>>,
}

struct RateWindow {
    started: Instant,
    requests: usize,
}

impl AppState {
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        Self::with_adapter(config, Arc::new(DisconnectedAdapter))
    }

    pub fn with_adapter(config: Arc<Config>, adapter: Arc<dyn DebuggerAdapter>) -> Self {
        let in_flight = Arc::new(Semaphore::new(config.max_inflight));
        Self {
            config,
            in_flight,
            adapter,
            rate_window: Arc::new(Mutex::new(RateWindow {
                started: Instant::now(),
                requests: 0,
            })),
        }
    }
}

pub fn router(state: AppState) -> Router {
    let max_body_bytes = state.config.max_body_bytes;
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/mcp", post(mcp_post).get(mcp_get))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_http_limits,
        ))
        .with_state(state)
}

async fn enforce_http_limits(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, HttpError> {
    let headers = request.headers();
    let header_bytes = headers.iter().try_fold(0_usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())?
            .checked_add(value.as_bytes().len())
    });
    if headers.len() > state.config.max_header_count
        || header_bytes.is_none_or(|bytes| bytes > state.config.max_header_bytes)
    {
        return Err(HttpError::new(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "HEADERS_TOO_LARGE",
            "request headers exceed configured limits",
        ));
    }

    let allowed = {
        let mut window = state.rate_window.lock().map_err(|_| {
            HttpError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "request limiter unavailable",
            )
        })?;
        if window.started.elapsed().as_secs() >= 1 {
            window.started = Instant::now();
            window.requests = 0;
        }
        if window.requests >= state.config.max_requests_per_second {
            false
        } else {
            window.requests += 1;
            true
        }
    };
    if !allowed {
        return Err(HttpError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            "request rate limit reached",
        ));
    }
    let _permit = acquire(&state)?;
    Ok(next.run(request).await)
}

async fn live() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        "{\"status\":\"ok\"}",
    )
}

async fn ready(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, HttpError> {
    authenticate(&state, &headers)?;
    authorize_origin(&state, &headers)?;
    if !state.adapter.is_ready() {
        return Ok(not_ready());
    }
    let Ok(snapshot) = state.adapter.call("debugger.state", &json!({})).await else {
        return Ok(not_ready());
    };
    Ok(Json(json!({
        "status": "ready",
        "backend": snapshot.get("backend").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
        "plugin_connected": true,
        "debugger_state": snapshot.get("debuggee_state").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
        "protocol_version": "2025-06-18",
        "version": env!("CARGO_PKG_VERSION")
    }))
    .into_response())
}

fn not_ready() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "status": "not_ready",
            "plugin_connected": false
        })),
    )
        .into_response()
}

async fn mcp_get() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response()
}

async fn mcp_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, HttpError> {
    authenticate(&state, &headers)?;
    authorize_origin(&state, &headers)?;
    require_json_content_type(&headers)?;
    require_json_accept(&headers)?;
    require_protocol_version(&headers)?;
    let body = body.map_err(|_| {
        HttpError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "REQUEST_TOO_LARGE",
            "request body exceeds configured limit",
        )
    })?;
    let response = mcp::handle(&body, state.adapter.as_ref()).await;
    bound_response(response, state.config.max_output_bytes).await
}

fn require_protocol_version(headers: &HeaderMap) -> Result<(), HttpError> {
    let valid = headers
        .get("mcp-protocol-version")
        .is_none_or(|value| value.as_bytes() == b"2025-06-18");
    valid.then_some(()).ok_or(HttpError::new(
        StatusCode::BAD_REQUEST,
        "INVALID_PROTOCOL_VERSION",
        "unsupported MCP protocol version",
    ))
}

fn authorize_origin(state: &AppState, headers: &HeaderMap) -> Result<(), HttpError> {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return Ok(());
    };
    let allowed = origin
        .to_str()
        .is_ok_and(|value| state.config.origin_allowed(value));
    allowed.then_some(()).ok_or(HttpError::new(
        StatusCode::FORBIDDEN,
        "ORIGIN_NOT_ALLOWED",
        "browser origin is not allowed",
    ))
}

async fn bound_response(response: Response, limit: usize) -> Result<Response, HttpError> {
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, limit).await.map_err(|_| {
        HttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "OUTPUT_LIMIT_EXCEEDED",
            "response exceeds configured output limit",
        )
    })?;
    Ok(Response::from_parts(parts, bytes.into()))
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<(), HttpError> {
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "))
        .unwrap_or_default();
    let expected = state.config.bearer_token();
    let valid = supplied.len() == expected.len() && supplied.ct_eq(expected).into();
    if valid {
        Ok(())
    } else {
        Err(HttpError::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "authentication required",
        ))
    }
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), HttpError> {
    let valid = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    valid.then_some(()).ok_or(HttpError::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "INVALID_CONTENT_TYPE",
        "Content-Type must be application/json",
    ))
}

fn require_json_accept(headers: &HeaderMap) -> Result<(), HttpError> {
    let valid = headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value.split(',').any(|part| {
                let mime = part.split(';').next().unwrap_or_default().trim();
                mime == "*/*" || mime.eq_ignore_ascii_case("application/json")
            })
        });
    valid.then_some(()).ok_or(HttpError::new(
        StatusCode::NOT_ACCEPTABLE,
        "INVALID_ACCEPT",
        "Accept must allow application/json",
    ))
}

fn acquire(state: &AppState) -> Result<OwnedSemaphorePermit, HttpError> {
    Arc::clone(&state.in_flight)
        .try_acquire_owned()
        .map_err(|_| {
            HttpError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "BUSY",
                "request concurrency limit reached",
            )
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::{Body, to_bytes},
        http::{HeaderName, HeaderValue, Request, StatusCode, header},
        response::IntoResponse,
    };
    use serde_json::Value;
    use tower::ServiceExt;

    use super::{AppState, bound_response, router};
    use crate::{adapter::FakeAdapter, config::Config};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn app() -> axum::Router {
        router(AppState::with_adapter(
            Arc::new(Config::for_test(TOKEN)),
            Arc::new(FakeAdapter),
        ))
    }

    #[tokio::test]
    async fn liveness_is_public_and_bounded() {
        let response = app()
            .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 128).await.unwrap();
        assert_eq!(&body[..], br#"{"status":"ok"}"#);
    }

    #[tokio::test]
    async fn oversized_response_is_replaced_with_structured_http_error() {
        let response = axum::body::Body::from("0123456789").into_response();
        let error = bound_response(response, 5).await.unwrap_err();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "OUTPUT_LIMIT_EXCEEDED");
    }

    #[tokio::test]
    async fn readiness_requires_bearer_authentication() {
        let response = app()
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }

    #[tokio::test]
    async fn authenticated_fake_adapter_is_ready() {
        let response = app()
            .oneshot(
                Request::get("/health/ready")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authenticated_disconnected_adapter_is_not_ready() {
        let app = router(AppState::new(Arc::new(Config::for_test(TOKEN))));
        let response = app
            .oneshot(
                Request::get("/health/ready")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn browser_origin_is_rejected_by_default_before_mcp_parsing() {
        let response = app()
            .oneshot(
                Request::post("/mcp")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .header(header::ORIGIN, "https://example.invalid")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::from("not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn initialize_contract_is_json_rpc() {
        let request = Request::post("/mcp")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
            ))
            .unwrap();
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(value["result"]["serverInfo"]["name"], "x64dbg-mcp-backend");
    }

    #[tokio::test]
    async fn tools_list_exposes_the_bounded_catalog() {
        let value =
            mcp_request(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#).await;
        let tools = value["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 20);
        assert!(tools.iter().any(|tool| tool["name"] == "debugger.state"));
        assert!(
            tools
                .iter()
                .any(|tool| tool["name"] == "debugger.wait_for_pause")
        );
        assert!(tools.iter().any(|tool| tool["name"] == "address.resolve"));
        assert!(tools.iter().any(|tool| tool["name"] == "memory.write"));
    }

    #[tokio::test]
    async fn tools_call_returns_text_and_matching_structured_content() {
        let value = mcp_request(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"debugger.state","arguments":{}}}"#,
        )
        .await;
        let result = &value["result"];
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["debuggee_state"], "paused");
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, result["structuredContent"]);
    }

    #[tokio::test]
    async fn structured_module_relative_address_matches_the_contract() {
        let value = mcp_request(
            r#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"address.resolve","arguments":{"address":{"module":"sample.exe","rva":"0x1000"}}}}"#,
        )
        .await;
        let result = &value["result"];
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["address"], "0x0000000140001000");
        assert_eq!(result["structuredContent"]["module"], "sample.exe");
        assert_eq!(result["structuredContent"]["rva"], "0x1000");
        assert_eq!(result["structuredContent"]["state_generation"], 7);
    }

    #[tokio::test]
    async fn callback_pause_observation_matches_the_contract() {
        let value = mcp_request(
            r#"{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"debugger.wait_for_pause","arguments":{"after_generation":7,"timeout_ms":5000}}}"#,
        )
        .await;
        let result = &value["result"];
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["state_generation"], 8);
        assert_eq!(
            result["structuredContent"]["pause_reason"]["kind"],
            "breakpoint"
        );
        assert_eq!(result["structuredContent"]["pause_reason"]["hit_count"], 1);
    }

    #[tokio::test]
    async fn mutation_without_operation_id_is_rejected_before_adapter_dispatch() {
        let value = mcp_request(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"debugger.resume","arguments":{}}}"#,
        )
        .await;
        assert_eq!(value["result"]["isError"], true);
        assert_eq!(
            value["result"]["structuredContent"]["error"]["code"],
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            value["result"]["structuredContent"]["error"]["details"]["field"],
            "operation_id"
        );
    }

    async fn mcp_request(body: &'static str) -> Value {
        let request = Request::post("/mcp")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::from(body))
            .unwrap();
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn mcp_get_is_explicitly_unsupported() {
        let response = app()
            .oneshot(
                Request::get("/mcp")
                    .header(header::ACCEPT, "text/event-stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "POST");
    }

    #[tokio::test]
    async fn invalid_mcp_protocol_header_is_rejected() {
        let response = app()
            .oneshot(
                Request::post("/mcp")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header("mcp-protocol-version", "2024-11-05")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oversized_request_has_a_structured_error() {
        let response = app()
            .oneshot(
                Request::post("/mcp")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::from(vec![b'x'; 1024 * 1024 + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["error"]["code"], "REQUEST_TOO_LARGE");
    }

    #[tokio::test]
    async fn excessive_header_count_is_rejected_before_routing() {
        let mut request = Request::get("/health/live").body(Body::empty()).unwrap();
        for index in 0..65 {
            request.headers_mut().insert(
                HeaderName::from_bytes(format!("x-test-{index}").as_bytes()).unwrap(),
                HeaderValue::from_static("x"),
            );
        }
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn request_rate_is_hard_bounded() {
        let app = app();
        for _ in 0..100 {
            let response = app
                .clone()
                .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = app
            .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
