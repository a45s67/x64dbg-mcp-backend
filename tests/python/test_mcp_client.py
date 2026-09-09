import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from urllib.error import HTTPError

import pytest

from mcp_client import McpClient, ProtocolError, RpcError, ToolError, decode_tool_result


def envelope(payload, is_error=False):
    return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "isError": is_error}


@pytest.mark.parametrize("payload", [
    None, [], True, 2**64 - 1, -(2**63), "\u5169\u500b\u5b57\n\"\\",
    {"items": list(range(2000)), "next_cursor": "opaque+/=\\\n\u00e9",
     "hex": "00ff" * 4096, "nested": {"integer": 2**64 - 1}},
])
def test_full_content_round_trip(payload):
    assert decode_tool_result(envelope(payload)) == payload


@pytest.mark.parametrize("result", [
    None, [], {}, {"content": [], "isError": False},
    {"content": [{"type": "text", "text": "{}"}], "isError": 0},
    {"content": [{"type": "text", "text": "{}"}]},
    {**envelope({}), "structuredContent": {}},
    {"content": [envelope({})["content"][0]] * 2, "isError": False},
    {"content": [{"type": "image", "text": "{}"}], "isError": False},
    {"content": [{"type": "text", "text": {}}], "isError": False},
    {"content": [None], "isError": False},
    *[{"content": [{"type": "text", "text": text}], "isError": False}
      for text in ("", "Summary only", '{"truncated":', "NaN", "Infinity", '{"a":1,"a":2}')],
    envelope({}, True), envelope({"ok": 0, "error": {}}, True), envelope([], True),
])
def test_rejects_malformed_or_legacy_content(result):
    with pytest.raises(ProtocolError):
        decode_tool_result(result)


@pytest.fixture
def endpoint():
    requests = []
    replies = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            requests.append((self.path, dict(self.headers), json.loads(data) if data else None))
            status, headers, payload = replies.pop(0)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(json.dumps(payload, ensure_ascii=False).encode("utf-8"))

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield McpClient(f"http://127.0.0.1:{server.server_port}", "test-token"), requests, replies
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def reply(result, request_id=1):
    return 200, {}, {"jsonrpc": "2.0", "id": request_id, "result": result}


def test_http_utf8_authentication_and_request_ids(endpoint):
    client, requests, replies = endpoint
    payload = {"value": "\u5169\u500b\u5b57", "integer": 2**64 - 1}
    replies.extend([reply(envelope(payload), "read"), reply({})])
    assert client.tool("example.read", {"expression": "\u5169\u500b\u5b57"}, "read") == payload
    assert client.rpc("ping", {}) == {}
    path, headers, body = requests[0]
    assert path == "/mcp"
    assert headers["Authorization"] == "Bearer test-token"
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert body == {"jsonrpc": "2.0", "id": "read", "method": "tools/call",
                    "params": {"name": "example.read", "arguments": {"expression": "\u5169\u500b\u5b57"}}}
    assert requests[1][2]["id"] == 1


def test_mutation_identity_injection_does_not_modify_caller(endpoint):
    client, requests, replies = endpoint
    client.instance_id = "current-instance"
    arguments = {"operation_id": "same-operation", "nested": {"values": [1]}}
    original = copy.deepcopy(arguments)
    replies.extend([reply(envelope({}), i) for i in range(1, 4)])
    client.tool("example.write", arguments)
    client.tool("example.write", arguments)
    client.tool("example.write", {**arguments, "instance_id": "stale-instance"})
    assert arguments == original
    assert requests[0][2]["params"] == requests[1][2]["params"]
    assert requests[0][2]["params"]["arguments"]["instance_id"] == "current-instance"
    assert requests[2][2]["params"]["arguments"]["instance_id"] == "stale-instance"


def test_unobserved_identity_fails_without_sending(endpoint):
    client, requests, _ = endpoint
    with pytest.raises(ProtocolError, match="identity"):
        client.tool("example.write", {"operation_id": "operation"})
    assert requests == []


def test_tool_error_is_distinct_from_rpc_error_and_is_not_retried(endpoint):
    client, requests, replies = endpoint
    client.instance_id = "instance"
    failure = {"ok": False, "error": {"code": "BUSY", "safeToRetry": True,
                                     "details": {"outcome": "unknown", "nested": [1, 2]}}}
    rpc_error = {"code": -32602, "message": "Invalid params"}
    replies.extend([reply(envelope(failure, True)),
                    (200, {}, {"jsonrpc": "2.0", "id": 2, "error": rpc_error})])
    with pytest.raises(ToolError) as error:
        client.tool("example.write", {"operation_id": "operation"})
    assert error.value.payload == failure
    assert len(requests) == 1
    with pytest.raises(RpcError) as error:
        client.rpc("tools/call", {})
    assert error.value.error == rpc_error
    assert len(requests) == 2


@pytest.mark.parametrize("response", [
    [], {}, {"jsonrpc": "1.0", "id": 1, "result": {}},
    {"jsonrpc": "2.0", "id": True, "result": {}},
    {"jsonrpc": "2.0", "id": "1", "result": {}},
    {"jsonrpc": "2.0", "id": 2, "result": {}},
    {"jsonrpc": "2.0", "id": 1},
    {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}},
    {"jsonrpc": "2.0", "id": 1, "error": None},
    {"jsonrpc": "2.0", "id": 1, "error": {"code": True, "message": "bad"}},
])
def test_rejects_invalid_rpc_responses(endpoint, response):
    client, _, replies = endpoint
    replies.append((200, {}, response))
    with pytest.raises(ProtocolError):
        client.rpc("ping", {})


@pytest.mark.parametrize("status", [401, 429, 503, 307])
def test_http_errors_and_redirects_are_not_retried(endpoint, status):
    client, requests, replies = endpoint
    replies.append((status, {"Location": client.base_url + "/redirect"}, {}))
    with pytest.raises(HTTPError) as error:
        client.health()
    assert error.value.code == status
    error.value.close()
    assert len(requests) == 1


@pytest.mark.parametrize("url", [
    "https://127.0.0.1", "http://example.com", "http://user:secret@localhost",
    "http://localhost/path", "http://localhost?query=1", "http://localhost#fragment",
])
def test_client_requires_loopback_origin(url):
    with pytest.raises(ValueError, match="loopback"):
        McpClient(url, "token")
