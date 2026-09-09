"""Exercise the actual disconnected sidecar over loopback, without x64dbg."""

import json
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID, uuid4

import pytest

from mcp_client import McpClient, RpcError, ToolError, decode_tool_result


pytestmark = pytest.mark.server


@pytest.fixture
def client(disconnected_server):
    return McpClient(*disconnected_server)


@pytest.fixture
def http(disconnected_server):
    base_url, token = disconnected_server
    opener = build_opener(ProxyHandler({}))

    def request(path, body=None, headers=None, method=None):
        effective = {"Authorization": f"Bearer {token}", "Accept": "application/json",
                     "Content-Type": "application/json"}
        effective.update(headers or {})
        req = Request(base_url + path, data=body, headers=effective, method=method)
        try:
            response = opener.open(req, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read()
            return response.status, response.headers, json.loads(raw) if raw else None

    return request


def test_health_distinguishes_live_from_ready(http):
    status, _, body = http("/health/live", headers={"Authorization": ""})
    assert status == 200
    assert body == {"status": "ok"}
    status, headers, body = http("/health/ready")
    assert status == 503
    assert "application/json" in headers["Content-Type"]
    assert body["status"] == "not_ready"
    assert body["plugin_connected"] is False
    assert body["diagnostic_code"] == "PLUGIN_DISCONNECTED"
    assert UUID(body["instance_id"])
    assert body["next_actions"] == [{"code": "START_DEBUGGER_WITH_PLUGIN"}]


@pytest.mark.parametrize("path", ["/health/ready", "/mcp"])
@pytest.mark.parametrize("authorization", ["", "Bearer wrong-token"])
def test_authentication_is_required(http, path, authorization):
    body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}' if path == "/mcp" else None
    status, _, _ = http(path, body, {"Authorization": authorization})
    assert status == 401


def test_origin_is_rejected(http):
    status, _, _ = http("/mcp", b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                        {"Origin": "https://untrusted.example"})
    assert status == 403


@pytest.mark.parametrize("version", ["2025-11-25", "2025-06-18"])
def test_initialize_ping_and_catalog(client, version):
    initialized = client.rpc("initialize", {"protocolVersion": version, "capabilities": {},
                                           "clientInfo": {"name": "pytest", "version": "1"}})
    assert initialized["protocolVersion"] == version
    assert initialized["capabilities"]["tools"] == {"listChanged": False}
    assert client.rpc("ping", {}, request_id="python-http-ping") == {}
    tools = client.rpc("tools/list", {})["tools"]
    names = [tool["name"] for tool in tools]
    assert len(names) == len(set(names))
    assert {"debugger.state", "debuggee.launch", "debuggee.attach", "memory.read", "memory.dump",
            "events.list", "events.wait", "logs.status", "logs.read"} <= set(names)
    for tool in tools:
        assert tool["inputSchema"]["type"] == "object"
        assert "outputSchema" not in tool


def test_new_tool_schemas_are_bounded_and_explicit(client):
    tools = {tool["name"]: tool for tool in client.rpc("tools/list", {})["tools"]}
    memory_read = tools["memory.read"]["inputSchema"]
    assert memory_read["properties"]["format"]["enum"] == [
        "bytes", "word", "dword", "qword", "str", "wstr",
    ]
    assert memory_read["properties"]["byte_order"]["enum"] == ["little", "big"]
    memory_dump = tools["memory.dump"]["inputSchema"]
    assert set(memory_dump["required"]) == {
        "operation_id", "instance_id", "address", "length", "path",
    }
    assert memory_dump["properties"]["length"]["maximum"] == 64 * 1024 * 1024
    assert memory_dump["properties"]["overwrite"]["default"] is False
    events_list = tools["events.list"]["inputSchema"]
    assert events_list["required"] == []
    assert set(events_list["properties"]) == {"cursor", "types", "limit"}
    events_wait = tools["events.wait"]["inputSchema"]
    assert events_wait["required"] == []
    assert events_wait["properties"]["timeout_ms"]["default"] == 5000
    assert tools["logs.status"]["inputSchema"]["required"] == []
    logs_read = tools["logs.read"]["inputSchema"]
    assert set(logs_read["properties"]) == {
        "cursor", "limit", "max_bytes",
    }
    assert logs_read["properties"]["limit"]["maximum"] == 100
    assert logs_read["properties"]["max_bytes"]["maximum"] == 256 * 1024


def test_disconnected_tool_content_contract(client, workspace):
    result = client.tool_result("debugger.state", {}, request_id=9)
    expected = json.loads((workspace / "contracts/mcp/disconnected-state.response.json").read_text())
    assert result == expected["result"]
    payload = decode_tool_result(result)
    assert payload["error"]["code"] == "PLUGIN_UNAVAILABLE"
    with pytest.raises(ToolError) as error:
        client.tool("debugger.state", {})
    assert error.value.payload == payload


def test_invalid_argument_and_stale_identity_are_not_dispatched(client, http):
    with pytest.raises(ToolError) as error:
        client.tool("memory.read", {"address": "not-an-address", "length": 1})
    assert error.value.payload["error"]["code"] == "INVALID_ARGUMENT"
    assert error.value.payload["error"]["details"]["field"] == "address"
    with pytest.raises(ToolError) as error:
        client.tool("memory.read", {
            "address": "0x1000", "length": 3, "format": "word", "byte_order": "little",
        })
    assert error.value.payload["error"]["details"]["field"] == "length"
    with pytest.raises(ToolError) as error:
        client.tool("memory.dump", {
            "address": "0x1000", "length": 1, "path": "C:\\bad\npath.bin",
            "instance_id": str(uuid4()), "operation_id": str(uuid4()),
        })
    assert error.value.payload["error"]["details"]["field"] == "path"
    _, _, ready = http("/health/ready")
    stale = str(uuid4())
    assert stale != ready["instance_id"]
    with pytest.raises(ToolError) as error:
        client.tool("debugger.resume", {"instance_id": stale, "operation_id": str(uuid4())})
    payload = error.value.payload["error"]
    assert payload["code"] == "BACKEND_RESTARTED"
    assert payload["safeToRetry"] is False
    assert payload["details"]["outcome"] == "not_started"
    assert payload["details"]["current_instance_id"] == ready["instance_id"]


@pytest.mark.parametrize("method,params,code", [
    ("unknown", {}, -32601),
    ("tools/call", {"name": "unknown", "arguments": {}}, -32602),
])
def test_json_rpc_errors(client, method, params, code):
    with pytest.raises(RpcError) as error:
        client.rpc(method, params)
    assert error.value.error["code"] == code


@pytest.mark.parametrize("body,code", [(b"{", -32700), (b"[]", -32600)])
def test_malformed_requests(http, body, code):
    status, _, payload = http("/mcp", body)
    assert status == 200
    assert payload["jsonrpc"] == "2.0"
    assert payload["id"] is None
    assert payload["error"]["code"] == code


def test_notifications_and_unsupported_get(http):
    status, _, body = http("/mcp", b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
    assert (status, body) == (202, None)
    status, headers, body = http("/mcp")
    assert status == 405
    assert headers["Allow"] == "POST"
