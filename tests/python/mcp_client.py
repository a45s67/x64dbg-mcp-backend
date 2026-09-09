"""Small, strict client for this server's content-only MCP test contract."""

import copy
import itertools
import json
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class ProtocolError(ValueError):
    pass


class RpcError(RuntimeError):
    def __init__(self, error):
        self.error = error
        super().__init__(f"JSON-RPC error: {json.dumps(error, ensure_ascii=True)}")


class ToolError(RuntimeError):
    def __init__(self, payload):
        self.payload = payload
        super().__init__(f"Tool error: {json.dumps(payload, ensure_ascii=True)}")


def assert_exact(actual, expected, message="JSON values differ"):
    # Python equality conflates true/1 and 1/1.0; replay checks must not.
    if json.dumps(actual, sort_keys=True, ensure_ascii=True, allow_nan=False) != json.dumps(
        expected, sort_keys=True, ensure_ascii=True, allow_nan=False
    ):
        raise AssertionError(message)


def _reject_constant(value):
    raise ProtocolError(f"Non-JSON number: {value}")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProtocolError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def _decode_json(text):
    try:
        return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError) as error:
        raise ProtocolError(f"Invalid JSON: {error}") from error


def decode_tool_result(result):
    if not isinstance(result, dict) or "structuredContent" in result:
        raise ProtocolError("Expected a content-only tool result, without structuredContent")
    if type(result.get("isError")) is not bool:
        raise ProtocolError("Tool result must contain a boolean isError")
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1:
        raise ProtocolError("Tool result must contain exactly one content block")
    block = content[0]
    if not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("text"), str):
        raise ProtocolError("Tool content must be a JSON text block")
    payload = _decode_json(block["text"])
    if result["isError"] and (
        not isinstance(payload, dict) or payload.get("ok") is not False
        or not isinstance(payload.get("error"), dict)
    ):
        raise ProtocolError("Tool failure must contain the existing ok:false error envelope")
    return payload


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the test bearer token to a redirected endpoint.
        return None


class McpClient:
    def __init__(self, base_url, token, instance_id=None, timeout=40):
        url = urlsplit(base_url)
        if (url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost", "::1")
                or url.username is not None or url.password is not None
                or url.path not in ("", "/") or url.query or url.fragment):
            raise ValueError("Tests require a loopback HTTP origin")
        self.base_url = base_url.rstrip("/")
        self.instance_id = instance_id
        self.timeout = timeout
        self._token = token
        self._ids = itertools.count(1)
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _request(self, path, body=None):
        data = None if body is None else json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        request = Request(self.base_url + path, data=data, headers={
            "Authorization": f"Bearer {self._token}", "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
        })
        with self._opener.open(request, timeout=self.timeout) as response:
            return _decode_json(response.read().decode("utf-8"))

    def health(self):
        return self._request("/health/ready")

    def rpc(self, method, params, request_id=None):
        # Do not change the caller's arguments: it may replay them or change a
        # single field to probe operation-id conflict handling.
        params = copy.deepcopy(params)
        if method == "tools/call" and isinstance(params, dict):
            arguments = params.get("arguments")
            if isinstance(arguments, dict) and "operation_id" in arguments and "instance_id" not in arguments:
                if not self.instance_id:
                    raise ProtocolError("Mutation attempted before backend instance identity was observed")
                arguments["instance_id"] = self.instance_id
        request_id = next(self._ids) if request_id is None else request_id
        response = self._request("/mcp", {
            "jsonrpc": "2.0", "id": request_id, "method": method, "params": params,
        })
        if (not isinstance(response, dict) or response.get("jsonrpc") != "2.0"
                or type(response.get("id")) is not type(request_id) or response.get("id") != request_id
                or ("result" in response) == ("error" in response)):
            raise ProtocolError("Invalid JSON-RPC response or mismatched request id")
        if "error" in response:
            error = response["error"]
            if (not isinstance(error, dict) or type(error.get("code")) is not int
                    or not isinstance(error.get("message"), str)):
                raise ProtocolError("Malformed JSON-RPC error")
            raise RpcError(error)
        return response["result"]

    def tool_result(self, name, arguments, request_id=None):
        result = self.rpc("tools/call", {"name": name, "arguments": arguments}, request_id)
        decode_tool_result(result)
        return result

    def tool(self, name, arguments, request_id=None):
        result = self.tool_result(name, arguments, request_id)
        payload = decode_tool_result(result)
        if result["isError"]:
            raise ToolError(payload)
        return payload
