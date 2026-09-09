"""HTTP assertions for run-attach-integration.ps1; process ownership stays in PS."""

import argparse
import ctypes
from ctypes import wintypes
import json
import os
import sys
import time
import uuid

from mcp_client import McpClient, ToolError, assert_exact, decode_tool_result


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def run(client, args, fixture_alive):
    def tool(name, arguments, request_id):
        # Attach callbacks can invalidate either read-only snapshot. Mutations
        # and expected-error probes are never replayed automatically.
        for attempt in range(21):
            try:
                return client.tool(name, arguments, request_id=request_id)
            except ToolError as error:
                detail = error.payload.get("error", {})
                if not (name in ("debugger.state", "modules.list") and attempt < 20
                        and detail.get("code") == "BUSY"
                        and detail.get("safeToRetry") is True):
                    raise
                time.sleep(0.1)

    client.rpc("initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "attach-integration", "version": "1"},
    }, request_id=1)
    before = tool("debugger.state", {}, 2)
    check(before["instance_id"] == client.instance_id,
          "Readiness and debugger.state reported different backend instances.")
    check(before.get("session_origin") is None and
          sum(action["tool"] == "debuggee.attach" for action in before["next_actions"]) == 1,
          "Absent state omitted the explicit attach action or retained an origin.")

    self_attach = client.tool_result("debuggee.attach", {
        "operation_id": str(uuid.uuid4()), "process_id": args.debugger_pid,
    }, request_id=3)
    self_payload = decode_tool_result(self_attach)
    check(self_attach.get("isError") is True and
          self_payload["error"]["code"] == "INVALID_ARGUMENT",
          "Backend did not reject attaching to its own debugger host.")

    attach_arguments = {"operation_id": str(uuid.uuid4()), "process_id": args.fixture_pid}
    attach_call = client.tool_result("debuggee.attach", attach_arguments, request_id=4)
    attached = decode_tool_result(attach_call)
    if attach_call.get("isError"):
        diagnostic_state = tool("debugger.state", {}, 40)
        raise AssertionError(f"Attach failed; state={json.dumps(diagnostic_state)}; "
                             f"error={json.dumps(attached)}")
    attached_replay = tool("debuggee.attach", attach_arguments, 5)
    assert_exact(attached, attached_replay, "Attach did not replay exactly.")
    check(attached["session_origin"] == "attached"
          and int(attached["process_id"], 16) == args.fixture_pid,
          "Attach was not PID-correlated, origin-aware, or replay-safe.")

    state = tool("debugger.state", {}, 6)
    check(state["debuggee_state"] == "paused" and state["session_origin"] == "attached"
          and int(state["process_id"], 16) == args.fixture_pid,
          "Attached debugger.state omitted its PID or session origin.")
    unsafe_stop = client.tool_result("debugger.stop", {
        "operation_id": str(uuid.uuid4()),
    }, request_id=7)
    unsafe_payload = decode_tool_result(unsafe_stop)
    check(unsafe_stop.get("isError") is True and
          unsafe_payload["error"]["code"] == "INVALID_DEBUGGER_STATE" and fixture_alive(),
          "Attached-session stop was not safely rejected.")
    modules = tool("modules.list", {"limit": 256}, 8)
    check(sum(item["name"].lower() == args.fixture_name.lower()
              for item in modules["items"]) == 1,
          "Attached fixture was not visible through bounded module discovery.")

    detached = tool("debuggee.detach", {"operation_id": str(uuid.uuid4())}, 9)
    time.sleep(0.1)
    survived = fixture_alive()
    check(detached["debuggee_state"] == "absent" and detached.get("session_origin") is None
          and int(detached["detached_process_id"], 16) == args.fixture_pid and survived,
          "Detach did not preserve the independently started fixture.")
    after = tool("debugger.state", {}, 10)
    check(after["debuggee_state"] == "absent" and after.get("session_origin") is None,
          "Debugger retained attached session state after detach.")
    return {
        "backend": args.backend, "architecture": state["architecture"],
        "instance_id": client.instance_id, "debugger_host_process_id": args.debugger_pid,
        "fixture_process_id": args.fixture_pid, "sidecar_port": args.port,
        "attached_state": attached["debuggee_state"], "attached_origin": attached["session_origin"],
        "attach_replay_equal": True, "self_attach_rejected": True,
        "destructive_stop_rejected": True, "detached_state": detached["debuggee_state"],
        "fixture_survived_detach": survived,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--backend", type=str.lower, choices=("x32", "x64"), required=True)
    parser.add_argument("--debugger-pid", type=int, required=True)
    parser.add_argument("--fixture-pid", type=int, required=True)
    parser.add_argument("--fixture-name", required=True)
    parser.add_argument("--port", type=int, required=True)
    return parser.parse_args(argv)


def main():
    args = parse_args()
    client = McpClient(args.base_url, os.environ["X64DBG_MCP_TOKEN"],
                       instance_id=str(uuid.UUID(args.instance_id)))
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    # Keep the original process object alive so PID reuse cannot mask its death.
    handle = kernel32.OpenProcess(0x00100000, False, args.fixture_pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        def fixture_alive():
            status = kernel32.WaitForSingleObject(handle, 0)
            if status == 0xFFFFFFFF:
                raise ctypes.WinError(ctypes.get_last_error())
            return status == 0x00000102  # WAIT_TIMEOUT: process has not exited.

        check(fixture_alive(), "Independent fixture exited before attach.")
        report = run(client, args, fixture_alive)
    finally:
        kernel32.CloseHandle(handle)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"attach-integration: {error}", file=sys.stderr)
        sys.exit(1)
