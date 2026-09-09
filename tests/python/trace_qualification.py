"""Live trace retirement checks, including a call that cannot return on its own."""

import ctypes
from ctypes import wintypes
import struct
import time
import uuid

from mcp_client import ToolError, assert_exact


def wait_until_blocked(process_id, address):
    # The HTTP memory API requires a pause. This read-only observation is a
    # fixture handshake, not a delay intended to let a debugger race settle.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.ReadProcessMemory.argtypes = (wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    process = kernel32.OpenProcess(0x0010, False, process_id)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        deadline = time.monotonic() + 2
        while True:
            value, count = wintypes.DWORD(), ctypes.c_size_t()
            if not kernel32.ReadProcessMemory(process, address, ctypes.byref(value), 4, ctypes.byref(count)):
                raise ctypes.WinError(ctypes.get_last_error())
            if count.value != 4:
                raise AssertionError("Incomplete blocked-call fixture observation")
            if value.value == 1:
                return
            if time.monotonic() >= deadline:
                raise AssertionError("Trace never entered the controlled blocking call")
            time.sleep(0.005)
    finally:
        kernel32.CloseHandle(process)


def relative_call_target(address, data_hex):
    code = bytes.fromhex(data_hex)
    if len(code) != 5 or code[0] != 0xE8:
        raise AssertionError("Fixture callsite must be a direct rel32 call")
    return address + 5 + struct.unpack("<i", code[1:])[0]


def qualify_blocked_trace(client, module_name, process_id, main_thread_id):
    def mutate(name, **arguments):
        return client.tool(name, {"operation_id": str(uuid.uuid4()), **arguments})

    addresses = {}
    for name in ("trace_wait", "trace_wait_callsite", "trace_wait_trigger",
                 "trace_wait_release", "trace_wait_observed"):
        symbol = client.tool("symbols.resolve", {"module": module_name, "name": "mcp_fixture_" + name})
        assert symbol["resolution"] == "found" and symbol["total_matches"] == 1, symbol
        addresses[name] = symbol["matches"][0]["location"]["address"]
    disassembly = client.tool("disassembly.read", {"address": addresses["trace_wait_callsite"], "count": 8})
    call = next(item for item in disassembly["items"] if item["text"].lower().startswith("call "))
    code = client.tool("memory.read", {"address": call["address"], "length": call["size"]})
    assert relative_call_target(int(call["address"], 16), code["data_hex"]) == int(addresses["trace_wait"], 16)
    after_call = hex(int(call["address"], 16) + call["size"])
    reports = {}
    for stop in ("timeout", "cancel"):
        for name, value in (("trace_wait_release", 0), ("trace_wait_observed", 0), ("trace_wait_trigger", 1)):
            mutate("memory.write", address=addresses[name], data_hex=struct.pack("<I", value).hex())
        mutate("breakpoints.set", address=call["address"])
        resumed = mutate("debugger.resume")
        landed = client.tool("debugger.wait_for_pause", {"after_generation": resumed["state_generation"], "timeout_ms": 9000})
        assert landed["instruction_pointer"] == call["address"] and landed["active_thread_id"] == main_thread_id, landed
        mutate("breakpoints.remove", address=call["address"])
        # Arm before stepping: TitanEngine may own an internal breakpoint at
        # this return address until the interrupted step-over has unwound.
        mutate("breakpoints.set", address=after_call)
        before = client.tool("debugger.state", {})
        started_at = time.monotonic()
        trace = mutate("trace.start", mode="over", max_steps=4096, timeout_ms=250 if stop == "timeout" else 30000)
        wait_until_blocked(process_id, int(addresses["trace_wait_observed"], 16))
        if stop == "cancel":
            cancelled = mutate("trace.cancel", trace_id=trace["trace_id"])
            assert cancelled["state"] == "cancelled" and cancelled["reason"] == "cancelled", cancelled
        pause = client.tool("debugger.wait_for_pause", {"after_generation": before["state_generation"], "timeout_ms": 5000})
        elapsed = time.monotonic() - started_at
        status = client.tool("trace.status", {"trace_id": trace["trace_id"]})
        expected = "timed_out" if stop == "timeout" else "cancelled"
        assert status["state"] == expected and status["reason"] == ("timeout" if stop == "timeout" else "cancelled"), status
        assert elapsed < 5, f"Blocked trace {stop} exceeded the five-second qualification bound"
        # No return from the stepped-over call and therefore no trace progress.
        assert status["steps_executed"] == 0 and status["points_retained"] == 1, status
        observed = client.tool("memory.read", {"address": addresses["trace_wait_observed"], "length": 4})
        assert observed["data_hex"] == "01000000", observed
        assert pause["pause_reason"]["kind"] == "user_pause" and pause["active_thread_id"] != main_thread_id, pause
        helper_thread = pause["active_thread_id"]
        for name, arguments in (
            ("trace.start", {"mode": "into", "max_steps": 2, "timeout_ms": 1000}),
            ("debugger.step_into", {}), ("debugger.step_over", {}),
            ("debugger.step_out", {}),
            ("debugger.run_to_address", {"address": after_call, "timeout_ms": 1000}),
            ("breakpoints.set", {"address": after_call}),
            ("breakpoints.remove", {"address": after_call}),
        ):
            try:
                mutate(name, **arguments)
            except ToolError as error:
                assert error.payload["error"]["code"] == "INVALID_DEBUGGER_STATE", (name, error.payload)
            else:
                raise AssertionError(f"{name} silently executed on the interrupt helper")
        assert client.tool("debugger.state", {})["state_generation"] == status["state_generation"]
        mutate("memory.write", address=addresses["trace_wait_release"], data_hex="01000000")
        resumed = mutate("debugger.resume")
        recovered = client.tool("debugger.wait_for_pause", {"after_generation": resumed["state_generation"], "timeout_ms": 5000})
        assert recovered["instruction_pointer"] == after_call and recovered["active_thread_id"] == main_thread_id, recovered
        mutate("breakpoints.remove", address=after_call)
        before_restart = client.tool("debugger.state", {})
        restart_arguments = {"operation_id": str(uuid.uuid4()), "mode": "into", "max_steps": 2, "timeout_ms": 3000}
        restarted = client.tool("trace.start", restart_arguments)
        assert_exact(restarted, client.tool("trace.start", restart_arguments), "Trace restart replay changed")
        restarted_pause = client.tool("debugger.wait_for_pause", {
            "after_generation": before_restart["state_generation"], "timeout_ms": 5000,
        })
        restarted_status = client.tool("trace.status", {"trace_id": restarted["trace_id"]})
        assert restarted_status["state"] == "completed" and restarted_status["reason"] == "max_steps", restarted_status
        assert restarted_status["steps_executed"] == 2 and restarted_status["points_retained"] == 3, restarted_status
        assert restarted_pause["active_thread_id"] == main_thread_id, restarted_pause
        reports[stop] = {"state": status["state"], "steps_executed": status["steps_executed"],
                         "elapsed_seconds": elapsed, "helper_thread_id": helper_thread,
                         "application_thread_id": main_thread_id, "restart_completed": True}
    return reports
