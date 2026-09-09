"""Offline translation regressions; no debugger, process handle, or HTTP access."""

from collections import deque
from copy import deepcopy
import base64
import hashlib
import json
import struct
from types import SimpleNamespace
import uuid

import pytest

import attach_integration as attach
import flare_checksum_smoke as flare
import generic_sample_smoke as generic
import real_integration as real
from mcp_client import ToolError, assert_exact


INSTANCE_ID = "12345678-1234-1234-1234-123456789abc"
ABSENT = {
    "instance_id": INSTANCE_ID, "debuggee_state": "absent", "session_origin": None,
    "diagnostic_code": "NO_DEBUGGEE",
    "next_actions": [{"code": "CALL_DEBUGGEE_LAUNCH", "tool": "debuggee.launch"},
                     {"code": "CALL_DEBUGGEE_ATTACH", "tool": "debuggee.attach"}],
}
EMPTY_EVENTS = {
    "session_id": f"{INSTANCE_ID}:0", "items": [], "next_cursor": None,
    "latest_sequence": 0, "history_complete": True, "storage_error": None,
}


class ScenarioFinished(Exception):
    """A deliberately short script reached the next unmocked native operation."""


class FakeClient:
    def __init__(self, responses):
        self.instance_id = INSTANCE_ID
        self.responses = deque(deepcopy(responses))
        self.calls = []

    def health(self):
        return {**deepcopy(ABSENT), "status": "ready", "debugger_state": "absent"}

    def rpc(self, method, params, request_id=None):
        assert method == "initialize"
        assert params["protocolVersion"] == "2025-11-25"
        return {}

    def _next(self, method, name, arguments, request_id):
        self.calls.append((method, name, deepcopy(arguments), request_id))
        if not self.responses:
            raise ScenarioFinished(name)
        expected, payload = self.responses.popleft()
        assert name == expected
        return payload(arguments) if callable(payload) else deepcopy(payload)

    def tool(self, name, arguments, request_id=None):
        payload = self._next("tool", name, arguments, request_id)
        if "error" in payload:
            raise ToolError(payload)
        return payload

    def tool_result(self, name, arguments, request_id=None):
        payload = self._next("tool_result", name, arguments, request_id)
        return {"content": [{"type": "text", "text": json.dumps(payload)}],
                "isError": "error" in payload}


def error_payload(code, safe=True):
    return {"ok": False, "error": {"code": code, "message": "scripted error",
                      "safeToRetry": safe, "recoverable": True}}


@pytest.fixture
def args(tmp_path, monkeypatch):
    monkeypatch.setattr(real.time, "sleep", lambda seconds: None)
    sample = tmp_path / "sample with space.exe"
    sample.write_bytes(b"offline sample bytes, never executed")
    return SimpleNamespace(
        backend="x64", backend_root=str(tmp_path), fixture_name="fixture.exe",
        debugger_pid=100, fixture_pid=200, sidecar_pid=300, port=12345,
        base_url="http://127.0.0.1:12345", sample=str(sample),
        staged_sample=str(tmp_path / "staged sample.exe"), expected_ascii_pattern=None,
        main_rva="0xa78a0",
    )


def real_prefix():
    return [("debugger.state", ABSENT), ("events.list", EMPTY_EVENTS),
            ("debuggee.launch", error_payload("INVALID_ARGUMENT"))]


def launch_result(arguments):
    return {"arguments": arguments["arguments"], "state_generation": 1}


def attach_flow(args):
    attached = {"debuggee_state": "paused", "session_origin": "attached",
                "process_id": hex(args.fixture_pid), "architecture": "x64", "state_generation": 1}
    return [
        ("debugger.state", ABSENT),
        ("debuggee.attach", error_payload("INVALID_ARGUMENT")),
        ("debuggee.attach", attached), ("debuggee.attach", attached),
        ("debugger.state", attached),
        ("debugger.stop", error_payload("INVALID_DEBUGGER_STATE")),
        ("modules.list", {"items": [{"name": args.fixture_name.upper()}]}),
        ("debuggee.detach", {"debuggee_state": "absent", "session_origin": None,
                             "detached_process_id": hex(args.fixture_pid)}),
        ("debugger.state", ABSENT),
    ]


@pytest.mark.parametrize("actual,expected", [
    (True, 1), (False, 0), (1, 1.0),
    ({"nested": [{"present": True}]}, {"nested": [{"present": 1}]}),
    ([1, 2], [2, 1]), ("Case", "case"),
])
def test_exact_json_rejects_type_and_value_changes(actual, expected):
    with pytest.raises(AssertionError, match="replay changed"):
        assert_exact(actual, expected, "replay changed")


def test_exact_json_ignores_object_key_order():
    assert_exact({"b": [True, 1, None], "a": "\u5169"},
                 {"a": "\u5169", "b": [True, 1, None]})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_exact_json_rejects_non_json_numbers(value):
    with pytest.raises((AssertionError, ValueError)):
        assert_exact(value, value)


def test_real_launch_replay_rejects_type_drift(args):
    client = FakeClient(real_prefix() + [
        ("debuggee.launch", launch_result),
        ("debuggee.launch", lambda arguments: {**launch_result(arguments), "state_generation": True}),
    ])
    with pytest.raises(AssertionError, match="replay"):
        real.run(client, args)
    assert_exact(client.calls[-2][2], client.calls[-1][2])
    assert client.calls[-2][3] != client.calls[-1][3]
    assert not client.responses


def test_attach_flow_preserves_pid_origin_replay_and_survival(args):
    client = FakeClient(attach_flow(args))
    observations = iter([True, True])
    report = attach.run(client, args, lambda: next(observations))
    assert report["fixture_process_id"] == args.fixture_pid
    assert report["attached_origin"] == "attached"
    assert report["attach_replay_equal"] is True
    assert report["destructive_stop_rejected"] is True
    assert report["fixture_survived_detach"] is True
    assert report["detached_state"] == "absent"
    assert_exact(client.calls[2][2], client.calls[3][2])
    assert client.calls[1][2]["process_id"] == args.debugger_pid
    assert client.calls[2][2]["process_id"] == args.fixture_pid
    assert not client.responses


def test_attach_replay_rejects_type_drift(args):
    responses = attach_flow(args)
    responses[3] = ("debuggee.attach", {**responses[3][1], "state_generation": True})
    client = FakeClient(responses)
    with pytest.raises(AssertionError, match="replay exactly"):
        attach.run(client, args, lambda: True)
    assert len(client.calls) == 4


@pytest.mark.parametrize("replayed_present", [True, 1])
def test_flare_conditional_replay_preserves_json_types(args, replayed_present):
    # Stop at the first managed replay, before the rest of native qualification.
    pause = {"state_generation": 2, "instruction_pointer": "0x1000", "active_thread_id": "0x1",
             "pause_reason": {"kind": "breakpoint", "address": "0x1000",
                              "breakpoint_type": "software", "hit_count": 1}}
    registers = {"state_generation": 2, "thread_id": "0x1", "current": True,
                 "registers": {"rip": "0x1000", "rsp": "0x2000"}}
    snapshot = {"state_generation": 2, "instruction_pointer": {"address": "0x1000"},
                "registers": dict.fromkeys(["rip", "rsp", "rax", "rbx"], "0x0"),
                "disassembly": [{}] * 8, "thread_id": "0x1", "active_thread_id": "0x1", "current": True}
    conditional = {"present": True, "fast_resume": True, "managed_id": INSTANCE_ID}
    client = FakeClient([
        ("debugger.state", ABSENT), ("debuggee.launch", {"state_generation": 1}),
        ("address.resolve", {"address": "0x1000"}), ("breakpoints.set", {"present": True}),
        ("debugger.resume", {"state_generation": 1}), ("debugger.wait_for_pause", pause),
        ("breakpoints.disable", {"changed": True, "enabled": False}),
        ("breakpoints.enable", {"changed": True, "enabled": True}),
        ("registers.read", registers), ("registers.read", registers),
        ("callstack.read", {"thread_id": "0x1", "frames": [], "state_generation": 2,
                            "completeness": "native_bounded"}),
        ("memory.read", {"state_generation": 2, "location": {"state_generation": 2},
                         "data_hex": "9090909090909090"}),
        ("disassembly.read", {"state_generation": 2, "location": {"state_generation": 2},
                              "items": [{"address": "0x1000", "size": 1}, {"address": "0x1001", "size": 1}]}),
        ("memory.search", {"read_completeness": "complete", "scan_complete": False, "items": [{}]}),
        ("debugger.snapshot", snapshot), ("debugger.snapshot", {**snapshot, "disassembly": [{}] * 2}),
        ("memory.map", {"state_generation": 2, "items": [{}]}),
        ("breakpoints.conditional.set", conditional),
        ("breakpoints.conditional.set", {**conditional, "present": replayed_present}),
    ])
    if replayed_present is True:
        with pytest.raises(ScenarioFinished, match="breakpoints.list"):
            flare.run(client, args)
        replay_calls = client.calls[-3:-1]
    else:
        with pytest.raises(AssertionError, match="replay exactly"):
            flare.run(client, args)
        replay_calls = client.calls[-2:]
    assert_exact(replay_calls[0][2], replay_calls[1][2])
    assert not client.responses


@pytest.mark.parametrize("survival", [(False,), (True, False)])
def test_attach_does_not_report_success_if_fixture_dies(args, survival):
    observations = iter(survival)
    with pytest.raises(AssertionError, match="safely rejected|preserve the independently"):
        attach.run(FakeClient(attach_flow(args)), args, lambda: next(observations))


@pytest.mark.parametrize("scenario", [real, attach])
def test_busy_state_reads_retry_with_same_arguments_and_request_id(args, scenario, monkeypatch):
    sleeps = []
    monkeypatch.setattr(real.time, "sleep", sleeps.append)
    client = FakeClient([("debugger.state", error_payload("BUSY"))] * 2 +
                        [("debugger.state", ABSENT)])
    with pytest.raises(ScenarioFinished):
        scenario.run(client, args, lambda: True) if scenario is attach else scenario.run(client, args)
    reads = [call for call in client.calls if call[1] == "debugger.state"]
    assert len(reads) == 3 and reads[0] == reads[1] == reads[2]
    assert sleeps == [0.1, 0.1]


@pytest.mark.parametrize("scenario", [real, attach])
@pytest.mark.parametrize("code,safe,attempts", [
    ("BUSY", True, 21), ("BUSY", False, 1), ("BUSY", 1, 1),
    ("BUSY", "true", 1), ("TIMEOUT", True, 1),
])
def test_state_retry_is_bounded_and_requires_explicit_safe_busy(args, scenario, code, safe, attempts):
    client = FakeClient([("debugger.state", error_payload(code, safe))] * attempts)
    with pytest.raises(ToolError):
        scenario.run(client, args, lambda: True) if scenario is attach else scenario.run(client, args)
    assert len(client.calls) == attempts
    assert not client.responses


@pytest.mark.parametrize("scenario", [real, attach, generic, flare])
def test_mutations_never_retry_even_safe_busy(args, scenario):
    target = "debuggee.detach" if scenario is attach else "debuggee.launch"
    prefix = (attach_flow(args)[:7] if scenario is attach else
              real_prefix() if scenario is real else [("debugger.state", ABSENT)])
    client = FakeClient(prefix + [(target, error_payload("BUSY"))])
    with pytest.raises(ToolError):
        scenario.run(client, args, lambda: True) if scenario is attach else scenario.run(client, args)
    calls = [call for call in client.calls if call[0] == "tool" and call[1] == target]
    assert len(calls) == 1
    assert not client.responses


def test_attach_retries_safe_module_snapshot_race(args):
    responses = attach_flow(args)
    client = FakeClient(responses[:6] + [("modules.list", error_payload("BUSY"))] * 2 + responses[6:])
    assert attach.run(client, args, lambda: True)["fixture_survived_detach"] is True
    reads = [call for call in client.calls if call[1] == "modules.list"]
    assert len(reads) == 3 and reads[0] == reads[1] == reads[2]
    assert not client.responses


@pytest.mark.parametrize("safe,attempts", [(True, 21), (False, 1), (1, 1)])
def test_attach_module_retries_are_bounded_and_explicitly_safe(args, safe, attempts):
    client = FakeClient(attach_flow(args)[:6] + [("modules.list", error_payload("BUSY", safe))] * attempts)
    with pytest.raises(ToolError):
        attach.run(client, args, lambda: True)
    assert sum(call[1] == "modules.list" for call in client.calls) == attempts
    assert not client.responses


@pytest.mark.parametrize("scenario", [real, attach])
def test_expected_error_probes_do_not_retry_busy(args, scenario):
    prefix = real_prefix()[:2] if scenario is real else [("debugger.state", ABSENT)]
    target = "debuggee.launch" if scenario is real else "debuggee.attach"
    client = FakeClient(prefix + [(target, error_payload("BUSY"))])
    with pytest.raises(AssertionError, match="INVALID_ARGUMENT|reject attaching"):
        scenario.run(client, args, lambda: True) if scenario is attach else scenario.run(client, args)
    assert sum(call[1] == target for call in client.calls) == 1
    assert client.calls[-1][0] == "tool_result"


@pytest.mark.parametrize("invalid", [None, {}, "", False, 0])
def test_real_initial_events_require_an_empty_array(args, invalid):
    client = FakeClient([("debugger.state", ABSENT),
                         ("events.list", {**EMPTY_EVENTS, "items": invalid})])
    with pytest.raises(AssertionError, match="empty event history"):
        real.run(client, args)
    assert len(client.calls) == 2


@pytest.mark.parametrize("actions", [None, {}, "", False, 0, []])
def test_real_paused_next_actions_require_an_empty_array(args, actions):
    client = FakeClient(real_prefix() + [
        ("debuggee.launch", launch_result), ("debuggee.launch", launch_result),
        ("debuggee.launch", error_payload("OPERATION_ID_CONFLICT")),
        ("debugger.state", {"debuggee_state": "paused", "state_generation": 1,
                            "diagnostic_code": None, "next_actions": actions}),
    ])
    if actions == []:
        with pytest.raises(ScenarioFinished, match="events.list"):
            real.run(client, args)
    else:
        with pytest.raises(AssertionError, match="stale bootstrap diagnostic"):
            real.run(client, args)


def test_observed_arguments_round_trip(tmp_path):
    items = ["C:\\fixture with space.exe", "", 'quote"inside', "trail\\", "\u5169\u500b\u5b57"]
    encoded = [item.encode("utf-8") for item in items]
    data = b"MARGV1\r\n" + struct.pack("<I", len(items))
    data += b"".join(struct.pack("<I", len(item)) + item for item in encoded)
    path = tmp_path / "observed.bin"
    path.write_bytes(data)
    assert_exact(real.read_observed_arguments(path), items)
    for length in range(len(data)):
        path.write_bytes(data[:length])
        with pytest.raises(AssertionError, match="truncated"):
            real.read_observed_arguments(path)


@pytest.mark.parametrize("data,exception", [
    (b"BADMAGIC", AssertionError),
    (b"MARGV1\r\n" + struct.pack("<I", 0), AssertionError),
    (b"MARGV1\r\n" + struct.pack("<I", 65), AssertionError),
    (b"MARGV1\r\n" + struct.pack("<II", 1, 32769), AssertionError),
    (b"MARGV1\r\n" + struct.pack("<II", 1, 1) + b"\xff", UnicodeDecodeError),
    (b"MARGV1\r\n" + struct.pack("<II", 1, 0) + b"trailing", AssertionError),
])
def test_observed_arguments_reject_malformed_data(tmp_path, data, exception):
    path = tmp_path / "observed.bin"
    path.write_bytes(data)
    with pytest.raises(exception):
        real.read_observed_arguments(path)


@pytest.mark.parametrize("name", ["DLLLoader32_12ab.exe", "dllloader64_ABCD.EXE"])
def test_dll_loader_name_is_case_insensitive(name):
    assert real.DLL_LOADER_NAME.fullmatch(name)


@pytest.mark.parametrize("name", ["DLLLoader16_abcd.exe", "DLLLoader64_abc.exe",
                                  "DLLLoader64_abcde.exe", "DLLLoader64_abcd.exe.extra",
                                  "DLLLoader64_abcd.exe\n", "other.exe"])
def test_dll_loader_name_remains_bounded(name):
    assert not real.DLL_LOADER_NAME.fullmatch(name)


@pytest.mark.parametrize("scenario", [real, attach, generic])
@pytest.mark.parametrize("backend", ["X32", "X64", "x64"])
def test_cli_normalizes_backend_without_starting_processes(scenario, backend):
    arguments = ["--base-url", "http://127.0.0.1:12345", "--backend", backend,
                 "--debugger-pid", "100"]
    if scenario is real:
        arguments += ["--backend-root", "C:\\runtime", "--fixture-name=fixture.exe"]
    else:
        arguments += ["--instance-id", INSTANCE_ID, "--port", "12345"]
        if scenario is attach:
            arguments += ["--fixture-pid", "200", "--fixture-name=fixture.exe"]
        else:
            arguments += ["--sample", "C:\\sample.exe", "--staged-sample", "C:\\runtime\\sample.exe",
                          "--backend-root", "C:\\runtime", "--sidecar-pid", "300"]
            encoded = base64.b64encode(b'quote" slash\\ spaces').decode("ascii")
            arguments += [f"--expected-ascii-pattern-base64={encoded}"]
    parsed = scenario.parse_args(arguments)
    assert parsed.backend == backend.lower()
    if scenario is generic:
        assert parsed.expected_ascii_pattern == 'quote" slash\\ spaces'
    arguments[arguments.index("--backend") + 1] = "arm64"
    with pytest.raises(SystemExit) as error:
        scenario.parse_args(arguments)
    assert error.value.code == 2


@pytest.mark.parametrize("pattern", [None, 'quote" slash\\ spaces'])
@pytest.mark.parametrize("search_generation", [5, 6])
def test_generic_flow_checks_generation_and_preserves_launch_arguments(args, pattern, search_generation):
    args.expected_ascii_pattern = pattern
    state = {"debuggee_state": "paused", "architecture": "x64", "state_generation": 5,
             "instruction_pointer": "0x1000", "pause_reason": {"kind": "process_created"}}
    responses = [
        ("debugger.state", ABSENT), ("debuggee.launch", state), ("debugger.state", state),
        ("debugger.snapshot", {"state_generation": 5, "disassembly": [{}] * 8}),
        ("modules.list", {"items": [{"name": "SAMPLE WITH SPACE.EXE", "base": "0x1000"}]}),
        ("sections.list", {"items": [{"name": ".text"}]}), ("imports.list", {"items": []}),
        ("memory.search", {"items": [{"location": {"address": "0x1000"}}],
                           "state_generation": search_generation}),
    ]
    if pattern:
        responses += [("memory.search", {"items": [{}], "state_generation": 5})]
    responses += [("events.list", {"session_id": f"{INSTANCE_ID}:1",
                                    "items": [{"type": "process_created"}],
                                    "next_cursor": None, "latest_sequence": 1,
                                    "history_complete": True, "storage_error": None}),
                   ("debugger.stop", {"debuggee_state": "absent"})]
    client = FakeClient(responses)
    if search_generation != 5:
        with pytest.raises(AssertionError, match="PE signature search"):
            generic.run(client, args)
        assert not any(call[1] == "debugger.stop" for call in client.calls)
        return
    report = generic.run(client, args)
    assert report["stopped"] is True
    assert report["sample_sha256"] == hashlib.sha256(b"offline sample bytes, never executed").hexdigest()
    assert report["expected_ascii_pattern"] == pattern
    assert report["expected_ascii_pattern_matches"] == (1 if pattern else None)
    launch = client.calls[1][2]
    uuid.UUID(launch["operation_id"])
    assert launch["path"] == args.staged_sample
    assert launch["working_directory"] == args.backend_root
    assert_exact(launch["arguments"], [])
    if pattern:
        search = client.calls[8][2]
        assert search["pattern_hex"] == pattern.encode("ascii").hex()
        assert search["mask"] == "x" * len(pattern)
    assert not client.responses


def test_flare_string_search_preserves_case_insensitive_pagination():
    client = FakeClient([
        ("strings.search", {"items": [], "next_cursor": "page-two"}),
        ("strings.search", {"items": [{"text": "prefix FLAREON2024 suffix"}], "next_cursor": None}),
    ])
    found = flare.find_installed_string(client, "CHECKSUM.EXE", "FlareOn2024", 60)
    assert found["page"] == 2
    assert client.calls[1][2]["cursor"] == "page-two"
    assert [call[3] for call in client.calls] == [60, 61]
    assert not client.responses
