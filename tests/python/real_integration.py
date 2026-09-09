"""Real-backend HTTP qualification; Windows process ownership stays in PowerShell."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
import traceback
from urllib.parse import urlsplit
import uuid

from mcp_client import McpClient, ToolError, assert_exact as exact, decode_tool_result
from trace_qualification import qualify_blocked_trace


DLL_LOADER_NAME = re.compile(r"DLLLoader(32|64)_[0-9A-Fa-f]{4}\.exe", re.IGNORECASE)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def operation(**arguments):
    return {"operation_id": str(uuid.uuid4()), **arguments}


def read_observed_arguments(path):
    with path.open("rb") as stream:
        def read(length):
            data = stream.read(length)
            check(len(data) == length, "Fixture argument observation was truncated.")
            return data

        def uint32():
            return struct.unpack("<I", read(4))[0]

        check(read(8) == b"MARGV1\r\n", "Invalid fixture argument format marker.")
        count = uint32()
        check(1 <= count <= 64, "Invalid fixture argument count.")
        items = []
        for _ in range(count):
            length = uint32()
            check(length <= 32768, "Fixture argument observation item is too large.")
            items.append(read(length).decode("utf-8", errors="strict"))
        check(not stream.read(1), "Fixture argument observation contains trailing data.")
        return items


def run(client, args):
    backend_root = Path(args.backend_root).resolve()
    fixture = str(backend_root / args.fixture_name)
    dll_fixture = str(backend_root / "mcp-debuggee-dll-fixture.dll")
    argument_observation = backend_root / "mcp-argv-observed.bin"

    def tool(name, arguments=None, request_id=None):
        # Only read-only state observations retry callback races. Mutations and
        # expected-error probes are never retried, even if marked safeToRetry.
        for attempt in range(21):
            try:
                return client.tool(name, {} if arguments is None else arguments,
                                   request_id=request_id)
            except ToolError as error:
                detail = error.payload.get("error", {})
                if not (name == "debugger.state" and attempt < 20
                        and detail.get("code") == "BUSY"
                        and detail.get("safeToRetry") is True):
                    raise
                time.sleep(0.1)

    def rejected(name, arguments, code, request_id=None):
        envelope = client.tool_result(name, arguments, request_id=request_id)
        payload = decode_tool_result(envelope)
        check(envelope.get("isError") is True and payload.get("error", {}).get("code") == code,
              f"{name} did not reject with {code}: {payload}")
        return payload

    def replay(name, arguments, request_id=None, replay_id=None):
        result = tool(name, arguments, request_id)
        repeated = tool(name, arguments, replay_id)
        exact(result, repeated, f"{name} did not replay the admitted operation exactly.")
        return result

    def first(items, predicate, context):
        item = next((item for item in items if predicate(item)), None)
        check(item is not None, context)
        return item

    def resume_wait(resume_id=None, wait_id=None):
        resumed = tool("debugger.resume", operation(), resume_id)
        paused = tool("debugger.wait_for_pause", {
            "after_generation": resumed["state_generation"], "timeout_ms": 9000,
        }, wait_id)
        return resumed, paused

    ready = client.health()
    check(ready["status"] == "ready", "Sidecar is not ready.")
    client.instance_id = str(uuid.UUID(ready["instance_id"]))
    check(ready["debugger_state"] == "absent" and ready["diagnostic_code"] == "NO_DEBUGGEE"
          and len(ready["next_actions"]) == 2
          and ready["next_actions"][0]["code"] == "CALL_DEBUGGEE_LAUNCH"
          and ready["next_actions"][0]["tool"] == "debuggee.launch"
          and ready["next_actions"][1]["tool"] == "debuggee.attach",
          "Readiness did not advertise bounded launch and attach actions.")
    client.rpc("initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "real-integration", "version": "1"},
    }, request_id=1)
    before_launch = tool("debugger.state", {}, 2)
    check(before_launch["instance_id"] == client.instance_id,
          "Readiness and debugger.state reported different backend instances.")
    check(before_launch["debuggee_state"] == "absent"
          and before_launch["diagnostic_code"] == "NO_DEBUGGEE"
          and len(before_launch["next_actions"]) == 2
          and before_launch["next_actions"][0]["tool"] == "debuggee.launch"
          and before_launch["next_actions"][1]["tool"] == "debuggee.attach",
          "Isolated debugger did not advertise absent-debuggee launch and attach actions.")
    initial_events = tool("events.list", {"limit": 1}, 212)
    check(initial_events["items"] == [] and initial_events["latest_sequence"] == 0
          and initial_events["history_complete"] and initial_events["storage_error"] is None
          and initial_events["next_cursor"] is None and initial_events["session_id"],
          "A fresh backend instance did not expose an empty event history.")
    rejected("debuggee.launch", operation(path=".\\relative-fixture.exe"), "INVALID_ARGUMENT", 3)
    launch_argument_values = ["", "plain", "with space", 'quote"inside', "trail\\",
                              "comma,value", "\u5169\u500b\u5b57"]
    launch_arguments = operation(path=fixture, working_directory=str(backend_root),
                                 arguments=launch_argument_values)
    launch = replay("debuggee.launch", launch_arguments, 4, 204)
    exact(launch["arguments"], launch_argument_values, "Launch result arguments were not exact.")
    rejected("debuggee.launch", {**launch_arguments, "arguments": ["different"]},
             "OPERATION_ID_CONFLICT", 205)
    state = tool("debugger.state", {}, 5)
    generation = state["state_generation"]
    check(state["debuggee_state"] == "paused", "Fixture did not reach paused state.")
    check(state.get("diagnostic_code") is None and state["next_actions"] == [],
          "Paused debugger.state retained a stale bootstrap diagnostic.")
    startup_event_types = ["process_created", "system_breakpoint", "dll_loaded"]
    startup_event_page_one = tool("events.list", {"types": startup_event_types, "limit": 1}, 213)
    check(len(startup_event_page_one["items"]) == 1 and startup_event_page_one["next_cursor"]
          and startup_event_page_one["history_complete"] and startup_event_page_one["storage_error"] is None
          and startup_event_page_one["items"][0]["type"] in startup_event_types
          and startup_event_page_one["items"][0]["state_generation"]
          and startup_event_page_one["items"][0]["session_id"] == startup_event_page_one["session_id"],
          "Filtered debugger-event history did not return a bounded first page.")
    startup_event_page_two = tool("events.list", {
        "cursor": startup_event_page_one["next_cursor"],
        "types": startup_event_types, "limit": 256,
    }, 214)
    check(len(startup_event_page_two["items"]) >= 1
          and startup_event_page_two["items"][0]["sequence"] > startup_event_page_one["items"][0]["sequence"]
          and startup_event_page_two["session_id"] == startup_event_page_one["session_id"]
          and startup_event_page_two["next_cursor"] is None,
          "Debugger-event continuation did not preserve sequence order and filter semantics.")
    rejected("events.wait", {"types": startup_event_types, "timeout_ms": 100}, "TIMEOUT", 215)

    registers = tool("registers.read", {}, 3)
    callstack = tool("callstack.read", {"limit": 50}, 201)
    check(callstack["thread_id"] and len(callstack["frames"]) <= 50
          and callstack["native_frame_count"] >= len(callstack["frames"])
          and callstack["completeness"] in ("native_bounded", "inconclusive")
          and callstack["state_generation"] == generation,
          "Native call-stack read was not bounded and generation-consistent.")
    specific_callstack = tool("callstack.read", {"thread_id": callstack["thread_id"], "limit": 1}, 202)
    check(specific_callstack["thread_id"] == callstack["thread_id"] and len(specific_callstack["frames"]) <= 1,
          "Exact-thread call-stack selection did not honor its bound.")
    expression = tool("expression.evaluate", {"expression": "cip"}, 4)
    batch_expressions = tool("expressions.evaluate_batch", {
        "expressions": ["cip", "csp", "x64dbg_mcp_symbol_that_does_not_exist"],
    }, 221)
    check(batch_expressions["requested_count"] == 3 and batch_expressions["success_count"] == 2
          and len(batch_expressions["items"]) == 3
          and batch_expressions["items"][0]["success"] and batch_expressions["items"][0]["value"]
          and batch_expressions["items"][1]["success"] and batch_expressions["items"][1]["value"]
          and not batch_expressions["items"][2]["success"]
          and batch_expressions["items"][2]["error"]["code"] == "INVALID_EXPRESSION"
          and batch_expressions["state_generation"] == generation,
          "Batch expression evaluation did not preserve per-item results and generation.")
    peb = tool("process.peb", {}, 222)
    check(all(peb[key] for key in ("address", "image_base", "loader_data", "process_parameters",
                                   "process_heap", "nt_global_flag"))
          and peb.get("being_debugged") is not None and peb["state_generation"] == generation,
          "Typed PEB summary was incomplete or generation-inconsistent.")
    peb_being_debugged_address = hex(int(peb["address"], 16) + 2)
    peb_being_debugged_original = tool("memory.read", {"address": peb_being_debugged_address, "length": 1}, 333)
    arguments = tool("context.arguments", {"count": 6}, 223)
    check(arguments["calling_convention"] == ("windows_x64" if args.backend == "x64" else "cdecl")
          and arguments["assumption"] == "paused_at_callee_entry" and len(arguments["items"]) == 6
          and arguments["items"][0]["source"] == ("rcx" if args.backend == "x64" else "stack")
          and arguments["return_address"] and arguments["state_generation"] == generation,
          "ABI argument candidates were incomplete or misleadingly described.")
    memory = tool("memory.read", {"address": expression["value"], "length": 16}, 5)
    disassembly = tool("disassembly.read", {"address": expression["value"], "count": 4}, 6)
    modules = tool("modules.list", {"limit": 256}, 7)
    fixture_module = first(modules["items"], lambda item: item["name"].lower() == args.fixture_name.lower(),
                           f"Launched fixture {args.fixture_name!r} missing from modules.list.")
    module_base = int(fixture_module["base"], 16)
    module_entry = int(fixture_module["entry"], 16)
    module_name = fixture_module["name"]
    section_page_one = tool("sections.list", {"module": module_name, "limit": 1}, 217)
    check(section_page_one["native_count"] >= 2
          and section_page_one["matched_count"] == section_page_one["native_count"]
          and len(section_page_one["items"]) == 1 and section_page_one["next_cursor"]
          and section_page_one["state_generation"] == generation,
          "Bounded loaded-section pagination did not return one generation-consistent item.")
    section_page_two = tool("sections.list", {
        "module": module_name, "limit": 1, "cursor": section_page_one["next_cursor"],
    }, 218)
    check(len(section_page_two["items"]) == 1 and section_page_two["native_count"] == section_page_one["native_count"],
          "Loaded-section cursor did not preserve native list shape.")
    rejected("sections.list", {"module": module_name, "query": ".text", "limit": 1,
                               "cursor": section_page_one["next_cursor"]}, "INVALID_ARGUMENT", 219)
    text_sections = tool("sections.list", {"module": module_name, "query": ".text", "limit": 16}, 220)
    text_section = first(text_sections["items"], lambda item: item["name"].lower() == ".text",
                         "Loaded fixture .text metadata was unavailable.")
    check(text_sections["completeness"] == "loaded_image_sections"
          and text_section["start"]["state_generation"] == generation,
          "Loaded fixture .text metadata was generation-inconsistent.")
    text_start = int(text_section["start"]["address"], 16)
    text_end = int(text_section["end_exclusive"], 16)
    check(text_end > text_start and text_start <= module_entry < text_end,
          "The loaded .text section did not contain the fixture entry point.")
    import_page_one = tool("imports.list", {"module": module_name, "limit": 1}, 206)
    check(import_page_one["native_count"] >= 1 and import_page_one["matched_count"] >= 1
          and len(import_page_one["items"]) == 1 and import_page_one["next_cursor"]
          and import_page_one["state_generation"] == generation,
          "Bounded import pagination did not return one generation-consistent item.")
    import_page_two = tool("imports.list", {
        "module": module_name, "limit": 1, "cursor": import_page_one["next_cursor"],
    }, 207)
    check(len(import_page_two["items"]) <= 1 and import_page_two["native_count"] == import_page_one["native_count"],
          "Import cursor did not preserve its native snapshot shape.")
    rejected("imports.list", {"module": module_name, "query": "Sleep", "limit": 1,
                              "cursor": import_page_one["next_cursor"]}, "INVALID_ARGUMENT", 208)
    sleep_imports = tool("imports.list", {"module": module_name, "query": "Sleep", "limit": 16}, 209)
    sleep_import = first(sleep_imports["items"], lambda item: "sleep" in (item.get("name") or "").lower(),
                         "Module import metadata omitted the fixture Sleep IAT record.")
    check(sleep_import["iat"]["address"] and sleep_import["resolution"] in ("resolved", "unresolved", "unreadable"),
          "Invalid fixture Sleep IAT metadata.")
    fixture_exports = tool("exports.list", {"module": module_name, "query": "mcp_fixture", "limit": 16}, 210)
    check(fixture_exports["matched_count"] >= 3 and len(fixture_exports["items"]) >= 3
          and all(item["location"]["address"] for item in fixture_exports["items"]),
          "Module export metadata did not expose the fixture exports.")
    kernel_module = first(modules["items"], lambda item: item["name"].lower() == "kernel32.dll",
                          "Loaded kernel32 module unavailable for forwarder qualification.")
    forwarded_exports = tool("exports.list", {
        "module": kernel_module["name"], "query": "AcquireSRWLockExclusive", "limit": 16,
    }, 211)
    forwarded_export = first(forwarded_exports["items"], lambda item: item["forwarded"] and item["forward_name"],
                             "Forwarded export metadata was not preserved by exports.list.")
    entry_rva = hex(module_entry - module_base)
    module_entry_ref = {"module": module_name.upper(), "rva": entry_rva}
    resolved_entry = tool("address.resolve", {"address": module_entry_ref}, 41)
    check(resolved_entry["address"] == fixture_module["entry"]
          and resolved_entry["module"].lower() == module_name.lower() and resolved_entry["rva"] == entry_rva,
          "Module-relative address resolution did not return the fixture entry.")
    resolved_absolute = tool("address.resolve", {"address": {"absolute": fixture_module["entry"]}}, 44)
    check(resolved_absolute["address"] == resolved_entry["address"]
          and resolved_absolute["module"].lower() == resolved_entry["module"].lower()
          and resolved_absolute["rva"] == resolved_entry["rva"],
          "Structured absolute and module-relative references did not resolve equally.")
    rejected("address.resolve", {"address": {"module": "definitely-missing.exe", "rva": "0x0"}}, "INVALID_ARGUMENT", 45)
    rejected("address.resolve", {"address": {"module": module_name, "rva": fixture_module["size"]}}, "INVALID_ARGUMENT", 46)
    rejected("address.resolve", {"address": "0x100000000" if args.backend == "x32" else "0x10000000000000000"},
             "INVALID_ARGUMENT", 47)
    after_width_error = tool("debugger.state", {}, 48)
    check(after_width_error["plugin_state"] == "ready" and after_width_error["debuggee_state"] == "paused",
          "A pointer-width validation error damaged the plugin connection.")
    module_memory = tool("memory.read", {"address": module_entry_ref, "length": 16}, 42)
    memory_views = {
        format_name: tool("memory.read", {
            "address": module_entry_ref, "length": 16, "format": format_name,
            **({"byte_order": "big"} if format_name in ("word", "dword", "qword") else {}),
        }, 430 + index)
        for index, format_name in enumerate(("bytes", "word", "dword", "qword", "str", "wstr"))
    }
    check(all(item["data_hex"] == module_memory["data_hex"]
              and item["view"]["format"] == format_name
              for format_name, item in memory_views.items())
          and memory_views["bytes"]["view"]["text"].replace(" ", "").lower() == module_memory["data_hex"]
          and all(memory_views[name]["view"]["byte_order"] == "big"
                  for name in ("word", "dword", "qword"))
          and all(memory_views[name]["view"]["status"] in ("ok", "decode_error")
                  for name in ("str", "wstr")),
          "Formatted memory reads changed raw bytes or returned an invalid bounded view.")
    dump_path = backend_root / f"mcp-memory-dump-{uuid.uuid4()}.bin"
    failed_dump_path = backend_root / f"mcp-memory-dump-failed-{uuid.uuid4()}.bin"
    dumped = tool("memory.dump", operation(address=module_entry_ref, length=16,
                                            path=str(dump_path)), 436)
    expected_dump = bytes.fromhex(module_memory["data_hex"])
    check(dumped["complete"] and dumped["bytes_written"] == 16
          and dumped["path"] == str(dump_path)
          and dumped["sha256"] == hashlib.sha256(expected_dump).hexdigest()
          and dump_path.read_bytes() == expected_dump,
          "memory.dump did not atomically publish the exact raw bytes and SHA-256.")
    rejected("memory.dump", operation(address=module_entry_ref, length=16,
             path=str(dump_path)), "ACCESS_DENIED", 437)
    check(dump_path.read_bytes() == expected_dump,
          "The default overwrite:false changed an existing dump destination.")
    rejected("memory.dump", operation(address="0x1", length=16,
             path=str(failed_dump_path)), "ACCESS_DENIED", 438)
    check(not failed_dump_path.exists(), "A failed memory dump exposed a partial destination file.")
    dump_path.unlink()
    entry_pattern = module_memory["data_hex"][:8]
    entry_search_arguments = {"scope": {"start": module_entry_ref, "length": 16},
                              "pattern_hex": entry_pattern, "mask": "xxxx", "limit": 1}
    entry_search = tool("memory.search", entry_search_arguments, 227)
    check(len(entry_search["items"]) == 1 and entry_search["items"][0]["location"]["address"] == fixture_module["entry"]
          and entry_search["next_cursor"] and not entry_search["scan_complete"]
          and entry_search["bytes_scanned"] == 1 and entry_search["state_generation"] == generation,
          "Explicit-range memory search did not return the entry match and continuation.")
    rejected("memory.search", {**entry_search_arguments, "mask": "xxx?", "cursor": entry_search["next_cursor"]},
             "INVALID_ARGUMENT", 228)
    wildcard_entry_search = tool("memory.search", {**entry_search_arguments, "mask": "xxx?", "limit": 8}, 231)
    check(sum(item["location"]["address"] == fixture_module["entry"] for item in wildcard_entry_search["items"]) == 1,
          "Live wildcard memory search did not retain the entry match.")
    unreadable_search = tool("memory.search", {
        "scope": {"start": "0x1", "length": 4096}, "pattern_hex": "4d5a", "mask": "xx", "limit": 8,
    }, 232)
    check(unreadable_search["read_completeness"] == "partial_unreadable" and unreadable_search["unreadable_bytes"] >= 1
          and unreadable_search["items"] == [] and unreadable_search["scan_complete"],
          "Unreadable memory search did not report a bounded partial result.")
    sentinel_bytes = b"MCP_DISCOVERY_ASCII_SENTINEL"
    sentinel_hex, sentinel_mask = sentinel_bytes.hex(), "x" * len(sentinel_bytes)
    module_pattern_search = tool("memory.search", {
        "scope": {"module": module_name.upper()}, "pattern_hex": sentinel_hex, "mask": sentinel_mask, "limit": 8,
    }, 229)
    check(len(module_pattern_search["items"]) >= 1
          and any(item["location"]["module"].lower() == module_name.lower() for item in module_pattern_search["items"])
          and module_pattern_search["pattern_hex"] == sentinel_hex and module_pattern_search["mask"] == sentinel_mask
          and module_pattern_search["state_generation"] == generation,
          "Module-scoped memory search did not find the fixture byte sentinel.")
    module_disassembly = tool("disassembly.read", {"address": module_entry_ref, "count": 4}, 43)
    patch_instruction_size = module_disassembly["items"][0]["size"]
    check(1 <= patch_instruction_size <= 16, "Fixture entry did not begin with a bounded patchable instruction.")
    patch_original_hex = module_memory["data_hex"][:patch_instruction_size * 2]
    patch_preview = tool("assembly.preview", {"address": module_entry_ref, "instruction": "int3"}, 120)
    check(patch_preview["bytes_hex"] == "cc" and patch_preview["byte_count"] == 1
          and patch_preview["state_generation"] == generation,
          "Assembly preview was not exact and generation-consistent.")
    rejected("assembly.patch", operation(address=module_entry_ref, instruction="int3",
                                         expected_bytes_hex="00" * patch_instruction_size, fill_nop=True), "CONFLICT", 121)
    tracked_patch = replay("assembly.patch", operation(address=module_entry_ref, instruction="int3",
                           expected_bytes_hex=patch_original_hex, fill_nop=True), 122, 123)
    check(tracked_patch["patch_tracked"] and len(tracked_patch["patched_bytes_hex"]) == len(patch_original_hex)
          and tracked_patch["nop_padding"] == patch_instruction_size - 1,
          "Tracked assembly patch was not bounded or padded.")
    second_patch_instruction = module_disassembly["items"][2]
    second_patch_ref = {"absolute": second_patch_instruction["address"]}
    second_patch_memory = tool("memory.read", {"address": second_patch_ref, "length": second_patch_instruction["size"]}, 209)
    second_patch = tool("assembly.patch", operation(address=second_patch_ref,
                        instruction="nop" if second_patch_memory["data_hex"].startswith("cc") else "int3",
                        expected_bytes_hex=second_patch_memory["data_hex"], fill_nop=True), 210)
    patch_page_one = tool("patches.list", {"module": module_name, "limit": 1}, 211)
    check(len(patch_page_one["items"]) == 1 and patch_page_one["next_cursor"]
          and patch_page_one["next_cursor"].startswith("v3:"),
          "Disjoint patch ranges did not produce a bounded v3 cursor.")
    patch_page_two = tool("patches.list", {"module": module_name, "limit": 1, "cursor": patch_page_one["next_cursor"]}, 212)
    check(len(patch_page_two["items"]) == 1 and not patch_page_two["next_cursor"]
          and patch_page_two["snapshot_fingerprint"] == patch_page_one["snapshot_fingerprint"],
          "Patch pagination mixed snapshots or returned an invalid second page.")
    tool("patches.restore", operation(address=second_patch_ref,
         expected_patched_bytes_hex=second_patch["patched_bytes_hex"],
         expected_original_bytes_hex=second_patch_memory["data_hex"]), 213)
    rejected("patches.list", {"module": module_name, "limit": 1, "cursor": patch_page_one["next_cursor"]}, "STALE_CURSOR", 214)
    listed_patches = tool("patches.list", {"module": module_name.upper(), "limit": 256}, 203)
    listed_entry_patch = first(listed_patches["items"], lambda item: item["start"]["address"] == tracked_patch["address"],
                               "Tracked patch listing omitted the entry range.")
    check(listed_entry_patch["current_matches_patch"] and listed_entry_patch["original_bytes_hex"] == patch_original_hex
          and listed_entry_patch["patched_bytes_hex"] == tracked_patch["patched_bytes_hex"]
          and listed_patches["completeness"] == "tracked_only" and listed_patches["snapshot_fingerprint"],
          "Tracked patch listing did not return the verified adjacent range.")
    rejected("assembly.patch", operation(address=module_entry_ref, instruction="int3",
              expected_bytes_hex=tracked_patch["patched_bytes_hex"], fill_nop=True), "CONFLICT", 124)
    restored_patch = replay("patches.restore", operation(address=module_entry_ref,
                            expected_patched_bytes_hex=tracked_patch["patched_bytes_hex"],
                            expected_original_bytes_hex=patch_original_hex), 125, 126)
    memory_after_restore = tool("memory.read", {"address": module_entry_ref, "length": patch_instruction_size}, 127)
    check(not restored_patch["patch_tracked"] and memory_after_restore["data_hex"] == patch_original_hex,
          "Tracked patch restore did not exactly recover the fixture bytes.")
    patches_after_restore = tool("patches.list", {"module": module_name, "limit": 256}, 204)
    check(patches_after_restore["items"] == [] and patches_after_restore["completeness"] == "tracked_only",
          "Patch listing retained restored patch records.")
    compact_snapshot = tool("debugger.snapshot", {}, 54)
    check(compact_snapshot["state_generation"] == generation
          and compact_snapshot["instruction_pointer"]["address"] == expression["value"]
          and compact_snapshot["instruction_pointer"]["state_generation"] == compact_snapshot["state_generation"]
          and len(compact_snapshot["registers"]) == 4 and len(compact_snapshot["disassembly"]) == 8,
          "Compact debugger snapshot mixed generations or omitted its bounded default fields.")
    symbols = tool("symbols.search", {"module": module_name.upper(), "query": "mcp_fixture", "limit": 64}, 60)
    functions = tool("functions.list", {"module": module_name.upper(), "limit": 64}, 61)
    fixture_symbols = {}
    refs = {}
    for name in ("analysis_target", "marker", "run_to_interrupter", "run_to_target", "exception_trigger",
                 "access_violation_trigger", "access_violation", "access_violation_recovery", "recovery_checkpoint",
                 "recovery_observed", "main_thread_id", "worker_thread_id"):
        symbol = first(symbols["items"], lambda item: item["name"].lower() == "mcp_fixture_" + name,
                       f"Fixture export mcp_fixture_{name} was not available as a structured symbol.")
        check(symbol["location"]["rva"], f"Fixture export {name} omitted its RVA.")
        fixture_symbols[name] = symbol
        refs[name] = {"module": module_name.upper(), "rva": symbol["location"]["rva"]}
    analysis_symbol = fixture_symbols["analysis_target"]
    analysis_ref = refs["analysis_target"]
    marker_symbol, marker_ref = fixture_symbols["marker"], refs["marker"]
    run_to_interrupter_address = fixture_symbols["run_to_interrupter"]["location"]["address"]
    run_to_target_address = fixture_symbols["run_to_target"]["location"]["address"]
    check(text_start <= int(analysis_symbol["location"]["address"], 16) < text_end,
          "The exported fixture analysis target was outside loaded .text metadata.")
    resolved_symbol_by_name = tool("symbols.resolve", {"module": module_name.upper(), "name": analysis_symbol["name"]}, 205)
    resolved_symbol_by_address = tool("symbols.resolve", {"address": {"absolute": analysis_symbol["location"]["address"]}}, 206)
    check(resolved_symbol_by_name["resolution"] == "found" and resolved_symbol_by_name["total_matches"] == 1
          and resolved_symbol_by_name["matches"][0]["location"]["address"] == analysis_symbol["location"]["address"]
          and resolved_symbol_by_address["resolution"] != "missing"
          and any(item["name"] == analysis_symbol["name"] for item in resolved_symbol_by_address["matches"]),
          "Exact symbol resolution did not agree by name and runtime address.")
    missing_symbol = tool("symbols.resolve", {"module": module_name, "name": "__mcp_definitely_missing_symbol__"}, 207)
    check(missing_symbol["resolution"] == "missing" and missing_symbol["total_matches"] == 0,
          "Missing exact symbol resolution was not an explicit successful result.")
    analysis_arguments = operation(address=analysis_ref)
    analysis = tool("analysis.function", analysis_arguments, 72)
    check(analysis["state_generation"] == generation
          and analysis["requested_location"]["address"] == analysis_symbol["location"]["address"]
          and analysis["function"]["start"]["module"] and analysis["function"]["end"]["module"],
          "Explicit function analysis omitted generation-consistent structured results.")
    known_function = tool("functions.at", {"address": analysis_ref}, 208)
    check(known_function["found"] and known_function["function"]["contains_query"]
          and known_function["function"]["start"]["address"] == analysis["function"]["start"]["address"]
          and known_function["function"]["end_inclusive"]["address"] == analysis["function"]["end"]["address"]
          and known_function["completeness"] == "known_only",
          "Known-function lookup did not return the analyzed containing function.")
    exact(analysis, tool("analysis.function", analysis_arguments, 73), "Explicit function analysis did not replay exactly.")
    analysis_function_found, analysis_cursor = False, None
    for page in range(8):
        list_arguments = {"module": module_name.upper(), "limit": 256}
        if analysis_cursor:
            list_arguments["cursor"] = analysis_cursor
        analyzed_functions = tool("functions.list", list_arguments, 74 + page)
        check(analyzed_functions["state_generation"] == generation, "Function discovery changed generation after analysis.")
        if any(item["start"]["address"] == analysis["function"]["start"]["address"] for item in analyzed_functions["items"]):
            analysis_function_found = True
            break
        analysis_cursor = analyzed_functions["next_cursor"]
        if not analysis_cursor:
            break
    check(analysis_function_found, "Explicit analysis was not visible through known-only function discovery.")
    ascii_strings = tool("strings.search", {"module": module_name.upper(), "query": "MCP_DISCOVERY_ASCII_SENTINEL",
                         "encoding": "ascii_utf8", "context_bytes": 0, "min_length": 4, "limit": 8}, 62)
    wide_strings = tool("strings.search", {"module": module_name.upper(), "query": "MCP_DISCOVERY_UTF16_SENTINEL",
                        "encoding": "utf16le", "context_bytes": 0, "min_length": 4, "limit": 8}, 63)
    references = tool("references.to", {"address": module_entry_ref, "limit": 32}, 64)
    check(any(item["text"] == "MCP_DISCOVERY_ASCII_SENTINEL" for item in ascii_strings["items"])
          and any(item["text"] == "MCP_DISCOVERY_UTF16_SENTINEL" for item in wide_strings["items"]),
          "Bounded string discovery did not find both fixture sentinels.")
    for item in ascii_strings["items"] + wide_strings["items"]:
        check(item.get("match_offset") is not None and item.get("text_offset") is not None
              and item["match_offset"] >= item["text_offset"] and item["before"] == "" and item["after"] == ""
              and item["text"] == item["match"] and item["text"] == item["before"] + item["match"] + item["after"],
              "A compact string result omitted its exact reconstructable match context.")
    for discovery in (symbols, functions, ascii_strings, wide_strings, references):
        check(discovery["completeness"] == "known_only" and discovery["state_generation"] == generation,
              "Discovery result omitted known-only or generation metadata.")
    discovery_cursor_arguments = {"module": module_name, "min_length": 4, "encoding": "both", "limit": 1}
    discovery_cursor_probe = tool("strings.search", discovery_cursor_arguments, 65)
    check(discovery_cursor_probe["next_cursor"] and discovery_cursor_probe["next_cursor"].startswith("v2:"),
          "String discovery did not return a v2 cursor for binding tests.")
    rejected("strings.search", {**discovery_cursor_arguments, "query": "different-filter",
                               "cursor": discovery_cursor_probe["next_cursor"]}, "INVALID_ARGUMENT", 66)
    context_cursor_arguments = {**discovery_cursor_arguments, "query": "MCP", "context_bytes": 0}
    context_cursor_probe = tool("strings.search", context_cursor_arguments, 70)
    check(context_cursor_probe["next_cursor"], "String discovery did not return a cursor for context binding.")
    rejected("strings.search", {**context_cursor_arguments, "context_bytes": 1,
                               "cursor": context_cursor_probe["next_cursor"]}, "INVALID_ARGUMENT", 71)
    check(tool("debugger.state", {}, 67)["plugin_state"] == "ready",
          "A mismatched discovery cursor damaged the plugin connection.")
    threads = tool("threads.list", {"limit": 2}, 8)
    memory_map = tool("memory.map", {"limit": 2}, 9)
    cursor_probe = tool("memory.map", {"limit": 1}, 52)
    filtered_map_arguments = {"module": module_name.upper(), "committed_only": True,
                              "executable_only": True, "compact": True, "limit": 1}
    filtered_map = tool("memory.map", filtered_map_arguments, 69)
    check(len(filtered_map["items"]) == 1 and filtered_map["next_cursor"] and filtered_map["next_cursor"].startswith("v2:"),
          "Filtered memory.map did not return one bounded item and a v2 cursor.")
    module_end = module_base + int(fixture_module["size"], 16)
    for region in filtered_map["items"]:
        region_base, region_size = int(region["base"], 16), int(region["size"], 16)
        check(region["state"] == "0x1000" and region_base < module_end and region_base + region_size > module_base,
              "Filtered memory.map returned a non-committed region outside the fixture module.")
        check("allocation_base" not in region or region["allocation_base"] != region["base"],
              "Compact memory.map retained a redundant allocation_base.")
        check("info" not in region or region["info"], "Compact memory.map retained an empty info field.")
    rejected("memory.map", {**filtered_map_arguments, "compact": False, "cursor": filtered_map["next_cursor"]},
             "INVALID_ARGUMENT", 70)
    check(tool("debugger.state", {}, 71)["plugin_state"] == "ready", "A mismatched memory-map cursor damaged the connection.")
    breakpoints = tool("breakpoints.list", {"limit": 2}, 10)
    check(all(snapshot["state_generation"] for snapshot in
              (state, registers, expression, memory, disassembly, modules, threads, memory_map, breakpoints)),
          "A read snapshot omitted its state_generation.")
    check(memory["state_generation"] == memory["location"]["state_generation"]
          and disassembly["state_generation"] == disassembly["location"]["state_generation"],
          "Address-consuming read returned mixed snapshot generations.")
    check(cursor_probe["next_cursor"], "memory.map did not return a cursor for stale-generation testing.")
    cursor_parts = cursor_probe["next_cursor"].split(":")
    check(len(cursor_parts) == 4 and cursor_parts[0] == "v2" and int(cursor_parts[1]) == cursor_probe["state_generation"],
          "Pagination cursor generation does not match its snapshot.")

    writable_register = "edi" if args.backend == "x32" else "rdi"
    original_register_value = registers["registers"][writable_register]
    test_register_value = "0x55667788" if original_register_value == "0x11223344" else "0x11223344"
    register_write = replay("registers.write", operation(name=writable_register, value=test_register_value), 80, 81)
    register_after_write = tool("registers.read", {"names": [writable_register]}, 82)
    check(register_write["changed"] and register_write["previous_value"] == original_register_value
          and register_write["value"] == test_register_value
          and register_after_write["registers"][writable_register] == test_register_value,
          "Typed register write was not verified or observable.")
    register_restore = tool("registers.write", operation(name=writable_register, value=original_register_value), 83)
    register_after_restore = tool("registers.read", {"names": [writable_register]}, 84)
    check(register_restore["value"] == original_register_value
          and register_after_restore["registers"][writable_register] == original_register_value,
          "Typed register write did not restore the fixture context.")
    rejected("registers.write", operation(name="eflags", value="0x100000000"), "INVALID_ARGUMENT", 85)
    write = replay("memory.write", operation(address=module_entry_ref, data_hex=module_memory["data_hex"][:2]), 11, 12)
    early_hardware_rejected = None
    if state["pause_reason"]["kind"] in ("process_created", "system_breakpoint"):
        rejected("breakpoints.hardware.set", operation(address=analysis_ref, access="execute", size=1),
                 "INVALID_DEBUGGER_STATE", 76)
        early_hardware_rejected = True
    # Native hardware slots need the actionable debug thread, past startup.
    with ThreadPoolExecutor(max_workers=1) as executor:
        future_event = executor.submit(
            client.tool, "events.wait", {"types": ["resumed"], "timeout_ms": 5000}, 439,
        )
        time.sleep(0.25)
        hardware_ready_resume, hardware_ready_pause = resume_wait(78, 79)
        resumed_event = future_event.result(timeout=6)
    check(resumed_event["event"]["type"] == "resumed"
          and resumed_event["event"]["session_id"] == resumed_event["session_id"],
          "Future-only events.wait did not observe the deterministic resumed event after arming.")
    check(hardware_ready_pause["debuggee_state"] == "paused"
          and hardware_ready_pause["state_generation"] > hardware_ready_resume["state_generation"],
          "Fixture did not reach an actionable pause before hardware breakpoint setup.")
    analysis_address = analysis["requested_location"]["address"]
    rejected("breakpoints.hardware.set", operation(address={"absolute": hex(int(analysis_address, 16) + 1)},
                                                   access="write", size=4), "INVALID_ARGUMENT", 77)
    if args.backend == "x32":
        rejected("breakpoints.hardware.set", operation(address=analysis_ref, access="write", size=8), "INVALID_ARGUMENT", 75)
    hardware_set = replay("breakpoints.hardware.set", operation(address=analysis_ref, access="execute", size=1), 86, 87)
    hardware_list = tool("breakpoints.list", {"limit": 256}, 88)
    listed_hardware = first(hardware_list["items"], lambda item: item["address"] == analysis_address and item["type"] == "hardware",
                            "Hardware breakpoint was not listed.")
    check(hardware_set["present"] and hardware_set["access"] == "execute" and hardware_set["size"] == 1
          and 0 <= hardware_set["slot"] <= 3 and listed_hardware["access"] == "execute" and listed_hardware["size"] == 1,
          "Typed hardware breakpoint was not exactly listed.")
    hardware_selector = {"kind": "hardware", "address": analysis_ref, "access": "execute", "size": 1}
    hardware_disable_arguments = operation(selector=hardware_selector)
    hardware_disabled = replay("breakpoints.disable", hardware_disable_arguments, 320, 321)
    disabled_hardware_list = tool("breakpoints.list", {"limit": 256}, 322)
    listed_disabled_hardware = first(disabled_hardware_list["items"],
        lambda item: item["address"] == analysis_address and item["type"] == "hardware", "Disabled hardware breakpoint disappeared.")
    check(hardware_disabled["changed"] and not hardware_disabled["enabled"] and hardware_disabled.get("slot") is None
          and not listed_disabled_hardware["enabled"] and listed_disabled_hardware.get("slot") is None,
          "Hardware disable did not preserve exact typed identity.")
    rejected("breakpoints.disable", {**hardware_disable_arguments, "selector": {**hardware_selector, "access": "write"}},
             "OPERATION_ID_CONFLICT", 323)
    hardware_enabled = tool("breakpoints.enable", operation(selector=hardware_selector), 324)
    hardware_enable_noop = tool("breakpoints.enable", operation(selector=hardware_selector), 333)
    check(hardware_enabled["changed"] and hardware_enabled["enabled"] and 0 <= hardware_enabled["slot"] <= 3
          and not hardware_enable_noop["changed"] and hardware_enable_noop["enabled"],
          "Hardware enable did not reacquire and verify a current debug-register slot.")
    rejected("breakpoints.hardware.remove", operation(address=analysis_ref, access="write", size=1), "CONFLICT", 89)
    step_out_entry_pause = None
    for attempt in range(6):
        _, step_out_wait = resume_wait(87 + attempt * 2, 88 + attempt * 2)
        if step_out_wait["pause_reason"]["kind"] == "breakpoint" and step_out_wait["pause_reason"].get("address") == analysis_address:
            step_out_entry_pause = step_out_wait
            break
    check(step_out_entry_pause, "Fixture analysis target was not reached for step-out qualification.")
    check(step_out_entry_pause["pause_reason"]["breakpoint_type"] == "hardware",
          "Fixture function entry did not report a hardware breakpoint hit.")
    hardware_remove = replay("breakpoints.hardware.remove", operation(address=analysis_ref, access="execute", size=1), 100, 101)
    check(not hardware_remove["present"], "Typed hardware breakpoint removal retained the breakpoint.")
    step_out_disassembly = tool("disassembly.read", {"address": analysis_ref, "count": 6}, 102)
    step_out_interrupt_instruction = first(step_out_disassembly["items"][1:], lambda item: not item["text"].lower().startswith("ret"),
                                          "Fixture function has no deterministic inner instruction for interruption testing.")
    step_out_interrupt_ref = {"absolute": step_out_interrupt_instruction["address"]}
    tool("breakpoints.set", operation(address=step_out_interrupt_ref), 102)
    software_selector = {"kind": "software", "address": step_out_interrupt_ref}
    software_disabled = tool("breakpoints.disable", operation(selector=software_selector), 325)
    software_enabled = tool("breakpoints.enable", operation(selector=software_selector), 326)
    check(software_disabled["changed"] and not software_disabled["enabled"] and software_enabled["changed"] and software_enabled["enabled"],
          "Plain software breakpoint transition was not exactly confirmed.")
    interrupted_step_out = replay("debugger.step_out", operation(), 103, 104)
    check(not interrupted_step_out["completed"] and interrupted_step_out["pause_reason"]["kind"] == "breakpoint"
          and interrupted_step_out["instruction_pointer"] == step_out_interrupt_instruction["address"],
          "Step-out did not expose its deterministic breakpoint interruption.")
    tool("breakpoints.remove", operation(address=step_out_interrupt_ref), 105)
    step_out = replay("debugger.step_out", operation(), 106, 107)
    check(step_out["completed"] and step_out["debuggee_state"] == "paused" and step_out["instruction"]["text"].lower().startswith("ret")
          and int(step_out["stack_pointer"], 16) >= int(step_out["initial_stack_pointer"], 16),
          "Step-out was not callback-confirmed at the fixture return.")
    argument_deadline = time.monotonic() + 5
    while not argument_observation.exists() and time.monotonic() < argument_deadline:
        time.sleep(0.05)
    check(argument_observation.exists(), "Fixture did not record its received launch arguments.")
    observed_arguments = read_observed_arguments(argument_observation)
    check(os.path.abspath(observed_arguments[0]).lower() == os.path.abspath(fixture).lower(),
          "Fixture observed an unexpected argv[0] executable path.")
    exact(observed_arguments[1:], launch_argument_values, "Fixture-observed launch arguments were not exact.")
    marker_address_value = int(marker_symbol["location"]["address"], 16)
    marker_map = tool("memory.map", {"module": module_name.upper(), "committed_only": True,
                      "executable_only": False, "compact": True, "limit": 256}, 116)
    marker_region = first(marker_map["items"], lambda item:
        int(item["base"], 16) <= marker_address_value < int(item["base"], 16) + int(item["size"], 16),
        "Fixture marker memory region was unavailable for range-bound testing.")
    rejected("breakpoints.memory.set", operation(
        address={"absolute": hex(int(marker_region["base"], 16) + int(marker_region["size"], 16) - 1)},
        access="read", size=2), "INVALID_ARGUMENT", 117)
    memory_breakpoint = replay("breakpoints.memory.set", operation(address=marker_ref, access="read", size=4), 108, 109)
    memory_breakpoint_list = tool("breakpoints.list", {"limit": 256}, 110)
    listed_memory = first(memory_breakpoint_list["items"],
        lambda item: item["address"] == marker_symbol["location"]["address"] and item["type"] == "memory",
        "Memory breakpoint was not listed.")
    check(memory_breakpoint["present"] and memory_breakpoint["access"] == "read" and memory_breakpoint["size"] == 4
          and listed_memory["access"] == "read" and listed_memory["size"] == 4,
          "Typed memory breakpoint was not exactly listed.")
    memory_selector = {"kind": "memory", "address": marker_ref, "access": "read", "size": 4}
    memory_disabled = tool("breakpoints.disable", operation(selector=memory_selector), 327)
    memory_enabled = tool("breakpoints.enable", operation(selector=memory_selector), 328)
    check(memory_disabled["changed"] and not memory_disabled["enabled"] and memory_enabled["changed"]
          and memory_enabled["enabled"] and memory_enabled["access"] == "read" and memory_enabled["size"] == 4,
          "Memory breakpoint transition did not preserve its exact range policy.")
    rejected("breakpoints.memory.remove", operation(address=marker_ref, access="write", size=4), "CONFLICT", 111)
    _, memory_pause = resume_wait(112, 113)
    check(memory_pause["pause_reason"]["kind"] == "breakpoint" and memory_pause["pause_reason"]["breakpoint_type"] == "memory",
          "Fixture marker read did not report a memory breakpoint hit.")
    memory_remove = replay("breakpoints.memory.remove", operation(address=marker_ref, access="read", size=4), 114, 115)
    check(not memory_remove["present"], "Typed memory breakpoint removal retained the breakpoint.")

    conditional_set_arguments = operation(address=refs["run_to_interrupter"], condition={
        "mode": "all", "predicates": [{"source": "hit_count", "operator": "eq", "value": 2}],
    })
    conditional_set = replay("breakpoints.conditional.set", conditional_set_arguments, 300, 301)
    conditional_list = tool("breakpoints.list", {"limit": 256}, 302)
    listed_conditional = first(conditional_list["items"],
        lambda item: item["address"] == run_to_interrupter_address and item["type"] == "software",
        "Conditional breakpoint was not listed.")
    check(conditional_set["present"] and conditional_set["fast_resume"]
          and conditional_set["managed_id"] == conditional_set_arguments["operation_id"]
          and conditional_set["condition_expression"] and listed_conditional["managed_id"] == conditional_set["managed_id"]
          and listed_conditional["fast_resume"] and listed_conditional["condition_expression"] == conditional_set["condition_expression"],
          "Typed conditional breakpoint was not exactly listed.")
    conditional_selector = {"kind": "conditional", "address": refs["run_to_interrupter"], "managed_id": conditional_set["managed_id"]}
    conditional_disabled = tool("breakpoints.disable", operation(selector=conditional_selector), 329)
    conditional_enabled = tool("breakpoints.enable", operation(selector=conditional_selector), 330)
    check(conditional_disabled["changed"] and not conditional_disabled["enabled"]
          and conditional_enabled["changed"] and conditional_enabled["enabled"] and conditional_enabled["fast_resume"]
          and conditional_enabled["condition_expression"] == conditional_set["condition_expression"],
          "Conditional breakpoint transition lost its managed condition policy.")
    rejected("breakpoints.conditional.remove", operation(address=refs["run_to_interrupter"], managed_id=str(uuid.uuid4())), "CONFLICT", 303)
    _, conditional_pause = resume_wait(304, 305)
    check(conditional_pause["pause_reason"]["kind"] == "breakpoint"
          and conditional_pause["pause_reason"]["breakpoint_type"] == "software"
          and conditional_pause["pause_reason"]["address"] == run_to_interrupter_address
          and conditional_pause["pause_reason"]["hit_count"] == 2,
          "Conditional hit-count breakpoint did not skip the first hit and pause on the second.")
    conditional_remove = replay("breakpoints.conditional.remove", operation(
        address=refs["run_to_interrupter"], managed_id=conditional_set["managed_id"]), 306, 307)
    check(not conditional_remove["present"], "Typed conditional breakpoint removal retained the breakpoint.")

    exception_set_arguments = operation(code="0xe0424242", chance="first")
    exception_set = replay("breakpoints.exception.set", exception_set_arguments, 308, 309)
    exception_list = tool("breakpoints.list", {"limit": 256}, 310)
    listed_exception = first(exception_list["items"], lambda item: item["type"] == "exception" and item.get("code") == "0xe0424242",
                             "Exception breakpoint was not listed.")
    check(exception_set["present"] and exception_set["chance"] == "first"
          and exception_set["managed_id"] == exception_set_arguments["operation_id"]
          and listed_exception["chance"] == "first" and listed_exception["managed_id"] == exception_set["managed_id"],
          "Typed exception breakpoint was not exactly listed.")
    exception_selector = {"kind": "exception", "code": "0xe0424242", "chance": "first", "managed_id": exception_set["managed_id"]}
    exception_disabled = tool("breakpoints.disable", operation(selector=exception_selector), 331)
    exception_enabled = tool("breakpoints.enable", operation(selector=exception_selector), 332)
    check(exception_disabled["changed"] and not exception_disabled["enabled"]
          and exception_enabled["changed"] and exception_enabled["enabled"] and exception_enabled["chance"] == "first"
          and exception_enabled["managed_id"] == exception_set["managed_id"],
          "Exception breakpoint transition lost its exact managed policy.")
    rejected("breakpoints.exception.remove", operation(code="0xe0424242", chance="first", managed_id=str(uuid.uuid4())), "CONFLICT", 311)
    tool("memory.write", operation(address=refs["exception_trigger"], data_hex="01000000"), 312)
    _, exception_pause = resume_wait(313, 314)
    check(exception_pause["pause_reason"]["kind"] == "exception" and exception_pause["pause_reason"]["code"] == "0xe0424242"
          and exception_pause["pause_reason"]["first_chance"],
          f"Typed exception breakpoint did not report its exact first-chance pause metadata: {exception_pause}")
    exception_remove = replay("breakpoints.exception.remove", operation(
        code="0xe0424242", chance="first", managed_id=exception_set["managed_id"]), 315, 316)
    check(not exception_remove["present"], "Typed exception breakpoint removal retained the breakpoint.")
    tool("debugger.resume", operation(), 317)
    tool("debugger.pause", operation(), 318)

    # Prove an exception-context override executes the ABI-compatible recovery
    # target, rather than merely changing the debugger's register view.
    access_violation_set = tool("breakpoints.exception.set", operation(code="0xc0000005", chance="first"), 319)
    tool("memory.write", operation(address=refs["recovery_observed"], data_hex="00000000"), 320)
    tool("memory.write", operation(address=refs["access_violation_trigger"], data_hex="01000000"), 321)
    tool("breakpoints.set", operation(address=refs["recovery_checkpoint"]), 328)
    _, av_pause = resume_wait(322, 323)
    check(av_pause["pause_reason"]["kind"] == "exception" and av_pause["pause_reason"]["code"] == "0xc0000005"
          and av_pause["pause_reason"]["first_chance"],
          "Benign access-violation fixture did not reach its first-chance pause.")
    instruction_register = "eip" if args.backend == "x32" else "rip"
    av_continue = tool("debugger.continue_exception", operation(disposition="handled", register_overrides=[{
        "name": instruction_register, "value": fixture_symbols["access_violation_recovery"]["location"]["address"],
    }]), 324)
    recovery_pause = tool("debugger.wait_for_pause", {"after_generation": av_continue["state_generation"], "timeout_ms": 9000}, 325)
    recovery_observed = tool("memory.read", {"address": refs["recovery_observed"], "length": 4}, 326)
    check(av_continue["debuggee_state"] == "running" and recovery_pause["pause_reason"]["kind"] == "breakpoint"
          and recovery_pause["instruction_pointer"] == fixture_symbols["recovery_checkpoint"]["location"]["address"]
          and recovery_observed["data_hex"] != "00000000",
          "Exception continuation did not execute the ABI-compatible recovery target.")
    rejected_override_thread = recovery_pause["active_thread_id"]
    check(rejected_override_thread, "Recovery checkpoint pause omitted its correlated thread.")
    before_rejected_override = tool("registers.read", {"thread_id": rejected_override_thread}, 700)
    rejected_override_register = "eax" if args.backend == "x32" else "rax"
    rejected_override_value = "0x2" if int(before_rejected_override["registers"][rejected_override_register], 16) == 1 else "0x1"
    for disposition in ("handled", "not_handled"):
        rejected("debugger.continue_exception", operation(disposition=disposition, register_overrides=[{
            "name": rejected_override_register, "value": rejected_override_value,
        }]), "INVALID_DEBUGGER_STATE", 701)
        after_rejected_override = tool("registers.read", {"thread_id": rejected_override_thread}, 702)
        exact(before_rejected_override["registers"], after_rejected_override["registers"],
              "Rejected exception continuation changed the paused thread registers.")
    tool("breakpoints.remove", operation(address=refs["recovery_checkpoint"]), 329)
    tool("breakpoints.exception.remove", operation(code="0xc0000005", chance="first", managed_id=access_violation_set["managed_id"]), 327)

    run_to_interrupter_set = tool("breakpoints.set", operation(address=refs["run_to_interrupter"]), 221)
    run_to_interrupted = tool("debugger.run_to_address", operation(address=refs["run_to_target"], timeout_ms=9000), 222)
    check(not run_to_interrupted["completed"] and run_to_interrupted["interruption"] == "breakpoint"
          and run_to_interrupted["temporary_breakpoint_cleaned"] and run_to_interrupted["instruction_pointer"] == run_to_interrupter_address,
          "Owned run-to did not report and clean an intervening caller breakpoint.")
    run_to_breakpoints = tool("breakpoints.list", {"limit": 256}, 223)
    check(sum(item["address"] == run_to_interrupter_address and item["type"] == "software" for item in run_to_breakpoints["items"]) == 1
          and not any(item["address"] == run_to_target_address and item["type"] == "software" for item in run_to_breakpoints["items"]),
          "Owned run-to cleanup removed caller state or retained its temporary target.")
    tool("breakpoints.remove", operation(address=refs["run_to_interrupter"]), 224)
    run_to_arguments = operation(address=refs["run_to_target"], timeout_ms=9000)
    run_to_completed = replay("debugger.run_to_address", run_to_arguments, 225, 226)
    check(run_to_completed["completed"] and run_to_completed["resumed"] and run_to_completed.get("interruption") is None
          and run_to_completed["temporary_breakpoint_cleaned"] and run_to_completed["instruction_pointer"] == run_to_target_address,
          "Owned run-to did not reach and clean its target.")
    rejected("debugger.run_to_address", {**run_to_arguments, "address": module_entry_ref}, "OPERATION_ID_CONFLICT", 227)
    run_to_timeout = tool("debugger.run_to_address", operation(address=module_entry_ref, timeout_ms=250), 228)
    check(not run_to_timeout["completed"] and run_to_timeout["interruption"] == "timeout"
          and run_to_timeout["temporary_breakpoint_cleaned"] and run_to_timeout["debuggee_state"] == "paused",
          "Owned run-to timeout did not pause and clean its unreachable target.")
    after_run_to_breakpoints = tool("breakpoints.list", {"limit": 256}, 229)
    check(not any(item["address"] == resolved_entry["address"] and item["type"] == "software" for item in after_run_to_breakpoints["items"]),
          "Owned run-to timeout retained its entry-point temporary breakpoint.")

    main_thread_id_memory = tool("memory.read", {"address": refs["main_thread_id"], "length": 4}, 243)
    worker_thread_id_memory = tool("memory.read", {"address": refs["worker_thread_id"], "length": 4}, 244)
    for thread_memory in (main_thread_id_memory, worker_thread_id_memory):
        check(re.fullmatch(r"[0-9a-fA-F]{8}", thread_memory["data_hex"]), "Expected exactly four hexadecimal thread-ID bytes.")
    fixture_main_thread_id = hex(struct.unpack("<I", bytes.fromhex(main_thread_id_memory["data_hex"]))[0])
    fixture_worker_thread_id = hex(struct.unpack("<I", bytes.fromhex(worker_thread_id_memory["data_hex"]))[0])
    threads_before_context_read = tool("threads.list", {"limit": 256}, 230)
    selected_thread = first(threads_before_context_read["items"], lambda item: item["current"], "No selected thread.")
    main_thread = first(threads_before_context_read["items"], lambda item: item["thread_id"] == fixture_main_thread_id, "Fixture main thread missing.")
    worker_thread = first(threads_before_context_read["items"], lambda item: item["thread_id"] == fixture_worker_thread_id, "Fixture worker thread missing.")
    check(main_thread["thread_id"] != worker_thread["thread_id"] and worker_thread["instruction_pointer"],
          "Fixture did not expose its exported persistent main and worker threads.")
    # A timeout pause may select either fixture thread; exercise the other one.
    if worker_thread["thread_id"] == selected_thread["thread_id"]:
        worker_thread = main_thread
    context_names = ["cip", "csp", "cbp", "eflags"]
    default_selected_registers = tool("registers.read", {"names": context_names}, 231)
    explicit_selected_registers = tool("registers.read", {"names": context_names, "thread_id": selected_thread["thread_id"]}, 232)
    worker_registers = tool("registers.read", {"names": context_names, "thread_id": worker_thread["thread_id"]}, 233)
    worker_snapshot = tool("debugger.snapshot", {"registers": context_names, "disassembly_count": 4, "thread_id": worker_thread["thread_id"]}, 234)
    threads_after_context_read = tool("threads.list", {"limit": 256}, 235)
    selected_thread_after = first(threads_after_context_read["items"], lambda item: item["current"], "Selected thread disappeared.")
    exact(default_selected_registers["registers"], explicit_selected_registers["registers"], "Default and explicit selected register maps differ.")
    selected_maps_equal = True
    check(default_selected_registers["current"] and explicit_selected_registers["current"]
          and default_selected_registers["thread_id"] == selected_thread["thread_id"]
          and explicit_selected_registers["thread_id"] == selected_thread["thread_id"]
          and not worker_registers["current"] and not worker_snapshot["current"]
          and worker_registers["thread_id"] == worker_thread["thread_id"] and worker_snapshot["thread_id"] == worker_thread["thread_id"]
          and worker_registers["registers"]["cip"] == worker_thread["instruction_pointer"]
          and worker_snapshot["instruction_pointer"]["address"] == worker_thread["instruction_pointer"]
          and worker_snapshot["active_thread_id"] == selected_thread["thread_id"] and len(worker_snapshot["disassembly"]) == 4
          and selected_thread_after["thread_id"] == selected_thread["thread_id"],
          "Exact-thread register/snapshot reads were inconsistent or changed thread selection: "
          f"selected={selected_thread}, after={selected_thread_after}, default={default_selected_registers}, "
          f"explicit={explicit_selected_registers}, worker={worker_thread}, registers={worker_registers}, snapshot={worker_snapshot}")
    worker_writable_before = tool("registers.read", {"names": [writable_register], "thread_id": worker_thread["thread_id"]}, 238)
    worker_original_value = worker_writable_before["registers"][writable_register]
    worker_test_value = "0x27182818" if worker_original_value == "0x31415926" else "0x31415926"
    worker_write = tool("registers.write", operation(name=writable_register, value=worker_test_value, thread_id=worker_thread["thread_id"]), 239)
    worker_after_write = tool("registers.read", {"names": [writable_register], "thread_id": worker_thread["thread_id"]}, 240)
    selection_after_worker_write = tool("threads.list", {"limit": 256}, 241)
    selected_after_worker_write = first(selection_after_worker_write["items"], lambda item: item["current"], "Selected thread disappeared after write.")
    check(worker_write["thread_id"] == worker_thread["thread_id"] and worker_write["value"] == worker_test_value
          and worker_after_write["registers"][writable_register] == worker_test_value
          and selected_after_worker_write["thread_id"] == selected_thread["thread_id"],
          "Exact-thread register write was not verified or changed x64dbg thread selection.")
    tool("registers.write", operation(name=writable_register, value=worker_original_value, thread_id=worker_thread["thread_id"]), 242)
    missing_thread_candidate = 0xffffffff
    known_thread_ids = {item["thread_id"] for item in threads_after_context_read["items"]}
    while hex(missing_thread_candidate) in known_thread_ids:
        missing_thread_candidate -= 1
    rejected("registers.read", {"thread_id": hex(missing_thread_candidate)}, "INVALID_ARGUMENT", 236)
    check(tool("debugger.state", {}, 237)["plugin_state"] == "ready", "A missing exact-thread read damaged the plugin connection.")

    blocked_trace_checks = qualify_blocked_trace(client, module_name, int(state["process_id"], 16), fixture_main_thread_id)
    trace_arguments = operation(mode="over", max_steps=8, timeout_ms=3000)
    trace_before = tool("debugger.state", {}, 400)
    trace_start = replay("trace.start", trace_arguments, 401, 402)
    rejected("trace.start", {**trace_arguments, "max_steps": 9}, "OPERATION_ID_CONFLICT", 403)
    if trace_start["state"] in ("starting", "running"):
        tool("debugger.wait_for_pause", {"after_generation": trace_before["state_generation"], "timeout_ms": 5000}, 404)
    trace_status = tool("trace.status", {"trace_id": trace_start["trace_id"]}, 405)
    check(trace_status["state"] == "completed" and trace_status["reason"] == "max_steps"
          and trace_status["steps_executed"] == 8 and trace_status["points_retained"] == 9,
          f"Bounded trace did not terminate exactly at its step cap: {trace_status}")
    trace_items, trace_cursor = [], None
    for page in range(4):
        result_arguments = {"trace_id": trace_start["trace_id"], "limit": 3}
        if trace_cursor:
            result_arguments["cursor"] = trace_cursor
        trace_page = tool("trace.results", result_arguments, 406 + page)
        trace_items.extend(trace_page["items"])
        trace_cursor = trace_page["next_cursor"]
        if not trace_cursor:
            break
    check(not trace_cursor and len(trace_items) == 9 and [item["sequence"] for item in trace_items] == list(range(9))
          and all(item["address"] for item in trace_items), "Bounded trace result pagination was incomplete or unordered.")
    rejected("trace.results", {"trace_id": trace_start["trace_id"], "limit": 3,
                               "cursor": f"v4:{trace_start['trace_id']}:0:0"}, "STALE_CURSOR", 410)
    tool("debugger.state", {}, 411)
    cancel_trace = tool("trace.start", operation(mode="over", max_steps=4096, timeout_ms=30000), 412)
    rejected("trace.start", operation(mode="into", max_steps=4, timeout_ms=3000), "BUSY", 413)
    cancelled_trace = tool("trace.cancel", operation(trace_id=cancel_trace["trace_id"]), 414)
    check(cancelled_trace["state"] == "cancelled" and cancelled_trace["reason"] == "cancelled",
          "Bounded trace cancellation did not reach a callback-confirmed terminal state.")
    cancel_results = tool("trace.results", {"trace_id": cancel_trace["trace_id"], "limit": 256}, 415)
    check(len(cancel_results["items"]) == cancelled_trace["steps_executed"] + 1,
          "Cancelled trace did not retain its initial point plus every completed step.")
    timeout_before = tool("debugger.state", {}, 416)
    timeout_trace = tool("trace.start", operation(mode="over", max_steps=4096, timeout_ms=100), 417)
    if timeout_trace["state"] in ("starting", "running"):
        tool("debugger.wait_for_pause", {"after_generation": timeout_before["state_generation"], "timeout_ms": 3000}, 418)
    timeout_status = tool("trace.status", {"trace_id": timeout_trace["trace_id"]}, 419)
    check(timeout_status["state"] == "timed_out" and timeout_status["reason"] == "timeout",
          f"Bounded trace did not enforce its wall-clock timeout: {timeout_status}")
    tool("breakpoints.set", operation(address=refs["run_to_target"]), 420)
    interrupt_before = tool("debugger.state", {}, 421)
    interrupted_trace = tool("trace.start", operation(mode="over", max_steps=4096, timeout_ms=5000), 422)
    if interrupted_trace["state"] in ("starting", "running"):
        tool("debugger.wait_for_pause", {"after_generation": interrupt_before["state_generation"], "timeout_ms": 5000}, 423)
    interrupted_status = tool("trace.status", {"trace_id": interrupted_trace["trace_id"]}, 424)
    check(interrupted_status["state"] == "interrupted" and interrupted_status["reason"] == "breakpoint",
          f"Bounded trace did not preserve breakpoint interruption: {interrupted_status}")
    tool("breakpoints.remove", operation(address=refs["run_to_target"]), 425)

    resume, startup_pause, stable_running = None, None, False
    tool("memory.write", operation(address=peb_being_debugged_address, data_hex="00"), 334)
    peb_being_debugged_hidden = tool("memory.read", {"address": peb_being_debugged_address, "length": 1}, 335)
    check(peb_being_debugged_hidden["data_hex"] == "00",
          "The benign fixture PEB BeingDebugged byte was not hidden before pause qualification.")
    for attempt in range(6):
        resume = tool("debugger.resume", operation(), 14 + attempt * 2)
        check(resume["state_generation"], "debugger.resume omitted its callback-confirmed state_generation.")
        wait_envelope = client.tool_result("debugger.wait_for_pause", {
            "after_generation": resume["state_generation"], "timeout_ms": 1500,
        }, request_id=15 + attempt * 2)
        wait = decode_tool_result(wait_envelope)
        if wait_envelope.get("isError"):
            detail = wait["error"]
            check(detail["code"] == "TIMEOUT" and detail["recoverable"] is True
                  and detail["safeToRetry"] is True and detail.get("retryable") is None,
                  f"Unexpected wait_for_pause failure: {wait}")
            stable_running = True
            break
        startup_pause = wait
        check(startup_pause["debuggee_state"] == "paused" and startup_pause["state_generation"] > resume["state_generation"]
              and startup_pause["pause_reason"]["kind"], "Callback wait did not return a newer structured pause observation.")
        if startup_pause["pause_reason"]["kind"] == "breakpoint":
            reason = startup_pause["pause_reason"]
            check(reason["address"] and reason["breakpoint_type"] and reason.get("hit_count") is not None
                  and startup_pause["instruction_pointer"] and startup_pause["active_thread_id"],
                  "Breakpoint pause observation omitted required address, type, hit, IP, or thread metadata.")
    check(stable_running, "Fixture never reached a stable running window after callback-observed startup pauses.")
    pause = tool("debugger.pause", operation(), 40)
    pause_observation = tool("debugger.wait_for_pause", {"after_generation": resume["state_generation"], "timeout_ms": 1500}, 49)
    check(pause_observation["state_generation"] == pause["state_generation"] and pause_observation["pause_reason"]["kind"] == "user_pause",
          f"Explicit pause was not retained as a generation-consistent user_pause observation: {pause_observation}")
    peb_being_debugged_after_pause = tool("memory.read", {"address": peb_being_debugged_address, "length": 1}, 337)
    check(peb_being_debugged_after_pause["data_hex"] == "00", "Explicit pause changed the hidden PEB BeingDebugged byte.")
    tool("memory.write", operation(address=peb_being_debugged_address, data_hex=peb_being_debugged_original["data_hex"]), 336)
    threads_before_exact_step = tool("threads.list", {"limit": 256}, 332)
    worker_thread_at_step = first(threads_before_exact_step["items"], lambda item: item["thread_id"] == fixture_worker_thread_id,
                                 "Persistent fixture worker thread exited before exact-thread stepping.")
    main_thread_at_step = first(threads_before_exact_step["items"], lambda item: item["thread_id"] == fixture_main_thread_id,
                               "Persistent fixture main thread exited before exact-thread stepping.")
    event_thread_id = pause_observation["active_thread_id"]
    non_event_thread = worker_thread_at_step if worker_thread_at_step["thread_id"] != event_thread_id else main_thread_at_step
    check(event_thread_id and non_event_thread["thread_id"] != event_thread_id, "Pause fixture did not expose a distinct non-event thread.")
    before_rejected_step_registers = tool("registers.read", {"thread_id": non_event_thread["thread_id"]}, 330)
    rejected("debugger.step_into", operation(instance_id=client.instance_id, thread_id=non_event_thread["thread_id"]), "INVALID_ARGUMENT", 333)
    after_rejected_step = tool("debugger.state", {}, 334)
    check(after_rejected_step["state_generation"] == pause["state_generation"] and after_rejected_step["debuggee_state"] == "paused",
          "Rejected non-event step changed debugger state.")
    after_rejected_step_registers = tool("registers.read", {"thread_id": non_event_thread["thread_id"]}, 331)
    exact(after_rejected_step_registers["registers"], before_rejected_step_registers["registers"],
          "Rejected non-event step changed the requested thread registers.")
    # An accepted step is correlated to the event thread; x64dbg does not freeze
    # other runnable threads while continuing that debug event.
    step_into = tool("debugger.step_into", operation(thread_id=event_thread_id), 17)
    step_into_observation = tool("debugger.wait_for_pause", {"after_generation": pause["state_generation"], "timeout_ms": 1500}, 50)
    check(step_into_observation["state_generation"] == step_into["state_generation"] and step_into_observation["pause_reason"]["kind"] == "step"
          and step_into["pause_reason"]["kind"] == "step" and step_into["instruction_pointer"] and step_into["active_thread_id"] == event_thread_id,
          "Exact-thread step-into callback reason, generation, or thread was not retained.")
    rejected("memory.map", {"limit": 1, "cursor": cursor_probe["next_cursor"]}, "STALE_CURSOR", 53)
    rejected("strings.search", {**discovery_cursor_arguments, "cursor": discovery_cursor_probe["next_cursor"]}, "STALE_CURSOR", 68)
    rejected("memory.search", {**entry_search_arguments, "cursor": entry_search["next_cursor"]}, "STALE_CURSOR", 230)
    step_over = tool("debugger.step_over", operation(), 18)
    step_over_observation = tool("debugger.wait_for_pause", {"after_generation": step_into["state_generation"], "timeout_ms": 1500}, 51)
    check(step_over_observation["state_generation"] == step_over["state_generation"] and step_over_observation["pause_reason"]["kind"] == "step"
          and step_over["pause_reason"]["kind"] == "step" and step_over["instruction_pointer"] and step_over["active_thread_id"],
          "Step-over callback reason or generation was not retained.")
    breakpoint_set = tool("breakpoints.set", operation(address=module_entry_ref), 19)
    breakpoint_remove = tool("breakpoints.remove", operation(address=module_entry_ref), 20)
    absent_breakpoint_remove = tool("breakpoints.remove", operation(address=module_entry_ref), 339)
    check(absent_breakpoint_remove["present"] is False,
          "Removing an already-absent breakpoint did not preserve its idempotent final state.")
    action_events = tool("events.list", {"types": ["breakpoint", "paused", "stepped"], "limit": 256}, 216)
    for required_event_type in ("breakpoint", "paused", "stepped"):
        check(any(item["type"] == required_event_type for item in action_events["items"]),
              f"Debugger-event history omitted callback type {required_event_type}.")
    breakpoint_event = first(action_events["items"], lambda item: item["type"] == "breakpoint", "Missing breakpoint event.")
    check(breakpoint_event["address"] and breakpoint_event["breakpoint_type"] and breakpoint_event.get("hit_count") is not None,
          "Debugger-event breakpoint metadata was not structured and applicable.")
    tool("debugger.stop", operation(), 21)

    rejected("debuggee.launch", operation(path=dll_fixture), "INVALID_ARGUMENT", 246)
    rejected("debuggee.launch_dll", operation(path=fixture), "INVALID_ARGUMENT", 247)
    dll_launch_arguments = operation(path=dll_fixture)
    dll_launch = replay("debuggee.launch_dll", dll_launch_arguments, 238, 239)
    check(dll_launch["target_kind"] == "dll" and not dll_launch["target_loaded"]
          and DLL_LOADER_NAME.fullmatch(dll_launch["loader_module"])
          and dll_launch["entry_rva"] != "0x0",
          "Typed DLL launch did not return an exact initial loader pause.")
    rejected("debuggee.launch_dll", {**dll_launch_arguments, "working_directory": str(backend_root)}, "OPERATION_ID_CONFLICT", 240)
    loader_modules = tool("modules.list", {"limit": 256}, 241)
    check(not any(item["name"].lower() == "mcp-debuggee-dll-fixture.dll" for item in loader_modules["items"])
          and sum(item["name"].lower() == dll_launch["loader_module"].lower() for item in loader_modules["items"]) == 1,
          "Initial DLL launch pause did not preserve the loader/target distinction.")
    _, dll_pause = resume_wait(242, 243)
    dll_modules = tool("modules.list", {"limit": 256}, 244)
    loaded_dll = first(dll_modules["items"], lambda item: item["name"].lower() == "mcp-debuggee-dll-fixture.dll", "DLL fixture was not loaded.")
    check(dll_pause["pause_reason"]["kind"] == "breakpoint" and dll_pause["instruction_pointer"] == loaded_dll["entry"]
          and dll_pause["state_generation"] == dll_modules["state_generation"],
          "Typed DLL workflow did not stop at the loaded fixture entry breakpoint.")
    stop = tool("debugger.stop", operation(), 245)
    check(stop["debuggee_state"] == "absent", "Final debugger stop did not return the absent state.")
    # CB_STOPDEBUG precedes x64dbg's generated-loader file cleanup.
    loader_cleanup_deadline = time.monotonic() + 3
    while True:
        retained_loaders = [path for path in backend_root.glob("DLLLoader*.exe") if path.is_file()]
        if not retained_loaders or time.monotonic() >= loader_cleanup_deadline:
            break
        time.sleep(0.025)
    check(not retained_loaders, "x64dbg retained a generated DLL loader after debugger stop.")
    stopped_events = tool("events.list", {"types": ["debug_stopped"], "limit": 16}, 215)
    debug_stopped_event = first(reversed(stopped_events["items"]), lambda item: item["type"] == "debug_stopped",
                                "The callback-confirmed debug stop was absent from debugger-event history.")
    check(debug_stopped_event["sequence"] <= stopped_events["latest_sequence"] and debug_stopped_event["state_generation"] <= stop["state_generation"],
          "The callback-confirmed debug stop had inconsistent event metadata.")

    return {
        "backend": args.backend,
        "instance_id": client.instance_id,
        "debugger_host_process_id": args.debugger_pid,
        "sidecar_port": urlsplit(args.base_url).port,
        "architecture": state["architecture"],
        "launched_path": launch["path"],
        "launch_arguments_exact": True,
        "launch_replay_equal": True,
        "launch_conflict_rejected": True,
        "dll_launch_loader": dll_launch["loader_module"],
        "dll_launch_entry": loaded_dll["entry"],
        "dll_launch_replay_equal": True,
        "dll_launch_conflict_rejected": True,
        "dll_launch_kind_mismatch_rejected": True,
        "dll_loader_cleaned": True,
        "process_id": state["process_id"],
        "registers": len(registers["registers"]),
        "memory_bytes": memory["bytes_read"],
        "instructions": len(disassembly["items"]),
        "modules": len(modules["items"]),
        "imports": import_page_one["native_count"],
        "import_pagination_verified": True,
        "import_cursor_filter_bound": True,
        "sleep_import_resolution": sleep_import["resolution"],
        "fixture_exports": fixture_exports["matched_count"],
        "forwarded_export": forwarded_export["forward_name"],
        "sections": section_page_one["native_count"],
        "section_pagination_verified": True,
        "section_cursor_filter_bound": True,
        "text_section": text_section["start"]["address"],
        "analysis_target_in_text": True,
        "event_history_initially_empty": True,
        "historical_event_wait_timed_out": True,
        "future_event_wait_type": resumed_event["event"]["type"],
        "startup_event_first_type": startup_event_page_one["items"][0]["type"],
        "startup_event_continuation_count": len(startup_event_page_two["items"]),
        "debug_stopped_event_sequence": debug_stopped_event["sequence"],
        "action_event_types_verified": True,
        "threads": len(threads["items"]),
        "memory_regions": len(memory_map["items"]),
        "compact_snapshot_instructions": len(compact_snapshot["disassembly"]),
        "filtered_executable_regions": len(filtered_map["items"]),
        "snapshot_generations_present": True,
        "bootstrap_launch_action_advertised": True,
        "paused_diagnostic_cleared": True,
        "address_snapshot_generations_equal": True,
        "cursor_generation_matches": True,
        "stale_cursor_rejected": True,
        "breakpoints": len(breakpoints["items"]),
        "resolved_entry": resolved_entry["address"],
        "resolved_module": resolved_entry["module"],
        "resolved_rva": resolved_entry["rva"],
        "absolute_resolution_equal": True,
        "missing_module_rejected": True,
        "out_of_range_rva_rejected": True,
        "pointer_width_rejected": True,
        "connection_survived_width_error": True,
        "module_memory_bytes": module_memory["bytes_read"],
        "memory_read_formats": list(memory_views),
        "memory_dump_sha256": dumped["sha256"],
        "memory_dump_atomic_no_partial": True,
        "memory_dump_overwrite_default_preserved": True,
        "memory_search_entry_match": entry_search["items"][0]["location"]["address"],
        "memory_search_module_matches": len(module_pattern_search["items"]),
        "memory_search_wildcard_match": True,
        "memory_search_unreadable_bytes": unreadable_search["unreadable_bytes"],
        "memory_search_cursor_filter_bound": True,
        "stale_memory_search_cursor_rejected": True,
        "module_instructions": len(module_disassembly["items"]),
        "symbols": len(symbols["items"]),
        "functions": len(functions["items"]),
        "callstack_frames": len(callstack["frames"]),
        "callstack_completeness": callstack["completeness"],
        "patches_verified": True,
        "patch_cursor_snapshot_bound": True,
        "exact_symbol_resolution": True,
        "known_function_lookup": True,
        "analysis_function_start": analysis["function"]["start"]["address"],
        "analysis_function_end": analysis["function"]["end"]["address"],
        "analysis_already_known": analysis["already_known"],
        "analysis_generation_unchanged": True,
        "analysis_replay_equal": True,
        "analysis_visible_in_discovery": analysis_function_found,
        "ascii_strings": len(ascii_strings["items"]),
        "utf16_strings": len(wide_strings["items"]),
        "inbound_references": len(references["items"]),
        "discovery_cursor_filter_bound": True,
        "stale_discovery_cursor_rejected": True,
        "write_verified": write["verified"],
        "write_replay_equal": True,
        "register_written": writable_register,
        "register_write_verified": True,
        "register_write_replay_equal": True,
        "register_restored": True,
        "register_width_rejected": True,
        "step_out_completed": step_out["completed"],
        "step_out_interruption_reported": True,
        "step_out_instruction": step_out["instruction"]["text"],
        "step_out_replay_equal": True,
        "hardware_breakpoint_hit": True,
        "initial_pause_reason": state["pause_reason"]["kind"],
        "hardware_startup_pause_rejected": early_hardware_rejected,
        "hardware_alignment_rejected": True,
        "hardware_x86_size_rejected": args.backend == "x32",
        "hardware_breakpoint_slot": hardware_set["slot"],
        "hardware_breakpoint_replay_equal": True,
        "hardware_breakpoint_mismatch_rejected": True,
        "breakpoint_transition_hardware": True,
        "breakpoint_transition_hardware_noop": not hardware_enable_noop["changed"],
        "breakpoint_transition_software": True,
        "memory_breakpoint_hit": True,
        "memory_cross_region_rejected": True,
        "memory_breakpoint_size": memory_breakpoint["size"],
        "memory_breakpoint_replay_equal": True,
        "memory_breakpoint_mismatch_rejected": True,
        "breakpoint_transition_memory": True,
        "conditional_breakpoint_hit_count": conditional_pause["pause_reason"]["hit_count"],
        "conditional_breakpoint_managed": conditional_set["managed_id"],
        "conditional_breakpoint_listed": True,
        "conditional_breakpoint_replay_equal": True,
        "conditional_breakpoint_foreign_remove_rejected": True,
        "conditional_breakpoint_removed": not conditional_remove["present"],
        "breakpoint_transition_conditional": True,
        "exception_breakpoint_code": exception_pause["pause_reason"]["code"],
        "exception_breakpoint_chance": exception_set["chance"],
        "exception_breakpoint_managed": exception_set["managed_id"],
        "exception_breakpoint_listed": True,
        "exception_breakpoint_replay_equal": True,
        "exception_breakpoint_foreign_remove_rejected": True,
        "exception_breakpoint_removed": not exception_remove["present"],
        "breakpoint_transition_exception": True,
        "exception_rejection_dispositions": ["handled", "not_handled"],
        "exception_rejection_registers_unchanged": True,
        "breakpoint_transition_conflict_rejected": True,
        "selected_thread_context_equal": selected_maps_equal,
        "noncurrent_thread_context_read": worker_thread["thread_id"],
        "noncurrent_snapshot_instructions": len(worker_snapshot["disassembly"]),
        "trace_max_steps": trace_status["steps_executed"],
        "trace_points": trace_status["points_retained"],
        "trace_replay_equal": True,
        "trace_cancelled": cancelled_trace["state"] == "cancelled",
        "trace_timed_out": timeout_status["state"] == "timed_out",
        "trace_breakpoint_interrupted": interrupted_status["reason"] == "breakpoint",
        "thread_selection_preserved": selected_thread_after["thread_id"] == selected_thread["thread_id"],
        "missing_thread_rejected": True,
        "run_to_interruption_preserved_caller_breakpoint": run_to_interrupter_set["present"],
        "run_to_target": run_to_completed["instruction_pointer"],
        "run_to_replay_equal": True,
        "run_to_conflict_rejected": True,
        "run_to_timeout_cleaned": True,
        "resume_state": resume["debuggee_state"],
        "resume_generation": resume["state_generation"],
        "startup_pause_reason": startup_pause["pause_reason"]["kind"] if startup_pause else None,
        "wait_timeout_safe_to_retry": True,
        "pause_reason": pause_observation["pause_reason"]["kind"],
        "pause_generation": pause_observation["state_generation"],
        "step_into_state": step_into["debuggee_state"],
        "step_into_reason": step_into_observation["pause_reason"]["kind"],
        "step_over_state": step_over["debuggee_state"],
        "step_over_reason": step_over_observation["pause_reason"]["kind"],
        "breakpoint_set": breakpoint_set["present"],
        "breakpoint_removed": not breakpoint_remove["present"],
        "pause_state": pause["debuggee_state"],
        "stop_state": stop["debuggee_state"],
        "blocked_trace_checks": blocked_trace_checks,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--backend", type=str.lower, choices=("x32", "x64"), required=True)
    parser.add_argument("--backend-root", required=True)
    parser.add_argument("--fixture-name", required=True)
    parser.add_argument("--debugger-pid", type=int, required=True)
    return parser.parse_args(argv)


def main():
    args = parse_args()
    check(Path(args.fixture_name).name == args.fixture_name and Path(args.fixture_name).suffix.lower() == ".exe",
          "fixture-name must be an .exe leaf filename.")
    client = McpClient(args.base_url, os.environ["X64DBG_MCP_TOKEN"])
    report = run(client, args)
    print(json.dumps(report, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"real-integration: {error}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
