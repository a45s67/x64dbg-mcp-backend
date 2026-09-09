"""HTTP assertions for run-flare-checksum-smoke.ps1; ownership stays in PS."""

import argparse
import json
import ntpath
import os
import sys
import uuid

from mcp_client import McpClient, assert_exact


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def find_installed_string(client, module, query, id_base):
    cursor = None
    for page in range(8):
        arguments = {
            "module": module, "query": query, "encoding": "ascii_utf8",
            "context_bytes": 32, "min_length": 4, "limit": 16,
        }
        if cursor:
            arguments["cursor"] = cursor
        result = client.tool("strings.search", arguments, request_id=id_base + page)
        match = next((item for item in result["items"]
                      if query.lower() in item["text"].lower()), None)
        if match is not None:
            return {"item": match, "page": page + 1, "result": result}
        cursor = result.get("next_cursor")
        if not cursor:
            break
    raise AssertionError(f"Installed strings.search did not find '{query}' within eight bounded pages.")


def run(client, args):
    # No automatic retries: repeated mutations below deliberately reuse operation identities.
    tool = client.tool
    ready = client.health()
    check(ready["instance_id"] == client.instance_id,
          "Readiness changed backend instances after endpoint ownership verification.")
    check(ready["status"] == "ready" and ready["debugger_state"] == "absent" and
          ready["diagnostic_code"] == "NO_DEBUGGEE" and
          [action["tool"] for action in ready["next_actions"]] == ["debuggee.launch", "debuggee.attach"],
          "Installed readiness did not advertise explicit launch and attach actions.")
    client.rpc("initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "flare-checksum-smoke", "version": "1"},
    }, request_id=1)
    initial = tool("debugger.state", {}, request_id=2)
    check(initial["instance_id"] == client.instance_id,
          "Readiness and debugger.state reported different backend instances.")
    check(initial["debuggee_state"] == "absent", "Installed debugger did not start without a debuggee.")
    check(initial["diagnostic_code"] == "NO_DEBUGGEE" and
          [action["tool"] for action in initial["next_actions"]] == ["debuggee.launch", "debuggee.attach"],
          "Installed debugger.state did not advertise launch and attach actions.")
    launch = tool("debuggee.launch", {
        "operation_id": str(uuid.uuid4()), "path": args.sample,
        "working_directory": ntpath.dirname(args.sample),
    }, request_id=3)
    module_name = ntpath.basename(args.sample).upper()
    module_ref = {"module": module_name, "rva": args.main_rva}
    resolved = tool("address.resolve", {"address": module_ref}, request_id=4)
    breakpoint = tool("breakpoints.set", {
        "operation_id": str(uuid.uuid4()), "address": module_ref,
    }, request_id=5)
    check(breakpoint["present"], "The module-relative main breakpoint was not confirmed.")

    main_pause = None
    for attempt in range(8):
        resume = tool("debugger.resume", {"operation_id": str(uuid.uuid4())}, request_id=10 + attempt * 2)
        observed = tool("debugger.wait_for_pause", {
            "after_generation": resume["state_generation"], "timeout_ms": 8000,
        }, request_id=11 + attempt * 2)
        if (observed["pause_reason"]["kind"] == "breakpoint" and
                observed["pause_reason"]["address"] == resolved["address"]):
            main_pause = observed
            break
    check(main_pause is not None, "checksum.exe did not reach the module-relative main breakpoint.")
    check(main_pause["instruction_pointer"] == resolved["address"] and
          main_pause["active_thread_id"] and main_pause["pause_reason"]["breakpoint_type"] and
          main_pause["pause_reason"].get("hit_count") is not None and
          main_pause["state_generation"] > launch["state_generation"],
          "Main pause snapshot is missing generation-consistent breakpoint metadata.")
    main_selector = {"kind": "software", "address": module_ref}
    main_disabled = tool("breakpoints.disable", {
        "operation_id": str(uuid.uuid4()), "selector": main_selector,
    }, request_id=140)
    main_enabled = tool("breakpoints.enable", {
        "operation_id": str(uuid.uuid4()), "selector": main_selector,
    }, request_id=141)
    check(main_disabled["changed"] and not main_disabled["enabled"] and
          main_enabled["changed"] and main_enabled["enabled"],
          "Installed plain software breakpoint transition was not exactly confirmed.")
    register_snapshot = tool("registers.read", {"names": ["rip", "rsp"]}, request_id=36)
    explicit_thread_registers = tool("registers.read", {
        "names": ["rip", "rsp"], "thread_id": main_pause["active_thread_id"],
    }, request_id=137)
    callstack_snapshot = tool("callstack.read", {
        "thread_id": main_pause["active_thread_id"], "limit": 32,
    }, request_id=35)
    memory_snapshot = tool("memory.read", {"address": module_ref, "length": 16}, request_id=37)
    disassembly_snapshot = tool("disassembly.read", {"address": module_ref, "count": 4}, request_id=38)
    main_pattern_search = tool("memory.search", {
        "scope": {"module": module_name}, "pattern_hex": memory_snapshot["data_hex"][:16],
        "mask": "xxxxxxxx", "limit": 1,
    }, request_id=42)
    compact_snapshot = tool("debugger.snapshot", {}, request_id=39)
    explicit_thread_snapshot = tool("debugger.snapshot", {
        "registers": ["rip", "rsp"], "disassembly_count": 2,
        "thread_id": main_pause["active_thread_id"],
    }, request_id=138)
    filtered_map = tool("memory.map", {
        "module": module_name, "committed_only": True, "executable_only": True,
        "compact": True, "limit": 32,
    }, request_id=41)
    check(all(snapshot["state_generation"] == main_pause["state_generation"] for snapshot in (
              register_snapshot, memory_snapshot, disassembly_snapshot, compact_snapshot,
              explicit_thread_registers, explicit_thread_snapshot, filtered_map)) and
          explicit_thread_registers["current"] and explicit_thread_snapshot["current"] and
          explicit_thread_registers["thread_id"] == main_pause["active_thread_id"] and
          explicit_thread_snapshot["thread_id"] == main_pause["active_thread_id"] and
          explicit_thread_snapshot["active_thread_id"] == main_pause["active_thread_id"] and
          main_pattern_search["read_completeness"] == "complete" and
          "completeness" not in main_pattern_search and not main_pattern_search["scan_complete"] and
          len(main_pattern_search["items"]) == 1 and
          explicit_thread_registers["registers"]["rip"] == resolved["address"] and
          explicit_thread_snapshot["instruction_pointer"]["address"] == resolved["address"] and
          len(explicit_thread_snapshot["disassembly"]) == 2 and
          compact_snapshot["instruction_pointer"]["address"] == resolved["address"] and
          len(compact_snapshot["registers"]) == 4 and len(compact_snapshot["disassembly"]) == 8 and
          len(filtered_map["items"]) > 0 and
          memory_snapshot["location"]["state_generation"] == memory_snapshot["state_generation"] and
          disassembly_snapshot["location"]["state_generation"] == disassembly_snapshot["state_generation"],
          "Installed read tools did not preserve the stable main-pause generation.")
    check(callstack_snapshot["thread_id"] == main_pause["active_thread_id"] and
          len(callstack_snapshot["frames"]) <= 32 and
          callstack_snapshot["completeness"] in ("native_bounded", "inconclusive") and
          callstack_snapshot["state_generation"] == main_pause["state_generation"],
          "Installed native call-stack read was not bounded and generation-consistent.")

    # Qualify managed metadata without resuming challenge logic.
    check(len(disassembly_snapshot["items"]) > 1 and
          1 <= disassembly_snapshot["items"][1]["size"] <= 16,
          "Main disassembly has no bounded instruction for managed breakpoint qualification.")
    managed_target = {"absolute": disassembly_snapshot["items"][1]["address"]}
    conditional_arguments = {
        "operation_id": str(uuid.uuid4()), "address": managed_target,
        "condition": {"mode": "all", "predicates": [{"source": "hit_count", "operator": "eq", "value": 1}]},
    }
    conditional_set = tool("breakpoints.conditional.set", conditional_arguments, request_id=130)
    conditional_replay = tool("breakpoints.conditional.set", conditional_arguments, request_id=131)
    assert_exact(conditional_set, conditional_replay, "Installed conditional breakpoint did not replay exactly.")
    conditional_list = tool("breakpoints.list", {"limit": 256}, request_id=132)
    listed_conditional = next((item for item in conditional_list["items"]
                               if item.get("address") == managed_target["absolute"] and
                               item["type"] == "software"), None)
    check(conditional_set["present"] and conditional_set["fast_resume"] and
          listed_conditional is not None and
          listed_conditional["managed_id"] == conditional_set["managed_id"],
          "Installed conditional breakpoint was not listed or replay-safe.")
    conditional_selector = {
        "kind": "conditional", "address": managed_target, "managed_id": conditional_set["managed_id"],
    }
    conditional_disabled = tool("breakpoints.disable", {
        "operation_id": str(uuid.uuid4()), "selector": conditional_selector,
    }, request_id=142)
    conditional_enabled = tool("breakpoints.enable", {
        "operation_id": str(uuid.uuid4()), "selector": conditional_selector,
    }, request_id=143)
    check(conditional_disabled["changed"] and not conditional_disabled["enabled"] and
          conditional_enabled["changed"] and conditional_enabled["enabled"] and
          conditional_enabled["managed_id"] == conditional_set["managed_id"] and
          conditional_enabled["condition_expression"] == conditional_set["condition_expression"],
          "Installed conditional transition lost its managed condition policy.")
    conditional_remove_arguments = {
        "operation_id": str(uuid.uuid4()), "address": managed_target,
        "managed_id": conditional_set["managed_id"],
    }
    conditional_remove = tool("breakpoints.conditional.remove", conditional_remove_arguments, request_id=133)
    conditional_remove_replay = tool("breakpoints.conditional.remove", conditional_remove_arguments, request_id=134)
    assert_exact(conditional_remove, conditional_remove_replay, "Installed conditional removal did not replay exactly.")
    check(not conditional_remove["present"],
          "Installed conditional breakpoint removal was not replay-safe.")

    exception_arguments = {"operation_id": str(uuid.uuid4()), "code": "0xe0424343", "chance": "first"}
    exception_set = tool("breakpoints.exception.set", exception_arguments, request_id=135)
    exception_replay = tool("breakpoints.exception.set", exception_arguments, request_id=136)
    assert_exact(exception_set, exception_replay, "Installed exception breakpoint did not replay exactly.")
    exception_list = tool("breakpoints.list", {"limit": 256}, request_id=137)
    listed_exception = next((item for item in exception_list["items"]
                             if item["type"] == "exception" and item["code"] == "0xe0424343"), None)
    check(exception_set["present"] and exception_set["chance"] == "first" and
          listed_exception is not None and listed_exception["managed_id"] == exception_set["managed_id"],
          "Installed exception breakpoint was not listed or replay-safe.")
    exception_selector = {
        "kind": "exception", "code": "0xe0424343", "chance": "first",
        "managed_id": exception_set["managed_id"],
    }
    exception_disabled = tool("breakpoints.disable", {
        "operation_id": str(uuid.uuid4()), "selector": exception_selector,
    }, request_id=144)
    exception_enabled = tool("breakpoints.enable", {
        "operation_id": str(uuid.uuid4()), "selector": exception_selector,
    }, request_id=145)
    check(exception_disabled["changed"] and not exception_disabled["enabled"] and
          exception_enabled["changed"] and exception_enabled["enabled"] and
          exception_enabled["managed_id"] == exception_set["managed_id"],
          "Installed exception transition lost its managed policy.")
    exception_remove_arguments = {
        "operation_id": str(uuid.uuid4()), "code": "0xe0424343", "chance": "first",
        "managed_id": exception_set["managed_id"],
    }
    exception_remove = tool("breakpoints.exception.remove", exception_remove_arguments, request_id=138)
    exception_remove_replay = tool("breakpoints.exception.remove", exception_remove_arguments, request_id=139)
    assert_exact(exception_remove, exception_remove_replay, "Installed exception removal did not replay exactly.")
    check(not exception_remove["present"],
          "Installed exception breakpoint removal was not replay-safe.")

    # Patch a non-current instruction and restore it before any execution.
    patch_instruction_target = disassembly_snapshot["items"][1]
    check(1 <= patch_instruction_target["size"] <= 16,
          "Main disassembly has no bounded non-current instruction for patch qualification.")
    patch_address = {"absolute": patch_instruction_target["address"]}
    patch_memory = tool("memory.read", {
        "address": patch_address, "length": patch_instruction_target["size"],
    }, request_id=120)
    int3_padded = "cc" + "90" * (patch_instruction_target["size"] - 1)
    patch_mnemonic = "nop" if patch_memory["data_hex"].lower() == int3_padded else "int3"
    patch_preview = tool("assembly.preview", {
        "address": patch_address, "instruction": patch_mnemonic,
    }, request_id=121)
    patch_arguments = {
        "operation_id": str(uuid.uuid4()), "address": patch_address,
        "instruction": patch_mnemonic, "expected_bytes_hex": patch_memory["data_hex"], "fill_nop": True,
    }
    tracked_patch = tool("assembly.patch", patch_arguments, request_id=122)
    tracked_patch_replay = tool("assembly.patch", patch_arguments, request_id=123)
    assert_exact(tracked_patch, tracked_patch_replay, "Installed tracked patch did not replay exactly.")
    check(tracked_patch["patch_tracked"] and patch_preview["byte_count"] == 1,
          "Installed tracked patch was not previewed, verified, or replay-safe.")
    installed_patch_list = tool("patches.list", {
        "module": ntpath.basename(args.sample), "limit": 32,
    }, request_id=127)
    installed_patch = next((item for item in installed_patch_list["items"]
                            if item["start"]["address"] == tracked_patch["address"]), None)
    check(installed_patch is not None and installed_patch["current_matches_patch"] and
          installed_patch["patched_bytes_hex"] == tracked_patch["patched_bytes_hex"] and
          installed_patch_list["completeness"] == "tracked_only",
          "Installed patch listing did not verify checksum.exe tracked bytes.")
    restore_arguments = {
        "operation_id": str(uuid.uuid4()), "address": patch_address,
        "expected_patched_bytes_hex": tracked_patch["patched_bytes_hex"],
        "expected_original_bytes_hex": patch_memory["data_hex"],
    }
    patch_restore = tool("patches.restore", restore_arguments, request_id=124)
    patch_restore_replay = tool("patches.restore", restore_arguments, request_id=125)
    assert_exact(patch_restore, patch_restore_replay, "Installed patch restore did not replay exactly.")
    patch_memory_after_restore = tool("memory.read", {
        "address": patch_address, "length": patch_instruction_target["size"],
    }, request_id=126)
    check(not patch_restore["patch_tracked"] and
          patch_memory_after_restore["data_hex"] == patch_memory["data_hex"],
          "Installed patch restore did not exactly recover checksum.exe bytes.")

    default_imports = tool("imports.list", {"module": module_name}, request_id=47)
    check(len(default_imports["items"]) == min(100, int(default_imports["native_count"])) and
          (default_imports["native_count"] <= 100 or default_imports.get("next_cursor")),
          "Installed imports.list did not apply its default page size.")
    default_imports_bytes = len(json.dumps(default_imports, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    main_symbols = tool("symbols.search", {
        "module": module_name, "query": "main.main", "limit": 32,
    }, request_id=50)
    main_functions = tool("functions.list", {
        "module": module_name, "query": "main.main", "limit": 32,
    }, request_id=51)
    analysis_arguments = {"operation_id": str(uuid.uuid4()), "address": module_ref}
    main_analysis = tool("analysis.function", analysis_arguments, request_id=53)
    main_analysis_replay = tool("analysis.function", analysis_arguments, request_id=54)
    assert_exact(main_analysis, main_analysis_replay, "Installed explicit analysis did not replay exactly.")
    check(main_analysis["state_generation"] == main_pause["state_generation"] and
          main_analysis["requested_location"]["address"] == resolved["address"],
          "Installed explicit analysis was not generation-consistent or replay-safe.")
    main_analysis_found = False
    analysis_cursor = None
    for analysis_page in range(8):
        analysis_list_arguments = {"module": module_name, "limit": 256}
        if analysis_cursor:
            analysis_list_arguments["cursor"] = analysis_cursor
        analysis_functions = tool("functions.list", analysis_list_arguments, request_id=80 + analysis_page)
        if any(item["start"]["address"] == main_analysis["function"]["start"]["address"]
               for item in analysis_functions["items"]):
            main_analysis_found = True
            break
        analysis_cursor = analysis_functions.get("next_cursor")
        if not analysis_cursor:
            break
    check(main_analysis_found, "Installed explicit analysis marker was not visible through functions.list.")
    main_function_at = tool("functions.at", {"address": module_ref}, request_id=55)
    check(main_function_at["found"] and main_function_at["function"]["contains_query"] and
          main_function_at["function"]["start"]["address"] == main_analysis["function"]["start"]["address"] and
          main_function_at["function"]["end_inclusive"]["address"] == main_analysis["function"]["end"]["address"],
          "Installed known-function lookup disagreed with explicit checksum.exe analysis.")
    exact_symbol_name = main_symbols["items"][0]["name"] if main_symbols["items"] else "main.main"
    main_symbol_exact = tool("symbols.resolve", {
        "module": module_name, "name": exact_symbol_name,
    }, request_id=56)
    check(main_symbol_exact["resolution"] in ("found", "missing", "ambiguous") and
          main_symbol_exact["completeness"] == "known_only" and
          (not main_symbols["items"] or main_symbol_exact["resolution"] != "missing"),
          "Installed exact symbol resolution did not preserve explicit known-only semantics.")
    main_references = tool("references.to", {"address": module_ref, "limit": 32}, request_id=52)
    key_string = find_installed_string(client, module_name, "FlareOn2024", 60)
    prompt_string = find_installed_string(client, module_name, "Check sum: %d + %d = ", 70)
    for discovery in (main_symbols, main_functions, main_references, key_string["result"], prompt_string["result"]):
        check(discovery["completeness"] == "known_only" and
              discovery["state_generation"] == main_pause["state_generation"],
              "Installed discovery result omitted stable known-only metadata.")
    for found in (key_string, prompt_string):
        item = found["item"]
        check(item.get("match_offset") is not None and item.get("text_offset") is not None and
              item["match_offset"] >= item["text_offset"] and len(item["before"]) <= 32 and
              len(item["after"]) <= 32 and item["text"] == item["before"] + item["match"] + item["after"],
              "Installed string discovery omitted valid match-context offsets.")

    # Restore the non-control register before continuing the sample.
    writable_register = "rdi"
    register_before_write = tool("registers.read", {"names": [writable_register]}, request_id=90)
    original_register_value = register_before_write["registers"][writable_register]
    test_register_value = "0x55667788" if original_register_value == "0x11223344" else "0x11223344"
    register_write_arguments = {
        "operation_id": str(uuid.uuid4()), "name": writable_register, "value": test_register_value,
    }
    register_write = tool("registers.write", register_write_arguments, request_id=91)
    register_write_replay = tool("registers.write", register_write_arguments, request_id=92)
    assert_exact(register_write, register_write_replay, "Installed register write did not replay exactly.")
    register_after_write = tool("registers.read", {"names": [writable_register]}, request_id=93)
    check(register_write["changed"] and register_write["previous_value"] == original_register_value and
          register_write["value"] == test_register_value and
          register_after_write["registers"][writable_register] == test_register_value,
          "Installed typed register write was not verified, observable, or replay-safe.")
    register_restore = tool("registers.write", {
        "operation_id": str(uuid.uuid4()), "name": writable_register, "value": original_register_value,
    }, request_id=94)
    register_after_restore = tool("registers.read", {"names": [writable_register]}, request_id=95)
    check(register_restore["value"] == original_register_value and
          register_after_restore["registers"][writable_register] == original_register_value,
          "Installed typed register write did not restore the Flare sample context.")

    check(len(disassembly_snapshot["items"]) >= 4 and
          all(item["size"] >= 1 for item in disassembly_snapshot["items"][1:4]),
          "Main disassembly has no deterministic instructions for typed breakpoint qualification.")
    hardware_instruction, memory_instruction, run_to_instruction = disassembly_snapshot["items"][1:4]
    hardware_arguments = {
        "operation_id": str(uuid.uuid4()), "address": {"absolute": hardware_instruction["address"]},
        "access": "execute", "size": 1,
    }
    hardware_set = tool("breakpoints.hardware.set", hardware_arguments, request_id=100)
    hardware_set_replay = tool("breakpoints.hardware.set", hardware_arguments, request_id=101)
    assert_exact(hardware_set, hardware_set_replay, "Installed hardware breakpoint did not replay exactly.")
    hardware_selector = {
        "kind": "hardware", "address": {"absolute": hardware_instruction["address"]},
        "access": "execute", "size": 1,
    }
    hardware_disabled = tool("breakpoints.disable", {
        "operation_id": str(uuid.uuid4()), "selector": hardware_selector,
    }, request_id=146)
    hardware_enabled = tool("breakpoints.enable", {
        "operation_id": str(uuid.uuid4()), "selector": hardware_selector,
    }, request_id=147)
    check(hardware_disabled["changed"] and not hardware_disabled["enabled"] and
          hardware_disabled.get("slot") is None and hardware_enabled["changed"] and
          hardware_enabled["enabled"] and 0 <= hardware_enabled["slot"] <= 3,
          "Installed hardware transition did not release and reacquire a slot.")
    hardware_resume = tool("debugger.resume", {"operation_id": str(uuid.uuid4())}, request_id=102)
    hardware_pause = tool("debugger.wait_for_pause", {
        "after_generation": hardware_resume["state_generation"], "timeout_ms": 9000,
    }, request_id=103)
    check(hardware_set["present"] and
          hardware_pause["pause_reason"]["kind"] == "breakpoint" and
          hardware_pause["pause_reason"]["breakpoint_type"] == "hardware" and
          hardware_pause["instruction_pointer"] == hardware_instruction["address"],
          "Installed hardware breakpoint was not replay-safe or did not hit the next instruction.")
    hardware_remove_arguments = {
        "operation_id": str(uuid.uuid4()), "address": {"absolute": hardware_instruction["address"]},
        "access": "execute", "size": 1,
    }
    hardware_remove = tool("breakpoints.hardware.remove", hardware_remove_arguments, request_id=104)
    hardware_remove_replay = tool("breakpoints.hardware.remove", hardware_remove_arguments, request_id=105)
    assert_exact(hardware_remove, hardware_remove_replay, "Installed hardware removal did not replay exactly.")
    check(not hardware_remove["present"],
          "Installed hardware breakpoint removal was not replay-safe.")

    memory_arguments = {
        "operation_id": str(uuid.uuid4()), "address": {"absolute": memory_instruction["address"]},
        "access": "execute", "size": memory_instruction["size"],
    }
    memory_set = tool("breakpoints.memory.set", memory_arguments, request_id=106)
    memory_set_replay = tool("breakpoints.memory.set", memory_arguments, request_id=107)
    assert_exact(memory_set, memory_set_replay, "Installed memory breakpoint did not replay exactly.")
    memory_selector = {
        "kind": "memory", "address": {"absolute": memory_instruction["address"]},
        "access": "execute", "size": memory_instruction["size"],
    }
    memory_disabled = tool("breakpoints.disable", {
        "operation_id": str(uuid.uuid4()), "selector": memory_selector,
    }, request_id=148)
    memory_enabled = tool("breakpoints.enable", {
        "operation_id": str(uuid.uuid4()), "selector": memory_selector,
    }, request_id=149)
    check(memory_disabled["changed"] and not memory_disabled["enabled"] and
          memory_enabled["changed"] and memory_enabled["enabled"] and
          memory_enabled["size"] == memory_instruction["size"],
          "Installed memory transition did not preserve its exact range policy.")
    memory_resume = tool("debugger.resume", {"operation_id": str(uuid.uuid4())}, request_id=108)
    memory_pause = tool("debugger.wait_for_pause", {
        "after_generation": memory_resume["state_generation"], "timeout_ms": 9000,
    }, request_id=109)
    check(memory_set["present"] and
          memory_pause["pause_reason"]["kind"] == "breakpoint" and
          memory_pause["pause_reason"]["breakpoint_type"] == "memory" and
          memory_pause["instruction_pointer"] == memory_instruction["address"],
          "Installed memory breakpoint was not replay-safe or did not hit the following instruction.")
    memory_remove_arguments = {
        "operation_id": str(uuid.uuid4()), "address": {"absolute": memory_instruction["address"]},
        "access": "execute", "size": memory_instruction["size"],
    }
    memory_remove = tool("breakpoints.memory.remove", memory_remove_arguments, request_id=110)
    memory_remove_replay = tool("breakpoints.memory.remove", memory_remove_arguments, request_id=111)
    assert_exact(memory_remove, memory_remove_replay, "Installed memory removal did not replay exactly.")
    check(not memory_remove["present"],
          "Installed memory breakpoint removal was not replay-safe.")

    run_to_arguments = {
        "operation_id": str(uuid.uuid4()), "address": {"absolute": run_to_instruction["address"]},
        "timeout_ms": 2000,
    }
    run_to = tool("debugger.run_to_address", run_to_arguments, request_id=112)
    run_to_replay = tool("debugger.run_to_address", run_to_arguments, request_id=113)
    assert_exact(run_to, run_to_replay, "Installed owned run-to did not replay exactly.")
    run_to_shape_valid = (
        run_to["resumed"] and run_to["temporary_breakpoint_cleaned"] and
        run_to["debuggee_state"] == "paused" and
        ((run_to["completed"] and run_to.get("interruption") is None and
          run_to["instruction_pointer"] == run_to_instruction["address"]) or
         (not run_to["completed"] and run_to["interruption"] in (
             "breakpoint", "exception", "step", "user_pause", "timeout", "unknown")))
    )
    check(run_to_shape_valid,
          f"Installed owned run-to did not return a cleaned replay-safe result: {json.dumps(run_to)}")

    # A bounded address trace retains no register or memory snapshots.
    trace_before = tool("debugger.state", {}, request_id=130)
    trace_arguments = {"operation_id": str(uuid.uuid4()), "mode": "over", "max_steps": 8, "timeout_ms": 3000}
    trace_start = tool("trace.start", trace_arguments, request_id=131)
    trace_replay = tool("trace.start", trace_arguments, request_id=132)
    assert_exact(trace_start, trace_replay, "Installed bounded trace start was not exactly replay-safe.")
    if trace_start["state"] in ("starting", "running"):
        tool("debugger.wait_for_pause", {
            "after_generation": trace_before["state_generation"], "timeout_ms": 5000,
        }, request_id=133)
    trace_status = tool("trace.status", {"trace_id": trace_start["trace_id"]}, request_id=134)
    trace_results = tool("trace.results", {"trace_id": trace_start["trace_id"], "limit": 16}, request_id=135)
    check(trace_status["state"] == "completed" and trace_status["reason"] == "max_steps" and
          trace_status["steps_executed"] == 8 and trace_status["points_retained"] == 9 and
          len(trace_results["items"]) == 9 and not trace_results.get("next_cursor"),
          f"Installed bounded trace was incomplete: {json.dumps(trace_status)}")
    step_into = tool("debugger.step_into", {"operation_id": str(uuid.uuid4())}, request_id=150)
    check(step_into["debuggee_state"] == "paused" and step_into["pause_reason"]["kind"] == "step" and
          step_into["instruction_pointer"] and step_into["active_thread_id"] and
          step_into["state_generation"] > trace_status["state_generation"],
          f"Installed step did not directly return its confirmed landing state: {json.dumps(step_into)}")
    stop = tool("debugger.stop", {"operation_id": str(uuid.uuid4())}, request_id=40)
    check(stop["debuggee_state"] == "absent", "Installed debugger stop did not return the absent state.")
    return {
        "sample": ntpath.basename(args.sample), "instance_id": client.instance_id,
        "debugger_pid": args.debugger_pid, "sidecar_pid": args.sidecar_pid,
        "endpoint_port": args.port, "endpoint_parent_verified": True,
        "module_reference": module_ref, "resolved_address": resolved["address"],
        "resolved_module_base": resolved["module_base"], "pause_reason": main_pause["pause_reason"]["kind"],
        "breakpoint_type": main_pause["pause_reason"]["breakpoint_type"],
        "hit_count": main_pause["pause_reason"]["hit_count"],
        "instruction_pointer": main_pause["instruction_pointer"],
        "active_thread_id": main_pause["active_thread_id"], "state_generation": main_pause["state_generation"],
        "bootstrap_launch_action_advertised": True,
        "registers_generation": register_snapshot["state_generation"],
        "memory_generation": memory_snapshot["state_generation"],
        "memory_search_read_completeness": main_pattern_search["read_completeness"],
        "memory_search_scan_complete": main_pattern_search["scan_complete"],
        "disassembly_generation": disassembly_snapshot["state_generation"], "snapshot_generations_equal": True,
        "compact_snapshot_instructions": len(compact_snapshot["disassembly"]),
        "explicit_thread_context_read": explicit_thread_registers["thread_id"],
        "explicit_thread_snapshot_instructions": len(explicit_thread_snapshot["disassembly"]),
        "filtered_executable_regions": len(filtered_map["items"]),
        "default_import_page_items": len(default_imports["items"]),
        "default_import_page_json_bytes": default_imports_bytes,
        "main_symbols": len(main_symbols["items"]), "main_functions": len(main_functions["items"]),
        "callstack_frames": len(callstack_snapshot["frames"]),
        "callstack_completeness": callstack_snapshot["completeness"],
        "tracked_patch_list_verified": True, "known_function_lookup": True,
        "exact_symbol_resolution": main_symbol_exact["resolution"],
        "analysis_function_start": main_analysis["function"]["start"]["address"],
        "analysis_function_end": main_analysis["function"]["end"]["address"],
        "analysis_already_known": main_analysis["already_known"],
        "analysis_generation_unchanged": True, "analysis_replay_equal": True,
        "analysis_visible_in_discovery": main_analysis_found,
        "inbound_main_references": len(main_references["items"]),
        "key_string": key_string["item"]["text"], "key_string_match": key_string["item"]["match"],
        "key_string_preview_bytes": len(key_string["item"]["text"].encode("utf-8")),
        "key_string_page": key_string["page"], "prompt_string": prompt_string["item"]["text"],
        "prompt_string_match": prompt_string["item"]["match"],
        "prompt_string_preview_bytes": len(prompt_string["item"]["text"].encode("utf-8")),
        "prompt_string_page": prompt_string["page"], "string_context_bytes": 32,
        "register_write_name": writable_register, "register_write_value": register_write["value"],
        "register_write_replay_equal": True,
        "register_restore_value": register_after_restore["registers"][writable_register],
        "patch_address": patch_instruction_target["address"], "patch_instruction": patch_mnemonic,
        "patch_span_length": tracked_patch["span_length"], "patch_replay_equal": True,
        "patch_restore_replay_equal": True, "patch_restored_bytes_equal": True,
        "hardware_breakpoint_address": hardware_pause["instruction_pointer"],
        "hardware_breakpoint_replay_equal": True, "breakpoint_transition_software": True,
        "breakpoint_transition_hardware": True, "memory_breakpoint_address": memory_pause["instruction_pointer"],
        "memory_breakpoint_size": memory_set["size"], "memory_breakpoint_replay_equal": True,
        "breakpoint_transition_memory": True, "conditional_breakpoint_managed": conditional_set["managed_id"],
        "conditional_breakpoint_replay_equal": True, "conditional_breakpoint_removed": not conditional_remove["present"],
        "breakpoint_transition_conditional": True, "exception_breakpoint_managed": exception_set["managed_id"],
        "exception_breakpoint_replay_equal": True, "exception_breakpoint_removed": not exception_remove["present"],
        "breakpoint_transition_exception": True, "run_to_target": run_to_instruction["address"],
        "run_to_completed": run_to["completed"], "run_to_interruption": run_to.get("interruption"),
        "run_to_final_address": run_to["instruction_pointer"], "run_to_replay_equal": True,
        "run_to_temporary_breakpoint_cleaned": True, "trace_id": trace_start["trace_id"],
        "trace_steps": trace_status["steps_executed"], "trace_points": len(trace_results["items"]),
        "trace_replay_equal": True, "step_into_address": step_into["instruction_pointer"],
        "step_into_reason": step_into["pause_reason"]["kind"], "stopped": stop["debuggee_state"] == "absent",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--sample", required=True)
    parser.add_argument("--main-rva", default="0xa78a0")
    parser.add_argument("--debugger-pid", type=int, required=True)
    parser.add_argument("--sidecar-pid", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    client = McpClient(args.base_url, os.environ["X64DBG_MCP_TOKEN"],
                       instance_id=str(uuid.UUID(args.instance_id)), timeout=40)
    print(json.dumps(run(client, args), indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"flare-checksum-smoke: {error}", file=sys.stderr)
        sys.exit(1)
