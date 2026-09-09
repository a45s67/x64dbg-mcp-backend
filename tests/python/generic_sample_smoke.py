"""HTTP assertions for run-generic-sample-smoke.ps1."""

import argparse
import base64
import hashlib
import json
import ntpath
import os
from pathlib import Path
import sys
import uuid

from mcp_client import McpClient


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def run(client, args):
    client.rpc("initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "generic-sample-smoke", "version": "1"},
    })
    initial = client.tool("debugger.state", {})
    check(initial["debuggee_state"] == "absent" and initial["instance_id"] == client.instance_id,
          "Fresh isolated backend state or identity is invalid.")
    launch = client.tool("debuggee.launch", {
        "operation_id": str(uuid.uuid4()), "path": args.staged_sample,
        "working_directory": args.backend_root, "arguments": [],
    })
    state = client.tool("debugger.state", {})
    snapshot = client.tool("debugger.snapshot", {"disassembly_count": 8})
    modules = client.tool("modules.list", {"limit": 256})
    sample_leaf = ntpath.basename(args.sample)
    module = next((item for item in modules["items"]
                   if item["name"].lower() == sample_leaf.lower()), None)
    check(module is not None, "Launched sample was not present in the bounded module list.")
    sections = client.tool("sections.list", {"module": sample_leaf, "limit": 64})
    imports = client.tool("imports.list", {"module": sample_leaf, "limit": 64})
    mz_search = client.tool("memory.search", {
        "scope": {"start": {"absolute": module["base"]}, "length": 4096},
        "pattern_hex": "4d5a", "mask": "xx", "limit": 4,
    })
    check(len(mz_search["items"]) >= 1 and
          mz_search["items"][0]["location"]["address"] == module["base"] and
          mz_search["state_generation"] == state["state_generation"],
          "Runtime PE signature search was incomplete or generation-inconsistent.")
    expected_matches = None
    if args.expected_ascii_pattern:
        pattern = args.expected_ascii_pattern
        check(1 <= len(pattern) <= 64 and all(0x20 <= ord(char) <= 0x7E for char in pattern),
              "ExpectedAsciiPattern must contain 1-64 printable ASCII characters only.")
        expected_search = client.tool("memory.search", {
            "scope": {"module": sample_leaf}, "pattern_hex": pattern.encode("ascii").hex(),
            "mask": "x" * len(pattern), "limit": 32,
        })
        expected_matches = len(expected_search["items"])
        check(expected_matches >= 1 and
              expected_search["state_generation"] == state["state_generation"],
              "Expected runtime ASCII pattern was not found in the sample module.")
    events = client.tool("events.list", {
        "types": ["process_created", "system_breakpoint", "dll_loaded"], "limit": 64,
    })
    check(state["debuggee_state"] == "paused" and
          snapshot["state_generation"] == state["state_generation"] and
          len(sections["items"]) >= 1 and len(events["items"]) >= 1,
          "Initial-pause sample observations were incomplete or generation-inconsistent.")
    stop = client.tool("debugger.stop", {"operation_id": str(uuid.uuid4())})
    return {
        "backend": args.backend, "architecture": state["architecture"], "sample": sample_leaf,
        "sample_sha256": hashlib.sha256(Path(args.sample).read_bytes()).hexdigest(),
        "instance_id": client.instance_id, "debugger_pid": args.debugger_pid,
        "sidecar_pid": args.sidecar_pid, "endpoint_port": args.port,
        "endpoint_parent_verified": True, "launch_state": launch["debuggee_state"],
        "pause_reason": state["pause_reason"]["kind"], "state_generation": state["state_generation"],
        "instruction_pointer": state["instruction_pointer"],
        "snapshot_instruction_count": len(snapshot["disassembly"]), "module_base": module["base"],
        "section_count": len(sections["items"]), "import_page_count": len(imports["items"]),
        "pe_signature_matches": len(mz_search["items"]),
        "expected_ascii_pattern": args.expected_ascii_pattern or None,
        "expected_ascii_pattern_matches": expected_matches,
        "startup_event_count": len(events["items"]), "stopped": stop["debuggee_state"] == "absent",
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--backend", type=str.lower, choices=("x32", "x64"), required=True)
    parser.add_argument("--sample", required=True)
    parser.add_argument("--staged-sample", required=True)
    parser.add_argument("--backend-root", required=True)
    parser.add_argument("--expected-ascii-pattern-base64", dest="expected_ascii_pattern",
                        type=lambda value: base64.b64decode(value, validate=True).decode("utf-8"))
    parser.add_argument("--debugger-pid", type=int, required=True)
    parser.add_argument("--sidecar-pid", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    return parser.parse_args(argv)


def main():
    args = parse_args()
    client = McpClient(args.base_url, os.environ["X64DBG_MCP_TOKEN"],
                       instance_id=str(uuid.UUID(args.instance_id)), timeout=35)
    print(json.dumps(run(client, args), indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"generic-sample-smoke: {error}", file=sys.stderr)
        sys.exit(1)
