//! Internal contracts for the JSON payload in MCP text content, not the IPC or result wrapper.
//! Native success objects remain unwrapped. Error results use {ok:false,error:{...}}.
//! Unmodeled fields are deliberately open; these schemas are not advertised to clients.
//! Shapes follow the result serializers in plugin/src/runtime.cpp, including `LocationJson`
//! and the state-dependent execution replies. IPC envelope fields are not result fields.
//! Error compatibility follows `mcp::tool_failure`, including arbitrary JSON details.

use serde_json::{Value, json};

#[must_use]
pub fn for_tool(name: &str) -> Option<Value> {
    let string = json!({"type":"string"});
    let nullable_string = json!({"type":["string","null"]});
    let integer = json!({"type":"integer","minimum":0});
    let boolean = json!({"type":"boolean"});
    let location = json!({
        "type":"object", "required":["address"],
        "properties":{
            "address":string, "module":nullable_string,
            "module_base":nullable_string, "rva":nullable_string,
            "state_generation":integer
        }
    });
    let mut properties = json!({});
    let required: &[&str] = match name {
        "debugger.state" => {
            properties = json!({
                "instance_id":string, "backend":string, "architecture":string,
                "plugin_state":string, "debuggee_state":string,
                "session_origin":nullable_string, "process_id":nullable_string,
                "active_thread_id":nullable_string, "instruction_pointer":nullable_string,
                "pause_reason":{"type":["object","null"]},
                "diagnostic_code":nullable_string, "next_actions":{"type":"array","items":{"type":"object"}},
                "state_generation":integer
            });
            &["instance_id", "debuggee_state", "state_generation"]
        }
        "debugger.snapshot" => {
            properties = json!({
                "debuggee_state":{"const":"paused"}, "state_generation":integer,
                "pause_reason":{"type":"object"}, "active_thread_id":string,
                "thread_id":string, "current":boolean, "instruction_pointer":location,
                "registers":{"type":"object","additionalProperties":{"type":"string"}},
                "disassembly":{"type":"array","items":{
                    "type":"object","required":["address","size","text"],
                    "properties":{"address":string,"size":integer,"text":string}
                }}
            });
            &[
                "debuggee_state",
                "state_generation",
                "instruction_pointer",
                "registers",
                "disassembly",
            ]
        }
        "memory.read" => {
            properties = json!({
                "address":string,"location":location,"data_hex":{"type":"string","pattern":"^(?:[0-9a-fA-F]{2})*$"},
                "bytes_read":integer,"complete":boolean,"state_generation":integer
            });
            &[
                "address",
                "data_hex",
                "bytes_read",
                "complete",
                "state_generation",
            ]
        }
        "memory.write" => {
            properties = json!({"address":string,"location":location,"bytes_written":integer,"verified":boolean});
            &["address", "location", "bytes_written", "verified"]
        }
        "memory.map" | "memory.search" | "strings.search" | "symbols.search" => {
            properties = json!({
                "items":{"type":"array","items":{"type":"object"}},
                "next_cursor":nullable_string,"state_generation":integer
            });
            if name == "memory.search" {
                properties["items"]["items"] = json!({
                    "type":"object", "required":["location"],
                    "properties":{"location":location}
                });
                properties["scan_complete"] = boolean.clone();
                properties["read_completeness"] = string.clone();
                properties["bytes_scanned"] = integer.clone();
                properties["unreadable_bytes"] = integer.clone();
            } else if name == "strings.search" {
                properties["items"]["items"] = json!({
                    "type":"object", "required":["text","encoding","byte_length","match_offset","text_offset","truncated","location"],
                    "properties":{"text":string,"encoding":string,"byte_length":integer,
                        "match_offset":integer,"text_offset":integer,"truncated":boolean,
                        "location":location,"before":string,"match":string,"after":string}
                });
                properties["bytes_scanned"] = integer.clone();
                properties["incomplete"] = boolean.clone();
                properties["completeness"] = string.clone();
            } else if name == "symbols.search" {
                properties["items"]["items"] = json!({
                    "type":"object", "required":["name","type","manual","location"],
                    "properties":{"name":string,"type":string,"manual":boolean,"location":location}
                });
                properties["completeness"] = string.clone();
            } else {
                properties["items"]["items"] = json!({
                    "type":"object", "required":["base","size","protect","state","type"],
                    "properties":{"base":string,"size":string,"protect":string,"state":string,
                        "type":string,"allocation_base":string,"info":string}
                });
            }
            match name {
                "memory.search" => &[
                    "items",
                    "next_cursor",
                    "state_generation",
                    "scan_complete",
                    "read_completeness",
                    "bytes_scanned",
                    "unreadable_bytes",
                ],
                "strings.search" => &[
                    "items",
                    "next_cursor",
                    "state_generation",
                    "bytes_scanned",
                    "incomplete",
                    "completeness",
                ],
                "symbols.search" => &["items", "next_cursor", "state_generation", "completeness"],
                _ => &["items", "next_cursor", "state_generation"],
            }
        }
        "debugger.resume"
        | "debugger.pause"
        | "debugger.step_into"
        | "debugger.step_over"
        | "debugger.step_out"
        | "debugger.run_to_address"
        | "debugger.continue_exception"
        | "debugger.wait_for_pause"
        | "debugger.stop"
        | "debuggee.detach" => {
            properties["debuggee_state"] = match name {
                "debugger.resume" | "debugger.continue_exception" => json!({"const":"running"}),
                "debugger.stop" | "debuggee.detach" => json!({"const":"absent"}),
                "debugger.run_to_address" => json!({"enum":["paused","absent"]}),
                _ => json!({"const":"paused"}),
            };
            properties["state_generation"] = integer;
            properties["instruction_pointer"] = nullable_string.clone();
            properties["active_thread_id"] = nullable_string.clone();
            properties["pause_reason"] = json!({"type":["object","null"]});
            properties["completed"] = boolean;
            properties["interruption"] = nullable_string;
            if matches!(name, "debugger.run_to_address" | "debugger.step_out") {
                &["debuggee_state", "state_generation", "completed"]
            } else {
                &["debuggee_state", "state_generation"]
            }
        }
        _ => return None,
    };
    // MCP serializes code/message/details without imposing the checked-in error schema's
    // length, pattern or object restrictions. Do not assert constraints it cannot ensure.
    let error = json!({
        "type":"object", "required":["ok","error"],
        "properties":{
            "ok":{"const":false},
            "error":{
                "type":"object", "required":["code","message","recoverable","safeToRetry","details"],
                "properties":{
                    "code":{"type":"string"},"message":{"type":"string"},
                    "recoverable":{"type":"boolean"},"safeToRetry":{"type":"boolean"},
                    "details":{},"suggestedAction":{"type":"string"},
                    "adviceSource":{"const":"x64dbg-mcp-backend"},
                    "nextActions":{"type":"array","maxItems":4,"items":{"type":"object"}}
                }
            }
        }
    });
    Some(json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "type":"object",
        "anyOf":[{"type":"object","required":required,"properties":properties,
            "not":{"required":["ok"],"properties":{"ok":{"const":false}}}}, error]
    }))
}
