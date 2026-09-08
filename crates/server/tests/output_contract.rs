use serde_json::json;

struct ReplyAdapter(Result<serde_json::Value, x64dbg_mcp_server::adapter::ToolError>);

#[async_trait::async_trait]
impl x64dbg_mcp_server::adapter::DebuggerAdapter for ReplyAdapter {
    fn is_ready(&self) -> bool {
        true
    }

    async fn call(
        &self,
        _name: &str,
        _arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, x64dbg_mcp_server::adapter::ToolError> {
        self.0.clone()
    }
}

#[tokio::test]
async fn mcp_serialized_results_match_the_advertised_contract() {
    use x64dbg_mcp_server::{adapter::ToolError, mcp};

    let native = json!({"instance_id":uuid::Uuid::nil(),"debuggee_state":"absent","instruction_pointer":null,"state_generation":0,"next_actions":[{"tool":"debuggee.launch"}]});
    for reply in [
        Ok(native.clone()),
        Err(ToolError {
            code: "TIMEOUT",
            message: "outcome unknown",
            recoverable: true,
            safe_to_retry: false,
            suggested_action: Some("Inspect state before retrying.".to_owned()),
            next_actions: vec![],
            details: json!(["arbitrary native details"]),
        }),
    ] {
        let failed = reply.is_err();
        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"debugger.state","arguments":{}}});
        let response = mcp::handle(
            &serde_json::to_vec(&request).unwrap(),
            &ReplyAdapter(reply),
            uuid::Uuid::nil(),
        )
        .await;
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let result = &response["result"];
        assert_eq!(result["isError"], failed);
        validate("debugger.state", &result["structuredContent"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        if failed {
            assert!(text.contains("safeToRetry=false"));
            assert!(text.contains("Inspect state before retrying."));
        } else {
            assert_eq!(result["structuredContent"], native);
            assert!(text.contains("debuggee_state=absent"));
            assert!(text.contains("debuggee.launch"));
        }
    }
}

fn catalog_schema(name: &str) -> Option<serde_json::Value> {
    x64dbg_mcp_server::tools::catalog()
        .iter()
        .find(|tool| tool["name"] == name)
        .and_then(|tool| tool.get("outputSchema"))
        .cloned()
}

fn validate(name: &str, value: &serde_json::Value, accepted: bool) {
    let schema =
        catalog_schema(name).unwrap_or_else(|| panic!("{name}: missing catalog outputSchema"));
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .unwrap();
    let errors: Vec<_> = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect();
    assert_eq!(errors.is_empty(), accepted, "{name}: {errors:?}; {value}");
}

#[test]
fn native_success_fixtures_validate_and_wrong_types_fail() {
    let location = json!({"address":"0x401000","module":"sample.exe","module_base":"0x400000","rva":"0x1000","state_generation":7});
    let fixtures = [
        (
            "debugger.state",
            json!({"instance_id":"instance","backend":"x32dbg","architecture":"x86","plugin_state":"ready","debuggee_state":"paused","session_origin":"attached","process_id":"0x10","active_thread_id":"0x20","instruction_pointer":"0x401000","pause_reason":{"kind":"unknown"},"diagnostic_code":null,"next_actions":[],"state_generation":7}),
        ),
        (
            "debugger.snapshot",
            json!({"debuggee_state":"paused","state_generation":7,"pause_reason":{"kind":"step"},"active_thread_id":"0x20","thread_id":"0x20","current":true,"instruction_pointer":location,"registers":{"eip":"0x401000"},"disassembly":[{"address":"0x401000","size":1,"text":"ret"}]}),
        ),
        (
            "memory.read",
            json!({"address":"0x401000","location":location,"data_hex":"41ff","bytes_read":2,"complete":true,"state_generation":7}),
        ),
        (
            "memory.write",
            json!({"address":"0x401000","location":location,"bytes_written":2,"verified":true}),
        ),
        (
            "memory.map",
            json!({"items":[{"base":"0x400000","size":"0x1000","protect":"0x20","state":"0x1000","type":"0x1000000"}],"next_cursor":null,"state_generation":7}),
        ),
        (
            "memory.search",
            json!({"items":[{"location":location}],"next_cursor":"opaque","scan_complete":false,"read_completeness":"partial_unreadable","bytes_scanned":4096,"unreadable_bytes":64,"state_generation":7}),
        ),
        (
            "strings.search",
            json!({"items":[{"text":"hello","encoding":"ascii","byte_length":5,"match_offset":0,"text_offset":0,"truncated":false,"location":location}],"next_cursor":null,"bytes_scanned":4096,"incomplete":true,"completeness":"known_only","state_generation":7}),
        ),
        (
            "symbols.search",
            json!({"items":[{"name":"main","type":"function","manual":false,"location":location}],"next_cursor":null,"completeness":"known_only","state_generation":7}),
        ),
    ];
    for (name, value) in fixtures {
        validate(name, &value, true);
        validate(name, &json!({"result":value}), false);
        let schema = catalog_schema(name).unwrap();
        for key in schema["anyOf"][0]["required"].as_array().unwrap() {
            let mut missing = value.clone();
            missing
                .as_object_mut()
                .unwrap()
                .remove(key.as_str().unwrap());
            validate(name, &missing, false);
        }
    }
    for state in ["absent", "running", "exited"] {
        validate(
            "debugger.state",
            &json!({"instance_id":"instance","debuggee_state":state,"process_id":null,"active_thread_id":null,"instruction_pointer":null,"pause_reason":null,"state_generation":0}),
            true,
        );
    }
    validate(
        "memory.map",
        &json!({"items":[{"base":"0x0","size":4096,"protect":"0x20","state":"0x1000","type":"0x0"}],"next_cursor":null,"state_generation":7}),
        false,
    );
    validate(
        "debugger.snapshot",
        &json!({"debuggee_state":"paused","state_generation":7,"instruction_pointer":"0x401000","registers":{},"disassembly":[]}),
        false,
    );
}

#[test]
fn every_core_schema_accepts_errors_without_requiring_success_fields() {
    let mut checked = 0;
    for tool in x64dbg_mcp_server::tools::catalog() {
        let name = tool["name"].as_str().unwrap();
        if catalog_schema(name).is_none() {
            continue;
        }
        checked += 1;
        for details in [
            json!(null),
            json!({"outcome":"unknown"}),
            json!([1]),
            json!("native diagnostic"),
        ] {
            let mut error = json!({"ok":false,"error":{"code":"TIMEOUT","message":"timeout","recoverable":true,"safeToRetry":false,"details":details,"suggestedAction":"Inspect state before retrying.","adviceSource":"x64dbg-mcp-backend","nextActions":[{"code":"CALL_STATE","execution":"required_before_retry","tool":"debugger.state","reason":"Observe current state"}]}});
            validate(name, &error, true);
            error["error"]["safeToRetry"] = json!("false");
            validate(name, &error, false);
        }
        validate(name, &json!({}), false);
        validate(name, &json!(null), false);
        validate(
            name,
            &json!({"ok":false,"error":{},"debuggee_state":"paused","state_generation":7}),
            false,
        );
    }
    assert!(checked >= 18, "core outputSchema wiring is missing");
}

#[test]
fn execution_contracts_follow_native_serializers() {
    // runtime.cpp: common execution reply, step reply, wait reply, and detach reply.
    for (name, value, impossible_states) in [
        (
            "debugger.resume",
            json!({"debuggee_state":"running","state_generation":8}),
            &["paused", "absent", "exited"][..],
        ),
        (
            "debugger.continue_exception",
            json!({"debuggee_state":"running","state_generation":8}),
            &["paused", "absent"][..],
        ),
        (
            "debugger.pause",
            json!({"debuggee_state":"paused","state_generation":8}),
            &["running", "absent"][..],
        ),
        (
            "debugger.stop",
            json!({"debuggee_state":"absent","state_generation":8}),
            &["paused", "running", "exited"][..],
        ),
        (
            "debuggee.detach",
            json!({"debuggee_state":"absent","session_origin":null,"detached_process_id":"0x10","state_generation":8}),
            &["paused", "running"][..],
        ),
        (
            "debugger.step_into",
            json!({"debuggee_state":"paused","active_thread_id":"0x20","instruction_pointer":"0x401000","pause_reason":{"kind":"step"},"state_generation":8}),
            &["running", "absent"][..],
        ),
        (
            "debugger.step_over",
            json!({"debuggee_state":"paused","active_thread_id":null,"instruction_pointer":"0x401000","pause_reason":{"kind":"step"},"state_generation":8}),
            &["running", "exited"][..],
        ),
        (
            "debugger.wait_for_pause",
            json!({"debuggee_state":"paused","active_thread_id":"0x20","instruction_pointer":"0x401000","pause_reason":{"kind":"exception","code":"0xc0000005","first_chance":true},"state_generation":8}),
            &["running", "absent", "exited"][..],
        ),
        // The lifecycle harness emits null IP/thread values for wait-for-pause.
        (
            "debugger.wait_for_pause",
            json!({"debuggee_state":"paused","active_thread_id":null,"instruction_pointer":null,"pause_reason":{"kind":"unknown"},"state_generation":8}),
            &["running"][..],
        ),
    ] {
        validate(name, &value, true);
        for state in impossible_states {
            let mut invalid = value.clone();
            invalid["debuggee_state"] = json!(state);
            validate(name, &invalid, false);
        }
        let mut invalid = value;
        invalid["state_generation"] = json!("8");
        validate(name, &invalid, false);
    }
}

#[test]
fn run_to_and_step_out_require_explicit_completion() {
    let target = json!({"address":"0x401000","module":null,"module_base":null,"rva":null,"state_generation":7});
    // Each run-to serializer: already at target, resumed to target, interrupted, exited.
    for value in [
        json!({"completed":true,"resumed":false,"target":target,"debuggee_state":"paused","pause_reason":{"kind":"step"},"instruction_pointer":"0x401000","interruption":null,"temporary_breakpoint_cleaned":true,"state_generation":7}),
        json!({"completed":true,"resumed":true,"target":target,"debuggee_state":"paused","pause_reason":{"kind":"breakpoint","breakpoint_type":"software","address":"0x401000","hit_count":1},"instruction_pointer":"0x401000","interruption":null,"temporary_breakpoint_cleaned":true,"state_generation":8}),
        json!({"completed":false,"resumed":true,"target":target,"debuggee_state":"paused","pause_reason":{"kind":"user_pause"},"instruction_pointer":"0x402000","interruption":"timeout","temporary_breakpoint_cleaned":true,"state_generation":8}),
        json!({"completed":false,"resumed":true,"target":target,"debuggee_state":"absent","pause_reason":null,"instruction_pointer":null,"interruption":"process_exited","temporary_breakpoint_cleaned":true,"state_generation":8}),
    ] {
        validate("debugger.run_to_address", &value, true);
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("completed");
        validate("debugger.run_to_address", &missing, false);
        for state in ["running", "exited"] {
            let mut invalid = value.clone();
            invalid["debuggee_state"] = json!(state);
            validate("debugger.run_to_address", &invalid, false);
        }
    }
    for (completed, instruction, reason) in [
        (true, "ret", json!({"kind":"step"})),
        (
            false,
            "mov eax, [ecx]",
            json!({"kind":"exception","code":"0xc0000005","first_chance":true}),
        ),
    ] {
        let mut value = json!({"completed":completed,"debuggee_state":"paused","pause_reason":reason,"instruction_pointer":"0x401000","stack_pointer":"0x100100","initial_stack_pointer":"0x100000","instruction":{"size":1,"text":instruction},"state_generation":8});
        validate("debugger.step_out", &value, true);
        value["completed"] = json!("false");
        validate("debugger.step_out", &value, false);
        value.as_object_mut().unwrap().remove("completed");
        validate("debugger.step_out", &value, false);
        value["completed"] = json!(completed);
        for state in ["running", "absent", "exited"] {
            value["debuggee_state"] = json!(state);
            validate("debugger.step_out", &value, false);
        }
    }
}

#[test]
fn search_completeness_cannot_be_omitted_even_on_empty_pages() {
    // These fields come from the native serializers, independently of schema.required.
    for (name, value, fields) in [
        (
            "memory.search",
            json!({"items":[],"next_cursor":null,"state_generation":8,"scan_complete":true,"read_completeness":"partial_unreadable","bytes_scanned":4096,"unreadable_bytes":64}),
            &[
                "scan_complete",
                "read_completeness",
                "bytes_scanned",
                "unreadable_bytes",
            ][..],
        ),
        (
            "strings.search",
            json!({"items":[],"next_cursor":"opaque","state_generation":8,"bytes_scanned":4096,"incomplete":true,"completeness":"known_only"}),
            &["bytes_scanned", "incomplete", "completeness"][..],
        ),
        (
            "symbols.search",
            json!({"items":[],"next_cursor":null,"state_generation":8,"completeness":"known_only"}),
            &["completeness"][..],
        ),
    ] {
        validate(name, &value, true);
        for field in fields {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(*field);
            validate(name, &missing, false);
            let mut invalid = value.clone();
            invalid[*field] = json!(null);
            validate(name, &invalid, false);
        }
    }
}

#[test]
fn core_contracts_cover_native_success_and_mcp_error_envelopes() {
    for name in [
        "debugger.state",
        "debugger.snapshot",
        "memory.read",
        "memory.write",
        "memory.map",
        "memory.search",
        "strings.search",
        "symbols.search",
        "debugger.resume",
        "debugger.pause",
        "debugger.step_into",
        "debugger.step_over",
        "debugger.step_out",
        "debugger.run_to_address",
        "debugger.continue_exception",
        "debugger.wait_for_pause",
        "debugger.stop",
        "debuggee.detach",
    ] {
        let schema = catalog_schema(name).unwrap();
        assert_eq!(schema["type"], "object", "{name}");
        let branches = schema["anyOf"].as_array().unwrap();
        assert_eq!(branches.len(), 2);
        assert!(
            branches[0]["required"]
                .as_array()
                .unwrap()
                .iter()
                .all(|key| branches[0]["properties"]
                    .get(key.as_str().unwrap())
                    .is_some())
        );
        assert_eq!(branches[1]["properties"]["ok"]["const"], false);
        assert_eq!(
            branches[1]["properties"]["error"]["properties"]["details"],
            json!({})
        );
        assert!(branches[0].get("additionalProperties").is_none());
        assert!(branches[0]["properties"].get("result").is_none());
    }
    assert!(catalog_schema("expression.evaluate").is_none());
    assert!(catalog_schema("unknown").is_none());
}

#[test]
fn native_shape_differences_are_not_normalized_into_false_contracts() {
    let state = catalog_schema("debugger.state").unwrap();
    let snapshot = catalog_schema("debugger.snapshot").unwrap();
    assert_eq!(
        state["anyOf"][0]["properties"]["instruction_pointer"]["type"],
        json!(["string", "null"])
    );
    assert_eq!(
        snapshot["anyOf"][0]["properties"]["instruction_pointer"]["type"],
        "object"
    );
    let write = catalog_schema("memory.write").unwrap();
    assert!(
        !write["anyOf"][0]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("state_generation"))
    );
    let search = catalog_schema("memory.search").unwrap();
    assert_eq!(
        search["anyOf"][0]["properties"]["scan_complete"]["type"],
        "boolean"
    );
    assert_eq!(
        search["anyOf"][0]["properties"]["read_completeness"]["type"],
        "string"
    );
}
