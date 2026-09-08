use serde_json::{Value, json};
use x64dbg_mcp_server::tools::{catalog, validate_arguments};

fn validator(name: &str) -> jsonschema::Validator {
    let tool = catalog().iter().find(|tool| tool["name"] == name).unwrap();
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(&tool["inputSchema"])
        .unwrap()
}

fn mutation(mut arguments: Value) -> Value {
    arguments["operation_id"] = json!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    arguments["instance_id"] = json!("11111111-2222-4333-8444-555555555555");
    arguments
}

fn contract(name: &str, arguments: &Value, accepted: bool) {
    assert_eq!(
        validator(name).is_valid(arguments),
        accepted,
        "schema {name}: {arguments}"
    );
    assert_eq!(
        validate_arguments(name, arguments).is_ok(),
        accepted,
        "runtime {name}: {arguments}"
    );
}

#[test]
fn every_schema_compiles_and_rejects_nonobjects_and_unknown_fields() {
    let response = json!({"jsonrpc":"2.0","id":1,"result":{"tools":catalog()}});
    let bytes = serde_json::to_vec(&response).unwrap().len();
    assert!(
        bytes <= 1024 * 1024,
        "tools/list exceeds the default 1 MiB output limit: {bytes} bytes"
    );
    for tool in catalog() {
        let name = tool["name"].as_str().unwrap();
        for arguments in [Value::Null, json!([]), json!({"unknown": true})] {
            contract(name, &arguments, false);
        }
    }
}

#[test]
fn symbol_resolution_closed_alternatives() {
    for arguments in [
        json!({"module":"test.exe","name":"main"}),
        json!({"address":"0x0"}),
        json!({"address":{"absolute":"0xffffffffffffffff"}}),
        json!({"address":{"module":"test.exe","rva":"0x10"}}),
    ] {
        contract("symbols.resolve", &arguments, true);
        let mut extra = arguments;
        extra["extra"] = json!(true);
        contract("symbols.resolve", &extra, false);
    }
    for arguments in [
        json!({}),
        json!({"module":"test.exe"}),
        json!({"name":"main"}),
        json!({"module":"test.exe","name":"main","address":"0x1"}),
        json!({"module":"test.exe","name":"a\n"}),
    ] {
        contract("symbols.resolve", &arguments, false);
    }
}

#[test]
fn exception_overrides_are_typed_and_closed() {
    contract(
        "debugger.continue_exception",
        &mutation(json!({"disposition":"handled"})),
        true,
    );
    for (overrides, accepted) in [
        (json!([{"name":"rip","value":"0xffffffffffffffff"}]), true),
        (
            json!([{"name":"eax","value":"0x0"},{"name":"eflags","value":"0x202"}]),
            true,
        ),
        (json!([]), false),
        (json!([1]), false),
        (json!([{"name":"rip"}]), false),
        (json!([{"name":"rip","value":"0x1","extra":true}]), false),
        (json!([{"name":"dr0","value":"0x1"}]), false),
        (json!([{"name":"rax","value":"0xA"}]), false),
        (json!([{"name":"rax","value":"0x10000000000000000"}]), false),
        (json!(vec![json!({"name":"rax","value":"0x1"}); 5]), false),
    ] {
        contract(
            "debugger.continue_exception",
            &mutation(json!({"disposition":"handled","register_overrides":overrides})),
            accepted,
        );
    }
}

#[test]
fn shared_bounds_controls_and_dependencies() {
    for address in [
        "0x0",
        "0xffffffffffffffff",
        "0x10000000000000000",
        "0X1",
        "0xA",
        "0x1\n",
    ] {
        let accepted = matches!(address, "0x0" | "0xffffffffffffffff");
        for reference in [
            json!(address),
            json!({"absolute":address}),
            json!({"module":"test.exe","rva":address}),
        ] {
            contract("address.resolve", &json!({"address":reference}), accepted);
        }
    }
    for name in [
        "debugger.snapshot",
        "registers.read",
        "callstack.read",
        "context.arguments",
        "debugger.step_into",
        "debugger.step_over",
        "registers.write",
    ] {
        for id in [
            "0x1",
            "0xffffffff",
            "0x00000001",
            "0x0",
            "0x00000000",
            "0x100000000",
        ] {
            let mut arguments = json!({"thread_id":id});
            if name == "registers.write" {
                arguments["name"] = json!("rax");
                arguments["value"] = json!("0x1");
            }
            if name.starts_with("debugger.step") || name == "registers.write" {
                arguments = mutation(arguments);
            }
            contract(
                name,
                &arguments,
                matches!(id, "0x1" | "0xffffffff" | "0x00000001"),
            );
        }
    }
    for byte in 0u8..=127 {
        contract(
            "assembly.preview",
            &json!({"address":"0x1","instruction":char::from(byte).to_string()}),
            (32..=126).contains(&byte) && byte != b';',
        );
    }
    contract(
        "strings.search",
        &json!({"module":"a","context_bytes":0}),
        false,
    );
    contract(
        "strings.search",
        &json!({"module":"a","query":"x","context_bytes":0}),
        true,
    );
    for text in ["a/b", "a\\b", "a\n", "a\u{85}"] {
        contract("symbols.search", &json!({"module":text}), false);
    }
    for (text, accepted) in [
        ("x".repeat(256), true),
        ("x".repeat(257), false),
        ("\u{e9}".repeat(128), true),
        ("a\u{85}".into(), false),
    ] {
        contract(
            "symbols.search",
            &json!({"module":"a","query":text}),
            accepted,
        );
    }
    for (path, accepted) in [
        ("x".repeat(8192), true),
        ("x".repeat(8193), false),
        ("\u{20ac}".into(), true),
        ("x\nxx".into(), false),
    ] {
        for name in ["debuggee.launch", "debuggee.launch_dll"] {
            contract(name, &mutation(json!({"path":path})), accepted);
            contract(
                name,
                &mutation(json!({"path":"C:\\test.exe","working_directory":path})),
                accepted,
            );
        }
    }
}

#[test]
fn numeric_and_byte_boundaries() {
    for (name, base, field, minimum, maximum) in [
        ("memory.read", json!({"address":"0x1"}), "length", 1, 65536),
        (
            "memory.search",
            json!({"scope":{"module":"a"},"pattern_hex":"aa","mask":"x"}),
            "limit",
            1,
            256,
        ),
        ("modules.list", json!({}), "limit", 1, 256),
        ("callstack.read", json!({}), "limit", 1, 50),
        (
            "disassembly.read",
            json!({"address":"0x1"}),
            "count",
            1,
            256,
        ),
        ("debugger.snapshot", json!({}), "disassembly_count", 0, 64),
        (
            "events.wait",
            json!({"after_sequence":0,"types":["paused"]}),
            "timeout_ms",
            1,
            9000,
        ),
        (
            "debugger.wait_for_pause",
            json!({"after_generation":0}),
            "timeout_ms",
            1,
            9000,
        ),
        (
            "debuggee.attach",
            mutation(json!({})),
            "process_id",
            1,
            4_294_967_295_i64,
        ),
    ] {
        for number in [minimum - 1, minimum, maximum, maximum + 1] {
            let mut arguments = base.clone();
            arguments[field] = json!(number);
            contract(name, &arguments, (minimum..=maximum).contains(&number));
        }
    }
    for bytes in [0, 1, 4096, 4097] {
        contract(
            "memory.write",
            &mutation(json!({"address":"0x1","data_hex":"aa".repeat(bytes)})),
            (1..=4096).contains(&bytes),
        );
    }
    for text in ["a", "aaa", "aA", "aa\n"] {
        contract(
            "memory.write",
            &mutation(json!({"address":"0x1","data_hex":text})),
            false,
        );
    }
    for (text, accepted) in [
        ("x".repeat(512), true),
        ("x".repeat(513), false),
        (String::new(), false),
    ] {
        contract("modules.list", &json!({"cursor":text}), accepted);
    }
    for id in [
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
        "aaaaaaaabbbb4ccc8dddeeeeeeeeeeee",
        "not-a-uuid",
    ] {
        for field in ["operation_id", "instance_id"] {
            let mut arguments = mutation(json!({}));
            arguments[field] = json!(id);
            contract(
                "debugger.pause",
                &arguments,
                id == "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            );
        }
    }
}

#[tokio::test]
async fn mcp_single_string_byte_limit_matches_advertised_paths() {
    use x64dbg_mcp_server::{adapter::DisconnectedAdapter, mcp};

    for (path, accepted) in [
        ("x".repeat(8192), true),
        ("x".repeat(8193), false),
        ("\u{e9}".repeat(4096), true),
        ("\u{e9}".repeat(4097), false),
    ] {
        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"debuggee.launch","arguments":mutation(json!({"path":path}))}});
        let response = mcp::handle(
            &serde_json::to_vec(&request).unwrap(),
            &DisconnectedAdapter,
            uuid::Uuid::nil(),
        )
        .await;
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&bytes).unwrap();
        if accepted {
            // Passing transport validation does not imply the debugger can launch this path.
            assert!(response.get("result").is_some(), "{response}");
        } else {
            assert_eq!(response["error"]["code"], -32600);
        }
    }
}

// These are intentionally runtime-only constraints, not claims of schema parity.
// Standard maxLength counts scalars; it cannot count UTF-8 bytes or sum arrays.
#[test]
fn documented_runtime_only_constraints() {
    for (name, arguments) in [
        (
            "symbols.search",
            json!({"module":"a","query":"\u{e9}".repeat(129)}),
        ),
        ("modules.list", json!({"cursor":"\u{e9}".repeat(257)})),
        ("debuggee.launch", mutation(json!({"path":"ab"}))),
        (
            "debuggee.launch",
            mutation(json!({"path":"\u{e9}".repeat(4097)})),
        ),
        (
            "debuggee.launch",
            mutation(json!({"path":"x".repeat(3),"arguments":vec!["x".repeat(256);3]})),
        ),
        (
            "expressions.evaluate_batch",
            json!({"expressions":vec!["x".repeat(1024);9]}),
        ),
        (
            "memory.search",
            json!({"scope":{"module":"a"},"pattern_hex":"abcd","mask":"x"}),
        ),
        (
            "patches.restore",
            mutation(
                json!({"address":"0x1","expected_patched_bytes_hex":"cc","expected_original_bytes_hex":"cc"}),
            ),
        ),
        (
            "debugger.continue_exception",
            mutation(
                json!({"disposition":"handled","register_overrides":[{"name":"rax","value":"0x1"},{"name":"rax","value":"0x2"}]}),
            ),
        ),
    ] {
        assert!(validator(name).is_valid(&arguments), "schema {name}");
        assert!(
            validate_arguments(name, &arguments).is_err(),
            "runtime {name}"
        );
    }
}
