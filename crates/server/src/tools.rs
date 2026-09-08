use std::sync::LazyLock;

use serde_json::{Value, json};
use uuid::Uuid;

static CATALOG: LazyLock<Vec<Value>> = LazyLock::new(build_catalog);
const EVENT_TYPES: &[&str] = &[
    "debug_initialized",
    "process_created",
    "system_breakpoint",
    "breakpoint",
    "exception",
    "paused",
    "stepped",
    "resumed",
    "attached",
    "detached",
    "stopping",
    "process_exited",
    "debug_stopped",
    "thread_created",
    "thread_exited",
    "dll_loaded",
    "dll_unloaded",
    "debug_string",
    "rip",
];

#[must_use]
pub fn catalog() -> &'static [Value] {
    &CATALOG
}

pub fn exists(name: &str) -> bool {
    CATALOG.iter().any(|tool| tool["name"] == name)
}

pub fn is_mutation(name: &str) -> bool {
    CATALOG
        .iter()
        .find(|tool| tool["name"] == name)
        .is_some_and(|tool| tool["annotations"]["readOnlyHint"] == false)
}

pub fn is_mutation_call(name: &str, arguments: &Value) -> bool {
    if name == "scyllahide.profile" {
        return arguments.get("action").and_then(Value::as_str) == Some("set");
    }
    is_mutation(name)
}

#[derive(Debug, PartialEq, Eq)]
pub struct ValidationError {
    pub field: &'static str,
    pub message: &'static str,
}

/// Validates one tool call against the same hard bounds advertised in its schema.
///
/// # Errors
///
/// Returns a stable field and message when required fields, types, formats,
/// additional properties, or hard size/count bounds are invalid.
pub fn validate_arguments(name: &str, arguments: &Value) -> Result<(), ValidationError> {
    let object = arguments
        .as_object()
        .ok_or(invalid("arguments", "must be an object"))?;
    match name {
        "events.list" => {
            exact_keys(object, &[], &["after_sequence", "types", "limit"])?;
            optional_integer(object, "after_sequence", 0, 9_007_199_254_740_991)?;
            optional_integer(object, "limit", 1, 256)?;
            if let Some(types) = object.get("types") {
                let values = types
                    .as_array()
                    .filter(|values| !values.is_empty() && values.len() <= 19)
                    .ok_or(invalid("types", "must contain 1 to 19 event types"))?;
                let mut seen = std::collections::HashSet::new();
                for value in values {
                    let name = value
                        .as_str()
                        .filter(|name| EVENT_TYPES.contains(name))
                        .ok_or(invalid("types", "contains an unknown event type"))?;
                    if !seen.insert(name) {
                        return Err(invalid("types", "must not contain duplicates"));
                    }
                }
            }
            Ok(())
        }
        "events.wait" => {
            exact_keys(object, &["after_sequence", "types"], &["timeout_ms"])?;
            integer(object, "after_sequence", 0, 9_007_199_254_740_991)?;
            optional_integer(object, "timeout_ms", 1, 9_000)?;
            let values = object
                .get("types")
                .and_then(Value::as_array)
                .filter(|values| !values.is_empty() && values.len() <= EVENT_TYPES.len())
                .ok_or(invalid("types", "must contain 1 to 19 event types"))?;
            let mut seen = std::collections::HashSet::new();
            for value in values {
                let name = value
                    .as_str()
                    .filter(|name| EVENT_TYPES.contains(name))
                    .ok_or(invalid("types", "contains an unknown event type"))?;
                if !seen.insert(name) {
                    return Err(invalid("types", "must not contain duplicates"));
                }
            }
            Ok(())
        }
        "debugger.snapshot" => {
            exact_keys(
                object,
                &[],
                &["registers", "disassembly_count", "thread_id"],
            )?;
            if object.contains_key("thread_id") {
                validate_thread_id(object)?;
            }
            if let Some(registers) = object.get("registers") {
                let registers = registers
                    .as_array()
                    .filter(|values| (1..=16).contains(&values.len()))
                    .ok_or(invalid("registers", "must contain 1 to 16 register names"))?;
                if registers.iter().any(|name| {
                    name.as_str()
                        .is_none_or(|value| value.is_empty() || value.len() > 32)
                }) {
                    return Err(invalid("registers", "contains an invalid register name"));
                }
                let unique = registers
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<std::collections::HashSet<_>>();
                if unique.len() != registers.len() {
                    return Err(invalid("registers", "register names must be unique"));
                }
            }
            optional_integer(object, "disassembly_count", 0, 64)
        }
        "debugger.wait_for_pause" => {
            exact_keys(object, &["after_generation"], &["timeout_ms"])?;
            integer(object, "after_generation", 0, 9_007_199_254_740_991)?;
            optional_integer(object, "timeout_ms", 1, 9_000)
        }
        "debugger.run_to_address" => {
            exact_keys(
                object,
                &["operation_id", "instance_id", "address"],
                &["timeout_ms"],
            )?;
            validate_operation_id(object)?;
            validate_instance_id(object)?;
            validate_address_ref(object, "address")?;
            optional_integer(object, "timeout_ms", 100, 20_000)
        }
        "debugger.pause" | "debugger.resume" | "debugger.step_out" | "debugger.stop"
        | "debuggee.detach" => operation(object, &[]),
        "debugger.step_into" | "debugger.step_over" => {
            exact_keys(object, &["operation_id", "instance_id"], &["thread_id"])?;
            validate_operation_id(object)?;
            validate_instance_id(object)?;
            if object.contains_key("thread_id") {
                validate_thread_id(object)?;
            }
            Ok(())
        }
        "debugger.continue_exception" => {
            exact_keys(
                object,
                &["operation_id", "instance_id", "disposition"],
                &["register_overrides"],
            )?;
            validate_operation_id(object)?;
            validate_instance_id(object)?;
            one_of(object, "disposition", &["handled", "not_handled"])?;
            if let Some(overrides) = object.get("register_overrides") {
                let overrides = overrides
                    .as_array()
                    .filter(|values| (1..=4).contains(&values.len()))
                    .ok_or(invalid(
                        "register_overrides",
                        "must contain 1 to 4 register overrides",
                    ))?;
                let mut names = std::collections::HashSet::new();
                for override_value in overrides {
                    let override_object = override_value.as_object().ok_or(invalid(
                        "register_overrides",
                        "must contain only register override objects",
                    ))?;
                    exact_keys(override_object, &["name", "value"], &[])?;
                    let name = string(override_object, "name", 2, 6)?;
                    if !matches!(
                        name,
                        "rax"
                            | "rbx"
                            | "rcx"
                            | "rdx"
                            | "rsi"
                            | "rdi"
                            | "rbp"
                            | "rsp"
                            | "rip"
                            | "r8"
                            | "r9"
                            | "r10"
                            | "r11"
                            | "r12"
                            | "r13"
                            | "r14"
                            | "r15"
                            | "eax"
                            | "ebx"
                            | "ecx"
                            | "edx"
                            | "esi"
                            | "edi"
                            | "ebp"
                            | "esp"
                            | "eip"
                            | "eflags"
                    ) {
                        return Err(invalid(
                            "register_overrides",
                            "contains an unsupported full-width register",
                        ));
                    }
                    if !names.insert(name) {
                        return Err(invalid(
                            "register_overrides",
                            "register names must be unique",
                        ));
                    }
                    let value = string(override_object, "value", 3, 18)?;
                    if !value.starts_with("0x")
                        || !value[2..]
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err(invalid(
                            "register_overrides",
                            "values must be canonical lowercase hexadecimal",
                        ));
                    }
                }
            }
            Ok(())
        }
        "debuggee.launch" => {
            if !object.contains_key("operation_id") {
                return Err(invalid("operation_id", "must be a UUID"));
            }
            if !object.contains_key("instance_id") {
                return Err(invalid("instance_id", "must be a UUID"));
            }
            exact_keys(
                object,
                &["operation_id", "instance_id", "path"],
                &["working_directory", "arguments"],
            )?;
            validate_operation_id(object)?;
            validate_instance_id(object)?;
            validate_path(object, "path")?;
            if object.contains_key("working_directory") {
                validate_path(object, "working_directory")?;
            }
            if let Some(arguments) = object.get("arguments") {
                let arguments = arguments
                    .as_array()
                    .filter(|values| values.len() <= 32)
                    .ok_or(invalid("arguments", "must contain at most 32 strings"))?;
                let mut total = 0usize;
                for argument in arguments {
                    let value = argument
                        .as_str()
                        .ok_or(invalid("arguments", "must contain only strings"))?;
                    if value.len() > 256 || value.chars().any(char::is_control) {
                        return Err(invalid(
                            "arguments",
                            "contains an oversized or control-character value",
                        ));
                    }
                    total = total.saturating_add(value.len());
                }
                if total > 512 {
                    return Err(invalid("arguments", "exceeds the 512-byte aggregate bound"));
                }
            }
            Ok(())
        }
        "debuggee.launch_dll" => {
            exact_keys(
                object,
                &["operation_id", "instance_id", "path"],
                &["working_directory"],
            )?;
            validate_operation_id(object)?;
            validate_instance_id(object)?;
            validate_path(object, "path")?;
            if object.contains_key("working_directory") {
                validate_path(object, "working_directory")?;
            }
            Ok(())
        }
        "debuggee.attach" => {
            operation(object, &["process_id"])?;
            integer(object, "process_id", 1, 4_294_967_295)
        }
        "trace.start" => {
            operation(object, &["mode", "max_steps", "timeout_ms"])?;
            one_of(object, "mode", &["into", "over"])?;
            integer(object, "max_steps", 1, 4096)?;
            integer(object, "timeout_ms", 100, 30_000)
        }
        "trace.status" => {
            exact_keys(object, &["trace_id"], &[])?;
            validate_uuid_field(object, "trace_id")
        }
        "trace.cancel" => {
            operation(object, &["trace_id"])?;
            validate_uuid_field(object, "trace_id")
        }
        "trace.results" => {
            exact_keys(object, &["trace_id"], &["limit", "cursor"])?;
            validate_uuid_field(object, "trace_id")?;
            discovery_page(object)
        }
        "scyllahide.profile" => {
            let action = string(object, "action", 3, 3)?;
            if action == "get" {
                exact_keys(object, &["action"], &[])
            } else if action == "set" {
                exact_keys(
                    object,
                    &[
                        "action",
                        "profile",
                        "expected_config_generation",
                        "operation_id",
                        "instance_id",
                    ],
                    &[],
                )?;
                string(object, "profile", 1, 128)?;
                let generation = string(object, "expected_config_generation", 71, 71)?;
                if !generation.starts_with("sha256:")
                    || !generation[7..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(invalid(
                        "expected_config_generation",
                        "must be sha256 followed by 64 lowercase hexadecimal characters",
                    ));
                }
                validate_operation_id(object)?;
                validate_instance_id(object)
            } else {
                Err(invalid("action", "must be get or set"))
            }
        }
        "registers.read" => {
            exact_keys(object, &[], &["names", "thread_id"])?;
            if object.contains_key("thread_id") {
                validate_thread_id(object)?;
            }
            if let Some(names) = object.get("names") {
                let names = names
                    .as_array()
                    .ok_or(invalid("names", "must be an array"))?;
                if names.len() > 64
                    || names.iter().any(|name| {
                        name.as_str()
                            .is_none_or(|value| value.is_empty() || value.len() > 32)
                    })
                {
                    return Err(invalid(
                        "names",
                        "contains too many or invalid register names",
                    ));
                }
                let unique = names
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<std::collections::HashSet<_>>();
                if unique.len() != names.len() {
                    return Err(invalid("names", "register names must be unique"));
                }
            }
            Ok(())
        }
        "registers.write" => {
            exact_keys(
                object,
                &["operation_id", "instance_id", "name", "value"],
                &["thread_id"],
            )?;
            validate_operation_id(object)?;
            validate_instance_id(object)?;
            if object.contains_key("thread_id") {
                validate_thread_id(object)?;
            }
            let name = string(object, "name", 2, 6)?;
            if !matches!(
                name,
                "rax"
                    | "rbx"
                    | "rcx"
                    | "rdx"
                    | "rsi"
                    | "rdi"
                    | "rbp"
                    | "rsp"
                    | "rip"
                    | "r8"
                    | "r9"
                    | "r10"
                    | "r11"
                    | "r12"
                    | "r13"
                    | "r14"
                    | "r15"
                    | "eax"
                    | "ebx"
                    | "ecx"
                    | "edx"
                    | "esi"
                    | "edi"
                    | "ebp"
                    | "esp"
                    | "eip"
                    | "eflags"
            ) {
                return Err(invalid("name", "must be a supported full-width register"));
            }
            let value = string(object, "value", 3, 18)?;
            if !value.starts_with("0x")
                || !value[2..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid("value", "must be canonical lowercase hexadecimal"));
            }
            Ok(())
        }
        "address.resolve" | "functions.at" => {
            exact_keys(object, &["address"], &[])?;
            validate_address_ref(object, "address")
        }
        "memory.read" => {
            exact_keys(object, &["address", "length"], &[])?;
            validate_address_ref(object, "address")?;
            integer(object, "length", 1, 65_536)
        }
        "memory.search" => {
            exact_keys(
                object,
                &["scope", "pattern_hex", "mask"],
                &["limit", "cursor"],
            )?;
            let scope = object
                .get("scope")
                .and_then(Value::as_object)
                .ok_or(invalid("scope", "must be a module or bounded range object"))?;
            if scope.contains_key("module") {
                exact_keys(scope, &["module"], &[])?;
                validate_module_name(scope, "module")?;
            } else {
                exact_keys(scope, &["start", "length"], &[])?;
                validate_address_ref(scope, "start")?;
                integer(scope, "length", 1, 16 * 1024 * 1024)?;
            }
            let pattern = string(object, "pattern_hex", 2, 128)?;
            if pattern.len() % 2 != 0
                || !pattern
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid(
                    "pattern_hex",
                    "must contain 1 to 64 lowercase hexadecimal bytes",
                ));
            }
            let mask = string(object, "mask", 1, 64)?;
            if mask.len() != pattern.len() / 2
                || !mask.bytes().all(|byte| matches!(byte, b'x' | b'?'))
                || mask.bytes().all(|byte| byte == b'?')
            {
                return Err(invalid(
                    "mask",
                    "must contain one x or ? per byte and at least one x",
                ));
            }
            discovery_page(object)
        }
        "memory.write" => {
            operation(object, &["address", "data_hex"])?;
            validate_address_ref(object, "address")?;
            let data = string(object, "data_hex", 2, 8192)?;
            if data.len() % 2 != 0
                || !data
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid(
                    "data_hex",
                    "must contain 1 to 4096 lowercase hexadecimal bytes",
                ));
            }
            Ok(())
        }
        "memory.map" => {
            exact_keys(
                object,
                &[],
                &[
                    "module",
                    "committed_only",
                    "executable_only",
                    "compact",
                    "limit",
                    "cursor",
                ],
            )?;
            if object.contains_key("module") {
                validate_module_name(object, "module")?;
            }
            for field in ["committed_only", "executable_only", "compact"] {
                if object.get(field).is_some_and(|value| !value.is_boolean()) {
                    return Err(invalid(field, "must be a boolean"));
                }
            }
            discovery_page(object)
        }
        "modules.list" | "threads.list" | "breakpoints.list" => page(object),
        "callstack.read" => {
            exact_keys(object, &[], &["thread_id", "limit"])?;
            if object.contains_key("thread_id") {
                validate_thread_id(object)?;
            }
            optional_integer(object, "limit", 1, 50)
        }
        "patches.list" => {
            exact_keys(object, &[], &["module", "limit", "cursor"])?;
            if object.contains_key("module") {
                validate_module_name(object, "module")?;
            }
            discovery_page(object)
        }
        "symbols.resolve" => validate_symbol_resolution(object),
        "analysis.function" | "breakpoints.set" | "breakpoints.remove" => {
            operation(object, &["address"])?;
            validate_address_ref(object, "address")
        }
        "breakpoints.hardware.set" | "breakpoints.hardware.remove" => {
            operation(object, &["address", "access", "size"])?;
            validate_address_ref(object, "address")?;
            one_of(object, "access", &["execute", "write", "read_write"])?;
            one_of_integer(object, "size", &[1, 2, 4, 8])
        }
        "breakpoints.memory.set" | "breakpoints.memory.remove" => {
            operation(object, &["address", "access", "size"])?;
            validate_address_ref(object, "address")?;
            one_of(object, "access", &["access", "read", "write", "execute"])?;
            integer(object, "size", 1, 65_536)
        }
        "breakpoints.exception.set" => {
            operation(object, &["code", "chance"])?;
            validate_exception_code(object)?;
            one_of(object, "chance", &["first", "second", "both"])
        }
        "breakpoints.exception.remove" => {
            operation(object, &["code", "chance", "managed_id"])?;
            validate_exception_code(object)?;
            one_of(object, "chance", &["first", "second", "both"])?;
            validate_uuid_field(object, "managed_id")
        }
        "breakpoints.conditional.set" => {
            operation(object, &["address", "condition"])?;
            validate_address_ref(object, "address")?;
            validate_conditional_spec(object)
        }
        "breakpoints.conditional.remove" => {
            operation(object, &["address", "managed_id"])?;
            validate_address_ref(object, "address")?;
            validate_uuid_field(object, "managed_id")
        }
        "breakpoints.enable" | "breakpoints.disable" => {
            operation(object, &["selector"])?;
            validate_breakpoint_selector(object)
        }
        "assembly.preview" => {
            exact_keys(object, &["address", "instruction"], &[])?;
            validate_address_ref(object, "address")?;
            validate_instruction(object)
        }
        "assembly.patch" => {
            operation(
                object,
                &["address", "instruction", "expected_bytes_hex", "fill_nop"],
            )?;
            validate_address_ref(object, "address")?;
            validate_instruction(object)?;
            validate_byte_hex(object, "expected_bytes_hex")?;
            if !object.get("fill_nop").is_some_and(Value::is_boolean) {
                return Err(invalid("fill_nop", "must be a boolean"));
            }
            Ok(())
        }
        "patches.restore" => {
            operation(
                object,
                &[
                    "address",
                    "expected_patched_bytes_hex",
                    "expected_original_bytes_hex",
                ],
            )?;
            validate_address_ref(object, "address")?;
            validate_byte_hex(object, "expected_patched_bytes_hex")?;
            validate_byte_hex(object, "expected_original_bytes_hex")?;
            let patched = object
                .get("expected_patched_bytes_hex")
                .and_then(Value::as_str)
                .ok_or(invalid(
                    "expected_patched_bytes_hex",
                    "has an invalid string value",
                ))?;
            let original = object
                .get("expected_original_bytes_hex")
                .and_then(Value::as_str)
                .ok_or(invalid(
                    "expected_original_bytes_hex",
                    "has an invalid string value",
                ))?;
            if patched.len() != original.len() || patched == original {
                return Err(invalid(
                    "expected_original_bytes_hex",
                    "must have equal length and differ from patched bytes",
                ));
            }
            Ok(())
        }
        "disassembly.read" => {
            exact_keys(object, &["address"], &["count"])?;
            validate_address_ref(object, "address")?;
            optional_integer(object, "count", 1, 256)
        }
        "symbols.search" | "functions.list" => {
            exact_keys(object, &["module"], &["query", "limit", "cursor"])?;
            validate_module_name(object, "module")?;
            optional_query(object)?;
            discovery_page(object)
        }
        "imports.list" | "exports.list" | "sections.list" => {
            exact_keys(object, &["module"], &["query", "limit", "cursor"])?;
            validate_module_name(object, "module")?;
            optional_query_with_limit(object, 128)?;
            discovery_page(object)
        }
        "strings.search" => {
            exact_keys(
                object,
                &["module"],
                &[
                    "query",
                    "min_length",
                    "encoding",
                    "context_bytes",
                    "limit",
                    "cursor",
                ],
            )?;
            validate_module_name(object, "module")?;
            optional_query(object)?;
            optional_integer(object, "min_length", 4, 256)?;
            optional_integer(object, "context_bytes", 0, 128)?;
            if object.contains_key("context_bytes") && !object.contains_key("query") {
                return Err(invalid("context_bytes", "requires query"));
            }
            if let Some(encoding) = object.get("encoding")
                && !matches!(encoding.as_str(), Some("ascii_utf8" | "utf16le" | "both"))
            {
                return Err(invalid("encoding", "must be ascii_utf8, utf16le, or both"));
            }
            discovery_page(object)
        }
        "references.to" => {
            exact_keys(object, &["address"], &["limit", "cursor"])?;
            validate_address_ref(object, "address")?;
            discovery_page(object)
        }
        "expression.evaluate" => {
            exact_keys(object, &["expression"], &[])?;
            let expression = string(object, "expression", 1, 1024)?;
            if expression.chars().any(char::is_control) {
                return Err(invalid("expression", "must not contain control characters"));
            }
            Ok(())
        }
        "expressions.evaluate_batch" => {
            exact_keys(object, &["expressions"], &[])?;
            let expressions = object
                .get("expressions")
                .and_then(Value::as_array)
                .filter(|values| !values.is_empty() && values.len() <= 32)
                .ok_or(invalid("expressions", "must contain 1 to 32 expressions"))?;
            let mut total = 0usize;
            for expression in expressions {
                let expression = expression
                    .as_str()
                    .filter(|value| !value.is_empty() && value.len() <= 1024)
                    .ok_or(invalid("expressions", "contains an invalid expression"))?;
                if expression.chars().any(char::is_control) {
                    return Err(invalid(
                        "expressions",
                        "must not contain control characters",
                    ));
                }
                total = total.saturating_add(expression.len());
            }
            if total > 8192 {
                return Err(invalid(
                    "expressions",
                    "exceeds the 8192-byte aggregate bound",
                ));
            }
            Ok(())
        }
        "debugger.state" | "process.peb" => exact_keys(object, &[], &[]),
        "context.arguments" => {
            exact_keys(object, &[], &["count", "calling_convention", "thread_id"])?;
            optional_integer(object, "count", 1, 16)?;
            if let Some(convention) = object.get("calling_convention")
                && !matches!(
                    convention.as_str(),
                    Some("auto" | "windows_x64" | "cdecl" | "stdcall" | "fastcall" | "thiscall")
                )
            {
                return Err(invalid(
                    "calling_convention",
                    "contains an unsupported convention",
                ));
            }
            if object.contains_key("thread_id") {
                validate_thread_id(object)?;
            }
            Ok(())
        }
        _ => Err(invalid("name", "unknown tool")),
    }
}

fn invalid(field: &'static str, message: &'static str) -> ValidationError {
    ValidationError { field, message }
}

fn exact_keys(
    object: &serde_json::Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), ValidationError> {
    if required.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid("arguments", "a required field is missing"));
    }
    if object
        .keys()
        .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(invalid("arguments", "contains an unknown field"));
    }
    Ok(())
}

fn operation(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
) -> Result<(), ValidationError> {
    if !object.contains_key("operation_id") {
        return Err(invalid("operation_id", "must be a UUID"));
    }
    if !object.contains_key("instance_id") {
        return Err(invalid("instance_id", "must be a UUID"));
    }
    let mut required = Vec::with_capacity(fields.len() + 2);
    required.push("operation_id");
    required.push("instance_id");
    required.extend_from_slice(fields);
    exact_keys(object, &required, &[])?;
    validate_operation_id(object)?;
    validate_instance_id(object)
}

fn validate_operation_id(object: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
    let id = string(object, "operation_id", 36, 36)?;
    let parsed = Uuid::parse_str(id).map_err(|_| invalid("operation_id", "must be a UUID"))?;
    if parsed.hyphenated().to_string() != id {
        return Err(invalid(
            "operation_id",
            "must be a canonical lowercase UUID",
        ));
    }
    Ok(())
}

fn validate_instance_id(object: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
    let id = string(object, "instance_id", 36, 36)?;
    let parsed = Uuid::parse_str(id).map_err(|_| invalid("instance_id", "must be a UUID"))?;
    if parsed.hyphenated().to_string() != id {
        return Err(invalid("instance_id", "must be a canonical lowercase UUID"));
    }
    Ok(())
}

fn validate_uuid_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ValidationError> {
    let id = string(object, field, 36, 36)?;
    let parsed = Uuid::parse_str(id).map_err(|_| invalid(field, "must be a UUID"))?;
    if parsed.hyphenated().to_string() != id {
        return Err(invalid(field, "must be a canonical lowercase UUID"));
    }
    Ok(())
}

fn validate_exception_code(object: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
    let code = string(object, "code", 3, 10)?;
    validate_hex(code, "code")?;
    u32::from_str_radix(&code[2..], 16)
        .map(|_| ())
        .map_err(|_| invalid("code", "must be a canonical 32-bit hexadecimal value"))
}

fn validate_conditional_spec(
    object: &serde_json::Map<String, Value>,
) -> Result<(), ValidationError> {
    let condition = object
        .get("condition")
        .and_then(Value::as_object)
        .ok_or(invalid("condition", "must be a bounded condition object"))?;
    exact_keys(condition, &["mode", "predicates"], &[])?;
    one_of(condition, "mode", &["all", "any"])?;
    let predicates = condition
        .get("predicates")
        .and_then(Value::as_array)
        .filter(|values| (1..=4).contains(&values.len()))
        .ok_or(invalid("predicates", "must contain 1 to 4 predicates"))?;
    for predicate in predicates {
        let predicate = predicate
            .as_object()
            .ok_or(invalid("predicates", "must contain only predicate objects"))?;
        let source = string(predicate, "source", 8, 10)?;
        match source {
            "register" => {
                exact_keys(predicate, &["source", "register", "operator", "value"], &[])?;
                one_of(
                    predicate,
                    "register",
                    &[
                        "cax", "cbx", "ccx", "cdx", "csi", "cdi", "cbp", "csp", "cip",
                    ],
                )?;
                one_of(predicate, "operator", &["eq", "ne", "lt", "le", "gt", "ge"])?;
                validate_bounded_hex_field(predicate, "value", 16)?;
            }
            "thread_id" => {
                exact_keys(predicate, &["source", "operator", "value"], &[])?;
                one_of(predicate, "operator", &["eq", "ne"])?;
                validate_bounded_hex_field(predicate, "value", 8)?;
            }
            "hit_count" => {
                exact_keys(predicate, &["source", "operator", "value"], &[])?;
                one_of(
                    predicate,
                    "operator",
                    &["eq", "ne", "lt", "le", "gt", "ge", "multiple_of"],
                )?;
                integer(predicate, "value", 1, 4_294_967_295)?;
            }
            _ => return Err(invalid("source", "is not an accepted enum value")),
        }
    }
    Ok(())
}

fn validate_breakpoint_selector(
    arguments: &serde_json::Map<String, Value>,
) -> Result<(), ValidationError> {
    let selector = arguments
        .get("selector")
        .and_then(Value::as_object)
        .ok_or(invalid(
            "selector",
            "must be a typed breakpoint selector object",
        ))?;
    let kind = selector
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(invalid("selector", "must contain a supported kind"))?;
    match kind {
        "software" => {
            exact_keys(selector, &["kind", "address"], &[])?;
            validate_address_ref(selector, "address")
        }
        "hardware" => {
            exact_keys(selector, &["kind", "address", "access", "size"], &[])?;
            validate_address_ref(selector, "address")?;
            one_of(selector, "access", &["execute", "write", "read_write"])?;
            one_of_integer(selector, "size", &[1, 2, 4, 8])
        }
        "memory" => {
            exact_keys(selector, &["kind", "address", "access", "size"], &[])?;
            validate_address_ref(selector, "address")?;
            one_of(selector, "access", &["access", "read", "write", "execute"])?;
            integer(selector, "size", 1, 65_536)
        }
        "conditional" => {
            exact_keys(selector, &["kind", "address", "managed_id"], &[])?;
            validate_address_ref(selector, "address")?;
            validate_uuid_field(selector, "managed_id")
        }
        "exception" => {
            exact_keys(selector, &["kind", "code", "chance", "managed_id"], &[])?;
            validate_exception_code(selector)?;
            one_of(selector, "chance", &["first", "second", "both"])?;
            validate_uuid_field(selector, "managed_id")
        }
        _ => Err(invalid("selector", "must contain a supported kind")),
    }
}

fn validate_bounded_hex_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    digits: usize,
) -> Result<(), ValidationError> {
    let value = string(object, field, 3, digits + 2)?;
    validate_hex(value, field)?;
    u64::from_str_radix(&value[2..], 16)
        .map(|_| ())
        .map_err(|_| invalid(field, "must be bounded canonical hexadecimal"))
}

fn validate_path(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ValidationError> {
    let value = string(object, field, 3, 8192)?;
    if value.chars().any(char::is_control) {
        return Err(invalid(field, "must not contain control characters"));
    }
    Ok(())
}

fn validate_address_ref(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ValidationError> {
    let value = object
        .get(field)
        .ok_or(invalid(field, "must be an address reference"))?;
    if let Some(value) = value.as_str() {
        return validate_hex(value, field);
    }
    let reference = value
        .as_object()
        .ok_or(invalid(field, "must be an address reference"))?;
    if reference.len() == 1 && reference.contains_key("absolute") {
        let absolute = reference["absolute"].as_str().ok_or(invalid(
            field,
            "absolute must be canonical lowercase hexadecimal",
        ))?;
        return validate_hex(absolute, field);
    }
    if reference.len() == 2 && reference.contains_key("module") && reference.contains_key("rva") {
        validate_module_value(&reference["module"], field)?;
        let rva = reference["rva"].as_str().ok_or(invalid(
            field,
            "rva must be canonical lowercase hexadecimal",
        ))?;
        return validate_hex(rva, field);
    }
    Err(invalid(
        field,
        "must contain only absolute or module and rva",
    ))
}

fn validate_module_name(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ValidationError> {
    let value = object
        .get(field)
        .ok_or(invalid(field, "module must be a bounded module name"))?;
    validate_module_value(value, field)
}

fn validate_module_value(value: &Value, field: &'static str) -> Result<(), ValidationError> {
    value
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 260
                && !value.chars().any(char::is_control)
                && !value.contains('/')
                && !value.contains('\\')
        })
        .map(|_| ())
        .ok_or(invalid(field, "module must be a bounded module name"))
}

fn optional_query(object: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
    optional_query_with_limit(object, 256)
}

fn optional_query_with_limit(
    object: &serde_json::Map<String, Value>,
    max_bytes: usize,
) -> Result<(), ValidationError> {
    if let Some(value) = object.get("query") {
        let query = value
            .as_str()
            .filter(|query| !query.is_empty() && query.len() <= max_bytes)
            .ok_or(invalid("query", "must be a bounded UTF-8 string"))?;
        if query.chars().any(char::is_control) {
            return Err(invalid("query", "must not contain control characters"));
        }
    }
    Ok(())
}

fn discovery_page(object: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
    optional_integer(object, "limit", 1, 256)?;
    if object.contains_key("cursor") {
        string(object, "cursor", 1, 512)?;
    }
    Ok(())
}

fn validate_hex(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if !(3..=18).contains(&value.len()) {
        return Err(invalid(field, "must be canonical lowercase hexadecimal"));
    }
    if !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(field, "must be canonical lowercase hexadecimal"));
    }
    Ok(())
}

fn validate_instruction(object: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
    let value = string(object, "instruction", 1, 128)?;
    if value
        .bytes()
        .any(|byte| !(0x20..=0x7e).contains(&byte) || byte == b';')
    {
        return Err(invalid(
            "instruction",
            "must be one printable ASCII instruction without semicolons",
        ));
    }
    Ok(())
}

fn validate_byte_hex(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ValidationError> {
    let value = string(object, field, 2, 32)?;
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            field,
            "must contain 1 to 16 lowercase hexadecimal bytes",
        ));
    }
    Ok(())
}

fn string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
    min: usize,
    max: usize,
) -> Result<&'a str, ValidationError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| (min..=max).contains(&value.len()))
        .ok_or(invalid(field, "has an invalid string value"))
}

fn integer(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    min: u64,
    max: u64,
) -> Result<(), ValidationError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| (min..=max).contains(value))
        .map(|_| ())
        .ok_or(invalid(field, "is outside its integer bounds"))
}

fn one_of(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    accepted: &[&str],
) -> Result<(), ValidationError> {
    let value = string(object, field, 1, 32)?;
    if accepted.contains(&value) {
        Ok(())
    } else {
        Err(invalid(field, "is not an accepted enum value"))
    }
}

fn one_of_integer(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    accepted: &[u64],
) -> Result<(), ValidationError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| accepted.contains(value))
        .map(|_| ())
        .ok_or(invalid(field, "is not an accepted integer value"))
}

fn validate_thread_id(object: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
    let value = string(object, "thread_id", 3, 10)?;
    if !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || u32::from_str_radix(&value[2..], 16)
            .ok()
            .is_none_or(|value| value == 0)
    {
        return Err(invalid(
            "thread_id",
            "must be a canonical lowercase 32-bit hexadecimal value",
        ));
    }
    Ok(())
}

fn validate_symbol_resolution(
    object: &serde_json::Map<String, Value>,
) -> Result<(), ValidationError> {
    let by_name = object.contains_key("module") || object.contains_key("name");
    let by_address = object.contains_key("address");
    if by_name == by_address {
        return Err(invalid(
            "arguments",
            "must contain exactly one of module/name or address",
        ));
    }
    if by_address {
        exact_keys(object, &["address"], &[])?;
        return validate_address_ref(object, "address");
    }
    exact_keys(object, &["module", "name"], &[])?;
    validate_module_name(object, "module")?;
    let name = string(object, "name", 1, 256)?;
    if name.chars().any(char::is_control) {
        return Err(invalid("name", "must not contain control characters"));
    }
    Ok(())
}

fn optional_integer(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    min: u64,
    max: u64,
) -> Result<(), ValidationError> {
    object
        .get(field)
        .map_or(Ok(()), |_| integer(object, field, min, max))
}

fn page(object: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
    exact_keys(object, &[], &["limit", "cursor"])?;
    optional_integer(object, "limit", 1, 256)?;
    if object.contains_key("cursor") {
        string(object, "cursor", 1, 512)?;
    }
    Ok(())
}

fn build_catalog() -> Vec<Value> {
    let mut tools = vec![
        read_tool(
            "debugger.state",
            "Read debugger, debuggee, architecture, thread, instruction pointer, and pause state. Use this before state-sensitive operations.",
            object(vec![], vec![]),
        ),
        read_tool(
            "events.list",
            "Read the fixed-capacity recent debugger event ring by sequence and closed event type; this is diagnostic history, not a trace stream.",
            object(
                vec![
                    (
                        "after_sequence",
                        json!({"type":"integer","minimum":0,"maximum":9_007_199_254_740_991_i64}),
                    ),
                    (
                        "types",
                        json!({"type":"array","minItems":1,"maxItems":19,"uniqueItems":true,"items":{"type":"string","enum":EVENT_TYPES}}),
                    ),
                    (
                        "limit",
                        json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
                    ),
                ],
                vec![],
            ),
        ),
        read_tool(
            "events.wait",
            "Wait for the first callback event newer than after_sequence that matches one or more closed event types. The wait is bounded and never consumes the event ring.",
            object(
                vec![
                    (
                        "after_sequence",
                        json!({"type":"integer","minimum":0,"maximum":9_007_199_254_740_991_i64}),
                    ),
                    (
                        "types",
                        json!({"type":"array","minItems":1,"maxItems":19,"uniqueItems":true,"items":{"type":"string","enum":EVENT_TYPES}}),
                    ),
                    (
                        "timeout_ms",
                        json!({"type":"integer","minimum":1,"maximum":9000,"default":5000}),
                    ),
                ],
                vec!["after_sequence", "types"],
            ),
        ),
        read_tool(
            "debugger.snapshot",
            "Capture one compact generation-consistent paused snapshot for one thread, containing selected registers, pause metadata, the instruction-pointer location, and bounded disassembly. Omit thread_id for the selected thread; explicit reads never change thread selection.",
            object(
                vec![
                    (
                        "registers",
                        json!({"type":"array","items":{"type":"string","minLength":1,"maxLength":32},"minItems":1,"maxItems":16,"uniqueItems":true}),
                    ),
                    (
                        "disassembly_count",
                        json!({"type":"integer","minimum":0,"maximum":64,"default":8}),
                    ),
                    (
                        "thread_id",
                        json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$","minLength":3,"maxLength":10}),
                    ),
                ],
                vec![],
            ),
        ),
        read_tool(
            "debugger.wait_for_pause",
            "Wait on debugger callbacks for a pause newer than after_generation. This is read-only observation; timeout does not make a prior mutation ambiguous.",
            object(
                vec![
                    (
                        "after_generation",
                        json!({"type":"integer","minimum":0,"maximum":9_007_199_254_740_991_i64}),
                    ),
                    (
                        "timeout_ms",
                        json!({"type":"integer","minimum":1,"maximum":9000,"default":5000}),
                    ),
                ],
                vec!["after_generation"],
            ),
        ),
        mutation_tool(
            "debugger.pause",
            "Pause a running debuggee and wait for callback-confirmed paused state.",
            operation_schema(vec![]),
            false,
        ),
        mutation_tool(
            "debugger.resume",
            "Resume a paused debuggee. Do not blindly retry an ambiguous result.",
            operation_schema(vec![]),
            false,
        ),
        mutation_tool(
            "debugger.continue_exception",
            "Continue from an actionable exception pause with optional atomic typed register overrides. Requires the current debug-event thread; overrides are architecture-checked before resuming.",
            operation_schema_with_optional(
                vec![(
                    "disposition",
                    json!({"type":"string","enum":["handled","not_handled"]}),
                )],
                vec![(
                    "register_overrides",
                    json!({"type":"array","minItems":1,"maxItems":4,
                        "description":"Atomic full-width register writes. Names must be unique (also checked at runtime); values must fit the target register.",
                        "items":object(vec![
                            ("name", json!({"type":"string","enum":["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip","r8","r9","r10","r11","r12","r13","r14","r15","eax","ebx","ecx","edx","esi","edi","ebp","esp","eip","eflags"]})),
                            ("value", canonical_hex()),
                        ], vec!["name", "value"])}),
                )],
            ),
            false,
        ),
        mutation_tool(
            "debugger.step_into",
            "Step the current debug-event thread; optional thread_id must match it.",
            operation_schema_with_optional(
                vec![],
                vec![(
                    "thread_id",
                    json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$"}),
                )],
            ),
            false,
        ),
        mutation_tool(
            "debugger.step_over",
            "Step over the current debug-event thread; optional thread_id must match it.",
            operation_schema_with_optional(
                vec![],
                vec![(
                    "thread_id",
                    json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$"}),
                )],
            ),
            false,
        ),
        mutation_tool(
            "debugger.step_out",
            "Run toward the current frame's return using fixed rtr, then return a generation-correlated pause snapshot. Check completed: an earlier breakpoint, exception, or user pause returns completed=false and must not be blindly retried.",
            operation_schema(vec![]),
            false,
        ),
        mutation_tool(
            "debugger.run_to_address",
            "Run from a paused state to one absolute or module-relative address through an exactly owned single-shot breakpoint. Interruption and timeout are bounded and the temporary breakpoint is cleaned before a successful result.",
            operation_schema_with_optional(
                vec![("address", address_ref())],
                vec![(
                    "timeout_ms",
                    json!({"type":"integer","minimum":100,"maximum":20000,"default":9000}),
                )],
            ),
            false,
        ),
        mutation_tool(
            "debugger.stop",
            "Stop the current debug session and wait for callback confirmation.",
            operation_schema(vec![]),
            true,
        ),
        mutation_tool(
            "trace.start",
            "Start one owned bounded x64dbg address trace from an actionable pause. Captures only the initial IP and observed into/over step IPs; no expressions, commands, files, registers, or memory history.",
            operation_schema(vec![
                ("mode", json!({"type":"string","enum":["into","over"]})),
                (
                    "max_steps",
                    json!({"type":"integer","minimum":1,"maximum":4096}),
                ),
                (
                    "timeout_ms",
                    json!({"type":"integer","minimum":100,"maximum":30000}),
                ),
            ]),
            false,
        ),
        read_tool(
            "trace.status",
            "Read copied status and counters for the exact retained trace UUID without changing debugger state.",
            object(vec![("trace_id", uuid_schema())], vec!["trace_id"]),
        ),
        mutation_tool(
            "trace.cancel",
            "Cancel the exact active trace UUID through a fixed pause and wait for callback-confirmed terminal state. Never starts or retries a trace.",
            operation_schema(vec![("trace_id", uuid_schema())]),
            false,
        ),
        read_tool(
            "trace.results",
            "Page immutable terminal address-path records for one retained trace UUID. Results contain absolute addresses and start-time module/RVA mappings only.",
            object(
                vec![
                    ("trace_id", uuid_schema()),
                    (
                        "limit",
                        json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
                    ),
                    (
                        "cursor",
                        json!({"type":"string","minLength":1,"maxLength":512}),
                    ),
                ],
                vec!["trace_id"],
            ),
        ),
        mixed_tool(
            "scyllahide.profile",
            "Read or atomically select a ScyllaHide profile for this debugger installation. A changed profile requires a Gateway-owned debugger restart before further analysis.",
            json!({
                "type": "object",
                "oneOf": [
                    {
                        "type": "object",
                        "properties": {"action": {"const": "get"}},
                        "required": ["action"],
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "properties": {
                            "action": {"const": "set"},
                            "profile": {"type":"string","minLength":1,"maxLength":128},
                            "expected_config_generation": {
                                "type":"string",
                                "pattern":"^sha256:[0-9a-f]{64}$"
                            },
                            "operation_id": uuid_schema(),
                            "instance_id": uuid_schema()
                        },
                        "required": ["action","profile","expected_config_generation","operation_id","instance_id"],
                        "additionalProperties": false
                    }
                ]
            }),
        ),
        mutation_tool(
            "debuggee.launch",
            "Load an existing architecture-matched PE into this debugger instance and wait for a callback-confirmed initial pause. Requires no current debuggee, does not restrict the filename extension, and never accepts arbitrary debugger commands.",
            operation_schema_with_optional(
                vec![("path", path_schema())],
                vec![
                    ("working_directory", path_schema()),
                    (
                        "arguments",
                        json!({
                            "type":"array","maxItems":32,
                            "items":{"type":"string","maxLength":256},
                            "description":"Structured argv values; aggregate UTF-8 text is limited to 512 bytes."
                        }),
                    ),
                ],
            ),
            true,
        ),
        mutation_tool(
            "debuggee.launch_dll",
            "Start one architecture-matched DLL through x64dbg's fixed loaddll helper and return at the initial loader pause without resuming. Requires no current debuggee; the canonical DLL path must fit 511 UTF-16 code units. The target is not yet loaded; resume and wait separately to reach x64dbg's DLL-entry breakpoint.",
            operation_schema_with_optional(
                vec![("path", path_schema())],
                vec![("working_directory", path_schema())],
            ),
            true,
        ),
        mutation_tool(
            "debuggee.attach",
            "Attach this matching-architecture debugger to one explicitly supplied PID and wait for pre-attach PID plus actionable-pause confirmation. No process enumeration is performed.",
            operation_schema(vec![(
                "process_id",
                json!({"type":"integer","minimum":1,"maximum":4_294_967_295_u64}),
            )]),
            true,
        ),
        mutation_tool(
            "debuggee.detach",
            "Detach from an attached session without terminating the pre-existing process and wait for callback-confirmed absent state.",
            operation_schema(vec![]),
            false,
        ),
        read_tool(
            "registers.read",
            "Read one thread's selected registers, or the bounded core register set when names is omitted. Omit thread_id for the selected thread. Requires a paused debuggee and never changes thread selection.",
            object(
                vec![
                    (
                        "names",
                        json!({"type":"array","items":{"type":"string","minLength":1,"maxLength":32},"maxItems":64,"uniqueItems":true}),
                    ),
                    (
                        "thread_id",
                        json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$","minLength":3,"maxLength":10}),
                    ),
                ],
                vec![],
            ),
        ),
        mutation_tool(
            "registers.write",
            "Write one full-width core register on an explicit or selected paused thread and verify read-back.",
            operation_schema_with_optional(
                vec![
                    (
                        "name",
                        json!({
                            "type":"string",
                            "enum":[
                                "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip",
                                "r8","r9","r10","r11","r12","r13","r14","r15",
                                "eax","ebx","ecx","edx","esi","edi","ebp","esp","eip",
                                "eflags"
                            ]
                        }),
                    ),
                    (
                        "value",
                        json!({"type":"string","pattern":"^0x[0-9a-f]{1,16}$","minLength":3,"maxLength":18}),
                    ),
                ],
                vec![(
                    "thread_id",
                    json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$"}),
                )],
            ),
            false,
        ),
        read_tool(
            "address.resolve",
            "Resolve an absolute or module-relative address inside the current paused debugger generation. Returns the canonical runtime address and module/RVA metadata.",
            object(vec![("address", address_ref())], vec!["address"]),
        ),
        mutation_tool(
            "analysis.function",
            "Explicitly run bounded recursive analysis for one function in a loaded module and wait for command-queue and function-marker confirmation. This never performs GUI-selection-based whole-module analysis.",
            operation_schema(vec![("address", address_ref())]),
            false,
        ),
        read_tool(
            "memory.read",
            "Read at most 65536 bytes from a paused debuggee. Accepts an absolute or module-relative address reference.",
            object(
                vec![
                    ("address", address_ref()),
                    (
                        "length",
                        json!({"type":"integer","minimum":1,"maximum":65536}),
                    ),
                ],
                vec!["address", "length"],
            ),
        ),
        read_tool(
            "memory.search",
            "Search at most 1 MiB of candidate runtime addresses per request for one explicit 1-64 byte pattern and byte mask. Scope is one loaded module up to 128 MiB or one explicit range up to 16 MiB; scan_complete reports scope pagination while read_completeness reports unreadable memory.",
            object(
                vec![
                    (
                        "scope",
                        json!({
                            "oneOf":[
                                {
                                    "type":"object",
                                    "properties":{"module":module_name_schema()},
                                    "required":["module"],
                                    "additionalProperties":false
                                },
                                {
                                    "type":"object",
                                    "properties":{
                                        "start":address_ref(),
                                        "length":{"type":"integer","minimum":1,"maximum":16_777_216}
                                    },
                                    "required":["start","length"],
                                    "additionalProperties":false
                                }
                            ]
                        }),
                    ),
                    (
                        "pattern_hex",
                        json!({"type":"string","pattern":"^(?:[0-9a-f]{2}){1,64}$","minLength":2,"maxLength":128}),
                    ),
                    (
                        "mask",
                        json!({"type":"string","pattern":"^[x?]*x[x?]*$","minLength":1,"maxLength":64}),
                    ),
                    (
                        "limit",
                        json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
                    ),
                    (
                        "cursor",
                        json!({"type":"string","minLength":1,"maxLength":512}),
                    ),
                ],
                vec!["scope", "pattern_hex", "mask"],
            ),
        ),
        mutation_tool(
            "memory.write",
            "Write at most 4096 bytes to a paused debuggee. Read original bytes first when verification or rollback matters.",
            operation_schema(vec![
                ("address", address_ref()),
                (
                    "data_hex",
                    json!({"type":"string","pattern":"^(?:[0-9a-f]{2}){1,4096}$","minLength":2,"maxLength":8192}),
                ),
            ]),
            true,
        ),
        read_tool(
            "memory.map",
            "List bounded, paginated memory regions for a paused debuggee, optionally filtered by loaded module, committed state, and executable protection.",
            object(
                vec![
                    ("module", module_name_schema()),
                    ("committed_only", json!({"type":"boolean","default":false})),
                    ("executable_only", json!({"type":"boolean","default":false})),
                    ("compact", json!({"type":"boolean","default":false})),
                    (
                        "limit",
                        json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
                    ),
                    (
                        "cursor",
                        json!({"type":"string","minLength":1,"maxLength":512}),
                    ),
                ],
                vec![],
            ),
        ),
        read_tool(
            "modules.list",
            "List bounded, paginated loaded modules for a paused debuggee.",
            page_schema(),
        ),
        read_tool(
            "threads.list",
            "List bounded, paginated threads for a paused debuggee.",
            page_schema(),
        ),
        read_tool(
            "breakpoints.list",
            "Read a bounded, paginated breakpoint snapshot.",
            page_schema(),
        ),
        read_tool(
            "callstack.read",
            "Read at most 50 native x64dbg call-stack frames for the current or one exact thread while paused. Empty native results remain explicitly inconclusive.",
            object(
                vec![
                    (
                        "thread_id",
                        json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$","minLength":3,"maxLength":10}),
                    ),
                    (
                        "limit",
                        json!({"type":"integer","minimum":1,"maximum":50,"default":32}),
                    ),
                ],
                vec![],
            ),
        ),
        read_tool(
            "patches.list",
            "List x64dbg-tracked patches as bounded adjacent ranges, with current-memory verification and snapshot-bound pagination.",
            object(
                vec![
                    ("module", module_name_schema()),
                    (
                        "limit",
                        json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
                    ),
                    (
                        "cursor",
                        json!({"type":"string","minLength":1,"maxLength":512}),
                    ),
                ],
                vec![],
            ),
        ),
        mutation_tool(
            "breakpoints.set",
            "Create a software breakpoint at an absolute or module-relative address while paused.",
            operation_schema(vec![("address", address_ref())]),
            false,
        ),
        mutation_tool(
            "breakpoints.remove",
            "Remove a software breakpoint at an absolute or module-relative address while paused.",
            operation_schema(vec![("address", address_ref())]),
            true,
        ),
        mutation_tool(
            "breakpoints.hardware.set",
            "Set one typed CPU hardware breakpoint after transient process-created and system-breakpoint startup pauses. Execute requires size 1; data addresses must be naturally aligned; x32 rejects size 8; four logical slots are available. Exact native read-back is required.",
            operation_schema(vec![
                ("address", address_ref()),
                (
                    "access",
                    json!({"type":"string","enum":["execute","write","read_write"]}),
                ),
                ("size", json!({"type":"integer","enum":[1,2,4,8]})),
            ]),
            false,
        ),
        mutation_tool(
            "breakpoints.hardware.remove",
            "Remove one hardware breakpoint only when its current access and size exactly match the request. This prevents address-only deletion of externally changed state.",
            operation_schema(vec![
                ("address", address_ref()),
                (
                    "access",
                    json!({"type":"string","enum":["execute","write","read_write"]}),
                ),
                ("size", json!({"type":"integer","enum":[1,2,4,8]})),
            ]),
            true,
        ),
        mutation_tool(
            "breakpoints.memory.set",
            "Set one typed guard-page memory breakpoint for an exact 1-65536 byte range contained in one current memory region, then require exact native read-back.",
            operation_schema(vec![
                ("address", address_ref()),
                (
                    "access",
                    json!({"type":"string","enum":["access","read","write","execute"]}),
                ),
                (
                    "size",
                    json!({"type":"integer","minimum":1,"maximum":65536}),
                ),
            ]),
            false,
        ),
        mutation_tool(
            "breakpoints.memory.remove",
            "Remove one memory breakpoint only when its current access and exact range size match the request. No address-only or batch removal is performed.",
            operation_schema(vec![
                ("address", address_ref()),
                (
                    "access",
                    json!({"type":"string","enum":["access","read","write","execute"]}),
                ),
                (
                    "size",
                    json!({"type":"integer","minimum":1,"maximum":65536}),
                ),
            ]),
            true,
        ),
        mutation_tool(
            "breakpoints.exception.set",
            "Create one backend-managed exception breakpoint for an exact 32-bit code and first, second, or both chances. Existing records collide; exact typed read-back is required.",
            operation_schema(vec![
                (
                    "code",
                    json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$","minLength":3,"maxLength":10}),
                ),
                (
                    "chance",
                    json!({"type":"string","enum":["first","second","both"]}),
                ),
            ]),
            false,
        ),
        mutation_tool(
            "breakpoints.exception.remove",
            "Remove one exception breakpoint only when its code, chance, and backend-managed identity still match. Batch and foreign-record deletion are unavailable.",
            operation_schema(vec![
                (
                    "code",
                    json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$","minLength":3,"maxLength":10}),
                ),
                (
                    "chance",
                    json!({"type":"string","enum":["first","second","both"]}),
                ),
                ("managed_id", uuid_schema()),
            ]),
            true,
        ),
        mutation_tool(
            "breakpoints.conditional.set",
            "Create one backend-managed software breakpoint whose condition is compiled from 1-4 closed register, thread-ID, or hit-count predicates. Caller debugger expressions and commands are not accepted.",
            operation_schema(vec![
                ("address", address_ref()),
                ("condition", conditional_schema()),
            ]),
            false,
        ),
        mutation_tool(
            "breakpoints.conditional.remove",
            "Remove one conditional software breakpoint only when its address and backend-managed identity still match.",
            operation_schema(vec![
                ("address", address_ref()),
                ("managed_id", uuid_schema()),
            ]),
            true,
        ),
        mutation_tool(
            "breakpoints.enable",
            "Enable one exact typed breakpoint while paused. The closed selector preserves managed conditional/exception ownership; hardware identity excludes its transient slot. Already enabled is a verified no-op.",
            operation_schema(vec![("selector", breakpoint_selector_schema())]),
            false,
        ),
        mutation_tool(
            "breakpoints.disable",
            "Disable one exact typed breakpoint while paused without deleting its configuration or managed ownership. Bulk disable and caller debugger commands are unavailable. Already disabled is a verified no-op.",
            operation_schema(vec![("selector", breakpoint_selector_schema())]),
            false,
        ),
        read_tool(
            "assembly.preview",
            "Assemble exactly one printable ASCII instruction at a paused runtime address and return at most 16 bytes without changing memory.",
            object(
                vec![
                    ("address", address_ref()),
                    (
                        "instruction",
                        json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[ -:<-~]+$"}),
                    ),
                ],
                vec!["address", "instruction"],
            ),
        ),
        mutation_tool(
            "assembly.patch",
            "Assemble one instruction and patch an exact 1-16 byte span only when current memory equals expected_bytes_hex and no tracked patch exists. Short instructions require fill_nop=true.",
            operation_schema(vec![
                ("address", address_ref()),
                (
                    "instruction",
                    json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[ -:<-~]+$"}),
                ),
                ("expected_bytes_hex", byte_hex_schema()),
                ("fill_nop", json!({"type":"boolean"})),
            ]),
            true,
        ),
        mutation_tool(
            "patches.restore",
            "Restore one exact 1-16 byte tracked patch only when memory and every x64dbg patch record match both supplied byte strings.",
            operation_schema(vec![
                ("address", address_ref()),
                ("expected_patched_bytes_hex", byte_hex_schema()),
                ("expected_original_bytes_hex", byte_hex_schema()),
            ]),
            true,
        ),
        read_tool(
            "disassembly.read",
            "Decode at most 256 instructions from an absolute or module-relative address while paused.",
            object(
                vec![
                    ("address", address_ref()),
                    (
                        "count",
                        json!({"type":"integer","minimum":1,"maximum":256,"default":32}),
                    ),
                ],
                vec!["address"],
            ),
        ),
        read_tool(
            "expression.evaluate",
            "Evaluate one x64dbg expression while paused. This never executes an arbitrary debugger command.",
            object(
                vec![(
                    "expression",
                    json!({"type":"string","minLength":1,"maxLength":1024}),
                )],
                vec!["expression"],
            ),
        ),
        read_tool(
            "expressions.evaluate_batch",
            "Evaluate 1-32 x64dbg expressions against one paused state generation. Each item reports its own success or evaluation error; no debugger command is executed.",
            object(
                vec![(
                    "expressions",
                    json!({"type":"array","minItems":1,"maxItems":32,"items":{"type":"string","minLength":1,"maxLength":1024}}),
                )],
                vec!["expressions"],
            ),
        ),
        read_tool(
            "process.peb",
            "Read a bounded typed summary of stable PEB fields for the paused debuggee, including anti-debug-relevant flags and core process pointers.",
            object(vec![], vec![]),
        ),
        read_tool(
            "context.arguments",
            "Read bounded ABI argument candidates from one paused thread. Values are exact register/stack reads, but their interpretation assumes the instruction pointer is at callee entry.",
            object(
                vec![
                    (
                        "count",
                        json!({"type":"integer","minimum":1,"maximum":16,"default":8}),
                    ),
                    (
                        "calling_convention",
                        json!({"type":"string","enum":["auto","windows_x64","cdecl","stdcall","fastcall","thiscall"],"default":"auto"}),
                    ),
                    (
                        "thread_id",
                        json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$","minLength":3,"maxLength":10}),
                    ),
                ],
                vec![],
            ),
        ),
        read_tool(
            "symbols.search",
            "Search the current x64dbg symbol database in one loaded module. Results are bounded, paginated, generation-consistent, and known-only.",
            discovery_schema(),
        ),
        read_tool(
            "symbols.resolve",
            "Resolve either one exact case-sensitive symbol name in one module or one runtime address against x64dbg's bounded known-symbol database.",
            json!({
                "type":"object",
                "oneOf":[
                    {
                        "required":["module","name"],
                        "properties":{
                            "module":module_name_schema(),
                            "name":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+$"}
                        },
                        "additionalProperties":false
                    },
                    {
                        "required":["address"],
                        "properties":{"address":address_ref()},
                        "additionalProperties":false
                    }
                ]
            }),
        ),
        read_tool(
            "functions.list",
            "List current x64dbg analyzed functions in one loaded module, optionally filtering by an exact literal substring.",
            discovery_schema(),
        ),
        read_tool(
            "functions.at",
            "Return the one already-known x64dbg function containing an absolute or module-relative address without triggering analysis.",
            object(vec![("address", address_ref())], vec!["address"]),
        ),
        read_tool(
            "imports.list",
            "List one loaded module's bounded import records and current IAT targets without reconstructing imports or evaluating names.",
            linkage_schema(),
        ),
        read_tool(
            "exports.list",
            "List one loaded module's bounded exports, ordinals, and forwarder metadata without triggering symbol work.",
            linkage_schema(),
        ),
        read_tool(
            "sections.list",
            "List bounded named section spans from one loaded module without inferring characteristics or raw-file metadata.",
            linkage_schema(),
        ),
        read_tool(
            "strings.search",
            "Incrementally scan at most 1 MiB of one loaded module for bounded string candidates. Queried results default to compact UTF-8-safe match context. Results are known-only and do not trigger analysis.",
            object(
                vec![
                    ("module", module_name_schema()),
                    (
                        "query",
                        json!({"type":"string","minLength":1,"maxLength":256}),
                    ),
                    (
                        "min_length",
                        json!({"type":"integer","minimum":4,"maximum":256,"default":4}),
                    ),
                    (
                        "encoding",
                        json!({"type":"string","enum":["ascii_utf8","utf16le","both"],"default":"both"}),
                    ),
                    (
                        "context_bytes",
                        json!({"type":"integer","minimum":0,"maximum":128,"default":64,"description":"Maximum UTF-8 bytes returned on each side of a supplied query match."}),
                    ),
                    (
                        "limit",
                        json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
                    ),
                    (
                        "cursor",
                        json!({"type":"string","minLength":1,"maxLength":512}),
                    ),
                ],
                vec!["module"],
            ),
        ),
        read_tool(
            "references.to",
            "List bounded inbound references already known to x64dbg for an absolute or module-relative target.",
            object(
                vec![
                    ("address", address_ref()),
                    (
                        "limit",
                        json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
                    ),
                    (
                        "cursor",
                        json!({"type":"string","minLength":1,"maxLength":512}),
                    ),
                ],
                vec!["address"],
            ),
        ),
    ];
    for tool in &mut tools {
        if let Some(schema) = crate::output_schema::for_tool(tool["name"].as_str().unwrap()) {
            tool["outputSchema"] = schema;
        }
        refine_schema(&mut tool["inputSchema"], "");
        match tool["name"].as_str().unwrap() {
            "strings.search" => {
                tool["inputSchema"]["dependentRequired"] = json!({"context_bytes":["query"]});
            }
            "debugger.snapshot" => {
                tool["inputSchema"]["properties"]["registers"]["description"] =
                    json!("Register names; omitted defaults to cip, csp, cbp, eflags.");
            }
            "registers.read" => {
                tool["inputSchema"]["properties"]["names"]["description"] = json!(
                    "Register names; omitted or empty selects the architecture's bounded core register set."
                );
            }
            "expressions.evaluate_batch" => {
                tool["inputSchema"]["properties"]["expressions"]["description"] = json!(
                    "1-32 expressions, at most 1024 UTF-8 bytes each and 8192 bytes in aggregate; aggregate and byte limits are checked at runtime."
                );
            }
            "memory.search" => {
                tool["inputSchema"]["properties"]["mask"]["description"] = json!(
                    "One x (exact) or ? (wildcard) per pattern byte, with at least one x. Runtime checks mask length equals half the pattern_hex length."
                );
            }
            "patches.restore" => {
                tool["inputSchema"]["properties"]["expected_original_bytes_hex"]["description"] = json!(
                    "Original bytes; must have the same byte length as, and differ from, expected_patched_bytes_hex. Cross-value comparison is checked at runtime."
                );
            }
            _ => {}
        }
    }
    tools
}

// JSON Schema lengths count Unicode scalars, not UTF-8 bytes. Keep byte limits
// explicit rather than claiming maxLength enforces the runtime byte budget.
fn refine_schema(schema: &mut Value, field: &str) {
    if schema["type"] == "string"
        && matches!(
            field,
            "module"
                | "query"
                | "expression"
                | "expressions"
                | "arguments"
                | "path"
                | "working_directory"
        )
    {
        schema["pattern"] = json!(if field == "module" {
            "^[^\\\\/\\u0000-\\u001f\\u007f-\\u009f]+$"
        } else {
            "^[^\\u0000-\\u001f\\u007f-\\u009f]*$"
        });
    }
    let description = match field {
        "operation_id" => Some(
            "Caller UUID. Reuse only for an identical retry; inspect state before retrying an ambiguous mutation, never blindly issue a new ID.",
        ),
        "instance_id" => Some(
            "Current instance UUID from debugger.state; guards against a replaced debugger instance.",
        ),
        "managed_id" => Some(
            "Backend-issued UUID from the managed breakpoint record; preserve it to prove ownership of the exact record.",
        ),
        "trace_id" => Some(
            "Backend-issued UUID returned by trace.start; identifies the exact retained trace, not an operation ID.",
        ),
        "cursor" => Some(
            "Opaque next_cursor from the preceding page; pass unchanged with the same tool and filters. Omit for the first page. A page is not proof of complete coverage; inspect completeness and continuation fields.",
        ),
        "thread_id" => {
            schema["not"] = json!({"pattern":"^0x0+$"});
            Some(
                "Nonzero lowercase hexadecimal 32-bit thread ID. Omit to use the selected thread for reads; stepping requires the current debug-event thread.",
            )
        }
        "query" => Some(
            "Nonempty case-insensitive literal substring filter, not a regex or debugger expression. Control characters are forbidden. Omit for an unfiltered page.",
        ),
        "compact" => Some(
            "Default false. True omits redundant allocation_base and empty info fields; does not merge regions or change pagination.",
        ),
        "length" | "size" => Some("Size in bytes."),
        "timeout_ms" => Some("Bounded wait duration in milliseconds."),
        "working_directory" => Some(
            "Existing absolute directory; omit to use the target file's parent directory. No control characters; minimum 3 UTF-8 bytes is checked at runtime.",
        ),
        _ => None,
    };
    if let Some(description) = description {
        schema["description"] = json!(description);
    }
    if schema["type"] == "string"
        && let Some(max) = schema["maxLength"].as_u64()
        && schema.get("format").is_none()
        && !schema["pattern"]
            .as_str()
            .is_some_and(|pattern| pattern.starts_with("^0x"))
    {
        let description = schema["description"].as_str().unwrap_or("");
        schema["description"] =
            json!(format!("{description} UTF-8 byte limit: {max} (runtime checked).").trim());
    }
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        for (name, child) in properties {
            refine_schema(child, name);
        }
    }
    if let Some(items) = schema.get_mut("items") {
        refine_schema(items, field);
    }
    for keyword in ["oneOf", "allOf", "anyOf"] {
        if let Some(branches) = schema.get_mut(keyword).and_then(Value::as_array_mut) {
            for branch in branches {
                refine_schema(branch, field);
            }
        }
    }
}

fn path_schema() -> Value {
    // One Unicode scalar can satisfy the runtime's three-byte minimum.
    json!({"type":"string","minLength":1,"maxLength":8192,
        "description":"Existing absolute file path, without control characters. Minimum 3 UTF-8 bytes is checked at runtime; the 8192-byte ceiling also applies at the MCP request boundary. Filesystem and PE architecture checks occur in the debugger."})
}

fn module_name_schema() -> Value {
    json!({"type":"string","minLength":1,"maxLength":260})
}

fn discovery_schema() -> Value {
    object(
        vec![
            ("module", module_name_schema()),
            (
                "query",
                json!({"type":"string","minLength":1,"maxLength":256}),
            ),
            (
                "limit",
                json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
            ),
            (
                "cursor",
                json!({"type":"string","minLength":1,"maxLength":512}),
            ),
        ],
        vec!["module"],
    )
}

fn linkage_schema() -> Value {
    object(
        vec![
            ("module", module_name_schema()),
            (
                "query",
                json!({"type":"string","minLength":1,"maxLength":128}),
            ),
            (
                "limit",
                json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
            ),
            (
                "cursor",
                json!({"type":"string","minLength":1,"maxLength":512}),
            ),
        ],
        vec!["module"],
    )
}

fn read_tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

fn mutation_tool(name: &str, description: &str, input_schema: Value, destructive: bool) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": destructive,
            "idempotentHint": false,
            "openWorldHint": false
        }
    })
}

fn mixed_tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": false,
            "idempotentHint": false,
            "openWorldHint": false
        }
    })
}

fn canonical_hex() -> Value {
    json!({ "type": "string", "pattern": "^0x[0-9a-f]{1,16}$", "minLength": 3, "maxLength": 18 })
}

fn byte_hex_schema() -> Value {
    json!({"type":"string","pattern":"^(?:[0-9a-f]{2}){1,16}$","minLength":2,"maxLength":32})
}

fn address_ref() -> Value {
    json!({
        "oneOf": [
            canonical_hex(),
            {
                "type": "object",
                "properties": { "absolute": canonical_hex() },
                "required": ["absolute"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "module": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 260,
                        "pattern": "^[^\\\\/\\u0000-\\u001f\\u007f]+$"
                    },
                    "rva": canonical_hex()
                },
                "required": ["module", "rva"],
                "additionalProperties": false
            }
        ]
    })
}

fn page_schema() -> Value {
    object(
        vec![
            (
                "limit",
                json!({"type":"integer","minimum":1,"maximum":256,"default":100}),
            ),
            (
                "cursor",
                json!({"type":"string","minLength":1,"maxLength":512}),
            ),
        ],
        vec![],
    )
}

fn uuid_schema() -> Value {
    json!({
        "type":"string",
        "format":"uuid",
        "pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        "minLength":36,
        "maxLength":36
    })
}

fn conditional_schema() -> Value {
    let register = object(
        vec![
            ("source", json!({"type":"string","const":"register"})),
            (
                "register",
                json!({"type":"string","enum":["cax","cbx","ccx","cdx","csi","cdi","cbp","csp","cip"]}),
            ),
            (
                "operator",
                json!({"type":"string","enum":["eq","ne","lt","le","gt","ge"]}),
            ),
            (
                "value",
                json!({"type":"string","pattern":"^0x[0-9a-f]{1,16}$","minLength":3,"maxLength":18}),
            ),
        ],
        vec!["source", "register", "operator", "value"],
    );
    let thread_id = object(
        vec![
            ("source", json!({"type":"string","const":"thread_id"})),
            ("operator", json!({"type":"string","enum":["eq","ne"]})),
            (
                "value",
                json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$","minLength":3,"maxLength":10}),
            ),
        ],
        vec!["source", "operator", "value"],
    );
    let hit_count = object(
        vec![
            ("source", json!({"type":"string","const":"hit_count"})),
            (
                "operator",
                json!({"type":"string","enum":["eq","ne","lt","le","gt","ge","multiple_of"]}),
            ),
            (
                "value",
                json!({"type":"integer","minimum":1,"maximum":4_294_967_295_u64}),
            ),
        ],
        vec!["source", "operator", "value"],
    );
    object(
        vec![
            ("mode", json!({"type":"string","enum":["all","any"]})),
            (
                "predicates",
                json!({
                    "type":"array",
                    "minItems":1,
                    "maxItems":4,
                    "items":{"oneOf":[register,thread_id,hit_count]}
                }),
            ),
        ],
        vec!["mode", "predicates"],
    )
}

fn breakpoint_selector_schema() -> Value {
    json!({
        "oneOf": [
            object(
                vec![
                    ("kind", json!({"type":"string","const":"software"})),
                    ("address", address_ref()),
                ],
                vec!["kind", "address"],
            ),
            object(
                vec![
                    ("kind", json!({"type":"string","const":"hardware"})),
                    ("address", address_ref()),
                    ("access", json!({"type":"string","enum":["execute","write","read_write"]})),
                    ("size", json!({"type":"integer","enum":[1,2,4,8]})),
                ],
                vec!["kind", "address", "access", "size"],
            ),
            object(
                vec![
                    ("kind", json!({"type":"string","const":"memory"})),
                    ("address", address_ref()),
                    ("access", json!({"type":"string","enum":["access","read","write","execute"]})),
                    ("size", json!({"type":"integer","minimum":1,"maximum":65536})),
                ],
                vec!["kind", "address", "access", "size"],
            ),
            object(
                vec![
                    ("kind", json!({"type":"string","const":"conditional"})),
                    ("address", address_ref()),
                    ("managed_id", uuid_schema()),
                ],
                vec!["kind", "address", "managed_id"],
            ),
            object(
                vec![
                    ("kind", json!({"type":"string","const":"exception"})),
                    ("code", json!({"type":"string","pattern":"^0x[0-9a-f]{1,8}$","minLength":3,"maxLength":10})),
                    ("chance", json!({"type":"string","enum":["first","second","both"]})),
                    ("managed_id", uuid_schema()),
                ],
                vec!["kind", "code", "chance", "managed_id"],
            ),
        ]
    })
}

fn operation_schema(mut properties: Vec<(&'static str, Value)>) -> Value {
    properties.insert(0, ("instance_id", uuid_schema()));
    properties.insert(0, ("operation_id", uuid_schema()));
    let mut required = vec!["operation_id", "instance_id"];
    required.extend(properties.iter().skip(2).map(|(name, _)| *name));
    object(properties, required)
}

fn operation_schema_with_optional(
    required_properties: Vec<(&'static str, Value)>,
    optional_properties: Vec<(&'static str, Value)>,
) -> Value {
    let mut properties = required_properties;
    let required_names = properties.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    properties.extend(optional_properties);
    let mut schema = operation_schema(properties);
    let mut required = vec![json!("operation_id"), json!("instance_id")];
    required.extend(required_names.into_iter().map(|name| json!(name)));
    schema["required"] = Value::Array(required);
    schema
}

fn object(properties: Vec<(&'static str, Value)>, required: Vec<&'static str>) -> Value {
    let properties = properties
        .into_iter()
        .map(|(name, schema)| (name.to_owned(), schema))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::{Value, json};

    use super::{catalog, is_mutation, is_mutation_call, validate_arguments as validate_raw};

    const INSTANCE_ID: &str = "11111111-2222-4333-8444-555555555555";

    fn validate_arguments(name: &str, arguments: &Value) -> Result<(), super::ValidationError> {
        let mut arguments = arguments.clone();
        if is_mutation(name)
            && arguments.get("operation_id").is_some()
            && arguments.get("instance_id").is_none()
        {
            arguments
                .as_object_mut()
                .expect("test mutation arguments with operation_id are objects")
                .insert("instance_id".to_owned(), json!(INSTANCE_ID));
        }
        validate_raw(name, &arguments)
    }

    fn next_u64(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    fn generated_argument(state: &mut u64, depth: usize) -> Value {
        let choice = next_u64(state) % if depth >= 4 { 4 } else { 6 };
        match choice {
            0 => Value::Null,
            1 => Value::Bool(next_u64(state) & 1 == 1),
            2 => json!(next_u64(state)),
            3 => {
                let length = (next_u64(state) % 384) as usize;
                Value::String(
                    (0..length)
                        .map(|_| char::from((next_u64(state) & 0x7f) as u8))
                        .collect(),
                )
            }
            4 => Value::Array(
                (0..(next_u64(state) % 10))
                    .map(|_| generated_argument(state, depth + 1))
                    .collect(),
            ),
            _ => {
                let mut values = serde_json::Map::new();
                for index in 0..(next_u64(state) % 10) {
                    values.insert(
                        format!("field_{index}"),
                        generated_argument(state, depth + 1),
                    );
                }
                Value::Object(values)
            }
        }
    }

    #[test]
    fn catalog_has_unique_bounded_tool_definitions() {
        assert_eq!(catalog().len(), 64);
        let names = catalog()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<HashSet<_>>();
        assert_eq!(names.len(), catalog().len());
        for tool in catalog() {
            if tool["name"] != "scyllahide.profile" && tool["name"] != "symbols.resolve" {
                assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            }
            assert!(tool["annotations"]["openWorldHint"].is_boolean());
            if tool["annotations"]["readOnlyHint"] == false && tool["name"] != "scyllahide.profile"
            {
                let required = tool["inputSchema"]["required"].as_array().unwrap();
                assert!(required.contains(&json!("operation_id")));
                assert!(required.contains(&json!("instance_id")));
            }
        }
    }

    #[test]
    fn scyllahide_profile_has_action_scoped_mutation_semantics() {
        assert!(!is_mutation_call(
            "scyllahide.profile",
            &json!({"action":"get"})
        ));
        assert!(is_mutation_call(
            "scyllahide.profile",
            &json!({"action":"set"})
        ));
        assert!(validate_raw("scyllahide.profile", &json!({"action":"get"})).is_ok());
        assert!(
            validate_raw(
                "scyllahide.profile",
                &json!({
                    "action":"set",
                    "profile":"VMProtect",
                    "expected_config_generation": format!("sha256:{}", "a".repeat(64)),
                    "operation_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "instance_id":INSTANCE_ID
                })
            )
            .is_ok()
        );
    }

    #[test]
    fn linkage_tools_default_to_broad_pages() {
        for name in ["imports.list", "exports.list", "sections.list"] {
            let tool = catalog()
                .iter()
                .find(|tool| tool["name"] == name)
                .expect("linkage tool must be present");
            assert_eq!(tool["inputSchema"]["properties"]["limit"]["default"], 100);
        }
    }

    #[test]
    fn validation_enforces_bounds_and_additional_properties() {
        assert!(validate_arguments("debugger.state", &json!({})).is_ok());
        assert!(
            validate_arguments(
                "events.list",
                &json!({"after_sequence":0,"types":["breakpoint","dll_loaded"],"limit":256})
            )
            .is_ok()
        );
        assert!(
            validate_arguments("events.list", &json!({"types":["breakpoint","breakpoint"]}))
                .is_err()
        );
        assert!(
            validate_arguments(
                "events.wait",
                &json!({"after_sequence":12,"types":["exception","dll_loaded"],"timeout_ms":9000})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "events.wait",
                &json!({"after_sequence":12,"types":[],"timeout_ms":9000})
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "debugger.snapshot",
                &json!({"registers":["cip","csp"],"disassembly_count":64,"thread_id":"0xffffffff"})
            )
            .is_ok()
        );
        assert!(validate_arguments("debugger.snapshot", &json!({"registers":[]})).is_err());
        assert!(validate_arguments("debugger.snapshot", &json!({"disassembly_count":65})).is_err());
        assert!(validate_arguments("debugger.snapshot", &json!({"thread_id":"0x0"})).is_err());
        assert!(validate_arguments("registers.read", &json!({"thread_id":"0x1"})).is_ok());
        assert!(validate_arguments("registers.read", &json!({"thread_id":"0X1"})).is_err());
        assert!(
            validate_arguments(
                "debugger.wait_for_pause",
                &json!({"after_generation":7,"timeout_ms":9000})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "debugger.wait_for_pause",
                &json!({"after_generation":7,"timeout_ms":9001})
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "debugger.run_to_address",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "instance_id":"11111111-2222-4333-8444-555555555555",
                    "address":{"module":"fixture.exe","rva":"0x1000"},
                    "timeout_ms":20000
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "debugger.run_to_address",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "instance_id":"11111111-2222-4333-8444-555555555555",
                    "address":"0x1000",
                    "timeout_ms":20001
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "registers.write",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "name":"r15",
                    "value":"0xffffffffffffffff"
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "registers.write",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "name":"dr0",
                    "value":"0x1"
                })
            )
            .is_err()
        );
        assert!(validate_arguments("debugger.state", &json!({"extra":true})).is_err());
        assert!(
            validate_arguments("memory.read", &json!({"address":"0x1000","length":65536})).is_ok()
        );
        assert!(
            validate_arguments(
                "memory.read",
                &json!({"address":{"module":"sample.exe","rva":"0x1000"},"length":16})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "memory.search",
                &json!({
                    "scope":{"module":"sample.exe"},
                    "pattern_hex":"488b000089",
                    "mask":"xx??x",
                    "limit":256
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "memory.search",
                &json!({
                    "scope":{
                        "start":{"module":"sample.exe","rva":"0x1000"},
                        "length":16_777_216
                    },
                    "pattern_hex":"4d5a",
                    "mask":"xx",
                    "cursor":"v2:1:abcd:0"
                })
            )
            .is_ok()
        );
        for invalid_search in [
            json!({"scope":{"module":"sample.exe"},"pattern_hex":"4D5A","mask":"xx"}),
            json!({"scope":{"module":"sample.exe"},"pattern_hex":"4d5","mask":"xx"}),
            json!({"scope":{"module":"sample.exe"},"pattern_hex":"4d5a","mask":"x"}),
            json!({"scope":{"module":"sample.exe"},"pattern_hex":"4d5a","mask":"??"}),
            json!({"scope":{"start":"0x1000","length":16_777_217},"pattern_hex":"4d5a","mask":"xx"}),
            json!({"scope":{"module":"sample.exe","length":1},"pattern_hex":"4d5a","mask":"xx"}),
        ] {
            assert!(validate_arguments("memory.search", &invalid_search).is_err());
        }
        assert!(
            validate_arguments(
                "address.resolve",
                &json!({"address":{"absolute":"0x140001000"}})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "analysis.function",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":{"module":"sample.exe","rva":"0x1000"}
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "assembly.preview",
                &json!({"address":"0x1000","instruction":"xor eax, eax"})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "assembly.patch",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":{"module":"sample.exe","rva":"0x1000"},
                    "instruction":"int3",
                    "expected_bytes_hex":"4889c8",
                    "fill_nop":true
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "patches.restore",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":"0x1000",
                    "expected_patched_bytes_hex":"cc9090",
                    "expected_original_bytes_hex":"4889c8"
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "assembly.preview",
                &json!({"address":"0x1000","instruction":"nop; run"})
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "patches.restore",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":"0x1000",
                    "expected_patched_bytes_hex":"cc",
                    "expected_original_bytes_hex":"cc"
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "breakpoints.hardware.set",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":{"module":"sample.exe","rva":"0x1000"},
                    "access":"read_write",
                    "size":8
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "breakpoints.hardware.remove",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":"0x1000",
                    "access":"read",
                    "size":3
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "breakpoints.memory.set",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":"0x1000",
                    "access":"write",
                    "size":65536
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "breakpoints.memory.remove",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":"0x1000",
                    "access":"access",
                    "size":65537
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "breakpoints.exception.set",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "code":"0xe0424242",
                    "chance":"first"
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "breakpoints.exception.remove",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "code":"0x100000000",
                    "chance":"all",
                    "managed_id":"01234567-89ab-4cde-8fab-0123456789ab"
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "breakpoints.conditional.set",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":{"module":"sample.exe","rva":"0x1000"},
                    "condition":{
                        "mode":"all",
                        "predicates":[
                            {"source":"register","register":"cax","operator":"eq","value":"0x1"},
                            {"source":"thread_id","operator":"ne","value":"0x20"},
                            {"source":"hit_count","operator":"multiple_of","value":3}
                        ]
                    }
                })
            )
            .is_ok()
        );
        for invalid_condition in [
            json!({"mode":"all","predicates":[]}),
            json!({"mode":"all","predicates":[{"source":"register","register":"rax","operator":"eq","value":"0x1"}]}),
            json!({"mode":"all","predicates":[{"source":"thread_id","operator":"lt","value":"0x1"}]}),
            json!({"mode":"all","predicates":[{"source":"hit_count","operator":"multiple_of","value":0}]}),
            json!({"mode":"all","predicates":[{"source":"hit_count","operator":"eq","value":1,"extra":true}]}),
        ] {
            assert!(
                validate_arguments(
                    "breakpoints.conditional.set",
                    &json!({
                        "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                        "address":"0x1000",
                        "condition":invalid_condition
                    })
                )
                .is_err()
            );
        }
        assert!(
            validate_arguments(
                "breakpoints.conditional.remove",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":"0x1000",
                    "managed_id":"01234567-89ab-4cde-8fab-0123456789ab"
                })
            )
            .is_ok()
        );
        for selector in [
            json!({"kind":"software","address":"0x1000"}),
            json!({"kind":"hardware","address":{"module":"sample.exe","rva":"0x1000"},"access":"write","size":4}),
            json!({"kind":"memory","address":"0x2000","access":"execute","size":4096}),
            json!({"kind":"conditional","address":"0x3000","managed_id":"01234567-89ab-4cde-8fab-0123456789ab"}),
            json!({"kind":"exception","code":"0xe0424242","chance":"both","managed_id":"01234567-89ab-4cde-8fab-0123456789ab"}),
        ] {
            assert!(
                validate_arguments(
                    "breakpoints.enable",
                    &json!({
                        "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                        "selector":selector
                    })
                )
                .is_ok()
            );
        }
        for selector in [
            json!({"kind":"software","address":"0x1000","managed_id":"01234567-89ab-4cde-8fab-0123456789ab"}),
            json!({"kind":"hardware","address":"0x1000","access":"read","size":4}),
            json!({"kind":"memory","address":"0x1000","access":"write","size":65537}),
            json!({"kind":"conditional","address":"0x1000"}),
            json!({"kind":"exception","code":"0xe0424242","chance":"all","managed_id":"01234567-89ab-4cde-8fab-0123456789ab"}),
            json!({"kind":"unknown","address":"0x1000"}),
        ] {
            assert!(
                validate_arguments(
                    "breakpoints.disable",
                    &json!({
                        "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                        "selector":selector
                    })
                )
                .is_err()
            );
        }
        assert!(
            validate_arguments("memory.read", &json!({"address":"0X1000","length":1})).is_err()
        );
        for invalid in [
            json!({"module":"sample.exe","rva":"0X1000"}),
            json!({"module":"..\\sample.exe","rva":"0x1000"}),
            json!({"module":"sample.exe","rva":"0x1000","extra":true}),
            json!({"absolute":"0x1000","rva":"0x20"}),
        ] {
            assert!(validate_arguments("address.resolve", &json!({"address":invalid})).is_err());
        }
        assert!(
            validate_arguments("memory.read", &json!({"address":"0x1000","length":65537})).is_err()
        );
        assert!(
            validate_arguments(
                "memory.map",
                &json!({"module":"sample.exe","committed_only":true,"executable_only":true,"compact":true,"limit":32})
            )
            .is_ok()
        );
        assert!(validate_arguments("memory.map", &json!({"committed_only":1})).is_err());
        assert!(
            validate_arguments(
                "debuggee.launch",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "path":"C:\\samples\\fixture.exe"
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "debuggee.launch",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "path":"C:\\samples\\fixture.exe",
                    "arguments":"unbounded raw command line"
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "debuggee.launch_dll",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "path":"C:\\samples\\fixture.dll"
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "debuggee.launch_dll",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "path":"C:\\samples\\fixture.dll",
                    "arguments":[]
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "debuggee.launch",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "path":"C:\\samples\\fixture.exe",
                    "arguments":["","with space","quote\"inside","trail\\","兩個字"]
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "debuggee.launch",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "path":"C:\\samples\\fixture.exe",
                    "arguments":["line\nbreak"]
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "debuggee.attach",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "process_id":4_294_967_295_u64
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "debuggee.attach",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "process_id":4_294_967_296_u64
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "imports.list",
                &json!({"module":"fixture.exe","query":"CreateFile","limit":1})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "sections.list",
                &json!({"module":"fixture.exe","query":".text","limit":1})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "exports.list",
                &json!({"module":"fixture.exe","query":"x".repeat(129)})
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "memory.write",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":"0x1000",
                    "data_hex":"90af"
                })
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "memory.write",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "address":"0x1000",
                    "data_hex":"90AF"
                })
            )
            .is_err()
        );
        assert!(
            validate_arguments("expression.evaluate", &json!({"expression":"cip\0junk"})).is_err()
        );
        assert!(
            validate_arguments(
                "expressions.evaluate_batch",
                &json!({"expressions":["cip","csp","kernel32:CreateFileW"]})
            )
            .is_ok()
        );
        assert!(
            validate_arguments("expressions.evaluate_batch", &json!({"expressions":[]})).is_err()
        );
        assert!(validate_arguments("process.peb", &json!({})).is_ok());
        assert!(
            validate_arguments(
                "context.arguments",
                &json!({"count":16,"calling_convention":"windows_x64","thread_id":"0x1"})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "context.arguments",
                &json!({"count":17,"calling_convention":"pascal"})
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "symbols.search",
                &json!({"module":"München.exe","query":"main.","limit":256})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "strings.search",
                &json!({"module":"sample.exe","query":"FlareOn2024","context_bytes":64,"min_length":4,"encoding":"both"})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "strings.search",
                &json!({"module":"sample.exe","query":"x","context_bytes":0})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "strings.search",
                &json!({"module":"sample.exe","context_bytes":64})
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "strings.search",
                &json!({"module":"sample.exe","query":"x","context_bytes":129})
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "strings.search",
                &json!({"module":"sample.exe","encoding":"utf32"})
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "references.to",
                &json!({"address":{"module":"sample.exe","rva":"0x1000"},"limit":100})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "callstack.read",
                &json!({"thread_id":"0xffffffff","limit":50})
            )
            .is_ok()
        );
        assert!(validate_arguments("callstack.read", &json!({"thread_id":"0X1"})).is_err());
        assert!(validate_arguments("callstack.read", &json!({"thread_id":"0x0"})).is_err());
        assert!(validate_arguments("callstack.read", &json!({"limit":51})).is_err());
        assert!(
            validate_arguments(
                "patches.list",
                &json!({"module":"checksum.exe","limit":256,"cursor":"opaque"})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "symbols.resolve",
                &json!({"module":"checksum.exe","name":"main"})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "symbols.resolve",
                &json!({"address":{"module":"checksum.exe","rva":"0x1000"}})
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "symbols.resolve",
                &json!({"module":"checksum.exe","name":"main","address":"0x1000"})
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "functions.at",
                &json!({"address":{"module":"checksum.exe","rva":"0x1000"}})
            )
            .is_ok()
        );
    }

    #[test]
    fn mutations_require_a_canonical_lowercase_uuid() {
        assert!(
            validate_arguments(
                "debugger.resume",
                &json!({"operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813"})
            )
            .is_ok()
        );
        for invalid_id in [
            "checksum-resume-to-entry-001",
            "83DB0D7D-DF01-40AC-BDFC-87BAC1E60813",
            "{83db0d7d-df01-40ac-bdfc-87bac1e60813}",
        ] {
            let error = validate_arguments("debugger.resume", &json!({"operation_id":invalid_id}))
                .unwrap_err();
            assert_eq!(error.field, "operation_id");
        }

        let missing = validate_raw(
            "debugger.resume",
            &json!({"operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813"}),
        )
        .unwrap_err();
        assert_eq!(missing.field, "instance_id");
        for invalid_id in [
            "backend-1",
            "11111111-2222-4333-8444-55555555555A",
            "{11111111-2222-4333-8444-555555555555}",
        ] {
            let error = validate_raw(
                "debugger.resume",
                &json!({
                    "operation_id":"83db0d7d-df01-40ac-bdfc-87bac1e60813",
                    "instance_id":invalid_id
                }),
            )
            .unwrap_err();
            assert_eq!(error.field, "instance_id");
        }
    }

    #[test]
    fn exception_continuation_accepts_only_typed_dispositions() {
        let operation_id = "83db0d7d-df01-40ac-bdfc-87bac1e60813";
        for disposition in ["handled", "not_handled"] {
            assert!(
                validate_arguments(
                    "debugger.continue_exception",
                    &json!({"operation_id":operation_id,"disposition":disposition})
                )
                .is_ok()
            );
        }
        for disposition in ["run", "pass", "swallow", ""] {
            let error = validate_arguments(
                "debugger.continue_exception",
                &json!({"operation_id":operation_id,"disposition":disposition}),
            )
            .unwrap_err();
            assert_eq!(error.field, "disposition");
        }
        assert!(
            validate_arguments(
                "debugger.continue_exception",
                &json!({
                    "operation_id":operation_id,
                    "disposition":"handled",
                    "register_overrides":[
                        {"name":"edi","value":"0x771e0000"},
                        {"name":"eip","value":"0x1e42d0c"}
                    ]
                })
            )
            .is_ok()
        );
        for invalid_overrides in [
            json!([]),
            json!([{"name":"dr0","value":"0x1"}]),
            json!([{"name":"eip","value":"0X1"}]),
            json!([{"name":"eip","value":"0x1"},{"name":"eip","value":"0x2"}]),
            json!([
                {"name":"eax","value":"0x1"},{"name":"ebx","value":"0x2"},
                {"name":"ecx","value":"0x3"},{"name":"edx","value":"0x4"},
                {"name":"esi","value":"0x5"}
            ]),
        ] {
            assert!(
                validate_arguments(
                    "debugger.continue_exception",
                    &json!({
                        "operation_id":operation_id,
                        "disposition":"handled",
                        "register_overrides":invalid_overrides
                    })
                )
                .is_err()
            );
        }
    }

    #[test]
    fn deterministic_argument_corpus_exercises_every_tool_validator() {
        const SEED: u64 = 0x544f_4f4c_5f41_5247;
        const CASES: usize = 4_096;
        let mut state = SEED;
        for case in 0..CASES {
            let tool = &catalog()[case % catalog().len()];
            let name = tool["name"].as_str().unwrap();
            let arguments = generated_argument(&mut state, 0);
            if let Err(error) = validate_arguments(name, &arguments) {
                assert!(error.field.len() <= 32, "seed={SEED:#x} case={case}");
                assert!(error.message.len() <= 128, "seed={SEED:#x} case={case}");
            }
        }
    }
}
