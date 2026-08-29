use std::sync::LazyLock;

use serde_json::{Value, json};
use uuid::Uuid;

static CATALOG: LazyLock<Vec<Value>> = LazyLock::new(build_catalog);

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
        "debugger.state" => exact_keys(object, &[], &[]),
        "debugger.snapshot" => {
            exact_keys(object, &[], &["registers", "disassembly_count"])?;
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
        "debugger.pause" | "debugger.resume" | "debugger.step_into" | "debugger.step_over"
        | "debugger.step_out" | "debugger.stop" | "debuggee.detach" => operation(object, &[]),
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
        "registers.read" => {
            exact_keys(object, &[], &["names"])?;
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
            operation(object, &["name", "value"])?;
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

fn validate_path(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), ValidationError> {
    let value = string(object, field, 3, 32_767)?;
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
    if let Some(value) = object.get("query") {
        let query = value
            .as_str()
            .filter(|query| !query.is_empty() && query.len() <= 256)
            .ok_or(invalid("query", "must be 1 to 256 UTF-8 bytes"))?;
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
    if !(3..=34).contains(&value.len()) {
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
    vec![
        read_tool(
            "debugger.state",
            "Read debugger, debuggee, architecture, thread, instruction pointer, and pause state. Use this before state-sensitive operations.",
            object(vec![], vec![]),
        ),
        read_tool(
            "debugger.snapshot",
            "Capture one compact generation-consistent paused snapshot containing selected registers, pause metadata, the instruction-pointer location, and bounded disassembly.",
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
            "debugger.step_into",
            "Execute one step-into operation and wait for callback-confirmed pause.",
            operation_schema(vec![]),
            false,
        ),
        mutation_tool(
            "debugger.step_over",
            "Execute one step-over operation and wait for callback-confirmed pause.",
            operation_schema(vec![]),
            false,
        ),
        mutation_tool(
            "debugger.step_out",
            "Run toward the current frame's return using fixed rtr, then return a generation-correlated pause snapshot. Check completed: an earlier breakpoint, exception, or user pause returns completed=false and must not be blindly retried.",
            operation_schema(vec![]),
            false,
        ),
        mutation_tool(
            "debugger.stop",
            "Stop the current debug session and wait for callback confirmation.",
            operation_schema(vec![]),
            true,
        ),
        mutation_tool(
            "debuggee.launch",
            "Load an existing executable into this debugger instance and wait for a callback-confirmed initial pause. Requires no current debuggee and never accepts arbitrary debugger commands.",
            operation_schema_with_optional(
                vec![(
                    "path",
                    json!({"type":"string","minLength":3,"maxLength":32767}),
                )],
                vec![(
                    "working_directory",
                    json!({"type":"string","minLength":3,"maxLength":32767}),
                )],
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
            "Read selected registers, or the bounded core register set when names is omitted. Requires a paused debuggee.",
            object(
                vec![(
                    "names",
                    json!({"type":"array","items":{"type":"string","minLength":1,"maxLength":32},"maxItems":64,"uniqueItems":true}),
                )],
                vec![],
            ),
        ),
        mutation_tool(
            "registers.write",
            "Write one full-width core register in a paused debuggee through the typed SDK, then verify exact read-back. Names are architecture-specific; partial, vector, segment, and debug registers are excluded.",
            operation_schema(vec![
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
            ]),
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
        mutation_tool(
            "memory.write",
            "Write at most 4096 bytes to a paused debuggee. Read original bytes first when verification or rollback matters.",
            operation_schema(vec![
                ("address", address_ref()),
                (
                    "data_hex",
                    json!({"type":"string","pattern":"^(?:[0-9a-f]{2}){1,4096}$"}),
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
        read_tool(
            "assembly.preview",
            "Assemble exactly one printable ASCII instruction at a paused runtime address and return at most 16 bytes without changing memory.",
            object(
                vec![
                    ("address", address_ref()),
                    (
                        "instruction",
                        json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[ -:<>-~]+$"}),
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
                    json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[ -:<>-~]+$"}),
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
            "symbols.search",
            "Search the current x64dbg symbol database in one loaded module. Results are bounded, paginated, generation-consistent, and known-only.",
            discovery_schema(),
        ),
        read_tool(
            "symbols.resolve",
            "Resolve either one exact case-sensitive symbol name in one module or one runtime address against x64dbg's bounded known-symbol database.",
            json!({
                "type":"object",
                "additionalProperties":false,
                "oneOf":[
                    {
                        "required":["module","name"],
                        "properties":{
                            "module":module_name_schema(),
                            "name":{"type":"string","minLength":1,"maxLength":256}
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
    ]
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

fn canonical_hex() -> Value {
    json!({ "type": "string", "pattern": "^0x[0-9a-f]+$", "minLength": 3, "maxLength": 34 })
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

fn operation_schema(mut properties: Vec<(&'static str, Value)>) -> Value {
    properties.insert(
        0,
        (
            "instance_id",
            json!({
                "type":"string",
                "format":"uuid",
                "pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                "minLength":36,
                "maxLength":36
            }),
        ),
    );
    properties.insert(
        0,
        (
            "operation_id",
            json!({
                "type":"string",
                "format":"uuid",
                "pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                "minLength":36,
                "maxLength":36
            }),
        ),
    );
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

    use super::{catalog, is_mutation, validate_arguments as validate_raw};

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
        assert_eq!(catalog().len(), 41);
        let names = catalog()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<HashSet<_>>();
        assert_eq!(names.len(), catalog().len());
        for tool in catalog() {
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            assert!(tool["annotations"]["openWorldHint"].is_boolean());
            if tool["annotations"]["readOnlyHint"] == false {
                let required = tool["inputSchema"]["required"].as_array().unwrap();
                assert!(required.contains(&json!("operation_id")));
                assert!(required.contains(&json!("instance_id")));
            }
        }
    }

    #[test]
    fn validation_enforces_bounds_and_additional_properties() {
        assert!(validate_arguments("debugger.state", &json!({})).is_ok());
        assert!(
            validate_arguments(
                "debugger.snapshot",
                &json!({"registers":["cip","csp"],"disassembly_count":64})
            )
            .is_ok()
        );
        assert!(validate_arguments("debugger.snapshot", &json!({"registers":[]})).is_err());
        assert!(validate_arguments("debugger.snapshot", &json!({"disassembly_count":65})).is_err());
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
