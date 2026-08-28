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
        | "debugger.stop" => operation(object, &[]),
        "debuggee.launch" => {
            exact_keys(object, &["operation_id", "path"], &["working_directory"])?;
            validate_operation_id(object)?;
            validate_path(object, "path")?;
            if object.contains_key("working_directory") {
                validate_path(object, "working_directory")?;
            }
            Ok(())
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
        "address.resolve" => {
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
        "breakpoints.set" | "breakpoints.remove" => {
            operation(object, &["address"])?;
            validate_address_ref(object, "address")
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
                &["query", "min_length", "encoding", "limit", "cursor"],
            )?;
            validate_module_name(object, "module")?;
            optional_query(object)?;
            optional_integer(object, "min_length", 4, 256)?;
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
    let mut required = Vec::with_capacity(fields.len() + 1);
    required.push("operation_id");
    required.extend_from_slice(fields);
    exact_keys(object, &required, &[])?;
    validate_operation_id(object)
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
        read_tool(
            "address.resolve",
            "Resolve an absolute or module-relative address inside the current paused debugger generation. Returns the canonical runtime address and module/RVA metadata.",
            object(vec![("address", address_ref())], vec!["address"]),
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
            "functions.list",
            "List current x64dbg analyzed functions in one loaded module, optionally filtering by an exact literal substring.",
            discovery_schema(),
        ),
        read_tool(
            "strings.search",
            "Incrementally scan at most 1 MiB of one loaded module for bounded string candidates. Results are known-only and do not trigger analysis.",
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
    let mut required = vec!["operation_id"];
    required.extend(properties.iter().skip(1).map(|(name, _)| *name));
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
    let mut required = vec![json!("operation_id")];
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

    use serde_json::json;

    use super::{catalog, validate_arguments};

    #[test]
    fn catalog_has_unique_bounded_tool_definitions() {
        assert_eq!(catalog().len(), 25);
        let names = catalog()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<HashSet<_>>();
        assert_eq!(names.len(), catalog().len());
        for tool in catalog() {
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            assert!(tool["annotations"]["openWorldHint"].is_boolean());
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
                &json!({"module":"sample.exe","min_length":4,"encoding":"both"})
            )
            .is_ok()
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
    }
}
