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
        "memory.map" | "modules.list" | "threads.list" | "breakpoints.list" => page(object),
        "breakpoints.set" | "breakpoints.remove" => {
            operation(object, &["address"])?;
            validate_address_ref(object, "address")
        }
        "disassembly.read" => {
            exact_keys(object, &["address"], &["count"])?;
            validate_address_ref(object, "address")?;
            optional_integer(object, "count", 1, 256)
        }
        "expression.evaluate" => {
            exact_keys(object, &["expression"], &[])?;
            string(object, "expression", 1, 1024).map(|_| ())
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
        let module = reference["module"]
            .as_str()
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 260
                    && !value.chars().any(char::is_control)
                    && !value.contains('/')
                    && !value.contains('\\')
            })
            .ok_or(invalid(field, "module must be a bounded module name"))?;
        let _ = module;
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
            "List bounded, paginated memory regions for a paused debuggee.",
            page_schema(),
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
    ]
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
        assert_eq!(catalog().len(), 19);
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
