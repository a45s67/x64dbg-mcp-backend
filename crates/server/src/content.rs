use std::fmt::Write;

use serde_json::Value;

const HEXDUMP_PREVIEW_BYTES: usize = 128;

pub(crate) fn success_summary(name: &str, value: &Value) -> String {
    if name == "memory.read"
        && let Some(summary) = memory_read_summary(value)
    {
        return summary;
    }
    if is_execution_tool(name) {
        return execution_summary(name, value);
    }
    if name.starts_with("breakpoints.")
        && name != "breakpoints.list"
        && let Some(summary) = breakpoint_summary(name, value)
    {
        return summary;
    }
    if name == "scyllahide.profile" {
        let profile = value
            .get("configured_profile")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return if value.get("restart_required").and_then(Value::as_bool) == Some(true) {
            format!("ScyllaHide profile is {profile}; restart x64dbg before continuing analysis.")
        } else {
            format!("ScyllaHide profile is {profile}; no restart is required.")
        };
    }
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let next_page = value
            .get("next_cursor")
            .is_some_and(|cursor| !cursor.is_null());
        return format!(
            "{name} completed: {} items; next_page={next_page}.",
            items.len()
        );
    }
    if let Some(state) = value.get("debuggee_state").and_then(Value::as_str) {
        return format!("{name} completed: debuggee_state={state}.");
    }
    format!("{name} completed.")
}

fn memory_read_summary(value: &Value) -> Option<String> {
    let data_hex = value.get("data_hex")?.as_str()?;
    let bytes_read = value.get("bytes_read")?.as_u64()?;
    let address = value.get("address")?.as_str()?;
    let base = parse_hex(address)?;
    let declared_bytes = usize::try_from(bytes_read).unwrap_or(usize::MAX);
    let preview = decode_hex_prefix(data_hex, HEXDUMP_PREVIEW_BYTES.min(declared_bytes))?;
    let location = format_location(value.get("location"), Some(address));
    let mut text = format!("{bytes_read} bytes at {location}");
    if preview.is_empty() {
        return Some(text);
    }
    text.push('\n');
    text.push_str(&format_hexdump(base, &preview));
    if bytes_read > preview.len() as u64 {
        let _ = write!(
            text,
            "\nShowing first {} of {bytes_read} bytes; complete data is available in structuredContent.",
            preview.len()
        );
    }
    Some(text)
}

fn decode_hex_prefix(value: &str, max_bytes: usize) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    pairs
        .iter()
        .take(max_bytes)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn format_hexdump(base: u64, bytes: &[u8]) -> String {
    let address_width = if base.saturating_add(bytes.len() as u64) > u64::from(u32::MAX) {
        16
    } else {
        8
    };
    let mut output = String::new();
    for (row_index, row) in bytes.chunks(16).enumerate() {
        if row_index != 0 {
            output.push('\n');
        }
        let row_address = base.saturating_add((row_index * 16) as u64);
        let _ = write!(output, "{row_address:0address_width$X}  ");
        let mut hexadecimal = String::new();
        for index in 0..16 {
            if index == 8 {
                hexadecimal.push(' ');
            }
            if let Some(byte) = row.get(index) {
                let _ = write!(hexadecimal, "{byte:02X}");
            } else {
                hexadecimal.push_str("  ");
            }
            if index != 15 {
                hexadecimal.push(' ');
            }
        }
        output.push_str(&hexadecimal);
        output.push_str("  |");
        for byte in row {
            output.push(if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            });
        }
        output.push('|');
    }
    output
}

fn parse_hex(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
}

fn format_location(location: Option<&Value>, fallback_address: Option<&str>) -> String {
    let object = location.and_then(Value::as_object);
    let address = object
        .and_then(|value| value.get("address"))
        .and_then(Value::as_str)
        .or(fallback_address)
        .unwrap_or("unknown address");
    match object
        .and_then(|value| Some((value.get("module")?.as_str()?, value.get("rva")?.as_str()?)))
    {
        Some((module, rva)) => format!("{module}+{rva} ({address})"),
        None => address.to_owned(),
    }
}

fn is_execution_tool(name: &str) -> bool {
    matches!(
        name,
        "debugger.resume"
            | "debugger.pause"
            | "debugger.step_into"
            | "debugger.step_over"
            | "debugger.step_out"
            | "debugger.run_to_address"
    )
}

fn execution_summary(name: &str, value: &Value) -> String {
    let Some(state) = value.get("debuggee_state").and_then(Value::as_str) else {
        return format!("{name} completed.");
    };
    let mut text = match state {
        "paused" => {
            let location = execution_location(value);
            location.map_or_else(
                || "Execution paused.".to_owned(),
                |location| format!("Execution paused at {location}."),
            )
        }
        "running" => "Execution resumed and the running state was callback-confirmed.".to_owned(),
        "absent" => "Debug session stopped and the absent state was callback-confirmed.".to_owned(),
        other => format!("{name} completed: debuggee_state={other}."),
    };
    if state == "paused" {
        if let Some(reason) = value.get("pause_reason").and_then(format_pause_reason) {
            let _ = write!(text, "\nReason: {reason}.");
        }
        if let Some(instruction) = value
            .get("instruction")
            .and_then(|item| item.get("text"))
            .and_then(Value::as_str)
            .filter(|text| bounded_text(text, 256))
        {
            let _ = write!(text, "\nInstruction: {instruction}");
        }
        if name == "debugger.run_to_address" {
            if let Some(completed) = value.get("completed").and_then(Value::as_bool) {
                let _ = write!(text, "\nRequested target reached: {completed}.");
            }
        } else if name == "debugger.step_out"
            && let Some(completed) = value.get("completed").and_then(Value::as_bool)
        {
            let _ = write!(text, "\nReturn condition confirmed: {completed}.");
        }
    }
    text
}

fn execution_location(value: &Value) -> Option<String> {
    let instruction_pointer = value.get("instruction_pointer")?;
    if instruction_pointer.is_object() {
        return Some(format_location(Some(instruction_pointer), None));
    }
    let absolute = instruction_pointer.as_str()?;
    let target = value.get("target");
    if target
        .and_then(|item| item.get("address"))
        .and_then(Value::as_str)
        == Some(absolute)
    {
        return Some(format_location(target, Some(absolute)));
    }
    Some(absolute.to_owned())
}

fn format_pause_reason(value: &Value) -> Option<String> {
    let kind = value.get("kind")?.as_str()?;
    if kind == "exception" {
        let code = value
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Some(match value.get("first_chance").and_then(Value::as_bool) {
            Some(true) => format!("exception {code}, first chance"),
            Some(false) => format!("exception {code}, second chance"),
            None => format!("exception {code}"),
        });
    }
    if kind == "breakpoint" {
        let breakpoint_type = value
            .get("breakpoint_type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Some(format!("{breakpoint_type} breakpoint"));
    }
    Some(kind.replace('_', " "))
}

fn breakpoint_summary(name: &str, value: &Value) -> Option<String> {
    let kind = value
        .get("type")
        .or_else(|| value.get("kind"))
        .and_then(Value::as_str)
        .or_else(|| breakpoint_kind_from_name(name))?;
    let description = breakpoint_description(kind, value);
    let location = value
        .get("location")
        .map(|location| {
            format_location(Some(location), value.get("address").and_then(Value::as_str))
        })
        .or_else(|| {
            value
                .get("code")
                .and_then(Value::as_str)
                .map(|code| format!("exception {code}"))
        })?;
    let action = if let Some(present) = value.get("present").and_then(Value::as_bool) {
        if present { "set" } else { "removed" }
    } else {
        let enabled = value.get("enabled").and_then(Value::as_bool)?;
        if enabled { "enabled" } else { "disabled" }
    };
    let mut text = format!("{description} breakpoint {action} and verified at {location}.");
    if let Some(managed_id) = value
        .get("managed_id")
        .and_then(Value::as_str)
        .filter(|id| bounded_text(id, 64))
    {
        let _ = write!(text, "\nBackend ownership: {managed_id}.");
    }
    if let Some(changed) = value.get("changed").and_then(Value::as_bool) {
        let _ = write!(text, "\nDebugger state changed: {changed}.");
    }
    Some(text)
}

fn breakpoint_kind_from_name(name: &str) -> Option<&'static str> {
    if name == "breakpoints.set" || name == "breakpoints.remove" {
        Some("software")
    } else if name.starts_with("breakpoints.hardware.") {
        Some("hardware")
    } else if name.starts_with("breakpoints.memory.") {
        Some("memory")
    } else if name.starts_with("breakpoints.exception.") {
        Some("exception")
    } else if name.starts_with("breakpoints.conditional.") {
        Some("conditional software")
    } else {
        None
    }
}

fn breakpoint_description(kind: &str, value: &Value) -> String {
    let mut description = match kind {
        "software" => "Software".to_owned(),
        "hardware" => "Hardware".to_owned(),
        "memory" => "Memory".to_owned(),
        "exception" => "Exception".to_owned(),
        "conditional" | "conditional software" => "Conditional software".to_owned(),
        other => other.to_owned(),
    };
    if let Some(access) = value.get("access").and_then(Value::as_str) {
        let _ = write!(description, " {access}");
    }
    description
}

fn bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{format_hexdump, success_summary};

    #[test]
    fn hexdump_formats_empty_partial_and_full_rows() {
        assert_eq!(format_hexdump(0x1000, &[]), "");
        let partial = format_hexdump(0x1000, b"A\0z");
        assert!(partial.starts_with("00001000  41 00 7A"));
        assert!(partial.ends_with("|A.z|"));

        let full = format_hexdump(0x1000, &(0_u8..16).collect::<Vec<_>>());
        assert!(full.contains("07  08"));
        assert!(full.ends_with("|................|"));
    }

    #[test]
    fn hexdump_increments_addresses_and_renders_printable_ascii() {
        let bytes = vec![b'A'; 17];
        let output = format_hexdump(0x1234, &bytes);
        assert!(output.contains("00001234"));
        assert!(output.contains("\n00001244"));
        assert!(output.contains("|AAAAAAAAAAAAAAAA|"));
    }

    #[test]
    fn memory_preview_is_module_relative_and_truncated_at_128_bytes() {
        let data_hex = "41".repeat(65_536);
        let value = json!({
            "address":"0x1e56090",
            "location":{
                "address":"0x1e56090",
                "module":"checksum.exe",
                "rva":"0x16090"
            },
            "data_hex":data_hex,
            "bytes_read":65_536,
            "complete":true,
            "state_generation":42
        });
        let text = success_summary("memory.read", &value);
        assert!(text.starts_with("65536 bytes at checksum.exe+0x16090 (0x1e56090)"));
        assert!(text.contains("Showing first 128 of 65536 bytes"));
        assert_eq!(text.matches("|AAAAAAAAAAAAAAAA|").count(), 8);
        assert!(!text.contains(&"41".repeat(129)));
    }

    #[test]
    fn memory_preview_uses_absolute_address_without_module() {
        let value = json!({
            "address":"0x140001000",
            "location":{"address":"0x140001000","module":null,"rva":null},
            "data_hex":"4142",
            "bytes_read":2
        });
        let text = success_summary("memory.read", &value);
        assert!(text.starts_with("2 bytes at 0x140001000"));
        assert!(text.contains("0000000140001000"));
        assert!(text.ends_with("|AB|"));
    }

    #[test]
    fn execution_summary_uses_only_returned_observation() {
        let value = json!({
            "debuggee_state":"paused",
            "instruction_pointer":"0x1e6548d",
            "pause_reason":{"kind":"exception","code":"0xc0000005","first_chance":true},
            "instruction":{"text":"movzx ecx, word ptr ds:[edi]"}
        });
        let text = success_summary("debugger.step_out", &value);
        assert!(text.contains("Execution paused at 0x1e6548d."));
        assert!(text.contains("Reason: exception 0xc0000005, first chance."));
        assert!(text.contains("Instruction: movzx ecx, word ptr ds:[edi]"));
    }

    #[test]
    fn breakpoint_summary_reports_verified_postcondition_and_ownership() {
        let value = json!({
            "location":{"address":"0x1b12a03","module":"checksum.exe","rva":"0x12a03"},
            "managed_id":"01234567-89ab-4cde-8fab-0123456789ab",
            "present":true
        });
        let text = success_summary("breakpoints.conditional.set", &value);
        assert!(text.contains(
            "Conditional software breakpoint set and verified at checksum.exe+0x12a03 (0x1b12a03)."
        ));
        assert!(text.contains("Backend ownership:"));
    }
}
