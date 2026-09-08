use std::fmt::Write;

use serde_json::Value;

const HEXDUMP_PREVIEW_BYTES: usize = 128;

pub(crate) fn success_summary(name: &str, value: &Value) -> String {
    limit_summary(&success_summary_inner(name, value))
}

fn success_summary_inner(name: &str, value: &Value) -> String {
    if value.get("ok").and_then(Value::as_bool) == Some(false) && value.get("error").is_some() {
        return error_summary(name, value);
    }
    if matches!(name, "debugger.state" | "debugger.snapshot") {
        let mut text = format!("{name}:");
        append_fields(
            &mut text,
            value,
            &[
                "debuggee_state",
                "architecture",
                "process_id",
                "active_thread_id",
                "thread_id",
                "current",
                "state_generation",
                "instance_id",
                "diagnostic_code",
            ],
        );
        if let Some(location) = execution_location(value) {
            let _ = write!(text, "\nInstruction pointer: {location}.");
        }
        if let Some(reason) = value.get("pause_reason").and_then(format_pause_reason) {
            let _ = write!(text, "\nReason: {reason}.");
        }
        if let Some(registers) = value.get("registers").and_then(Value::as_object) {
            let _ = write!(text, "\nRegisters ({}):", registers.len());
            for (name, value) in registers.iter().take(16) {
                if bounded_text(name, 32)
                    && let Some(value) = value.as_str().filter(|v| bounded_text(v, 34))
                {
                    let _ = write!(text, " {name}={value};");
                }
            }
            if registers.len() > 16 {
                text.push_str(
                    "\nShowing at most 16 registers; full set is available in structuredContent.",
                );
            }
        }
        if let Some(items) = value.get("disassembly").and_then(Value::as_array) {
            let _ = write!(text, "\nDisassembly: {} instructions.", items.len());
            append_preview(&mut text, items);
        }
        if let Some(actions) = value.get("next_actions").and_then(Value::as_array) {
            for action in actions.iter().take(2) {
                if let Some(tool) = action
                    .get("tool")
                    .and_then(Value::as_str)
                    .filter(|v| bounded_text(v, 128))
                {
                    let _ = write!(text, "\nNext: call {tool}.");
                }
            }
        }
        return text;
    }
    if name == "memory.write"
        && let Some(bytes) = value.get("bytes_written").and_then(Value::as_u64)
    {
        let mut text = format!(
            "Wrote {bytes} bytes at {}.",
            format_location(
                value.get("location"),
                value.get("address").and_then(Value::as_str)
            )
        );
        append_fields(&mut text, value, &["verified"]);
        return text;
    }
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
        return match value.get("restart_required").and_then(Value::as_bool) {
            Some(true) => format!(
                "ScyllaHide profile is {profile}; restart x64dbg before continuing analysis."
            ),
            Some(false) => format!("ScyllaHide profile is {profile}; no restart is required."),
            None => {
                format!("ScyllaHide profile is {profile}; restart requirement was not reported.")
            }
        };
    }
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let next_page = value
            .get("next_cursor")
            .is_some_and(|cursor| !cursor.is_null());
        let mut text = format!(
            "{name}: {} items in this response; next_page={next_page}.",
            items.len()
        );
        append_fields(
            &mut text,
            value,
            &[
                "scan_complete",
                "read_completeness",
                "bytes_scanned",
                "unreadable_bytes",
                "incomplete",
                "completeness",
                "truncated",
                "state_generation",
            ],
        );
        if name.ends_with(".search") || name == "memory.map" {
            append_preview(&mut text, items);
        }
        if next_page {
            text.push_str("\nContinue with the opaque next_cursor from structuredContent and unchanged filters.");
        }
        return text;
    }
    if let Some(state) = value.get("debuggee_state").and_then(Value::as_str) {
        return format!("{name} completed: debuggee_state={state}.");
    }
    format!("{name} completed.")
}

fn append_fields(text: &mut String, value: &Value, fields: &[&str]) {
    for field in fields {
        let Some(value) = value.get(*field) else {
            continue;
        };
        match value {
            Value::String(value) => {
                let _ = write!(text, " {field}=");
                let end = value.floor_char_boundary(value.len().min(256));
                for character in value[..end].chars() {
                    text.push(if character.is_control() {
                        ' '
                    } else {
                        character
                    });
                }
                if end < value.len() {
                    text.push_str(" [truncated; see structuredContent]");
                }
                text.push(';');
            }
            Value::Bool(_) | Value::Number(_) => {
                let _ = write!(text, " {field}={value};");
            }
            _ => {}
        }
    }
}

fn append_preview(text: &mut String, items: &[Value]) {
    for item in items.iter().take(3) {
        text.push('\n');
        text.push_str(&format_location(
            item.get("location"),
            item.get("address")
                .or_else(|| item.get("base"))
                .and_then(Value::as_str),
        ));
        append_fields(
            text,
            item,
            &[
                "text",
                "name",
                "encoding",
                "byte_length",
                "truncated",
                "size",
                "protect",
                "state",
                "type",
                "info",
            ],
        );
    }
    if items.len() > 3 {
        text.push_str("\nShowing first 3 items; full page is available in structuredContent.");
    }
}

// Bound the final rendering too: module names and diagnostics come from the debuggee.
fn limit_summary(text: &str) -> String {
    const LIMIT: usize = 4096;
    const SUFFIX: &str = "\nSummary truncated; see structuredContent.";
    let mut output = String::new();
    for character in text.chars() {
        let character = if character.is_control() && character != '\n' {
            ' '
        } else {
            character
        };
        if output.len() + character.len_utf8() > LIMIT - SUFFIX.len() {
            output.push_str(SUFFIX);
            return output;
        }
        output.push(character);
    }
    output
}

/// Render the serialized MCP tool-error envelope without changing its retry advice.
pub(crate) fn error_summary(name: &str, value: &Value) -> String {
    let error = &value["error"];
    let message = error["details"]["debugger_message"]
        .as_str()
        .filter(|v| bounded_text(v, 512))
        .or_else(|| error["message"].as_str().filter(|v| bounded_text(v, 512)))
        .unwrap_or("see structuredContent for the error message");
    let mut text = format!(
        "{name} failed: {}: {message}; recoverable={}; safeToRetry={}.",
        error["code"].as_str().unwrap_or("UNKNOWN"),
        error["recoverable"],
        error["safeToRetry"]
    );
    append_fields(
        &mut text,
        &error["details"],
        &["current_state", "debuggee_state", "outcome"],
    );
    let mut displayed = 0;
    if let Some(action) = error["suggestedAction"]
        .as_str()
        .filter(|v| bounded_text(v, 512))
    {
        let _ = write!(text, "\nNext: {action}");
        displayed += 1;
    }
    if let Some(actions) = error["nextActions"].as_array() {
        for action in actions.iter().take(2 - displayed) {
            if let Some(reason) = action["reason"].as_str().filter(|v| bounded_text(v, 256)) {
                text.push_str("\nNext:");
                append_fields(&mut text, action, &["code", "execution", "tool"]);
                let _ = write!(text, " {reason}");
            }
        }
    }
    limit_summary(&text)
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
    if value.get("complete").and_then(Value::as_bool) == Some(false) {
        text.push_str("; read incomplete");
    }
    append_fields(&mut text, value, &["state_generation"]);
    if preview.is_empty() {
        return Some(text);
    }
    text.push('\n');
    text.push_str(&format_hexdump(base, &preview));
    if bytes_read > preview.len() as u64 {
        let _ = write!(
            text,
            "\nShowing first {} of {bytes_read} bytes; returned data is available in structuredContent.",
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
            | "debugger.continue_exception"
            | "debugger.pause"
            | "debugger.step_into"
            | "debugger.step_over"
            | "debugger.step_out"
            | "debugger.run_to_address"
            | "debugger.wait_for_pause"
            | "debugger.stop"
            | "debuggee.detach"
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
    append_fields(
        &mut text,
        value,
        &["state_generation", "active_thread_id", "interruption"],
    );
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
    if state != "paused" {
        append_fields(&mut text, value, &["completed"]);
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
    fn state_and_snapshot_show_observations_and_bounded_previews() {
        let state = success_summary(
            "debugger.state",
            &json!({"debuggee_state":"absent","diagnostic_code":"NO_DEBUGGEE","instruction_pointer":null,"next_actions":[{"tool":"debuggee.launch"},{"tool":"debuggee.attach"}]}),
        );
        assert!(state.contains("debuggee_state=absent"));
        assert!(state.contains("Next: call debuggee.launch."));
        assert!(!state.contains("Instruction pointer:"));
        let snapshot = success_summary(
            "debugger.snapshot",
            &json!({"debuggee_state":"paused","instruction_pointer":{"address":"0x401000","module":"sample.exe","rva":"0x1000"},"registers":{"eax":"0x1"},"disassembly":vec![json!({"address":"0x401000","size":1,"text":"ret"}); 20]}),
        );
        assert!(snapshot.contains("sample.exe+0x1000"));
        assert!(snapshot.contains("eax=0x1"));
        assert!(snapshot.contains("Disassembly: 20 instructions"));
        assert_eq!(snapshot.matches("text=ret").count(), 3);
    }

    #[test]
    fn search_and_map_use_native_fields_and_do_not_claim_exhaustiveness() {
        let map = success_summary(
            "memory.map",
            &json!({"items":[{"base":"0x400000","size":"0x1000","protect":"0x20"}],"next_cursor":null}),
        );
        assert!(map.contains("0x400000 size=0x1000; protect=0x20;"));
        assert!(!map.contains("unknown address"));
        for name in ["memory.search", "strings.search", "symbols.search"] {
            let text = success_summary(
                name,
                &json!({"items":[],"next_cursor":"secret-opaque-cursor","scan_complete":false,"read_completeness":"partial_unreadable","incomplete":true,"completeness":"known_only","bytes_scanned":4096,"unreadable_bytes":64}),
            );
            assert!(text.contains("0 items in this response; next_page=true"));
            assert!(text.contains("partial_unreadable"));
            assert!(text.contains("known_only"));
            assert!(text.contains("unchanged filters"));
            assert!(!text.contains("secret-opaque-cursor"));
        }
    }

    #[test]
    fn search_previews_keep_long_utf8_text_and_mark_summary_truncation() {
        for (name, field) in [("strings.search", "text"), ("symbols.search", "name")] {
            for value in ["A".repeat(257), format!("{}\u{754c}tail", "A".repeat(255))] {
                let mut item = json!({"location":{"address":"0x1000"},"truncated":false});
                item[field] = json!(value);
                let text = success_summary(name, &json!({"items":[item],"next_cursor":null}));
                assert!(text.contains(&format!("{field}={}", "A".repeat(255))));
                assert!(text.contains("[truncated; see structuredContent]"));
                assert!(text.contains("truncated=false"));
                assert!(!text.contains("tail"));
                assert!(text.len() <= 4096);
            }
        }
        let text = success_summary(
            "strings.search",
            &json!({"items":[{"text":"A".repeat(256),"location":{"address":"0x1000"}}],"next_cursor":null}),
        );
        assert!(text.contains(&format!("text={};", "A".repeat(256))));
        assert!(!text.contains("[truncated"));
    }

    #[test]
    fn search_previews_sanitize_controls_without_dropping_text() {
        let text = success_summary(
            "strings.search",
            &json!({"items":vec![json!({"text":format!("hello\n\t\u{1b}\u{0}{}", "\u{754c}".repeat(1000)),"location":{"address":"0x1000"}}); 20],"next_cursor":"opaque"}),
        );
        assert!(text.contains("text=hello    \u{754c}"));
        assert_eq!(
            text.matches("[truncated; see structuredContent]").count(),
            3
        );
        assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
        assert!(text.len() <= 4096);
        assert!(text.contains("unchanged filters"));
    }

    #[test]
    fn partial_results_and_unreported_postconditions_remain_explicit() {
        let text = success_summary(
            "memory.search",
            &json!({"items":[],"next_cursor":null,"scan_complete":true,"read_completeness":"partial_unreadable","unreadable_bytes":4096}),
        );
        assert!(text.contains("next_page=false"));
        assert!(text.contains("partial_unreadable"));
        assert!(!text.contains("completed"));
        let text = success_summary(
            "debugger.run_to_address",
            &json!({"debuggee_state":"paused","completed":false,"interruption":"exception","instruction_pointer":"0x1000"}),
        );
        assert!(text.contains("Requested target reached: false"));
        assert!(text.contains("interruption=exception"));
        let text = success_summary(
            "scyllahide.profile",
            &json!({"configured_profile":"Default"}),
        );
        assert!(text.contains("restart requirement was not reported"));
    }

    #[test]
    fn summaries_bound_unicode_and_preserve_error_retry_advice() {
        let value = json!({"ok":false,"error":{"code":"TIMEOUT","message":"timeout","recoverable":true,"safeToRetry":false,"details":{"outcome":"unknown"},"suggestedAction":"Inspect state; do not blindly retry."}});
        let text = success_summary("debugger.resume", &value);
        assert!(text.contains("safeToRetry=false"));
        assert!(text.contains("outcome=unknown"));
        assert!(text.contains("do not blindly retry"));
        let huge = "\u{754c}\u{1b}".repeat(10_000);
        for name in ["debugger.state", "debugger.snapshot", "memory.read"] {
            let text = success_summary(
                name,
                &json!({"instruction_pointer":{"address":"0x1000","module":huge,"rva":"0x0"},"address":"0x1000","location":{"address":"0x1000","module":huge,"rva":"0x0"},"bytes_read":1,"data_hex":"41"}),
            );
            assert!(text.len() <= 4096);
            assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
            assert!(text.contains("Summary truncated"));
        }
    }

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
