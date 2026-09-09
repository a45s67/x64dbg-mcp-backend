//! Optional, lossless presentations of a native memory.read payload.

use serde_json::{Value, json};

use crate::{adapter::ToolError, tools};

/// Removes presentation-only options before dispatching to the native reader.
#[must_use]
pub fn native_arguments(arguments: &Value) -> Value {
    let mut native = arguments.clone();
    if let Some(object) = native.as_object_mut() {
        object.remove("format");
        object.remove("byte_order");
    }
    native
}

/// Adds a requested view without altering native fields or native failure payloads.
/// String decoding failures are view data, not failures of the memory read.
///
/// # Errors
/// Returns `INVALID_ARGUMENT` for invalid presentation arguments or `INTERNAL`
/// for a malformed successful native payload. Raw calls are returned unchanged.
pub fn apply(arguments: &Value, mut payload: Value) -> Result<Value, ToolError> {
    if payload.get("ok") == Some(&Value::Bool(false)) || arguments.get("format").is_none() {
        return Ok(payload);
    }
    tools::validate_arguments("memory.read", arguments).map_err(|error| {
        ToolError::new(
            "INVALID_ARGUMENT",
            error.message,
            true,
            true,
            json!({"field":error.field}),
        )
    })?;
    let malformed = || {
        ToolError::new(
            "INTERNAL",
            "Malformed native memory.read payload",
            false,
            true,
            json!({"tool":"memory.read"}),
        )
    };
    let data = payload
        .get("data_hex")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    let length = arguments["length"].as_u64().ok_or_else(malformed)?;
    if data.len() > 131_072
        || data.len() as u64 != length * 2
        || payload.get("bytes_read").and_then(Value::as_u64) != Some(length)
    {
        return Err(malformed());
    }
    let bytes = hex::decode(data).map_err(|_| malformed())?;
    let format = arguments["format"].as_str().ok_or_else(malformed)?;
    let view = match format {
        "bytes" => {
            json!({"format":format,"text":bytes.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" ")})
        }
        "word" | "dword" | "qword" => {
            let width = match format {
                "word" => 2,
                "dword" => 4,
                _ => 8,
            };
            let byte_order = arguments
                .get("byte_order")
                .and_then(Value::as_str)
                .unwrap_or("little");
            let values: Vec<String> = bytes
                .chunks_exact(width)
                .map(|chunk| {
                    let value = if byte_order == "big" {
                        chunk
                            .iter()
                            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
                    } else {
                        chunk
                            .iter()
                            .rev()
                            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
                    };
                    format!("0x{value:0digits$x}", digits = width * 2)
                })
                .collect();
            json!({"format":format,"byte_order":byte_order,"values":values})
        }
        "str" | "wstr" => {
            let width = if format == "str" { 1 } else { 2 };
            let encoding = if format == "str" { "utf-8" } else { "utf-16le" };
            let end = bytes
                .chunks_exact(width)
                .position(|chunk| chunk.iter().all(|byte| *byte == 0))
                .map(|index| index * width);
            let text_bytes = end.unwrap_or(bytes.len());
            let decoded = if format == "str" {
                std::str::from_utf8(&bytes[..text_bytes])
                    .map(str::to_owned)
                    .map_err(|error| error.valid_up_to())
            } else {
                let units = bytes[..text_bytes]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes(*pair));
                let mut text = String::new();
                let mut offset = 0;
                let mut error = None;
                for character in char::decode_utf16(units) {
                    if let Ok(character) = character {
                        offset += character.len_utf16() * 2;
                        text.push(character);
                    } else {
                        error = Some(offset);
                        break;
                    }
                }
                error.map_or(Ok(text), Err)
            };
            match decoded {
                Ok(text) => json!({"format":format,"encoding":encoding,"status":"ok","text":text,
                    "terminated":end.is_some(),"text_bytes":text_bytes,
                    "bytes_consumed":text_bytes + if end.is_some() { width } else { 0 }}),
                Err(offset) => json!({"format":format,"encoding":encoding,"status":"decode_error",
                    "error":{"kind":if format == "str" { "invalid_utf8" } else { "invalid_utf16" },"byte_offset":offset}}),
            }
        }
        _ => return Err(malformed()),
    };
    payload
        .as_object_mut()
        .ok_or_else(malformed)?
        .insert("view".to_owned(), view);
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::{apply, native_arguments};
    use serde_json::{Value, json};

    fn present(data: &str, format: &str, order: Option<&str>) -> Value {
        let mut arguments = json!({"address":"0x1000","length":data.len()/2,"format":format});
        if let Some(order) = order {
            arguments["byte_order"] = json!(order);
        }
        let raw = json!({"data_hex":data,"bytes_read":data.len()/2,"complete":true,"extra":{"kept":true}});
        let mut result = apply(&arguments, raw.clone()).unwrap();
        let view = result.as_object_mut().unwrap().remove("view").unwrap();
        assert_eq!(result, raw);
        view
    }

    #[test]
    fn raw_and_failed_payloads_are_exactly_preserved() {
        for payload in [
            Value::Null,
            json!({"data_hex":"AA","extra":[1,2]}),
            json!({"ok":false,"error":{"code":"READ_FAILED"}}),
        ] {
            assert_eq!(
                apply(&json!({"address":"0x1","length":1}), payload.clone()).unwrap(),
                payload
            );
        }
        let failed = json!({"ok":false,"error":{"code":"READ_FAILED"}});
        assert_eq!(
            apply(&json!({"format":"str"}), failed.clone()).unwrap(),
            failed
        );
        let arguments = json!({"address":{"module":"a.exe","rva":"0x1"},"length":8,"format":"qword","byte_order":"big"});
        assert_eq!(
            native_arguments(&arguments),
            json!({"address":{"module":"a.exe","rva":"0x1"},"length":8})
        );
        assert_eq!(arguments["format"], "qword");
        let raw = json!({"address":"0x1","length":1});
        assert_eq!(native_arguments(&raw), raw);
    }

    #[test]
    fn bytes_and_fixed_width_numbers_are_lossless() {
        assert_eq!(
            present("00aAff", "bytes", None),
            json!({"format":"bytes","text":"00 AA FF"})
        );
        for (format, data, little, big) in [
            (
                "word",
                "01020000",
                vec!["0x0201", "0x0000"],
                vec!["0x0102", "0x0000"],
            ),
            ("dword", "01020304", vec!["0x04030201"], vec!["0x01020304"]),
            (
                "qword",
                "0123456789abcdefffffffffffffffff",
                vec!["0xefcdab8967452301", "0xffffffffffffffff"],
                vec!["0x0123456789abcdef", "0xffffffffffffffff"],
            ),
        ] {
            assert_eq!(
                present(data, format, None),
                json!({"format":format,"byte_order":"little","values":little})
            );
            assert_eq!(
                present(data, format, Some("little"))["values"],
                json!(little)
            );
            assert_eq!(present(data, format, Some("big"))["values"], json!(big));
        }
    }

    #[test]
    fn strict_strings_are_bounded_and_json_safe() {
        for (format, data, text, terminated, text_bytes, consumed) in [
            ("str", "00ff", "", true, 0, 1),
            ("str", "c3a900ff", "\u{e9}", true, 2, 3),
            ("str", "225c0a09", "\"\\\n\t", false, 4, 4),
            ("str", "6100", "a", true, 1, 2),
            ("wstr", "000000d8", "", true, 0, 2),
            ("wstr", "3dd800de000000dc", "\u{1f600}", true, 4, 6),
            ("wstr", "41000001", "A\u{100}", false, 4, 4),
            ("wstr", "41000000", "A", true, 2, 4),
        ] {
            let view = present(data, format, None);
            assert_eq!(
                view,
                json!({"format":format,"encoding":if format == "str" {"utf-8"} else {"utf-16le"},"status":"ok","text":text,"terminated":terminated,"text_bytes":text_bytes,"bytes_consumed":consumed})
            );
            assert_eq!(
                serde_json::from_str::<Value>(&serde_json::to_string(&view).unwrap()).unwrap(),
                view
            );
        }
    }

    #[test]
    fn invalid_text_reports_byte_offsets_without_replacement() {
        for (format, data, offset) in [
            ("str", "61ff", 1),
            ("str", "61e282", 1),
            ("str", "c080", 0),
            ("str", "eda080", 0),
            ("str", "e200", 0),
            ("wstr", "410000dc", 2),
            ("wstr", "410000d8", 2),
            ("wstr", "00d84100", 0),
            ("wstr", "00d80000", 0),
            ("wstr", "3dd800de00dc", 4),
        ] {
            assert_eq!(
                present(data, format, None),
                json!({"format":format,"encoding":if format == "str" {"utf-8"} else {"utf-16le"},"status":"decode_error","error":{"kind":if format == "str" {"invalid_utf8"} else {"invalid_utf16"},"byte_offset":offset}})
            );
        }
    }

    #[test]
    fn maximum_reads_and_malformed_native_payloads() {
        assert_eq!(
            present(&"61".repeat(65_536), "str", None)["text_bytes"],
            65_536
        );
        assert_eq!(
            present(&"6100".repeat(32_768), "wstr", None)["text_bytes"],
            65_536
        );
        assert_eq!(
            present(&"ff".repeat(65_536), "qword", None)["values"]
                .as_array()
                .unwrap()
                .len(),
            8192
        );
        let args = json!({"address":"0x1","length":2,"format":"word"});
        for payload in [
            Value::Null,
            json!({}),
            json!({"data_hex":12,"bytes_read":2}),
            json!({"data_hex":"0000"}),
            json!({"data_hex":"0000","bytes_read":"2"}),
            json!({"data_hex":"0000","bytes_read":1}),
            json!({"data_hex":"00","bytes_read":1}),
            json!({"data_hex":"000","bytes_read":2}),
            json!({"data_hex":"zzzz","bytes_read":2}),
            json!({"data_hex":"000000","bytes_read":3}),
        ] {
            assert_eq!(apply(&args, payload).unwrap_err().code, "INTERNAL");
        }
        for (format, length, order) in [
            ("wstr", 1, None),
            ("word", 3, None),
            ("dword", 2, None),
            ("qword", 4, None),
            ("bytes", 2, Some("little")),
            ("str", 2, Some("big")),
            ("wstr", 2, Some("big")),
            ("word", 2, Some("native")),
            ("unknown", 2, None),
        ] {
            let mut args = json!({"address":"0x1","length":length,"format":format});
            if let Some(order) = order {
                args["byte_order"] = json!(order);
            }
            assert_eq!(
                apply(&args, json!({})).unwrap_err().code,
                "INVALID_ARGUMENT"
            );
        }
    }
}
