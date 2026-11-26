//! `logstash-codec-cef` 6.2.8.
//!
//! A message is `CEF:0|vendor|product|version|signature|name|severity|extensions`.
//! Header pipes and backslashes are escaped. Extension keys are the CEF short
//! name or the full name. ECS `v1` and `v8` use the gem's field paths; `v8`
//! selects the v1 names. Timestamps are epoch milliseconds or an English
//! `MMM dd yyyy HH:mm:ss` value. A timestamp without a zone uses UTC when
//! `default_timezone` is unset. Named zones other than UTC/GMT are refused.
//! Non-English `locale` values are refused. Month names are English.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use chrono::{DateTime, Datelike, FixedOffset, TimeZone, Utc};

use crate::event::Event;
use crate::lscl::{Arg, Plugin};
use crate::run::{Ecs, RunError, fail};
use crate::timefmt::format_timestamp;
use crate::value::{Map, Value};

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

struct Spec {
    name: &'static str,
    key: &'static str,
    ecs: &'static str,
    legacy: &'static str,
    priority: u8,
    timestamp: bool,
}

struct OwnedSpec {
    name: String,
    key: String,
    ecs: String,
    legacy: String,
    priority: u8,
    timestamp: bool,
}

struct Options {
    vendor: String,
    product: String,
    version: String,
    signature: String,
    name: String,
    severity: String,
    fields: Vec<String>,
    reverse: bool,
    delimiter: Option<String>,
    raw_data_field: Option<String>,
    device: String,
    timezone_offset: i32,
    ecs: bool,
}

#[derive(Debug)]
enum ParseError {
    Bad(String),
    Fatal(RunError),
}

pub(crate) fn prepare(codec: &Plugin) -> Result<(), RunError> {
    let _ = options(Some(codec), Ecs::Disabled)?;
    Ok(())
}

pub(crate) fn encode(codec: Option<&Plugin>, event: &Event, ecs: Ecs) -> Result<String, RunError> {
    let options = options(codec, ecs)?;
    let vendor = header_value(event, &options.vendor, "Elasticsearch")?;
    let product = header_value(event, &options.product, "Logstash")?;
    let version = header_value(event, &options.version, "1.0")?;
    let signature = header_value(event, &options.signature, "Logstash")?;
    let name = header_value(event, &options.name, "Logstash")?;
    let severity = severity_value(event, &options.severity)?;
    let header = format!("CEF:0|{vendor}|{product}|{version}|{signature}|{name}|{severity}");
    let (_, encode_map, _) = maps(&options);
    let mut parts = Vec::new();
    for field in &options.fields {
        if let Some(piece) = extension_piece(event, field, &encode_map)? {
            parts.push(piece);
        }
    }
    let mut encoded = format!("{header}|{}", parts.join(" "));
    if let Some(delimiter) = &options.delimiter {
        encoded.push_str(delimiter);
    }
    Ok(encoded)
}

pub(crate) fn decode(
    codec: Option<&Plugin>,
    data: &[u8],
    ecs: Ecs,
) -> Result<Vec<Event>, RunError> {
    let options = options(codec, ecs)?;
    let text = match String::from_utf8(data.to_vec()) {
        Ok(text) => text,
        Err(error) => {
            return Ok(vec![failure_event(&String::from_utf8_lossy(
                error.as_bytes(),
            ))]);
        }
    };
    let pieces = split_pieces(&text, options.delimiter.as_deref());
    let mut events = Vec::new();
    for piece in pieces {
        match parse_line(&options, &piece) {
            Ok(event) => events.push(event),
            Err(ParseError::Bad(payload)) => events.push(failure_event(&payload)),
            Err(ParseError::Fatal(error)) => return Err(error),
        }
    }
    Ok(events)
}

fn options(codec: Option<&Plugin>, pipeline: Ecs) -> Result<Options, RunError> {
    let ecs = match codec
        .and_then(|codec| arg_string(codec, "ecs_compatibility"))
        .as_deref()
    {
        Some("disabled") => false,
        Some("v1" | "v8") => true,
        Some(other) => {
            return Err(fail(format!(
                "Expected one of [\"disabled\", \"v1\", \"v8\"], got \"{other}\""
            )));
        }
        None => pipeline != Ecs::Disabled,
    };
    let device = match codec
        .and_then(|codec| arg_string(codec, "device"))
        .as_deref()
    {
        None | Some("observer") => "observer".to_string(),
        Some("host") => "host".to_string(),
        Some(other) => {
            return Err(fail(format!(
                "Expected one of [\"observer\", \"host\"], got \"{other}\""
            )));
        }
    };
    if let Some(locale) = codec.and_then(|codec| arg_string(codec, "locale"))
        && !english_locale(&locale)
    {
        return Err(fail("cef locale is not implemented"));
    }
    let timezone_offset = match codec.and_then(|codec| arg_string(codec, "default_timezone")) {
        None => 0,
        Some(name) => {
            zone_offset(&name).ok_or_else(|| fail("cef default_timezone is not implemented"))?
        }
    };
    let reverse = match codec
        .and_then(|codec| arg_string(codec, "reverse_mapping"))
        .as_deref()
    {
        None | Some("false") => false,
        Some("true") => true,
        Some(other) => {
            return Err(fail(format!(
                "Expected boolean 'true' or 'false', got \"{other}\""
            )));
        }
    };
    Ok(Options {
        vendor: codec
            .and_then(|codec| arg_string(codec, "vendor"))
            .unwrap_or_else(|| "Elasticsearch".to_string()),
        product: codec
            .and_then(|codec| arg_string(codec, "product"))
            .unwrap_or_else(|| "Logstash".to_string()),
        version: codec
            .and_then(|codec| arg_string(codec, "version"))
            .unwrap_or_else(|| "1.0".to_string()),
        signature: codec
            .and_then(|codec| arg_string(codec, "signature"))
            .unwrap_or_else(|| "Logstash".to_string()),
        name: codec
            .and_then(|codec| arg_string(codec, "name"))
            .unwrap_or_else(|| "Logstash".to_string()),
        severity: codec
            .and_then(|codec| arg_string(codec, "severity"))
            .unwrap_or_else(|| "6".to_string()),
        fields: codec.map(field_list).unwrap_or_default(),
        reverse,
        delimiter: codec
            .and_then(|codec| arg_string(codec, "delimiter"))
            .map(|text| expand_delimiter(&text))
            .filter(|text| !text.is_empty()),
        raw_data_field: codec.and_then(|codec| arg_string(codec, "raw_data_field")),
        device,
        timezone_offset,
        ecs,
    })
}

fn english_locale(locale: &str) -> bool {
    locale == "en" || locale.starts_with("en_") || locale.starts_with("en-")
}

fn field_list(codec: &Plugin) -> Vec<String> {
    match codec
        .args
        .iter()
        .find(|(key, _)| key == "fields")
        .map(|(_, value)| value)
    {
        Some(Arg::Array(items)) => items.iter().filter_map(arg_text).collect(),
        Some(Arg::String(text)) => vec![text.clone()],
        _ => Vec::new(),
    }
}

fn arg_text(arg: &Arg) -> Option<String> {
    match arg {
        Arg::String(text) => Some(text.clone()),
        Arg::Int(number) => Some(number.to_string()),
        _ => None,
    }
}

fn expand_delimiter(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\\' && index + 1 < chars.len() && matches!(chars[index + 1], 'r' | 'n')
        {
            out.push(if chars[index + 1] == 'r' { '\r' } else { '\n' });
            index += 2;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

fn split_pieces(data: &str, delimiter: Option<&str>) -> Vec<String> {
    let Some(delimiter) = delimiter else {
        return vec![data.to_string()];
    };
    let mut parts = Vec::new();
    let mut rest = data;
    while let Some(index) = rest.find(delimiter) {
        parts.push(rest[..index].to_string());
        rest = &rest[index + delimiter.len()..];
    }
    if !rest.is_empty() {
        parts.push(rest.to_string());
    }
    parts
}

fn parse_line(options: &Options, original: &str) -> Result<Event, ParseError> {
    let mut data = original.to_string();
    if data.starts_with('"') {
        data = strip_quotes(&data);
    }
    let payload = data.clone();
    let mut event = Event::new();
    if let Some(field) = &options.raw_data_field {
        event
            .set_field(field, Value::from(original))
            .map_err(|error| ParseError::Fatal(fail(error.to_string())))?;
    }
    let unprocessed = chomp(&data);
    if unprocessed.contains('\n') {
        return Err(ParseError::Bad(payload));
    }
    let headers = header_names(options.ecs);
    let mut rest = unprocessed;
    let mut values = Vec::new();
    for _ in 0..7 {
        let Some((field, next)) = next_header(rest) else {
            return Err(ParseError::Bad(payload));
        };
        values.push(field);
        rest = next;
    }
    if values[0].contains(' ') {
        let (syslog, _, version) = split_last_space(&values[0]);
        event
            .set_field(syslog_name(options.ecs), Value::from(syslog))
            .map_err(|error| ParseError::Fatal(fail(error.to_string())))?;
        values[0] = version;
    }
    if let Some(stripped) = values[0].strip_prefix("CEF:") {
        values[0] = stripped.to_string();
    }
    for (name, value) in headers.iter().zip(values) {
        event
            .set_field(name, Value::from(value))
            .map_err(|error| ParseError::Fatal(fail(error.to_string())))?;
    }
    let (decode_map, _, timestamps) = maps(options);
    let mut extensions = HashMap::new();
    let mut message = rest.trim().to_string();
    while !message.is_empty() {
        let Some(key_len) = key_length(&message) else {
            return Err(ParseError::Bad(payload));
        };
        let mut key = message[..key_len].to_string();
        message = message[key_len + 1..].to_string();
        let value_len = value_length(&message);
        let raw_value = message[..value_len].to_string();
        message = message[value_len..].trim_start().to_string();
        if let Some(mapped) = decode_map.get(&key) {
            key = mapped.clone();
        }
        if key.ends_with(']')
            && let Some(legal) = legal_array_key(&key)
        {
            key = legal;
        }
        extensions.insert(key, desanitize_extension(&raw_value));
    }
    let device_zone = extensions.get("[event][timezone]").cloned();
    if options.ecs {
        for name in &timestamps {
            let Some(raw) = extensions.remove(name) else {
                continue;
            };
            if raw.trim().is_empty() {
                event
                    .set_field(name, Value::Null)
                    .map_err(|error| ParseError::Fatal(fail(error.to_string())))?;
                continue;
            }
            let parsed = normalize_timestamp(&raw, device_zone.as_deref(), options.timezone_offset)
                .map_err(|_| ParseError::Bad(payload.clone()))?;
            event
                .set_field(name, Value::Timestamp(parsed))
                .map_err(|error| ParseError::Fatal(fail(error.to_string())))?;
        }
    }
    for (key, value) in extensions {
        event
            .set_field(&key, Value::from(value))
            .map_err(|error| ParseError::Fatal(fail(error.to_string())))?;
    }
    Ok(event)
}

fn strip_quotes(data: &str) -> String {
    let mut chars = data.chars();
    chars.next();
    let rest: String = chars.collect();
    if rest.is_empty() {
        return String::new();
    }
    let mut chars = rest.chars();
    chars.next_back();
    chars.collect()
}

fn chomp(text: &str) -> &str {
    if let Some(stripped) = text.strip_suffix("\r\n") {
        stripped
    } else if let Some(stripped) = text.strip_suffix('\n').or_else(|| text.strip_suffix('\r')) {
        stripped
    } else {
        text
    }
}

fn split_last_space(text: &str) -> (String, String, String) {
    match text.rfind(' ') {
        Some(index) => (
            text[..index].to_string(),
            " ".to_string(),
            text[index + 1..].to_string(),
        ),
        None => (String::new(), String::new(), text.to_string()),
    }
}

fn next_header(input: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    let mut consumed = 0;
    let mut saw_pipe = false;
    while let Some(ch) = chars.next() {
        consumed += ch.len_utf8();
        if ch == '\\' {
            match chars.next() {
                Some('\\') => {
                    consumed += 1;
                    out.push('\\');
                }
                Some('|') => {
                    consumed += 1;
                    out.push('|');
                }
                Some(other) => {
                    consumed += other.len_utf8();
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else if ch == '|' {
            saw_pipe = true;
            break;
        } else {
            out.push(ch);
        }
    }
    if !saw_pipe {
        return None;
    }
    Some((out, &input[consumed..]))
}

fn key_length(input: &str) -> Option<usize> {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    if chars.is_empty() || !is_word(chars[0].1) {
        return None;
    }
    let mut index = 0;
    while index < chars.len() && is_word(chars[index].1) {
        index += 1;
    }
    while index < chars.len() && chars[index].1 == '.' {
        let start = index;
        index += 1;
        let mut count = 0;
        while index < chars.len() && is_subkey(chars[index].1) {
            index += 1;
            count += 1;
        }
        if count == 0 {
            index = start;
            break;
        }
    }
    if index < chars.len() && chars[index].1 == '[' {
        let start = index;
        index += 1;
        let mut digits = 0;
        while index < chars.len() && chars[index].1.is_ascii_digit() {
            index += 1;
            digits += 1;
        }
        if digits > 0 && index < chars.len() && chars[index].1 == ']' {
            index += 1;
        } else {
            index = start;
        }
    }
    let end = chars
        .get(index)
        .map(|(byte, _)| *byte)
        .unwrap_or(input.len());
    if input[end..].starts_with('=') {
        Some(end)
    } else {
        None
    }
}

fn is_word(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

fn is_subkey(ch: char) -> bool {
    ch != '.'
        && ch != '='
        && !ch.is_whitespace()
        && ch != '|'
        && ch != '\\'
        && ch != '['
        && ch != ']'
}

fn value_length(input: &str) -> usize {
    let mut end = 0;
    let mut index = 0;
    while index < input.len() {
        let ch = input[index..].chars().next().unwrap_or(' ');
        if ch.is_whitespace() {
            let mut next = index;
            while next < input.len() {
                let whitespace = input[next..].chars().next().unwrap_or('a');
                if !whitespace.is_whitespace() {
                    break;
                }
                next += whitespace.len_utf8();
            }
            if key_length(&input[next..]).is_some() {
                break;
            }
            index = next;
            end = index;
        } else {
            index += ch.len_utf8();
            end = index;
        }
    }
    end
}

fn legal_array_key(key: &str) -> Option<String> {
    let bytes = key.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index] != b'[' {
        index += 1;
    }
    if index == 0 || index == bytes.len() {
        return None;
    }
    let base = &key[..index];
    if base.contains('[') || base.contains(']') {
        return None;
    }
    let mut rest = &key[index..];
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let stripped = rest.strip_prefix('[')?;
        let (digits, after) = stripped.split_once(']')?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        rest = after;
    }
    Some(format!("[{base}]{}", &key[index..]))
}

fn desanitize_extension(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\\' && index + 1 < chars.len() {
            match chars[index + 1] {
                '\\' => out.push('\\'),
                '=' => out.push('='),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                other => {
                    out.push('\\');
                    out.push(other);
                    index += 2;
                    continue;
                }
            }
            index += 2;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

fn failure_event(message: &str) -> Event {
    let mut event = Event::new();
    let _ = event.set_field("message", Value::from(message));
    event.tag("_cefparsefailure");
    event
}

fn header_names(ecs: bool) -> [&'static str; 7] {
    if ecs {
        [
            "[cef][version]",
            "[observer][vendor]",
            "[observer][product]",
            "[observer][version]",
            "[event][code]",
            "[cef][name]",
            "[event][severity]",
        ]
    } else {
        [
            "cefVersion",
            "deviceVendor",
            "deviceProduct",
            "deviceVersion",
            "deviceEventClassId",
            "name",
            "severity",
        ]
    }
}

fn syslog_name(ecs: bool) -> &'static str {
    if ecs {
        "[log][syslog][header]"
    } else {
        "syslog"
    }
}

fn header_value(event: &Event, template: &str, default_value: &str) -> Result<String, RunError> {
    let rendered = event
        .sprintf(template)
        .map_err(|error| fail(error.to_string()))?;
    let sanitized = sanitize_header(&rendered);
    if sanitized.is_empty() {
        Ok(default_value.to_string())
    } else {
        Ok(sanitized)
    }
}

fn sanitize_header(value: &str) -> String {
    let collapsed = value.replace("\r\n", "\n");
    let mut out = String::new();
    for ch in collapsed.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\n' | '\r' => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

fn severity_value(event: &Event, template: &str) -> Result<String, RunError> {
    let rendered = event
        .sprintf(template)
        .map_err(|error| fail(error.to_string()))?;
    let sanitized = sanitize_header(&rendered);
    let text = sanitized.trim();
    if valid_severity(text) {
        Ok(ruby_to_i(text).to_string())
    } else {
        Ok("6".to_string())
    }
}

fn valid_severity(text: &str) -> bool {
    let Ok(number) = text.parse::<f64>() else {
        return false;
    };
    number.fract() == 0.0 && (0.0..=10.0).contains(&number)
}

fn ruby_to_i(text: &str) -> i64 {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut sign = 1i64;
    if bytes.first() == Some(&b'+') {
        index = 1;
    } else if bytes.first() == Some(&b'-') {
        sign = -1;
        index = 1;
    }
    let mut number = 0i64;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        number = number
            .saturating_mul(10)
            .saturating_add(i64::from(bytes[index] - b'0'));
        index += 1;
    }
    number * sign
}

fn extension_piece(
    event: &Event,
    field: &str,
    encode_map: &HashMap<String, String>,
) -> Result<Option<String>, RunError> {
    let present = event
        .includes(field)
        .map_err(|error| fail(error.to_string()))?;
    if !present {
        return Ok(None);
    }
    let value = event
        .get_field(field)
        .map_err(|error| fail(error.to_string()))?
        .unwrap_or(Value::Null);
    if matches!(value, Value::Null) {
        return Ok(None);
    }
    let key = encode_map
        .get(field)
        .cloned()
        .unwrap_or_else(|| field.to_string());
    let key = sanitize_extension_key(&key);
    let rendered = match &value {
        Value::Array(_) | Value::Map(_) => json_text(&value)?,
        Value::Timestamp(timestamp) => format_timestamp(*timestamp),
        other => other.to_string(),
    };
    Ok(Some(format!("{key}={}", sanitize_extension(&rendered))))
}

fn sanitize_extension_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn sanitize_extension(value: &str) -> String {
    let collapsed = value.replace("\r\n", "\n");
    let mut out = String::new();
    for ch in collapsed.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' | '\r' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

fn json_text(value: &Value) -> Result<String, RunError> {
    serde_json::to_string(&json_of(value)?).map_err(|error| fail(error.to_string()))
}

fn json_of(value: &Value) -> Result<serde_json::Value, RunError> {
    Ok(match value {
        Value::Null => serde_json::Value::Null,
        Value::String(text) => serde_json::Value::String(text.clone()),
        Value::Integer(number) => {
            if let Ok(small) = i64::try_from(*number) {
                serde_json::Value::Number(small.into())
            } else {
                serde_json::Value::String(number.to_string())
            }
        }
        Value::Float(number) => serde_json::Number::from_f64(*number)
            .map(serde_json::Value::Number)
            .ok_or_else(|| fail("cef float is not a JSON number"))?,
        Value::Boolean(flag) => serde_json::Value::Bool(*flag),
        Value::Timestamp(timestamp) => serde_json::Value::String(format_timestamp(*timestamp)),
        Value::Decimal(decimal) => serde_json::Value::String(decimal.as_str().to_string()),
        Value::Array(items) => {
            let mut array = Vec::new();
            for item in items {
                array.push(json_of(item)?);
            }
            serde_json::Value::Array(array)
        }
        Value::Map(map) => serde_json::Value::Object(json_map(map)?),
    })
}

fn json_map(map: &Map) -> Result<serde_json::Map<String, serde_json::Value>, RunError> {
    let mut object = serde_json::Map::new();
    for (key, value) in map.iter() {
        object.insert(key.to_string(), json_of(value)?);
    }
    Ok(object)
}

fn maps(
    options: &Options,
) -> (
    HashMap<String, String>,
    HashMap<String, String>,
    HashSet<String>,
) {
    let mut specs: Vec<&OwnedSpec> = catalog().iter().collect();
    specs.sort_by_key(|spec| spec.priority);
    let mut decode = HashMap::new();
    let mut encode = HashMap::new();
    let mut timestamps = HashSet::new();
    for spec in specs {
        let ecs_field = if spec.ecs.is_empty() {
            device_ecs(&spec.name, &options.device)
        } else {
            spec.ecs.clone()
        };
        let field_name = if options.ecs {
            ecs_field.clone()
        } else {
            spec.name.clone()
        };
        let target = if options.reverse {
            spec.key.clone()
        } else {
            spec.name.clone()
        };
        decode.insert(spec.key.clone(), field_name.clone());
        decode.insert(spec.name.clone(), field_name.clone());
        encode.insert(field_name.clone(), target.clone());
        if spec.name != field_name {
            encode.insert(spec.name.clone(), target);
        }
        if !spec.legacy.is_empty() {
            let legacy_field = if options.ecs {
                ecs_field
            } else {
                spec.legacy.clone()
            };
            decode.insert(spec.legacy.clone(), legacy_field);
            let legacy_target = if options.reverse {
                spec.key.clone()
            } else {
                spec.legacy.clone()
            };
            encode.insert(spec.legacy.clone(), legacy_target);
        }
        if options.ecs && spec.timestamp {
            timestamps.insert(field_name);
        }
    }
    (decode, encode, timestamps)
}

fn device_ecs(name: &str, device: &str) -> String {
    match name {
        "deviceAddress" => format!("[{device}][ip]"),
        "deviceDnsDomain" => format!("[{device}][registered_domain]"),
        "deviceExternalId" if device == "host" => "[host][id]".to_string(),
        "deviceExternalId" => "[observer][name]".to_string(),
        "deviceHostName" if device == "host" => "[host][name]".to_string(),
        "deviceHostName" => "[observer][hostname]".to_string(),
        "deviceMacAddress" => format!("[{device}][mac]"),
        other => other.to_string(),
    }
}

fn catalog() -> &'static [OwnedSpec] {
    static CATALOG: OnceLock<Vec<OwnedSpec>> = OnceLock::new();
    CATALOG.get_or_init(build_catalog)
}

fn build_catalog() -> Vec<OwnedSpec> {
    let mut specs: Vec<OwnedSpec> = SPECS.iter().map(OwnedSpec::from_spec).collect();
    for index in 1..=15 {
        specs.push(custom(
            format!("deviceCustomFloatingPoint{index}"),
            format!("cfp{index}"),
            format!("[cef][device_custom_floating_point_{index}][value]"),
        ));
        specs.push(custom(
            format!("deviceCustomFloatingPoint{index}Label"),
            format!("cfp{index}Label"),
            format!("[cef][device_custom_floating_point_{index}][label]"),
        ));
        specs.push(custom(
            format!("deviceCustomIPv6Address{index}"),
            format!("c6a{index}"),
            format!("[cef][device_custom_ipv6_address_{index}][value]"),
        ));
        specs.push(custom(
            format!("deviceCustomIPv6Address{index}Label"),
            format!("c6a{index}Label"),
            format!("[cef][device_custom_ipv6_address_{index}][label]"),
        ));
        specs.push(custom(
            format!("deviceCustomNumber{index}"),
            format!("cn{index}"),
            format!("[cef][device_custom_number_{index}][value]"),
        ));
        specs.push(custom(
            format!("deviceCustomNumber{index}Label"),
            format!("cn{index}Label"),
            format!("[cef][device_custom_number_{index}][label]"),
        ));
        specs.push(custom(
            format!("deviceCustomString{index}"),
            format!("cs{index}"),
            format!("[cef][device_custom_string_{index}][value]"),
        ));
        specs.push(custom(
            format!("deviceCustomString{index}Label"),
            format!("cs{index}Label"),
            format!("[cef][device_custom_string_{index}][label]"),
        ));
    }
    specs
}

fn custom(name: String, key: String, ecs: String) -> OwnedSpec {
    OwnedSpec {
        name,
        key,
        ecs,
        legacy: String::new(),
        priority: 0,
        timestamp: false,
    }
}

impl OwnedSpec {
    fn from_spec(spec: &Spec) -> Self {
        Self {
            name: spec.name.to_string(),
            key: if spec.key.is_empty() {
                spec.name.to_string()
            } else {
                spec.key.to_string()
            },
            ecs: spec.ecs.to_string(),
            legacy: spec.legacy.to_string(),
            priority: spec.priority,
            timestamp: spec.timestamp,
        }
    }
}

fn normalize_timestamp(
    value: &str,
    device_zone: Option<&str>,
    default_offset: i32,
) -> Result<DateTime<Utc>, ()> {
    let value = value.trim();
    if let Some(parsed) = millis_timestamp(value) {
        return Ok(parsed);
    }
    parse_cef_datetime(value, device_zone, default_offset)
}

fn millis_timestamp(value: &str) -> Option<DateTime<Utc>> {
    let mut chars = value.chars();
    let first = chars.next()?;
    if !first.is_ascii_digit() || first == '0' {
        return None;
    }
    let mut saw_dot = false;
    for ch in chars {
        if ch == '.' {
            if saw_dot {
                return None;
            }
            saw_dot = true;
            continue;
        }
        if !ch.is_ascii_digit() {
            return None;
        }
    }
    if value.ends_with('.') {
        return None;
    }
    let millis: f64 = value.parse().ok()?;
    let seconds = millis / 1000.0;
    let whole = seconds.trunc() as i64;
    let nanos = ((seconds - whole as f64) * 1_000_000_000.0).round() as u32;
    DateTime::from_timestamp(whole, nanos.min(999_999_999))
}

fn parse_cef_datetime(
    value: &str,
    device_zone: Option<&str>,
    default_offset: i32,
) -> Result<DateTime<Utc>, ()> {
    let mut rest = value;
    let month = month_index(take_token(&mut rest)?)?;
    rest = rest.strip_prefix(' ').ok_or(())?;
    let (day, next) = take_number(rest, 2)?;
    rest = next;
    let mut year = None;
    if let Some(stripped) = rest.strip_prefix(' ')
        && stripped
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit())
    {
        let (parsed, next) = take_number(stripped, 4)?;
        if parsed >= 1000 {
            year = Some(i32::try_from(parsed).map_err(|_| ())?);
            rest = next;
        }
    }
    rest = rest.strip_prefix(' ').ok_or(())?;
    let (hour, next) = take_number(rest, 2)?;
    rest = next.strip_prefix(':').ok_or(())?;
    let (minute, next) = take_number(rest, 2)?;
    rest = next.strip_prefix(':').ok_or(())?;
    let (second, next) = take_number(rest, 2)?;
    rest = next;
    let mut nanos = 0u32;
    if let Some(stripped) = rest.strip_prefix('.') {
        let digits: String = stripped
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect();
        if !matches!(digits.len(), 3 | 6 | 9) {
            return Err(());
        }
        let scale = 10u32.pow(9 - u32::try_from(digits.len()).map_err(|_| ())?);
        nanos = digits.parse::<u32>().map_err(|_| ())? * scale;
        rest = &stripped[digits.len()..];
    }
    let offset = if let Some(stripped) = rest.strip_prefix(' ') {
        if !stripped.is_empty() && stripped.contains(' ') {
            return Err(());
        }
        zone_offset(stripped).ok_or(())?
    } else if rest.is_empty() {
        match device_zone {
            Some(zone) => zone_offset(zone).ok_or(())?,
            None => default_offset,
        }
    } else {
        return Err(());
    };
    let offset = FixedOffset::east_opt(offset).ok_or(())?;
    let year = match year {
        Some(year) => year,
        None => resolve_year(month, day, hour, minute, second, nanos, offset)?,
    };
    let local = offset
        .with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .ok_or(())?;
    Ok(local.with_timezone(&Utc) + chrono::Duration::nanoseconds(i64::from(nanos)))
}

fn resolve_year(
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanos: u32,
    offset: FixedOffset,
) -> Result<i32, ()> {
    let now = utc_now().with_timezone(&offset);
    let year = now.year();
    let clock = Clock {
        hour,
        minute,
        second,
        nanos,
    };
    let current = zoned(year, month, day, clock, offset)?;
    let two_days = chrono::Duration::days(2);
    if current > now + two_days {
        return Ok(year - 1);
    }
    if now.month() == 12 {
        let next = zoned(year + 1, month, day, clock, offset)?;
        if next <= now + two_days {
            return Ok(year + 1);
        }
    }
    Ok(year)
}

#[derive(Clone, Copy)]
struct Clock {
    hour: u32,
    minute: u32,
    second: u32,
    nanos: u32,
}

fn zoned(
    year: i32,
    month: u32,
    day: u32,
    clock: Clock,
    offset: FixedOffset,
) -> Result<DateTime<FixedOffset>, ()> {
    let local = offset
        .with_ymd_and_hms(year, month, day, clock.hour, clock.minute, clock.second)
        .single()
        .ok_or(())?;
    Ok(local + chrono::Duration::nanoseconds(i64::from(clock.nanos)))
}

fn utc_now() -> DateTime<Utc> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    DateTime::from_timestamp(seconds, 0).unwrap_or(DateTime::UNIX_EPOCH)
}

fn take_token<'a>(rest: &mut &'a str) -> Result<&'a str, ()> {
    let end = rest
        .find(|ch: char| ch.is_whitespace())
        .unwrap_or(rest.len());
    if end == 0 {
        return Err(());
    }
    let token = &rest[..end];
    *rest = &rest[end..];
    Ok(token)
}

fn month_index(token: &str) -> Result<u32, ()> {
    MONTHS
        .iter()
        .position(|month| month.eq_ignore_ascii_case(token))
        .map(|index| u32::try_from(index + 1).unwrap_or(1))
        .ok_or(())
}

fn take_number(text: &str, max_digits: usize) -> Result<(u32, &str), ()> {
    let digits: String = text
        .chars()
        .take(max_digits)
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return Err(());
    }
    let number = digits.parse().map_err(|_| ())?;
    Ok((number, &text[digits.len()..]))
}

fn zone_offset(text: &str) -> Option<i32> {
    let text = text.trim();
    if matches!(text, "Z" | "UTC" | "GMT" | "UT" | "Etc/UTC") {
        return Some(0);
    }
    let (sign, rest) = if let Some(rest) = text.strip_prefix('+') {
        (1, rest)
    } else {
        let rest = text.strip_prefix('-')?;
        (-1, rest)
    };
    let rest = rest.replace(':', "");
    if !rest.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (hours, minutes) = if rest.len() == 2 {
        (rest.parse::<i32>().ok()?, 0)
    } else if rest.len() == 4 {
        (rest[..2].parse().ok()?, rest[2..].parse().ok()?)
    } else {
        return None;
    };
    if hours > 18 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

fn arg_string(plugin: &Plugin, name: &str) -> Option<String> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .and_then(|(_, value)| match value {
            Arg::String(text) => Some(text.clone()),
            Arg::Int(number) => Some(number.to_string()),
            _ => None,
        })
}

const SPECS: &[Spec] = &[
    spec("agentAddress", "agt", "[agent][ip]", "", 0, false),
    spec(
        "agentDnsDomain",
        "",
        "[cef][agent][registered_domain]",
        "",
        10,
        false,
    ),
    spec("agentHostName", "ahost", "[agent][name]", "", 0, false),
    spec("agentId", "aid", "[agent][id]", "", 0, false),
    spec("agentMacAddress", "amac", "[agent][mac]", "", 0, false),
    spec(
        "agentNtDomain",
        "",
        "[cef][agent][registered_domain]",
        "",
        0,
        false,
    ),
    spec("agentReceiptTime", "art", "[event][created]", "", 0, true),
    spec(
        "agentTimeZone",
        "atz",
        "[cef][agent][timezone]",
        "",
        0,
        false,
    ),
    spec(
        "agentTranslatedAddress",
        "",
        "[cef][agent][nat][ip]",
        "",
        0,
        false,
    ),
    spec(
        "agentTranslatedZoneExternalID",
        "",
        "[cef][agent][translated_zone][external_id]",
        "",
        0,
        false,
    ),
    spec(
        "agentTranslatedZoneURI",
        "",
        "[cef][agent][translated_zone][uri]",
        "",
        0,
        false,
    ),
    spec("agentType", "at", "[agent][type]", "", 0, false),
    spec("agentVersion", "av", "[agent][version]", "", 0, false),
    spec(
        "agentZoneExternalID",
        "",
        "[cef][agent][zone][external_id]",
        "",
        0,
        false,
    ),
    spec("agentZoneURI", "", "[cef][agent][zone][uri]", "", 0, false),
    spec(
        "applicationProtocol",
        "app",
        "[network][protocol]",
        "",
        0,
        false,
    ),
    spec(
        "baseEventCount",
        "cnt",
        "[cef][base_event_count]",
        "",
        0,
        false,
    ),
    spec("bytesIn", "in", "[source][bytes]", "", 0, false),
    spec("bytesOut", "out", "[destination][bytes]", "", 0, false),
    spec(
        "categoryDeviceType",
        "catdt",
        "[cef][device_type]",
        "",
        0,
        false,
    ),
    spec("customerExternalID", "", "[organization][id]", "", 0, false),
    spec("customerURI", "", "[organization][name]", "", 0, false),
    spec(
        "destinationAddress",
        "dst",
        "[destination][ip]",
        "",
        0,
        false,
    ),
    spec(
        "destinationDnsDomain",
        "",
        "[destination][registered_domain]",
        "",
        10,
        false,
    ),
    spec(
        "destinationGeoLatitude",
        "dlat",
        "[destination][geo][location][lat]",
        "destinationLatitude",
        0,
        false,
    ),
    spec(
        "destinationGeoLongitude",
        "dlong",
        "[destination][geo][location][lon]",
        "destinationLongitude",
        0,
        false,
    ),
    spec(
        "destinationHostName",
        "dhost",
        "[destination][domain]",
        "",
        0,
        false,
    ),
    spec(
        "destinationMacAddress",
        "dmac",
        "[destination][mac]",
        "",
        0,
        false,
    ),
    spec(
        "destinationNtDomain",
        "dntdom",
        "[destination][registered_domain]",
        "",
        0,
        false,
    ),
    spec(
        "destinationPort",
        "dpt",
        "[destination][port]",
        "",
        0,
        false,
    ),
    spec(
        "destinationProcessId",
        "dpid",
        "[destination][process][pid]",
        "",
        0,
        false,
    ),
    spec(
        "destinationProcessName",
        "dproc",
        "[destination][process][name]",
        "",
        0,
        false,
    ),
    spec(
        "destinationServiceName",
        "",
        "[destination][service][name]",
        "",
        0,
        false,
    ),
    spec(
        "destinationTranslatedAddress",
        "",
        "[destination][nat][ip]",
        "",
        0,
        false,
    ),
    spec(
        "destinationTranslatedPort",
        "",
        "[destination][nat][port]",
        "",
        0,
        false,
    ),
    spec(
        "destinationTranslatedZoneExternalID",
        "",
        "[cef][destination][translated_zone][external_id]",
        "",
        0,
        false,
    ),
    spec(
        "destinationTranslatedZoneURI",
        "",
        "[cef][destination][translated_zone][uri]",
        "",
        0,
        false,
    ),
    spec(
        "destinationUserId",
        "duid",
        "[destination][user][id]",
        "",
        0,
        false,
    ),
    spec(
        "destinationUserName",
        "duser",
        "[destination][user][name]",
        "",
        0,
        false,
    ),
    spec(
        "destinationUserPrivileges",
        "dpriv",
        "[destination][user][group][name]",
        "",
        0,
        false,
    ),
    spec(
        "destinationZoneExternalID",
        "",
        "[cef][destination][zone][external_id]",
        "",
        0,
        false,
    ),
    spec(
        "destinationZoneURI",
        "",
        "[cef][destination][zone][uri]",
        "",
        0,
        false,
    ),
    spec("deviceAction", "act", "[event][action]", "", 0, false),
    spec("deviceAddress", "dvc", "", "", 0, false),
    spec("deviceDnsDomain", "", "", "", 10, false),
    spec("deviceDirection", "", "[network][direction]", "", 0, false),
    spec(
        "deviceEventCategory",
        "cat",
        "[cef][category]",
        "",
        0,
        false,
    ),
    spec("deviceExternalId", "", "", "", 0, false),
    spec(
        "deviceFacility",
        "",
        "[log][syslog][facility][code]",
        "",
        0,
        false,
    ),
    spec("deviceHostName", "dvchost", "", "", 0, false),
    spec(
        "deviceInboundInterface",
        "",
        "[observer][ingress][interface][name]",
        "",
        0,
        false,
    ),
    spec("deviceMacAddress", "dvcmac", "", "", 0, false),
    spec("deviceNtDomain", "", "[cef][nt_domain]", "", 0, false),
    spec(
        "deviceOutboundInterface",
        "",
        "[observer][egress][interface][name]",
        "",
        0,
        false,
    ),
    spec("devicePayloadId", "", "[cef][payload_id]", "", 0, false),
    spec("deviceProcessId", "dvcpid", "[process][pid]", "", 0, false),
    spec("deviceProcessName", "", "[process][name]", "", 0, false),
    spec("deviceReceiptTime", "rt", "@timestamp", "", 0, true),
    spec(
        "deviceTimeZone",
        "dtz",
        "[event][timezone]",
        "destinationTimeZone",
        0,
        false,
    ),
    spec(
        "deviceTranslatedAddress",
        "",
        "[host][nat][ip]",
        "",
        0,
        false,
    ),
    spec(
        "deviceTranslatedZoneExternalID",
        "",
        "[cef][translated_zone][external_id]",
        "",
        0,
        false,
    ),
    spec(
        "deviceTranslatedZoneURI",
        "",
        "[cef][translated_zone][uri]",
        "",
        0,
        false,
    ),
    spec("deviceVersion", "", "[observer][version]", "", 0, false),
    spec(
        "deviceZoneExternalID",
        "",
        "[cef][zone][external_id]",
        "",
        0,
        false,
    ),
    spec("deviceZoneURI", "", "[cef][zone][uri]", "", 0, false),
    spec("endTime", "end", "[event][end]", "", 0, true),
    spec("eventId", "", "[event][id]", "", 0, false),
    spec("eventOutcome", "outcome", "[event][outcome]", "", 0, false),
    spec("externalId", "", "[cef][external_id]", "", 0, false),
    spec("fileCreateTime", "", "[file][created]", "", 0, false),
    spec("fileHash", "", "[file][hash]", "", 0, false),
    spec("fileId", "", "[file][inode]", "", 0, false),
    spec("fileModificationTime", "", "[file][mtime]", "", 0, true),
    spec("fileName", "fname", "[file][name]", "", 0, false),
    spec("filePath", "", "[file][path]", "", 0, false),
    spec("filePermission", "", "[file][group]", "", 0, false),
    spec("fileSize", "fsize", "[file][size]", "", 0, false),
    spec("fileType", "", "[file][extension]", "", 0, false),
    spec(
        "managerReceiptTime",
        "mrt",
        "[event][ingested]",
        "",
        0,
        true,
    ),
    spec("message", "msg", "[message]", "", 0, false),
    spec(
        "oldFileCreateTime",
        "",
        "[cef][old_file][created]",
        "",
        0,
        true,
    ),
    spec("oldFileHash", "", "[cef][old_file][hash]", "", 0, false),
    spec("oldFileId", "", "[cef][old_file][inode]", "", 0, false),
    spec(
        "oldFileModificationTime",
        "",
        "[cef][old_file][mtime]",
        "",
        0,
        true,
    ),
    spec("oldFileName", "", "[cef][old_file][name]", "", 0, false),
    spec("oldFilePath", "", "[cef][old_file][path]", "", 0, false),
    spec(
        "oldFilePermission",
        "",
        "[cef][old_file][group]",
        "",
        0,
        false,
    ),
    spec("oldFileSize", "", "[cef][old_file][size]", "", 0, false),
    spec(
        "oldFileType",
        "",
        "[cef][old_file][extension]",
        "",
        0,
        false,
    ),
    spec("rawEvent", "", "[event][original]", "", 0, false),
    spec("Reason", "reason", "[event][reason]", "", 0, false),
    spec(
        "requestClientApplication",
        "",
        "[user_agent][original]",
        "",
        0,
        false,
    ),
    spec(
        "requestContext",
        "",
        "[http][request][referrer]",
        "",
        0,
        false,
    ),
    spec(
        "requestCookies",
        "",
        "[cef][request][cookies]",
        "",
        0,
        false,
    ),
    spec("requestMethod", "", "[http][request][method]", "", 0, false),
    spec("requestUrl", "request", "[url][original]", "", 0, false),
    spec("sourceAddress", "src", "[source][ip]", "", 0, false),
    spec(
        "sourceDnsDomain",
        "",
        "[source][registered_domain]",
        "",
        10,
        false,
    ),
    spec(
        "sourceGeoLatitude",
        "slat",
        "[source][geo][location][lat]",
        "sourceLatitude",
        0,
        false,
    ),
    spec(
        "sourceGeoLongitude",
        "slong",
        "[source][geo][location][lon]",
        "sourceLongitude",
        0,
        false,
    ),
    spec("sourceHostName", "shost", "[source][domain]", "", 0, false),
    spec("sourceMacAddress", "smac", "[source][mac]", "", 0, false),
    spec(
        "sourceNtDomain",
        "sntdom",
        "[source][registered_domain]",
        "",
        0,
        false,
    ),
    spec("sourcePort", "spt", "[source][port]", "", 0, false),
    spec(
        "sourceProcessId",
        "spid",
        "[source][process][pid]",
        "",
        0,
        false,
    ),
    spec(
        "sourceProcessName",
        "sproc",
        "[source][process][name]",
        "",
        0,
        false,
    ),
    spec(
        "sourceServiceName",
        "",
        "[source][service][name]",
        "",
        0,
        false,
    ),
    spec(
        "sourceTranslatedAddress",
        "",
        "[source][nat][ip]",
        "",
        0,
        false,
    ),
    spec(
        "sourceTranslatedPort",
        "",
        "[source][nat][port]",
        "",
        0,
        false,
    ),
    spec(
        "sourceTranslatedZoneExternalID",
        "",
        "[cef][source][translated_zone][external_id]",
        "",
        0,
        false,
    ),
    spec(
        "sourceTranslatedZoneURI",
        "",
        "[cef][source][translated_zone][uri]",
        "",
        0,
        false,
    ),
    spec("sourceUserId", "suid", "[source][user][id]", "", 0, false),
    spec(
        "sourceUserName",
        "suser",
        "[source][user][name]",
        "",
        0,
        false,
    ),
    spec(
        "sourceUserPrivileges",
        "spriv",
        "[source][user][group][name]",
        "",
        0,
        false,
    ),
    spec(
        "sourceZoneExternalID",
        "",
        "[cef][source][zone][external_id]",
        "",
        0,
        false,
    ),
    spec(
        "sourceZoneURI",
        "",
        "[cef][source][zone][uri]",
        "",
        0,
        false,
    ),
    spec("startTime", "start", "[event][start]", "", 0, true),
    spec(
        "transportProtocol",
        "proto",
        "[network][transport]",
        "",
        0,
        false,
    ),
    spec("type", "", "[cef][type]", "", 0, false),
];

const fn spec(
    name: &'static str,
    key: &'static str,
    ecs: &'static str,
    legacy: &'static str,
    priority: u8,
    timestamp: bool,
) -> Spec {
    Spec {
        name,
        key,
        ecs,
        legacy,
        priority,
        timestamp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str, ecs: Ecs) -> Event {
        let options = options(None, ecs).expect("options");
        parse_line(&options, text).expect("parse")
    }

    fn field(event: &Event, name: &str) -> Option<Value> {
        event.get_field(name).expect("field")
    }

    #[test]
    fn headers_short_names_and_escapes() {
        let event = line(
            r"CEF:0|Foo\|Bar|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 msg=a\=b",
            Ecs::Disabled,
        );
        assert_eq!(field(&event, "cefVersion"), Some(Value::from("0")));
        assert_eq!(field(&event, "deviceVendor"), Some(Value::from("Foo|Bar")));
        assert_eq!(
            field(&event, "name"),
            Some(Value::from("worm successfully stopped"))
        );
        assert_eq!(field(&event, "severity"), Some(Value::from("10")));
        assert_eq!(
            field(&event, "sourceAddress"),
            Some(Value::from("10.0.0.1"))
        );
        assert_eq!(
            field(&event, "destinationAddress"),
            Some(Value::from("2.1.2.2"))
        );
        assert_eq!(field(&event, "sourcePort"), Some(Value::from("1232")));
        assert_eq!(field(&event, "message"), Some(Value::from("a=b")));
    }

    #[test]
    fn ecs_paths_syslog_and_millis_timestamp() {
        let event = line(
            "Sep 01 00:00:00 CEF:0|Security|threatmanager|1.0|100|worm|5|src=10.0.0.1 rt=1600000000000",
            Ecs::V1,
        );
        assert_eq!(
            field(&event, "[log][syslog][header]"),
            Some(Value::from("Sep 01 00:00:00"))
        );
        assert_eq!(field(&event, "[cef][version]"), Some(Value::from("0")));
        assert_eq!(
            field(&event, "[observer][vendor]"),
            Some(Value::from("Security"))
        );
        assert_eq!(field(&event, "[event][code]"), Some(Value::from("100")));
        assert_eq!(field(&event, "[source][ip]"), Some(Value::from("10.0.0.1")));
        assert_eq!(
            field(&event, "@timestamp"),
            Some(Value::Timestamp(
                DateTime::from_timestamp(1_600_000_000, 0).expect("time")
            ))
        );
    }

    #[test]
    fn a_broken_header_is_a_failure_event() {
        let options = options(None, Ecs::Disabled).expect("options");
        let error = parse_line(&options, "not-cef").expect_err("bad");
        let ParseError::Bad(payload) = error else {
            panic!("config error");
        };
        let event = failure_event(&payload);
        assert_eq!(field(&event, "message"), Some(Value::from("not-cef")));
        assert_eq!(
            field(&event, "tags"),
            Some(Value::Array(vec![Value::from("_cefparsefailure")]))
        );
    }
}
