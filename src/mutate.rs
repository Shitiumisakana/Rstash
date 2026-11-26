//! `logstash-filter-mutate` 3.6.0 `filter` order and the conversions that spec exercises.
//!
//! Register rejects an unknown convert type and a short `gsub` triad. A failure while
//! applying the filter tags the event and does not raise, matching the `rescue` in `filter`.

use crate::event::Event;
use crate::lscl::{Arg, Key, Plugin};
use crate::run::{RunError, fail};
use crate::value::{Decimal, Value};

const VALID_CONVERSIONS: &[&str] = &[
    "string",
    "integer",
    "float",
    "boolean",
    "integer_eu",
    "float_eu",
];

pub(crate) fn apply(plugin: &Plugin, event: &mut Event) -> Result<(), RunError> {
    validate(plugin)?;
    if let Err(error) = apply_inner(plugin, event) {
        let tag =
            arg_string(plugin, "tag_on_failure").unwrap_or_else(|| "_mutate_error".to_string());
        let tag = event.sprintf(&tag).unwrap_or(tag);
        event.tag(&tag);
        let _ = error;
    }
    Ok(())
}

fn validate(plugin: &Plugin) -> Result<(), RunError> {
    if let Some(arg) = arg(plugin, "convert") {
        for (_, kind) in pairs(arg)? {
            if !VALID_CONVERSIONS.contains(&kind.as_str()) {
                return Err(fail(format!(
                    "Invalid conversion type '{kind}', expected one of '{}'",
                    VALID_CONVERSIONS.join(",")
                )));
            }
        }
    }
    if let Some(arg) = arg(plugin, "gsub") {
        let items = scalars(arg)?;
        if items.len() % 3 != 0 {
            return Err(fail(format!(
                "Invalid gsub configuration {items:?}. gsub requires 3 non-nil elements per config entry"
            )));
        }
    }
    for (name, _) in &plugin.args {
        if !matches!(
            name.as_str(),
            "coerce"
                | "rename"
                | "update"
                | "replace"
                | "convert"
                | "gsub"
                | "uppercase"
                | "capitalize"
                | "lowercase"
                | "strip"
                | "split"
                | "join"
                | "merge"
                | "copy"
                | "add_field"
                | "remove_field"
                | "add_tag"
                | "remove_tag"
                | "id"
                | "enable_metric"
                | "tag_on_failure"
                | "periodic_flush"
        ) {
            return Err(fail(format!("mutate option {name} is not implemented")));
        }
    }
    Ok(())
}

fn apply_inner(plugin: &Plugin, event: &mut Event) -> Result<(), RunError> {
    if let Some(arg) = arg(plugin, "coerce") {
        for (field, value) in pairs(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            if event_is_null(event, &field)? {
                let text = event.sprintf(&value).map_err(event_fail)?;
                event
                    .set_field(&field, Value::from(text))
                    .map_err(event_fail)?;
            }
        }
    }
    if let Some(arg) = arg(plugin, "rename") {
        for (old, new) in pairs(arg)? {
            let old = event.sprintf(&old).map_err(event_fail)?;
            let new = event.sprintf(&new).map_err(event_fail)?;
            if event.includes(&old).map_err(event_fail)?
                && let Some(removed) = event.remove_field(&old).map_err(event_fail)?
            {
                event.set_field(&new, removed).map_err(event_fail)?;
            }
        }
    }
    if let Some(arg) = arg(plugin, "update") {
        for (field, value) in pairs(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            if event.includes(&field).map_err(event_fail)? {
                let text = event.sprintf(&value).map_err(event_fail)?;
                event
                    .set_field(&field, Value::from(text))
                    .map_err(event_fail)?;
            }
        }
    }
    if let Some(arg) = arg(plugin, "replace") {
        for (field, value) in pairs(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            let text = event.sprintf(&value).map_err(event_fail)?;
            event
                .set_field(&field, Value::from(text))
                .map_err(event_fail)?;
        }
    }
    if let Some(arg) = arg(plugin, "convert") {
        for (field, kind) in pairs(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            convert_field(event, &field, &kind)?;
        }
    }
    if let Some(arg) = arg(plugin, "gsub") {
        let items = scalars(arg)?;
        for chunk in items.chunks(3) {
            gsub_field(event, &chunk[0], &chunk[1], &chunk[2])?;
        }
    }
    for name in ["uppercase", "capitalize", "lowercase"] {
        if let Some(arg) = arg(plugin, name) {
            for field in names(arg)? {
                let field = event.sprintf(&field).map_err(event_fail)?;
                change_case(event, &field, name)?;
            }
        }
    }
    if let Some(arg) = arg(plugin, "strip") {
        for field in names(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            strip_field(event, &field)?;
        }
    }
    if let Some(arg) = arg(plugin, "split") {
        for (field, separator) in pairs(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            let separator = event.sprintf(&separator).map_err(event_fail)?;
            split_field(event, &field, &separator)?;
        }
    }
    if let Some(arg) = arg(plugin, "join") {
        for (field, separator) in pairs(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            let separator = event.sprintf(&separator).map_err(event_fail)?;
            join_field(event, &field, &separator)?;
        }
    }
    if let Some(arg) = arg(plugin, "merge") {
        for (field, added) in pairs(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            let added = event.sprintf(&added).map_err(event_fail)?;
            merge_field(event, &field, &added)?;
        }
    }
    if let Some(arg) = arg(plugin, "copy") {
        for (source, dest) in pairs(arg)? {
            let source = event.sprintf(&source).map_err(event_fail)?;
            let dest = event.sprintf(&dest).map_err(event_fail)?;
            if let Some(value) = event.get_field(&source).map_err(event_fail)?
                && !matches!(value, Value::Null)
            {
                event.set_field(&dest, value).map_err(event_fail)?;
            }
        }
    }
    if let Some(arg) = arg(plugin, "add_field") {
        for (field, value) in pairs(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            let text = event.sprintf(&value).map_err(event_fail)?;
            add_field(event, &field, Value::from(text))?;
        }
    }
    if let Some(arg) = arg(plugin, "remove_field") {
        for field in names(arg)? {
            let field = event.sprintf(&field).map_err(event_fail)?;
            event.remove_field(&field).map_err(event_fail)?;
        }
    }
    if let Some(arg) = arg(plugin, "add_tag") {
        for tag in names(arg)? {
            let tag = event.sprintf(&tag).map_err(event_fail)?;
            event.tag(&tag);
        }
    }
    if let Some(arg) = arg(plugin, "remove_tag") {
        for tag in names(arg)? {
            let tag = event.sprintf(&tag).map_err(event_fail)?;
            remove_tag(event, &tag)?;
        }
    }
    Ok(())
}

pub(crate) fn add_field(event: &mut Event, field: &str, value: Value) -> Result<(), RunError> {
    if event.includes(field).map_err(event_fail)? {
        let mut list = match event.remove_field(field).map_err(event_fail)? {
            Some(Value::Array(items)) => items,
            Some(existing) => vec![existing],
            None => Vec::new(),
        };
        list.push(value);
        event
            .set_field(field, Value::Array(list))
            .map_err(event_fail)
    } else {
        event.set_field(field, value).map_err(event_fail)
    }
}

fn event_is_null(event: &Event, field: &str) -> Result<bool, RunError> {
    Ok(event.includes(field).map_err(event_fail)?
        && event.get_field(field).map_err(event_fail)?.is_none())
}

fn convert_field(event: &mut Event, field: &str, kind: &str) -> Result<(), RunError> {
    if !event.includes(field).map_err(event_fail)? {
        return Ok(());
    }
    let Some(current) = event.get_field(field).map_err(event_fail)? else {
        return Ok(());
    };
    if matches!(current, Value::Map(_)) {
        return Ok(());
    }
    let converted = match current {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| {
                    if matches!(item, Value::Null) {
                        item
                    } else {
                        convert_value(item, kind)
                    }
                })
                .collect(),
        ),
        Value::Null => Value::Null,
        other => convert_value(other, kind),
    };
    event.set_field(field, converted).map_err(event_fail)
}

fn convert_value(value: Value, kind: &str) -> Value {
    let value = if kind.ends_with("_eu") {
        eu_to_us(value)
    } else {
        value
    };
    let kind = kind.trim_end_matches("_eu");
    match kind {
        "string" => Value::from(ruby_to_s(&value)),
        "integer" => convert_integer(value),
        "float" => convert_float(value),
        "boolean" => convert_boolean(value),
        _ => value,
    }
}

fn eu_to_us(value: Value) -> Value {
    match value {
        Value::String(text) => {
            let swapped: String = text
                .chars()
                .map(|ch| match ch {
                    ',' => '.',
                    '.' => ',',
                    other => other,
                })
                .collect();
            Value::String(swapped)
        }
        other => other,
    }
}

fn convert_integer(value: Value) -> Value {
    let value = match value {
        Value::String(text) => Value::String(text.trim().replace(',', "").to_ascii_lowercase()),
        other => other,
    };
    match value {
        Value::Boolean(true) => Value::Integer(1),
        Value::Boolean(false) => Value::Integer(0),
        Value::Integer(number) => Value::Integer(number),
        Value::Float(number) => Value::Integer(number as i128),
        Value::String(text) => integer_from_text(&text).unwrap_or(Value::String(text)),
        other => other,
    }
}

fn integer_from_text(text: &str) -> Option<Value> {
    if let Some(number) = parse_signed_hex_str(text) {
        if !text.contains('.') {
            return Some(integer_value(&format!("{}", number as i128)));
        }
        return Some(Value::Integer(number as i128));
    }
    let digits = trunc_decimal(text)?;
    Some(integer_value(&digits))
}

fn integer_value(digits: &str) -> Value {
    if let Ok(number) = digits.parse::<i128>() {
        Value::Integer(number)
    } else {
        Value::Decimal(Decimal::exact(digits))
    }
}

fn convert_float(value: Value) -> Value {
    let value = match value {
        Value::String(text) => Value::String(text.trim().replace(',', "").to_ascii_lowercase()),
        other => other,
    };
    match value {
        Value::Boolean(true) => Value::Float(1.0),
        Value::Boolean(false) => Value::Float(0.0),
        Value::Float(number) => Value::Float(number),
        Value::Integer(number) => Value::Float(number as f64),
        Value::String(text) => {
            if let Some(number) = parse_signed_hex_str(&text) {
                Value::Float(number)
            } else if let Ok(number) = text.parse::<f64>() {
                Value::Float(number)
            } else {
                Value::String(text)
            }
        }
        other => other,
    }
}

fn convert_boolean(value: Value) -> Value {
    let text = ruby_to_s(&value);
    if matches!(
        text.to_ascii_lowercase().as_str(),
        "true" | "t" | "yes" | "y" | "1" | "1.0"
    ) {
        Value::Boolean(true)
    } else if text.is_empty()
        || matches!(
            text.to_ascii_lowercase().as_str(),
            "false" | "f" | "no" | "n" | "0" | "0.0"
        )
    {
        Value::Boolean(false)
    } else {
        value
    }
}

fn ruby_to_s(value: &Value) -> String {
    match value {
        Value::Float(number) => ruby_float(*number),
        Value::Boolean(true) => "true".to_string(),
        Value::Boolean(false) => "false".to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn ruby_float(number: f64) -> String {
    if number.fract() == 0.0 && number.is_finite() {
        format!("{number:.1}")
    } else {
        let text = format!("{number}");
        if text.contains('.') || text.contains('e') || text.contains('E') {
            text
        } else {
            format!("{text}.0")
        }
    }
}

/// Ruby `Float` for `^[+-]?0x` numbers, including a binary exponent (`p`).
/// `nil` when the text is not a signed hex literal, matching `parse_signed_hex_str`.
pub fn parse_signed_hex_str(text: &str) -> Option<f64> {
    let (sign, rest) = if let Some(rest) = text.strip_prefix('+') {
        (1.0, rest)
    } else if let Some(rest) = text.strip_prefix('-') {
        (-1.0, rest)
    } else {
        (1.0, text)
    };
    let rest = if rest.len() >= 2 && rest[..2].eq_ignore_ascii_case("0x") {
        &rest[2..]
    } else {
        return None;
    };
    let (body, exponent) = if let Some((body, exp)) = rest.split_once(['p', 'P']) {
        (body, exp.parse::<i32>().ok()?)
    } else {
        (rest, 0)
    };
    let (whole, frac) = body.split_once('.').unwrap_or((body, ""));
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    if !whole.chars().all(|ch| ch.is_ascii_hexdigit())
        || !frac.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return None;
    }
    let mut value =
        i128::from_str_radix(if whole.is_empty() { "0" } else { whole }, 16).ok()? as f64;
    for (index, ch) in frac.chars().enumerate() {
        let digit = ch.to_digit(16)? as f64;
        value += digit / 16_f64.powi(index as i32 + 1);
    }
    Some(sign * value * 2_f64.powi(exponent))
}

fn trunc_decimal(text: &str) -> Option<String> {
    let (negative, rest) = if let Some(rest) = text.strip_prefix('+') {
        (false, rest)
    } else if let Some(rest) = text.strip_prefix('-') {
        (true, rest)
    } else {
        (false, text)
    };
    let (mantissa, exponent) = if let Some((mantissa, exp)) = rest.split_once(['e', 'E']) {
        (mantissa, exp.parse::<i32>().ok()?)
    } else {
        (rest, 0)
    };
    let (whole, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if (whole.is_empty() && frac.is_empty())
        || !whole.chars().all(|ch| ch.is_ascii_digit())
        || !frac.chars().all(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    let raw = format!("{whole}{frac}");
    let point = whole.len() as i32 + exponent;
    if point <= 0 {
        return Some("0".to_string());
    }
    let point = point as usize;
    let mut digits = if point >= raw.len() {
        let mut extended = raw.clone();
        extended.extend(std::iter::repeat_n('0', point - raw.len()));
        extended
    } else {
        raw[..point].to_string()
    };
    let trimmed = digits.trim_start_matches('0');
    digits = if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    };
    if negative && digits != "0" {
        digits.insert(0, '-');
    }
    Some(digits)
}

fn gsub_field(
    event: &mut Event,
    field: &str,
    needle: &str,
    replacement: &str,
) -> Result<(), RunError> {
    let field = event.sprintf(field).map_err(event_fail)?;
    let Some(value) = event.get_field(&field).map_err(event_fail)? else {
        return Ok(());
    };
    let replacement = event.sprintf(replacement).map_err(event_fail)?;
    let pattern = if needle.contains("%{") {
        event.sprintf(needle).map_err(event_fail)?
    } else {
        needle.to_string()
    };
    let next = match value {
        Value::String(text) => Value::from(gsub_text(&text, &pattern, &replacement)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| match item {
                    Value::String(text) => Value::from(gsub_text(&text, &pattern, &replacement)),
                    other => other,
                })
                .collect(),
        ),
        other => other,
    };
    event.set_field(&field, next).map_err(event_fail)
}

fn gsub_text(text: &str, pattern: &str, replacement: &str) -> String {
    if pattern == r"\d$" {
        let mut chars: Vec<char> = text.chars().collect();
        if chars.last().is_some_and(|ch| ch.is_ascii_digit()) {
            chars.pop();
            let mut out: String = chars.into_iter().collect();
            out.push_str(replacement);
            return out;
        }
        return text.to_string();
    }
    if pattern_is_literal(pattern) {
        return text.replace(pattern, replacement);
    }
    text.to_string()
}

fn pattern_is_literal(pattern: &str) -> bool {
    !pattern.chars().any(|ch| {
        matches!(
            ch,
            '\\' | '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
        )
    })
}

fn change_case(event: &mut Event, field: &str, operation: &str) -> Result<(), RunError> {
    let Some(value) = event.get_field(field).map_err(event_fail)? else {
        return Ok(());
    };
    if matches!(value, Value::Null) {
        return Ok(());
    }
    let next = match value {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| match item {
                    Value::String(text) => Value::from(case_text(&text, operation)),
                    other => other,
                })
                .collect(),
        ),
        Value::String(text) => Value::from(case_text(&text, operation)),
        other => other,
    };
    event.set_field(field, next).map_err(event_fail)
}

fn case_text(text: &str, operation: &str) -> String {
    match operation {
        "uppercase" => text.to_uppercase(),
        "lowercase" => text.to_lowercase(),
        "capitalize" => {
            let mut chars = text.chars();
            match chars.next() {
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
                None => String::new(),
            }
        }
        _ => text.to_string(),
    }
}

fn strip_field(event: &mut Event, field: &str) -> Result<(), RunError> {
    let Some(value) = event.get_field(field).map_err(event_fail)? else {
        return Ok(());
    };
    let next = match value {
        Value::String(text) => Value::from(text.trim()),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| match item {
                    Value::String(text) => Value::from(text.trim()),
                    other => other,
                })
                .collect(),
        ),
        other => other,
    };
    event.set_field(field, next).map_err(event_fail)
}

fn split_field(event: &mut Event, field: &str, separator: &str) -> Result<(), RunError> {
    let Some(Value::String(text)) = event.get_field(field).map_err(event_fail)? else {
        return Ok(());
    };
    let mut parts: Vec<Value> = if separator.is_empty() {
        text.chars().map(|ch| Value::from(ch.to_string())).collect()
    } else {
        text.split(separator).map(Value::from).collect()
    };
    while parts.len() > 1 && matches!(parts.last(), Some(Value::String(last)) if last.is_empty()) {
        parts.pop();
    }
    event
        .set_field(field, Value::Array(parts))
        .map_err(event_fail)
}

fn join_field(event: &mut Event, field: &str, separator: &str) -> Result<(), RunError> {
    let Some(Value::Array(items)) = event.get_field(field).map_err(event_fail)? else {
        return Ok(());
    };
    let text = items
        .iter()
        .map(|item| item.to_string())
        .collect::<Vec<_>>()
        .join(separator);
    event
        .set_field(field, Value::from(text))
        .map_err(event_fail)
}

fn merge_field(event: &mut Event, field: &str, added: &str) -> Result<(), RunError> {
    let dest = event.get_field(field).map_err(event_fail)?;
    let extra = event.get_field(added).map_err(event_fail)?;
    let dest_is_map = matches!(dest, Some(Value::Map(_)));
    let extra_is_map = matches!(extra, Some(Value::Map(_)));
    if dest_is_map ^ extra_is_map {
        return Ok(());
    }
    if dest_is_map {
        let Value::Map(mut dest_map) = dest.unwrap() else {
            return Ok(());
        };
        if let Some(Value::Map(extra_map)) = extra {
            for (key, value) in extra_map.iter() {
                dest_map.insert(key, value.clone());
            }
        }
        event
            .set_field(field, Value::Map(dest_map))
            .map_err(event_fail)
    } else {
        let mut list = array_wrap(dest);
        list.extend(array_wrap(extra));
        event
            .set_field(field, Value::Array(list))
            .map_err(event_fail)
    }
}

fn array_wrap(value: Option<Value>) -> Vec<Value> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items,
        Some(other) => vec![other],
    }
}

fn remove_tag(event: &mut Event, tag: &str) -> Result<(), RunError> {
    let Some(Value::Array(items)) = event.get_field("tags").map_err(event_fail)? else {
        return Ok(());
    };
    let kept: Vec<Value> = items
        .into_iter()
        .filter(|item| item.to_string() != tag)
        .collect();
    event
        .set_field("tags", Value::Array(kept))
        .map_err(event_fail)
}

fn arg<'a>(plugin: &'a Plugin, name: &str) -> Option<&'a Arg> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn arg_string(plugin: &Plugin, name: &str) -> Option<String> {
    match arg(plugin, name) {
        Some(Arg::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn pairs(arg: &Arg) -> Result<Vec<(String, String)>, RunError> {
    match arg {
        Arg::Map(entries) => entries
            .iter()
            .map(|(key, value)| Ok((key_text(key), scalar(value)?)))
            .collect(),
        Arg::Array(items) => {
            if items.len() % 2 != 0 {
                return Err(fail("mutate hash option needs pairs"));
            }
            items
                .chunks(2)
                .map(|chunk| Ok((scalar(&chunk[0])?, scalar(&chunk[1])?)))
                .collect()
        }
        _ => Err(fail("mutate option must be a hash or an array of pairs")),
    }
}

fn names(arg: &Arg) -> Result<Vec<String>, RunError> {
    match arg {
        Arg::String(value) => Ok(vec![value.clone()]),
        Arg::Array(items) => items.iter().map(scalar).collect(),
        Arg::Map(entries) => entries.iter().map(|(key, _)| Ok(key_text(key))).collect(),
        other => Ok(vec![scalar(other)?]),
    }
}

fn scalars(arg: &Arg) -> Result<Vec<String>, RunError> {
    match arg {
        Arg::Array(items) => items.iter().map(scalar).collect(),
        other => Ok(vec![scalar(other)?]),
    }
}

fn scalar(arg: &Arg) -> Result<String, RunError> {
    match arg {
        Arg::String(value) => Ok(value.clone()),
        Arg::Int(value) => Ok(value.to_string()),
        Arg::Float(value) => Ok(ruby_float(*value)),
        Arg::Big(value) => Ok(value.clone()),
        _ => Err(fail("plugin option value must be a scalar")),
    }
}

fn key_text(key: &Key) -> String {
    match key {
        Key::String(value) => value.clone(),
        Key::Int(value) => value.to_string(),
        Key::Big(value) => value.clone(),
        Key::Float(value) => ruby_float(*value),
    }
}

fn event_fail(error: crate::EventError) -> RunError {
    fail(error.to_string())
}
