//! `logstash-filter-grok` 4.4.4 on `jls-grok` 0.11.5, with patterns-core 4.3.4.
//!
//! `%{NAME}` and `%{NAME:field}` expand the same way as `Grok#compile`. Named
//! captures become event fields. `int` and `float` follow Ruby `to_i` / `to_f`.
//! The engine is `fancy-regex` (pure Rust). Oniguruma `\d` / `\h` are rewritten
//! to ASCII classes. A pattern that still cannot be compiled returns an error.
//! `timeout_millis` is accepted and not enforced: a match runs to completion.

use std::collections::HashMap;
use std::sync::OnceLock;

use fancy_regex::Regex;

use crate::event::Event;
use crate::lscl::{Arg, Key, Plugin};
use crate::pattern_files::{ECS_V1, LEGACY};
use crate::run::{Ecs, RunError, fail};
use crate::value::Value;

pub(crate) fn apply(plugin: &Plugin, event: &mut Event, ecs: Ecs) -> Result<(), RunError> {
    let Some(arg) = arg(plugin, "match") else {
        for tag in failure_tags(plugin) {
            event.tag(&tag);
        }
        return Ok(());
    };
    let Arg::Map(entries) = arg else {
        return Err(fail("grok match must be a hash"));
    };
    let dictionary = dictionary_for(plugin, ecs)?;
    let named_only = flag(plugin, "named_captures_only", true);
    let keep_empty = flag(plugin, "keep_empty_captures", false);
    let stop_after_match = flag(plugin, "break_on_match", true);
    let overwrite = string_list(plugin, "overwrite");
    let target = target_prefix(plugin);
    let mut compiled = Vec::new();
    for (key, value) in entries {
        let field = key_text(key);
        let mut patterns = Vec::new();
        for pattern in pattern_list(value)? {
            patterns.push(compile(&dictionary, &pattern, named_only)?);
        }
        compiled.push((field, patterns));
    }
    let mut matched = false;
    for (field, patterns) in &compiled {
        let input = event.get_field(field).map_err(event_fail)?;
        if match_value(
            patterns,
            input.as_ref(),
            event,
            stop_after_match,
            keep_empty,
            target.as_deref(),
            &overwrite,
        )? {
            matched = true;
            if stop_after_match {
                break;
            }
        }
    }
    if matched {
        crate::mutate::filter_matched(plugin, event)?;
    } else {
        for tag in failure_tags(plugin) {
            event.tag(&tag);
        }
    }
    Ok(())
}

/// Multiline codec. `logstash-codec-multiline` loads the legacy pattern set.
/// `flush_at_end` is what the file input does on exit. Stdin does not flush.
pub(crate) fn multiline_decode(
    codec: &Plugin,
    text: &str,
    ecs: Ecs,
    flush_at_end: bool,
) -> Result<Vec<Event>, RunError> {
    let pattern = arg_string(codec, "pattern").ok_or_else(|| fail("multiline requires pattern"))?;
    let what = arg_string(codec, "what").ok_or_else(|| fail("multiline requires what"))?;
    if what != "previous" && what != "next" {
        return Err(fail("multiline what must be previous or next"));
    }
    if let Some(charset) = arg_string(codec, "charset")
        && !charset.eq_ignore_ascii_case("UTF-8")
    {
        return Err(fail(format!(
            "multiline charset {charset} is not implemented"
        )));
    }
    let negate = flag(codec, "negate", false);
    let max_lines = arg_usize(codec, "max_lines").unwrap_or(500);
    let max_bytes = if arg(codec, "max_bytes").is_some() {
        parse_bytes(&arg_string(codec, "max_bytes").unwrap_or_default())?
    } else {
        10 * 1024 * 1024
    };
    let tag = arg_string(codec, "multiline_tag").unwrap_or_else(|| "multiline".to_string());
    let dictionary = dictionary_for(codec, Ecs::Disabled)?;
    let matcher = compile(&dictionary, &pattern, false)?;
    let mut lines = Vec::new();
    let mut bytes = 0usize;
    let mut events = Vec::new();
    for line in ruby_split_nl(text) {
        let hit = matcher
            .regex
            .is_match(line)
            .map_err(|error| fail(format!("multiline match failed: {error}")))?;
        let matched = (hit && !negate) || (!hit && negate);
        if what == "previous" {
            if !matched || lines.len() > max_lines || bytes >= max_bytes {
                push_merged(&mut events, &lines, bytes, max_lines, max_bytes, &tag, ecs);
                lines.clear();
                bytes = 0;
            }
            bytes += line.len();
            lines.push(line.to_string());
        } else {
            bytes += line.len();
            lines.push(line.to_string());
            if !matched || lines.len() > max_lines || bytes >= max_bytes {
                push_merged(&mut events, &lines, bytes, max_lines, max_bytes, &tag, ecs);
                lines.clear();
                bytes = 0;
            }
        }
    }
    if flush_at_end {
        push_merged(&mut events, &lines, bytes, max_lines, max_bytes, &tag, ecs);
    }
    Ok(events)
}

fn push_merged(
    events: &mut Vec<Event>,
    lines: &[String],
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
    tag: &str,
    ecs: Ecs,
) {
    if lines.is_empty() {
        return;
    }
    let message = lines.join("\n");
    let mut event = Event::new();
    let _ = event.set_field("message", Value::from(message.as_str()));
    if ecs != Ecs::Disabled {
        let _ = event.set_field("[event][original]", Value::from(message.as_str()));
    }
    if !tag.is_empty() && lines.len() > 1 {
        event.tag(tag);
    }
    if lines.len() > max_lines {
        event.tag("multiline_codec_max_lines_reached");
    }
    if bytes >= max_bytes {
        event.tag("multiline_codec_max_bytes_reached");
    }
    events.push(event);
}

fn ruby_split_nl(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<&str> = text.split('\n').collect();
    while parts.last() == Some(&"") {
        parts.pop();
    }
    parts
}

struct Compiled {
    regex: Regex,
    captures: Vec<Capture>,
}

struct Capture {
    group: String,
    field: String,
    coerce: Coerce,
}

enum Coerce {
    None,
    Int,
    Float,
}

#[derive(Clone)]
struct Dictionary {
    patterns: HashMap<String, String>,
}

fn dictionary_for(plugin: &Plugin, ecs: Ecs) -> Result<Dictionary, RunError> {
    let mut dictionary = builtin(ecs).clone();
    if let Some(paths) = optional_strings(plugin, "patterns_dir") {
        let glob = arg_string(plugin, "patterns_files_glob").unwrap_or_else(|| "*".to_string());
        for path in paths {
            load_path(&mut dictionary, &path, &glob)?;
        }
    }
    if let Some(Arg::Map(entries)) = arg(plugin, "pattern_definitions") {
        for (key, value) in entries {
            if let Ok(pattern) = scalar(value) {
                dictionary.patterns.insert(
                    key_text(key),
                    pattern.trim_end_matches(['\n', '\r']).to_string(),
                );
            }
        }
    }
    Ok(dictionary)
}

fn builtin(ecs: Ecs) -> &'static Dictionary {
    if ecs == Ecs::Disabled {
        static LEGACY_PATTERNS: OnceLock<Dictionary> = OnceLock::new();
        LEGACY_PATTERNS.get_or_init(|| load_files(LEGACY))
    } else {
        static ECS_PATTERNS: OnceLock<Dictionary> = OnceLock::new();
        ECS_PATTERNS.get_or_init(|| load_files(ECS_V1))
    }
}

fn load_files(files: &[(&str, &str)]) -> Dictionary {
    let mut dictionary = Dictionary {
        patterns: HashMap::new(),
    };
    for (_, text) in files {
        load_text(&mut dictionary, text);
    }
    dictionary
}

fn load_path(dictionary: &mut Dictionary, path: &str, glob: &str) -> Result<(), RunError> {
    let file = std::path::Path::new(path);
    if file.is_dir() {
        let mut names: Vec<_> = std::fs::read_dir(file)
            .map_err(|error| fail(error.to_string()))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_file())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| glob_match(glob, name))
            })
            .collect();
        names.sort();
        for path in names {
            let text = std::fs::read_to_string(&path).map_err(|error| fail(error.to_string()))?;
            load_text(dictionary, &text);
        }
        return Ok(());
    }
    if !file.exists() {
        return Err(fail(format!("Grok pattern file does not exist: {path}")));
    }
    let text = std::fs::read_to_string(file).map_err(|error| fail(error.to_string()))?;
    load_text(dictionary, &text);
    Ok(())
}

fn load_text(dictionary: &mut Dictionary, text: &str) {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, pattern)) = trimmed.split_once(|ch: char| ch.is_whitespace()) else {
            continue;
        };
        dictionary.patterns.insert(
            name.to_string(),
            pattern
                .trim_start()
                .trim_end_matches(['\n', '\r'])
                .to_string(),
        );
    }
}

fn glob_match(glob: &str, name: &str) -> bool {
    if glob == "*" {
        return true;
    }
    let parts: Vec<&str> = glob.split('*').collect();
    if parts.len() == 1 {
        return name == glob;
    }
    if !name.starts_with(parts[0]) || !name.ends_with(parts[parts.len() - 1]) {
        return false;
    }
    let mut cursor = parts[0].len();
    for part in &parts[1..parts.len() - 1] {
        let Some(found) = name[cursor..].find(part) else {
            return false;
        };
        cursor += found + part.len();
    }
    true
}

fn compile(dictionary: &Dictionary, pattern: &str, named_only: bool) -> Result<Compiled, RunError> {
    let mut local = dictionary.clone();
    let (expanded, captures) = expand(pattern, &mut local, named_only)?;
    let source = format!(
        "(?ms){}",
        relax_nested_quantifiers(&translate_onig(&expanded))
    );
    let regex = Regex::new(&source).map_err(|error| {
        fail(format!(
            "grok pattern {pattern} failed to compile: {error}; expanded: {expanded}"
        ))
    })?;
    Ok(Compiled { regex, captures })
}

fn expand(
    pattern: &str,
    dictionary: &mut Dictionary,
    named_only: bool,
) -> Result<(String, Vec<Capture>), RunError> {
    let mut expanded = pattern.to_string();
    let mut captures = Vec::new();
    let mut next_group = 0usize;
    for _ in 0..10_000 {
        let Some(token) = find_token(&expanded) else {
            let expanded = rename_raw_groups(&expanded, &mut captures, &mut next_group);
            return Ok((expanded, captures));
        };
        if let Some(definition) = &token.definition {
            dictionary
                .patterns
                .insert(token.pattern.clone(), definition.clone());
        }
        let Some(body) = dictionary.patterns.get(&token.pattern).cloned() else {
            return Err(fail(format!("pattern {} not defined", token.raw)));
        };
        let replacement = if named_only && !token.name.contains(':') {
            format!("(?:{body})")
        } else {
            let group = format!("c{next_group}");
            next_group += 1;
            let (field, coerce) = field_of(&token.name);
            captures.push(Capture {
                group: group.clone(),
                field,
                coerce,
            });
            format!("(?<{group}>{body})")
        };
        expanded.replace_range(token.start..token.end, &replacement);
    }
    Err(fail(format!(
        "Deep recursion pattern compilation of {pattern}"
    )))
}

struct Token {
    start: usize,
    end: usize,
    raw: String,
    pattern: String,
    name: String,
    definition: Option<String>,
}

fn find_token(text: &str) -> Option<Token> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'%'
            && bytes[index + 1] == b'{'
            && (index == 0 || bytes[index - 1] != b'\\')
            && let Some(token) = parse_token(text, index)
        {
            return Some(token);
        }
        index += 1;
    }
    None
}

fn parse_token(text: &str, start: usize) -> Option<Token> {
    let rest = &text[start + 2..];
    let name_len = rest
        .chars()
        .take_while(|ch| is_name_char(*ch))
        .map(char::len_utf8)
        .sum::<usize>();
    if name_len == 0 {
        return None;
    }
    let pattern = rest[..name_len].to_string();
    let bytes = rest.as_bytes();
    let mut cursor = name_len;
    let mut subname = None;
    if bytes.get(cursor) == Some(&b':') {
        cursor += 1;
        let sub_start = cursor;
        while cursor < bytes.len() && is_sub_char(bytes[cursor]) {
            cursor += 1;
        }
        if cursor == sub_start {
            return None;
        }
        subname = Some(rest[sub_start..cursor].to_string());
    }
    let mut definition = None;
    if bytes.get(cursor) == Some(&b'=') {
        cursor += 1;
        let (body, next) = read_definition(rest, cursor)?;
        definition = Some(body);
        cursor = next;
    }
    while cursor < bytes.len() && bytes[cursor] != b'}' {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'}') {
        return None;
    }
    let end = start + 2 + cursor + 1;
    let name = match &subname {
        Some(sub) => format!("{pattern}:{sub}"),
        None => pattern.clone(),
    };
    Some(Token {
        start,
        end,
        raw: text[start..end].to_string(),
        pattern,
        name,
        definition,
    })
}

fn read_definition(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut index = start;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 1 < bytes.len() {
            index += 2;
            continue;
        }
        if bytes[index] == b'{' {
            depth += 1;
            index += 1;
            continue;
        }
        if bytes[index] == b'}' {
            if depth == 0 {
                return Some((text[start..index].to_string(), index));
            }
            depth -= 1;
        }
        index += 1;
    }
    None
}

fn is_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '[' | '\\' | ']' | '^' | '_' | '`')
}

fn is_sub_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'@' | b'[' | b'\\' | b']' | b'^' | b'_' | b'`' | b':' | b'.' | b'-'
        )
}

fn field_of(spec: &str) -> (String, Coerce) {
    let mut parts = spec.split(':');
    let pattern = parts.next().unwrap_or("");
    let name = parts.next();
    let coerce = match parts.next() {
        Some("int") => Coerce::Int,
        Some("float") => Coerce::Float,
        _ => Coerce::None,
    };
    (name.unwrap_or(pattern).to_string(), coerce)
}

fn rename_raw_groups(text: &str, captures: &mut Vec<Capture>, next_group: &mut usize) -> String {
    let mut out = String::new();
    let mut index = 0;
    while index < text.len() {
        if text[index..].starts_with('\\') {
            let mut chars = text[index..].chars();
            chars.next();
            if let Some(next) = chars.next() {
                out.push('\\');
                out.push(next);
                index += 1 + next.len_utf8();
                continue;
            }
        }
        if text[index..].starts_with("(?<!") || text[index..].starts_with("(?<=") {
            out.push_str(&text[index..index + 4]);
            index += 4;
            continue;
        }
        if text[index..].starts_with("(?<")
            && let Some(end) = text[index + 3..].find('>')
        {
            let name = &text[index + 3..index + 3 + end];
            if let Some(rest) = name.strip_prefix('c')
                && !rest.is_empty()
                && rest.chars().all(|ch| ch.is_ascii_digit())
            {
                out.push_str(&text[index..index + 3 + end + 1]);
            } else {
                let group = format!("c{next_group}");
                *next_group += 1;
                let (field, coerce) = field_of(name);
                captures.push(Capture {
                    group: group.clone(),
                    field,
                    coerce,
                });
                out.push_str(&format!("(?<{group}>"));
            }
            index += 3 + end + 1;
            continue;
        }
        let ch = text[index..].chars().next().expect("char");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// JRuby replaces a nested `?` and `*` with `*`: `.?*` compiles as `.*`.
/// `?*` inside a character class stays a pair of literal characters.
fn relax_nested_quantifiers(text: &str) -> String {
    let mut out = String::new();
    let mut class = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            out.push('\\');
            if let Some(next) = chars.next() {
                out.push(next);
            }
            continue;
        }
        if !class && ch == '[' {
            class = true;
            out.push(ch);
            continue;
        }
        if class && ch == ']' {
            class = false;
            out.push(ch);
            continue;
        }
        if !class && ch == '?' && chars.peek() == Some(&'*') {
            chars.next();
            out.push('*');
            continue;
        }
        out.push(ch);
    }
    out
}

fn translate_onig(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('d') => out.push_str("[0-9]"),
            Some('D') => out.push_str("[^0-9]"),
            Some('h') => out.push_str("[0-9A-Fa-f]"),
            Some('H') => out.push_str("[^0-9A-Fa-f]"),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn match_value(
    patterns: &[Compiled],
    input: Option<&Value>,
    event: &mut Event,
    stop_after_match: bool,
    keep_empty: bool,
    target: Option<&str>,
    overwrite: &[String],
) -> Result<bool, RunError> {
    match input {
        Some(Value::Array(items)) => {
            let mut any = false;
            for item in items {
                if match_text(
                    patterns,
                    &item.to_string(),
                    event,
                    stop_after_match,
                    keep_empty,
                    target,
                    overwrite,
                )? {
                    any = true;
                }
            }
            Ok(any)
        }
        Some(value) => match_text(
            patterns,
            &value.to_string(),
            event,
            stop_after_match,
            keep_empty,
            target,
            overwrite,
        ),
        None => match_text(
            patterns,
            "",
            event,
            stop_after_match,
            keep_empty,
            target,
            overwrite,
        ),
    }
}

fn match_text(
    patterns: &[Compiled],
    text: &str,
    event: &mut Event,
    stop_after_match: bool,
    keep_empty: bool,
    target: Option<&str>,
    overwrite: &[String],
) -> Result<bool, RunError> {
    let mut matched = false;
    for pattern in patterns {
        let found = pattern
            .regex
            .captures(text)
            .map_err(|error| fail(format!("grok match failed: {error}")))?;
        let Some(found) = found else {
            continue;
        };
        matched = true;
        for capture in &pattern.captures {
            let Some(text) = found.name(&capture.group).map(|item| item.as_str()) else {
                if keep_empty {
                    store(event, &capture.field, None, target, overwrite, true)?;
                }
                continue;
            };
            if text.is_empty() && !keep_empty {
                continue;
            }
            let value = match capture.coerce {
                Coerce::None => Value::from(text),
                Coerce::Int => Value::Integer(ruby_to_i(text)),
                Coerce::Float => Value::Float(ruby_to_f(text)),
            };
            store(
                event,
                &capture.field,
                Some(value),
                target,
                overwrite,
                keep_empty,
            )?;
        }
        if stop_after_match {
            break;
        }
    }
    Ok(matched)
}

fn store(
    event: &mut Event,
    field: &str,
    value: Option<Value>,
    target: Option<&str>,
    overwrite: &[String],
    keep_empty: bool,
) -> Result<(), RunError> {
    let Some(value) = value else {
        if keep_empty {
            return event
                .set_field(&target_field(target, field), Value::Null)
                .map_err(event_fail);
        }
        return Ok(());
    };
    if matches!(value, Value::String(ref text) if text.is_empty()) && !keep_empty {
        return Ok(());
    }
    let path = target_field(target, field);
    if overwrite.iter().any(|item| item == field)
        || event.get_field(&path).map_err(event_fail)?.is_none()
    {
        return event.set_field(&path, value).map_err(event_fail);
    }
    match event.get_field(&path).map_err(event_fail)? {
        Some(Value::Array(mut items)) => {
            items.push(value);
            event
                .set_field(&path, Value::Array(items))
                .map_err(event_fail)
        }
        Some(Value::String(existing)) => event
            .set_field(&path, Value::Array(vec![Value::String(existing), value]))
            .map_err(event_fail),
        Some(_) => Ok(()),
        None => event.set_field(&path, value).map_err(event_fail),
    }
}

fn target_field(target: Option<&str>, field: &str) -> String {
    match target {
        Some(target) => format!("{target}[{field}]"),
        None => field.to_string(),
    }
}

fn ruby_to_i(text: &str) -> i128 {
    let text = text.trim_start();
    let (sign, rest) = if let Some(rest) = text.strip_prefix('-') {
        (-1i128, rest)
    } else if let Some(rest) = text.strip_prefix('+') {
        (1, rest)
    } else {
        (1, text)
    };
    let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        return 0;
    }
    sign * digits.parse::<i128>().unwrap_or(0)
}

fn ruby_to_f(text: &str) -> f64 {
    let text = text.trim_start();
    let bytes = text.as_bytes();
    let mut end = 0;
    if bytes.first() == Some(&b'+') || bytes.first() == Some(&b'-') {
        end = 1;
    }
    let mark = end;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end < bytes.len() && bytes[end] == b'.' {
        end += 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
    }
    if !text[mark..end].chars().any(|ch| ch.is_ascii_digit()) {
        return 0.0;
    }
    text[..end].parse().unwrap_or(0.0)
}

fn target_prefix(plugin: &Plugin) -> Option<String> {
    let target = arg_string(plugin, "target")?;
    if target.contains('[') {
        Some(target)
    } else {
        Some(format!("[{}]", target.trim()))
    }
}

fn failure_tags(plugin: &Plugin) -> Vec<String> {
    match optional_strings(plugin, "tag_on_failure") {
        Some(tags) if !tags.is_empty() => tags,
        _ => vec!["_grokparsefailure".to_string()],
    }
}

fn pattern_list(value: &Arg) -> Result<Vec<String>, RunError> {
    match value {
        Arg::String(pattern) => Ok(vec![pattern.clone()]),
        Arg::Array(items) => items.iter().map(scalar).collect(),
        _ => Err(fail("grok match pattern must be a string")),
    }
}

fn match_plugin_flag(value: &Arg) -> Option<bool> {
    match value {
        Arg::String(text) if text == "true" => Some(true),
        Arg::String(text) if text == "false" => Some(false),
        _ => None,
    }
}

fn flag(plugin: &Plugin, name: &str, default: bool) -> bool {
    arg(plugin, name)
        .and_then(match_plugin_flag)
        .unwrap_or(default)
}

fn string_list(plugin: &Plugin, name: &str) -> Vec<String> {
    optional_strings(plugin, name).unwrap_or_default()
}

fn optional_strings(plugin: &Plugin, name: &str) -> Option<Vec<String>> {
    match arg(plugin, name) {
        None => None,
        Some(Arg::String(value)) => Some(vec![value.clone()]),
        Some(Arg::Array(items)) => {
            Some(items.iter().filter_map(|item| scalar(item).ok()).collect())
        }
        Some(other) => scalar(other).ok().map(|value| vec![value]),
    }
}

fn arg_usize(plugin: &Plugin, name: &str) -> Option<usize> {
    match arg(plugin, name) {
        Some(Arg::Int(value)) if *value >= 0 => Some(*value as usize),
        Some(Arg::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn parse_bytes(text: &str) -> Result<usize, RunError> {
    let trimmed = text.trim();
    if let Ok(value) = trimmed.parse::<usize>() {
        return Ok(value);
    }
    let lower = trimmed.to_ascii_lowercase();
    let (number, factor) = if let Some(number) = lower.strip_suffix("mib") {
        (number, 1024 * 1024)
    } else if let Some(number) = lower.strip_suffix("kib") {
        (number, 1024)
    } else if let Some(number) = lower.strip_suffix("gib") {
        (number, 1024 * 1024 * 1024)
    } else if let Some(number) = lower.strip_suffix("mb") {
        (number, 1000 * 1000)
    } else if let Some(number) = lower.strip_suffix('b') {
        (number, 1)
    } else {
        return Err(fail(format!("multiline max_bytes {text} is not a size")));
    };
    let number = number
        .trim()
        .parse::<f64>()
        .map_err(|_| fail(format!("multiline max_bytes {text} is not a size")))?;
    Ok((number * factor as f64) as usize)
}

fn arg<'a>(plugin: &'a Plugin, name: &str) -> Option<&'a Arg> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn arg_string(plugin: &Plugin, name: &str) -> Option<String> {
    arg(plugin, name).and_then(|value| scalar(value).ok())
}

fn scalar(value: &Arg) -> Result<String, RunError> {
    match value {
        Arg::String(text) => Ok(text.clone()),
        Arg::Int(value) => Ok(value.to_string()),
        _ => Err(fail("grok option must be a string")),
    }
}

fn key_text(key: &Key) -> String {
    match key {
        Key::String(text) | Key::Big(text) => text.clone(),
        Key::Int(value) => value.to_string(),
        Key::Float(value) => value.to_string(),
    }
}

fn event_fail(error: crate::EventError) -> RunError {
    fail(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_pattern_compiles() {
        for ecs in [Ecs::Disabled, Ecs::V8] {
            let dictionary = builtin(ecs);
            let mut names: Vec<_> = dictionary.patterns.keys().cloned().collect();
            names.sort();
            for name in names {
                compile(dictionary, &format!("%{{{name}}}"), true).unwrap_or_else(|error| {
                    panic!("{ecs:?} {name}: {error}");
                });
            }
        }
    }
}
