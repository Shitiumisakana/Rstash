//! The grok patterns the mutate specs actually match: `%{WORD:name}` and `(?:literal)`.
//!
//! `WORD` is `[A-Za-z0-9_]+` with a word boundary on both sides. Anything else in a
//! pattern is an error, so a later pattern is not silently treated as a literal.

use crate::event::Event;
use crate::lscl::{Arg, Key, Plugin};
use crate::run::{RunError, fail};
use crate::value::Value;

pub(crate) fn apply(plugin: &Plugin, event: &mut Event) -> Result<(), RunError> {
    let Some(arg) = plugin
        .args
        .iter()
        .find(|(name, _)| name == "match")
        .map(|(_, value)| value)
    else {
        return Ok(());
    };
    let Arg::Map(entries) = arg else {
        return Err(fail("grok match must be a hash"));
    };
    let stop_after_match = break_on_match(plugin);
    let mut matched = false;
    for (key, value) in entries {
        let field = key_text(key);
        let patterns = pattern_list(value)?;
        let Some(Value::String(text)) = event.get_field(&field).map_err(event_fail)? else {
            continue;
        };
        for pattern in patterns {
            let pieces = pieces(&pattern)?;
            if let Some(captures) = find_match(&text, &pieces) {
                matched = true;
                for (name, word) in captures {
                    event
                        .set_field(&name, Value::from(word))
                        .map_err(event_fail)?;
                }
                if stop_after_match {
                    break;
                }
            }
        }
    }
    if !matched {
        let tag = plugin
            .args
            .iter()
            .find(|(name, _)| name == "tag_on_failure")
            .and_then(|(_, value)| match value {
                Arg::String(text) => Some(text.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "_grokparsefailure".to_string());
        event.tag(&tag);
    }
    Ok(())
}

fn break_on_match(plugin: &Plugin) -> bool {
    match plugin
        .args
        .iter()
        .find(|(name, _)| name == "break_on_match")
        .map(|(_, value)| value)
    {
        Some(Arg::String(value)) => value != "false",
        _ => true,
    }
}

fn pattern_list(value: &Arg) -> Result<Vec<String>, RunError> {
    match value {
        Arg::String(pattern) => Ok(vec![pattern.clone()]),
        Arg::Array(items) => items
            .iter()
            .map(|item| match item {
                Arg::String(pattern) => Ok(pattern.clone()),
                _ => Err(fail("grok match pattern must be a string")),
            })
            .collect(),
        _ => Err(fail("grok match pattern must be a string")),
    }
}

enum Piece {
    Lit(String),
    Word(String),
}

fn pieces(pattern: &str) -> Result<Vec<Piece>, RunError> {
    let mut out = Vec::new();
    let mut literal = String::new();
    let mut rest = pattern;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("%{WORD:") {
            if !literal.is_empty() {
                out.push(Piece::Lit(std::mem::take(&mut literal)));
            }
            let Some(end) = after.find('}') else {
                return Err(fail(format!("grok pattern {pattern} is not implemented")));
            };
            let name = &after[..end];
            if name.is_empty() {
                return Err(fail(format!("grok pattern {pattern} is not implemented")));
            }
            out.push(Piece::Word(name.to_string()));
            rest = &after[end + 1..];
        } else if let Some(after) = rest.strip_prefix("(?:") {
            let Some(end) = after.find(')') else {
                return Err(fail(format!("grok pattern {pattern} is not implemented")));
            };
            literal.push_str(&after[..end]);
            rest = &after[end + 1..];
        } else {
            let ch = rest.chars().next().expect("rest");
            if matches!(
                ch,
                '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\'
            ) {
                return Err(fail(format!("grok pattern {pattern} is not implemented")));
            }
            literal.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    if !literal.is_empty() {
        out.push(Piece::Lit(literal));
    }
    Ok(out)
}

fn find_match(text: &str, pieces: &[Piece]) -> Option<Vec<(String, String)>> {
    if pieces.is_empty() {
        return None;
    }
    let mut start = 0;
    loop {
        if let Some(found) = apply_at(text, start, pieces) {
            return Some(found);
        }
        if start >= text.len() {
            return None;
        }
        let ch = text[start..].chars().next().expect("char");
        start += ch.len_utf8();
    }
}

fn apply_at(text: &str, mut pos: usize, pieces: &[Piece]) -> Option<Vec<(String, String)>> {
    let mut captures = Vec::new();
    for piece in pieces {
        match piece {
            Piece::Lit(literal) => {
                if !text[pos..].starts_with(literal.as_str()) {
                    return None;
                }
                pos += literal.len();
            }
            Piece::Word(name) => {
                if !left_boundary(text, pos) {
                    return None;
                }
                let word: String = text[pos..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                    .collect();
                if word.is_empty() {
                    return None;
                }
                pos += word.len();
                if !right_boundary(text, pos) {
                    return None;
                }
                captures.push((name.clone(), word));
            }
        }
    }
    Some(captures)
}

fn left_boundary(text: &str, pos: usize) -> bool {
    if pos == 0 {
        return true;
    }
    let previous = text[..pos].chars().next_back().expect("previous");
    !(previous.is_ascii_alphanumeric() || previous == '_')
}

fn right_boundary(text: &str, pos: usize) -> bool {
    if pos >= text.len() {
        return true;
    }
    let next = text[pos..].chars().next().expect("next");
    !(next.is_ascii_alphanumeric() || next == '_')
}

fn key_text(key: &Key) -> String {
    match key {
        Key::String(value) => value.clone(),
        Key::Int(value) => value.to_string(),
        Key::Big(value) => value.clone(),
        Key::Float(value) => value.to_string(),
    }
}

fn event_fail(error: crate::EventError) -> RunError {
    fail(error.to_string())
}
