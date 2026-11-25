use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::error::EventError;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FieldRef {
    pub path: Vec<String>,
    pub key: String,
    pub target: Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Data,
    Metadata,
    MetadataRoot,
}

/// `config.field_reference.escape_style`. The default in 9.5.2 is `none`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldEscape {
    None,
    Percent,
    Ampersand,
}

pub fn parse_field(input: &str) -> Result<FieldRef, EventError> {
    Ok((*intern_field_escaped(input, FieldEscape::None)?).clone())
}

pub fn parse_field_escaped(input: &str, style: FieldEscape) -> Result<FieldRef, EventError> {
    Ok((*intern_field_escaped(input, style)?).clone())
}

/// `FieldReference.from`. The same parsed reference is one shared value.
/// `@timestamp` and `[@timestamp]` therefore compare identical.
pub fn intern_field(input: &str) -> Result<Arc<FieldRef>, EventError> {
    intern_field_escaped(input, FieldEscape::None)
}

/// Official cache check: `@timestamp` and `[@timestamp]` are one instance.
pub fn same_interned_field(left: &str, right: &str) -> Result<bool, EventError> {
    let mut cache = field_cache().lock().expect("field cache");
    cache.clear();
    let left = cache.intern(left, FieldEscape::None)?;
    let right = cache.intern(right, FieldEscape::None)?;
    Ok(Arc::ptr_eq(&left, &right))
}

/// Official cache check: the source map stops at 10_000 distinct references.
pub fn field_cache_len_after_distinct(count: usize) -> Result<usize, EventError> {
    let mut cache = field_cache().lock().expect("field cache");
    cache.clear();
    for index in 0..count {
        cache.intern(&format!("[array][{index}]"), FieldEscape::None)?;
    }
    Ok(cache.by_source.len())
}

fn intern_field_escaped(input: &str, style: FieldEscape) -> Result<Arc<FieldRef>, EventError> {
    field_cache()
        .lock()
        .expect("field cache")
        .intern(input, style)
}

struct FieldCache {
    by_source: HashMap<String, Arc<FieldRef>>,
    by_value: HashMap<FieldRef, Arc<FieldRef>>,
}

impl FieldCache {
    fn clear(&mut self) {
        self.by_source.clear();
        self.by_value.clear();
    }

    fn intern(&mut self, reference: &str, style: FieldEscape) -> Result<Arc<FieldRef>, EventError> {
        let key = format!("{}:{reference}", style_key(style));
        if let Some(found) = self.by_source.get(&key) {
            return Ok(Arc::clone(found));
        }
        let parsed = parse_uncached(reference, style)?;
        if self.by_source.len() >= 10_000 {
            return Ok(Arc::new(parsed));
        }
        let stored = if let Some(existing) = self.by_value.get(&parsed) {
            Arc::clone(existing)
        } else {
            let stored = Arc::new(parsed);
            self.by_value.insert((*stored).clone(), Arc::clone(&stored));
            stored
        };
        self.by_source.insert(key, Arc::clone(&stored));
        Ok(stored)
    }
}

fn field_cache() -> &'static Mutex<FieldCache> {
    static CACHE: OnceLock<Mutex<FieldCache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(FieldCache {
            by_source: HashMap::new(),
            by_value: HashMap::new(),
        })
    })
}

fn style_key(style: FieldEscape) -> u8 {
    match style {
        FieldEscape::None => 0,
        FieldEscape::Percent => 1,
        FieldEscape::Ampersand => 2,
    }
}

fn parse_uncached(input: &str, style: FieldEscape) -> Result<FieldRef, EventError> {
    let mut tokens = tokenize(input)?;
    for token in &mut tokens {
        *token = unescape_token(token, style);
    }
    from_tokens(tokens)
}

fn unescape_token(token: &str, style: FieldEscape) -> String {
    match style {
        FieldEscape::None => token.to_string(),
        FieldEscape::Percent => unescape_percent(token),
        FieldEscape::Ampersand => unescape_ampersand(token),
    }
}

/// `EscapeHandler.PERCENT`: only `%` plus two uppercase hex digits is encoded.
fn unescape_percent(token: &str) -> String {
    if !token.contains('%') {
        return token.to_string();
    }
    let chars: Vec<char> = token.chars().collect();
    if !chars
        .windows(3)
        .any(|window| window[0] == '%' && is_upper_hex(window[1]) && is_upper_hex(window[2]))
    {
        return token.to_string();
    }
    let mut escaped = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '%'
            && !(index + 2 < chars.len()
                && is_upper_hex(chars[index + 1])
                && is_upper_hex(chars[index + 2]))
        {
            escaped.push_str("%25");
            index += 1;
            continue;
        }
        escaped.push(chars[index]);
        index += 1;
    }
    percent_decode(&escaped)
}

fn percent_decode(token: &str) -> String {
    let bytes = token.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(decoded)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

fn unescape_ampersand(token: &str) -> String {
    if !token.contains('&') {
        return token.to_string();
    }
    let chars: Vec<char> = token.chars().collect();
    let mut output = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '&' && chars.get(index + 1) == Some(&'#') {
            let mut end = index + 2;
            let start = end;
            while end < chars.len() && chars[end].is_ascii_digit() {
                end += 1;
            }
            if end - start >= 2 && chars.get(end) == Some(&';') {
                let digits: String = chars[start..end].iter().collect();
                if let Ok(code) = digits.parse::<u32>()
                    && let Some(ch) = char::from_u32(code)
                {
                    output.push(ch);
                    index = end + 1;
                    continue;
                }
            }
        }
        output.push(chars[index]);
        index += 1;
    }
    output
}

fn is_upper_hex(ch: char) -> bool {
    ch.is_ascii_digit() || ('A'..='F').contains(&ch)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn from_tokens(mut tokens: Vec<String>) -> Result<FieldRef, EventError> {
    let Some(key) = tokens.pop() else {
        return Err(EventError::InvalidField {
            reference: String::new(),
        });
    };
    if tokens.is_empty() && key == "@metadata" {
        return Ok(FieldRef {
            path: Vec::new(),
            key,
            target: Target::MetadataRoot,
        });
    }
    if tokens.first().is_some_and(|segment| segment == "@metadata") {
        return Ok(FieldRef {
            path: tokens.into_iter().skip(1).collect(),
            key,
            target: Target::Metadata,
        });
    }
    Ok(FieldRef {
        path: tokens,
        key,
        target: Target::Data,
    })
}

/// Bracket rules copied from `FieldReference.StrictTokenizer` in Logstash 9.5.2.
fn tokenize(input: &str) -> Result<Vec<String>, EventError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut error = false;
    let mut seen_bracket = false;
    let mut depth = 0i32;
    let mut token_start = 0usize;
    let mut current = '\0';
    let mut previous;
    let mut index = 0usize;
    while index < chars.len() {
        previous = current;
        current = chars[index];
        match current {
            '[' => {
                seen_bracket = true;
                if token_start != index {
                    error = true;
                    break;
                }
                depth += 1;
                token_start = index + 1;
            }
            ']' => {
                seen_bracket = true;
                if depth <= 0 {
                    error = true;
                    break;
                }
                if token_start == index && previous != ']' {
                    error = true;
                    break;
                }
                if token_start < index {
                    tokens.push(chars[token_start..index].iter().collect());
                }
                depth -= 1;
                token_start = index + 1;
            }
            _ => {
                if seen_bracket && previous == ']' {
                    error = true;
                    break;
                }
            }
        }
        index += 1;
    }
    if !seen_bracket {
        return Ok(vec![input.to_string()]);
    }
    if depth > 0 {
        error = true;
    }
    if error {
        return Err(EventError::InvalidField {
            reference: input.to_string(),
        });
    }
    Ok(tokens)
}
