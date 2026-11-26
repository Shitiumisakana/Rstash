//! Ruby `logstash-codec-plain` 3.1.0 and `logstash-codec-line` 3.1.1.
//!
//! `Charset#convert` turns a declared charset into UTF-8. Invalid UTF-8 becomes
//! the Ruby `String#inspect` body. `line` splits on `\n` unless `delimiter` is set.

use crate::event::Event;
use crate::run::Ecs;
use crate::value::Value;

#[derive(Debug, Clone)]
pub struct TextCodec {
    pub name: String,
    pub charset: String,
    pub delimiter: String,
    pub format: Option<String>,
    pub ecs_original: bool,
    pending: String,
}

impl TextCodec {
    pub fn plain(ecs: Ecs) -> Self {
        Self {
            name: "plain".to_string(),
            charset: "UTF-8".to_string(),
            delimiter: String::new(),
            format: None,
            ecs_original: ecs != Ecs::Disabled,
            pending: String::new(),
        }
    }

    pub fn line(ecs: Ecs) -> Self {
        Self {
            name: "line".to_string(),
            charset: "UTF-8".to_string(),
            delimiter: "\n".to_string(),
            format: None,
            ecs_original: ecs != Ecs::Disabled,
            pending: String::new(),
        }
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Event>, String> {
        let text = convert_charset(&self.charset, data)?;
        if self.name == "plain" {
            return Ok(vec![self.event(text)]);
        }
        self.pending.push_str(&text);
        let mut events = Vec::new();
        while let Some(index) = self.pending.find(&self.delimiter) {
            let line = self.pending[..index].to_string();
            self.pending
                .replace_range(..index + self.delimiter.len(), "");
            events.push(self.event(line));
        }
        Ok(events)
    }

    pub fn flush(&mut self) -> Result<Vec<Event>, String> {
        if self.name != "line" || self.pending.is_empty() {
            return Ok(Vec::new());
        }
        let line = std::mem::take(&mut self.pending);
        Ok(vec![self.event(line)])
    }

    /// The string passed to `on_event` before the output writes bytes.
    pub fn encode(&self, event: &Event) -> Result<String, String> {
        let body = if let Some(format) = &self.format {
            event.sprintf(format).map_err(|error| error.to_string())?
        } else {
            event.plain_string()
        };
        if self.name == "line" {
            Ok(body + &self.delimiter)
        } else {
            Ok(body)
        }
    }

    fn event(&self, message: String) -> Event {
        let mut event = Event::new();
        let _ = event.set_field("message", Value::from(message.as_str()));
        if self.ecs_original {
            let _ = event.set_field("[event][original]", Value::from(message));
        }
        event
    }
}

pub fn convert_charset(charset: &str, data: &[u8]) -> Result<String, String> {
    match charset.to_ascii_uppercase().as_str() {
        "UTF-8" | "UTF8" => {
            if let Ok(text) = std::str::from_utf8(data) {
                Ok(text.to_string())
            } else {
                Ok(ruby_inspect_body(data))
            }
        }
        "ISO-8859-1" | "LATIN1" => Ok(data.iter().map(|byte| char::from(*byte)).collect()),
        "ASCII-8BIT" | "BINARY" => Ok(data
            .iter()
            .map(|byte| {
                if *byte < 128 {
                    char::from(*byte)
                } else {
                    '\u{FFFD}'
                }
            })
            .collect()),
        other => Err(format!("charset {other} is not implemented")),
    }
}

/// `String#inspect` without the surrounding quotes, for bytes that are not valid UTF-8.
fn ruby_inspect_body(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut index = 0;
    while index < bytes.len() {
        let width = utf8_char_width(bytes[index]);
        if width > 0
            && index + width <= bytes.len()
            && std::str::from_utf8(&bytes[index..index + width]).is_ok()
        {
            let text = std::str::from_utf8(&bytes[index..index + width]).expect("checked");
            for ch in text.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    other if other.is_control() => {
                        out.push_str(&format!("\\x{:02X}", u32::from(other)));
                    }
                    other => out.push(other),
                }
            }
            index += width;
        } else {
            out.push_str(&format!("\\x{:02X}", bytes[index]));
            index += 1;
        }
    }
    out
}

fn utf8_char_width(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte & 0xE0 == 0xC0 {
        2
    } else if byte & 0xF0 == 0xE0 {
        3
    } else if byte & 0xF8 == 0xF0 {
        4
    } else {
        0
    }
}
