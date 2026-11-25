use chrono::{DateTime, Utc};

use crate::error::EventError;
use crate::field::{self, Target};
use crate::timefmt::{self, format_timestamp};
use crate::value::{Map, Value};

/// One Logstash event.
///
/// `@timestamp` and `@version` live in the field map. `@metadata` is a separate
/// map and is not part of the field data.
#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    data: Map,
    metadata: Map,
    cancelled: bool,
}

impl Event {
    pub fn new() -> Self {
        Self::at(utc_now())
    }

    pub fn at(timestamp: DateTime<Utc>) -> Self {
        let mut event = Self {
            data: Map::new(),
            metadata: Map::new(),
            cancelled: false,
        };
        event
            .data
            .insert("@version", Value::String(String::from("1")));
        event.data.insert("@timestamp", Value::Timestamp(timestamp));
        event
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub fn uncancel(&mut self) {
        self.cancelled = false;
    }

    /// Snapshot of a field. The metadata root is not stored as one cell, so
    /// callers receive a copy they can keep after later writes.
    pub fn get_field(&self, reference: &str) -> Result<Option<Value>, EventError> {
        let field = field::parse_field(reference)?;
        Ok(match field.target {
            Target::Data => self.data_get(&field.path, &field.key).cloned(),
            Target::Metadata => self.metadata_get(&field.path, &field.key).cloned(),
            Target::MetadataRoot => Some(Value::Map(self.metadata.clone())),
        })
    }

    pub fn set_field(&mut self, reference: &str, value: Value) -> Result<(), EventError> {
        let field = field::parse_field(reference)?;
        match field.target {
            Target::Data => set_path(&mut self.data, &field.path, &field.key, value),
            Target::Metadata => set_path(&mut self.metadata, &field.path, &field.key, value),
            Target::MetadataRoot => match value {
                Value::Map(map) => {
                    self.metadata = map;
                    Ok(())
                }
                other => Err(invalid_field_set(
                    "@metadata",
                    &Value::Map(self.metadata.clone()),
                    &other,
                )),
            },
        }
    }

    pub fn remove_field(&mut self, reference: &str) -> Result<Option<Value>, EventError> {
        let field = field::parse_field(reference)?;
        Ok(match field.target {
            Target::Data => remove_path(&mut self.data, &field.path, &field.key),
            Target::Metadata => remove_path(&mut self.metadata, &field.path, &field.key),
            Target::MetadataRoot => {
                let removed = std::mem::take(&mut self.metadata);
                Some(Value::Map(removed))
            }
        })
    }

    pub fn sprintf(&self, template: &str) -> Result<String, EventError> {
        let Some(mut open) = template.find("%{") else {
            return Ok(template.to_string());
        };
        let Some(mut close) = template[open..].find('}').map(|offset| open + offset) else {
            return Ok(template.to_string());
        };
        let mut output = String::new();
        let mut cursor = 0usize;
        loop {
            if open > cursor {
                output.push_str(&template[cursor..open]);
            }
            let inner_start = open + 2;
            let inner = &template[inner_start..close];
            if inner == "+%s" {
                if let Some(timestamp) = self.timestamp() {
                    output.push_str(&timestamp.timestamp().to_string());
                }
            } else if template.as_bytes().get(inner_start) == Some(&b'{')
                && template.as_bytes().get(close + 1) == Some(&b'}')
            {
                let pattern = &template[inner_start + 1..close];
                close += 1;
                if pattern == "TIME_NOW" {
                    output.push_str(&format_timestamp(utc_now()));
                } else if let Some(timestamp) = self.timestamp() {
                    output.push_str(&timefmt::format_java_pattern(timestamp, pattern)?);
                }
            } else if template.as_bytes().get(inner_start) == Some(&b'+') {
                if let Some(timestamp) = self.timestamp() {
                    let pattern = &template[inner_start + 1..close];
                    output.push_str(&timefmt::format_joda_pattern(timestamp, pattern)?);
                }
            } else {
                match self.get_field(inner)? {
                    Some(value) => output.push_str(&render_sprintf_value(&value)?),
                    None => {
                        output.push_str("%{");
                        output.push_str(inner);
                        output.push('}');
                    }
                }
            }
            cursor = close + 1;
            let Some(next_open) = template[cursor..].find("%{").map(|offset| cursor + offset)
            else {
                break;
            };
            let Some(next_close) = template[next_open..]
                .find('}')
                .map(|offset| next_open + offset)
            else {
                break;
            };
            open = next_open;
            close = next_close;
        }
        if cursor < template.len() {
            output.push_str(&template[cursor..]);
        }
        Ok(output)
    }

    fn timestamp(&self) -> Option<DateTime<Utc>> {
        match self.data.get("@timestamp") {
            Some(Value::Timestamp(timestamp)) => Some(*timestamp),
            _ => None,
        }
    }

    fn data_get(&self, path: &[String], key: &str) -> Option<&Value> {
        descend_get(&self.data, path, key)
    }

    fn metadata_get(&self, path: &[String], key: &str) -> Option<&Value> {
        descend_get(&self.metadata, path, key)
    }
}

impl Default for Event {
    fn default() -> Self {
        Self::new()
    }
}

fn descend_get<'a>(map: &'a Map, path: &[String], key: &str) -> Option<&'a Value> {
    let mut current = map;
    for segment in path {
        match current.get(segment) {
            Some(Value::Map(child)) => current = child,
            _ => return None,
        }
    }
    match current.get(key) {
        Some(Value::Null) | None => None,
        Some(value) => Some(value),
    }
}

fn set_path(map: &mut Map, path: &[String], key: &str, value: Value) -> Result<(), EventError> {
    if path.is_empty() {
        map.insert(key, value);
        return Ok(());
    }
    let head = &path[0];
    let rest = &path[1..];
    let next_field = rest.first().map(String::as_str).unwrap_or(key);
    if map.get(head).is_none() {
        map.insert(head.clone(), Value::Map(Map::new()));
    }
    let Some(current) = map.get_mut(head) else {
        return Err(invalid_field_set(next_field, &Value::Null, &value));
    };
    match current {
        Value::Map(child) => set_path(child, rest, key, value),
        other => Err(invalid_field_set(next_field, other, &value)),
    }
}

fn remove_path(map: &mut Map, path: &[String], key: &str) -> Option<Value> {
    if path.is_empty() {
        return map.remove(key);
    }
    let head = &path[0];
    let rest = &path[1..];
    match map.get_mut(head) {
        Some(Value::Map(child)) => remove_path(child, rest, key),
        _ => None,
    }
}

fn utc_now() -> DateTime<Utc> {
    let Ok(duration) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return DateTime::UNIX_EPOCH;
    };
    DateTime::from_timestamp(duration.as_secs() as i64, duration.subsec_nanos())
        .unwrap_or(DateTime::UNIX_EPOCH)
}

fn invalid_field_set(field: &str, object: &Value, value: &Value) -> EventError {
    EventError::InvalidFieldSet {
        message: format!(
            "Could not set field '{field}' on object '{object}' to value '{value}'.This is probably due to trying to set a field like [foo][bar] = someValuewhen [foo] is not either a map or a string"
        ),
    }
}

fn render_sprintf_value(value: &Value) -> Result<String, EventError> {
    match value {
        Value::Array(items) => Ok(items
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")),
        Value::Map(map) => map_to_json(map),
        other => Ok(other.to_string()),
    }
}

fn map_to_json(map: &Map) -> Result<String, EventError> {
    let mut entries: Vec<(&str, &Value)> = map.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    let mut object = serde_json::Map::new();
    for (key, value) in entries {
        object.insert(key.to_string(), value_to_json(value)?);
    }
    serde_json::to_string(&serde_json::Value::Object(object)).map_err(|error| EventError::Json {
        message: error.to_string(),
    })
}

fn value_to_json(value: &Value) -> Result<serde_json::Value, EventError> {
    Ok(match value {
        Value::Null => serde_json::Value::Null,
        Value::String(text) => serde_json::Value::String(text.clone()),
        Value::Integer(number) => serde_json::Value::Number((*number).into()),
        Value::Float(number) => serde_json::Number::from_f64(*number)
            .map(serde_json::Value::Number)
            .ok_or_else(|| EventError::Json {
                message: String::from("float is not a JSON number"),
            })?,
        Value::Boolean(flag) => serde_json::Value::Bool(*flag),
        Value::Timestamp(timestamp) => serde_json::Value::String(format_timestamp(*timestamp)),
        Value::Array(items) => {
            let mut array = Vec::with_capacity(items.len());
            for item in items {
                array.push(value_to_json(item)?);
            }
            serde_json::Value::Array(array)
        }
        Value::Map(map) => {
            serde_json::from_str(&map_to_json(map)?).map_err(|error| EventError::Json {
                message: error.to_string(),
            })?
        }
    })
}
