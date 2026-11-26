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

    pub(crate) fn field_map(&self) -> &Map {
        &self.data
    }

    pub(crate) fn metadata_map(&self) -> &Map {
        &self.metadata
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
        reject_illegal_tags(&field, &value)?;
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

    /// Java `Event.toMap`. A new map, so later edits do not change the event.
    pub fn to_map(&self) -> Map {
        self.data.clone()
    }

    /// Ruby `to_hash_with_metadata`.
    pub fn to_map_with_metadata(&self) -> Map {
        let mut map = self.data.clone();
        map.insert("@metadata", Value::Map(self.metadata.clone()));
        map
    }

    /// Java `Event.toJson`: field data only, `@metadata` stays out.
    pub fn to_json(&self) -> Result<String, EventError> {
        map_to_json(&self.data)
    }

    /// Java `Event.fromJson`. Blank input yields no events.
    pub fn from_json(json: &str) -> Result<Vec<Event>, EventError> {
        Self::from_json_with(json, Event::from_data)
    }

    /// Ruby `Event.from_json` with a block. The block receives each object and returns the event.
    pub fn from_json_with<F>(json: &str, mut factory: F) -> Result<Vec<Event>, EventError>
    where
        F: FnMut(Map) -> Event,
    {
        if json.trim().is_empty() {
            return Ok(Vec::new());
        }
        let parsed: serde_json::Value =
            serde_json::from_str(json).map_err(|error| EventError::Json {
                message: error.to_string(),
            })?;
        match parsed {
            serde_json::Value::Object(_) => Ok(vec![factory(json_to_map(&parsed)?)]),
            serde_json::Value::Array(items) => {
                let mut events = Vec::with_capacity(items.len());
                for item in items {
                    let serde_json::Value::Object(_) = &item else {
                        return Err(EventError::Json {
                            message: String::from("json array elements must be objects"),
                        });
                    };
                    events.push(factory(json_to_map(&item)?));
                }
                Ok(events)
            }
            other => Err(EventError::Json {
                message: format!("incompatible json object type {other}"),
            }),
        }
    }

    /// Java `Event(Map)`. Keys are literal, including ones that look like field references.
    pub fn from_data(mut data: Map) -> Self {
        if data.get("@version").is_none() {
            data.insert("@version", Value::from("1"));
        }
        let metadata = match data.remove("@metadata") {
            Some(Value::Map(map)) => map,
            _ => Map::new(),
        };
        if let Some(tags) = data.get("tags").cloned()
            && !legal_tag_value(&tags)
        {
            data.insert("_tags", Value::Array(vec![tags]));
            data.insert("tags", Value::Array(vec![Value::from("_tagsparsefailure")]));
        }
        let provided = data.get("@timestamp").cloned();
        let parsed = match &provided {
            Some(Value::Timestamp(timestamp)) => Some(*timestamp),
            Some(Value::String(text)) => DateTime::parse_from_rfc3339(text)
                .ok()
                .map(|timestamp| timestamp.with_timezone(&Utc)),
            Some(Value::Null) | None => Some(utc_now()),
            Some(_) => None,
        };
        let mut event = Self {
            data,
            metadata,
            cancelled: false,
        };
        match parsed {
            Some(timestamp) => {
                event.data.insert("@timestamp", Value::Timestamp(timestamp));
            }
            None => {
                event.data.insert("@timestamp", Value::Timestamp(utc_now()));
                event.tag("_timestampparsefailure");
                if let Some(original) = provided {
                    event.data.insert("_@timestamp", original);
                }
            }
        }
        event
    }

    /// Java `Event.tag`. The first tag creates a list. A repeated tag is not added again.
    pub fn tag(&mut self, tag: &str) {
        let tag_value = Value::from(tag);
        match self.data.get("tags").cloned() {
            None | Some(Value::Null) => {
                self.data.insert("tags", Value::Array(vec![tag_value]));
            }
            Some(Value::Array(mut items)) => {
                if !items.iter().any(|item| item == &tag_value) {
                    items.push(tag_value);
                    self.data.insert("tags", Value::Array(items));
                }
            }
            Some(Value::String(existing)) => {
                let mut items = vec![Value::String(existing)];
                if items[0] != tag_value {
                    items.push(tag_value);
                }
                self.data.insert("tags", Value::Array(items));
            }
            Some(_) => {}
        }
    }

    /// Java `Event.append` / `Util.mapMerge` on the field map.
    pub fn append(&mut self, other: &Event) {
        map_merge(&mut self.data, &other.data);
    }

    /// Java `Event.toString`: timestamp, host, message. Missing host or message stays a sprintf token.
    pub fn plain_string(&self) -> String {
        let host = match self.get_field("host").ok().flatten() {
            Some(value) => value.to_string(),
            None => String::from("%{host}"),
        };
        let message = match self.get_field("message").ok().flatten() {
            Some(value) => value.to_string(),
            None => String::from("%{message}"),
        };
        let body = format!("{host} {message}");
        match self.timestamp() {
            Some(timestamp) => format!("{} {body}", format_timestamp(timestamp)),
            None => body,
        }
    }

    /// Java `Event#includes`: the key is present, including when its value is null.
    pub fn includes(&self, reference: &str) -> Result<bool, EventError> {
        let field = field::parse_field(reference)?;
        Ok(match field.target {
            Target::Data => contains_path(&self.data, &field.path, &field.key),
            Target::Metadata => contains_path(&self.metadata, &field.path, &field.key),
            Target::MetadataRoot => true,
        })
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

fn contains_path(map: &Map, path: &[String], key: &str) -> bool {
    if path.is_empty() {
        return map.get(key).is_some();
    }
    match map.get(&path[0]) {
        Some(value) => contains_value(value, &path[1..], key),
        None => false,
    }
}

fn contains_value(value: &Value, path: &[String], key: &str) -> bool {
    if path.is_empty() {
        return match value {
            Value::Map(map) => map.get(key).is_some(),
            Value::Array(items) => list_index(key, items.len()).is_some(),
            _ => false,
        };
    }
    match value {
        Value::Map(map) => contains_path(map, path, key),
        Value::Array(items) => {
            let Some(index) = list_index(&path[0], items.len()) else {
                return false;
            };
            items
                .get(index)
                .is_some_and(|child| contains_value(child, &path[1..], key))
        }
        _ => false,
    }
}

fn descend_get<'a>(map: &'a Map, path: &[String], key: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return present(fetch_map(map, key));
    }
    present(lookup_value(fetch_map(map, &path[0])?, &path[1..], key))
}

fn lookup_value<'a>(value: &'a Value, path: &[String], key: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return fetch_value(value, key);
    }
    lookup_value(fetch_value(value, &path[0])?, &path[1..], key)
}

fn fetch_map<'a>(map: &'a Map, key: &str) -> Option<&'a Value> {
    map.get(key)
}

fn fetch_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Map(map) => map.get(key),
        Value::Array(items) => {
            let index = list_index(key, items.len())?;
            items.get(index)
        }
        _ => None,
    }
}

fn present(value: Option<&Value>) -> Option<&Value> {
    match value {
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
    if map.get(head).is_none() {
        map.insert(head.clone(), Value::Map(Map::new()));
    }
    let Some(current) = map.get_mut(head) else {
        return Err(invalid_field_set(key, &Value::Null, &value));
    };
    set_child(current, rest, key, value)
}

fn set_child(
    current: &mut Value,
    path: &[String],
    key: &str,
    value: Value,
) -> Result<(), EventError> {
    if path.is_empty() {
        return match current {
            Value::Map(map) => {
                map.insert(key, value);
                Ok(())
            }
            Value::Array(items) => set_on_list(items, key, value),
            other => Err(invalid_field_set(key, other, &value)),
        };
    }
    let head = &path[0];
    let rest = &path[1..];
    match current {
        Value::Map(map) => {
            if map.get(head).is_none() {
                map.insert(head.clone(), Value::Map(Map::new()));
            }
            let Some(child) = map.get_mut(head) else {
                return Err(invalid_field_set(key, &Value::Null, &value));
            };
            set_child(child, rest, key, value)
        }
        Value::Array(items) => {
            let Some(index) = list_index(head, items.len()) else {
                return Err(invalid_field_set(
                    head,
                    &Value::Array(items.clone()),
                    &value,
                ));
            };
            let Some(child) = items.get_mut(index) else {
                return Err(invalid_field_set(head, &Value::Array(Vec::new()), &value));
            };
            set_child(child, rest, key, value)
        }
        other => Err(invalid_field_set(head, other, &value)),
    }
}

/// `Accessors.setOnList`. A non-numeric key is ignored. Indexes past the end pad with null.
fn set_on_list(items: &mut Vec<Value>, key: &str, value: Value) -> Result<(), EventError> {
    let Ok(index) = parse_java_int(key) else {
        return Ok(());
    };
    let size = items.len() as i32;
    if index >= size {
        let mut cursor = size;
        while cursor < index {
            items.push(Value::Null);
            cursor += 1;
        }
        items.push(value);
        return Ok(());
    }
    let Some(at) = positive_index(index, items.len()) else {
        return Err(invalid_field_set(key, &Value::Array(items.clone()), &value));
    };
    if let Some(slot) = items.get_mut(at) {
        *slot = value;
    }
    Ok(())
}

fn remove_path(map: &mut Map, path: &[String], key: &str) -> Option<Value> {
    if path.is_empty() {
        return map.remove(key);
    }
    let head = &path[0];
    let rest = &path[1..];
    let child = map.get_mut(head)?;
    remove_child(child, rest, key)
}

fn remove_child(current: &mut Value, path: &[String], key: &str) -> Option<Value> {
    if path.is_empty() {
        return match current {
            Value::Map(map) => map.remove(key),
            Value::Array(items) => {
                let index = list_index(key, items.len())?;
                Some(items.remove(index))
            }
            _ => None,
        };
    }
    let head = &path[0];
    let rest = &path[1..];
    match current {
        Value::Map(map) => remove_child(map.get_mut(head)?, rest, key),
        Value::Array(items) => {
            let index = list_index(head, items.len())?;
            remove_child(items.get_mut(index)?, rest, key)
        }
        _ => None,
    }
}

fn list_index(key: &str, size: usize) -> Option<usize> {
    positive_index(parse_java_int(key).ok()?, size)
}

fn positive_index(index: i32, size: usize) -> Option<usize> {
    let resolved = if index < 0 {
        size as i32 + index
    } else {
        index
    };
    if resolved < 0 {
        return None;
    }
    let resolved = resolved as usize;
    if resolved >= size {
        None
    } else {
        Some(resolved)
    }
}

fn parse_java_int(key: &str) -> Result<i32, ()> {
    let text = key.strip_prefix('+').unwrap_or(key);
    text.parse::<i32>().map_err(|_| ())
}

fn reject_illegal_tags(field: &crate::field::FieldRef, value: &Value) -> Result<(), EventError> {
    let tags_child = field.path.first().is_some_and(|segment| segment == "tags");
    let tags_root = field.path.is_empty() && field.key == "tags";
    if tags_child || (tags_root && !legal_tag_value(value)) {
        Err(EventError::InvalidTags)
    } else {
        Ok(())
    }
}

fn legal_tag_value(value: &Value) -> bool {
    match value {
        Value::Null | Value::String(_) => true,
        Value::Array(items) => items.iter().all(|item| matches!(item, Value::String(_))),
        _ => false,
    }
}

fn map_merge(target: &mut Map, add: &Map) {
    for (key, entry) in add.iter() {
        match target.get(key).cloned() {
            None | Some(Value::Null) => target.insert(key, entry.clone()),
            Some(Value::Map(mut child)) => match entry {
                Value::Map(extra) => {
                    map_merge(&mut child, extra);
                    target.insert(key, Value::Map(child));
                }
                other => merge_scalar(target, key, &Value::Map(child), other),
            },
            Some(existing) => merge_scalar(target, key, &existing, entry),
        }
    }
}

fn merge_scalar(target: &mut Map, key: &str, existing: &Value, entry: &Value) {
    match (existing, entry) {
        (Value::Map(_), Value::Map(_)) => {}
        (_, Value::Array(incoming)) => {
            if let Value::Array(current) = existing {
                target.insert(key, Value::Array(union_lists(current, incoming)));
            } else {
                let mut merged = vec![existing.clone()];
                for item in incoming {
                    if item != existing {
                        merged.push(item.clone());
                    }
                }
                target.insert(key, Value::Array(merged));
            }
        }
        (Value::Array(current), _) => {
            if !current.iter().any(|item| item == entry) {
                let mut merged = current.clone();
                merged.push(entry.clone());
                target.insert(key, Value::Array(merged));
            }
        }
        _ if existing != entry => {
            target.insert(key, Value::Array(vec![existing.clone(), entry.clone()]));
        }
        _ => {}
    }
}

fn union_lists(target: &[Value], source: &[Value]) -> Vec<Value> {
    let mut merged = target.to_vec();
    for item in source {
        if !merged.iter().any(|existing| existing == item) {
            merged.push(item.clone());
        }
    }
    merged
}

fn json_to_map(value: &serde_json::Value) -> Result<Map, EventError> {
    let serde_json::Value::Object(object) = value else {
        return Err(EventError::Json {
            message: String::from("json event must be an object"),
        });
    };
    let mut map = Map::new();
    for (key, child) in object {
        map.insert(key, json_to_value(child)?);
    }
    Ok(map)
}

fn json_to_value(value: &serde_json::Value) -> Result<Value, EventError> {
    Ok(match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(flag) => Value::Boolean(*flag),
        serde_json::Value::Number(number) => {
            if number.to_string().contains(['.', 'e', 'E']) {
                Value::Float(number.as_f64().ok_or_else(|| EventError::Json {
                    message: String::from("float is not a JSON number"),
                })?)
            } else if let Some(integer) = number.as_i64() {
                Value::Integer(i128::from(integer))
            } else if let Some(integer) = number.as_u64() {
                Value::Integer(i128::from(integer))
            } else {
                return Err(EventError::Json {
                    message: String::from("integer is outside i128"),
                });
            }
        }
        serde_json::Value::String(text) => Value::String(text.clone()),
        serde_json::Value::Array(items) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                values.push(json_to_value(item)?);
            }
            Value::Array(values)
        }
        serde_json::Value::Object(_) => Value::Map(json_to_map(value)?),
    })
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
        Value::Integer(number) => {
            if let Ok(small) = i64::try_from(*number) {
                serde_json::Value::Number(small.into())
            } else {
                serde_json::Value::String(number.to_string())
            }
        }
        Value::Float(number) => serde_json::Number::from_f64(*number)
            .map(serde_json::Value::Number)
            .ok_or_else(|| EventError::Json {
                message: String::from("float is not a JSON number"),
            })?,
        Value::Boolean(flag) => serde_json::Value::Bool(*flag),
        Value::Timestamp(timestamp) => serde_json::Value::String(format_timestamp(*timestamp)),
        Value::Decimal(decimal) => {
            if let Ok(integer) = decimal.as_str().parse::<i64>() {
                serde_json::Value::Number(integer.into())
            } else if let Ok(number) = decimal.as_str().parse::<f64>() {
                serde_json::Number::from_f64(number)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| EventError::Json {
                        message: String::from("decimal is not a JSON number"),
                    })?
            } else {
                serde_json::Value::String(decimal.as_str().to_string())
            }
        }
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
