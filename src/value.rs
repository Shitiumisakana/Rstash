use std::fmt::{self, Display, Formatter};

use chrono::{DateTime, Utc};

/// One Logstash field value.
///
/// Maps keep insertion order. sprintf of a map sorts keys when it emits JSON.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    String(String),
    Integer(i128),
    Float(f64),
    Boolean(bool),
    Timestamp(DateTime<Utc>),
    /// Exact decimal, the in-memory stand-in for Ruby `BigDecimal`.
    Decimal(Decimal),
    Array(Vec<Value>),
    Map(Map),
}

/// A base-10 decimal kept as text so `1` stays `1`, not a binary float.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decimal {
    text: String,
}

impl Decimal {
    pub fn exact(text: &str) -> Self {
        Self {
            text: text.to_string(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Map {
    entries: Vec<(String, Value)>,
}

impl Map {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value))
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(existing, _)| existing == key)
            .map(|(_, value)| value)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.entries
            .iter_mut()
            .find(|(existing, _)| existing == key)
            .map(|(_, value)| value)
    }

    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        if let Some((_, slot)) = self
            .entries
            .iter_mut()
            .find(|(existing, _)| existing == &key)
        {
            *slot = value;
        } else {
            self.entries.push((key, value));
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let index = self
            .entries
            .iter()
            .position(|(existing, _)| existing == key)?;
        Some(self.entries.remove(index).1)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Value::String(value.to_string())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Value::String(value)
    }
}

impl Default for Map {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Value {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => formatter.write_str("null"),
            Value::String(text) => formatter.write_str(text),
            Value::Integer(value) => write!(formatter, "{value}"),
            Value::Float(value) => write!(formatter, "{value}"),
            Value::Boolean(value) => write!(formatter, "{value}"),
            Value::Timestamp(timestamp) => {
                formatter.write_str(&crate::timefmt::format_timestamp(*timestamp))
            }
            Value::Decimal(decimal) => formatter.write_str(decimal.as_str()),
            Value::Array(items) => {
                formatter.write_str("[")?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{item}")?;
                }
                formatter.write_str("]")
            }
            Value::Map(map) => {
                formatter.write_str("{")?;
                for (index, (key, value)) in map.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{key}={value}")?;
                }
                formatter.write_str("}")
            }
        }
    }
}
