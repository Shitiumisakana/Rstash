//! `logstash-codec-avro` 3.5.0 for one Avro datum, not an Avro container file.
//!
//! `schema_uri` is a local path or a `file://` URI. `http://` and `https://`
//! are refused, and so are `ssl_enabled => true` and `proxy`. Named types that
//! are not written inline are refused. `encoding => binary` is the raw datum;
//! the output path carries UTF-8, so a datum that is not UTF-8 fails instead of
//! being rewritten. The default `base64` encoding uses strict Base64 and, on
//! failure, the raw bytes, matching the gem's `strict_decode64` rescue.

use std::fs;

use serde_json::Value as Json;

use crate::event::Event;
use crate::lscl::{Arg, Plugin};
use crate::run::{Ecs, RunError, fail};
use crate::value::{Map, Value};

pub(crate) fn missing_schema() -> String {
    "Missing a required setting for the avro codec plugin:\n\n  codec {\n    avro {\n      schema_uri => # SETTING MISSING\n      ...\n    }\n  }"
        .to_string()
}

pub(crate) fn prepare(codec: &Plugin) -> Result<(), RunError> {
    let _ = load(codec)?;
    Ok(())
}

pub(crate) fn encode(codec: &Plugin, event: &Event) -> Result<String, RunError> {
    let schema = load(codec)?;
    let bytes = write_record(&schema, &Source::Event(event))?;
    match encoding_of(codec)? {
        Encoding::Base64 => Ok(base64_encode(&bytes)),
        Encoding::Binary => {
            String::from_utf8(bytes).map_err(|_| fail("avro encoding binary is not valid utf-8"))
        }
    }
}

pub(crate) fn decode(codec: &Plugin, data: &[u8], ecs: Ecs) -> Result<Event, RunError> {
    let schema = load(codec)?;
    let datum = datum_bytes(encoding_of(codec)?, data);
    let tagged = failure_tag(codec)?;
    match read_event(codec, &schema, &datum, ecs, data) {
        Ok(event) => Ok(event),
        Err(_) if tagged => Ok(failure_event(data)),
        Err(error) => Err(error),
    }
}

fn load(codec: &Plugin) -> Result<Schema, RunError> {
    refuse_remote(codec)?;
    let uri = arg_string(codec, "schema_uri").ok_or_else(|| fail(missing_schema()))?;
    let _ = encoding_of(codec)?;
    let _ = failure_tag(codec)?;
    let path = uri.strip_prefix("file://").unwrap_or(uri.as_str());
    let text = fs::read_to_string(path)
        .map_err(|error| fail(format!("avro schema_uri {path} could not be read: {error}")))?;
    let json: Json = serde_json::from_str(&text)
        .map_err(|error| fail(format!("avro schema is invalid: {error}")))?;
    let schema = parse_schema(&json)?;
    if !matches!(schema, Schema::Record { .. }) {
        return Err(fail("avro schema must be a record"));
    }
    Ok(schema)
}

fn refuse_remote(codec: &Plugin) -> Result<(), RunError> {
    if arg_string(codec, "ssl_enabled").as_deref() == Some("true") {
        return Err(fail("plugin avro ssl_enabled is not implemented"));
    }
    if arg_string(codec, "proxy").is_some() {
        return Err(fail("avro proxy is not implemented"));
    }
    if let Some(uri) = arg_string(codec, "schema_uri") {
        if uri.starts_with("https://") {
            return Err(fail("avro schema https is not implemented"));
        }
        if uri.starts_with("http://") {
            return Err(fail("avro schema http is not implemented"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Base64,
    Binary,
}

fn encoding_of(codec: &Plugin) -> Result<Encoding, RunError> {
    match arg_string(codec, "encoding").as_deref() {
        None | Some("base64") => Ok(Encoding::Base64),
        Some("binary") => Ok(Encoding::Binary),
        Some(other) => Err(fail(format!(
            "Expected one of [\"binary\", \"base64\"], got \"{other}\""
        ))),
    }
}

fn failure_tag(codec: &Plugin) -> Result<bool, RunError> {
    match arg_string(codec, "tag_on_failure").as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(other) => Err(fail(format!(
            "Expected boolean 'true' or 'false', got \"{other}\""
        ))),
    }
}

fn datum_bytes(encoding: Encoding, data: &[u8]) -> Vec<u8> {
    if encoding == Encoding::Binary {
        return data.to_vec();
    }
    match std::str::from_utf8(data) {
        Ok(text) => base64_decode(text).unwrap_or_else(|| data.to_vec()),
        Err(_) => data.to_vec(),
    }
}

fn read_event(
    codec: &Plugin,
    schema: &Schema,
    datum: &[u8],
    ecs: Ecs,
    original: &[u8],
) -> Result<Event, RunError> {
    let mut reader = Reader {
        data: datum,
        pos: 0,
    };
    let value = read_schema(&mut reader, schema)?;
    let Value::Map(fields) = value else {
        return Err(fail("avro schema must be a record"));
    };
    let mut event = Event::new();
    if let Some(target) = arg_string(codec, "target") {
        event
            .set_field(&target, Value::Map(fields))
            .map_err(|error| fail(error.to_string()))?;
    } else {
        for (name, value) in fields.iter() {
            event
                .set_field(name, value.clone())
                .map_err(|error| fail(error.to_string()))?;
        }
    }
    if ecs != Ecs::Disabled {
        event
            .set_field(
                "[event][original]",
                Value::from(String::from_utf8_lossy(original).to_string()),
            )
            .map_err(|error| fail(error.to_string()))?;
    }
    Ok(event)
}

fn failure_event(data: &[u8]) -> Event {
    let mut event = Event::new();
    let _ = event.set_field(
        "message",
        Value::from(String::from_utf8_lossy(data).to_string()),
    );
    event.tag("_avroparsefailure");
    event
}

enum Source<'a> {
    Event(&'a Event),
    Map(&'a Map),
}

fn write_record(schema: &Schema, source: &Source<'_>) -> Result<Vec<u8>, RunError> {
    let Schema::Record { fields } = schema else {
        return Err(fail("avro schema must be a record"));
    };
    let mut bytes = Vec::new();
    for field in fields {
        let value = lookup(source, &field.name)?;
        match value {
            Some(value) => write_schema(&mut bytes, &field.schema, &value)?,
            None => match &field.default {
                Some(default) => write_schema(&mut bytes, &field.schema, &json_to_value(default))?,
                None => {
                    return Err(fail(format!("avro field {} is missing", field.name)));
                }
            },
        }
    }
    Ok(bytes)
}

fn lookup(source: &Source<'_>, name: &str) -> Result<Option<Value>, RunError> {
    match source {
        Source::Event(event) => {
            if event
                .includes(name)
                .map_err(|error| fail(error.to_string()))?
            {
                Ok(Some(
                    event
                        .get_field(name)
                        .map_err(|error| fail(error.to_string()))?
                        .unwrap_or(Value::Null),
                ))
            } else {
                Ok(None)
            }
        }
        Source::Map(map) => Ok(map.get(name).cloned()),
    }
}

struct Field {
    name: String,
    schema: Schema,
    default: Option<Json>,
}

enum Schema {
    Null,
    Boolean,
    Int,
    Long,
    Float,
    Double,
    Bytes,
    String,
    Record { fields: Vec<Field> },
    Enum { symbols: Vec<String> },
    Array(Box<Schema>),
    Map(Box<Schema>),
    Union(Vec<Schema>),
    Fixed(usize),
}

fn parse_schema(value: &Json) -> Result<Schema, RunError> {
    match value {
        Json::String(name) => primitive(name),
        Json::Array(items) => parse_union(items),
        Json::Object(map) => parse_object(map),
        _ => Err(fail("avro schema is invalid: expected a type")),
    }
}

fn primitive(name: &str) -> Result<Schema, RunError> {
    Ok(match name {
        "null" => Schema::Null,
        "boolean" => Schema::Boolean,
        "int" => Schema::Int,
        "long" => Schema::Long,
        "float" => Schema::Float,
        "double" => Schema::Double,
        "bytes" => Schema::Bytes,
        "string" => Schema::String,
        other => return Err(fail(format!("avro type {other} is not implemented"))),
    })
}

fn parse_union(items: &[Json]) -> Result<Schema, RunError> {
    if items.is_empty() {
        return Err(fail("avro schema is invalid: empty union"));
    }
    let mut branches = Vec::new();
    for item in items {
        if item.is_array() {
            return Err(fail("avro schema is invalid: union cannot contain a union"));
        }
        branches.push(parse_schema(item)?);
    }
    Ok(Schema::Union(branches))
}

fn parse_object(map: &serde_json::Map<String, Json>) -> Result<Schema, RunError> {
    let type_value = map
        .get("type")
        .ok_or_else(|| fail("avro schema is invalid: missing type"))?;
    match type_value {
        Json::String(name) if name == "record" => {
            let fields = map
                .get("fields")
                .and_then(Json::as_array)
                .ok_or_else(|| fail("avro schema is invalid: record fields"))?;
            let mut parsed = Vec::new();
            for field in fields {
                let object = field
                    .as_object()
                    .ok_or_else(|| fail("avro schema is invalid: record field"))?;
                let name = object
                    .get("name")
                    .and_then(Json::as_str)
                    .ok_or_else(|| fail("avro schema is invalid: record field name"))?;
                let schema = parse_schema(
                    object
                        .get("type")
                        .ok_or_else(|| fail("avro schema is invalid: record field type"))?,
                )?;
                parsed.push(Field {
                    name: name.to_string(),
                    schema,
                    default: object.get("default").cloned(),
                });
            }
            Ok(Schema::Record { fields: parsed })
        }
        Json::String(name) if name == "enum" => {
            let symbols = map
                .get("symbols")
                .and_then(Json::as_array)
                .ok_or_else(|| fail("avro schema is invalid: enum symbols"))?;
            let mut names = Vec::new();
            for symbol in symbols {
                let text = symbol
                    .as_str()
                    .ok_or_else(|| fail("avro schema is invalid: enum symbol"))?;
                names.push(text.to_string());
            }
            Ok(Schema::Enum { symbols: names })
        }
        Json::String(name) if name == "array" => {
            let items = map
                .get("items")
                .ok_or_else(|| fail("avro schema is invalid: array items"))?;
            Ok(Schema::Array(Box::new(parse_schema(items)?)))
        }
        Json::String(name) if name == "map" => {
            let values = map
                .get("values")
                .ok_or_else(|| fail("avro schema is invalid: map values"))?;
            Ok(Schema::Map(Box::new(parse_schema(values)?)))
        }
        Json::String(name) if name == "fixed" => {
            let size = map
                .get("size")
                .and_then(Json::as_u64)
                .ok_or_else(|| fail("avro schema is invalid: fixed size"))?;
            Ok(Schema::Fixed(
                usize::try_from(size).map_err(|error| fail(error.to_string()))?,
            ))
        }
        Json::String(name) => primitive(name),
        Json::Array(items) => parse_union(items),
        _ => Err(fail("avro schema is invalid: type")),
    }
}

fn json_to_value(json: &Json) -> Value {
    match json {
        Json::Null => Value::Null,
        Json::Bool(value) => Value::Boolean(*value),
        Json::Number(number) => {
            if let Some(value) = number.as_i64() {
                Value::Integer(i128::from(value))
            } else if let Some(value) = number.as_u64() {
                Value::Integer(i128::from(value))
            } else {
                Value::Float(number.as_f64().unwrap_or(0.0))
            }
        }
        Json::String(value) => Value::from(value.clone()),
        Json::Array(items) => Value::Array(items.iter().map(json_to_value).collect()),
        Json::Object(map) => {
            let mut fields = Map::new();
            for (key, value) in map {
                fields.insert(key.clone(), json_to_value(value));
            }
            Value::Map(fields)
        }
    }
}

fn write_schema(out: &mut Vec<u8>, schema: &Schema, value: &Value) -> Result<(), RunError> {
    match schema {
        Schema::Null => {
            if !matches!(value, Value::Null) {
                return Err(fail("avro value is not null"));
            }
        }
        Schema::Boolean => {
            let Value::Boolean(flag) = value else {
                return Err(fail("avro value is not a boolean"));
            };
            out.push(u8::from(*flag));
        }
        Schema::Int => write_long(out, i64::from(int_value(value)?)),
        Schema::Long => write_long(out, long_value(value)?),
        Schema::Float => out.extend(float_value(value)?.to_le_bytes()),
        Schema::Double => out.extend(double_value(value)?.to_le_bytes()),
        Schema::Bytes | Schema::String => write_bytes(out, text_bytes(value)?)?,
        Schema::Fixed(size) => {
            let bytes = text_bytes(value)?;
            if bytes.len() != *size {
                return Err(fail(format!(
                    "avro fixed value has length {}, expected {size}",
                    bytes.len()
                )));
            }
            out.extend(bytes);
        }
        Schema::Enum { symbols } => {
            let Value::String(text) = value else {
                return Err(fail("avro value is not an enum symbol"));
            };
            let index = symbols
                .iter()
                .position(|symbol| symbol == text)
                .ok_or_else(|| fail(format!("avro enum symbol {text} is not in the schema")))?;
            write_long(
                out,
                i64::try_from(index).map_err(|error| fail(error.to_string()))?,
            );
        }
        Schema::Array(item) => {
            let Value::Array(items) = value else {
                return Err(fail("avro value is not an array"));
            };
            if !items.is_empty() {
                write_long(
                    out,
                    i64::try_from(items.len()).map_err(|error| fail(error.to_string()))?,
                );
                for item_value in items {
                    write_schema(out, item, item_value)?;
                }
            }
            write_long(out, 0);
        }
        Schema::Map(item) => {
            let Value::Map(map) = value else {
                return Err(fail("avro value is not a map"));
            };
            let entries: Vec<(&str, &Value)> = map.iter().collect();
            if !entries.is_empty() {
                write_long(
                    out,
                    i64::try_from(entries.len()).map_err(|error| fail(error.to_string()))?,
                );
                for (key, item_value) in entries {
                    write_bytes(out, key.as_bytes())?;
                    write_schema(out, item, item_value)?;
                }
            }
            write_long(out, 0);
        }
        Schema::Union(branches) => {
            let index = branches
                .iter()
                .position(|branch| value_matches(branch, value))
                .ok_or_else(|| fail("avro value does not match a union branch"))?;
            write_long(
                out,
                i64::try_from(index).map_err(|error| fail(error.to_string()))?,
            );
            write_schema(out, &branches[index], value)?;
        }
        Schema::Record { .. } => {
            let Value::Map(map) = value else {
                return Err(fail("avro value is not a record"));
            };
            let nested = write_record(schema, &Source::Map(map))?;
            out.extend(nested);
        }
    }
    Ok(())
}

fn value_matches(schema: &Schema, value: &Value) -> bool {
    match schema {
        Schema::Null => matches!(value, Value::Null),
        Schema::Boolean => matches!(value, Value::Boolean(_)),
        Schema::Int => int_value(value).is_ok(),
        Schema::Long => long_value(value).is_ok(),
        Schema::Float | Schema::Double => matches!(value, Value::Float(_) | Value::Integer(_)),
        Schema::Bytes | Schema::String => matches!(value, Value::String(_)),
        Schema::Fixed(size) => {
            matches!(value, Value::String(text) if text.len() == *size)
        }
        Schema::Enum { symbols } => {
            matches!(value, Value::String(text) if symbols.iter().any(|symbol| symbol == text))
        }
        Schema::Array(_) => matches!(value, Value::Array(_)),
        Schema::Map(_) | Schema::Record { .. } => matches!(value, Value::Map(_)),
        Schema::Union(_) => false,
    }
}

fn int_value(value: &Value) -> Result<i32, RunError> {
    let Value::Integer(number) = value else {
        return Err(fail("avro value is not an int"));
    };
    i32::try_from(*number).map_err(|_| fail(format!("avro int {number} is out of range")))
}

fn long_value(value: &Value) -> Result<i64, RunError> {
    let Value::Integer(number) = value else {
        return Err(fail("avro value is not a long"));
    };
    i64::try_from(*number).map_err(|_| fail(format!("avro long {number} is out of range")))
}

fn float_value(value: &Value) -> Result<f32, RunError> {
    match value {
        Value::Float(number) => Ok(*number as f32),
        Value::Integer(number) => Ok(*number as f32),
        _ => Err(fail("avro value is not a float")),
    }
}

fn double_value(value: &Value) -> Result<f64, RunError> {
    match value {
        Value::Float(number) => Ok(*number),
        Value::Integer(number) => Ok(*number as f64),
        _ => Err(fail("avro value is not a double")),
    }
}

fn text_bytes(value: &Value) -> Result<&[u8], RunError> {
    let Value::String(text) = value else {
        return Err(fail("avro value is not a string"));
    };
    Ok(text.as_bytes())
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RunError> {
    write_long(
        out,
        i64::try_from(bytes.len()).map_err(|error| fail(error.to_string()))?,
    );
    out.extend(bytes);
    Ok(())
}

fn write_long(out: &mut Vec<u8>, value: i64) {
    let mut encoded = ((value.wrapping_shl(1)) ^ (value >> 63)) as u64;
    loop {
        let mut byte = (encoded & 0x7f) as u8;
        encoded >>= 7;
        if encoded != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if encoded == 0 {
            break;
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn read_schema(&mut self, schema: &Schema) -> Result<Value, RunError> {
        match schema {
            Schema::Null => Ok(Value::Null),
            Schema::Boolean => {
                let byte = self.byte()?;
                match byte {
                    0 => Ok(Value::Boolean(false)),
                    1 => Ok(Value::Boolean(true)),
                    _ => Err(fail(format!("avro boolean byte {byte} is not 0 or 1"))),
                }
            }
            Schema::Int => {
                let value = self.read_long()?;
                i32::try_from(value)
                    .map(|value| Value::Integer(i128::from(value)))
                    .map_err(|_| fail(format!("avro int {value} is out of range")))
            }
            Schema::Long => Ok(Value::Integer(i128::from(self.read_long()?))),
            Schema::Float => {
                let bytes = self.take(4)?;
                let mut wide = [0u8; 4];
                wide.copy_from_slice(bytes);
                Ok(Value::Float(f64::from(f32::from_le_bytes(wide))))
            }
            Schema::Double => {
                let bytes = self.take(8)?;
                let mut wide = [0u8; 8];
                wide.copy_from_slice(bytes);
                Ok(Value::Float(f64::from_le_bytes(wide)))
            }
            Schema::Bytes | Schema::String => Ok(Value::from(self.read_text()?)),
            Schema::Fixed(size) => Ok(Value::from(self.read_text_len(*size)?)),
            Schema::Enum { symbols } => {
                let index =
                    usize::try_from(self.read_long()?).map_err(|error| fail(error.to_string()))?;
                let symbol = symbols.get(index).ok_or_else(|| {
                    fail(format!("avro enum index {index} is outside the schema"))
                })?;
                Ok(Value::from(symbol.clone()))
            }
            Schema::Array(item) => {
                let mut items = Vec::new();
                loop {
                    let count = self.read_long()?;
                    if count == 0 {
                        break;
                    }
                    let count = if count < 0 {
                        let _size = self.read_long()?;
                        -count
                    } else {
                        count
                    };
                    let count = usize::try_from(count).map_err(|error| fail(error.to_string()))?;
                    for _ in 0..count {
                        items.push(self.read_schema(item)?);
                    }
                }
                Ok(Value::Array(items))
            }
            Schema::Map(item) => {
                let mut map = Map::new();
                loop {
                    let count = self.read_long()?;
                    if count == 0 {
                        break;
                    }
                    let count = if count < 0 {
                        let _size = self.read_long()?;
                        -count
                    } else {
                        count
                    };
                    let count = usize::try_from(count).map_err(|error| fail(error.to_string()))?;
                    for _ in 0..count {
                        let key = self.read_text()?;
                        map.insert(key, self.read_schema(item)?);
                    }
                }
                Ok(Value::Map(map))
            }
            Schema::Union(branches) => {
                let index =
                    usize::try_from(self.read_long()?).map_err(|error| fail(error.to_string()))?;
                let branch = branches.get(index).ok_or_else(|| {
                    fail(format!("avro union index {index} is outside the schema"))
                })?;
                self.read_schema(branch)
            }
            Schema::Record { fields } => {
                let mut map = Map::new();
                for field in fields {
                    map.insert(field.name.clone(), self.read_schema(&field.schema)?);
                }
                Ok(Value::Map(map))
            }
        }
    }

    fn read_text(&mut self) -> Result<String, RunError> {
        let length = usize::try_from(self.read_long()?).map_err(|error| fail(error.to_string()))?;
        self.read_text_len(length)
    }

    fn read_text_len(&mut self, length: usize) -> Result<String, RunError> {
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| fail("avro bytes are not valid utf-8"))
    }

    fn read_long(&mut self) -> Result<i64, RunError> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.byte()?;
            if shift == 63 && byte & 0x7f > 1 {
                return Err(fail("avro varint is too long"));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return Err(fail("avro varint is too long"));
            }
        }
        Ok(((value >> 1) as i64) ^ -((value & 1) as i64))
    }

    fn byte(&mut self) -> Result<u8, RunError> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or_else(|| fail("avro datum ended early"))?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RunError> {
        let end = self
            .pos
            .checked_add(length)
            .ok_or_else(|| fail("avro datum ended early"))?;
        if end > self.data.len() {
            return Err(fail("avro datum ended early"));
        }
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}

fn read_schema(reader: &mut Reader<'_>, schema: &Schema) -> Result<Value, RunError> {
    reader.read_schema(schema)
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

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        let packed = (u32::from(data[index]) << 16)
            | (u32::from(data[index + 1]) << 8)
            | u32::from(data[index + 2]);
        push_base64(&mut out, packed, 4);
        index += 3;
    }
    let rest = data.len() - index;
    if rest == 1 {
        let packed = u32::from(data[index]) << 16;
        push_base64(&mut out, packed, 2);
        out.push('=');
        out.push('=');
    } else if rest == 2 {
        let packed = (u32::from(data[index]) << 16) | (u32::from(data[index + 1]) << 8);
        push_base64(&mut out, packed, 3);
        out.push('=');
    }
    fn push_base64(out: &mut String, packed: u32, count: usize) {
        let shifts = [18, 12, 6, 0];
        for shift in shifts.into_iter().take(count) {
            out.push(ALPHABET[((packed >> shift) & 63) as usize] as char);
        }
    }
    out
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let chunk = &bytes[index..index + 4];
        let pads = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if pads > 2 || (index + 4 != bytes.len() && pads != 0) {
            return None;
        }
        let mut packed = 0u32;
        for (place, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                if place < 4 - pads {
                    return None;
                }
                continue;
            }
            packed = (packed << 6) | u32::from(base64_value(*byte)?);
        }
        packed <<= 6 * pads;
        out.push((packed >> 16) as u8);
        if pads < 2 {
            out.push((packed >> 8) as u8);
        }
        if pads < 1 {
            out.push(packed as u8);
        }
        index += 4;
    }
    Some(out)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_with(message: &str) -> Event {
        let mut event = Event::new();
        event
            .set_field("message", Value::from(message))
            .expect("message");
        event
    }

    #[test]
    fn string_datum_matches_the_avro_binary_encoding() {
        let schema =
            r#"{"type":"record","name":"E","fields":[{"name":"message","type":"string"}]}"#;
        let json: Json = serde_json::from_str(schema).expect("schema");
        let parsed = parse_schema(&json).expect("parse");
        let bytes = write_record(&parsed, &Source::Event(&event_with("hello"))).expect("write");
        assert_eq!(bytes, vec![0x0a, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(base64_encode(&bytes), "CmhlbGxv");
        let mut reader = Reader {
            data: &bytes,
            pos: 0,
        };
        let Value::Map(fields) = read_schema(&mut reader, &parsed).expect("read") else {
            panic!("record");
        };
        assert_eq!(fields.get("message"), Some(&Value::from("hello")));
    }

    #[test]
    fn default_union_and_array_round_trip() {
        let schema = r#"{"type":"record","name":"E","fields":[
            {"name":"message","type":"string"},
            {"name":"n","type":"int","default":1},
            {"name":"color","type":["null","string"],"default":null},
            {"name":"flags","type":{"type":"array","items":"boolean"}}
        ]}"#;
        let json: Json = serde_json::from_str(schema).expect("schema");
        let parsed = parse_schema(&json).expect("parse");
        let mut event = event_with("a");
        event
            .set_field(
                "flags",
                Value::Array(vec![Value::Boolean(true), Value::Boolean(false)]),
            )
            .expect("flags");
        let bytes = write_record(&parsed, &Source::Event(&event)).expect("write");
        let mut reader = Reader {
            data: &bytes,
            pos: 0,
        };
        let Value::Map(fields) = read_schema(&mut reader, &parsed).expect("read") else {
            panic!("record");
        };
        assert_eq!(fields.get("n"), Some(&Value::Integer(1)));
        assert_eq!(fields.get("color"), Some(&Value::Null));
        assert_eq!(
            fields.get("flags"),
            Some(&Value::Array(vec![
                Value::Boolean(true),
                Value::Boolean(false)
            ]))
        );
    }

    #[test]
    fn zigzag_matches_the_avro_spec() {
        let samples = [
            (0i64, vec![0u8]),
            (-1, vec![1]),
            (1, vec![2]),
            (64, vec![128, 1]),
        ];
        for (value, expected) in samples {
            let mut bytes = Vec::new();
            write_long(&mut bytes, value);
            assert_eq!(bytes, expected, "{value}");
            let mut reader = Reader {
                data: &bytes,
                pos: 0,
            };
            assert_eq!(reader.read_long().expect("long"), value);
        }
    }
}
