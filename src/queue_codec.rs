//! Jackson CBOR for `Event.serialize` in logstash-core 9.5.2.
//!
//! The bytes are tag 256 around `[java.util.HashMap, {DATA, META}]`.
//! `DATA` is a `ConvertedMap`. Strings that came from JRuby are wrapped as
//! `org.jruby.RubyString`. `@timestamp` is `org.logstash.Timestamp`. An empty
//! metadata map is tag 25, integer 2, then an empty map.

use chrono::{DateTime, Utc};

use crate::event::Event;
use crate::run::{RunError, fail};
use crate::timefmt::format_timestamp;
use crate::value::{Map, Value};

pub(crate) fn encode_event(event: &Event) -> Vec<u8> {
    let mut out = vec![0xd9, 0x01, 0x00, 0x9f];
    write_text(&mut out, "java.util.HashMap");
    out.push(0xbf);
    write_text(&mut out, "DATA");
    write_converted_map(&mut out, event.field_map());
    write_text(&mut out, "META");
    if event.metadata_map().is_empty() {
        out.extend_from_slice(&[0x9f, 0xd8, 0x19, 0x02, 0xbf, 0xff, 0xff]);
    } else {
        write_converted_map(&mut out, event.metadata_map());
    }
    out.push(0xff);
    out.push(0xff);
    out
}

pub(crate) fn decode_event(bytes: &[u8]) -> Result<Event, RunError> {
    let (value, offset) = read_value(bytes, 0)?;
    if offset != bytes.len() {
        return Err(fail("event cbor has trailing bytes"));
    }
    let root = unwrap_typed(&value);
    let map = expect_map(&root)?;
    let mut data = Map::new();
    let mut metadata = Map::new();
    for (key, value) in map {
        let name = expect_text(key)?;
        if name == "META" {
            metadata = map_value(&unwrap_typed(value))?;
        } else if name == "DATA" {
            data = map_value(&unwrap_typed(value))?;
        }
    }
    if !metadata.is_empty() {
        data.insert("@metadata", Value::Map(metadata));
    }
    Ok(Event::from_data(data))
}

fn write_converted_map(out: &mut Vec<u8>, map: &Map) {
    out.push(0x9f);
    write_text(out, "org.logstash.ConvertedMap");
    out.push(0xbf);
    for (key, value) in map.iter() {
        write_text(out, key);
        write_field(out, key, value);
    }
    out.push(0xff);
    out.push(0xff);
}

fn write_field(out: &mut Vec<u8>, key: &str, value: &Value) {
    match value {
        Value::String(text) if key == "@version" => write_text(out, text),
        Value::String(text) => {
            out.push(0x9f);
            write_text(out, "org.jruby.RubyString");
            write_text(out, text);
            out.push(0xff);
        }
        Value::Timestamp(timestamp) => {
            out.push(0x9f);
            write_text(out, "org.logstash.Timestamp");
            write_text(out, &format_timestamp(*timestamp));
            out.push(0xff);
        }
        Value::Integer(number) => write_int(out, *number),
        Value::Float(number) => {
            out.push(0xfb);
            out.extend_from_slice(&number.to_be_bytes());
        }
        Value::Boolean(true) => out.push(0xf5),
        Value::Boolean(false) => out.push(0xf4),
        Value::Null => out.push(0xf6),
        Value::Decimal(decimal) => {
            out.push(0x9f);
            write_text(out, "org.jruby.RubyString");
            write_text(out, decimal.as_str());
            out.push(0xff);
        }
        Value::Array(items) => {
            out.push(0x9f);
            for item in items {
                write_field(out, "", item);
            }
            out.push(0xff);
        }
        Value::Map(map) => write_converted_map(out, map),
    }
}

fn write_text(out: &mut Vec<u8>, text: &str) {
    write_header(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

fn write_int(out: &mut Vec<u8>, number: i128) {
    if let Ok(number) = u64::try_from(number) {
        write_header(out, 0, number);
    } else if let Ok(number) = i64::try_from(number) {
        write_header(out, 1, (-1 - i128::from(number)) as u64);
    } else {
        out.push(0x9f);
        write_text(out, "org.jruby.RubyString");
        write_text(out, &number.to_string());
        out.push(0xff);
    }
}

fn write_header(out: &mut Vec<u8>, major: u8, len: u64) {
    let head = major << 5;
    if len < 24 {
        out.push(head | u8::try_from(len).unwrap_or(23));
    } else if len <= 0xff {
        out.push(head | 24);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(head | 25);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= 0xffff_ffff {
        out.push(head | 26);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        out.push(head | 27);
        out.extend_from_slice(&len.to_be_bytes());
    }
}

#[derive(Clone, Debug)]
enum Cbor {
    Uint(u64),
    Neg(u64),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Tag(u64, Box<Cbor>),
    Bool(bool),
    Null,
    Float(f64),
}

fn read_value(bytes: &[u8], index: usize) -> Result<(Cbor, usize), RunError> {
    if index >= bytes.len() {
        return Err(fail("truncated cbor"));
    }
    let initial = bytes[index];
    let major = initial >> 5;
    let extra = initial & 0x1f;
    if extra == 31 {
        return read_indefinite(bytes, index + 1, major);
    }
    let (argument, mut next) = read_argument(bytes, index + 1, extra)?;
    let value = match major {
        0 => Cbor::Uint(argument),
        1 => Cbor::Neg(argument),
        2 => {
            let end = next + argument as usize;
            if end > bytes.len() {
                return Err(fail("truncated cbor bytes"));
            }
            next = end;
            Cbor::Text(String::from_utf8_lossy(&bytes[next - argument as usize..end]).into_owned())
        }
        3 => {
            let end = next + argument as usize;
            if end > bytes.len() {
                return Err(fail("truncated cbor text"));
            }
            let text = std::str::from_utf8(&bytes[next..end])
                .map_err(|_| fail("cbor text is not utf-8"))?
                .to_string();
            next = end;
            Cbor::Text(text)
        }
        4 => {
            let mut items = Vec::new();
            for _ in 0..argument {
                let (item, after) = read_value(bytes, next)?;
                items.push(item);
                next = after;
            }
            Cbor::Array(items)
        }
        5 => {
            let mut items = Vec::new();
            for _ in 0..argument {
                let (key, after_key) = read_value(bytes, next)?;
                let (value, after_value) = read_value(bytes, after_key)?;
                items.push((key, value));
                next = after_value;
            }
            Cbor::Map(items)
        }
        6 => {
            let (inner, after) = read_value(bytes, next)?;
            next = after;
            Cbor::Tag(argument, Box::new(inner))
        }
        7 => match extra {
            20 => Cbor::Bool(false),
            21 => Cbor::Bool(true),
            22 => Cbor::Null,
            27 => {
                let end = next;
                if end < 8 {
                    return Err(fail("truncated cbor float"));
                }
                let bits = u64::from_be_bytes(bytes[end - 8..end].try_into().expect("8"));
                Cbor::Float(f64::from_bits(bits))
            }
            _ => return Err(fail(format!("unsupported cbor simple {extra}"))),
        },
        _ => return Err(fail("bad cbor major type")),
    };
    Ok((value, next))
}

fn read_indefinite(bytes: &[u8], mut index: usize, major: u8) -> Result<(Cbor, usize), RunError> {
    match major {
        4 => {
            let mut items = Vec::new();
            while index < bytes.len() && bytes[index] != 0xff {
                let (item, next) = read_value(bytes, index)?;
                items.push(item);
                index = next;
            }
            if index >= bytes.len() || bytes[index] != 0xff {
                return Err(fail("truncated indefinite cbor"));
            }
            Ok((Cbor::Array(items), index + 1))
        }
        5 => {
            let mut items = Vec::new();
            while index < bytes.len() && bytes[index] != 0xff {
                let (key, after_key) = read_value(bytes, index)?;
                let (value, after_value) = read_value(bytes, after_key)?;
                items.push((key, value));
                index = after_value;
            }
            if index >= bytes.len() || bytes[index] != 0xff {
                return Err(fail("truncated indefinite cbor"));
            }
            Ok((Cbor::Map(items), index + 1))
        }
        _ => Err(fail("unsupported indefinite cbor")),
    }
}

fn read_argument(bytes: &[u8], index: usize, extra: u8) -> Result<(u64, usize), RunError> {
    if extra < 24 {
        return Ok((u64::from(extra), index));
    }
    let width = match extra {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(fail("bad cbor argument")),
    };
    if index + width > bytes.len() {
        return Err(fail("truncated cbor argument"));
    }
    let mut raw = [0u8; 8];
    raw[8 - width..].copy_from_slice(&bytes[index..index + width]);
    Ok((u64::from_be_bytes(raw), index + width))
}

fn unwrap_typed(value: &Cbor) -> Cbor {
    let value = match value {
        Cbor::Tag(256, inner) => inner.as_ref().clone(),
        other => other.clone(),
    };
    if let Cbor::Array(items) = &value
        && items.len() == 2
        && (is_type_name(&items[0]) || matches!(items[0], Cbor::Tag(_, _)))
    {
        return unwrap_typed(&items[1]);
    }
    value
}

fn is_type_name(value: &Cbor) -> bool {
    match value {
        Cbor::Text(text) => text.contains('.'),
        Cbor::Tag(_, _) => true,
        _ => false,
    }
}

fn expect_map(value: &Cbor) -> Result<&[(Cbor, Cbor)], RunError> {
    match value {
        Cbor::Map(items) => Ok(items),
        _ => Err(fail("event cbor map was not a map")),
    }
}

fn expect_text(value: &Cbor) -> Result<&str, RunError> {
    match value {
        Cbor::Text(text) => Ok(text),
        _ => Err(fail("event cbor key was not text")),
    }
}

fn map_value(value: &Cbor) -> Result<Map, RunError> {
    let mut map = Map::new();
    for (key, item) in expect_map(value)? {
        map.insert(expect_text(key)?, field_value(item)?);
    }
    Ok(map)
}

fn field_value(value: &Cbor) -> Result<Value, RunError> {
    if let Cbor::Array(items) = value
        && items.len() == 2
        && let Cbor::Text(class_name) = &items[0]
        && class_name.contains('.')
    {
        if class_name.ends_with("Timestamp")
            && let Cbor::Text(text) = &items[1]
        {
            let timestamp = DateTime::parse_from_rfc3339(text)
                .map_err(|_| fail(format!("bad timestamp {text}")))?;
            return Ok(Value::Timestamp(timestamp.with_timezone(&Utc)));
        }
        return field_value(&items[1]);
    }
    if let Cbor::Tag(_, inner) = value {
        return field_value(inner);
    }
    Ok(match value {
        Cbor::Text(text) => Value::String(text.clone()),
        Cbor::Uint(number) => Value::Integer(i128::from(*number)),
        Cbor::Neg(number) => Value::Integer(-1 - i128::from(*number)),
        Cbor::Bool(bit) => Value::Boolean(*bit),
        Cbor::Null => Value::Null,
        Cbor::Float(number) => Value::Float(*number),
        Cbor::Array(items) => {
            let mut values = Vec::new();
            for item in items {
                values.push(field_value(item)?);
            }
            Value::Array(values)
        }
        Cbor::Map(_) => Value::Map(map_value(value)?),
        Cbor::Tag(_, inner) => field_value(inner)?,
    })
}
