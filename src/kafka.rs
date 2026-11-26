//! Kafka output from logstash-integration-kafka 12.1.5, plaintext only.
//!
//! The client sends Metadata v4 and Produce v3. Record batches use magic 2
//! and CRC-32C. `SSL`, `SASL_PLAINTEXT`, and `SASL_SSL` are refused. A produce
//! error fails the event instead of retrying until the process is stopped.
//! The default codec is `plain`.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::event::Event;
use crate::lscl::{Arg, Plugin};
use crate::run::{RunError, encode_event, fail};

const METADATA: i16 = 3;
const PRODUCE: i16 = 0;
const METADATA_VERSION: i16 = 4;
const PRODUCE_VERSION: i16 = 3;

pub(crate) fn send(plugin: &Plugin, event: &Event) -> Result<(), RunError> {
    let topic = text(plugin, "topic_id").ok_or_else(|| fail("kafka output requires topic_id"))?;
    let topic = event
        .sprintf(&topic)
        .map_err(|error| fail(error.to_string()))?;
    let protocol = text(plugin, "security_protocol").unwrap_or_else(|| "PLAINTEXT".to_string());
    if protocol != "PLAINTEXT" {
        return Err(fail(format!(
            "kafka security_protocol {protocol} is not implemented"
        )));
    }
    let compression = text(plugin, "compression_type").unwrap_or_else(|| "none".to_string());
    if compression != "none" {
        return Err(fail(format!(
            "kafka compression_type {compression} is not implemented"
        )));
    }
    let serializer = text(plugin, "value_serializer")
        .unwrap_or_else(|| "org.apache.kafka.common.serialization.StringSerializer".to_string());
    if serializer != "org.apache.kafka.common.serialization.StringSerializer"
        && serializer != "org.apache.kafka.common.serialization.ByteArraySerializer"
    {
        return Err(fail(
            "'value_serializer' only supports org.apache.kafka.common.serialization.ByteArraySerializer and org.apache.kafka.common.serialization.StringSerializer",
        ));
    }
    if let Some(retries) = number(plugin, "retries")
        && retries < 0
    {
        return Err(fail(format!(
            "A negative retry count ({retries}) is not valid. Must be a value >= 0"
        )));
    }
    let payload = encode_event(plugin, event, "plain")?;
    let key = match text(plugin, "message_key") {
        Some(template) => Some(
            event
                .sprintf(&template)
                .map_err(|error| fail(error.to_string()))?,
        ),
        None => None,
    };
    let acks = match text(plugin, "acks").as_deref().unwrap_or("1") {
        "0" => 0,
        "1" => 1,
        "all" => -1,
        other => {
            return Err(fail(format!("kafka acks {other} is not implemented")));
        }
    };
    let servers = text(plugin, "bootstrap_servers").unwrap_or_else(|| "localhost:9092".to_string());
    let (host, port) = parse_bootstrap(&servers)?;
    let client_id = text(plugin, "client_id").unwrap_or_else(|| "logstash".to_string());
    let metadata = request(
        &host,
        port,
        &frame(
            METADATA,
            METADATA_VERSION,
            1,
            &client_id,
            &metadata_body(&topic),
        ),
    )?;
    let (_leader_host, leader_port, partition) = parse_metadata(&metadata)?;
    let body = produce_body(acks, &topic, partition, key.as_deref(), payload.as_bytes());
    let response = request(
        &host,
        leader_port,
        &frame(PRODUCE, PRODUCE_VERSION, 2, &client_id, &body),
    )?;
    parse_produce(&response)
}

fn parse_bootstrap(servers: &str) -> Result<(String, u16), RunError> {
    let first = servers
        .split(',')
        .next()
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .ok_or_else(|| fail("kafka bootstrap_servers is empty"))?;
    let (host, port) = first
        .rsplit_once(':')
        .ok_or_else(|| fail(format!("kafka bootstrap server {first} needs a port")))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| fail(format!("kafka bootstrap server {first} needs a port")))?;
    Ok((host.to_string(), port))
}

fn metadata_body(topic: &str) -> Vec<u8> {
    let mut body = Vec::new();
    write_i32(&mut body, 1);
    write_string(&mut body, topic);
    body.push(1);
    body
}

fn produce_body(
    acks: i16,
    topic: &str,
    partition: i32,
    key: Option<&str>,
    value: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    write_i16(&mut body, -1);
    write_i16(&mut body, acks);
    write_i32(&mut body, 30_000);
    write_i32(&mut body, 1);
    write_string(&mut body, topic);
    write_i32(&mut body, 1);
    write_i32(&mut body, partition);
    let batch = record_batch(key, value);
    write_i32(&mut body, batch.len() as i32);
    body.extend_from_slice(&batch);
    body
}

fn record_batch(key: Option<&str>, value: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.push(0);
    write_varint(&mut record, 0);
    write_varint(&mut record, 0);
    match key {
        Some(key) => {
            write_varint(&mut record, key.len() as i64);
            record.extend_from_slice(key.as_bytes());
        }
        None => write_varint(&mut record, -1),
    }
    write_varint(&mut record, value.len() as i64);
    record.extend_from_slice(value);
    write_varint(&mut record, 0);
    let mut records = Vec::new();
    write_varint(&mut records, record.len() as i64);
    records.extend_from_slice(&record);

    let mut attributes = Vec::new();
    write_i16(&mut attributes, 0);
    write_i32(&mut attributes, 0);
    write_i64(&mut attributes, 0);
    write_i64(&mut attributes, 0);
    write_i64(&mut attributes, -1);
    write_i16(&mut attributes, -1);
    write_i32(&mut attributes, -1);
    write_i32(&mut attributes, 1);
    attributes.extend_from_slice(&records);
    let crc = crc32c(&attributes);

    let mut after_length = Vec::new();
    write_i32(&mut after_length, -1);
    after_length.push(2);
    write_i32(&mut after_length, crc as i32);
    after_length.extend_from_slice(&attributes);

    let mut batch = Vec::new();
    write_i64(&mut batch, 0);
    write_i32(&mut batch, after_length.len() as i32);
    batch.extend_from_slice(&after_length);
    batch
}

fn frame(api_key: i16, version: i16, correlation: i32, client_id: &str, body: &[u8]) -> Vec<u8> {
    let mut request = Vec::new();
    write_i16(&mut request, api_key);
    write_i16(&mut request, version);
    write_i32(&mut request, correlation);
    write_string(&mut request, client_id);
    request.extend_from_slice(body);
    let mut framed = Vec::new();
    write_i32(&mut framed, request.len() as i32);
    framed.extend_from_slice(&request);
    framed
}

fn request(host: &str, port: u16, bytes: &[u8]) -> Result<Vec<u8>, RunError> {
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|error| fail(error.to_string()))?
        .next()
        .ok_or_else(|| fail("kafka bootstrap server did not resolve"))?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|error| fail(error.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| fail(error.to_string()))?;
    stream
        .write_all(bytes)
        .map_err(|error| fail(error.to_string()))?;
    let mut size = [0u8; 4];
    stream
        .read_exact(&mut size)
        .map_err(|error| fail(error.to_string()))?;
    let length = i32::from_be_bytes(size);
    if length < 0 {
        return Err(fail("kafka response size is negative"));
    }
    let mut body = vec![0u8; length as usize];
    stream
        .read_exact(&mut body)
        .map_err(|error| fail(error.to_string()))?;
    Ok(body)
}

fn parse_metadata(bytes: &[u8]) -> Result<(String, u16, i32), RunError> {
    let mut cursor = Cursor(bytes);
    let _correlation = cursor.i32()?;
    let _throttle = cursor.i32()?;
    let brokers = cursor.i32()?;
    if brokers < 1 {
        return Err(fail("kafka metadata returned no brokers"));
    }
    let _node = cursor.i32()?;
    let host = cursor.string()?;
    let port = cursor.i32()?;
    let _rack = cursor.nullable_string()?;
    for _ in 1..brokers {
        let _node = cursor.i32()?;
        let _host = cursor.string()?;
        let _port = cursor.i32()?;
        let _rack = cursor.nullable_string()?;
    }
    let _cluster = cursor.nullable_string()?;
    let _controller = cursor.i32()?;
    let topics = cursor.i32()?;
    if topics < 1 {
        return Err(fail("kafka metadata returned no topics"));
    }
    let error = cursor.i16()?;
    if error != 0 {
        return Err(fail(format!("kafka metadata error code {error}")));
    }
    let _name = cursor.string()?;
    let _internal = cursor.u8()?;
    let partitions = cursor.i32()?;
    if partitions < 1 {
        return Err(fail("kafka metadata returned no partitions"));
    }
    let error = cursor.i16()?;
    if error != 0 {
        return Err(fail(format!("kafka partition error code {error}")));
    }
    let partition = cursor.i32()?;
    let _leader = cursor.i32()?;
    Ok((host, port as u16, partition))
}

fn parse_produce(bytes: &[u8]) -> Result<(), RunError> {
    let mut cursor = Cursor(bytes);
    let _correlation = cursor.i32()?;
    let topics = cursor.i32()?;
    if topics < 1 {
        return Err(fail("kafka produce response has no topics"));
    }
    for _ in 0..topics {
        let _name = cursor.string()?;
        let partitions = cursor.i32()?;
        if partitions < 1 {
            return Err(fail("kafka produce response has no partitions"));
        }
        for _ in 0..partitions {
            let _partition = cursor.i32()?;
            let error = cursor.i16()?;
            let _base_offset = cursor.i64()?;
            let _log_append_time = cursor.i64()?;
            if error != 0 {
                return Err(fail(format!("kafka produce error code {error}")));
            }
        }
    }
    let _throttle = cursor.i32()?;
    Ok(())
}

struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn take(&mut self, size: usize) -> Result<&[u8], RunError> {
        if self.0.len() < size {
            return Err(fail("kafka response ended early"));
        }
        let (head, tail) = self.0.split_at(size);
        self.0 = tail;
        Ok(head)
    }

    fn i16(&mut self) -> Result<i16, RunError> {
        let bytes = self.take(2)?;
        Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn i32(&mut self) -> Result<i32, RunError> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i64(&mut self) -> Result<i64, RunError> {
        let bytes = self.take(8)?;
        Ok(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn u8(&mut self) -> Result<u8, RunError> {
        Ok(self.take(1)?[0])
    }

    fn string(&mut self) -> Result<String, RunError> {
        let length = self.i16()?;
        if length < 0 {
            return Err(fail("kafka response string is null"));
        }
        let bytes = self.take(length as usize)?;
        String::from_utf8(bytes.to_vec()).map_err(|error| fail(error.to_string()))
    }

    fn nullable_string(&mut self) -> Result<Option<String>, RunError> {
        let length = self.i16()?;
        if length < 0 {
            return Ok(None);
        }
        let bytes = self.take(length as usize)?;
        String::from_utf8(bytes.to_vec())
            .map(Some)
            .map_err(|error| fail(error.to_string()))
    }
}

fn write_i16(out: &mut Vec<u8>, value: i16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_i16(out, value.len() as i16);
    out.extend_from_slice(value.as_bytes());
}

fn write_varint(out: &mut Vec<u8>, value: i64) {
    let mut encoded = ((value << 1) ^ (value >> 63)) as u64;
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

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

fn text(plugin: &Plugin, name: &str) -> Option<String> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .and_then(|(_, value)| match value {
            Arg::String(value) => Some(value.clone()),
            Arg::Int(value) => Some(value.to_string()),
            _ => None,
        })
}

fn number(plugin: &Plugin, name: &str) -> Option<i64> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .and_then(|(_, value)| match value {
            Arg::Int(value) => Some(*value),
            Arg::String(value) => value.parse().ok(),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::crc32c;

    #[test]
    fn crc32c_matches_the_castagnoli_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }
}
