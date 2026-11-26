//! Kafka output and input from logstash-integration-kafka 12.1.5, plaintext only.
//!
//! The output sends Metadata v4 and Produce v3. The input does one Metadata,
//! OffsetFetch, ListOffsets, Fetch v4, and OffsetCommit, then returns. The
//! official consumer polls until the pipeline stops. Record batches use magic
//! 2 and CRC-32C. `SSL`, `SASL_PLAINTEXT`, and `SASL_SSL` are refused.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use std::collections::HashMap;

use crate::codec::TextCodec;
use crate::event::Event;
use crate::lscl::{Arg, Plugin};
use crate::mutate::filter_matched;
use crate::run::{Ecs, RunError, Settings, encode_event, fail};
use crate::value::Value;

const METADATA: i16 = 3;
const PRODUCE: i16 = 0;
const METADATA_VERSION: i16 = 4;
const PRODUCE_VERSION: i16 = 3;

pub(crate) fn send(plugin: &Plugin, event: &Event, ecs: Ecs) -> Result<(), RunError> {
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
    let payload = encode_event(plugin, event, "plain", ecs)?;
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

    fn bytes(&mut self) -> Result<Vec<u8>, RunError> {
        let length = self.i32()?;
        if length < 0 {
            return Ok(Vec::new());
        }
        Ok(self.take(length as usize)?.to_vec())
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

const FIND_COORDINATOR: i16 = 10;
const OFFSET_FETCH: i16 = 9;
const LIST_OFFSETS: i16 = 2;
const FETCH: i16 = 1;
const OFFSET_COMMIT: i16 = 8;

struct Leader {
    topic: String,
    partition: i32,
    host: String,
    port: u16,
}

struct Fetched {
    offset: i64,
    timestamp: i64,
    key: Option<String>,
    value: Vec<u8>,
    headers: Vec<(String, String)>,
}

pub(crate) fn poll(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    refuse_security(plugin)?;
    if text(plugin, "topics_pattern").is_some() {
        return Err(fail("kafka topics_pattern is not implemented"));
    }
    if text(plugin, "schema_registry_url").is_some() {
        return Err(fail("kafka schema_registry_url is not implemented"));
    }
    if number(plugin, "consumer_threads").unwrap_or(1) != 1 {
        return Err(fail("kafka consumer_threads above 1 is not implemented"));
    }
    check_group_protocol(plugin)?;
    let deserializer = text(plugin, "value_deserializer_class")
        .unwrap_or_else(|| "org.apache.kafka.common.serialization.StringDeserializer".to_string());
    if deserializer != "org.apache.kafka.common.serialization.StringDeserializer"
        && deserializer != "org.apache.kafka.common.serialization.ByteArrayDeserializer"
    {
        return Err(fail(
            "'value_deserializer_class' only supports org.apache.kafka.common.serialization.ByteArrayDeserializer and org.apache.kafka.common.serialization.StringDeserializer",
        ));
    }
    let decorate_mode = decorate_mode(plugin)?;
    let topics = topic_list(plugin);
    let reset = text(plugin, "auto_offset_reset").unwrap_or_else(|| "latest".to_string());
    if reset.starts_with("by_duration:") {
        return Err(fail(
            "kafka auto_offset_reset by_duration is not implemented",
        ));
    }
    if reset != "earliest" && reset != "latest" && reset != "none" {
        return Err(fail(format!(
            "kafka auto_offset_reset {reset} is not implemented"
        )));
    }
    let servers = text(plugin, "bootstrap_servers").unwrap_or_else(|| "localhost:9092".to_string());
    let (host, port) = parse_bootstrap(&servers)?;
    let client_id = text(plugin, "client_id").unwrap_or_else(|| "logstash".to_string());
    let group = text(plugin, "group_id").unwrap_or_else(|| "logstash".to_string());
    let auto_create = flag(plugin, "auto_create_topics").unwrap_or(true);
    let metadata = request(
        &host,
        port,
        &frame(
            METADATA,
            METADATA_VERSION,
            1,
            &client_id,
            &metadata_topics(&topics, auto_create),
        ),
    )?;
    let leaders = parse_leaders(&metadata)?;
    let coordinator = request(
        &host,
        port,
        &frame(FIND_COORDINATOR, 0, 2, &client_id, &group_key(&group)),
    )?;
    let (coordinator_host, coordinator_port) = parse_coordinator(&coordinator)?;
    let fetched = request(
        &coordinator_host,
        coordinator_port,
        &frame(
            OFFSET_FETCH,
            1,
            3,
            &client_id,
            &offset_fetch_body(&group, &leaders),
        ),
    )?;
    let mut starts = parse_offset_fetch(&fetched)?;
    for leader in &leaders {
        let key = (leader.topic.clone(), leader.partition);
        if starts.contains_key(&key) {
            continue;
        }
        if reset == "none" {
            return Err(fail(format!(
                "Undefined offset with no reset policy for partition {}-{}",
                leader.topic, leader.partition
            )));
        }
        let timestamp = if reset == "earliest" { -2 } else { -1 };
        let listed = request(
            &leader.host,
            leader.port,
            &frame(
                LIST_OFFSETS,
                1,
                4,
                &client_id,
                &list_offsets_body(&leader.topic, leader.partition, timestamp),
            ),
        )?;
        starts.insert(key, parse_list_offsets(&listed)?);
    }
    let isolation = match text(plugin, "isolation_level")
        .unwrap_or_else(|| "read_uncommitted".to_string())
        .as_str()
    {
        "read_uncommitted" => 0i8,
        "read_committed" => 1,
        other => {
            return Err(fail(format!(
                "kafka isolation_level {other} is not implemented"
            )));
        }
    };
    let wait = i32::try_from(number(plugin, "fetch_max_wait_ms").unwrap_or(500)).unwrap_or(500);
    let min_bytes = i32::try_from(number(plugin, "fetch_min_bytes").unwrap_or(1)).unwrap_or(1);
    let max_bytes = i32::try_from(number(plugin, "fetch_max_bytes").unwrap_or(52_428_800))
        .unwrap_or(52_428_800);
    let part_max = i32::try_from(number(plugin, "max_partition_fetch_bytes").unwrap_or(1_048_576))
        .unwrap_or(1_048_576);
    let limit = number(plugin, "max_poll_records").unwrap_or(500).max(0) as usize;
    let check_crc = flag(plugin, "check_crcs").unwrap_or(true);
    let mut events = Vec::new();
    let mut commits = Vec::new();
    for leader in &leaders {
        if events.len() >= limit {
            break;
        }
        let offset = starts
            .get(&(leader.topic.clone(), leader.partition))
            .copied()
            .unwrap_or(0);
        let response = request(
            &leader.host,
            leader.port,
            &frame(
                FETCH,
                4,
                5,
                &client_id,
                &fetch_body(
                    wait,
                    min_bytes,
                    max_bytes,
                    isolation,
                    &leader.topic,
                    leader.partition,
                    offset,
                    part_max,
                ),
            ),
        )?;
        let records = parse_fetch(&response, &leader.topic, leader.partition, check_crc)?;
        let mut next = offset;
        for record in records {
            if events.len() >= limit {
                break;
            }
            next = record.offset + 1;
            events.extend(events_from_record(
                plugin,
                settings,
                &group,
                &decorate_mode,
                &deserializer,
                &leader.topic,
                leader.partition,
                record,
            )?);
        }
        if next > offset {
            commits.push((leader.topic.clone(), leader.partition, next));
        }
    }
    if !commits.is_empty() {
        let committed = request(
            &coordinator_host,
            coordinator_port,
            &frame(
                OFFSET_COMMIT,
                2,
                6,
                &client_id,
                &offset_commit_body(&group, &commits),
            ),
        )?;
        parse_offset_commit(&committed)?;
    }
    Ok(events)
}

fn refuse_security(plugin: &Plugin) -> Result<(), RunError> {
    let protocol = text(plugin, "security_protocol").unwrap_or_else(|| "PLAINTEXT".to_string());
    if protocol != "PLAINTEXT" {
        return Err(fail(format!(
            "kafka security_protocol {protocol} is not implemented"
        )));
    }
    Ok(())
}

fn check_group_protocol(plugin: &Plugin) -> Result<(), RunError> {
    if text(plugin, "group_protocol").as_deref() != Some("consumer") {
        return Ok(());
    }
    let heartbeat = number(plugin, "heartbeat_interval_ms").unwrap_or(3000) != 3000;
    let session = number(plugin, "session_timeout_ms").unwrap_or(10_000) != 10_000;
    if heartbeat || session || text(plugin, "partition_assignment_strategy").is_some() {
        return Err(fail(
            "group_protocol cannot be set to 'consumer' when any of partition_assignment_strategy, heartbeat_interval_ms or session_timeout_ms is set",
        ));
    }
    Ok(())
}

fn decorate_mode(plugin: &Plugin) -> Result<String, RunError> {
    let mode = text(plugin, "decorate_events").unwrap_or_else(|| "none".to_string());
    match mode.as_str() {
        "none" | "false" => Ok("none".to_string()),
        "basic" | "true" => Ok("basic".to_string()),
        "extended" => Ok("extended".to_string()),
        other => Err(fail(format!(
            "kafka decorate_events {other} is not implemented"
        ))),
    }
}

fn topic_list(plugin: &Plugin) -> Vec<String> {
    match plugin.args.iter().find(|(key, _)| key == "topics") {
        Some((_, Arg::Array(items))) => items
            .iter()
            .filter_map(|item| match item {
                Arg::String(value) => Some(value.clone()),
                _ => None,
            })
            .collect(),
        Some((_, Arg::String(value))) => vec![value.clone()],
        _ => vec!["logstash".to_string()],
    }
}

fn metadata_topics(topics: &[String], auto_create: bool) -> Vec<u8> {
    let mut body = Vec::new();
    write_i32(&mut body, topics.len() as i32);
    for topic in topics {
        write_string(&mut body, topic);
    }
    body.push(u8::from(auto_create));
    body
}

fn group_key(group: &str) -> Vec<u8> {
    let mut body = Vec::new();
    write_string(&mut body, group);
    body
}

fn parse_leaders(bytes: &[u8]) -> Result<Vec<Leader>, RunError> {
    let mut cursor = Cursor(bytes);
    let _correlation = cursor.i32()?;
    let _throttle = cursor.i32()?;
    let brokers = cursor.i32()?;
    if brokers < 1 {
        return Err(fail("kafka metadata returned no brokers"));
    }
    let mut nodes = HashMap::new();
    for _ in 0..brokers {
        let id = cursor.i32()?;
        let host = cursor.string()?;
        let port = cursor.i32()?;
        let _rack = cursor.nullable_string()?;
        nodes.insert(id, (host, port));
    }
    let _cluster = cursor.nullable_string()?;
    let _controller = cursor.i32()?;
    let topics = cursor.i32()?;
    let mut leaders = Vec::new();
    for _ in 0..topics {
        let error = cursor.i16()?;
        if error != 0 {
            return Err(fail(format!("kafka metadata error code {error}")));
        }
        let topic = cursor.string()?;
        let _internal = cursor.u8()?;
        let partitions = cursor.i32()?;
        for _ in 0..partitions {
            let error = cursor.i16()?;
            if error != 0 {
                return Err(fail(format!("kafka partition error code {error}")));
            }
            let partition = cursor.i32()?;
            let leader = cursor.i32()?;
            let replicas = cursor.i32()?;
            for _ in 0..replicas {
                let _node = cursor.i32()?;
            }
            let isr = cursor.i32()?;
            for _ in 0..isr {
                let _node = cursor.i32()?;
            }
            let (host, port) = nodes
                .get(&leader)
                .ok_or_else(|| fail(format!("kafka partition {partition} has no leader")))?;
            leaders.push(Leader {
                topic: topic.clone(),
                partition,
                host: host.clone(),
                port: *port as u16,
            });
        }
    }
    if leaders.is_empty() {
        return Err(fail("kafka metadata returned no partitions"));
    }
    Ok(leaders)
}

fn parse_coordinator(bytes: &[u8]) -> Result<(String, u16), RunError> {
    let mut cursor = Cursor(bytes);
    let _correlation = cursor.i32()?;
    let error = cursor.i16()?;
    if error != 0 {
        return Err(fail(format!("kafka coordinator error code {error}")));
    }
    let _node = cursor.i32()?;
    let host = cursor.string()?;
    let port = cursor.i32()?;
    Ok((host, port as u16))
}

fn offset_fetch_body(group: &str, leaders: &[Leader]) -> Vec<u8> {
    let mut body = Vec::new();
    write_string(&mut body, group);
    let mut topics: Vec<(String, Vec<i32>)> = Vec::new();
    for leader in leaders {
        if let Some((_, partitions)) = topics.iter_mut().find(|(name, _)| name == &leader.topic) {
            partitions.push(leader.partition);
        } else {
            topics.push((leader.topic.clone(), vec![leader.partition]));
        }
    }
    write_i32(&mut body, topics.len() as i32);
    for (topic, partitions) in topics {
        write_string(&mut body, &topic);
        write_i32(&mut body, partitions.len() as i32);
        for partition in partitions {
            write_i32(&mut body, partition);
        }
    }
    body
}

fn parse_offset_fetch(bytes: &[u8]) -> Result<HashMap<(String, i32), i64>, RunError> {
    let mut cursor = Cursor(bytes);
    let _correlation = cursor.i32()?;
    let topics = cursor.i32()?;
    let mut offsets = HashMap::new();
    for _ in 0..topics {
        let topic = cursor.string()?;
        let partitions = cursor.i32()?;
        for _ in 0..partitions {
            let partition = cursor.i32()?;
            let offset = cursor.i64()?;
            let _metadata = cursor.nullable_string()?;
            let error = cursor.i16()?;
            if error == 0 && offset >= 0 {
                offsets.insert((topic.clone(), partition), offset);
            }
        }
    }
    Ok(offsets)
}

fn list_offsets_body(topic: &str, partition: i32, timestamp: i64) -> Vec<u8> {
    let mut body = Vec::new();
    write_i32(&mut body, -1);
    write_i32(&mut body, 1);
    write_string(&mut body, topic);
    write_i32(&mut body, 1);
    write_i32(&mut body, partition);
    write_i64(&mut body, timestamp);
    body
}

fn parse_list_offsets(bytes: &[u8]) -> Result<i64, RunError> {
    let mut cursor = Cursor(bytes);
    let _correlation = cursor.i32()?;
    let topics = cursor.i32()?;
    if topics < 1 {
        return Err(fail("kafka list offsets returned no topics"));
    }
    let _topic = cursor.string()?;
    let partitions = cursor.i32()?;
    if partitions < 1 {
        return Err(fail("kafka list offsets returned no partitions"));
    }
    let _partition = cursor.i32()?;
    let error = cursor.i16()?;
    if error != 0 {
        return Err(fail(format!("kafka list offsets error code {error}")));
    }
    let _timestamp = cursor.i64()?;
    cursor.i64()
}

#[allow(clippy::too_many_arguments)]
fn fetch_body(
    wait: i32,
    min_bytes: i32,
    max_bytes: i32,
    isolation: i8,
    topic: &str,
    partition: i32,
    offset: i64,
    part_max: i32,
) -> Vec<u8> {
    let mut body = Vec::new();
    write_i32(&mut body, -1);
    write_i32(&mut body, wait);
    write_i32(&mut body, min_bytes);
    write_i32(&mut body, max_bytes);
    body.push(isolation as u8);
    write_i32(&mut body, 1);
    write_string(&mut body, topic);
    write_i32(&mut body, 1);
    write_i32(&mut body, partition);
    write_i64(&mut body, offset);
    write_i32(&mut body, part_max);
    body
}

fn parse_fetch(
    bytes: &[u8],
    topic: &str,
    partition: i32,
    check_crc: bool,
) -> Result<Vec<Fetched>, RunError> {
    let mut cursor = Cursor(bytes);
    let _correlation = cursor.i32()?;
    let _throttle = cursor.i32()?;
    let topics = cursor.i32()?;
    let mut records = Vec::new();
    for _ in 0..topics {
        let name = cursor.string()?;
        let partitions = cursor.i32()?;
        for _ in 0..partitions {
            let part = cursor.i32()?;
            let error = cursor.i16()?;
            if error != 0 {
                return Err(fail(format!("kafka fetch error code {error}")));
            }
            let _high = cursor.i64()?;
            let _stable = cursor.i64()?;
            let aborted = cursor.i32()?;
            if aborted > 0 {
                for _ in 0..aborted {
                    let _producer = cursor.i64()?;
                    let _first = cursor.i64()?;
                }
            }
            let blob = cursor.bytes()?;
            if name == topic && part == partition {
                records.extend(read_records(&blob, check_crc)?);
            }
        }
    }
    Ok(records)
}

fn read_records(blob: &[u8], check_crc: bool) -> Result<Vec<Fetched>, RunError> {
    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor + 12 <= blob.len() {
        let base = i64::from_be_bytes(blob[cursor..cursor + 8].try_into().expect("offset"));
        cursor += 8;
        let length = i32::from_be_bytes(blob[cursor..cursor + 4].try_into().expect("length"));
        cursor += 4;
        if length < 0 {
            break;
        }
        let end = cursor + length as usize;
        if end > blob.len() {
            return Err(fail("kafka record batch ended early"));
        }
        let batch = &blob[cursor..end];
        cursor = end;
        records.extend(read_batch(base, batch, check_crc)?);
    }
    Ok(records)
}

fn read_batch(base_offset: i64, batch: &[u8], check_crc: bool) -> Result<Vec<Fetched>, RunError> {
    if batch.len() < 9 + 45 {
        return Err(fail("kafka record batch ended early"));
    }
    let magic = batch[4];
    if magic != 2 {
        return Err(fail(format!(
            "kafka record batch magic {magic} is not implemented"
        )));
    }
    let crc = u32::from_be_bytes(batch[5..9].try_into().expect("crc"));
    let attributes = &batch[9..];
    if check_crc && crc32c(attributes) != crc {
        return Err(fail("kafka record batch crc mismatch"));
    }
    let mut cursor = Cursor(attributes);
    let flags = cursor.i16()?;
    if flags & 0b111 != 0 {
        return Err(fail("kafka record compression is not implemented"));
    }
    let _last_delta = cursor.i32()?;
    let base_timestamp = cursor.i64()?;
    let _max_timestamp = cursor.i64()?;
    let _producer = cursor.i64()?;
    let _epoch = cursor.i16()?;
    let _sequence = cursor.i32()?;
    let count = cursor.i32()?;
    let mut records = Vec::new();
    let rest = cursor.0;
    let mut at = 0;
    for _ in 0..count {
        let size = read_varlong(rest, &mut at)?;
        if size < 0 {
            return Err(fail("kafka record length is negative"));
        }
        let stop = at + size as usize;
        if stop > rest.len() {
            return Err(fail("kafka record ended early"));
        }
        let record = &rest[at..stop];
        at = stop;
        records.push(read_record(base_offset, base_timestamp, record)?);
    }
    Ok(records)
}

fn read_record(base_offset: i64, base_timestamp: i64, record: &[u8]) -> Result<Fetched, RunError> {
    let mut at = 0;
    let _attributes = record.first().copied().unwrap_or(0);
    at += 1;
    let timestamp_delta = read_varlong(record, &mut at)?;
    let offset_delta = read_varlong(record, &mut at)?;
    let key = read_bytes(record, &mut at)?;
    let value = read_bytes(record, &mut at)?.unwrap_or_default();
    let headers = read_varlong(record, &mut at)?;
    if headers < 0 {
        return Err(fail("kafka record header count is negative"));
    }
    let mut parsed = Vec::new();
    for _ in 0..headers as usize {
        let key_bytes = read_bytes(record, &mut at)?.unwrap_or_default();
        let value_bytes = read_bytes(record, &mut at)?;
        if let (Ok(name), Some(Ok(text))) = (
            String::from_utf8(key_bytes),
            value_bytes.map(String::from_utf8),
        ) {
            parsed.push((name, text));
        }
    }
    Ok(Fetched {
        offset: base_offset + offset_delta,
        timestamp: base_timestamp + timestamp_delta,
        key: key.and_then(|bytes| String::from_utf8(bytes).ok()),
        value,
        headers: parsed,
    })
}

fn read_bytes(data: &[u8], at: &mut usize) -> Result<Option<Vec<u8>>, RunError> {
    let length = read_varlong(data, at)?;
    if length < 0 {
        return Ok(None);
    }
    let length = length as usize;
    if *at + length > data.len() {
        return Err(fail("kafka record ended early"));
    }
    let bytes = data[*at..*at + length].to_vec();
    *at += length;
    Ok(Some(bytes))
}

fn read_varlong(data: &[u8], at: &mut usize) -> Result<i64, RunError> {
    let unsigned = read_unsigned_varint(data, at)?;
    Ok(((unsigned >> 1) as i64) ^ -((unsigned & 1) as i64))
}

fn read_unsigned_varint(data: &[u8], at: &mut usize) -> Result<u64, RunError> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        if *at >= data.len() {
            return Err(fail("kafka varint ended early"));
        }
        let byte = data[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 63 {
            return Err(fail("kafka varint is too long"));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn events_from_record(
    plugin: &Plugin,
    settings: &Settings,
    group: &str,
    decorate_mode: &str,
    deserializer: &str,
    topic: &str,
    partition: i32,
    record: Fetched,
) -> Result<Vec<Event>, RunError> {
    if deserializer == "org.apache.kafka.common.serialization.StringDeserializer" {
        std::str::from_utf8(&record.value).map_err(|error| fail(error.to_string()))?;
    }
    let codec_name = codec_name(plugin);
    let mut events = if codec_name == "json" || codec_name == "json_lines" {
        let text =
            String::from_utf8(record.value.clone()).map_err(|error| fail(error.to_string()))?;
        crate::plugins::decode_events(&codec_name, &text)?
    } else if codec_name == "line" {
        let mut codec = TextCodec::line(settings.ecs);
        codec.decode(&record.value).map_err(fail)?
    } else if codec_name == "plain" {
        let mut codec = TextCodec::plain(settings.ecs);
        codec.decode(&record.value).map_err(fail)?
    } else if codec_name == "avro" {
        let codec = plugin
            .args
            .iter()
            .find(|(key, _)| key == "codec")
            .and_then(|(_, arg)| match arg {
                Arg::Plugin(codec) => Some(codec),
                _ => None,
            })
            .ok_or_else(|| fail(crate::avro::missing_schema()))?;
        vec![crate::avro::decode(codec, &record.value, settings.ecs)?]
    } else if codec_name == "cef" {
        let codec =
            plugin
                .args
                .iter()
                .find(|(key, _)| key == "codec")
                .and_then(|(_, arg)| match arg {
                    Arg::Plugin(codec) => Some(codec),
                    _ => None,
                });
        crate::cef::decode(codec, &record.value, settings.ecs)?
    } else {
        return Err(fail(format!(
            "plugin codec {codec_name} is not implemented"
        )));
    };
    for event in &mut events {
        decorate_input(plugin, event)?;
        if decorate_mode == "basic" || decorate_mode == "extended" {
            event
                .set_field("[@metadata][kafka][topic]", Value::from(topic))
                .map_err(|error| fail(error.to_string()))?;
            set_meta(event, "consumer_group", Value::from(group))?;
            set_meta(event, "partition", Value::Integer(i128::from(partition)))?;
            set_meta(event, "offset", Value::Integer(i128::from(record.offset)))?;
            set_meta(
                event,
                "key",
                record.key.clone().map(Value::from).unwrap_or(Value::Null),
            )?;
            set_meta(
                event,
                "timestamp",
                Value::Integer(i128::from(record.timestamp)),
            )?;
        }
        if decorate_mode == "extended" {
            for (name, value) in &record.headers {
                event
                    .set_field(
                        &format!("[@metadata][kafka][headers][{name}]"),
                        Value::from(value.as_str()),
                    )
                    .map_err(|error| fail(error.to_string()))?;
            }
        }
    }
    Ok(events)
}

fn set_meta(event: &mut Event, name: &str, value: Value) -> Result<(), RunError> {
    event
        .set_field(&format!("[@metadata][kafka][{name}]"), value)
        .map_err(|error| fail(error.to_string()))
}

fn decorate_input(plugin: &Plugin, event: &mut Event) -> Result<(), RunError> {
    if let Some(kind) = text(plugin, "type") {
        event
            .set_field("type", Value::from(kind.as_str()))
            .map_err(|error| fail(error.to_string()))?;
    }
    if let Some((_, Arg::Array(tags))) = plugin.args.iter().find(|(key, _)| key == "tags") {
        for tag in tags {
            if let Arg::String(tag) = tag {
                event.tag(tag);
            }
        }
    }
    filter_matched(plugin, event)
}

fn codec_name(plugin: &Plugin) -> String {
    match plugin.args.iter().find(|(key, _)| key == "codec") {
        Some((_, Arg::Plugin(codec))) => codec.name.clone(),
        Some((_, Arg::String(name))) => name.clone(),
        _ => "plain".to_string(),
    }
}

fn offset_commit_body(group: &str, commits: &[(String, i32, i64)]) -> Vec<u8> {
    let mut body = Vec::new();
    write_string(&mut body, group);
    write_i32(&mut body, -1);
    write_string(&mut body, "");
    write_i64(&mut body, -1);
    let mut topics: Vec<(String, Vec<(i32, i64)>)> = Vec::new();
    for (topic, partition, offset) in commits {
        if let Some((_, parts)) = topics.iter_mut().find(|(name, _)| name == topic) {
            parts.push((*partition, *offset));
        } else {
            topics.push((topic.clone(), vec![(*partition, *offset)]));
        }
    }
    write_i32(&mut body, topics.len() as i32);
    for (topic, parts) in topics {
        write_string(&mut body, &topic);
        write_i32(&mut body, parts.len() as i32);
        for (partition, offset) in parts {
            write_i32(&mut body, partition);
            write_i64(&mut body, offset);
            write_i16(&mut body, -1);
        }
    }
    body
}

fn parse_offset_commit(bytes: &[u8]) -> Result<(), RunError> {
    let mut cursor = Cursor(bytes);
    let _correlation = cursor.i32()?;
    let topics = cursor.i32()?;
    for _ in 0..topics {
        let _name = cursor.string()?;
        let partitions = cursor.i32()?;
        for _ in 0..partitions {
            let _partition = cursor.i32()?;
            let error = cursor.i16()?;
            if error != 0 {
                return Err(fail(format!("kafka offset commit error code {error}")));
            }
        }
    }
    Ok(())
}

fn flag(plugin: &Plugin, name: &str) -> Option<bool> {
    match plugin.args.iter().find(|(key, _)| key == name) {
        Some((_, Arg::String(value))) => Some(value != "false"),
        Some((_, Arg::Int(value))) => Some(*value != 0),
        Some((_, _)) => Some(true),
        None => None,
    }
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use super::{crc32c, record_batch};
    use crate::run::{Ecs, Settings, run};
    use crate::value::Value;

    #[test]
    fn crc32c_matches_the_castagnoli_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn input_fetches_one_record_and_commits_the_next_offset() {
        let port = Arc::new(Mutex::new(0u16));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let port_slot = port.clone();
        let seen_slot = seen.clone();
        thread::spawn(move || input_broker(port_slot, seen_slot));
        let bound = loop {
            let value = *port.lock().expect("port");
            if value != 0 {
                break value;
            }
            thread::sleep(Duration::from_millis(10));
        };
        let config = format!(
            r#"
            input {{
              kafka {{
                bootstrap_servers => "127.0.0.1:{bound}"
                topics => ["logs"]
                auto_offset_reset => "earliest"
                decorate_events => "basic"
              }}
            }}
            output {{ null {{}} }}
            "#
        );
        let result = run(&config, &settings()).expect("fetch");
        assert_eq!(result.events.len(), 1);
        assert_eq!(
            result.events[0].get_field("message").expect("message"),
            Some(Value::from("hello-kafka"))
        );
        assert_eq!(
            result.events[0]
                .get_field("[@metadata][kafka][offset]")
                .expect("offset"),
            Some(Value::Integer(0))
        );
        let seen = seen.lock().expect("seen");
        let keys: Vec<i16> = seen
            .iter()
            .map(|request| i16::from_be_bytes([request[0], request[1]]))
            .collect();
        assert_eq!(keys, vec![3, 10, 9, 2, 1, 8]);
    }

    fn settings() -> Settings {
        Settings {
            workers: 1,
            batch_size: 125,
            batch_delay: Duration::from_millis(50),
            ecs: Ecs::Disabled,
            test_and_exit: false,
            stdin: None,
            workers_set: false,
            path_data: None,
            path_queue: None,
            persisted_queue: false,
            queue_page_capacity: 64 * 1024 * 1024,
            pipeline_id: String::from("main"),
            dlq_enabled: false,
            path_dlq: None,
            dlq_max_bytes: 1024 * 1024 * 1024,
            dlq_storage_policy: String::from("drop_newer"),
            api_port: None,
        }
    }

    fn input_broker(port_slot: Arc<Mutex<u16>>, seen: Arc<Mutex<Vec<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        *port_slot.lock().expect("port") = port;
        for _ in 0..6 {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            let mut size = [0u8; 4];
            stream.read_exact(&mut size).expect("size");
            let length = i32::from_be_bytes(size) as usize;
            let mut request = vec![0u8; length];
            stream.read_exact(&mut request).expect("body");
            let api = i16::from_be_bytes([request[0], request[1]]);
            let correlation =
                i32::from_be_bytes([request[8], request[9], request[10], request[11]]);
            seen.lock().expect("seen").push(request);
            let response = match api {
                3 => metadata(correlation, port),
                10 => coordinator(correlation, port),
                9 => missing_offset(correlation),
                2 => earliest(correlation),
                1 => fetch(correlation),
                _ => commit(correlation),
            };
            let mut framed = Vec::new();
            framed.extend_from_slice(&(response.len() as i32).to_be_bytes());
            framed.extend_from_slice(&response);
            stream.write_all(&framed).expect("write");
        }
    }

    fn string_bytes(value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(value.len() as i16).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
        out
    }

    fn metadata(correlation: i32, port: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&correlation.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend(string_bytes("127.0.0.1"));
        out.extend_from_slice(&i32::from(port).to_be_bytes());
        out.extend_from_slice(&(-1i16).to_be_bytes());
        out.extend_from_slice(&(-1i16).to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend_from_slice(&0i16.to_be_bytes());
        out.extend(string_bytes("logs"));
        out.push(0);
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend_from_slice(&0i16.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out
    }

    fn coordinator(correlation: i32, port: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&correlation.to_be_bytes());
        out.extend_from_slice(&0i16.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend(string_bytes("127.0.0.1"));
        out.extend_from_slice(&i32::from(port).to_be_bytes());
        out
    }

    fn missing_offset(correlation: i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&correlation.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend(string_bytes("logs"));
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&(-1i64).to_be_bytes());
        out.extend_from_slice(&(-1i16).to_be_bytes());
        out.extend_from_slice(&0i16.to_be_bytes());
        out
    }

    fn earliest(correlation: i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&correlation.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend(string_bytes("logs"));
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&0i16.to_be_bytes());
        out.extend_from_slice(&0i64.to_be_bytes());
        out.extend_from_slice(&0i64.to_be_bytes());
        out
    }

    fn fetch(correlation: i32) -> Vec<u8> {
        let batch = record_batch(None, b"hello-kafka");
        let mut out = Vec::new();
        out.extend_from_slice(&correlation.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend(string_bytes("logs"));
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&0i16.to_be_bytes());
        out.extend_from_slice(&1i64.to_be_bytes());
        out.extend_from_slice(&1i64.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&(batch.len() as i32).to_be_bytes());
        out.extend_from_slice(&batch);
        out
    }

    fn commit(correlation: i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&correlation.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend(string_bytes("logs"));
        out.extend_from_slice(&1i32.to_be_bytes());
        out.extend_from_slice(&0i32.to_be_bytes());
        out.extend_from_slice(&0i16.to_be_bytes());
        out
    }
}
