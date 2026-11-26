//! Dead-letter queue segments from logstash-core 9.5.2.
//!
//! A segment is `N.log`. Byte 0 is the character `1`. Each record is a 13-byte
//! header (type, size, total size or -1, CRC32) and a payload. A complete
//! payload is a `DLQEntry`: length-prefixed timestamp text, the event's Jackson
//! CBOR, then the plugin type, plugin id, and reason. Blocks are 32768 bytes.
//! This pass reads the segments that already exist and returns. It does not
//! wait for a writer to append more.

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};

use crate::event::Event;
use crate::queue_codec::{decode_event, encode_event};
use crate::run::{RunError, fail};
use crate::timefmt::format_timestamp;

const BLOCK_SIZE: u64 = 32_768;
const HEADER_SIZE: usize = 13;
const COMPLETE: u8 = b'c';
const START: u8 = b's';
const MIDDLE: u8 = b'm';
const END: u8 = b'e';
const SEGMENT_LIMIT: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DlqRecord {
    pub event: Event,
    pub plugin_type: String,
    pub plugin_id: String,
    pub reason: String,
    pub entry_time: String,
}

pub fn write_entry(
    dir: &Path,
    event: &Event,
    plugin_type: &str,
    plugin_id: &str,
    reason: &str,
    max_bytes: u64,
    storage_policy: &str,
) -> Result<(), RunError> {
    fs::create_dir_all(dir).map_err(|error| fail(error.to_string()))?;
    let payload = encode_dlq(event, plugin_type, plugin_id, reason, &entry_timestamp());
    let existing = segment_paths(dir)?;
    let (path, pos_in_block) = if let Some(last) = existing.last() {
        let len = fs::metadata(last).map(|meta| meta.len()).unwrap_or(0);
        if len + estimate_record(payload.len()) > SEGMENT_LIMIT {
            (next_segment(dir, last), 0usize)
        } else {
            (
                last.clone(),
                if len == 0 {
                    0
                } else {
                    ((len - 1) % BLOCK_SIZE) as usize
                },
            )
        }
    } else {
        (dir.join("1.log"), 0usize)
    };
    let record = encode_records(&payload, pos_in_block);
    if storage_policy == "drop_newer" && queue_size(dir)? + record.len() as u64 > max_bytes {
        return Err(fail(format!(
            "Cannot write event to DLQ(path: {}): reached maxQueueSize of {max_bytes}",
            dir.display()
        )));
    }
    if storage_policy == "drop_older" {
        while queue_size(dir)? + record.len() as u64 > max_bytes {
            let Some(oldest) = segment_paths(dir)?.into_iter().next() else {
                return Err(fail(format!(
                    "Queue size {} exceeded, but no complete DLQ segments found",
                    queue_size(dir)?
                )));
            };
            fs::remove_file(&oldest).map_err(|error| fail(error.to_string()))?;
        }
    } else if storage_policy != "drop_newer" {
        return Err(fail(format!(
            "dead_letter_queue.storage_policy {storage_policy} is not implemented"
        )));
    }
    append_record(&path, &record)
}

pub(crate) fn read_records_from(
    dir: &Path,
    segment: Option<&Path>,
    offset: u64,
) -> Result<(Vec<DlqRecord>, Option<PathBuf>, u64), RunError> {
    let paths = segment_paths(dir)?;
    let mut records = Vec::new();
    let mut started = segment.is_none();
    let mut last_path = None;
    let mut last_offset = 0u64;
    for path in paths {
        if !started {
            if segment.is_some_and(|segment| path != segment) {
                continue;
            }
            started = true;
        }
        let skip = if segment.is_some_and(|segment| path == segment) {
            offset
        } else {
            0
        };
        let (payloads, end) = read_segment_from(&path, skip)?;
        for payload in payloads {
            records.push(decode_dlq(&payload)?);
        }
        last_path = Some(path);
        last_offset = end;
    }
    Ok((records, last_path, last_offset))
}

fn entry_timestamp() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let time = DateTime::<Utc>::from_timestamp(nanos.as_secs() as i64, nanos.subsec_nanos())
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    format_timestamp(time)
}

fn encode_dlq(
    event: &Event,
    plugin_type: &str,
    plugin_id: &str,
    reason: &str,
    entry_time: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    put_length(&mut out, entry_time.as_bytes());
    put_length(&mut out, &encode_event(event));
    put_length(&mut out, plugin_type.as_bytes());
    put_length(&mut out, plugin_id.as_bytes());
    put_length(&mut out, reason.as_bytes());
    out
}

fn decode_dlq(bytes: &[u8]) -> Result<DlqRecord, RunError> {
    let mut offset = 0;
    let entry_time = take_string(bytes, &mut offset)?;
    let event_bytes = take_bytes(bytes, &mut offset)?;
    let plugin_type = take_string(bytes, &mut offset)?;
    let plugin_id = take_string(bytes, &mut offset)?;
    let reason = take_string(bytes, &mut offset)?;
    Ok(DlqRecord {
        event: decode_event(&event_bytes)?,
        plugin_type,
        plugin_id,
        reason,
        entry_time,
    })
}

fn put_length(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_bytes(bytes: &[u8], offset: &mut usize) -> Result<Vec<u8>, RunError> {
    if *offset + 4 > bytes.len() {
        return Err(fail("truncated dlq entry"));
    }
    let length =
        u32::from_be_bytes(bytes[*offset..*offset + 4].try_into().expect("4 bytes")) as usize;
    *offset += 4;
    if *offset + length > bytes.len() {
        return Err(fail("truncated dlq entry"));
    }
    let taken = bytes[*offset..*offset + length].to_vec();
    *offset += length;
    Ok(taken)
}

fn take_string(bytes: &[u8], offset: &mut usize) -> Result<String, RunError> {
    let raw = take_bytes(bytes, offset)?;
    String::from_utf8(raw).map_err(|_| fail("dlq string is not utf-8"))
}

fn estimate_record(payload: usize) -> u64 {
    (HEADER_SIZE + payload) as u64
}

fn encode_records(payload: &[u8], mut pos_in_block: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut previous = None;
    while offset < payload.len() {
        if pos_in_block + HEADER_SIZE + 1 > BLOCK_SIZE as usize {
            let pad = BLOCK_SIZE as usize - pos_in_block;
            out.extend(std::iter::repeat_n(0u8, pad));
            pos_in_block = 0;
        }
        let room = BLOCK_SIZE as usize - pos_in_block - HEADER_SIZE;
        let size = room.min(payload.len() - offset);
        let fits = size == payload.len() - offset;
        let kind = match previous {
            None if fits => COMPLETE,
            None => START,
            Some(START | MIDDLE) if fits => END,
            Some(START | MIDDLE) => MIDDLE,
            _ => COMPLETE,
        };
        let total = if kind == START {
            payload.len() as i32
        } else {
            -1
        };
        let checksum = crate::queue::crc32(&payload[offset..offset + size]);
        out.push(kind);
        out.extend_from_slice(&(size as u32).to_be_bytes());
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&payload[offset..offset + size]);
        pos_in_block += HEADER_SIZE + size;
        offset += size;
        previous = Some(kind);
    }
    out
}

fn append_record(path: &Path, record: &[u8]) -> Result<(), RunError> {
    let existed = path.is_file();
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| fail(error.to_string()))?;
    if !existed || file.metadata().map(|meta| meta.len()).unwrap_or(0) == 0 {
        file.write_all(b"1")
            .map_err(|error| fail(error.to_string()))?;
    } else {
        file.seek(SeekFrom::End(0))
            .map_err(|error| fail(error.to_string()))?;
    }
    file.write_all(record)
        .map_err(|error| fail(error.to_string()))?;
    Ok(())
}

fn read_segment_from(path: &Path, skip: u64) -> Result<(Vec<Vec<u8>>, u64), RunError> {
    let bytes = fs::read(path).map_err(|error| fail(error.to_string()))?;
    if bytes.is_empty() {
        return Ok((Vec::new(), 0));
    }
    if bytes[0] != b'1' {
        return Err(fail(format!(
            "dlq segment {} has version {}",
            path.display(),
            bytes[0]
        )));
    }
    let mut position = 1u64;
    let mut events = Vec::new();
    let mut pending: Option<Vec<u8>> = None;
    while position + HEADER_SIZE as u64 <= bytes.len() as u64 {
        let at = position as usize;
        let kind = bytes[at];
        if !matches!(kind, COMPLETE | START | MIDDLE | END) {
            let block = (position - 1) / BLOCK_SIZE;
            let next = (block + 1) * BLOCK_SIZE + 1;
            if next >= bytes.len() as u64 {
                break;
            }
            position = next;
            continue;
        }
        let size = u32::from_be_bytes(bytes[at + 1..at + 5].try_into().expect("4 bytes")) as usize;
        let checksum = u32::from_be_bytes(bytes[at + 9..at + 13].try_into().expect("4 bytes"));
        let start = at + HEADER_SIZE;
        let end = start + size;
        if end > bytes.len() {
            return Err(fail(format!("truncated dlq record in {}", path.display())));
        }
        let slice = &bytes[start..end];
        if crate::queue::crc32(slice) != checksum {
            return Err(fail(format!(
                "dlq record checksum mismatch in {}",
                path.display()
            )));
        }
        position = end as u64;
        match kind {
            COMPLETE => {
                if position > skip {
                    events.push(slice.to_vec());
                }
            }
            START | MIDDLE => {
                let buffer = pending.get_or_insert_with(Vec::new);
                buffer.extend_from_slice(slice);
            }
            END => {
                let mut buffer = pending.take().unwrap_or_default();
                buffer.extend_from_slice(slice);
                if position > skip {
                    events.push(buffer);
                }
            }
            _ => {}
        }
    }
    Ok((events, position))
}

pub(crate) fn segment_paths(dir: &Path) -> Result<Vec<PathBuf>, RunError> {
    let mut paths = Vec::new();
    if !dir.exists() {
        return Ok(paths);
    }
    for entry in fs::read_dir(dir).map_err(|error| fail(error.to_string()))? {
        let entry = entry.map_err(|error| fail(error.to_string()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(number) = name.strip_suffix(".log")
            && number.parse::<u32>().is_ok()
        {
            paths.push(entry.path());
        }
    }
    paths.sort_by_key(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".log"))
            .and_then(|number| number.parse::<u32>().ok())
            .unwrap_or(0)
    });
    Ok(paths)
}

fn next_segment(dir: &Path, last: &Path) -> PathBuf {
    let number = last
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".log"))
        .and_then(|number| number.parse::<u32>().ok())
        .unwrap_or(0);
    dir.join(format!("{}.log", number + 1))
}

fn queue_size(dir: &Path) -> Result<u64, RunError> {
    let mut total = 0u64;
    for path in segment_paths(dir)? {
        total += fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    }
    Ok(total)
}

pub(crate) fn write_sincedb(path: &Path, segment: &Path, offset: u64) -> Result<(), RunError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| fail(error.to_string()))?;
    }
    let text = segment.to_string_lossy();
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(&u16::from(b'1').to_be_bytes());
    let length = i32::try_from(bytes.len()).map_err(|_| fail("sincedb path is too long"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(&offset.to_be_bytes());
    fs::write(path, out).map_err(|error| fail(error.to_string()))
}

pub(crate) fn read_sincedb(path: &Path) -> Result<Option<(PathBuf, u64)>, RunError> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|error| fail(error.to_string()))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() < 2 {
        return Err(fail("truncated dlq sincedb"));
    }
    let version = u16::from_be_bytes(bytes[..2].try_into().expect("2 bytes"));
    if version != u16::from(b'1') {
        return Err(fail(format!(
            "Sincedb version: {} does not match: 1",
            char::from_u32(u32::from(version)).unwrap_or('?')
        )));
    }
    if bytes.len() < 6 {
        return Err(fail("truncated dlq sincedb"));
    }
    let length = i32::from_be_bytes(bytes[2..6].try_into().expect("4 bytes"));
    let length = usize::try_from(length).map_err(|_| fail("truncated dlq sincedb"))?;
    if bytes.len() < 6 + length + 8 {
        return Err(fail("truncated dlq sincedb"));
    }
    let segment = String::from_utf8(bytes[6..6 + length].to_vec())
        .map_err(|_| fail("dlq sincedb path is not utf-8"))?;
    let offset = u64::from_be_bytes(
        bytes[6 + length..6 + length + 8]
            .try_into()
            .expect("8 bytes"),
    );
    Ok(Some((PathBuf::from(segment), offset)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_entry_roundtrips_message_and_reason() {
        let dir = std::env::temp_dir().join(format!(
            "rstash-dlq-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let mut event = Event::new();
        event
            .set_field("message", crate::value::Value::from("dead"))
            .unwrap();
        write_entry(
            &dir,
            &event,
            "output",
            "stdout",
            "boom",
            u64::MAX,
            "drop_newer",
        )
        .unwrap();
        let (records, _, _) = read_records_from(&dir, None, 0).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].plugin_type, "output");
        assert_eq!(records[0].plugin_id, "stdout");
        assert_eq!(records[0].reason, "boom");
        assert_eq!(
            records[0].event.get_field("message").unwrap(),
            Some(crate::value::Value::from("dead"))
        );
        let raw = fs::read(dir.join("1.log")).unwrap();
        assert_eq!(raw[0], b'1');
        assert_eq!(raw[1], b'c');
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_input_emits_the_stored_event() {
        let root = std::env::temp_dir().join(format!(
            "rstash-dlq-in-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let queue = root.join("dlq");
        let mut event = Event::new();
        event
            .set_field("message", crate::value::Value::from("dead"))
            .unwrap();
        write_entry(
            &queue.join("main"),
            &event,
            "output",
            "stdout",
            "boom",
            u64::MAX,
            "drop_newer",
        )
        .unwrap();
        let path = queue.display().to_string().replace('\\', "/");
        let sincedb = root.join("sincedb");
        let sincedb_text = sincedb.display().to_string().replace('\\', "/");
        let settings = crate::run::Settings {
            workers: 1,
            batch_size: 125,
            batch_delay: std::time::Duration::from_millis(50),
            ecs: crate::run::Ecs::Disabled,
            test_and_exit: false,
            stdin: None,
            workers_set: false,
            path_data: Some(root.display().to_string()),
            path_queue: None,
            persisted_queue: false,
            queue_page_capacity: 1024,
            pipeline_id: String::from("main"),
            dlq_enabled: false,
            path_dlq: None,
            dlq_max_bytes: 1024 * 1024 * 1024,
            dlq_storage_policy: String::from("drop_newer"),
        };
        let ran = crate::run::run(
            &format!(
                "input {{ dead_letter_queue {{ path => \"{path}\" sincedb_path => \"{sincedb_text}\" }} }} output {{ stdout {{ codec => plain }} }}"
            ),
            &settings,
        )
        .unwrap();
        assert!(ran.stdout.contains("dead"), "{}", ran.stdout);
        assert_eq!(
            ran.events[0]
                .get_field("[@metadata][dead_letter_queue][reason]")
                .unwrap(),
            Some(crate::value::Value::from("boom"))
        );
        let _ = fs::remove_dir_all(&root);
    }
}
