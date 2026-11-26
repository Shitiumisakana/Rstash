//! Persistent-queue pages and checkpoints from logstash-core 9.5.2.
//!
//! `MmapPageIOV2` writes a version byte, then each element as a big-endian
//! sequence number, a big-endian length, the bytes, and a CRC32 of those bytes.
//! `FileCheckpointIO` writes 34 bytes: version 1 as a short, then the five
//! checkpoint fields, then a CRC32 of the first 30 bytes. The unused tail of a
//! page file is zeros out to the page capacity.

use crate::run::{RunError, fail};

pub(crate) const PAGE_VERSION: u8 = 2;
pub(crate) const CHECKPOINT_VERSION: u16 = 1;
pub(crate) const MIN_PAGE_CAPACITY: usize = 18;
const CHECKPOINT_BYTES: usize = 34;
const CHECKPOINT_CRC_AT: usize = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub page_num: i32,
    pub first_unacked_page_num: i32,
    pub first_unacked_seq_num: u64,
    pub min_seq_num: u64,
    pub element_count: i32,
}

pub fn check_directory(dir: &std::path::Path) -> Result<(), RunError> {
    let head = read_checkpoint(&read_file(&dir.join(head_checkpoint_name()))?)?;
    let page = read_file(&dir.join(page_name(head.page_num)))?;
    let count =
        usize::try_from(head.element_count).map_err(|_| fail("element count is negative"))?;
    read_page(&page, head.min_seq_num, count)?;
    let tail = dir.join(tail_checkpoint_name(head.page_num));
    if tail.is_file() {
        read_checkpoint(&read_file(&tail)?)?;
    }
    Ok(())
}

fn read_file(path: &std::path::Path) -> Result<Vec<u8>, RunError> {
    std::fs::read(path).map_err(|error| fail(format!("cannot read {}: {error}", path.display())))
}

pub(crate) fn page_name(page_num: i32) -> String {
    format!("page.{page_num}")
}

pub(crate) fn head_checkpoint_name() -> &'static str {
    "checkpoint.head"
}

pub(crate) fn tail_checkpoint_name(page_num: i32) -> String {
    format!("checkpoint.{page_num}")
}

pub fn write_page(capacity: usize, elements: &[(u64, &[u8])]) -> Result<Vec<u8>, RunError> {
    if capacity < MIN_PAGE_CAPACITY {
        return Err(fail(format!(
            "page capacity {capacity} is below {MIN_PAGE_CAPACITY}"
        )));
    }
    let mut page = vec![0u8; capacity];
    page[0] = PAGE_VERSION;
    let mut head = 1usize;
    for (seq_num, payload) in elements {
        let size = persisted_byte_count(payload.len());
        if head + size > capacity {
            return Err(fail("page is full"));
        }
        page[head..head + 8].copy_from_slice(&seq_num.to_be_bytes());
        let length = u32::try_from(payload.len()).map_err(|_| fail("element is too large"))?;
        page[head + 8..head + 12].copy_from_slice(&length.to_be_bytes());
        page[head + 12..head + 12 + payload.len()].copy_from_slice(payload);
        let checksum = crc32(payload);
        page[head + 12 + payload.len()..head + size].copy_from_slice(&checksum.to_be_bytes());
        head += size;
    }
    Ok(page)
}

pub fn read_page(
    bytes: &[u8],
    min_seq_num: u64,
    element_count: usize,
) -> Result<Vec<(u64, Vec<u8>)>, RunError> {
    if bytes.len() < MIN_PAGE_CAPACITY {
        return Err(fail("corrupted page"));
    }
    if bytes[0] != PAGE_VERSION {
        return Err(fail(format!("invalid page version {}", bytes[0])));
    }
    let mut head = 1usize;
    let mut elements = Vec::with_capacity(element_count);
    for index in 0..element_count {
        let expected = min_seq_num + index as u64;
        if head + 12 > bytes.len() {
            return Err(fail(
                "cannot read seqNum and length bytes past buffer capacity",
            ));
        }
        let seq_num = u64::from_be_bytes(bytes[head..head + 8].try_into().expect("8 bytes"));
        if seq_num != expected {
            return Err(fail(format!(
                "Element seqNum {seq_num} is expected to be {expected}"
            )));
        }
        let length = u32::from_be_bytes(bytes[head + 8..head + 12].try_into().expect("4 bytes"));
        if length == 0 {
            return Err(fail("Element invalid length"));
        }
        let length = length as usize;
        let payload_at = head + 12;
        let checksum_at = payload_at + length;
        if checksum_at + 4 > bytes.len() {
            return Err(fail(
                "cannot read element payload and checksum past buffer capacity",
            ));
        }
        let payload = bytes[payload_at..checksum_at].to_vec();
        let stored = u32::from_be_bytes(
            bytes[checksum_at..checksum_at + 4]
                .try_into()
                .expect("4 bytes"),
        );
        if crc32(&payload) != stored {
            return Err(fail("Element invalid checksum"));
        }
        elements.push((seq_num, payload));
        head = checksum_at + 4;
    }
    Ok(elements)
}

pub fn write_checkpoint(checkpoint: &Checkpoint) -> Vec<u8> {
    let mut bytes = vec![0u8; CHECKPOINT_BYTES];
    bytes[..2].copy_from_slice(&CHECKPOINT_VERSION.to_be_bytes());
    bytes[2..6].copy_from_slice(&checkpoint.page_num.to_be_bytes());
    bytes[6..10].copy_from_slice(&checkpoint.first_unacked_page_num.to_be_bytes());
    bytes[10..18].copy_from_slice(&checkpoint.first_unacked_seq_num.to_be_bytes());
    bytes[18..26].copy_from_slice(&checkpoint.min_seq_num.to_be_bytes());
    bytes[26..30].copy_from_slice(&checkpoint.element_count.to_be_bytes());
    let checksum = crc32(&bytes[..CHECKPOINT_CRC_AT]);
    bytes[30..34].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

pub fn read_checkpoint(bytes: &[u8]) -> Result<Checkpoint, RunError> {
    if bytes.len() < CHECKPOINT_BYTES {
        return Err(fail("checkpoint is short"));
    }
    let version = u16::from_be_bytes(bytes[..2].try_into().expect("2 bytes"));
    let stored = u32::from_be_bytes(bytes[30..34].try_into().expect("4 bytes"));
    let computed = crc32(&bytes[..CHECKPOINT_CRC_AT]);
    if computed != stored {
        return Err(fail(format!(
            "Checkpoint checksum mismatch, expected: {computed}, actual: {stored}"
        )));
    }
    if version != CHECKPOINT_VERSION {
        return Err(fail(format!("Unknown checkpoint version {version}")));
    }
    Ok(Checkpoint {
        page_num: i32::from_be_bytes(bytes[2..6].try_into().expect("4 bytes")),
        first_unacked_page_num: i32::from_be_bytes(bytes[6..10].try_into().expect("4 bytes")),
        first_unacked_seq_num: u64::from_be_bytes(bytes[10..18].try_into().expect("8 bytes")),
        min_seq_num: u64::from_be_bytes(bytes[18..26].try_into().expect("8 bytes")),
        element_count: i32::from_be_bytes(bytes[26..30].try_into().expect("4 bytes")),
    })
}

struct Stored {
    page: i32,
    seq: u64,
    bytes: Vec<u8>,
}

pub(crate) struct DiskQueue {
    dir: std::path::PathBuf,
    capacity: usize,
    checkpoint: Checkpoint,
    elements: Vec<Stored>,
    acked: usize,
    next_seq: u64,
}

impl DiskQueue {
    pub(crate) fn open(dir: &std::path::Path, capacity: usize) -> Result<Self, RunError> {
        std::fs::create_dir_all(dir).map_err(|error| fail(error.to_string()))?;
        let version = dir.join(".queue-version");
        if !version.exists() {
            std::fs::write(&version, 2i32.to_be_bytes())
                .map_err(|error| fail(error.to_string()))?;
        }
        let lock = dir.join(".lock");
        if !lock.exists() {
            std::fs::write(&lock, b"").map_err(|error| fail(error.to_string()))?;
        }
        let head_path = dir.join(head_checkpoint_name());
        if !head_path.exists() {
            let checkpoint = Checkpoint {
                page_num: 0,
                first_unacked_page_num: 0,
                first_unacked_seq_num: 0,
                min_seq_num: 0,
                element_count: 0,
            };
            let page = write_page(capacity, &[])?;
            std::fs::write(dir.join(page_name(0)), page)
                .map_err(|error| fail(error.to_string()))?;
            store_checkpoint(&head_path, &checkpoint)?;
            return Ok(Self {
                dir: dir.to_path_buf(),
                capacity,
                checkpoint,
                elements: Vec::new(),
                acked: 0,
                next_seq: 1,
            });
        }
        let mut checkpoint = read_checkpoint(&read_file(&head_path)?)?;
        let page_path = dir.join(page_name(checkpoint.page_num));
        let page = read_file(&page_path)?;
        let capacity = page.len().max(capacity);
        if checkpoint.element_count > 0 {
            store_checkpoint(
                &dir.join(tail_checkpoint_name(checkpoint.page_num)),
                &checkpoint,
            )?;
            let sealed = checkpoint.page_num;
            checkpoint = Checkpoint {
                page_num: sealed + 1,
                first_unacked_page_num: checkpoint.first_unacked_page_num,
                first_unacked_seq_num: 0,
                min_seq_num: 0,
                element_count: 0,
            };
            let fresh = write_page(capacity, &[])?;
            std::fs::write(dir.join(page_name(checkpoint.page_num)), fresh)
                .map_err(|error| fail(error.to_string()))?;
            store_checkpoint(&head_path, &checkpoint)?;
        }
        let elements = load_unacked(dir, &checkpoint)?;
        let next_seq = next_sequence(dir, &checkpoint)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            capacity,
            checkpoint,
            elements,
            acked: 0,
            next_seq,
        })
    }

    pub(crate) fn unacked_events(&self) -> Result<Vec<crate::event::Event>, RunError> {
        self.elements[self.acked..]
            .iter()
            .map(|stored| crate::queue_codec::decode_event(&stored.bytes))
            .collect()
    }

    pub(crate) fn append(&mut self, event: &crate::event::Event) -> Result<(), RunError> {
        let payload = crate::queue_codec::encode_event(event);
        let needed = persisted_byte_count(payload.len());
        if self.page_used(self.checkpoint.page_num) + needed > self.capacity {
            if self.checkpoint.element_count == 0 {
                return Err(fail("page is full"));
            }
            store_checkpoint(
                &self
                    .dir
                    .join(tail_checkpoint_name(self.checkpoint.page_num)),
                &self.checkpoint,
            )?;
            let next = self.checkpoint.page_num + 1;
            self.checkpoint = Checkpoint {
                page_num: next,
                first_unacked_page_num: self.checkpoint.first_unacked_page_num,
                first_unacked_seq_num: 0,
                min_seq_num: 0,
                element_count: 0,
            };
            let fresh = write_page(self.capacity, &[])?;
            std::fs::write(self.dir.join(page_name(next)), fresh)
                .map_err(|error| fail(error.to_string()))?;
            store_checkpoint(&self.dir.join(head_checkpoint_name()), &self.checkpoint)?;
            if 1 + needed > self.capacity {
                return Err(fail("page is full"));
            }
        }
        let seq = self.next_seq;
        let page_num = self.checkpoint.page_num;
        self.elements.push(Stored {
            page: page_num,
            seq,
            bytes: payload,
        });
        self.rewrite_page(page_num)?;
        if self.checkpoint.element_count == 0 {
            self.checkpoint.min_seq_num = seq;
            self.checkpoint.first_unacked_seq_num = seq;
        }
        self.checkpoint.element_count += 1;
        self.next_seq = seq + 1;
        store_checkpoint(&self.dir.join(head_checkpoint_name()), &self.checkpoint)
    }

    pub(crate) fn ack(&mut self, count: usize) -> Result<(), RunError> {
        if count == 0 {
            return Ok(());
        }
        if self.acked + count > self.elements.len() {
            return Err(fail("ack past the end of the page"));
        }
        let end = self.acked + count;
        while self.acked < end {
            let page = self.elements[self.acked].page;
            let page_end = self.elements[self.acked..]
                .iter()
                .position(|stored| stored.page != page)
                .map(|offset| self.acked + offset)
                .unwrap_or(self.elements.len());
            let take_until = page_end.min(end);
            self.acked = take_until;
            if take_until < page_end {
                let next_seq = self.elements[self.acked].seq;
                if page == self.checkpoint.page_num {
                    self.checkpoint.first_unacked_seq_num = next_seq;
                    store_checkpoint(&self.dir.join(head_checkpoint_name()), &self.checkpoint)?;
                } else {
                    let mut checkpoint =
                        read_checkpoint(&read_file(&self.dir.join(tail_checkpoint_name(page)))?)?;
                    checkpoint.first_unacked_seq_num = next_seq;
                    store_checkpoint(&self.dir.join(tail_checkpoint_name(page)), &checkpoint)?;
                }
            } else if page == self.checkpoint.page_num {
                let old = self.dir.join(page_name(page));
                if old.exists() {
                    std::fs::remove_file(&old).map_err(|error| fail(error.to_string()))?;
                }
                let next = page + 1;
                self.checkpoint = Checkpoint {
                    page_num: next,
                    first_unacked_page_num: next,
                    first_unacked_seq_num: 0,
                    min_seq_num: 0,
                    element_count: 0,
                };
                let fresh = write_page(self.capacity, &[])?;
                std::fs::write(self.dir.join(page_name(next)), fresh)
                    .map_err(|error| fail(error.to_string()))?;
                self.next_seq = 1;
                store_checkpoint(&self.dir.join(head_checkpoint_name()), &self.checkpoint)?;
            } else {
                let old = self.dir.join(page_name(page));
                if old.exists() {
                    std::fs::remove_file(&old).map_err(|error| fail(error.to_string()))?;
                }
                let checkpoint_path = self.dir.join(tail_checkpoint_name(page));
                if checkpoint_path.exists() {
                    std::fs::remove_file(&checkpoint_path)
                        .map_err(|error| fail(error.to_string()))?;
                }
                if self.checkpoint.first_unacked_page_num == page {
                    self.checkpoint.first_unacked_page_num = self
                        .elements
                        .get(self.acked)
                        .map(|stored| stored.page)
                        .unwrap_or(self.checkpoint.page_num);
                    if self.checkpoint.element_count == 0 {
                        self.checkpoint.first_unacked_seq_num = 0;
                        self.checkpoint.min_seq_num = 0;
                    }
                    if self.checkpoint.first_unacked_page_num == self.checkpoint.page_num
                        && self.checkpoint.element_count == 0
                    {
                        self.next_seq = 1;
                    }
                    store_checkpoint(&self.dir.join(head_checkpoint_name()), &self.checkpoint)?;
                }
            }
        }
        Ok(())
    }

    fn page_used(&self, page: i32) -> usize {
        self.elements
            .iter()
            .filter(|stored| stored.page == page)
            .fold(1usize, |used, stored| {
                used + persisted_byte_count(stored.bytes.len())
            })
    }

    fn rewrite_page(&self, page: i32) -> Result<(), RunError> {
        let view: Vec<(u64, &[u8])> = self
            .elements
            .iter()
            .filter(|stored| stored.page == page)
            .map(|stored| (stored.seq, stored.bytes.as_slice()))
            .collect();
        let bytes = write_page(self.capacity, &view)?;
        std::fs::write(self.dir.join(page_name(page)), bytes)
            .map_err(|error| fail(error.to_string()))
    }
}

fn load_unacked(dir: &std::path::Path, head: &Checkpoint) -> Result<Vec<Stored>, RunError> {
    let mut elements = Vec::new();
    let mut page = head.first_unacked_page_num;
    while page < head.page_num {
        let checkpoint = read_checkpoint(&read_file(&dir.join(tail_checkpoint_name(page)))?)?;
        push_page(&mut elements, dir, page, &checkpoint)?;
        page += 1;
    }
    if head.element_count > 0 {
        push_page(&mut elements, dir, head.page_num, head)?;
    }
    Ok(elements)
}

fn push_page(
    elements: &mut Vec<Stored>,
    dir: &std::path::Path,
    page: i32,
    checkpoint: &Checkpoint,
) -> Result<(), RunError> {
    let count =
        usize::try_from(checkpoint.element_count).map_err(|_| fail("element count is negative"))?;
    if count == 0 {
        return Ok(());
    }
    let bytes = read_file(&dir.join(page_name(page)))?;
    for (seq, payload) in read_page(&bytes, checkpoint.min_seq_num, count)? {
        if seq >= checkpoint.first_unacked_seq_num {
            elements.push(Stored {
                page,
                seq,
                bytes: payload,
            });
        }
    }
    Ok(())
}

fn next_sequence(dir: &std::path::Path, head: &Checkpoint) -> Result<u64, RunError> {
    if head.element_count == 0 && head.first_unacked_page_num == head.page_num {
        return Ok(1);
    }
    if head.element_count > 0 {
        return Ok(head.min_seq_num + head.element_count as u64);
    }
    let previous = read_checkpoint(&read_file(
        &dir.join(tail_checkpoint_name(head.page_num - 1)),
    )?)?;
    Ok(previous.min_seq_num + previous.element_count as u64)
}

/// `PqRepair` from logstash-core 9.5.2.
///
/// Deletes `checkpoint.*.tmp`, pages and checkpoints fully below
/// `checkpoint.head`'s first unacked page, checkpoints with no page, and pages
/// shorter than 18 bytes. Every page except the highest one gets a 34-byte
/// checkpoint rebuilt from the page bytes when its checkpoint is missing or
/// the wrong length.
pub fn repair(dir: &std::path::Path) -> Result<(), RunError> {
    if !dir.is_dir() {
        return Err(fail(format!(
            "Given PQ path {} is not a directory.",
            dir.display()
        )));
    }
    let mut pages = std::collections::BTreeMap::<i32, std::path::PathBuf>::new();
    let mut checkpoints = std::collections::BTreeMap::<i32, std::path::PathBuf>::new();
    for entry in std::fs::read_dir(dir).map_err(|error| fail(error.to_string()))? {
        let entry = entry.map_err(|error| fail(error.to_string()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if is_temp_checkpoint(name) {
            std::fs::remove_file(entry.path()).map_err(|error| fail(error.to_string()))?;
            continue;
        }
        if let Some(number) = name.strip_prefix("page.") {
            if let Ok(number) = number.parse::<i32>() {
                pages.insert(number, entry.path());
            }
        } else if name != head_checkpoint_name()
            && let Some(number) = name.strip_prefix("checkpoint.")
            && let Ok(number) = number.parse::<i32>()
        {
            checkpoints.insert(number, entry.path());
        }
    }
    let head_path = dir.join(head_checkpoint_name());
    if head_path.is_file() {
        let head = read_checkpoint(&read_file(&head_path)?)?;
        let first = head.first_unacked_page_num;
        for number in pages.keys().copied().collect::<Vec<_>>() {
            if number >= first {
                break;
            }
            if let Some(path) = pages.remove(&number) {
                std::fs::remove_file(path).map_err(|error| fail(error.to_string()))?;
            }
        }
        for number in checkpoints.keys().copied().collect::<Vec<_>>() {
            if number >= first {
                break;
            }
            if let Some(path) = checkpoints.remove(&number) {
                std::fs::remove_file(path).map_err(|error| fail(error.to_string()))?;
            }
        }
    }
    for number in checkpoints.keys().copied().collect::<Vec<_>>() {
        if !pages.contains_key(&number)
            && let Some(path) = checkpoints.remove(&number)
        {
            std::fs::remove_file(path).map_err(|error| fail(error.to_string()))?;
        }
    }
    for number in pages.keys().copied().collect::<Vec<_>>() {
        let Some(path) = pages.get(&number) else {
            continue;
        };
        let length = std::fs::metadata(path)
            .map_err(|error| fail(error.to_string()))?
            .len();
        if length >= MIN_PAGE_CAPACITY as u64 {
            continue;
        }
        std::fs::remove_file(path).map_err(|error| fail(error.to_string()))?;
        pages.remove(&number);
        if let Some(checkpoint) = checkpoints.remove(&number) {
            std::fs::remove_file(checkpoint).map_err(|error| fail(error.to_string()))?;
        }
    }
    let numbers = pages.keys().copied().collect::<Vec<_>>();
    if numbers.len() > 1 {
        for number in &numbers[..numbers.len() - 1] {
            let path = &pages[number];
            let missing = !checkpoints.contains_key(number);
            let short = checkpoints.get(number).is_some_and(|checkpoint| {
                std::fs::metadata(checkpoint)
                    .map(|meta| meta.len() != 34)
                    .unwrap_or(true)
            });
            if missing || short {
                if let Some(checkpoint) = checkpoints.get(number) {
                    std::fs::remove_file(checkpoint).map_err(|error| fail(error.to_string()))?;
                }
                recreate_checkpoint(path, *number)?;
            }
        }
    }
    Ok(())
}

fn is_temp_checkpoint(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("checkpoint.") else {
        return false;
    };
    rest.ends_with(".tmp") && rest != ".tmp"
}

fn recreate_checkpoint(path: &std::path::Path, page_num: i32) -> Result<(), RunError> {
    let bytes = read_file(path)?;
    if bytes.is_empty() {
        return Err(fail(format!(
            "Pagefile {} contains version byte 0, this tool only supports versions 1 and 2.",
            path.display()
        )));
    }
    let version = bytes[0];
    if version != 1 && version != PAGE_VERSION {
        return Err(fail(format!(
            "Pagefile {} contains version byte {version}, this tool only supports versions 1 and 2.",
            path.display()
        )));
    }
    if bytes.len() < 13 {
        return Err(fail(format!(
            "Pagefile {} is too short to rebuild a checkpoint.",
            path.display()
        )));
    }
    let min_seq = u64::from_be_bytes(bytes[1..9].try_into().expect("8 bytes"));
    let length = u32::from_be_bytes(bytes[9..13].try_into().expect("4 bytes")) as u64;
    let mut position = 13 + length + 4;
    let mut count = 1i32;
    let size = bytes.len() as u64;
    while position < size.saturating_sub(18) {
        let at = position as usize;
        let next = if at + 12 <= bytes.len() {
            u32::from_be_bytes(bytes[at + 8..at + 12].try_into().expect("4 bytes")) as u64
        } else {
            0
        };
        position = position + next + 4;
        count += 1;
    }
    let checkpoint = Checkpoint {
        page_num,
        first_unacked_page_num: 0,
        first_unacked_seq_num: min_seq,
        min_seq_num: min_seq,
        element_count: count,
    };
    store_checkpoint(
        &path.with_file_name(tail_checkpoint_name(page_num)),
        &checkpoint,
    )
}

fn store_checkpoint(path: &std::path::Path, checkpoint: &Checkpoint) -> Result<(), RunError> {
    let bytes = write_checkpoint(checkpoint);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|error| fail(error.to_string()))?;
    if path.exists() {
        std::fs::remove_file(path).map_err(|error| fail(error.to_string()))?;
    }
    std::fs::rename(&tmp, path).map_err(|error| fail(error.to_string()))
}

#[cfg(test)]
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
}

fn persisted_byte_count(length: usize) -> usize {
    12 + length + 4
}

/// Java `java.util.zip.CRC32`.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes written by `MmapPageIOV2` and `FileCheckpointIO` from logstash-core 9.5.2.
    /// Page capacity 1024, one element, sequence 1, payload `hello`.
    const PAGE_PREFIX: &[u8] = &[
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, b'h', b'e',
        b'l', b'l', b'o', 0x36, 0x10, 0xA6, 0x86,
    ];
    const CHECKPOINT: &[u8] = &[
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0xF4, 0xF2, 0x27, 0x32,
    ];

    #[test]
    fn page_and_checkpoint_match_the_9_5_2_bytes() {
        let page = write_page(1024, &[(1, b"hello")]).unwrap();
        assert_eq!(page.len(), 1024);
        assert_eq!(&page[..PAGE_PREFIX.len()], PAGE_PREFIX);
        assert!(page[PAGE_PREFIX.len()..].iter().all(|byte| *byte == 0));
        let elements = read_page(&page, 1, 1).unwrap();
        assert_eq!(elements, vec![(1, b"hello".to_vec())]);

        let checkpoint = Checkpoint {
            page_num: 0,
            first_unacked_page_num: 0,
            first_unacked_seq_num: 1,
            min_seq_num: 1,
            element_count: 1,
        };
        assert_eq!(write_checkpoint(&checkpoint), CHECKPOINT);
        assert_eq!(read_checkpoint(CHECKPOINT).unwrap(), checkpoint);
        assert_eq!(head_checkpoint_name(), "checkpoint.head");
        assert_eq!(tail_checkpoint_name(0), "checkpoint.0");
        assert_eq!(page_name(0), "page.0");
    }

    #[test]
    fn pqcheck_reads_the_official_directory() {
        let dir = std::env::temp_dir().join(format!(
            "rstash-pq-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut page = PAGE_PREFIX.to_vec();
        page.resize(1024, 0);
        std::fs::write(dir.join("page.0"), page).unwrap();
        std::fs::write(dir.join("checkpoint.head"), CHECKPOINT).unwrap();
        std::fs::write(dir.join("checkpoint.0"), CHECKPOINT).unwrap();
        check_directory(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_and_fully_acked_checkpoints_match_9_5_2() {
        let empty = Checkpoint {
            page_num: 0,
            first_unacked_page_num: 0,
            first_unacked_seq_num: 0,
            min_seq_num: 0,
            element_count: 0,
        };
        assert_eq!(
            write_checkpoint(&empty),
            hex("0001000000000000000000000000000000000000000000000000000000006303e791")
        );
        let acked = Checkpoint {
            page_num: 1,
            first_unacked_page_num: 1,
            first_unacked_seq_num: 0,
            min_seq_num: 0,
            element_count: 0,
        };
        assert_eq!(
            write_checkpoint(&acked),
            hex("0001000000010000000100000000000000000000000000000000000000005952f401")
        );
    }

    #[test]
    fn official_event_cbor_keeps_message_and_timestamp() {
        let bytes = hex(
            "d901009f716a6176612e7574696c2e486173684d6170bf64444154419f78196f72672e6c6f6773746173682e436f6e7665727465644d6170bf676d6573736167659f746f72672e6a727562792e52756279537472696e676568656c6c6fff6a4074696d657374616d709f766f72672e6c6f6773746173682e54696d657374616d70781e323032362d31312d32365430323a31393a32372e3235353638323430305aff684076657273696f6e6131ffff644d4554419fd81902bfffffffff",
        );
        let event = crate::queue_codec::decode_event(&bytes).unwrap();
        assert_eq!(
            event.get_field("message").unwrap(),
            Some(crate::value::Value::from("hello"))
        );
        let text = event.to_json().unwrap();
        assert!(text.contains("2026-11-26T02:19:27.255682400Z"), "{text}");
    }

    #[test]
    fn disk_queue_acks_a_page_the_way_9_5_2_does() {
        let dir = std::env::temp_dir().join(format!(
            "rstash-disk-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let mut queue = DiskQueue::open(&dir, 1024).unwrap();
        let head = std::fs::read(dir.join("checkpoint.head")).unwrap();
        assert_eq!(
            head,
            hex("0001000000000000000000000000000000000000000000000000000000006303e791")
        );
        let mut event = crate::event::Event::new();
        event
            .set_field("message", crate::value::Value::from("hello"))
            .unwrap();
        queue.append(&event).unwrap();
        let read = queue.unacked_events().unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(
            read[0].get_field("message").unwrap(),
            Some(crate::value::Value::from("hello"))
        );
        queue.ack(1).unwrap();
        assert!(dir.join("page.1").is_file());
        assert!(!dir.join("page.0").exists());
        let head = std::fs::read(dir.join("checkpoint.head")).unwrap();
        assert_eq!(
            head,
            hex("0001000000010000000100000000000000000000000000000000000000005952f401")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persisted_pipeline_acks_the_page_after_stdout() {
        let dir = std::env::temp_dir().join(format!(
            "rstash-pq-run-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let settings = crate::run::Settings {
            workers: 1,
            batch_size: 125,
            batch_delay: std::time::Duration::from_millis(50),
            ecs: crate::run::Ecs::Disabled,
            test_and_exit: false,
            stdin: None,
            workers_set: false,
            path_data: Some(dir.to_string_lossy().into_owned()),
            path_queue: None,
            persisted_queue: true,
            queue_page_capacity: 1024,
            pipeline_id: String::from("main"),
            dlq_enabled: false,
            path_dlq: None,
            dlq_max_bytes: 1024 * 1024 * 1024,
            dlq_storage_policy: String::from("drop_newer"),
        };
        let ran = crate::run::run(
            r#"input { generator { count => 1 message => "queued" } } output { stdout { codec => plain } }"#,
            &settings,
        )
        .unwrap();
        assert!(ran.stdout.contains("queued"), "{}", ran.stdout);
        let queue = dir.join("queue").join("main");
        assert!(queue.join("page.1").is_file());
        assert!(!queue.join("page.0").exists());
        let head = std::fs::read(queue.join("checkpoint.head")).unwrap();
        assert_eq!(
            head,
            hex("0001000000010000000100000000000000000000000000000000000000005952f401")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_queue_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rstash-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reopening_a_tail_seals_it_and_keeps_the_event() {
        let dir = temp_queue_dir("seal");
        let mut queue = DiskQueue::open(&dir, 1024).unwrap();
        let mut event = crate::event::Event::new();
        event
            .set_field("message", crate::value::Value::from("kept"))
            .unwrap();
        queue.append(&event).unwrap();
        drop(queue);
        let mut queue = DiskQueue::open(&dir, 1024).unwrap();
        assert!(dir.join("checkpoint.0").is_file());
        assert!(dir.join("page.1").is_file());
        let head = read_checkpoint(&std::fs::read(dir.join("checkpoint.head")).unwrap()).unwrap();
        assert_eq!(head.page_num, 1);
        assert_eq!(head.element_count, 0);
        assert_eq!(head.first_unacked_page_num, 0);
        let read = queue.unacked_events().unwrap();
        assert_eq!(read.len(), 1);
        queue.append(&event).unwrap();
        let page = std::fs::read(dir.join("page.1")).unwrap();
        let seq = u64::from_be_bytes(page[1..9].try_into().unwrap());
        assert_eq!(seq, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_full_page_rolls_and_keeps_global_sequence_numbers() {
        let dir = temp_queue_dir("roll");
        let mut queue = DiskQueue::open(&dir, 500).unwrap();
        for index in 0..3 {
            let mut event = crate::event::Event::new();
            event
                .set_field("message", crate::value::Value::from(format!("m{index}")))
                .unwrap();
            queue.append(&event).unwrap();
        }
        assert!(dir.join("page.0").is_file());
        assert!(dir.join("page.1").is_file());
        let sealed = read_checkpoint(&std::fs::read(dir.join("checkpoint.0")).unwrap()).unwrap();
        assert_eq!(sealed.page_num, 0);
        assert_eq!(sealed.min_seq_num, 1);
        assert!(sealed.element_count >= 1);
        let head = read_checkpoint(&std::fs::read(dir.join("checkpoint.head")).unwrap()).unwrap();
        assert_eq!(head.page_num, 1);
        assert_eq!(head.min_seq_num, sealed.element_count as u64 + 1);
        let read = queue.unacked_events().unwrap();
        assert_eq!(read.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn acking_a_sealed_page_leaves_the_empty_tail() {
        let dir = temp_queue_dir("ackseal");
        let mut queue = DiskQueue::open(&dir, 1024).unwrap();
        for index in 0..2 {
            let mut event = crate::event::Event::new();
            event
                .set_field("message", crate::value::Value::from(format!("m{index}")))
                .unwrap();
            queue.append(&event).unwrap();
        }
        drop(queue);
        let mut queue = DiskQueue::open(&dir, 1024).unwrap();
        queue.ack(1).unwrap();
        let sealed = read_checkpoint(&std::fs::read(dir.join("checkpoint.0")).unwrap()).unwrap();
        assert_eq!(sealed.first_unacked_seq_num, 2);
        assert_eq!(sealed.min_seq_num, 1);
        assert_eq!(sealed.element_count, 2);
        queue.ack(1).unwrap();
        assert!(!dir.join("page.0").exists());
        assert!(!dir.join("checkpoint.0").exists());
        let head = read_checkpoint(&std::fs::read(dir.join("checkpoint.head")).unwrap()).unwrap();
        assert_eq!(head.page_num, 1);
        assert_eq!(head.first_unacked_page_num, 1);
        assert_eq!(head.element_count, 0);
        assert!(dir.join("page.1").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pqrepair_drops_acked_pages_and_rebuilds_a_checkpoint() {
        let dir = temp_queue_dir("repair");
        std::fs::write(dir.join("page.0"), PAGE_PREFIX).unwrap();
        std::fs::write(
            dir.join("page.1"),
            vec![
                PAGE_VERSION,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        )
        .unwrap();
        let head = Checkpoint {
            page_num: 1,
            first_unacked_page_num: 0,
            first_unacked_seq_num: 0,
            min_seq_num: 0,
            element_count: 0,
        };
        std::fs::write(dir.join("checkpoint.head"), write_checkpoint(&head)).unwrap();
        std::fs::write(dir.join("checkpoint.7.tmp"), b"temp").unwrap();
        std::fs::write(dir.join("checkpoint.8"), write_checkpoint(&head)).unwrap();
        std::fs::write(dir.join("page.4"), vec![PAGE_VERSION, 0, 0, 0]).unwrap();
        std::fs::write(dir.join("checkpoint.4"), write_checkpoint(&head)).unwrap();
        repair(&dir).unwrap();
        assert!(!dir.join("checkpoint.7.tmp").exists());
        assert!(!dir.join("checkpoint.8").exists());
        assert!(!dir.join("page.4").exists());
        assert!(!dir.join("checkpoint.4").exists());
        let rebuilt = read_checkpoint(&std::fs::read(dir.join("checkpoint.0")).unwrap()).unwrap();
        assert_eq!(rebuilt.page_num, 0);
        assert_eq!(rebuilt.first_unacked_page_num, 0);
        assert_eq!(rebuilt.first_unacked_seq_num, 1);
        assert_eq!(rebuilt.min_seq_num, 1);
        assert_eq!(rebuilt.element_count, 1);
        assert!(!dir.join("checkpoint.1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_checksum_is_rejected() {
        let mut page = write_page(64, &[(1, b"hello")]).unwrap();
        page[PAGE_PREFIX.len() - 1] ^= 0xff;
        let error = read_page(&page, 1, 1).unwrap_err();
        assert!(error.to_string().contains("Element invalid checksum"));
    }
}
