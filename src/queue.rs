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

fn persisted_byte_count(length: usize) -> usize {
    12 + length + 4
}

/// Java `java.util.zip.CRC32`.
fn crc32(data: &[u8]) -> u32 {
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
    fn a_bad_checksum_is_rejected() {
        let mut page = write_page(64, &[(1, b"hello")]).unwrap();
        page[PAGE_PREFIX.len() - 1] ^= 0xff;
        let error = read_page(&page, 1, 1).unwrap_err();
        assert!(error.to_string().contains("Element invalid checksum"));
    }
}
