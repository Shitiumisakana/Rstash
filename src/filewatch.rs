//! `logstash-input-file` 4.4.7 sincedb, the text format in the plugin, not core.
//!
//! A v2 line is `inode major minor position changed_at path`. A v1 line stops
//! after the position. On Windows the inode is `volumeSerial-fileIndexLow-fileIndexHigh`
//! and the device numbers are 0, matching `Winhelper.identifier_from_path`.
//! This pass reads each discovered file once and writes the checkpoint.
//! Tail mode does not stay running: there is no shutdown signal yet.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::digest::md5_hex;
use crate::run::{RunError, fail};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SinceRecord {
    pub inode: String,
    pub major: i64,
    pub minor: i64,
    pub position: u64,
    pub changed_at: f64,
    pub path: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct FileChunk {
    pub path: String,
    pub text: String,
}

pub(crate) struct ReadOptions<'a> {
    pub paths: &'a [String],
    pub mode: &'a str,
    pub start_position: &'a str,
    pub sincedb_path: Option<&'a str>,
    pub delimiter: &'a str,
    pub path_data: Option<&'a str>,
    pub delete_when_done: bool,
}

pub(crate) struct ReadOutcome {
    pub chunks: Vec<FileChunk>,
    pub completed: Vec<String>,
}

pub(crate) fn read_files(options: &ReadOptions<'_>) -> Result<ReadOutcome, RunError> {
    let paths = options.paths;
    let plugin_mode = options.mode;
    let plugin_start = options.start_position;
    let sincedb_path = options.sincedb_path;
    let delimiter = options.delimiter;
    let path_data = options.path_data;
    let delete_when_done = options.delete_when_done;
    for path in paths {
        if !path_is_absolute(path) {
            return Err(fail(format!(
                "File paths must be absolute, relative path specified: {path}"
            )));
        }
    }
    let mut files = Vec::new();
    for path in paths {
        files.extend(expand_path(path)?);
    }
    files.sort_by(|left, right| {
        let left_time = fs::metadata(left).and_then(|meta| meta.modified()).ok();
        let right_time = fs::metadata(right).and_then(|meta| meta.modified()).ok();
        left_time.cmp(&right_time).then_with(|| left.cmp(right))
    });
    let db_path = sincedb_file(paths, sincedb_path, path_data)?;
    if let Some(path) = &db_path
        && path.is_dir()
    {
        return Err(fail(format!(
            "The \"sincedb_path\" argument must point to a file, received a directory: \"{}\"",
            path.display()
        )));
    }
    let mut records = db_path
        .as_ref()
        .map(|path| load_sincedb(path))
        .transpose()?
        .unwrap_or_default();
    let read_mode = plugin_mode == "read";
    let mut chunks = Vec::new();
    let mut completed = Vec::new();
    let mut finished = Vec::new();
    for file in files {
        let path_text = file.to_string_lossy().to_string();
        let key = file_key(&file)?;
        let bytes = fs::read(&file).map_err(|error| fail(error.to_string()))?;
        let previous = records.iter().find(|record| {
            record.inode == key.0
                && record.major == key.1
                && record.minor == key.2
                && record
                    .path
                    .as_deref()
                    .is_none_or(|stored| paths_equal(stored, &path_text))
        });
        let start = match previous {
            Some(record) => record.position.min(bytes.len() as u64) as usize,
            None if read_mode || plugin_start == "beginning" => 0,
            None => bytes.len(),
        };
        let (text, position) = take_bytes(&bytes, start, delimiter, read_mode);
        let stored_path = previous
            .and_then(|record| record.path.clone())
            .unwrap_or_else(|| path_text.clone());
        records.retain(|record| {
            !(record.inode == key.0 && record.major == key.1 && record.minor == key.2)
        });
        records.push(SinceRecord {
            inode: key.0,
            major: key.1,
            minor: key.2,
            position: position as u64,
            changed_at: now_secs(),
            path: Some(stored_path),
        });
        if !text.is_empty() {
            chunks.push(FileChunk {
                path: path_text.clone(),
                text,
            });
        }
        if read_mode {
            finished.push(path_text);
            if delete_when_done {
                completed.push(file);
            }
        }
    }
    if let Some(path) = &db_path {
        write_sincedb(path, &records)?;
    }
    for path in completed {
        let _ = fs::remove_file(path);
    }
    Ok(ReadOutcome {
        chunks,
        completed: finished,
    })
}

pub(crate) fn parse_sincedb(text: &str) -> Vec<SinceRecord> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<SinceRecord> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let inode = parts[0].to_string();
    let major = parts[1].parse().ok()?;
    let minor = parts[2].parse().ok()?;
    let position = parts[3].parse::<i64>().ok()?.max(0) as u64;
    if parts.len() == 4 {
        return Some(SinceRecord {
            inode,
            major,
            minor,
            position,
            changed_at: now_secs(),
            path: None,
        });
    }
    let changed_at = parts[4].parse().ok()?;
    let path = if parts.len() > 5 {
        Some(parts[5..].join(" "))
    } else {
        None
    };
    Some(SinceRecord {
        inode,
        major,
        minor,
        position,
        changed_at,
        path,
    })
}

fn format_record(record: &SinceRecord) -> String {
    let mut line = format!(
        "{} {} {} {} {}",
        record.inode, record.major, record.minor, record.position, record.changed_at
    );
    if let Some(path) = &record.path {
        line.push(' ');
        line.push_str(path);
    }
    line.push('\n');
    line
}

fn load_sincedb(path: &Path) -> Result<Vec<SinceRecord>, RunError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(parse_sincedb(&text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(fail(error.to_string())),
    }
}

fn write_sincedb(path: &Path, records: &[SinceRecord]) -> Result<(), RunError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| fail(error.to_string()))?;
    }
    let mut text = String::new();
    let now = now_secs();
    let keep_for = 14.0 * 24.0 * 3600.0;
    for record in records {
        if now > record.changed_at + keep_for {
            continue;
        }
        text.push_str(&format_record(record));
    }
    fs::write(path, text).map_err(|error| fail(error.to_string()))
}

fn sincedb_file(
    paths: &[String],
    explicit: Option<&str>,
    path_data: Option<&str>,
) -> Result<Option<PathBuf>, RunError> {
    if let Some(path) = explicit {
        return Ok(Some(PathBuf::from(path)));
    }
    let base = path_data
        .map(PathBuf::from)
        .map(|path| path.join("plugins").join("inputs").join("file"))
        .or_else(|| std::env::var_os("SINCEDB_DIR").map(PathBuf::from))
        .or_else(|| std::env::var_os("LOGSTASH_HOME").map(PathBuf::from));
    let Some(base) = base else {
        return Ok(None);
    };
    let name = format!(".sincedb_{}", md5_hex(paths.join(",").as_bytes()));
    Ok(Some(base.join(name)))
}

fn take_bytes(
    bytes: &[u8],
    start: usize,
    delimiter: &str,
    flush_remainder: bool,
) -> (String, usize) {
    let start = start.min(bytes.len());
    let slice = &bytes[start..];
    let marker = delimiter.as_bytes();
    if marker.is_empty() {
        return (String::from_utf8_lossy(slice).into_owned(), bytes.len());
    }
    let mut consumed = start;
    let mut pieces = Vec::new();
    let mut cursor = 0;
    while let Some(found) = find_subslice(&slice[cursor..], marker) {
        let end = cursor + found;
        pieces.push(String::from_utf8_lossy(&slice[cursor..end]).into_owned());
        cursor = end + marker.len();
        consumed = start + cursor;
    }
    if flush_remainder && cursor < slice.len() {
        pieces.push(String::from_utf8_lossy(&slice[cursor..]).into_owned());
        consumed = bytes.len();
    }
    let mut out = pieces.join(delimiter);
    if !flush_remainder && !pieces.is_empty() {
        out.push_str(delimiter);
    }
    (out, consumed)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn expand_path(pattern: &str) -> Result<Vec<PathBuf>, RunError> {
    if !pattern.chars().any(|ch| matches!(ch, '*' | '?')) {
        let path = PathBuf::from(pattern);
        if path.is_file() {
            return Ok(vec![path]);
        }
        return Ok(Vec::new());
    }
    let parts: Vec<String> = pattern
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    let mut prefix = PathBuf::new();
    let mut index = 0;
    if let Some(first) = parts.first()
        && first.ends_with(':')
    {
        prefix.push(format!("{first}\\"));
        index = 1;
    } else if pattern.starts_with('/') || pattern.starts_with('\\') {
        prefix.push(std::path::MAIN_SEPARATOR_STR);
    }
    let mut found = Vec::new();
    walk(&prefix, &parts[index..], &mut found)?;
    Ok(found)
}

fn walk(dir: &Path, parts: &[String], found: &mut Vec<PathBuf>) -> Result<(), RunError> {
    if parts.is_empty() {
        if dir.is_file() {
            found.push(dir.to_path_buf());
        }
        return Ok(());
    }
    if parts[0] == "**" {
        walk(dir, &parts[1..], found)?;
        if dir.is_dir() {
            for entry in fs::read_dir(dir).map_err(|error| fail(error.to_string()))? {
                let entry = entry.map_err(|error| fail(error.to_string()))?;
                if entry.path().is_dir() {
                    let mut rest = vec!["**".to_string()];
                    rest.extend(parts[1..].iter().cloned());
                    walk(&entry.path(), &rest, found)?;
                }
            }
        }
        return Ok(());
    }
    if !dir.is_dir() && !dir.as_os_str().is_empty() {
        return Ok(());
    }
    let listing = if dir.as_os_str().is_empty() {
        return Ok(());
    } else {
        fs::read_dir(dir).map_err(|error| fail(error.to_string()))?
    };
    for entry in listing {
        let entry = entry.map_err(|error| fail(error.to_string()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if glob_piece(&parts[0], &name) {
            walk(&entry.path(), &parts[1..], found)?;
        }
    }
    Ok(())
}

fn glob_piece(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    fn rec(pattern: &[char], name: &[char]) -> bool {
        if pattern.is_empty() {
            return name.is_empty();
        }
        if pattern[0] == '*' {
            rec(&pattern[1..], name) || (!name.is_empty() && rec(pattern, &name[1..]))
        } else if !name.is_empty() && (pattern[0] == '?' || pattern[0] == name[0]) {
            rec(&pattern[1..], &name[1..])
        } else {
            false
        }
    }
    rec(&pattern, &name)
}

fn paths_equal(left: &str, right: &str) -> bool {
    #[cfg(windows)]
    {
        left.replace('/', "\\")
            .eq_ignore_ascii_case(&right.replace('/', "\\"))
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn path_is_absolute(path: &str) -> bool {
    Path::new(path).is_absolute()
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn file_key(path: &Path) -> Result<(String, i64, i64), RunError> {
    #[cfg(windows)]
    {
        windows_file_key(path)
    }
    #[cfg(not(windows))]
    {
        unix_file_key(path)
    }
}

#[cfg(windows)]
fn windows_file_key(path: &Path) -> Result<(String, i64, i64), RunError> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            0,
            7,
            std::ptr::null(),
            3,
            0x80,
            std::ptr::null_mut(),
        );
        if handle.is_null() || handle == INVALID_HANDLE {
            return Err(fail(format!("file identity failed for {}", path.display())));
        }
        let mut info = ByHandleFileInformation::default();
        let ok = GetFileInformationByHandle(handle, &mut info);
        CloseHandle(handle);
        if ok == 0 {
            return Err(fail(format!("file identity failed for {}", path.display())));
        }
        Ok((
            format!(
                "{}-{}-{}",
                info.volume_serial, info.file_index_low, info.file_index_high
            ),
            0,
            0,
        ))
    }
}

#[cfg(not(windows))]
fn unix_file_key(path: &Path) -> Result<(String, i64, i64), RunError> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).map_err(|error| fail(error.to_string()))?;
    let dev = meta.dev();
    let major = (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as i64;
    let minor = ((dev & 0xff) | ((dev >> 12) & !0xff)) as i64;
    Ok((meta.ino().to_string(), major, minor))
}

#[cfg(windows)]
const INVALID_HANDLE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
    _attributes: u32,
    _creation_low: u32,
    _creation_high: u32,
    _access_low: u32,
    _access_high: u32,
    _write_low: u32,
    _write_high: u32,
    volume_serial: u32,
    _size_high: u32,
    _size_low: u32,
    _links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[cfg(windows)]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const std::ffi::c_void,
        disposition: u32,
        flags: u32,
        template: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn GetFileInformationByHandle(
        handle: *mut std::ffi::c_void,
        info: *mut ByHandleFileInformation,
    ) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}

#[cfg(test)]
mod tests {
    use super::parse_sincedb;

    #[test]
    fn sincedb_v2_and_v1_lines() {
        let records = parse_sincedb(
            "2977152 1 4 94 1519319662.852678 /var/log/app.log\n2977152 1 4 10\n123-4-5 0 0 8 1000.5 C:\\logs\\app.log\n",
        );
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].inode, "2977152");
        assert_eq!(records[0].major, 1);
        assert_eq!(records[0].minor, 4);
        assert_eq!(records[0].position, 94);
        assert!((records[0].changed_at - 1519319662.852678).abs() < 0.000_001);
        assert_eq!(records[0].path.as_deref(), Some("/var/log/app.log"));
        assert_eq!(records[1].position, 10);
        assert_eq!(records[1].path, None);
        assert_eq!(records[2].inode, "123-4-5");
        assert_eq!(records[2].position, 8);
        assert_eq!(records[2].path.as_deref(), Some("C:\\logs\\app.log"));
    }
}
