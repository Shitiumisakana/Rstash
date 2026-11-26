//! Plugins from the 9.5.2 distribution, wired by the names a `.conf` file uses.
//!
//! Java plugins whose config name is `java_*` or `jdots` are a different plugin.
//! Long-running inputs (`heartbeat` with `count => -1`, `exec` on an interval,
//! file tail, a TCP server) finish one finite pass here: `run` returns when
//! every input closes, and there is no shutdown signal yet.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, TimeZone, Utc};

use crate::digest::{hmac_sha1_hex, hmac_sha256_hex, sha1_hex, sha256_hex};
use crate::event::Event;
use crate::lscl::{Arg, Key, Kind, Plugin};
use crate::run::{Ecs, RunError, Settings, fail};
use crate::value::{Map, Value};

pub(crate) fn known(kind: Kind, name: &str) -> bool {
    matches!(
        (kind, name),
        (Kind::Input, "stdin" | "heartbeat" | "exec" | "file")
            | (
                Kind::Filter,
                "uuid"
                    | "json"
                    | "clone"
                    | "split"
                    | "prune"
                    | "urldecode"
                    | "truncate"
                    | "syslog_pri"
                    | "de_dot"
                    | "anonymize"
                    | "csv"
                    | "date"
                    | "dissect"
                    | "kv"
                    | "fingerprint"
                    | "sleep"
            )
            | (Kind::Output, "null" | "sink" | "file")
            | (
                Kind::Codec,
                "dots" | "json" | "json_lines" | "rubydebug" | "multiline"
            )
    )
}

pub(crate) fn produce(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    match plugin.name.as_str() {
        "stdin" => stdin_input(plugin, settings),
        "heartbeat" => heartbeat_input(plugin, settings),
        "exec" => exec_input(plugin, settings),
        "file" => file_input(plugin, settings),
        other => Err(fail(format!("plugin input {other} is not implemented"))),
    }
}

pub(crate) fn filter(
    plugin: &Plugin,
    event: Event,
    settings: &Settings,
) -> Result<Vec<Event>, RunError> {
    match plugin.name.as_str() {
        "uuid" => uuid_filter(plugin, event),
        "json" => json_filter(plugin, event),
        "clone" => clone_filter(plugin, event, settings),
        "split" => split_filter(plugin, event),
        "prune" => prune_filter(plugin, event),
        "urldecode" => urldecode_filter(plugin, event),
        "truncate" => truncate_filter(plugin, event),
        "syslog_pri" => syslog_pri_filter(plugin, event, settings),
        "de_dot" => de_dot_filter(plugin, event),
        "anonymize" => anonymize_filter(plugin, event),
        "csv" => csv_filter(plugin, event),
        "date" => date_filter(plugin, event),
        "dissect" => dissect_filter(plugin, event),
        "kv" => kv_filter(plugin, event),
        "fingerprint" => fingerprint_filter(plugin, event),
        "sleep" => sleep_filter(plugin, event),
        other => Err(fail(format!("plugin filter {other} is not implemented"))),
    }
}

pub(crate) fn encode(
    name: &str,
    delimiter: &str,
    metadata: bool,
    event: &Event,
) -> Result<String, RunError> {
    match name {
        "dots" => Ok(".".to_string()),
        "json" => event.to_json().map_err(|error| fail(error.to_string())),
        "json_lines" => event
            .to_json()
            .map(|text| text + delimiter)
            .map_err(|error| fail(error.to_string())),
        "rubydebug" => Ok(rubydebug(event, metadata)),
        "multiline" => Err(fail("codec multiline cannot encode")),
        other => Err(fail(format!("plugin codec {other} is not implemented"))),
    }
}

pub(crate) fn decode_events(name: &str, data: &str) -> Result<Vec<Event>, RunError> {
    match name {
        "json" => decode_json(data),
        "json_lines" => {
            let mut events = Vec::new();
            for line in data.split('\n') {
                if !line.is_empty() {
                    events.extend(decode_json(line)?);
                }
            }
            Ok(events)
        }
        "dots" => Err(fail("codec dots cannot decode")),
        "rubydebug" => Err(fail("codec rubydebug cannot decode")),
        other => Err(fail(format!("plugin codec {other} is not implemented"))),
    }
}

pub(crate) fn write_file(plugin: &Plugin, bytes: &str) -> Result<(), RunError> {
    let path = arg_string(plugin, "path").ok_or_else(|| fail("file output requires path"))?;
    let path = path.as_str();
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| fail(error.to_string()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| fail(error.to_string()))?;
    file.write_all(bytes.as_bytes())
        .map_err(|error| fail(error.to_string()))?;
    Ok(())
}

fn stdin_input(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    let text = if let Some(text) = &settings.stdin {
        text.clone()
    } else {
        std::io::read_to_string(std::io::stdin()).map_err(|error| fail(error.to_string()))?
    };
    if matches!(codec_name(plugin).as_str(), "json" | "json_lines") {
        return decode_events(&codec_name(plugin), &text);
    }
    if let Some(codec) = codec_plugin(plugin)
        && codec.name == "multiline"
    {
        let events = crate::grok::multiline_decode(codec, &text, settings.ecs, false)?;
        return decorate_stdin(events, settings);
    }
    let host = crate::run::hostname();
    let ecs = settings.ecs != Ecs::Disabled;
    let host_field = if ecs { "[host][hostname]" } else { "host" };
    let mut events = Vec::new();
    for line in text.split_inclusive('\n') {
        let message = line.trim_end_matches(['\n', '\r']);
        if message.is_empty() && line.ends_with('\n') {
            continue;
        }
        if message.is_empty() && !line.is_empty() {
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let mut event = Event::new();
        event
            .set_field("message", Value::from(message))
            .map_err(err)?;
        if ecs {
            event
                .set_field(
                    "[event][original]",
                    Value::from(line.trim_end_matches(['\n', '\r'])),
                )
                .map_err(err)?;
        }
        if !event.includes(host_field).map_err(err)? {
            event
                .set_field(host_field, Value::from(host.as_str()))
                .map_err(err)?;
        }
        let _ = plugin;
        events.push(event);
    }
    Ok(events)
}

fn heartbeat_input(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    let count = arg_i64(plugin, "count").unwrap_or(-1);
    if count < 0 {
        return Err(fail(
            "heartbeat count -1 runs until shutdown; set count to a positive number so the pipeline can finish",
        ));
    }
    let interval = arg_i64(plugin, "interval").unwrap_or(60).max(0) as u64;
    let message = arg_string(plugin, "message").unwrap_or_else(|| "ok".to_string());
    let sequence = arg_string(plugin, "sequence");
    let legacy = sequence.is_none() && (message == "epoch" || message == "sequence");
    let mode = sequence.clone().unwrap_or_else(|| {
        if legacy {
            message.clone()
        } else {
            "none".to_string()
        }
    });
    let host = crate::run::hostname();
    let ecs = settings.ecs != Ecs::Disabled;
    let host_field = if ecs { "[host][name]" } else { "host" };
    let clock_field = if ecs { "[event][sequence]" } else { "clock" };
    let mut events = Vec::new();
    for index in 1..=count {
        let mut event = Event::new();
        event
            .set_field(host_field, Value::from(host.as_str()))
            .map_err(err)?;
        match mode.as_str() {
            "epoch" => {
                let seconds = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0);
                event
                    .set_field(clock_field, Value::Integer(i128::from(seconds)))
                    .map_err(err)?;
                if !legacy {
                    event
                        .set_field("message", Value::from(message.as_str()))
                        .map_err(err)?;
                }
            }
            "sequence" => {
                event
                    .set_field(clock_field, Value::Integer(i128::from(index)))
                    .map_err(err)?;
                if !legacy {
                    event
                        .set_field("message", Value::from(message.as_str()))
                        .map_err(err)?;
                }
            }
            _ => {
                event
                    .set_field("message", Value::from(message.as_str()))
                    .map_err(err)?;
            }
        }
        events.push(event);
        if index != count && interval > 0 {
            thread::sleep(Duration::from_secs(interval));
        }
    }
    Ok(events)
}

fn exec_input(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    let command =
        arg_string(plugin, "command").ok_or_else(|| fail("exec input requires command"))?;
    if arg(plugin, "interval").is_none() && arg(plugin, "schedule").is_none() {
        return Err(fail(
            "exec input: either 'interval' or 'schedule' option must be defined.",
        ));
    }
    if arg(plugin, "schedule").is_some() {
        return Err(fail(
            "exec input schedule stays running; interval runs the command once and the pipeline finishes",
        ));
    }
    let started = std::time::Instant::now();
    let output = run_shell(&command)?;
    let elapsed = started.elapsed().as_secs_f64();
    let host = crate::run::hostname();
    let ecs = settings.ecs != Ecs::Disabled;
    let mut event = Event::new();
    event
        .set_field(
            "message",
            Value::from(output.stdout.trim_end_matches(['\n', '\r'])),
        )
        .map_err(err)?;
    if ecs {
        event
            .set_field("[host][name]", Value::from(host))
            .map_err(err)?;
        event
            .set_field("[process][command_line]", Value::from(command))
            .map_err(err)?;
        event
            .set_field(
                "[process][exit_code]",
                Value::Integer(i128::from(output.code)),
            )
            .map_err(err)?;
    } else {
        event.set_field("host", Value::from(host)).map_err(err)?;
        event
            .set_field("command", Value::from(command))
            .map_err(err)?;
        event
            .set_field(
                "[@metadata][exit_status]",
                Value::Integer(i128::from(output.code)),
            )
            .map_err(err)?;
        event
            .set_field("[@metadata][duration]", Value::Float(elapsed))
            .map_err(err)?;
    }
    Ok(vec![event])
}

struct ShellOutput {
    stdout: String,
    code: i32,
}

fn run_shell(command: &str) -> Result<ShellOutput, RunError> {
    let process = if cfg!(windows) {
        Command::new("cmd").args(["/C", command]).output()
    } else {
        Command::new("sh").args(["-c", command]).output()
    }
    .map_err(|error| fail(error.to_string()))?;
    let code = process.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&process.stdout).to_string();
    let _ = process.stderr;
    Ok(ShellOutput { stdout, code })
}

fn file_input(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    let path = arg_string(plugin, "path").ok_or_else(|| fail("file input requires path"))?;
    let bytes = fs::read(&path).map_err(|error| fail(error.to_string()))?;
    let text = String::from_utf8_lossy(&bytes);
    let start = arg_string(plugin, "start_position").unwrap_or_else(|| "end".to_string());
    let body = if start == "beginning" || arg_string(plugin, "mode").as_deref() == Some("read") {
        text.as_ref()
    } else if let Some(sincedb) = arg_string(plugin, "sincedb_path") {
        let offset = fs::read_to_string(&sincedb)
            .ok()
            .and_then(|text| text.trim().parse::<usize>().ok())
            .unwrap_or(0);
        text.get(offset..).unwrap_or("")
    } else {
        ""
    };
    if let Some(sincedb) = arg_string(plugin, "sincedb_path") {
        fs::write(&sincedb, bytes.len().to_string()).map_err(|error| fail(error.to_string()))?;
    }
    if let Some(codec) = codec_plugin(plugin)
        && codec.name == "multiline"
    {
        let mut events = crate::grok::multiline_decode(codec, body, settings.ecs, true)?;
        for event in &mut events {
            event
                .set_field("path", Value::from(path.as_str()))
                .map_err(err)?;
            if settings.ecs != Ecs::Disabled {
                event
                    .set_field("[log][file][path]", Value::from(path.as_str()))
                    .map_err(err)?;
            }
        }
        return Ok(events);
    }
    let mut events = Vec::new();
    for line in body.split_inclusive('\n') {
        let message = line.trim_end_matches(['\n', '\r']);
        if message.is_empty() {
            continue;
        }
        let mut event = Event::new();
        event
            .set_field("message", Value::from(message))
            .map_err(err)?;
        event
            .set_field("path", Value::from(path.as_str()))
            .map_err(err)?;
        if settings.ecs != Ecs::Disabled {
            event
                .set_field("[log][file][path]", Value::from(path.as_str()))
                .map_err(err)?;
        }
        events.push(event);
    }
    Ok(events)
}

fn uuid_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let target = arg_string(plugin, "target").ok_or_else(|| fail("uuid filter requires target"))?;
    let overwrite = arg_bool(plugin, "overwrite");
    let missing = event.get_field(&target).map_err(err)?.is_none();
    if overwrite || missing {
        event
            .set_field(&target, Value::from(uuid_v4()))
            .map_err(err)?;
    }
    Ok(vec![event])
}

fn json_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let source = arg_string(plugin, "source").ok_or_else(|| fail("json filter requires source"))?;
    let Some(value) = event.get_field(&source).map_err(err)? else {
        return Ok(vec![event]);
    };
    if matches!(value, Value::Null) {
        return Ok(vec![event]);
    }
    let text = value.to_string();
    let parsed = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(parsed) => parsed,
        Err(_) => {
            tag_failure(&mut event, plugin, "_jsonparsefailure");
            return Ok(vec![event]);
        }
    };
    if let Some(target) = arg_string(plugin, "target") {
        event
            .set_field(&target, json_to_value(&parsed))
            .map_err(err)?;
    } else {
        let serde_json::Value::Object(mut fields) = parsed else {
            tag_failure(&mut event, plugin, "_jsonparsefailure");
            return Ok(vec![event]);
        };
        let timestamp = fields.remove("@timestamp");
        for (key, value) in fields {
            event.set_field(&key, json_to_value(&value)).map_err(err)?;
        }
        if let Some(timestamp) = timestamp {
            match coerce_timestamp(&json_to_value(&timestamp)) {
                Some(parsed) => {
                    event
                        .set_field("@timestamp", Value::Timestamp(parsed))
                        .map_err(err)?;
                }
                None => {
                    event.tag("_timestampparsefailure");
                    event
                        .set_field("_@timestamp", json_to_value(&timestamp))
                        .map_err(err)?;
                }
            }
        }
    }
    Ok(vec![event])
}

fn clone_filter(
    plugin: &Plugin,
    event: Event,
    settings: &Settings,
) -> Result<Vec<Event>, RunError> {
    let clones = string_list(plugin, "clones")?;
    let mut events = vec![event.clone()];
    let ecs = settings.ecs != Ecs::Disabled;
    for kind in clones {
        let mut clone = event.clone();
        if ecs {
            clone.tag(&kind);
        } else {
            clone.set_field("type", Value::from(kind)).map_err(err)?;
        }
        events.push(clone);
    }
    Ok(events)
}

fn split_filter(plugin: &Plugin, event: Event) -> Result<Vec<Event>, RunError> {
    let field = arg_string(plugin, "field").unwrap_or_else(|| "message".to_string());
    let target = arg_string(plugin, "target").unwrap_or_else(|| field.clone());
    let terminator = arg_string(plugin, "terminator").unwrap_or_else(|| "\n".to_string());
    let Some(value) = event.get_field(&field).map_err(err)? else {
        let mut event = event;
        event.tag("_split_type_failure");
        return Ok(vec![event]);
    };
    let pieces: Vec<Value> = match value {
        Value::Array(items) => items,
        Value::String(text) => {
            let parts: Vec<Value> = text
                .split(&terminator)
                .map(Value::from)
                .filter(|item| item.to_string() != "")
                .collect();
            if parts.len() <= 1 && !text.contains(&terminator) {
                return Ok(vec![event]);
            }
            parts
        }
        _ => {
            let mut event = event;
            event.tag("_split_type_failure");
            return Ok(vec![event]);
        }
    };
    let mut events = Vec::new();
    for piece in pieces {
        if matches!(piece, Value::Null) || piece.to_string().is_empty() {
            continue;
        }
        let mut clone = event.clone();
        clone.set_field(&target, piece).map_err(err)?;
        events.push(clone);
    }
    Ok(events)
}

fn prune_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let whitelist = string_list(plugin, "whitelist_names").unwrap_or_default();
    let blacklist = if arg(plugin, "blacklist_names").is_some() {
        string_list(plugin, "blacklist_names")?
    } else {
        vec!["%\\{[^}]+\\}".to_string()]
    };
    let keys: Vec<String> = event
        .to_map()
        .iter()
        .map(|(key, _)| key.to_string())
        .collect();
    for key in keys {
        let listed =
            whitelist.is_empty() || whitelist.iter().any(|pattern| name_match(pattern, &key));
        let blocked = blacklist.iter().any(|pattern| name_match(pattern, &key));
        if !listed || blocked {
            event.remove_field(&key).map_err(err)?;
        }
    }
    Ok(vec![event])
}

fn name_match(pattern: &str, key: &str) -> bool {
    if let Some(exact) = pattern
        .strip_prefix('^')
        .and_then(|rest| rest.strip_suffix('$'))
    {
        return key == exact;
    }
    if pattern.contains('\\') || pattern.contains('(') || pattern.contains('[') {
        return key.contains(pattern.trim_matches(|ch| ch == '^' || ch == '$'));
    }
    key.contains(pattern)
}

fn urldecode_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let field = arg_string(plugin, "field").unwrap_or_else(|| "message".to_string());
    if arg_bool(plugin, "all_fields") {
        let keys: Vec<(String, Value)> = event
            .to_map()
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect();
        for (key, value) in keys {
            event.set_field(&key, urldecode_value(value)).map_err(err)?;
        }
    } else if let Some(value) = event.get_field(&field).map_err(err)? {
        event
            .set_field(&field, urldecode_value(value))
            .map_err(err)?;
    }
    Ok(vec![event])
}

fn urldecode_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::from(percent_decode(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(urldecode_value).collect()),
        Value::Map(map) => {
            let mut decoded = Map::new();
            for (key, value) in map.iter() {
                decoded.insert(key, urldecode_value(value.clone()));
            }
            Value::Map(decoded)
        }
        other => other,
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""),
                16,
            )
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn truncate_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let length = arg_i64(plugin, "length_bytes")
        .ok_or_else(|| fail("truncate filter requires length_bytes"))? as usize;
    let fields = string_list(plugin, "fields").unwrap_or_else(|_| {
        event
            .to_map()
            .iter()
            .map(|(key, _)| format!("[{key}]"))
            .collect()
    });
    for field in fields {
        if let Some(value) = event.get_field(&field).map_err(err)? {
            event
                .set_field(&field, truncate_value(value, length))
                .map_err(err)?;
        }
    }
    Ok(vec![event])
}

fn truncate_value(value: Value, length: usize) -> Value {
    match value {
        Value::String(text) => Value::from(trim_utf8(&text, length)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| truncate_value(item, length))
                .collect(),
        ),
        other => other,
    }
}

fn trim_utf8(text: &str, length: usize) -> String {
    if text.len() <= length {
        return text.to_string();
    }
    let mut end = length.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn syslog_pri_filter(
    plugin: &Plugin,
    mut event: Event,
    settings: &Settings,
) -> Result<Vec<Event>, RunError> {
    let ecs = settings.ecs != Ecs::Disabled;
    let source = arg_string(plugin, "syslog_pri_field_name").unwrap_or_else(|| {
        if ecs {
            "[log][syslog][priority]".to_string()
        } else {
            "syslog_pri".to_string()
        }
    });
    let priority = match event.get_field(&source).map_err(err)? {
        Some(Value::Array(items)) => items
            .first()
            .map(Value::to_string)
            .unwrap_or_default()
            .parse()
            .unwrap_or(13),
        Some(value) => value.to_string().parse().unwrap_or(13),
        None => 13,
    };
    let severity = priority & 7;
    let facility = priority >> 3;
    let (severity_code, facility_code, severity_name, facility_name) = if ecs {
        (
            "[log][syslog][severity][code]",
            "[log][syslog][facility][code]",
            "[log][syslog][severity][name]",
            "[log][syslog][facility][name]",
        )
    } else {
        (
            "syslog_severity_code",
            "syslog_facility_code",
            "syslog_severity",
            "syslog_facility",
        )
    };
    event
        .set_field(severity_code, Value::Integer(i128::from(severity)))
        .map_err(err)?;
    event
        .set_field(facility_code, Value::Integer(i128::from(facility)))
        .map_err(err)?;
    const FACILITIES: [&str; 24] = [
        "kernel",
        "user-level",
        "mail",
        "daemon",
        "security/authorization",
        "syslogd",
        "line printer",
        "network news",
        "uucp",
        "clock",
        "security/authorization",
        "ftp",
        "ntp",
        "log audit",
        "log alert",
        "clock",
        "local0",
        "local1",
        "local2",
        "local3",
        "local4",
        "local5",
        "local6",
        "local7",
    ];
    const SEVERITIES: [&str; 8] = [
        "emergency",
        "alert",
        "critical",
        "error",
        "warning",
        "notice",
        "informational",
        "debug",
    ];
    if arg_bool_default(plugin, "use_labels", true) {
        if facility >= FACILITIES.len() as i32 {
            event.tag("_syslogpriparsefailure");
        } else {
            event
                .set_field(facility_name, Value::from(FACILITIES[facility as usize]))
                .map_err(err)?;
            event
                .set_field(severity_name, Value::from(SEVERITIES[severity as usize]))
                .map_err(err)?;
        }
    }
    Ok(vec![event])
}

fn de_dot_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let separator = arg_string(plugin, "separator").unwrap_or_else(|| "_".to_string());
    if separator.contains('.') {
        return Err(fail("de_dot: separator cannot be or contain '.'"));
    }
    let keys: Vec<String> = event
        .to_map()
        .iter()
        .map(|(key, _)| key.to_string())
        .collect();
    for key in keys {
        if key.contains('.') {
            let value = event.remove_field(&key).map_err(err)?;
            if let Some(value) = value {
                event
                    .set_field(&key.replace('.', &separator), value)
                    .map_err(err)?;
            }
        }
    }
    Ok(vec![event])
}

fn anonymize_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let key = arg_string(plugin, "key").ok_or_else(|| fail("anonymize filter requires key"))?;
    let fields = string_list(plugin, "fields")?;
    let algorithm = arg_string(plugin, "algorithm").unwrap_or_else(|| "SHA1".to_string());
    for field in fields {
        let Some(value) = event.get_field(&field).map_err(err)? else {
            continue;
        };
        let next = match value {
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(|item| Value::from(anonymize(&algorithm, &key, &item.to_string())))
                    .collect(),
            ),
            other => Value::from(anonymize(&algorithm, &key, &other.to_string())),
        };
        event.set_field(&field, next).map_err(err)?;
    }
    Ok(vec![event])
}

fn anonymize(algorithm: &str, key: &str, data: &str) -> String {
    match algorithm {
        "SHA256" => hmac_sha256_hex(key, data),
        _ => hmac_sha1_hex(key, data),
    }
}

fn csv_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let source = arg_string(plugin, "source").unwrap_or_else(|| "message".to_string());
    let Some(Value::String(text)) = event.get_field(&source).map_err(err)? else {
        return Ok(vec![event]);
    };
    let separator = arg_string(plugin, "separator").unwrap_or_else(|| ",".to_string());
    let columns = string_list(plugin, "columns").unwrap_or_default();
    let values = split_csv(&text, separator.chars().next().unwrap_or(','));
    let target = arg_string(plugin, "target");
    for (index, value) in values.into_iter().enumerate() {
        if value.is_empty() && arg_bool(plugin, "skip_empty_columns") {
            continue;
        }
        let name = columns
            .get(index)
            .cloned()
            .unwrap_or_else(|| format!("column{}", index + 1));
        let converted = convert_csv(plugin, &name, value);
        let field = if let Some(target) = &target {
            format!("{target}[{name}]")
        } else {
            name
        };
        event.set_field(&field, converted).map_err(err)?;
    }
    Ok(vec![event])
}

fn convert_csv(plugin: &Plugin, name: &str, value: String) -> Value {
    let kind = match arg(plugin, "convert") {
        Some(Arg::Map(entries)) => entries.iter().find_map(|(key, value)| {
            if key_text(key) == name {
                arg_text(value).ok()
            } else {
                None
            }
        }),
        _ => None,
    };
    match kind.as_deref() {
        Some("integer") => value
            .parse::<i128>()
            .map(Value::Integer)
            .unwrap_or(Value::from(value)),
        Some("float") => value
            .parse::<f64>()
            .map(Value::Float)
            .unwrap_or(Value::from(value)),
        Some("boolean") => match value.trim().to_ascii_lowercase().as_str() {
            "true" => Value::Boolean(true),
            "false" => Value::Boolean(false),
            _ => Value::from(value),
        },
        _ => Value::from(value),
    }
}

fn split_csv(text: &str, separator: char) -> Vec<String> {
    let mut rows = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in text.chars() {
        if ch == '"' {
            quoted = !quoted;
        } else if ch == separator && !quoted {
            rows.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    rows.push(current);
    rows
}

fn date_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let matchers = string_list(plugin, "match")?;
    if matchers.len() < 2 {
        return Err(fail(
            "date filter match must contain a field name and at least one format",
        ));
    }
    let source = &matchers[0];
    let target = arg_string(plugin, "target").unwrap_or_else(|| "@timestamp".to_string());
    let Some(value) = event.get_field(source).map_err(err)? else {
        tag_list(&mut event, plugin, "_dateparsefailure");
        return Ok(vec![event]);
    };
    let text = value.to_string();
    for format in &matchers[1..] {
        if let Some(timestamp) = parse_date(format, &text) {
            event
                .set_field(&target, Value::Timestamp(timestamp))
                .map_err(err)?;
            return Ok(vec![event]);
        }
    }
    tag_list(&mut event, plugin, "_dateparsefailure");
    Ok(vec![event])
}

fn parse_date(format: &str, text: &str) -> Option<DateTime<Utc>> {
    match format {
        "UNIX" => {
            let seconds = text.parse::<f64>().ok()?;
            DateTime::from_timestamp(seconds.trunc() as i64, 0)
        }
        "UNIX_MS" => {
            let millis = text.parse::<i64>().ok()?;
            DateTime::from_timestamp_millis(millis)
        }
        "ISO8601" => DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|timestamp| timestamp.with_timezone(&Utc))
            .or_else(|| {
                chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f")
                    .ok()
                    .map(|naive| Utc.from_utc_datetime(&naive))
            }),
        other => {
            let pattern = joda_to_chrono(other);
            chrono::NaiveDateTime::parse_from_str(text, &pattern)
                .ok()
                .map(|naive| Utc.from_utc_datetime(&naive))
                .or_else(|| {
                    chrono::NaiveDate::parse_from_str(text, &pattern)
                        .ok()
                        .map(|date| date.and_hms_opt(0, 0, 0).unwrap())
                        .map(|naive| Utc.from_utc_datetime(&naive))
                })
        }
    }
}

fn joda_to_chrono(format: &str) -> String {
    let mut out = String::new();
    let mut chars = format.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        if ch == '\'' {
            quoted = !quoted;
            continue;
        }
        if quoted {
            out.push(ch);
            continue;
        }
        let mut run = 1;
        while chars.peek() == Some(&ch) {
            chars.next();
            run += 1;
        }
        let token = match (ch, run) {
            ('y', 2) => "%y",
            ('y', _) => "%Y",
            ('M', 1 | 2) => "%m",
            ('M', 3) => "%b",
            ('M', _) => "%B",
            ('d', _) => "%d",
            ('H', _) => "%H",
            ('m', _) => "%M",
            ('s', _) => "%S",
            ('S', _) => "%f",
            _ => {
                out.extend(std::iter::repeat_n(ch, run));
                continue;
            }
        };
        out.push_str(token);
    }
    out
}

fn dissect_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let Some(Arg::Map(entries)) = arg(plugin, "mapping") else {
        return Err(fail("dissect filter requires mapping"));
    };
    for (key, value) in entries {
        let field = key_text(key);
        let pattern = arg_text(value)?;
        let Some(Value::String(text)) = event.get_field(&field).map_err(err)? else {
            event.tag("_dissectfailure");
            continue;
        };
        if !apply_dissect(&mut event, &text, &pattern)? {
            event.tag("_dissectfailure");
        }
    }
    Ok(vec![event])
}

fn apply_dissect(event: &mut Event, text: &str, pattern: &str) -> Result<bool, RunError> {
    let tokens = dissect_tokens(pattern);
    let mut rest = text;
    let mut appends: Vec<(String, usize, String, String)> = Vec::new();
    let mut saved: Vec<(String, String)> = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let captured = if let Some(delimiter) = &token.delimiter {
            if let Some(found) = rest.find(delimiter) {
                let captured = rest[..found].to_string();
                rest = &rest[found + delimiter.len()..];
                captured
            } else {
                return Ok(false);
            }
        } else if index + 1 == tokens.len() {
            let captured = rest.to_string();
            rest = "";
            captured
        } else {
            return Ok(false);
        };
        match token.kind {
            DissectKind::Field => {
                event
                    .set_field(&token.key, Value::from(captured))
                    .map_err(err)?;
            }
            DissectKind::Skip => {}
            DissectKind::Append => {
                let glue = token.leading.clone().unwrap_or_else(|| " ".to_string());
                appends.push((
                    token.key.clone(),
                    token.order.unwrap_or(index),
                    glue,
                    captured,
                ));
            }
            DissectKind::Indirect => saved.push((token.key.clone(), captured)),
        }
    }
    let mut names: Vec<String> = appends.iter().map(|(key, _, _, _)| key.clone()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let mut parts: Vec<_> = appends
            .iter()
            .filter(|(key, _, _, _)| key == &name)
            .collect();
        parts.sort_by_key(|(_, order, _, _)| *order);
        let mut text = String::new();
        for (index, (_, _, glue, value)) in parts.iter().enumerate() {
            if index > 0 {
                text.push_str(glue);
            }
            text.push_str(value);
        }
        event.set_field(&name, Value::from(text)).map_err(err)?;
    }
    for (key, value) in saved {
        if let Some(Value::String(name)) = event.get_field(&key).map_err(err)? {
            event.set_field(&name, Value::from(value)).map_err(err)?;
        }
    }
    Ok(true)
}

struct DissectToken {
    kind: DissectKind,
    key: String,
    order: Option<usize>,
    delimiter: Option<String>,
    leading: Option<String>,
}

enum DissectKind {
    Field,
    Skip,
    Append,
    Indirect,
}

fn dissect_tokens(pattern: &str) -> Vec<DissectToken> {
    let mut tokens = Vec::new();
    let mut rest = pattern;
    let mut leading = None;
    if let Some(start) = rest.find("%{")
        && start > 0
    {
        leading = Some(rest[..start].to_string());
        rest = &rest[start..];
    }
    while let Some(start) = rest.find("%{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            break;
        };
        let body = &after[..end];
        let next = &after[end + 1..];
        let delimiter = next.find("%{").map(|index| next[..index].to_string());
        let (kind, key, order) = dissect_body(body);
        tokens.push(DissectToken {
            kind,
            key,
            order,
            delimiter: delimiter.clone(),
            leading: leading.take(),
        });
        if let Some(delimiter) = delimiter {
            rest = &next[delimiter.len()..];
        } else {
            break;
        }
    }
    tokens
}

fn dissect_body(body: &str) -> (DissectKind, String, Option<usize>) {
    if body.is_empty() {
        return (DissectKind::Skip, String::new(), None);
    }
    let (kind, rest) = match body.as_bytes()[0] {
        b'?' => (DissectKind::Skip, &body[1..]),
        b'+' => (DissectKind::Append, &body[1..]),
        b'&' => (DissectKind::Indirect, &body[1..]),
        _ => (DissectKind::Field, body),
    };
    if let Some((key, order)) = rest.split_once('/') {
        (kind, key.to_string(), order.parse().ok())
    } else {
        (kind, rest.to_string(), None)
    }
}

fn kv_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let source = arg_string(plugin, "source").unwrap_or_else(|| "message".to_string());
    let Some(Value::String(text)) = event.get_field(&source).map_err(err)? else {
        return Ok(vec![event]);
    };
    let field_split = arg_string(plugin, "field_split").unwrap_or_else(|| " ".to_string());
    let value_split = arg_string(plugin, "value_split").unwrap_or_else(|| "=".to_string());
    let target = arg_string(plugin, "target");
    let trim_key = arg_string(plugin, "trim_key");
    let trim_value = arg_string(plugin, "trim_value");
    for piece in text.split(&field_split) {
        let Some((key, value)) = piece.split_once(&value_split) else {
            continue;
        };
        let key = trim_chars(key, trim_key.as_deref());
        let value = trim_chars(value, trim_value.as_deref());
        if key.is_empty() {
            continue;
        }
        let field = if let Some(target) = &target {
            format!("{target}[{key}]")
        } else {
            key
        };
        event.set_field(&field, Value::from(value)).map_err(err)?;
    }
    Ok(vec![event])
}

fn trim_chars(text: &str, chars: Option<&str>) -> String {
    let Some(chars) = chars else {
        return text.to_string();
    };
    text.trim_matches(|ch| chars.contains(ch)).to_string()
}

fn fingerprint_filter(plugin: &Plugin, mut event: Event) -> Result<Vec<Event>, RunError> {
    let method = arg_string(plugin, "method").unwrap_or_else(|| "SHA1".to_string());
    let target = arg_string(plugin, "target").unwrap_or_else(|| "fingerprint".to_string());
    if method == "UUID" {
        event
            .set_field(&target, Value::from(uuid_v4()))
            .map_err(err)?;
        return Ok(vec![event]);
    }
    let source = string_list(plugin, "source").unwrap_or_else(|_| vec!["message".to_string()]);
    if method == "PUNCTUATION" {
        for field in source {
            if let Some(Value::String(text)) = event.get_field(&field).map_err(err)? {
                let punct: String = text
                    .chars()
                    .filter(|ch| ch.is_ascii_punctuation())
                    .collect();
                event.set_field(&target, Value::from(punct)).map_err(err)?;
            }
        }
        return Ok(vec![event]);
    }
    for field in source {
        let Some(value) = event.get_field(&field).map_err(err)? else {
            continue;
        };
        let digest = match method.as_str() {
            "SHA256" => sha256_hex(&value.to_string()),
            "SHA1" => sha1_hex(&value.to_string()),
            other => {
                return Err(fail(format!(
                    "fingerprint method {other} is not implemented"
                )));
            }
        };
        event.set_field(&target, Value::from(digest)).map_err(err)?;
    }
    Ok(vec![event])
}

fn sleep_filter(plugin: &Plugin, event: Event) -> Result<Vec<Event>, RunError> {
    if let Some(time) = arg_string(plugin, "time")
        && let Ok(seconds) = time.parse::<f64>()
        && seconds > 0.0
    {
        thread::sleep(Duration::from_secs_f64(seconds));
    }
    Ok(vec![event])
}

fn rubydebug(event: &Event, metadata: bool) -> String {
    let map = if metadata {
        event.to_map_with_metadata()
    } else {
        event.to_map()
    };
    let mut lines = Vec::new();
    let mut width = 0;
    let pairs: Vec<(String, String)> = map
        .iter()
        .map(|(key, value)| {
            let rendered = ruby_value(value);
            width = width.max(key.len());
            (key.to_string(), rendered)
        })
        .collect();
    for (key, value) in pairs {
        lines.push(format!(
            "    {key:>width$} => {value}",
            key = format!("\"{key}\"")
        ));
    }
    format!("{{\n{}\n}}\n", lines.join(",\n"))
}

fn ruby_value(value: &Value) -> String {
    match value {
        Value::String(text) => format!("\"{text}\""),
        Value::Null => "nil".to_string(),
        Value::Boolean(true) => "true".to_string(),
        Value::Boolean(false) => "false".to_string(),
        Value::Array(items) => {
            let rendered = items.iter().map(ruby_value).collect::<Vec<_>>().join(", ");
            format!("[{rendered}]")
        }
        Value::Map(map) => {
            let rendered = map
                .iter()
                .map(|(key, value)| format!("\"{key}\" => {}", ruby_value(value)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{rendered}}}")
        }
        other => other.to_string(),
    }
}

fn decode_json(data: &str) -> Result<Vec<Event>, RunError> {
    match Event::from_json(data) {
        Ok(events) if !events.is_empty() => Ok(events),
        _ => {
            let mut event = Event::new();
            event.set_field("message", Value::from(data)).map_err(err)?;
            event.tag("_jsonparsefailure");
            Ok(vec![event])
        }
    }
}

fn json_to_value(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(flag) => Value::Boolean(*flag),
        serde_json::Value::Number(number) => {
            if number.to_string().contains(['.', 'e', 'E']) {
                Value::Float(number.as_f64().unwrap_or(0.0))
            } else if let Some(integer) = number.as_i64() {
                Value::Integer(i128::from(integer))
            } else if let Some(integer) = number.as_u64() {
                Value::Integer(i128::from(integer))
            } else {
                Value::from(number.to_string())
            }
        }
        serde_json::Value::String(text) => Value::from(text.as_str()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(json_to_value).collect()),
        serde_json::Value::Object(fields) => {
            let mut map = Map::new();
            for (key, value) in fields {
                map.insert(key, json_to_value(value));
            }
            Value::Map(map)
        }
    }
}

fn coerce_timestamp(value: &Value) -> Option<DateTime<Utc>> {
    match value {
        Value::Timestamp(timestamp) => Some(*timestamp),
        Value::String(text) => DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|timestamp| timestamp.with_timezone(&Utc)),
        Value::Integer(number) => DateTime::from_timestamp(*number as i64, 0),
        Value::Float(number) => DateTime::from_timestamp(number.trunc() as i64, 0),
        _ => None,
    }
}

fn tag_failure(event: &mut Event, plugin: &Plugin, default_tag: &str) {
    tag_list(event, plugin, default_tag);
}

fn tag_list(event: &mut Event, plugin: &Plugin, default_tag: &str) {
    match string_list(plugin, "tag_on_failure") {
        Ok(tags) if !tags.is_empty() => {
            for tag in tags {
                event.tag(&tag);
            }
        }
        _ => event.tag(default_tag),
    }
}

fn uuid_v4() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let tick = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&nanos.to_le_bytes()[..8]);
    bytes[8..].copy_from_slice(&tick.to_le_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn string_list(plugin: &Plugin, name: &str) -> Result<Vec<String>, RunError> {
    match arg(plugin, name) {
        None => Err(fail(format!("missing {name}"))),
        Some(Arg::String(value)) => Ok(vec![value.clone()]),
        Some(Arg::Array(items)) => items.iter().map(arg_text).collect(),
        Some(other) => Ok(vec![arg_text(other)?]),
    }
}

fn decorate_stdin(events: Vec<Event>, settings: &Settings) -> Result<Vec<Event>, RunError> {
    let host = crate::run::hostname();
    let ecs = settings.ecs != Ecs::Disabled;
    let host_field = if ecs { "[host][hostname]" } else { "host" };
    let mut decorated = Vec::new();
    for mut event in events {
        if !event.includes(host_field).map_err(err)? {
            event
                .set_field(host_field, Value::from(host.as_str()))
                .map_err(err)?;
        }
        decorated.push(event);
    }
    Ok(decorated)
}

fn codec_plugin(plugin: &Plugin) -> Option<&Plugin> {
    match arg(plugin, "codec") {
        Some(Arg::Plugin(codec)) => Some(codec),
        _ => None,
    }
}

fn codec_name(plugin: &Plugin) -> String {
    match arg(plugin, "codec") {
        Some(Arg::String(name)) => name.clone(),
        Some(Arg::Plugin(codec)) => codec.name.clone(),
        _ => "line".to_string(),
    }
}

fn arg<'a>(plugin: &'a Plugin, name: &str) -> Option<&'a Arg> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn arg_string(plugin: &Plugin, name: &str) -> Option<String> {
    match arg(plugin, name) {
        Some(Arg::String(value)) => Some(value.clone()),
        Some(Arg::Int(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn arg_i64(plugin: &Plugin, name: &str) -> Option<i64> {
    match arg(plugin, name) {
        Some(Arg::Int(value)) => Some(*value),
        Some(Arg::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn arg_bool(plugin: &Plugin, name: &str) -> bool {
    arg_bool_default(plugin, name, false)
}

fn arg_bool_default(plugin: &Plugin, name: &str, default: bool) -> bool {
    match arg(plugin, name) {
        Some(Arg::String(value)) => value != "false",
        None => default,
        Some(_) => true,
    }
}

fn arg_text(arg: &Arg) -> Result<String, RunError> {
    match arg {
        Arg::String(value) => Ok(value.clone()),
        Arg::Int(value) => Ok(value.to_string()),
        Arg::Big(value) => Ok(value.clone()),
        Arg::Float(value) => Ok(value.to_string()),
        _ => Err(fail("plugin option value must be a scalar")),
    }
}

fn key_text(key: &Key) -> String {
    match key {
        Key::String(value) => value.clone(),
        Key::Int(value) => value.to_string(),
        Key::Big(value) => value.clone(),
        Key::Float(value) => value.to_string(),
    }
}

fn err(error: crate::EventError) -> RunError {
    fail(error.to_string())
}
