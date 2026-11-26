//! JDBC input 5.6.4 for a one-shot statement.
//!
//! Official `schedule`, `interval`, and `period` stay in the scheduler until
//! shutdown. This pipeline has no shutdown signal, so those options are
//! refused. `jdbc:postgresql://` speaks the PostgreSQL 3.0 simple-query
//! protocol (trust, cleartext, or md5). Other JDBC schemes are refused.
//! Prepared-statement placeholders are inlined into that simple query.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::digest::md5_hex;
use crate::event::Event;
use crate::lscl::{Arg, Key, Plugin};
use crate::mutate::filter_matched;
use crate::run::{RunError, Settings, fail};
use crate::value::{Map, Value};

const EPOCH: &str = "1970-01-01 00:00:00.000000000 Z";

pub(crate) fn read(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    let repeat = [
        text(plugin, "interval").is_some(),
        text(plugin, "schedule").is_some(),
        text(plugin, "period").is_some(),
    ]
    .into_iter()
    .filter(|set| *set)
    .count();
    if repeat > 1 {
        return Err(fail("Use only one of: interval, period, schedule."));
    }
    if repeat == 1 {
        return Err(fail("jdbc schedule is not implemented"));
    }
    if flag(plugin, "jdbc_paging_enabled").unwrap_or(false) {
        return Err(fail("jdbc paging is not implemented"));
    }
    if text(plugin, "charset").is_some() || has_map(plugin, "columns_charset") {
        return Err(fail("jdbc charset is not implemented"));
    }
    if text(plugin, "jdbc_password").is_some() && text(plugin, "jdbc_password_filepath").is_some() {
        return Err(fail(
            "Only one of :jdbc_password, :jdbc_password_filepath may be set at a time.",
        ));
    }
    let driver = text(plugin, "jdbc_driver_class")
        .ok_or_else(|| fail("jdbc input requires jdbc_driver_class"))?;
    let connection = text(plugin, "jdbc_connection_string")
        .ok_or_else(|| fail("jdbc input requires jdbc_connection_string"))?;
    let user = text(plugin, "jdbc_user").ok_or_else(|| fail("jdbc input requires jdbc_user"))?;
    let _driver = driver;
    if let Some(library) = text(plugin, "jdbc_driver_library")
        && !PathBuf::from(&library).is_file()
    {
        return Err(fail(format!("jdbc_driver_library {library} was not found")));
    }
    let mut password = text(plugin, "jdbc_password").unwrap_or_default();
    if let Some(path) = text(plugin, "jdbc_password_filepath") {
        password = fs::read_to_string(&path)
            .map_err(|error| fail(error.to_string()))?
            .trim()
            .to_string();
    }
    let statement = load_statement(plugin)?;
    let prepared = flag(plugin, "use_prepared_statements").unwrap_or(false);
    if prepared {
        let mut errors = Vec::new();
        if text(plugin, "prepared_statement_name")
            .unwrap_or_default()
            .is_empty()
        {
            errors.push(
                "must provide a name for the Prepared Statement, it must be unique for the db session",
            );
        }
        let marks = placeholder_count(&statement);
        let binds = string_list(plugin, "prepared_statement_bind_values").len();
        if marks != binds {
            errors.push(
                "there is a mismatch between the number of statement `?` placeholders and :prepared_statement_bind_values array setting elements",
            );
        }
        if !errors.is_empty() {
            return Err(fail(format!(
                "Prepared Statement Mode validation errors: {}",
                errors.join(", ")
            )));
        }
    }
    if flag(plugin, "use_column_value").unwrap_or(false)
        && text(plugin, "tracking_column").is_none()
    {
        return Err(fail(
            "Must set :tracking_column if :use_column_value is true.",
        ));
    }
    let address = parse_postgres(&connection)?;
    let record = flag(plugin, "record_last_run").unwrap_or(true);
    let tracker = Tracker::open(plugin, settings, record)?;
    let attempts = number(plugin, "statement_retry_attempts")
        .unwrap_or(1)
        .max(1);
    let wait = wait_seconds(plugin);
    let mut last_error = None;
    for attempt in 0..attempts {
        match query_once(
            plugin, &address, &user, &password, &statement, prepared, &tracker,
        ) {
            Ok(events) => {
                tracker.store(plugin, &events)?;
                return Ok(events);
            }
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < attempts {
                    std::thread::sleep(Duration::from_secs_f64(wait));
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| fail("jdbc query failed")))
}

struct Address {
    host: String,
    port: u16,
    database: String,
}

fn parse_postgres(connection: &str) -> Result<Address, RunError> {
    let rest = connection.strip_prefix("jdbc:").ok_or_else(|| {
        fail(format!(
            "jdbc connection string {connection} is not a jdbc url"
        ))
    })?;
    let (scheme, after) = rest
        .split_once(':')
        .ok_or_else(|| fail(format!("jdbc driver {rest} is not implemented")))?;
    if scheme != "postgresql" {
        return Err(fail(format!("jdbc driver {scheme} is not implemented")));
    }
    let after = after.strip_prefix("//").ok_or_else(|| {
        fail(format!(
            "jdbc connection string {connection} is not a jdbc url"
        ))
    })?;
    if after.contains("ssl=true")
        || after.contains("sslmode=require")
        || after.contains("sslmode=verify-")
    {
        return Err(fail("jdbc ssl is not implemented"));
    }
    let (authority, database) = after
        .split_once('/')
        .ok_or_else(|| fail("jdbc postgresql url needs a database name"))?;
    let database = database.split(['?', ';']).next().unwrap_or(database);
    if database.is_empty() {
        return Err(fail("jdbc postgresql url needs a database name"));
    }
    if authority.starts_with('[') {
        return Err(fail("jdbc ipv6 hosts are not implemented"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| fail(format!("jdbc postgresql port {port} is not a number")))?;
            (host.to_string(), port)
        }
        None => (authority.to_string(), 5432),
    };
    if host.is_empty() {
        return Err(fail("jdbc postgresql url needs a host"));
    }
    Ok(Address {
        host,
        port,
        database: database.to_string(),
    })
}

fn query_once(
    plugin: &Plugin,
    address: &Address,
    user: &str,
    password: &str,
    statement: &str,
    prepared: bool,
    tracker: &Tracker,
) -> Result<Vec<Event>, RunError> {
    let sql = if prepared {
        inline_placeholders(
            statement,
            &string_list(plugin, "prepared_statement_bind_values"),
        )?
    } else {
        bind_named(statement, &named_literals(plugin, tracker)?)?
    };
    let mut stream = TcpStream::connect_timeout(
        &format!("{}:{}", address.host, address.port)
            .parse()
            .map_err(|error| fail(format!("jdbc postgresql {error}")))?,
        Duration::from_secs(2),
    )
    .map_err(|error| fail(format!("jdbc postgresql {error}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| fail(error.to_string()))?;
    stream
        .write_all(&startup(user, &address.database))
        .map_err(|error| fail(error.to_string()))?;
    until_ready(&mut stream, user, password)?;
    let mut query = Vec::new();
    query.push(b'Q');
    let mut body = sql.into_bytes();
    body.push(0);
    write_i32(&mut query, (body.len() + 4) as i32);
    query.extend_from_slice(&body);
    stream
        .write_all(&query)
        .map_err(|error| fail(error.to_string()))?;
    let rows = read_rows(&mut stream)?;
    rows_to_events(plugin, rows)
}

fn startup(user: &str, database: &str) -> Vec<u8> {
    let mut body = Vec::new();
    write_i32(&mut body, 196_608);
    for (key, value) in [
        ("user", user),
        ("database", database),
        ("client_encoding", "UTF8"),
    ] {
        body.extend_from_slice(key.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut message = Vec::new();
    write_i32(&mut message, (body.len() + 4) as i32);
    message.extend_from_slice(&body);
    message
}

fn until_ready(stream: &mut TcpStream, user: &str, password: &str) -> Result<(), RunError> {
    loop {
        let (kind, payload) = read_message(stream)?;
        match kind {
            b'Z' => return Ok(()),
            b'E' => return Err(postgres_error(&payload)),
            b'R' => authenticate(stream, &payload, user, password)?,
            b'S' | b'K' | b'N' => {}
            other => {
                return Err(fail(format!(
                    "jdbc postgresql message {} is not implemented",
                    other as char
                )));
            }
        }
    }
}

fn authenticate(
    stream: &mut TcpStream,
    payload: &[u8],
    user: &str,
    password: &str,
) -> Result<(), RunError> {
    if payload.len() < 4 {
        return Err(fail("jdbc postgresql authentication response ended early"));
    }
    let kind = i32::from_be_bytes(payload[0..4].try_into().expect("auth"));
    match kind {
        0 => Ok(()),
        3 => send_password(stream, password.as_bytes()),
        5 => {
            if payload.len() < 8 {
                return Err(fail("jdbc postgresql md5 salt ended early"));
            }
            let inner = md5_hex([password.as_bytes(), user.as_bytes()].concat().as_slice());
            let outer = md5_hex([inner.as_bytes(), &payload[4..8]].concat().as_slice());
            send_password(stream, format!("md5{outer}").as_bytes())
        }
        other => Err(fail(format!(
            "jdbc postgresql authentication {other} is not implemented"
        ))),
    }
}

fn send_password(stream: &mut TcpStream, password: &[u8]) -> Result<(), RunError> {
    let mut message = vec![b'p'];
    write_i32(&mut message, (password.len() + 5) as i32);
    message.extend_from_slice(password);
    message.push(0);
    stream
        .write_all(&message)
        .map_err(|error| fail(error.to_string()))
}

struct PgRow {
    names: Vec<String>,
    cells: Vec<Option<Vec<u8>>>,
    types: Vec<i32>,
}

fn read_rows(stream: &mut TcpStream) -> Result<Vec<PgRow>, RunError> {
    let mut names = Vec::new();
    let mut types = Vec::new();
    let mut rows = Vec::new();
    loop {
        let (kind, payload) = read_message(stream)?;
        match kind {
            b'T' => {
                let (parsed_names, parsed_types) = row_description(&payload)?;
                names = parsed_names;
                types = parsed_types;
            }
            b'D' => rows.push(PgRow {
                names: names.clone(),
                cells: data_row(&payload)?,
                types: types.clone(),
            }),
            b'C' | b'I' | b'N' => {}
            b'Z' => return Ok(rows),
            b'E' => return Err(postgres_error(&payload)),
            other => {
                return Err(fail(format!(
                    "jdbc postgresql message {} is not implemented",
                    other as char
                )));
            }
        }
    }
}

fn row_description(payload: &[u8]) -> Result<(Vec<String>, Vec<i32>), RunError> {
    if payload.len() < 2 {
        return Err(fail("jdbc postgresql row description ended early"));
    }
    let count = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let mut cursor = 2;
    let mut names = Vec::new();
    let mut types = Vec::new();
    for _ in 0..count {
        let name = cstring(payload, &mut cursor)?;
        cursor += 4 + 2;
        if cursor + 4 > payload.len() {
            return Err(fail("jdbc postgresql row description ended early"));
        }
        let oid = i32::from_be_bytes(payload[cursor..cursor + 4].try_into().expect("oid"));
        cursor += 4 + 2 + 4 + 2;
        names.push(name);
        types.push(oid);
    }
    Ok((names, types))
}

fn data_row(payload: &[u8]) -> Result<Vec<Option<Vec<u8>>>, RunError> {
    if payload.len() < 2 {
        return Err(fail("jdbc postgresql data row ended early"));
    }
    let count = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let mut cursor = 2;
    let mut cells = Vec::new();
    for _ in 0..count {
        if cursor + 4 > payload.len() {
            return Err(fail("jdbc postgresql data row ended early"));
        }
        let length = i32::from_be_bytes(payload[cursor..cursor + 4].try_into().expect("len"));
        cursor += 4;
        if length < 0 {
            cells.push(None);
            continue;
        }
        let length = length as usize;
        if cursor + length > payload.len() {
            return Err(fail("jdbc postgresql data row ended early"));
        }
        cells.push(Some(payload[cursor..cursor + length].to_vec()));
        cursor += length;
    }
    Ok(cells)
}

fn rows_to_events(plugin: &Plugin, rows: Vec<PgRow>) -> Result<Vec<Event>, RunError> {
    let lower = flag(plugin, "lowercase_column_names").unwrap_or(true);
    let target = text(plugin, "target");
    let mut events = Vec::new();
    for PgRow { names, cells, types } in rows {
        let mut columns = Vec::new();
        for ((name, cell), oid) in names.into_iter().zip(cells).zip(types) {
            let name = if lower {
                name.to_ascii_lowercase()
            } else {
                name
            };
            columns.push((name, cell_value(oid, cell)?));
        }
        let mut event = Event::new();
        if let Some(target) = &target {
            let mut map = Map::new();
            for (name, value) in columns {
                map.insert(name, value);
            }
            event
                .set_field(target, Value::Map(map))
                .map_err(|error| fail(error.to_string()))?;
        } else {
            for (name, value) in columns {
                event
                    .set_field(&name, value)
                    .map_err(|error| fail(error.to_string()))?;
            }
        }
        decorate(plugin, &mut event)?;
        events.push(event);
    }
    Ok(events)
}

fn cell_value(oid: i32, cell: Option<Vec<u8>>) -> Result<Value, RunError> {
    let Some(bytes) = cell else {
        return Ok(Value::Null);
    };
    let text = String::from_utf8(bytes).map_err(|error| fail(error.to_string()))?;
    Ok(match oid {
        16 => Value::Boolean(matches!(text.as_str(), "t" | "true" | "1")),
        20 | 21 | 23 => text
            .parse::<i128>()
            .map(Value::Integer)
            .unwrap_or_else(|_| Value::from(text.as_str())),
        700 | 701 => text
            .parse::<f64>()
            .map(Value::Float)
            .unwrap_or_else(|_| Value::from(text.as_str())),
        1700 => Value::from(text.as_str()),
        1082 | 1114 | 1184 => timestamp_value(&text).unwrap_or_else(|| Value::from(text.as_str())),
        _ => Value::from(text.as_str()),
    })
}

fn timestamp_value(text: &str) -> Option<Value> {
    let normalized = text.replace(' ', "T");
    let parsed = chrono::DateTime::parse_from_rfc3339(&normalized)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(&format!("{normalized}Z")));
    parsed
        .ok()
        .map(|time| Value::Timestamp(time.with_timezone(&chrono::Utc)))
}

struct Tracker {
    path: Option<PathBuf>,
    numeric: bool,
    value: SqlValue,
}

enum SqlValue {
    Number(i128),
    Time(String),
}

impl Tracker {
    fn open(plugin: &Plugin, settings: &Settings, record: bool) -> Result<Self, RunError> {
        let numeric = flag(plugin, "use_column_value").unwrap_or(false)
            && text(plugin, "tracking_column_type").unwrap_or_else(|| "numeric".to_string())
                == "numeric";
        let path = if record {
            Some(metadata_path(plugin, settings)?)
        } else {
            None
        };
        if flag(plugin, "clean_run").unwrap_or(false)
            && let Some(path) = &path
        {
            let _ = fs::remove_file(path);
        }
        let value = match &path {
            Some(path) => read_metadata(path, numeric).unwrap_or_else(|| default_value(numeric)),
            None => default_value(numeric),
        };
        Ok(Self {
            path,
            numeric,
            value,
        })
    }

    fn literal(&self) -> String {
        match &self.value {
            SqlValue::Number(number) => number.to_string(),
            SqlValue::Time(text) => quote(text),
        }
    }

    fn store(&self, plugin: &Plugin, events: &[Event]) -> Result<(), RunError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let value = if flag(plugin, "use_column_value").unwrap_or(false) {
            let column = text(plugin, "tracking_column").unwrap_or_default();
            let column = if flag(plugin, "lowercase_column_names").unwrap_or(true) {
                column.to_ascii_lowercase()
            } else {
                column
            };
            events
                .iter()
                .rev()
                .find_map(|event| tracked_value(event, &column, self.numeric))
                .unwrap_or_else(|| self.literal_yaml())
        } else {
            format!("--- {}\n", format_now())
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| fail(error.to_string()))?;
        }
        fs::write(path, value).map_err(|error| fail(error.to_string()))
    }

    fn literal_yaml(&self) -> String {
        match &self.value {
            SqlValue::Number(number) => format!("--- {number}\n"),
            SqlValue::Time(text) => format!("--- {text}\n"),
        }
    }
}

fn tracked_value(event: &Event, column: &str, numeric: bool) -> Option<String> {
    let value = event.get_field(column).ok().flatten()?;
    if numeric {
        match value {
            Value::Integer(number) => Some(format!("--- {number}\n")),
            _ => None,
        }
    } else {
        match value {
            Value::Timestamp(time) => {
                Some(format!("--- {}\n", time.format("%Y-%m-%d %H:%M:%S%.9f Z")))
            }
            Value::String(text) => Some(format!("--- {text}\n")),
            _ => None,
        }
    }
}

fn default_value(numeric: bool) -> SqlValue {
    if numeric {
        SqlValue::Number(0)
    } else {
        SqlValue::Time(EPOCH.to_string())
    }
}

fn read_metadata(path: &PathBuf, numeric: bool) -> Option<SqlValue> {
    let text = fs::read_to_string(path).ok()?;
    let body = text.trim().trim_start_matches("---").trim();
    if numeric {
        body.parse::<i128>().ok().map(SqlValue::Number)
    } else if body.contains('-') && body.contains(':') {
        Some(SqlValue::Time(body.to_string()))
    } else {
        None
    }
}

fn metadata_path(plugin: &Plugin, settings: &Settings) -> Result<PathBuf, RunError> {
    if let Some(path) = text(plugin, "last_run_metadata_path") {
        let file = PathBuf::from(&path);
        if file.is_dir() {
            return Err(fail(format!(
                "The \"last_run_metadata_path\" argument must point to a file, received a directory: \"{path}\""
            )));
        }
        return Ok(file);
    }
    let data = settings
        .path_data
        .as_deref()
        .ok_or_else(|| fail("jdbc record_last_run requires path.data or last_run_metadata_path"))?;
    let directory = PathBuf::from(data)
        .join("plugins")
        .join("inputs")
        .join("jdbc");
    fs::create_dir_all(&directory).map_err(|error| fail(error.to_string()))?;
    let file = directory.join("logstash_jdbc_last_run");
    if !file.exists()
        && let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
    {
        let old = PathBuf::from(home).join(".logstash_jdbc_last_run");
        if old.is_file() {
            let _ = fs::copy(&old, &file);
        }
    }
    Ok(file)
}

fn named_literals(
    plugin: &Plugin,
    tracker: &Tracker,
) -> Result<BTreeMap<String, String>, RunError> {
    let mut values = BTreeMap::new();
    values.insert("sql_last_value".to_string(), tracker.literal());
    if let Some(Arg::Map(entries)) = arg(plugin, "parameters") {
        for (key, value) in entries {
            values.insert(key_text(key), sql_literal(value)?);
        }
    }
    Ok(values)
}

fn bind_named(sql: &str, values: &BTreeMap<String, String>) -> Result<String, RunError> {
    substitute(sql, false, &mut |name| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| fail(format!("jdbc parameter {name} is not set")))
    })
}

fn inline_placeholders(sql: &str, values: &[String]) -> Result<String, RunError> {
    let mut index = 0;
    substitute(sql, true, &mut |_| {
        let value = values
            .get(index)
            .ok_or_else(|| fail("jdbc prepared statement ran out of bind values"))?;
        index += 1;
        Ok(quote(value))
    })
}

fn substitute(
    sql: &str,
    positional: bool,
    replace: &mut dyn FnMut(&str) -> Result<String, RunError>,
) -> Result<String, RunError> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\'' {
            out.push('\'');
            index += 1;
            while index < chars.len() {
                out.push(chars[index]);
                if chars[index] == '\'' {
                    if index + 1 < chars.len() && chars[index + 1] == '\'' {
                        out.push(chars[index + 1]);
                        index += 2;
                        continue;
                    }
                    index += 1;
                    break;
                }
                index += 1;
            }
            continue;
        }
        if chars[index] == '?' {
            if positional {
                out.push_str(&replace("?")?);
            } else {
                out.push('?');
            }
            index += 1;
            continue;
        }
        if !positional && chars[index] == ':' && (index == 0 || chars[index - 1] != ':') {
            let start = index + 1;
            if start < chars.len() && (chars[start].is_ascii_alphabetic() || chars[start] == '_') {
                let mut end = start + 1;
                while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_')
                {
                    end += 1;
                }
                let name: String = chars[start..end].iter().collect();
                out.push_str(&replace(&name)?);
                index = end;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    Ok(out)
}

fn placeholder_count(sql: &str) -> usize {
    let mut count = 0;
    let mut quoted = false;
    let mut chars = sql.chars().peekable();
    while let Some(char) = chars.next() {
        if char == '\'' {
            if quoted && chars.peek() == Some(&'\'') {
                chars.next();
                continue;
            }
            quoted = !quoted;
            continue;
        }
        if !quoted && char == '?' {
            count += 1;
        }
    }
    count
}

fn sql_literal(value: &Arg) -> Result<String, RunError> {
    Ok(match value {
        Arg::Int(number) => number.to_string(),
        Arg::Big(text) | Arg::String(text) => {
            if text.chars().all(|char| char.is_ascii_digit())
                || text.starts_with('-') && text[1..].chars().all(|char| char.is_ascii_digit())
            {
                text.clone()
            } else {
                quote(text)
            }
        }
        Arg::Float(number) => number.to_string(),
        _ => return Err(fail("jdbc parameter values must be scalars")),
    })
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

fn load_statement(plugin: &Plugin) -> Result<String, RunError> {
    let statement = text(plugin, "statement");
    let path = text(plugin, "statement_filepath");
    match (statement, path) {
        (Some(statement), None) => Ok(statement),
        (None, Some(path)) => fs::read_to_string(&path).map_err(|error| fail(error.to_string())),
        _ => Err(fail(
            "Must set either :statement or :statement_filepath. Only one may be set at a time.",
        )),
    }
}

fn decorate(plugin: &Plugin, event: &mut Event) -> Result<(), RunError> {
    if let Some(kind) = text(plugin, "type") {
        event
            .set_field("type", Value::from(kind.as_str()))
            .map_err(|error| fail(error.to_string()))?;
    }
    for tag in string_list(plugin, "tags") {
        event.tag(&tag);
    }
    filter_matched(plugin, event)
}

fn format_now() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    chrono::DateTime::from_timestamp(duration.as_secs() as i64, duration.subsec_nanos())
        .map(|time| time.format("%Y-%m-%d %H:%M:%S%.9f Z").to_string())
        .unwrap_or_else(|| EPOCH.to_string())
}

fn read_message(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), RunError> {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|error| fail(error.to_string()))?;
    let length = i32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if length < 4 {
        return Err(fail("jdbc postgresql message length is short"));
    }
    let mut payload = vec![0u8; (length - 4) as usize];
    if !payload.is_empty() {
        stream
            .read_exact(&mut payload)
            .map_err(|error| fail(error.to_string()))?;
    }
    Ok((header[0], payload))
}

fn postgres_error(payload: &[u8]) -> RunError {
    let mut cursor = 0;
    let mut message = String::new();
    while cursor < payload.len() && payload[cursor] != 0 {
        let code = payload[cursor];
        cursor += 1;
        let text = cstring(payload, &mut cursor).unwrap_or_default();
        if code == b'M' {
            message = text;
        }
    }
    if message.is_empty() {
        message = "jdbc postgresql error".to_string();
    }
    fail(message)
}

fn cstring(payload: &[u8], cursor: &mut usize) -> Result<String, RunError> {
    let start = *cursor;
    while *cursor < payload.len() && payload[*cursor] != 0 {
        *cursor += 1;
    }
    if *cursor >= payload.len() {
        return Err(fail("jdbc postgresql string ended early"));
    }
    let text = String::from_utf8(payload[start..*cursor].to_vec())
        .map_err(|error| fail(error.to_string()))?;
    *cursor += 1;
    Ok(text)
}

fn write_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn arg<'a>(plugin: &'a Plugin, name: &str) -> Option<&'a Arg> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn has_map(plugin: &Plugin, name: &str) -> bool {
    matches!(arg(plugin, name), Some(Arg::Map(entries)) if !entries.is_empty())
}

fn text(plugin: &Plugin, name: &str) -> Option<String> {
    match arg(plugin, name) {
        Some(Arg::String(value)) => Some(value.clone()),
        Some(Arg::Int(value)) => Some(value.to_string()),
        Some(Arg::Big(value)) => Some(value.clone()),
        _ => None,
    }
}

fn number(plugin: &Plugin, name: &str) -> Option<i64> {
    match arg(plugin, name) {
        Some(Arg::Int(value)) => Some(*value),
        Some(Arg::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn flag(plugin: &Plugin, name: &str) -> Option<bool> {
    match arg(plugin, name) {
        Some(Arg::String(value)) => Some(value != "false"),
        Some(Arg::Int(value)) => Some(*value != 0),
        Some(_) => Some(true),
        None => None,
    }
}

fn string_list(plugin: &Plugin, name: &str) -> Vec<String> {
    match arg(plugin, name) {
        Some(Arg::Array(items)) => items
            .iter()
            .filter_map(|item| match item {
                Arg::String(value) => Some(value.clone()),
                Arg::Int(value) => Some(value.to_string()),
                Arg::Big(value) => Some(value.clone()),
                _ => None,
            })
            .collect(),
        Some(Arg::String(value)) => vec![value.clone()],
        _ => Vec::new(),
    }
}

fn wait_seconds(plugin: &Plugin) -> f64 {
    match arg(plugin, "statement_retry_attempts_wait_time") {
        Some(Arg::Float(value)) => *value,
        Some(Arg::Int(value)) => *value as f64,
        Some(Arg::String(value)) => value.parse().unwrap_or(0.5),
        _ => 0.5,
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

#[cfg(test)]
mod tests {
    use super::bind_named;
    use std::collections::BTreeMap;

    #[test]
    fn named_parameters_skip_casts_and_quotes() {
        let mut values = BTreeMap::new();
        values.insert("id".to_string(), "7".to_string());
        values.insert("sql_last_value".to_string(), "'1970-01-01'".to_string());
        let sql = bind_named(
            "SELECT id::int FROM t WHERE id = :id AND note = ':id' AND seen > :sql_last_value",
            &values,
        )
        .expect("bind");
        assert_eq!(
            sql,
            "SELECT id::int FROM t WHERE id = 7 AND note = ':id' AND seen > '1970-01-01'"
        );
    }
}
