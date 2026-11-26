//! TCP, UDP, HTTP, and Beats from the 9.5.2 gems.
//!
//! A server returns after a peer has connected and the listen socket then stays
//! idle. Official Logstash waits on `stop?`. There is no shutdown signal yet.
//! `ssl_enabled => true` is refused: this build does not link a TLS stack.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use crate::event::Event;
use crate::lscl::{Arg, Plugin};
use crate::run::{Ecs, RunError, Settings, fail};
use crate::value::{Map, Value};

const IDLE: Duration = Duration::from_millis(200);
const FIRST: Duration = Duration::from_secs(3);

pub(crate) fn tcp_input(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    refuse_ssl(plugin)?;
    let port = required_port(plugin)?;
    let host = bind_host(plugin);
    let mode = arg_string(plugin, "mode").unwrap_or_else(|| "server".to_string());
    if mode == "client" {
        let mut stream = TcpStream::connect((host.as_str(), port as u16))
            .map_err(|error| fail(error.to_string()))?;
        let peer = stream.peer_addr().ok();
        let bytes = read_until_idle(&mut stream)?;
        return events_from_bytes(
            plugin,
            settings,
            &bytes,
            peer.as_ref().map(|addr| addr.ip().to_string()),
            peer.map(|addr| addr.port()),
            "tcp",
        );
    }
    if mode != "server" {
        return Err(fail("tcp mode must be server or client"));
    }
    let listener = bind_tcp(&host, port)?;
    let mut events = Vec::new();
    accept_until_idle(&listener, |mut stream, peer| {
        let bytes = read_until_idle(&mut stream)?;
        events.extend(events_from_bytes(
            plugin,
            settings,
            &bytes,
            Some(peer.ip().to_string()),
            Some(peer.port()),
            "tcp",
        )?);
        Ok(())
    })?;
    Ok(events)
}

pub(crate) fn tcp_send(plugin: &Plugin, payload: &str) -> Result<(), RunError> {
    refuse_ssl(plugin)?;
    let host = arg_string(plugin, "host").ok_or_else(|| fail("tcp output requires host"))?;
    let port = required_port(plugin)?;
    let mode = arg_string(plugin, "mode").unwrap_or_else(|| "client".to_string());
    if mode != "client" {
        return Err(fail("tcp output server mode is not implemented"));
    }
    let mut stream = TcpStream::connect((host.as_str(), port as u16))
        .map_err(|error| fail(error.to_string()))?;
    stream
        .write_all(payload.as_bytes())
        .map_err(|error| fail(error.to_string()))?;
    Ok(())
}

pub(crate) fn udp_input(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    let port = required_port(plugin)?;
    let host = bind_host(plugin);
    let socket =
        UdpSocket::bind((host.as_str(), port as u16)).map_err(|error| fail(error.to_string()))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|error| fail(error.to_string()))?;
    let mut events = Vec::new();
    let started = Instant::now();
    let mut buffer = vec![0u8; arg_usize(plugin, "buffer_size").unwrap_or(65_536)];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, peer)) => {
                events.extend(events_from_bytes(
                    plugin,
                    settings,
                    &buffer[..size],
                    Some(peer.ip().to_string()),
                    Some(peer.port()),
                    "udp",
                )?);
            }
            Err(error) if idle_error(&error) => {
                if !events.is_empty() || started.elapsed() > FIRST {
                    break;
                }
            }
            Err(error) => return Err(fail(error.to_string())),
        }
    }
    Ok(events)
}

pub(crate) fn udp_send(plugin: &Plugin, event: &Event, payload: &str) -> Result<(), RunError> {
    let host = arg_string(plugin, "host").ok_or_else(|| fail("udp output requires host"))?;
    let port_text = arg_string(plugin, "port").ok_or_else(|| fail("udp output requires port"))?;
    let port_text = event
        .sprintf(&port_text)
        .map_err(|error| fail(error.to_string()))?;
    let port: u16 = port_text.parse().map_err(|_| {
        fail(format!(
            "Failed to resolve port, dropping event: {port_text}"
        ))
    })?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|error| fail(error.to_string()))?;
    socket
        .send_to(payload.as_bytes(), (host.as_str(), port))
        .map_err(|error| fail(error.to_string()))?;
    Ok(())
}

pub(crate) fn http_input(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    refuse_ssl(plugin)?;
    let port = arg_i64(plugin, "port").unwrap_or(8080);
    let host = bind_host(plugin);
    let listener = bind_tcp(&host, port)?;
    let user = arg_string(plugin, "user");
    let password = arg_string(plugin, "password");
    let mut events = Vec::new();
    accept_until_idle(&listener, |mut stream, peer| {
        let bytes = read_http(&mut stream)?;
        let Some(request) = parse_http(&bytes) else {
            return Ok(());
        };
        if !authorized(&request, user.as_deref(), password.as_deref()) {
            let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
            return Ok(());
        }
        let codec = codec_for_type(plugin, request.content_type.as_deref());
        let mut decoded =
            if codec == "cef" {
                let block = plugin.args.iter().find(|(key, _)| key == "codec").and_then(
                    |(_, arg)| match arg {
                        Arg::Plugin(codec) => Some(codec),
                        _ => None,
                    },
                );
                crate::cef::decode(block, request.body.as_bytes(), settings.ecs)?
            } else if codec == "avro" {
                let block = plugin
                    .args
                    .iter()
                    .find(|(key, _)| key == "codec")
                    .and_then(|(_, arg)| match arg {
                        Arg::Plugin(codec) => Some(codec),
                        _ => None,
                    })
                    .ok_or_else(|| fail(crate::avro::missing_schema()))?;
                vec![crate::avro::decode(
                    block,
                    request.body.as_bytes(),
                    settings.ecs,
                )?]
            } else {
                decode_payload(codec, request.body.as_bytes())?
            };
        for event in &mut decoded {
            stamp_http(event, settings, &peer.ip().to_string(), &request)?;
        }
        events.extend(decoded);
        let code = arg_i64(plugin, "response_code").unwrap_or(200);
        let response = format!(
            "HTTP/1.1 {code} OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        );
        let _ = stream.write_all(response.as_bytes());
        Ok(())
    })?;
    Ok(events)
}

pub(crate) fn http_send(plugin: &Plugin, event: &Event) -> Result<(), RunError> {
    let url = arg_string(plugin, "url").ok_or_else(|| fail("http output requires url"))?;
    let method = arg_string(plugin, "http_method")
        .ok_or_else(|| fail("http output requires http_method"))?
        .to_ascii_uppercase();
    let format = arg_string(plugin, "format").unwrap_or_else(|| "json".to_string());
    let body = match format.as_str() {
        "json" => event.to_json().map_err(|error| fail(error.to_string()))?,
        "message" => {
            let template =
                arg_string(plugin, "message").unwrap_or_else(|| "%{message}".to_string());
            event
                .sprintf(&template)
                .map_err(|error| fail(error.to_string()))?
        }
        other => {
            return Err(fail(format!(
                "http output format {other} is not implemented"
            )));
        }
    };
    let (host, port, path) = split_url(&url)?;
    let content_type = arg_string(plugin, "content_type").unwrap_or_else(|| {
        if format == "json" {
            "application/json".to_string()
        } else {
            "text/plain".to_string()
        }
    });
    let mut stream =
        TcpStream::connect((host.as_str(), port)).map_err(|error| fail(error.to_string()))?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| fail(error.to_string()))?;
    let _ = stream.flush();
    let response = read_until_idle(&mut stream)?;
    let status = http_status(&response).unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(fail(format!("http output {url} returned {status}")));
    }
    Ok(())
}

pub(crate) fn beats_input(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    refuse_ssl(plugin)?;
    let port = required_port(plugin)?;
    let host = bind_host(plugin);
    let listener = bind_tcp(&host, port)?;
    let mut events = Vec::new();
    accept_until_idle(&listener, |mut stream, _peer| {
        events.extend(read_beats(&mut stream, settings)?);
        Ok(())
    })?;
    Ok(events)
}

fn bind_tcp(host: &str, port: i64) -> Result<TcpListener, RunError> {
    let listener =
        TcpListener::bind((host, port as u16)).map_err(|error| fail(error.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| fail(error.to_string()))?;
    Ok(listener)
}

fn accept_until_idle(
    listener: &TcpListener,
    mut on_stream: impl FnMut(TcpStream, SocketAddr) -> Result<(), RunError>,
) -> Result<(), RunError> {
    let started = Instant::now();
    let mut quiet_since: Option<Instant> = None;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(IDLE));
                on_stream(stream, peer)?;
                quiet_since = Some(Instant::now());
            }
            Err(error) if idle_error(&error) => {
                if quiet_since.is_some_and(|since| since.elapsed() > IDLE) {
                    break;
                }
                if quiet_since.is_none() && started.elapsed() > FIRST {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(fail(error.to_string())),
        }
    }
    Ok(())
}

fn read_until_idle(stream: &mut TcpStream) -> Result<Vec<u8>, RunError> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(IDLE));
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => bytes.extend_from_slice(&buffer[..size]),
            Err(error) if idle_error(&error) => break,
            Err(error) => return Err(fail(error.to_string())),
        }
    }
    Ok(bytes)
}

fn read_http(stream: &mut TcpStream) -> Result<Vec<u8>, RunError> {
    let mut bytes = read_until_idle(stream)?;
    if let Some(header_end) = find_header_end(&bytes) {
        let length = content_length(&bytes[..header_end]);
        while bytes.len() < header_end + 4 + length {
            let mut more = read_until_idle(stream)?;
            if more.is_empty() {
                break;
            }
            bytes.append(&mut more);
        }
    }
    Ok(bytes)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn read_beats(stream: &mut TcpStream, settings: &Settings) -> Result<Vec<Event>, RunError> {
    let mut events = Vec::new();
    let mut sequence = 0u32;
    loop {
        let mut head = [0u8; 6];
        if stream.read_exact(&mut head).is_err() {
            break;
        }
        if head[0] != b'2' {
            return Err(fail("beats frame version is not 2"));
        }
        let length = u32::from_be_bytes([head[2], head[3], head[4], head[5]]) as usize;
        let mut payload = vec![0u8; length];
        if length > 0 && stream.read_exact(&mut payload).is_err() {
            break;
        }
        match head[1] {
            b'W' => {}
            b'J' => {
                sequence = sequence.saturating_add(1);
                let text = String::from_utf8_lossy(&payload);
                let mut decoded =
                    Event::from_json(&text).map_err(|error| fail(error.to_string()))?;
                if settings.ecs != Ecs::Disabled {
                    for event in &mut decoded {
                        let _ = event.set_field("[@metadata][beat]", Value::from("filebeat"));
                    }
                }
                events.extend(decoded);
                let _ = stream.write_all(&ack_frame(sequence));
            }
            b'C' => return Err(fail("beats compressed frames are not implemented")),
            _ => {}
        }
    }
    Ok(events)
}

fn ack_frame(sequence: u32) -> [u8; 10] {
    let seq = sequence.to_be_bytes();
    [b'2', b'A', 0, 0, 0, 4, seq[0], seq[1], seq[2], seq[3]]
}

struct HttpRequest {
    content_type: Option<String>,
    authorization: Option<String>,
    headers: Vec<(String, String)>,
    body: String,
}

fn parse_http(bytes: &[u8]) -> Option<HttpRequest> {
    let text = String::from_utf8_lossy(bytes);
    let (head, body) = text.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let request = lines.next()?;
    let mut parts = request.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut content_type = None;
    let mut authorization = None;
    let mut headers = Vec::new();
    let mut length = body.len();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        if name.trim().eq_ignore_ascii_case("content-type") {
            content_type = Some(value.clone());
        }
        if name.trim().eq_ignore_ascii_case("authorization") {
            authorization = Some(value.clone());
        }
        if name.trim().eq_ignore_ascii_case("content-length") {
            length = value.parse().unwrap_or(length);
        }
        headers.push((name.trim().to_string(), value));
    }
    headers.push(("request_method".to_string(), method.clone()));
    headers.push(("request_path".to_string(), path.clone()));
    let body = body.chars().take(length).collect();
    Some(HttpRequest {
        content_type,
        authorization,
        headers,
        body,
    })
}

fn authorized(request: &HttpRequest, user: Option<&str>, password: Option<&str>) -> bool {
    let Some(user) = user else {
        return true;
    };
    let password = password.unwrap_or("");
    request.authorization.as_deref() == Some(basic_token(user, password).as_str())
}

fn basic_token(user: &str, password: &str) -> String {
    format!("Basic {}", base64(&format!("{user}:{password}")))
}

fn base64(text: &str) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn stamp_http(
    event: &mut Event,
    settings: &Settings,
    ip: &str,
    request: &HttpRequest,
) -> Result<(), RunError> {
    let host_field = if settings.ecs == Ecs::Disabled {
        "host"
    } else {
        "[host][ip]"
    };
    event
        .set_field(host_field, Value::from(ip))
        .map_err(|error| fail(error.to_string()))?;
    let header_field = if settings.ecs == Ecs::Disabled {
        "headers"
    } else {
        "[@metadata][input][http][request][headers]"
    };
    let mut map = Map::new();
    for (key, value) in &request.headers {
        map.insert(key.clone(), Value::from(value.clone()));
    }
    event
        .set_field(header_field, Value::Map(map))
        .map_err(|error| fail(error.to_string()))?;
    Ok(())
}

fn codec_for_type(plugin: &Plugin, content_type: Option<&str>) -> &'static str {
    let type_name = content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if type_name.eq_ignore_ascii_case("application/json") {
        return "json";
    }
    match codec_name(plugin) {
        Some("line") => "line",
        Some("json") => "json",
        Some("json_lines") => "json_lines",
        Some("avro") => "avro",
        Some("cef") => "cef",
        _ => "plain",
    }
}

fn events_from_bytes(
    plugin: &Plugin,
    settings: &Settings,
    bytes: &[u8],
    ip: Option<String>,
    port: Option<u16>,
    kind: &str,
) -> Result<Vec<Event>, RunError> {
    let codec = codec_name(plugin).unwrap_or(if kind == "udp" { "plain" } else { "line" });
    if codec == "cef" {
        let block =
            plugin
                .args
                .iter()
                .find(|(key, _)| key == "codec")
                .and_then(|(_, arg)| match arg {
                    Arg::Plugin(codec) => Some(codec),
                    _ => None,
                });
        let mut events = crate::cef::decode(block, bytes, settings.ecs)?;
        for event in &mut events {
            stamp_peer(event, settings, ip.as_deref(), port, kind)?;
        }
        return Ok(events);
    }
    if codec == "avro" {
        let block = plugin
            .args
            .iter()
            .find(|(key, _)| key == "codec")
            .and_then(|(_, arg)| match arg {
                Arg::Plugin(codec) => Some(codec),
                _ => None,
            })
            .ok_or_else(|| fail(crate::avro::missing_schema()))?;
        let mut events = vec![crate::avro::decode(block, bytes, settings.ecs)?];
        for event in &mut events {
            stamp_peer(event, settings, ip.as_deref(), port, kind)?;
        }
        return Ok(events);
    }
    let mut events = decode_payload(codec, bytes)?;
    for event in &mut events {
        stamp_peer(event, settings, ip.as_deref(), port, kind)?;
    }
    Ok(events)
}

fn decode_payload(codec: &str, bytes: &[u8]) -> Result<Vec<Event>, RunError> {
    let text = String::from_utf8_lossy(bytes);
    match codec {
        "json" | "json_lines" => crate::plugins::decode_events(codec, &text),
        "line" => {
            let mut events = Vec::new();
            for line in text.split('\n') {
                let line = line.trim_end_matches('\r');
                if line.is_empty() {
                    continue;
                }
                let mut event = Event::new();
                event
                    .set_field("message", Value::from(line))
                    .map_err(|error| fail(error.to_string()))?;
                events.push(event);
            }
            Ok(events)
        }
        _ => {
            let mut event = Event::new();
            event
                .set_field("message", Value::from(text.as_ref()))
                .map_err(|error| fail(error.to_string()))?;
            Ok(vec![event])
        }
    }
}

fn stamp_peer(
    event: &mut Event,
    settings: &Settings,
    ip: Option<&str>,
    port: Option<u16>,
    kind: &str,
) -> Result<(), RunError> {
    let Some(ip) = ip else {
        return Ok(());
    };
    if kind == "udp" {
        let field = if settings.ecs == Ecs::Disabled {
            "host"
        } else {
            "[host][ip]"
        };
        if event
            .get_field(field)
            .map_err(|error| fail(error.to_string()))?
            .is_none()
        {
            event
                .set_field(field, Value::from(ip))
                .map_err(|error| fail(error.to_string()))?;
        }
        return Ok(());
    }
    if settings.ecs == Ecs::Disabled {
        let _ = event.set_field("host", Value::from(ip));
        if let Some(port) = port {
            let _ = event.set_field("port", Value::Integer(i128::from(port)));
        }
        let _ = event.set_field("[@metadata][ip_address]", Value::from(ip));
    } else {
        let _ = event.set_field("[@metadata][input][tcp][source][ip]", Value::from(ip));
        let _ = event.set_field("[@metadata][input][tcp][source][name]", Value::from(ip));
        if let Some(port) = port {
            let _ = event.set_field(
                "[@metadata][input][tcp][source][port]",
                Value::Integer(i128::from(port)),
            );
        }
    }
    Ok(())
}

fn split_url(url: &str) -> Result<(String, u16, String), RunError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| fail(format!("http output url must be http:// : {url}")))?;
    let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path}");
    let (host, port) = if let Some((host, port)) = host_port.split_once(':') {
        let port = port
            .parse()
            .map_err(|_| fail(format!("http output url has a bad port: {url}")))?;
        (host.to_string(), port)
    } else {
        (host_port.to_string(), 80)
    };
    Ok((host, port, path))
}

fn http_status(bytes: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(bytes);
    let code = text.split_whitespace().nth(1)?;
    code.parse().ok()
}

fn idle_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn refuse_ssl(plugin: &Plugin) -> Result<(), RunError> {
    if arg_string(plugin, "ssl_enabled").as_deref() == Some("true") {
        return Err(fail(format!(
            "plugin {} ssl_enabled is not implemented",
            plugin.name
        )));
    }
    Ok(())
}

fn bind_host(plugin: &Plugin) -> String {
    arg_string(plugin, "host").unwrap_or_else(|| "0.0.0.0".to_string())
}

fn required_port(plugin: &Plugin) -> Result<i64, RunError> {
    arg_i64(plugin, "port").ok_or_else(|| fail(format!("{} requires port", plugin.name)))
}

fn codec_name(plugin: &Plugin) -> Option<&str> {
    match arg(plugin, "codec") {
        Some(Arg::String(name)) => Some(name),
        Some(Arg::Plugin(codec)) => Some(codec.name.as_str()),
        _ => None,
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

fn arg_usize(plugin: &Plugin, name: &str) -> Option<usize> {
    arg_i64(plugin, name).and_then(|value| usize::try_from(value).ok())
}
