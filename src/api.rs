//! Monitoring HTTP API from Logstash 9.5.2.
//!
//! The server listens only when `api.http.port` is set, and it stops when the
//! pipeline returns. Official Logstash listens on `9600-9700` for the life of
//! the process. JVM memory, GC, and hot-thread stacks are omitted: this
//! process has no JVM, and those numbers are not invented.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value as Json, json};

use crate::run::{RunError, Settings, fail, hostname};

const VERSION: &str = "9.5.2";
const BUILD_DATE: &str = "2026-08-17T18:16:06+00:00";
const BUILD_SHA: &str = "81753940099b4c9df5dba0da3fe6adb2f190a880";

pub(crate) struct Live {
    pub host: String,
    pub id: String,
    pub ephemeral_id: String,
    pub workers: usize,
    pub batch_size: usize,
    pub batch_delay_ms: u64,
    pub pipeline_id: String,
    pub persisted: bool,
    pub events_in: AtomicU64,
    pub events_filtered: AtomicU64,
    pub events_out: AtomicU64,
    pub bound_port: AtomicU16,
}

impl Live {
    pub(crate) fn from_settings(settings: &Settings) -> Self {
        Self {
            host: hostname(),
            id: String::new(),
            ephemeral_id: format!("{:032x}", nanos()),
            workers: settings.workers,
            batch_size: settings.batch_size,
            batch_delay_ms: settings.batch_delay.as_millis() as u64,
            pipeline_id: settings.pipeline_id.clone(),
            persisted: settings.persisted_queue,
            events_in: AtomicU64::new(0),
            events_filtered: AtomicU64::new(0),
            events_out: AtomicU64::new(0),
            bound_port: AtomicU16::new(0),
        }
    }
}

pub(crate) struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn serve(port: u16, live: Arc<Live>) -> Result<Server, RunError> {
    let listener =
        TcpListener::bind(("127.0.0.1", port)).map_err(|error| fail(error.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| fail(error.to_string()))?;
    live.bound_port.store(
        listener
            .local_addr()
            .map_err(|error| fail(error.to_string()))?
            .port(),
        Ordering::SeqCst,
    );
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let thread = thread::spawn(move || accept_loop(listener, live, flag));
    Ok(Server {
        stop,
        thread: Some(thread),
    })
}

fn accept_loop(listener: TcpListener, live: Arc<Live>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = answer(stream, &live);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn answer(mut stream: TcpStream, live: &Live) -> Result<(), RunError> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buffer = [0u8; 4096];
    let size = stream
        .read(&mut buffer)
        .map_err(|error| fail(error.to_string()))?;
    let text = String::from_utf8_lossy(&buffer[..size]);
    let path = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let path = path.split('?').next().unwrap_or("/");
    let (status, body) = match document(path, live) {
        Some(body) => (200, body),
        None => (404, json!({"path": path, "status": 404}).to_string()),
    };
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .map_err(|error| fail(error.to_string()))?;
    stream
        .write_all(body.as_bytes())
        .map_err(|error| fail(error.to_string()))?;
    Ok(())
}

pub(crate) fn document(path: &str, live: &Live) -> Option<String> {
    let meta = metadata(live);
    let body = match path {
        "/" => json!({
            "build_date": BUILD_DATE,
            "build_sha": BUILD_SHA,
            "build_snapshot": false,
        }),
        "/_node" => json!({
            "os": os_payload(),
            "pipelines": pipelines(live),
        }),
        "/_node/stats" | "/_node/stats/" => stats(live),
        "/_node/hot_threads" => json!({
            "hot_threads": {
                "hostname": live.host,
                "threads": [],
            }
        }),
        "/_health_report" => json!({
            "status": "green",
        }),
        other if other.starts_with("/_node/stats/pipelines/") => {
            let id = other.trim_start_matches("/_node/stats/pipelines/");
            if id != live.pipeline_id {
                return None;
            }
            json!({"pipelines": {id: pipeline_stats(live)}})
        }
        "/_node/stats/pipelines" => {
            json!({"pipelines": {live.pipeline_id.clone(): pipeline_stats(live)}})
        }
        _ => return None,
    };
    Some(merge(meta, body).to_string())
}

fn stats(live: &Live) -> Json {
    json!({
        "events": events(live),
        "pipelines": { live.pipeline_id.clone(): pipeline_stats(live) },
        "reloads": {"successes": 0, "failures": 0},
        "os": {},
        "queue": {"events_count": 0},
        "process": {},
    })
}

fn pipeline_stats(live: &Live) -> Json {
    json!({
        "events": events(live),
        "queue": {"type": if live.persisted { "persisted" } else { "memory" }},
    })
}

fn pipelines(live: &Live) -> Json {
    json!({
        live.pipeline_id.clone(): {
            "workers": live.workers,
            "batch_size": live.batch_size,
            "batch_delay": live.batch_delay_ms,
        }
    })
}

fn events(live: &Live) -> Json {
    json!({
        "in": live.events_in.load(Ordering::Relaxed),
        "filtered": live.events_filtered.load(Ordering::Relaxed),
        "out": live.events_out.load(Ordering::Relaxed),
        "duration_in_millis": 0,
        "queue_push_duration_in_millis": 0,
    })
}

fn metadata(live: &Live) -> Json {
    let port = live.bound_port.load(Ordering::Relaxed);
    json!({
        "host": live.host,
        "version": VERSION,
        "http_address": format!("127.0.0.1:{port}"),
        "id": live.id,
        "name": live.host,
        "ephemeral_id": live.ephemeral_id,
        "snapshot": false,
        "status": "green",
        "pipeline": {
            "workers": live.workers,
            "batch_size": live.batch_size,
            "batch_delay": live.batch_delay_ms,
        }
    })
}

fn os_payload() -> Json {
    json!({
        "name": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "available_processors": std::thread::available_parallelism().map(|count| count.get()).unwrap_or(1),
    })
}

fn merge(mut meta: Json, body: Json) -> Json {
    if let (Some(meta), Some(body)) = (meta.as_object_mut(), body.as_object()) {
        for (key, value) in body {
            meta.insert(key.clone(), value.clone());
        }
    }
    meta
}

pub(crate) fn node_id(path_data: Option<&str>) -> String {
    let Some(dir) = path_data else {
        return format!("{:032x}", nanos());
    };
    let path = std::path::Path::new(dir).join("uuid");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let text = text.trim();
        if !text.is_empty() {
            return text.to_string();
        }
    }
    let id = format!("{:032x}", nanos());
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(path, &id);
    id
}

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
