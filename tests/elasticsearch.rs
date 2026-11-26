//! Elasticsearch output 12.1.6 over HTTP.
//!
//! The mock answers the same calls the 9.5.2 plugin makes: cluster version,
//! index template, rollover alias, ILM policy, then `_bulk`. Nil `_id` and
//! `routing` stay in the action line because JrJackson writes them.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rstash::{Ecs, Settings, run};

struct Hit {
    method: String,
    path: String,
    headers: String,
    body: Vec<u8>,
}

fn settings(ecs: Ecs) -> Settings {
    Settings {
        workers: 1,
        batch_size: 125,
        batch_delay: Duration::from_millis(50),
        ecs,
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
    }
}

fn serve(hits: Arc<Mutex<Vec<Hit>>>, stop: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let hit = read_hit(&mut stream);
                    let (status, body) = answer(&hit.method, &hit.path);
                    hits.lock().expect("hits").push(Hit {
                        method: hit.method.clone(),
                        path: hit.path.clone(),
                        headers: hit.headers.clone(),
                        body: hit.body.clone(),
                    });
                    let response = if hit.method == "HEAD" {
                        format!(
                            "HTTP/1.1 {status} X\r\nX-Elastic-Product: Elasticsearch\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    } else {
                        format!(
                            "HTTP/1.1 {status} X\r\nX-Elastic-Product: Elasticsearch\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    };
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    port
}

fn answer(method: &str, path: &str) -> (u16, String) {
    if method == "GET" && (path == "/" || path.ends_with("/")) && !path.contains("_ilm") {
        (
            200,
            r#"{"version":{"number":"8.15.0","build_flavor":"default"},"tagline":"You Know, for Search"}"#
                .to_string(),
        )
    } else if method == "HEAD" || (method == "GET" && path.contains("_ilm")) {
        (404, String::new())
    } else if method == "PUT" {
        (200, "{}".to_string())
    } else if method == "POST" {
        (
            201,
            r#"{"errors":false,"items":[{"create":{"status":201}}]}"#.to_string(),
        )
    } else {
        (500, "unexpected".to_string())
    }
}

fn read_hit(stream: &mut std::net::TcpStream) -> Hit {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        if let Some(hit) = parse_hit(&buf) {
            return hit;
        }
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => {
                return parse_hit(&buf).unwrap_or(Hit {
                    method: String::new(),
                    path: String::new(),
                    headers: String::new(),
                    body: Vec::new(),
                });
            }
            Ok(size) => buf.extend_from_slice(&tmp[..size]),
        }
    }
}

fn parse_hit(buf: &[u8]) -> Option<Hit> {
    let split = buf.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..split]).ok()?;
    let mut lines = head.lines();
    let request = lines.next()?;
    let mut parts = request.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut length = 0usize;
    for line in lines {
        if let Some(value) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim())
        {
            length = value.parse().ok()?;
        }
    }
    let body = &buf[split + 4..];
    if body.len() < length {
        return None;
    }
    Some(Hit {
        method,
        path,
        headers: head.to_string(),
        body: body[..length].to_vec(),
    })
}

#[test]
fn data_stream_bulk_uses_create_and_nil_metadata() {
    let stop = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(Mutex::new(Vec::new()));
    let port = serve(hits.clone(), stop.clone());
    let config = format!(
        r#"
        input {{ generator {{ count => 1 message => "hello" }} }}
        output {{ elasticsearch {{ hosts => "127.0.0.1:{port}" compression_level => 0 }} }}
        "#
    );
    let result = run(&config, &settings(Ecs::V8)).expect("data stream");
    stop.store(true, Ordering::Relaxed);
    assert_eq!(result.events.len(), 1);
    let hits = hits.lock().expect("hits");
    let paths: Vec<_> = hits.iter().map(|hit| hit.path.as_str()).collect();
    assert_eq!(paths, ["/", "/_bulk"]);
    let body = String::from_utf8(hits[1].body.clone()).expect("utf8");
    let mut lines = body.lines();
    assert_eq!(
        lines.next().expect("action"),
        r#"{"create":{"_id":null,"_index":"logs-generic-default","routing":null}}"#
    );
    let document = lines.next().expect("document");
    assert!(document.contains(r#""message":"hello""#), "{document}");
    assert!(
        document
            .contains(r#""data_stream":{"dataset":"generic","namespace":"default","type":"logs"}"#),
        "{document}"
    );
    assert!(hits[1].headers.contains("X-Elastic-Event-Count: 1"));
    assert!(
        !hits[1]
            .headers
            .to_ascii_lowercase()
            .contains("content-encoding")
    );
}

#[test]
fn default_bulk_is_gzip() {
    let stop = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(Mutex::new(Vec::new()));
    let port = serve(hits.clone(), stop.clone());
    let config = format!(
        r#"
        input {{ generator {{ count => 1 message => "hello" }} }}
        output {{ elasticsearch {{ hosts => "127.0.0.1:{port}" }} }}
        "#
    );
    run(&config, &settings(Ecs::V8)).expect("gzip");
    stop.store(true, Ordering::Relaxed);
    let hits = hits.lock().expect("hits");
    let bulk = hits.iter().find(|hit| hit.path == "/_bulk").expect("bulk");
    assert!(
        bulk.headers
            .to_ascii_lowercase()
            .contains("content-encoding: gzip")
    );
    assert_eq!(&bulk.body[..2], &[0x1f, 0x8b]);
}

#[test]
fn disabled_ecs_installs_ilm_and_indexes_the_alias() {
    let stop = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(Mutex::new(Vec::new()));
    let port = serve(hits.clone(), stop.clone());
    let config = format!(
        r#"
        input {{ generator {{ count => 1 message => "hello" }} }}
        output {{ elasticsearch {{ hosts => "127.0.0.1:{port}" compression_level => 0 }} }}
        "#
    );
    run(&config, &settings(Ecs::Disabled)).expect("ilm");
    stop.store(true, Ordering::Relaxed);
    let hits = hits.lock().expect("hits");
    let calls: Vec<_> = hits
        .iter()
        .map(|hit| format!("{} {}", hit.method, hit.path))
        .collect();
    assert_eq!(
        calls,
        vec![
            "GET /".to_string(),
            "HEAD /_index_template/logstash".to_string(),
            "PUT /_index_template/logstash".to_string(),
            "HEAD /logstash".to_string(),
            "PUT /%3Clogstash-%7Bnow%2Fd%7D-000001%3E".to_string(),
            "GET /_ilm/policy/logstash-policy".to_string(),
            "PUT /_ilm/policy/logstash-policy".to_string(),
            "POST /_bulk".to_string(),
        ]
    );
    let template = String::from_utf8(hits[2].body.clone()).expect("template");
    assert!(template.contains("logstash-*"), "{template}");
    assert!(template.contains("index.lifecycle.name"), "{template}");
    assert!(template.contains("logstash-policy"), "{template}");
    let policy = String::from_utf8(hits[6].body.clone()).expect("policy");
    assert!(policy.contains("50gb"), "{policy}");
    let bulk = String::from_utf8(hits[7].body.clone()).expect("bulk");
    assert!(
        bulk.starts_with(r#"{"index":{"_id":null,"_index":"logstash","routing":null}}"#),
        "{bulk}"
    );
}

#[test]
fn https_and_sniffing_and_unknown_options_fail() {
    let https = run(
        r#"input { generator { count => 1 } } output { elasticsearch { hosts => "https://127.0.0.1:9" } }"#,
        &settings(Ecs::V8),
    );
    assert!(
        https
            .expect_err("https")
            .to_string()
            .contains("ssl_enabled is not implemented")
    );
    let sniffing = run(
        r#"input { generator { count => 1 } } output { elasticsearch { hosts => "127.0.0.1:9" sniffing => true } }"#,
        &settings(Ecs::V8),
    );
    assert!(
        sniffing
            .expect_err("sniffing")
            .to_string()
            .contains("sniffing is not implemented")
    );
    let custom = run(
        r#"input { generator { count => 1 } } output { elasticsearch { document_type => "logs" } }"#,
        &settings(Ecs::V8),
    );
    assert!(
        custom
            .expect_err("document_type")
            .to_string()
            .contains("option document_type is not implemented")
    );
}
