//! Elasticsearch input 5.3.2 and filter 4.4.1 against a local HTTP mock.
//!
//! Elasticsearch 8 answers a point-in-time search. The filter sends `q` and
//! copies `_source` fields. A failed lookup tags the event and the pipeline
//! still exits 0.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rstash::{Ecs, Settings, Value, run};

struct Hit {
    method: String,
    path: String,
    headers: String,
    body: String,
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
        api_port: None,
    }
}

fn serve<F>(answer: F) -> (u16, Arc<Mutex<Vec<Hit>>>, Arc<AtomicBool>)
where
    F: Fn(&Hit, usize) -> (u16, String) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let hits = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let stored = hits.clone();
    let stopping = stop.clone();
    let searches = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        while !stopping.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let hit = read_hit(&mut stream);
                    let search = if hit.path.starts_with("/_search") {
                        searches.fetch_add(1, Ordering::Relaxed)
                    } else {
                        0
                    };
                    let (status, body) = answer(&hit, search);
                    stored.lock().expect("hits").push(hit);
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nX-Elastic-Product: Elasticsearch\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (port, hits, stop)
}

fn read_hit(stream: &mut std::net::TcpStream) -> Hit {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
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
                    body: String::new(),
                });
            }
            Ok(size) => buf.extend_from_slice(&tmp[..size]),
        }
    }
}

fn parse_hit(buf: &[u8]) -> Option<Hit> {
    let split = buf.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..split]).ok()?.to_string();
    let mut lines = head.lines();
    let request = lines.next()?;
    let mut parts = request.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut length = 0usize;
    for line in head.lines() {
        if let Some((_, value)) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        {
            length = value.trim().parse().ok()?;
        }
    }
    let body = &buf[split + 4..];
    if body.len() < length {
        return None;
    }
    Some(Hit {
        method,
        path,
        headers: head,
        body: String::from_utf8_lossy(&body[..length]).to_string(),
    })
}

#[test]
fn input_reads_a_point_in_time_page() {
    let (port, hits, stop) = serve(|hit, search| {
        if hit.method == "GET" {
            (
                200,
                r#"{"version":{"number":"8.15.0","build_flavor":"default"},"tagline":"You Know, for Search"}"#
                    .to_string(),
            )
        } else if hit.path.contains("/_pit") {
            (200, r#"{"id":"pit-1"}"#.to_string())
        } else if hit.path.starts_with("/_search") && search == 0 {
            (
                200,
                r#"{"hits":{"hits":[{"_index":"logs","_id":"abc","_source":{"message":"hello"},"sort":[1]}]}}"#
                    .to_string(),
            )
        } else if hit.method == "DELETE" {
            (200, "{}".to_string())
        } else {
            (200, r#"{"hits":{"hits":[]}}"#.to_string())
        }
    });
    let config = format!(
        r#"
        input {{
          elasticsearch {{
            hosts => "127.0.0.1:{port}"
            index => "logs"
            size => 2
            docinfo => true
          }}
        }}
        output {{ stdout {{ codec => rubydebug }} }}
        "#
    );
    let result = run(&config, &settings(Ecs::Disabled)).expect("input");
    stop.store(true, Ordering::Relaxed);
    assert_eq!(result.events.len(), 1);
    assert_eq!(
        result.events[0].get_field("message").unwrap(),
        Some(Value::from("hello"))
    );
    assert_eq!(
        result.events[0].get_field("[@metadata][_id]").unwrap(),
        Some(Value::from("abc"))
    );
    let hits = hits.lock().expect("hits");
    let calls: Vec<_> = hits
        .iter()
        .map(|hit| format!("{} {}", hit.method, hit.path))
        .collect();
    assert!(
        calls
            .iter()
            .any(|call| call == "POST /logs/_pit?keep_alive=1m"),
        "{calls:?}"
    );
    let search = hits
        .iter()
        .find(|hit| hit.path.starts_with("/_search"))
        .expect("search");
    assert!(search.body.contains("\"pit\""));
    assert!(search.body.contains("_doc"));
    assert!(
        search
            .headers
            .to_ascii_lowercase()
            .contains("x-elastic-product-origin")
    );
}

#[test]
fn filter_copies_the_query_string_hit() {
    let (port, hits, stop) = serve(|hit, _search| {
        if hit.method == "GET" && hit.path == "/" {
            (
                200,
                r#"{"version":{"number":"8.15.0","build_flavor":"default"},"tagline":"You Know, for Search"}"#
                    .to_string(),
            )
        } else {
            (
                200,
                r#"{"_shards":{},"hits":{"total":{"value":1,"relation":"eq"},"hits":[{"_id":"1","_source":{"message":"hello"}}]}}"#
                    .to_string(),
            )
        }
    });
    let config = format!(
        r#"
        input {{ generator {{ count => 1 message => "seed" }} }}
        filter {{
          elasticsearch {{
            hosts => "127.0.0.1:{port}"
            index => "logs"
            query => "message:hello"
            fields => {{ "message" => "found" }}
            enable_sort => false
          }}
        }}
        output {{ stdout {{ codec => rubydebug }} }}
        "#
    );
    let result = run(&config, &settings(Ecs::V8)).expect("filter");
    stop.store(true, Ordering::Relaxed);
    assert_eq!(
        result.events[0].get_field("found").unwrap(),
        Some(Value::from("hello"))
    );
    assert_eq!(
        result.events[0]
            .get_field("[@metadata][total_hits]")
            .unwrap(),
        Some(Value::Integer(1))
    );
    let hits = hits.lock().expect("hits");
    let search = hits
        .iter()
        .find(|hit| hit.path.contains("_search"))
        .expect("search");
    assert_eq!(search.method, "GET");
    assert!(search.path.contains("q=message%3Ahello"), "{}", search.path);
    assert!(search.path.contains("size=1"), "{}", search.path);
    assert!(!search.path.contains("sort="), "{}", search.path);
}

#[test]
fn filter_tags_a_failed_lookup_and_keeps_the_event() {
    let (port, _hits, stop) = serve(|hit, _search| {
        if hit.path == "/" {
            (
                200,
                r#"{"version":{"number":"8.15.0","build_flavor":"default"},"tagline":"You Know, for Search"}"#
                    .to_string(),
            )
        } else {
            (500, "no".to_string())
        }
    });
    let config = format!(
        r#"
        input {{ generator {{ count => 1 message => "seed" }} }}
        filter {{
          elasticsearch {{
            hosts => "127.0.0.1:{port}"
            index => "logs"
            query => "message:hello"
          }}
        }}
        output {{ stdout {{ codec => rubydebug }} }}
        "#
    );
    let result = run(&config, &settings(Ecs::V8)).expect("tagged");
    stop.store(true, Ordering::Relaxed);
    let tags = result.events[0].get_field("tags").unwrap().unwrap();
    assert_eq!(
        tags,
        Value::Array(vec![Value::from("_elasticsearch_lookup_failure")])
    );
}

#[test]
fn filter_requires_a_query() {
    let error = run(
        r#"
        input { generator { count => 1 } }
        filter { elasticsearch { hosts => "127.0.0.1:9" } }
        output { stdout { codec => rubydebug } }
        "#,
        &settings(Ecs::V8),
    )
    .expect_err("missing query");
    assert!(error.to_string().contains("query"));
}
