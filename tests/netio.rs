//! TCP, UDP, HTTP, and Beats against a real socket.
//!
//! Expected bytes come from the 9.5.2 gems: a line codec keeps the line, UDP
//! writes the peer address into `host` when ECS is off, HTTP JSON uses the
//! `application/json` codec, and Beats v2 answers a JSON frame with an ack.

use rstash::{Ecs, Event, Settings, Value, run};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn settings() -> Settings {
    Settings {
        workers: 1,
        batch_size: 125,
        batch_delay: Duration::from_millis(50),
        ecs: Ecs::Disabled,
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

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

fn message(event: &Event) -> String {
    match event.get_field("message").expect("field") {
        Some(Value::String(text)) => text,
        other => panic!("message was {other:?}"),
    }
}

fn udp_input_with_a_free_port() -> rstash::RunResult {
    let reserved = UdpSocket::bind("127.0.0.1:0").expect("udp bind");
    let port = reserved.local_addr().expect("udp port").port();
    drop(reserved);
    thread::spawn(move || {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("udp sender");
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            let _ = socket.send_to(b"hello", ("127.0.0.1", port));
            thread::sleep(Duration::from_millis(30));
        }
    });
    run(
        &format!(
            r#"input {{ udp {{ host => "127.0.0.1" port => {port} codec => plain }} }} output {{ stdout {{ codec => plain }} }}"#
        ),
        &settings(),
    )
    .unwrap_or_else(|error| panic!("{error}"))
}

fn connect_retry(port: u16) -> TcpStream {
    let started = Instant::now();
    loop {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            return stream;
        }
        if started.elapsed() > Duration::from_secs(3) {
            panic!("connect to {port}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn tcp_server_reads_a_line_and_records_the_peer() {
    let port = free_port();
    thread::spawn(move || {
        let mut stream = connect_retry(port);
        stream.write_all(b"hello\n").unwrap();
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    let ran = run(
        &format!(
            r#"input {{ tcp {{ host => "127.0.0.1" port => {port} codec => line }} }} output {{ stdout {{ codec => plain }} }}"#
        ),
        &settings(),
    )
    .unwrap();
    assert_eq!(ran.events.len(), 1);
    assert_eq!(message(&ran.events[0]), "hello");
    assert_eq!(
        ran.events[0].get_field("host").unwrap(),
        Some(Value::from("127.0.0.1"))
    );
    assert!(ran.stdout.contains("127.0.0.1 hello"), "{}", ran.stdout);
}

#[test]
fn tcp_client_output_writes_the_codec_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        run(
            &format!(
                r#"input {{ generator {{ count => 1 message => "ping" }} }} output {{ tcp {{ host => "127.0.0.1" port => {port} codec => line }} }}"#
            ),
            &settings(),
        )
        .unwrap();
    });
    let (mut stream, _) = listener.accept().unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 256];
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => bytes.extend_from_slice(&buffer[..size]),
            Err(_) => {
                if bytes.ends_with(b" ping\n") {
                    break;
                }
            }
        }
    }
    handle.join().unwrap();
    assert!(
        bytes.ends_with(b" ping\n"),
        "{}",
        String::from_utf8_lossy(&bytes)
    );
}

#[test]
fn udp_input_sets_host_and_output_sends_the_payload() {
    let ran = udp_input_with_a_free_port();
    assert!(!ran.events.is_empty());
    assert_eq!(message(&ran.events[0]), "hello");
    assert_eq!(
        ran.events[0].get_field("host").unwrap(),
        Some(Value::from("127.0.0.1"))
    );

    let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
    let out_port = listener.local_addr().unwrap().port();
    listener
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    run(
        &format!(
            r#"input {{ generator {{ count => 1 message => "pong" }} }} output {{ udp {{ host => "127.0.0.1" port => "{out_port}" codec => line }} }}"#
        ),
        &settings(),
    )
    .unwrap();
    let mut buffer = [0u8; 64];
    let (size, _) = listener.recv_from(&mut buffer).unwrap();
    assert!(
        buffer[..size].ends_with(b" pong\n"),
        "{}",
        String::from_utf8_lossy(&buffer[..size])
    );
}

#[test]
fn http_post_json_and_basic_auth() {
    let port = free_port();
    thread::spawn(move || {
        let mut stream = connect_retry(port);
        let body = r#"{"message":"posted"}"#;
        let request = format!(
            "POST /ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).unwrap();
        let _ = stream.flush();
        let mut response = [0u8; 128];
        let _ = stream.read(&mut response);
    });
    let ran = run(
        &format!(
            r#"input {{ http {{ host => "127.0.0.1" port => {port} }} }} output {{ stdout {{ codec => plain }} }}"#
        ),
        &settings(),
    )
    .unwrap();
    assert_eq!(ran.events.len(), 1);
    assert_eq!(message(&ran.events[0]), "posted");
    assert_eq!(
        ran.events[0].get_field("host").unwrap(),
        Some(Value::from("127.0.0.1"))
    );

    let port = free_port();
    thread::spawn(move || {
        let mut stream = connect_retry(port);
        stream
            .write_all(b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let mut response = [0u8; 128];
        let size = stream.read(&mut response).unwrap_or(0);
        let text = String::from_utf8_lossy(&response[..size]);
        assert!(text.starts_with("HTTP/1.1 401"), "{text}");
    });
    let ran = run(
        &format!(
            r#"input {{ http {{ host => "127.0.0.1" port => {port} user => "me" password => "secret" }} }} output {{ stdout {{ codec => plain }} }}"#
        ),
        &settings(),
    )
    .unwrap();
    assert!(ran.events.is_empty());
}

#[test]
fn http_output_posts_the_message_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let got = Arc::new(Mutex::new(String::new()));
    let slot = Arc::clone(&got);
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => {
                    bytes.extend_from_slice(&buffer[..size]);
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        *slot.lock().unwrap() = String::from_utf8_lossy(&bytes).into_owned();
    });
    run(
        &format!(
            r#"input {{ generator {{ count => 1 message => "out" }} }} output {{ http {{ url => "http://127.0.0.1:{port}/hook" http_method => post format => message message => "out" }} }}"#
        ),
        &settings(),
    )
    .unwrap();
    let text = got.lock().unwrap().clone();
    assert!(text.starts_with("POST /hook HTTP/1.1"), "{text}");
    assert!(text.contains("\r\n\r\nout"), "{text}");
}

#[test]
fn beats_json_frame_is_acked() {
    let port = free_port();
    thread::spawn(move || {
        let mut stream = connect_retry(port);
        let payload = br#"{"message":"beat"}"#;
        let mut frame = vec![b'2', b'W', 0, 0, 0, 4, 0, 0, 0, 1, b'2', b'J'];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        stream.write_all(&frame).unwrap();
        let _ = stream.flush();
        let mut ack = [0u8; 10];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(ack[0], b'2');
        assert_eq!(ack[1], b'A');
        assert_eq!(&ack[6..], &1u32.to_be_bytes());
    });
    let ran = run(
        &format!(
            r#"input {{ beats {{ host => "127.0.0.1" port => {port} }} }} output {{ stdout {{ codec => plain }} }}"#
        ),
        &settings(),
    )
    .unwrap();
    assert_eq!(ran.events.len(), 1);
    assert_eq!(message(&ran.events[0]), "beat");
}

#[test]
fn ssl_and_a_missing_port_fail() {
    let error = run(
        r#"input { tcp { host => "127.0.0.1" port => 1 ssl_enabled => true } } output { stdout { } }"#,
        &settings(),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("ssl_enabled is not implemented"),
        "{error}"
    );
    let error = run(
        r#"input { udp { host => "127.0.0.1" } } output { stdout { } }"#,
        &settings(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("udp requires port"), "{error}");
}
