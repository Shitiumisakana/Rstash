//! Kafka output 12.1.5 over a plaintext Metadata v4 and Produce v3 broker.
//!
//! The mock is the leader for every topic. The record value is the plain
//! codec payload.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rstash::{Ecs, Settings, run};

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
        api_port: None,
    }
}

fn broker(port_slot: Arc<Mutex<u16>>, seen: Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    *port_slot.lock().expect("port") = port;
    for _ in 0..2 {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut size = [0u8; 4];
        stream.read_exact(&mut size).expect("size");
        let length = i32::from_be_bytes(size) as usize;
        let mut request = vec![0u8; length];
        stream.read_exact(&mut request).expect("body");
        seen.lock().expect("seen").push(request.clone());
        let api = i16::from_be_bytes([request[0], request[1]]);
        let correlation = i32::from_be_bytes([request[8], request[9], request[10], request[11]]);
        let response = if api == 3 {
            metadata_response(correlation, port)
        } else {
            produce_response(correlation)
        };
        let mut framed = Vec::new();
        framed.extend_from_slice(&(response.len() as i32).to_be_bytes());
        framed.extend_from_slice(&response);
        stream.write_all(&framed).expect("write");
    }
}

fn string(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(value.len() as i16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out
}

fn metadata_response(correlation: i32, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&correlation.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend(string("127.0.0.1"));
    out.extend_from_slice(&(i32::from(port)).to_be_bytes());
    out.extend_from_slice(&(-1i16).to_be_bytes());
    out.extend_from_slice(&(-1i16).to_be_bytes());
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend_from_slice(&0i16.to_be_bytes());
    out.extend(string("logs"));
    out.push(0);
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend_from_slice(&0i16.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out
}

fn produce_response(correlation: i32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&correlation.to_be_bytes());
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend(string("logs"));
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&0i16.to_be_bytes());
    out.extend_from_slice(&0i64.to_be_bytes());
    out.extend_from_slice(&(-1i64).to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes());
    out
}

#[test]
fn plaintext_produce_sends_the_message() {
    let port = Arc::new(Mutex::new(0u16));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port_slot = port.clone();
    let seen_slot = seen.clone();
    thread::spawn(move || broker(port_slot, seen_slot));
    let bound = loop {
        let value = *port.lock().expect("port");
        if value != 0 {
            break value;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let config = format!(
        r#"
        input {{ generator {{ count => 1 message => "hello-kafka" }} }}
        output {{
          kafka {{
            bootstrap_servers => "127.0.0.1:{bound}"
            topic_id => "logs"
            codec => plain {{ format => "%{{message}}" }}
          }}
        }}
        "#
    );
    run(&config, &settings()).expect("produce");
    let seen = seen.lock().expect("seen");
    assert_eq!(seen.len(), 2);
    let produce = &seen[1];
    let text = String::from_utf8_lossy(produce);
    assert!(text.contains("hello-kafka"), "{text}");
    assert_eq!(i16::from_be_bytes([produce[0], produce[1]]), 0);
    assert_eq!(i16::from_be_bytes([produce[2], produce[3]]), 3);
}

#[test]
fn sasl_is_rejected() {
    let error = run(
        r#"
        input { generator { count => 1 } }
        output { kafka { topic_id => "logs" security_protocol => "SASL_SSL" } }
        "#,
        &settings(),
    )
    .expect_err("sasl");
    assert!(error.to_string().contains("SASL_SSL"));
}
