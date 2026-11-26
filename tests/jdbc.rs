//! JDBC input 5.6.4 against a PostgreSQL 3.0 simple-query mock.
//!
//! The mock accepts trust authentication and returns one text column.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rstash::{Ecs, Settings, Value, run};

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

fn mock(port_slot: Arc<Mutex<u16>>, seen: Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    *port_slot.lock().expect("port") = listener.local_addr().expect("addr").port();
    let (mut stream, _) = listener.accept().expect("accept");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let mut size = [0u8; 4];
    stream.read_exact(&mut size).expect("startup size");
    let length = i32::from_be_bytes(size);
    let mut startup = vec![0u8; (length - 4) as usize];
    stream.read_exact(&mut startup).expect("startup");
    stream.write_all(&auth_ok()).expect("auth");
    stream.write_all(&ready()).expect("ready");
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).expect("query header");
    let query_length = i32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let mut query = vec![0u8; (query_length - 4) as usize];
    stream.read_exact(&mut query).expect("query");
    seen.lock().expect("seen").push(query);
    stream
        .write_all(&row_description("message", 25))
        .expect("description");
    stream.write_all(&data_row("hello")).expect("row");
    stream.write_all(&command_complete()).expect("complete");
    stream.write_all(&ready()).expect("ready");
}

fn auth_ok() -> Vec<u8> {
    let mut message = vec![b'R'];
    message.extend_from_slice(&8i32.to_be_bytes());
    message.extend_from_slice(&0i32.to_be_bytes());
    message
}

fn ready() -> Vec<u8> {
    let mut message = vec![b'Z'];
    message.extend_from_slice(&5i32.to_be_bytes());
    message.push(b'I');
    message
}

fn row_description(name: &str, oid: i32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&0i32.to_be_bytes());
    payload.extend_from_slice(&0i16.to_be_bytes());
    payload.extend_from_slice(&oid.to_be_bytes());
    payload.extend_from_slice(&(-1i16).to_be_bytes());
    payload.extend_from_slice(&(-1i32).to_be_bytes());
    payload.extend_from_slice(&0i16.to_be_bytes());
    let mut message = vec![b'T'];
    message.extend_from_slice(&((payload.len() + 4) as i32).to_be_bytes());
    message.extend(payload);
    message
}

fn data_row(value: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&(value.len() as i32).to_be_bytes());
    payload.extend_from_slice(value.as_bytes());
    let mut message = vec![b'D'];
    message.extend_from_slice(&((payload.len() + 4) as i32).to_be_bytes());
    message.extend(payload);
    message
}

fn command_complete() -> Vec<u8> {
    let text = b"SELECT 1\0";
    let mut message = vec![b'C'];
    message.extend_from_slice(&((text.len() + 4) as i32).to_be_bytes());
    message.extend_from_slice(text);
    message
}

#[test]
fn postgres_simple_query_returns_the_row() {
    let port = Arc::new(Mutex::new(0u16));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port_slot = port.clone();
    let seen_slot = seen.clone();
    thread::spawn(move || mock(port_slot, seen_slot));
    let bound = loop {
        let value = *port.lock().expect("port");
        if value != 0 {
            break value;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let config = format!(
        r#"
        input {{
          jdbc {{
            jdbc_driver_class => "org.postgresql.Driver"
            jdbc_connection_string => "jdbc:postgresql://127.0.0.1:{bound}/app"
            jdbc_user => "logstash"
            statement => "SELECT message FROM notes WHERE id = :id AND kind::text = 'x'"
            parameters => {{ "id" => 7 }}
            record_last_run => false
          }}
        }}
        output {{ null {{}} }}
        "#
    );
    let result = run(&config, &settings()).expect("jdbc");
    assert_eq!(result.events.len(), 1);
    assert_eq!(
        result.events[0].get_field("message").expect("field"),
        Some(Value::from("hello"))
    );
    let query = String::from_utf8(seen.lock().expect("seen")[0].clone()).expect("utf8");
    assert!(
        query.contains("id = 7") && query.contains("kind::text"),
        "{query}"
    );
}

#[test]
fn other_drivers_and_two_schedules_are_rejected() {
    let missing = run(
        r#"
        input { jdbc { jdbc_connection_string => "jdbc:mysql://127.0.0.1/app" jdbc_user => "a" statement => "select 1" } }
        output { null {} }
        "#,
        &settings(),
    )
    .expect_err("driver class");
    assert!(missing.to_string().contains("jdbc_driver_class"));
    let mysql = run(
        r#"
        input {
          jdbc {
            jdbc_driver_class => "com.mysql.jdbc.Driver"
            jdbc_connection_string => "jdbc:mysql://127.0.0.1/app"
            jdbc_user => "a"
            statement => "select 1"
          }
        }
        output { null {} }
        "#,
        &settings(),
    )
    .expect_err("mysql");
    assert!(
        mysql
            .to_string()
            .contains("jdbc driver mysql is not implemented")
    );
    let both = run(
        r#"
        input {
          jdbc {
            jdbc_driver_class => "org.postgresql.Driver"
            jdbc_connection_string => "jdbc:postgresql://127.0.0.1/app"
            jdbc_user => "a"
            statement => "select 1"
            schedule => "* * * * *"
            interval => "1m"
          }
        }
        output { null {} }
        "#,
        &settings(),
    )
    .expect_err("both");
    assert!(
        both.to_string()
            .contains("Use only one of: interval, period, schedule.")
    );
}
