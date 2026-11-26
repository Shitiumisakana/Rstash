//! `logstash-codec-avro` 3.5.0 encodes one datum, not an Avro container file.
//!
//! The bytes for the string `hello` are the Avro binary encoding: a zigzag
//! length of 5, then the UTF-8 bytes. Strict Base64 of that datum is
//! `CmhlbGxv`.

use rstash::{Ecs, Settings, Value, cli::execute, run};
use std::time::Duration;

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

fn schema_path() -> String {
    let dir = std::env::temp_dir().join("rstash-avro-hello");
    std::fs::create_dir_all(&dir).expect("dir");
    let schema = dir.join("event.avsc");
    std::fs::write(
        &schema,
        r#"{"type":"record","name":"E","fields":[{"name":"message","type":"string"}]}"#,
    )
    .expect("schema");
    schema.to_string_lossy().replace('\\', "/")
}

#[test]
fn stdout_writes_the_base64_datum_for_hello() {
    let path = schema_path();
    let config = format!(
        r#"input {{ generator {{ count => 1 message => "hello" }} }} output {{ stdout {{ codec => avro {{ schema_uri => "{path}" }} }} }}"#
    );
    let ran = run(&config, &settings()).expect("run");
    assert_eq!(ran.stdout, "CmhlbGxv");
}

#[test]
fn binary_encoding_is_the_raw_utf8_datum() {
    let path = schema_path();
    let config = format!(
        r#"input {{ generator {{ count => 1 message => "hello" }} }} output {{ stdout {{ codec => avro {{ schema_uri => "{path}" encoding => binary }} }} }}"#
    );
    let ran = run(&config, &settings()).expect("run");
    assert_eq!(ran.stdout, "\nhello");
}

#[test]
fn stdin_decodes_the_same_datum() {
    let path = schema_path();
    let mut settings = settings();
    settings.stdin = Some("CmhlbGxv".to_string());
    let config = format!(
        r#"input {{ stdin {{ codec => avro {{ schema_uri => "{path}" }} }} }} output {{ stdout {{ codec => plain {{ format => "%{{message}}" }} }} }}"#
    );
    let ran = run(&config, &settings).expect("run");
    assert_eq!(ran.stdout, "hello");
    assert_eq!(
        ran.events[0].get_field("message").expect("field"),
        Some(Value::from("hello"))
    );
}

#[test]
fn a_bad_datum_can_be_tagged() {
    let path = schema_path();
    let mut settings = settings();
    settings.stdin = Some("%%%".to_string());
    let config = format!(
        r#"input {{ stdin {{ codec => avro {{ schema_uri => "{path}" tag_on_failure => true }} }} }} output {{ stdout {{ codec => plain {{ format => "%{{message}}" }} }} }}"#
    );
    let ran = run(&config, &settings).expect("run");
    assert_eq!(ran.stdout, "%%%");
    let tags = ran.events[0].get_field("tags").expect("tags");
    assert_eq!(
        tags,
        Some(Value::Array(vec![Value::from("_avroparsefailure")]))
    );
}

#[test]
fn remote_schema_and_a_missing_uri_are_refused() {
    let https = run(
        r#"input { generator { count => 1 } } output { stdout { codec => avro { schema_uri => "https://example.com/a.avsc" } } }"#,
        &settings(),
    )
    .expect_err("https");
    assert!(
        https
            .message
            .contains("avro schema https is not implemented"),
        "{}",
        https.message
    );

    let missing = run(
        r#"input { generator { count => 1 } } output { stdout { codec => avro { } } }"#,
        &settings(),
    )
    .expect_err("missing");
    assert!(
        missing.message.contains("schema_uri => # SETTING MISSING"),
        "{}",
        missing.message
    );

    let mut listed = Vec::new();
    execute(
        &["plugin".to_string(), "list".to_string(), "avro".to_string()],
        &mut listed,
    )
    .expect("list");
    let text = String::from_utf8(listed).expect("utf8");
    assert!(text.contains("logstash-codec-avro\n"), "{text}");
}
