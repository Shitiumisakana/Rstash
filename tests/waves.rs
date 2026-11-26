//! Behavior from the 9.5.2 gems for waves A–C and the small filters beside them.
//!
//! Expected values come from those plugins: UUID shape, SHA1("abc"), syslog
//! priority 165, UNIX 1600000000, and the clone/split event counts.

use rstash::{Ecs, Event, Settings, Value, apply_filter, run};
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

fn field(event: &Event, name: &str) -> Option<Value> {
    event.get_field(name).expect("field")
}

fn one(config: &str, json: &str) -> Event {
    let mut event = Event::from_json(json).unwrap().remove(0);
    apply_filter(config, &mut event).unwrap();
    event
}

#[test]
fn wave_a_stdin_dots_sink_and_uuid() {
    let mut settings = settings();
    settings.stdin = Some("one\ntwo\n".to_string());
    let ran = run(
        r#"input { stdin { } } output { stdout { codec => dots } }"#,
        &settings,
    )
    .unwrap();
    assert_eq!(ran.events.len(), 2);
    assert_eq!(ran.stdout, "..");
    assert_eq!(field(&ran.events[0], "message"), Some(Value::from("one")));
    assert!(field(&ran.events[0], "host").is_some());

    let sunk = run(
        r#"input { generator { count => 1 message => "gone" } } output { sink { } }"#,
        &settings,
    )
    .unwrap();
    assert!(sunk.stdout.is_empty());
    assert_eq!(sunk.events.len(), 1);

    let event = one(r#"filter { uuid { target => "id" } }"#, r#"{"id":"keep"}"#);
    assert_eq!(field(&event, "id"), Some(Value::from("keep")));
    let event = one(
        r#"filter { uuid { target => "id" overwrite => true } }"#,
        r#"{"id":"keep"}"#,
    );
    let Value::String(id) = field(&event, "id").unwrap() else {
        panic!("uuid");
    };
    assert!(id.len() == 36 && id.as_bytes()[14] == b'4');
}

#[test]
fn wave_b_filters_match_the_gem_behavior() {
    let event = one(
        r#"filter { json { source => "message" } }"#,
        r#"{"message":"{\"foo\":1,\"bar\":\"x\"}"}"#,
    );
    assert_eq!(field(&event, "foo"), Some(Value::Integer(1)));
    assert_eq!(field(&event, "bar"), Some(Value::from("x")));

    let event = one(
        r#"filter { json { source => "message" } }"#,
        r#"{"message":"not-json"}"#,
    );
    match field(&event, "tags") {
        Some(Value::Array(tags)) => assert!(tags.contains(&Value::from("_jsonparsefailure"))),
        other => panic!("{other:?}"),
    }

    let event = one(
        r#"filter { kv { source => "message" } }"#,
        r#"{"message":"a=1 b=two"}"#,
    );
    assert_eq!(field(&event, "a"), Some(Value::from("1")));
    assert_eq!(field(&event, "b"), Some(Value::from("two")));

    let event = one(
        r#"filter { csv { columns => ["name", "qty"] convert => { "qty" => "integer" } } }"#,
        r#"{"message":"widget,3"}"#,
    );
    assert_eq!(field(&event, "name"), Some(Value::from("widget")));
    assert_eq!(field(&event, "qty"), Some(Value::Integer(3)));

    let event = one(
        r#"filter { date { match => ["message", "UNIX"] } }"#,
        r#"{"message":"1600000000"}"#,
    );
    assert!(matches!(
        field(&event, "@timestamp"),
        Some(Value::Timestamp(_))
    ));

    let event = one(
        r#"filter { dissect { mapping => { "message" => "%{a} %{b}" } } }"#,
        r#"{"message":"one two"}"#,
    );
    assert_eq!(field(&event, "a"), Some(Value::from("one")));
    assert_eq!(field(&event, "b"), Some(Value::from("two")));

    let event = one(
        r#"filter { fingerprint { method => "SHA1" source => ["message"] } }"#,
        r#"{"message":"abc"}"#,
    );
    assert_eq!(
        field(&event, "fingerprint"),
        Some(Value::from("a9993e364706816aba3e25717850c26c9cd0d89d"))
    );

    let event = one(
        r#"filter { prune { whitelist_names => ["^message$"] } }"#,
        r#"{"message":"stay","dropme":"no"}"#,
    );
    assert_eq!(field(&event, "message"), Some(Value::from("stay")));
    assert_eq!(field(&event, "dropme"), None);

    let cloned = run(
        r#"
        input { generator { count => 1 message => "orig" } }
        filter { clone { clones => ["copy"] } }
        output { stdout { codec => plain } }
        "#,
        &settings(),
    )
    .unwrap();
    assert_eq!(cloned.events.len(), 2);
    assert_eq!(field(&cloned.events[1], "type"), Some(Value::from("copy")));

    let split = run(
        r#"
        input { generator { count => 1 message => "a
b" } }
        filter { split { } }
        output { stdout { codec => plain } }
        "#,
        &settings(),
    )
    .unwrap();
    assert_eq!(split.events.len(), 2);
    assert_eq!(field(&split.events[0], "message"), Some(Value::from("a")));
    assert_eq!(field(&split.events[1], "message"), Some(Value::from("b")));
}

#[test]
fn wave_c_and_small_filters() {
    let ran = run(
        r#"input { generator { count => 1 message => "hello" } } output { stdout { codec => json_lines } }"#,
        &settings(),
    )
    .unwrap();
    assert!(ran.stdout.contains("\"message\":\"hello\""));
    assert!(ran.stdout.ends_with('\n'));

    let ran = run(
        r#"input { generator { count => 1 message => "hello" } } output { stdout { codec => rubydebug } }"#,
        &settings(),
    )
    .unwrap();
    assert!(ran.stdout.contains("\"message\" => \"hello\""));
    assert!(ran.stdout.ends_with('\n'));

    let event = one(
        r#"filter { urldecode { field => "message" } }"#,
        r#"{"message":"a%20b"}"#,
    );
    assert_eq!(field(&event, "message"), Some(Value::from("a b")));

    let event = one(
        r#"filter { truncate { fields => ["message"] length_bytes => 5 } }"#,
        r#"{"message":"hello world"}"#,
    );
    assert_eq!(field(&event, "message"), Some(Value::from("hello")));

    let event = one(
        r#"filter { syslog_pri { syslog_pri_field_name => "syslog_pri" } }"#,
        r#"{"syslog_pri":"165"}"#,
    );
    assert_eq!(
        field(&event, "[log][syslog][facility][name]"),
        Some(Value::from("local4"))
    );
    assert_eq!(
        field(&event, "[log][syslog][severity][name]"),
        Some(Value::from("notice"))
    );

    let event = one(r#"filter { de_dot { } }"#, r#"{"a.b":"c"}"#);
    assert_eq!(field(&event, "a_b"), Some(Value::from("c")));
    assert_eq!(field(&event, "a.b"), None);

    let event = one(
        r#"filter { anonymize { algorithm => "SHA1" key => "secret" fields => ["message"] } }"#,
        r#"{"message":"abc"}"#,
    );
    let Value::String(hash) = field(&event, "message").unwrap() else {
        panic!("hash");
    };
    assert_eq!(hash.len(), 40);
    assert_ne!(hash, "a9993e364706816aba3e25717850c26c9cd0d89d");

    let path = std::env::temp_dir().join("rstash-wave-file-out.txt");
    let _ = std::fs::remove_file(&path);
    let path_text = path.to_string_lossy().replace('\\', "/");
    run(
        &format!(
            r#"input {{ generator {{ count => 1 message => "saved" }} }} output {{ file {{ path => "{path_text}" codec => line }} }}"#
        ),
        &settings(),
    )
    .unwrap();
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("saved"));
    let _ = std::fs::remove_file(&path);

    let beats = run(
        r#"input { generator { count => 2 message => "ok" } } filter { sleep { time => "0" } } output { null { } }"#,
        &settings(),
    )
    .unwrap();
    assert!(beats.stdout.is_empty());
    assert_eq!(beats.events.len(), 2);
}
