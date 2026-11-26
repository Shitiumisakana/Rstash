//! Grok 4.4.4 and multiline codec 3.1.2 against patterns-core 4.3.4.
//!
//! The sample lines are the ones in the gem comments. Field names come from
//! the ecs-v1 pattern file (`SYSLOGBASE` writes `[host][hostname]` and
//! `[process][name]`). `apply_filter` runs at ECS v8, which selects that set.

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
fn grok_common_log_and_syslog_base() {
    let event = one(
        r#"filter { grok { match => { "message" => "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes:int} %{NUMBER:duration:float}" } } }"#,
        r#"{"message":"55.3.244.1 GET /index.html 15824 0.043"}"#,
    );
    assert_eq!(field(&event, "client"), Some(Value::from("55.3.244.1")));
    assert_eq!(field(&event, "method"), Some(Value::from("GET")));
    assert_eq!(field(&event, "request"), Some(Value::from("/index.html")));
    assert_eq!(field(&event, "bytes"), Some(Value::Integer(15824)));
    let Value::Float(duration) = field(&event, "duration").unwrap() else {
        panic!("duration");
    };
    assert_eq!(duration, "0.043".parse::<f64>().unwrap());

    let event = one(
        r#"filter { grok { match => { "message" => "%{SYSLOGBASE} %{GREEDYDATA:message}" } overwrite => ["message"] } }"#,
        r#"{"message":"May 29 16:37:11 sadness logger: hello world"}"#,
    );
    assert_eq!(
        field(&event, "timestamp"),
        Some(Value::from("May 29 16:37:11"))
    );
    assert_eq!(
        field(&event, "[host][hostname]"),
        Some(Value::from("sadness"))
    );
    assert_eq!(
        field(&event, "[process][name]"),
        Some(Value::from("logger"))
    );
    assert_eq!(field(&event, "message"), Some(Value::from("hello world")));
}

#[test]
fn grok_failure_custom_pattern_and_break_on_match() {
    let event = one(
        r#"filter { grok { match => { "message" => "%{WORD:foo}" } } }"#,
        r#"{"message":"..."}"#,
    );
    match field(&event, "tags") {
        Some(Value::Array(tags)) => assert!(tags.contains(&Value::from("_grokparsefailure"))),
        other => panic!("{other:?}"),
    }

    let event = one(
        r#"filter { grok { pattern_definitions => { "GREETING" => "hello" } match => { "message" => "%{GREETING:hi}" } } }"#,
        r#"{"message":"say hello"}"#,
    );
    assert_eq!(field(&event, "hi"), Some(Value::from("hello")));

    let event = one(
        r#"filter { grok { break_on_match => false match => { "message" => [ "%{WORD:word}", "%{NUMBER:num:int}" ] } } }"#,
        r#"{"message":"foo 12"}"#,
    );
    assert_eq!(field(&event, "word"), Some(Value::from("foo")));
    assert_eq!(field(&event, "num"), Some(Value::Integer(12)));

    let event = one(
        r#"filter { grok { match => { "message" => [ "%{WORD:word}", "%{NUMBER:num:int}" ] } } }"#,
        r#"{"message":"foo 12"}"#,
    );
    assert_eq!(field(&event, "word"), Some(Value::from("foo")));
    assert_eq!(field(&event, "num"), None);

    let mut event = Event::from_json(r#"{"message":"hello"}"#)
        .unwrap()
        .remove(0);
    let error = apply_filter(
        r#"filter { grok { match => { "message" => "%{NO_SUCH_PATTERN:x}" } } }"#,
        &mut event,
    );
    assert!(error.is_err());
}

#[test]
fn multiline_previous_and_next_on_a_file() {
    let dir = std::env::temp_dir().join("rstash-multiline");
    let _ = std::fs::create_dir_all(&dir);
    let stack = dir.join("stack.log");
    std::fs::write(
        &stack,
        "Exception in thread \"main\"\n    at com.example.Main.main\n",
    )
    .unwrap();
    let stack_text = stack.to_string_lossy().replace('\\', "/");
    let ran = run(
        &format!(
            r#"input {{ file {{ path => "{stack_text}" mode => "read" codec => multiline {{ pattern => "^\s" what => "previous" }} }} }} output {{ stdout {{ codec => plain }} }}"#
        ),
        &settings(),
    )
    .unwrap();
    assert_eq!(ran.events.len(), 1);
    assert_eq!(
        field(&ran.events[0], "message"),
        Some(Value::from(
            "Exception in thread \"main\"\n    at com.example.Main.main"
        ))
    );
    match field(&ran.events[0], "tags") {
        Some(Value::Array(tags)) => assert!(tags.contains(&Value::from("multiline"))),
        other => panic!("{other:?}"),
    }

    let cont = dir.join("cont.log");
    std::fs::write(&cont, "line1 \\\nline2\n").unwrap();
    let cont_text = cont.to_string_lossy().replace('\\', "/");
    let ran = run(
        &format!(
            r#"input {{ file {{ path => "{cont_text}" mode => "read" codec => multiline {{ pattern => "\\$" what => "next" }} }} }} output {{ stdout {{ codec => plain }} }}"#
        ),
        &settings(),
    )
    .unwrap();
    assert_eq!(ran.events.len(), 1);
    assert_eq!(
        field(&ran.events[0], "message"),
        Some(Value::from("line1 \\\nline2"))
    );
}
