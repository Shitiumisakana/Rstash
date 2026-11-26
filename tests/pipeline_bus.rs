//! `pipeline` input and output. Events are cloned onto an in-process address.

use std::time::Duration;

use rstash::{Ecs, Settings, Value, run, run_many};

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

fn message(event: &rstash::Event) -> Option<String> {
    match event.get_field("message").expect("message") {
        Some(Value::String(text)) => Some(text),
        Some(other) => panic!("message is {other:?}"),
        None => None,
    }
}

#[test]
fn an_event_crosses_three_pipelines_and_stays_independent() {
    let named = vec![
        (
            "up".to_string(),
            r#"
            input { generator { count => 1 message => "hop" } }
            output { pipeline { send_to => "mid" } }
            "#
            .to_string(),
        ),
        (
            "mid".to_string(),
            r#"
            input { pipeline { address => "mid" } }
            output { pipeline { send_to => ["end"] } }
            "#
            .to_string(),
        ),
        (
            "end".to_string(),
            r#"
            input {
              pipeline {
                address => "end"
                type => "relay"
                tags => ["from-bus"]
                add_field => { "via" => "pipeline" }
              }
            }
            output { stdout { codec => plain { format => "%{message}" } } }
            "#
            .to_string(),
        ),
    ];
    let results = run_many(&named, &settings()).expect("bus");
    assert_eq!(message(&results[0].1.events[0]).as_deref(), Some("hop"));
    assert_eq!(results[0].1.events[0].get_field("via").expect("via"), None);
    assert_eq!(message(&results[2].1.events[0]).as_deref(), Some("hop"));
    assert_eq!(
        results[2].1.events[0].get_field("type").expect("type"),
        Some(Value::from("relay"))
    );
    assert_eq!(
        results[2].1.events[0].get_field("via").expect("via"),
        Some(Value::from("pipeline"))
    );
    assert_eq!(
        results[2].1.events[0].get_field("tags").expect("tags"),
        Some(Value::Array(vec![Value::from("from-bus")]))
    );
    assert_eq!(results[2].1.stdout, "hop");
}

#[test]
fn one_output_clones_to_two_addresses() {
    let named = vec![
        (
            "up".to_string(),
            r#"
            input { generator { count => 1 message => "fan" } }
            output { pipeline { send_to => ["left", "right"] } }
            "#
            .to_string(),
        ),
        (
            "left".to_string(),
            r#"
            input { pipeline { address => "left" add_field => { "side" => "left" } } }
            output { stdout { codec => plain } }
            "#
            .to_string(),
        ),
        (
            "right".to_string(),
            r#"
            input { pipeline { address => "right" add_field => { "side" => "right" } } }
            output { stdout { codec => plain } }
            "#
            .to_string(),
        ),
    ];
    let results = run_many(&named, &settings()).expect("fan");
    assert_eq!(
        results[1].1.events[0].get_field("side").expect("side"),
        Some(Value::from("left"))
    );
    assert_eq!(
        results[2].1.events[0].get_field("side").expect("side"),
        Some(Value::from("right"))
    );
    assert_eq!(
        results[0].1.events[0].get_field("side").expect("side"),
        None
    );
}

#[test]
fn missing_peers_cycles_and_bad_settings_fail() {
    let missing_address = run(
        "input { pipeline { } } output { stdout { codec => plain } }",
        &settings(),
    )
    .expect_err("address");
    assert!(
        missing_address
            .to_string()
            .contains("address => # SETTING MISSING"),
        "{missing_address}"
    );

    let missing_send = run(
        "input { generator { count => 1 } } output { pipeline { } }",
        &settings(),
    )
    .expect_err("send_to");
    assert!(
        missing_send
            .to_string()
            .contains("send_to => # SETTING MISSING"),
        "{missing_send}"
    );

    let bad_bool = run(
        r#"input { generator { count => 1 } } output { pipeline { send_to => "x" ensure_delivery => nope } }"#,
        &settings(),
    )
    .expect_err("boolean");
    assert!(
        bad_bool
            .to_string()
            .contains("Expected boolean 'true' or 'false', got \"nope\""),
        "{bad_bool}"
    );

    let dropped = run(
        r#"input { generator { count => 1 message => "gone" } } output { pipeline { send_to => "missing" ensure_delivery => false } }"#,
        &settings(),
    )
    .expect("drop");
    assert_eq!(message(&dropped.events[0]).as_deref(), Some("gone"));

    let no_input = run(
        r#"input { generator { count => 1 } } output { pipeline { send_to => "missing" } }"#,
        &settings(),
    )
    .expect_err("no input");
    assert!(
        no_input
            .to_string()
            .contains("send_to \"missing\" has no pipeline input"),
        "{no_input}"
    );

    let no_sender = run(
        r#"input { pipeline { address => "alone" } } output { stdout { codec => plain } }"#,
        &settings(),
    )
    .expect_err("no sender");
    assert!(
        no_sender
            .to_string()
            .contains("address \"alone\" has no sender"),
        "{no_sender}"
    );

    let obsolete = run(
        r#"input { pipeline { address => "x" debug => true } } output { stdout { codec => plain } }"#,
        &settings(),
    )
    .expect_err("obsolete");
    assert!(
        obsolete
            .to_string()
            .contains("setting `debug` in plugin `pipeline` is obsolete"),
        "{obsolete}"
    );

    let unknown = run(
        r#"input { pipeline { address => "x" foo => "bar" } } output { stdout { codec => plain } }"#,
        &settings(),
    )
    .expect_err("unknown");
    assert!(
        unknown
            .to_string()
            .contains("Unknown setting 'foo' for pipeline"),
        "{unknown}"
    );

    let duplicate = run_many(
        &[
            (
                "a".to_string(),
                r#"input { pipeline { address => "dup" } } output { stdout { codec => plain } }"#
                    .to_string(),
            ),
            (
                "b".to_string(),
                r#"input { pipeline { address => "dup" } } output { stdout { codec => plain } }"#
                    .to_string(),
            ),
        ],
        &settings(),
    )
    .expect_err("duplicate");
    assert!(
        duplicate.to_string().contains(
            "Internal input at 'dup' already bound! Addresses must be globally unique across pipelines."
        ),
        "{duplicate}"
    );

    let cycle = run_many(
        &[
            (
                "a".to_string(),
                r#"input { pipeline { address => "from-b" } } output { pipeline { send_to => "to-b" } }"#
                    .to_string(),
            ),
            (
                "b".to_string(),
                r#"input { pipeline { address => "to-b" } } output { pipeline { send_to => "from-b" } }"#
                    .to_string(),
            ),
        ],
        &settings(),
    )
    .expect_err("cycle");
    assert!(
        cycle
            .to_string()
            .contains("pipeline send cycle is not implemented"),
        "{cycle}"
    );
}
