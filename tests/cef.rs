//! `logstash-codec-cef` 6.2.8. Header fields, short extension names, and the
//! default encode line come from the 6.2.8 codec.

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

const SAMPLE: &str = "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232";

#[test]
fn stdin_decodes_the_header_and_short_names() {
    let mut settings = settings();
    settings.stdin = Some(SAMPLE.to_string());
    let ran = run(
        r#"input { stdin { codec => cef } } output { stdout { codec => plain { format => "%{sourceAddress}" } } }"#,
        &settings,
    )
    .expect("run");
    assert_eq!(ran.stdout, "10.0.0.1");
    let event = &ran.events[0];
    assert_eq!(
        event.get_field("deviceVendor").expect("field"),
        Some(Value::from("Security"))
    );
    assert_eq!(
        event.get_field("name").expect("field"),
        Some(Value::from("worm successfully stopped"))
    );
    assert_eq!(
        event.get_field("destinationAddress").expect("field"),
        Some(Value::from("2.1.2.2"))
    );
    assert_eq!(
        event.get_field("sourcePort").expect("field"),
        Some(Value::from("1232"))
    );
}

#[test]
fn stdout_writes_the_default_header() {
    let ran = run(
        r#"input { generator { count => 1 message => "hi" } } output { stdout { codec => cef { fields => ["message"] } } }"#,
        &settings(),
    )
    .expect("run");
    assert_eq!(
        ran.stdout,
        "CEF:0|Elasticsearch|Logstash|1.0|Logstash|Logstash|6|message=hi"
    );

    let reversed = run(
        r#"input { generator { count => 1 message => "hi" } } output { stdout { codec => cef { fields => ["message"] reverse_mapping => true severity => "3" } } }"#,
        &settings(),
    )
    .expect("run");
    assert_eq!(
        reversed.stdout,
        "CEF:0|Elasticsearch|Logstash|1.0|Logstash|Logstash|3|msg=hi"
    );
}

#[test]
fn a_payload_that_is_not_cef_is_tagged() {
    let mut settings = settings();
    settings.stdin = Some("not-cef".to_string());
    let ran = run(
        r#"input { stdin { codec => cef } } output { stdout { codec => plain { format => "%{message}" } } }"#,
        &settings,
    )
    .expect("run");
    assert_eq!(ran.stdout, "not-cef");
    assert_eq!(
        ran.events[0].get_field("tags").expect("tags"),
        Some(Value::Array(vec![Value::from("_cefparsefailure")]))
    );
}

#[test]
fn ecs_reads_source_ip_and_a_millis_timestamp() {
    let mut settings = settings();
    settings.ecs = Ecs::V1;
    settings.stdin = Some(
        "CEF:0|Security|threatmanager|1.0|100|worm|5|src=10.0.0.1 rt=1600000000000".to_string(),
    );
    let ran = run(
        r#"input { stdin { codec => cef } } output { stdout { codec => plain } }"#,
        &settings,
    )
    .expect("run");
    let event = &ran.events[0];
    assert_eq!(
        event.get_field("[source][ip]").expect("field"),
        Some(Value::from("10.0.0.1"))
    );
    assert_eq!(
        event.get_field("[cef][version]").expect("field"),
        Some(Value::from("0"))
    );
    let Value::Timestamp(timestamp) = event.get_field("@timestamp").expect("field").expect("time")
    else {
        panic!("timestamp");
    };
    assert_eq!(timestamp.timestamp(), 1_600_000_000);
}

#[test]
fn an_unknown_device_and_a_named_zone_are_refused() {
    let device = run(
        r#"input { generator { count => 1 } } output { stdout { codec => cef { device => "router" } } }"#,
        &settings(),
    )
    .expect_err("device");
    assert!(
        device
            .message
            .contains("Expected one of [\"observer\", \"host\"]"),
        "{}",
        device.message
    );

    let zone = run(
        r#"input { generator { count => 1 } } output { stdout { codec => cef { default_timezone => "America/New_York" } } }"#,
        &settings(),
    )
    .expect_err("zone");
    assert!(
        zone.message
            .contains("cef default_timezone is not implemented"),
        "{}",
        zone.message
    );

    let mut listed = Vec::new();
    execute(
        &["plugin".to_string(), "list".to_string(), "cef".to_string()],
        &mut listed,
    )
    .expect("list");
    let text = String::from_utf8(listed).expect("utf8");
    assert!(text.contains("logstash-codec-cef\n"), "{text}");
}
