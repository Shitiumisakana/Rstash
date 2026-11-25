use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rstash::{Event, EventError, Value};

fn pipeline_event() -> serde_json::Value {
    let text = include_str!("fixtures/oracle/event_fields.out");
    let json = text
        .lines()
        .find(|line| line.starts_with('{'))
        .expect("pipeline fixture has one JSON event");
    serde_json::from_str(json).expect("pipeline fixture JSON")
}

fn probe_values() -> HashMap<String, String> {
    include_str!("fixtures/oracle/event_probe.out")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty() && !line.starts_with("TS "))
        .map(|line| {
            let (key, value) = line.split_once('=').expect("probe line");
            (key.to_string(), value.to_string())
        })
        .collect()
}

fn probe_timestamps() -> Vec<(String, String)> {
    include_str!("fixtures/oracle/event_probe.out")
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("TS ")?;
            let (instant, formatted) = rest.split_once(" => ")?;
            Some((instant.to_string(), formatted.to_string()))
        })
        .collect()
}

fn at_rfc3339(text: &str) -> Event {
    let timestamp = DateTime::parse_from_rfc3339(text)
        .expect("oracle timestamp")
        .with_timezone(&Utc);
    Event::at(timestamp)
}

fn message_after_class(value: &str) -> &str {
    value
        .split_once(' ')
        .map(|(_, message)| message)
        .unwrap_or(value)
}

#[test]
fn event_fields() {
    let fixture = pipeline_event();
    let message = fixture["message"].as_str().expect("message");
    assert_eq!(fixture["msg_copy"], message, "emoji survives Logstash JSON");
    assert!(fixture.get("@metadata").is_none());
    assert_eq!(fixture["@version"], "1");
    assert_eq!(fixture["foo"]["bar"], "nested");
    assert_eq!(fixture["copied"], "nested");
    assert_eq!(fixture["meta_copy"], "filebeat");
    assert_eq!(fixture["missing"], "%{[no][such]}");
    assert_eq!(
        fixture["tags"],
        serde_json::json!(["alpha", "beta", "nested"])
    );
    assert_eq!(fixture["tags_join"], "alpha,beta,nested");
    assert_eq!(fixture["deep"]["a"], serde_json::json!({}));
    assert_eq!(fixture["event"]["sequence"], 0);
    assert!(fixture["host"]["name"].is_string());

    let timestamp = fixture["@timestamp"].as_str().expect("timestamp");
    let mut event = at_rfc3339(timestamp);
    event
        .set_field("[@metadata][beat]", Value::from("filebeat"))
        .unwrap();
    event
        .set_field("[foo][bar]", Value::from("nested"))
        .unwrap();
    event
        .set_field("[deep][a][b]", Value::from("leaf"))
        .unwrap();
    event.set_field("message", Value::from(message)).unwrap();
    event
        .set_field(
            "tags",
            Value::Array(vec![
                Value::from("alpha"),
                Value::from("beta"),
                Value::from("nested"),
            ]),
        )
        .unwrap();

    assert_eq!(event.get_field("@version").unwrap(), Some(Value::from("1")));
    assert_eq!(
        event.get_field("[foo][bar]").unwrap(),
        Some(Value::from("nested"))
    );
    assert_eq!(
        event.get_field("[@metadata][beat]").unwrap(),
        Some(Value::from("filebeat"))
    );
    let mut metadata = rstash::Map::new();
    metadata.insert("beat", Value::from("filebeat"));
    assert_eq!(
        event.get_field("@metadata").unwrap(),
        Some(Value::Map(metadata))
    );
    assert!(!event.is_cancelled());

    assert_eq!(
        event.sprintf("%{[foo][bar]}").unwrap(),
        fixture["copied"].as_str().unwrap()
    );
    assert_eq!(
        event.sprintf("%{[@metadata][beat]}").unwrap(),
        fixture["meta_copy"].as_str().unwrap()
    );
    assert_eq!(
        event.sprintf("%{[no][such]}").unwrap(),
        fixture["missing"].as_str().unwrap()
    );
    assert_eq!(
        event.sprintf("%{+YYYY.MM.dd}").unwrap(),
        fixture["day"].as_str().unwrap()
    );
    assert_eq!(
        event.sprintf("%{{yyyy-MM-dd}}").unwrap(),
        fixture["java_day"].as_str().unwrap()
    );
    assert_eq!(
        event.sprintf("%{+%s}").unwrap(),
        fixture["epoch"].as_str().unwrap()
    );
    assert_eq!(
        event.sprintf("%{message}").unwrap(),
        fixture["msg_copy"].as_str().unwrap()
    );
    assert_eq!(
        event.sprintf("%{tags}").unwrap(),
        fixture["tags_join"].as_str().unwrap()
    );
    assert_eq!(
        event.sprintf("%{[foo]}").unwrap(),
        fixture["foo_json"].as_str().unwrap()
    );
    assert_eq!(event.sprintf("%{@timestamp}").unwrap(), timestamp);

    let removed = event.remove_field("[deep][a][b]").unwrap();
    assert_eq!(removed, Some(Value::from("leaf")));
    assert_eq!(
        event.get_field("[deep][a]").unwrap(),
        Some(Value::Map(rstash::Map::new()))
    );
}

#[test]
fn event_fields_timestamp_format() {
    for (instant, formatted) in probe_timestamps() {
        let event = at_rfc3339(&instant);
        assert_eq!(event.sprintf("%{@timestamp}").unwrap(), formatted);
    }
}

#[test]
fn event_fields_probe_sprintf() {
    let probe = probe_values();
    let mut event = at_rfc3339(&probe["FIXED_TIMESTAMP"]);
    event
        .set_field("[foo][bar]", Value::from("nested"))
        .unwrap();
    event
        .set_field("[@metadata][beat]", Value::from("filebeat"))
        .unwrap();
    event
        .set_field("message", Value::from(probe["SPRINTF_MSG"].as_str()))
        .unwrap();
    event.set_field("[pair][z]", Value::from("1")).unwrap();
    event.set_field("[pair][a]", Value::from("2")).unwrap();

    assert_eq!(
        event.sprintf("%{[foo][bar]}").unwrap(),
        probe["SPRINTF_NESTED"]
    );
    assert_eq!(
        event.sprintf("%{[@metadata][beat]}").unwrap(),
        probe["SPRINTF_META"]
    );
    assert_eq!(
        event.sprintf("%{[no][such]}").unwrap(),
        probe["SPRINTF_MISS"]
    );
    assert_eq!(
        event.sprintf("%{+YYYY.MM.dd}").unwrap(),
        probe["SPRINTF_DAY"]
    );
    assert_eq!(event.sprintf("%{+%s}").unwrap(), probe["SPRINTF_EPOCH"]);
    assert_eq!(
        event.sprintf("%{{yyyy-MM-dd}}").unwrap(),
        probe["SPRINTF_JAVA"]
    );
    assert_eq!(
        event.sprintf("x %{[foo][bar]} y").unwrap(),
        probe["SPRINTF_PREFIX"]
    );
    assert_eq!(event.sprintf("%{[pair]}").unwrap(), probe["SPRINTF_PAIR"]);

    event.remove_field("@timestamp").unwrap();
    assert_eq!(
        event.sprintf("%{+YYYY.MM.dd}").unwrap(),
        probe["SPRINTF_NO_TS"]
    );
    assert_eq!(event.sprintf("%{+%s}").unwrap(), probe["SPRINTF_NO_EPOCH"]);
    assert_eq!(event.remove_field("[no][such]").unwrap(), None);
}

#[test]
fn event_fields_invalid_reference_and_scalar_child() {
    let probe = probe_values();
    let mut event = Event::at(chrono::DateTime::UNIX_EPOCH);
    let error = event
        .set_field("foo[bar]", Value::from("x"))
        .expect_err("bad reference");
    assert_eq!(
        error.to_string(),
        message_after_class(&probe["INVALID_SET"])
    );
    assert!(matches!(error, EventError::InvalidField { .. }));

    event.set_field("plain", Value::from("top")).unwrap();
    let error = event
        .set_field("[plain][child]", Value::from("x"))
        .expect_err("scalar parent");
    assert_eq!(
        error.to_string(),
        message_after_class(&probe["OVERWRITE_SCALAR"])
    );
    assert_eq!(event.get_field("[plain][child]").unwrap(), None);
}
