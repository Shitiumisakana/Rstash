//! Official Logstash 9.5.2 tests, rewritten against the Rust event and compiler.
//!
//! Sources:
//! - logstash-core/src/test/java/org/logstash/EventTest.java
//! - logstash-core/src/test/java/org/logstash/FieldReferenceTest.java
//! - logstash-core/src/test/java/org/logstash/StringInterpolationTest.java
//! - logstash-core/spec/logstash/event_spec.rb
//! - logstash-core/spec/logstash/config/string_escape_spec.rb
//!
//! JVM-only assertions are not reproduced: CBOR byte fixtures, JRuby proxy identity,
//! field-reference cache size, `estimateMemory`, and `NoMethodError` for a missing Ruby method.
//! `CompiledPipelineTest` and `EventConditionTest` execute plugins; that is the memory pipeline slice.

use std::thread;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rstash::{
    Decimal, Event, EventError, FieldEscape, Map, Target, Value, field_cache_len_after_distinct,
    parse_field, parse_field_escaped, process_string_escapes, same_interned_field,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn at(text: &str) -> Event {
    let timestamp = DateTime::parse_from_rfc3339(text)
        .unwrap()
        .with_timezone(&Utc);
    Event::at(timestamp)
}

fn json_of(event: &Event) -> serde_json::Value {
    serde_json::from_str(&event.to_json().unwrap()).unwrap()
}

fn field_map(pairs: &[(&str, Value)]) -> Map {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(*key, value.clone());
    }
    map
}

#[test]
fn event_test_to_json_and_fields() {
    let bare = Event::new();
    let bare_json = json_of(&bare);
    assert_eq!(bare_json["@version"], "1");
    assert!(bare_json["@timestamp"].is_string());
    assert!(bare_json.get("@metadata").is_none());

    let mut simple = Event::from_data(field_map(&[("foo", Value::from("bar"))]));
    assert_eq!(json_of(&simple)["foo"], "bar");

    let literal_key = Event::from_data(field_map(&[("this[key]", Value::from("value"))]));
    assert_eq!(json_of(&literal_key)["this[key]"], "value");
    let nested_looking = Event::from_data(field_map(&[(
        "[deeply][nested][field]",
        Value::from("value"),
    )]));
    assert_eq!(json_of(&nested_looking)["[deeply][nested][field]"], "value");

    simple.set_field("count", Value::Integer(1)).unwrap();
    assert_eq!(json_of(&simple)["count"], 1);

    let mut decimal = Event::new();
    decimal.set_field("foo", Value::Float(1.0)).unwrap();
    assert_eq!(json_of(&decimal)["foo"].as_f64(), Some(1.0));

    let mut deep = Event::new();
    deep.set_field("[foo][bar][baz]", Value::Integer(1))
        .unwrap();
    assert_eq!(json_of(&deep)["foo"]["bar"]["baz"], 1);
    deep.set_field("[foo][0][baz]", Value::Integer(1)).unwrap();
    assert_eq!(json_of(&deep)["foo"]["0"]["baz"], 1);

    let mut flag = Event::new();
    flag.set_field("[foo][bar][baz]", Value::Boolean(true))
        .unwrap();
    assert_eq!(json_of(&flag)["foo"]["bar"]["baz"], true);

    let listed = Event::from_data(field_map(&[("foo", Value::Array(vec![Value::Integer(1)]))]));
    assert_eq!(
        listed.get_field("[foo][0]").unwrap(),
        Some(Value::Integer(1))
    );

    let rows = Event::from_data(field_map(&[(
        "foo",
        Value::Array(vec![Value::Map(field_map(&[("bar", Value::from("baz"))]))]),
    )]));
    assert_eq!(
        rows.get_field("[foo][0][bar]").unwrap(),
        Some(Value::from("baz"))
    );

    let original = Event::from_data(field_map(&[
        (
            "array",
            Value::Array(vec![Value::Map(field_map(&[("foo", Value::from("bar"))]))]),
        ),
        ("foo", Value::Float(1.0)),
        ("bar", Value::from("bar")),
        ("baz", Value::Integer(1)),
    ]));
    let cloned = original.clone();
    assert_eq!(json_of(&cloned), json_of(&original));
}

#[test]
fn event_test_tags_remove_and_timestamp_string() {
    let mut event = Event::new();
    event.tag("foo");
    assert_eq!(
        event.get_field("tags").unwrap(),
        Some(Value::Array(vec![Value::from("foo")]))
    );
    let mut tagged = Event::from_data(field_map(&[("tags", Value::from("foo"))]));
    tagged.tag("bar");
    assert_eq!(
        tagged.get_field("tags").unwrap(),
        Some(Value::Array(vec![Value::from("foo"), Value::from("bar")]))
    );

    let mut host = Event::from_data(field_map(&[
        ("host", Value::from("foo")),
        ("message", Value::from("bar")),
    ]));
    let stamp = host.get_field("@timestamp").unwrap().unwrap().to_string();
    assert_eq!(host.plain_string(), format!("{stamp} foo bar"));
    host.remove_field("@timestamp").unwrap();
    assert_eq!(host.plain_string(), "foo bar");
    let mut empty = Event::new();
    empty.remove_field("@timestamp").unwrap();
    assert_eq!(empty.plain_string(), "%{host} %{message}");

    let mut meta = Event::new();
    let mut metadata = Map::new();
    metadata.insert("foo", Value::from("bar"));
    meta.set_field("@metadata", Value::Map(metadata)).unwrap();
    assert_eq!(
        meta.remove_field("[@metadata][foo]").unwrap(),
        Some(Value::from("bar"))
    );
    assert!(!meta.includes("[@metadata][foo]").unwrap());
    meta.set_field("[@metadata][foo]", Value::from("bar"))
        .unwrap();
    let removed = meta.remove_field("[@metadata]").unwrap();
    assert!(matches!(removed, Some(Value::Map(_))));
    assert!(!meta.includes("[@metadata][foo]").unwrap());

    let error = Event::new()
        .set_field("[tags][foo]", Value::from("bar"))
        .unwrap_err();
    assert!(matches!(error, EventError::InvalidTags));
    let error = Event::new()
        .set_field("[tags]", Value::Integer(123))
        .unwrap_err();
    assert!(matches!(error, EventError::InvalidTags));

    let mut tags = Event::new();
    tags.set_field("[tags]", Value::from("bar")).unwrap();
    tags.set_field("[tags]", Value::from("foo")).unwrap();
    assert_eq!(tags.get_field("[tags]").unwrap(), Some(Value::from("foo")));
    tags.set_field(
        "[tags]",
        Value::Array(vec![Value::from("foo"), Value::from("bar")]),
    )
    .unwrap();
    assert_eq!(
        tags.get_field("[tags]").unwrap(),
        Some(Value::Array(vec![Value::from("foo"), Value::from("bar")]))
    );

    let renamed = Event::from_data(field_map(&[(
        "tags",
        Value::Map(field_map(&[("poison", Value::from("true"))])),
    )]));
    assert_eq!(
        renamed.get_field("tags").unwrap(),
        Some(Value::Array(vec![Value::from("_tagsparsefailure")]))
    );
    assert_eq!(
        renamed.get_field("[_tags][0][poison]").unwrap(),
        Some(Value::from("true"))
    );

    let plain = Event::from_data(field_map(&[("world", Value::from("cup"))]));
    assert_eq!(plain.get_field("tags").unwrap(), None);

    let parsed =
        Event::from_json("{\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"foo\":\"bar\"}").unwrap();
    assert_eq!(
        parsed[0].get_field("[foo]").unwrap(),
        Some(Value::from("bar"))
    );
    assert_eq!(
        parsed[0]
            .get_field("@timestamp")
            .unwrap()
            .unwrap()
            .to_string(),
        "2015-05-28T23:02:05.350Z"
    );
    assert!(Event::from_json("").unwrap().is_empty());
    assert!(Event::from_json("   ").unwrap().is_empty());
    assert!(Event::from_json("gabeutch").is_err());
    assert!(Event::from_json("[1,2]").is_err());
    assert!(Event::from_json("[\"gabeutch\"]").is_err());
    assert!(Event::from_json("[{\"foo\":\"bar\"}, 1]").is_err());
    let many = Event::from_json("[{\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"foo\":\"bar\"}, {\"@timestamp\":\"2016-05-28T23:02:05.350Z\",\"foo\":\"baz\"}]").unwrap();
    assert_eq!(many.len(), 2);
    assert_eq!(
        many[1].get_field("[foo]").unwrap(),
        Some(Value::from("baz"))
    );
    assert_eq!(
        Event::from_json("[{}]").unwrap()[0]
            .get_field("[foo]")
            .unwrap(),
        None
    );
}

#[test]
fn event_test_append() {
    let mut left = Event::from_data(field_map(&[(
        "field1",
        Value::Array(vec![Value::from("original1"), Value::from("original2")]),
    )]));
    let right = Event::from_data(field_map(&[("field1", Value::from("original1"))]));
    left.append(&right);
    assert_eq!(
        left.get_field("[field1]").unwrap(),
        Some(Value::Array(vec![
            Value::from("original1"),
            Value::from("original2")
        ]))
    );

    let mut lists = Event::from_data(field_map(&[(
        "field1",
        Value::Array(vec![Value::from("original1"), Value::from("original2")]),
    )]));
    lists.append(&Event::from_data(field_map(&[(
        "field1",
        Value::Array(vec![Value::from("original3"), Value::from("original4")]),
    )])));
    assert_eq!(
        lists.get_field("field1").unwrap(),
        Some(Value::Array(vec![
            Value::from("original1"),
            Value::from("original2"),
            Value::from("original3"),
            Value::from("original4"),
        ]))
    );
}

#[test]
fn event_spec_get_set_append_tag_clone_json() {
    let mut event = at("2015-05-28T23:02:05.350Z");
    event.set_field("foo", Value::from("bar")).unwrap();
    event.set_field("bar", Value::Integer(1)).unwrap();
    event.set_field("baz", Value::Float(1.0)).unwrap();
    assert_eq!(event.get_field("foo").unwrap(), Some(Value::from("bar")));
    assert_eq!(event.get_field("[foo]").unwrap(), Some(Value::from("bar")));
    assert_eq!(event.get_field("bar").unwrap(), Some(Value::Integer(1)));
    assert_eq!(event.get_field("[baz]").unwrap(), Some(Value::Float(1.0)));
    assert_eq!(
        event.get_field("@timestamp").unwrap().unwrap().to_string(),
        "2015-05-28T23:02:05.350Z"
    );

    event
        .set_field("[fancy][pants][socks]", Value::from("shoes"))
        .unwrap();
    assert_eq!(json_of(&event)["fancy"]["pants"]["socks"], "shoes");
    let mut with_null = at("2015-05-28T23:02:05.350Z");
    with_null.set_field("null_value", Value::Null).unwrap();
    assert_eq!(json_of(&with_null)["null_value"], serde_json::Value::Null);

    let nested = Event::from_data(field_map(&[(
        "foo",
        Value::Map(field_map(&[
            ("bar", Value::Integer(1)),
            ("baz", Value::Float(1.0)),
            ("biz", Value::from("boz")),
        ])),
    )]));
    assert_eq!(
        nested.get_field("[foo][bar]").unwrap(),
        Some(Value::Integer(1))
    );
    let array = Event::from_data(field_map(&[(
        "foo",
        Value::Array(vec![
            Value::from("bar"),
            Value::Integer(1),
            Value::Float(1.0),
        ]),
    )]));
    assert_eq!(
        array.get_field("[foo][0]").unwrap(),
        Some(Value::from("bar"))
    );
    assert_eq!(
        array.get_field("[foo][1]").unwrap(),
        Some(Value::Integer(1))
    );
    assert_eq!(
        array.get_field("[foo][2]").unwrap(),
        Some(Value::Float(1.0))
    );
    assert_eq!(array.get_field("[foo][3]").unwrap(), None);
    assert_eq!(
        array.get_field("[foo][-3]").unwrap(),
        Some(Value::from("bar"))
    );
    assert_eq!(
        array.get_field("[foo][-2]").unwrap(),
        Some(Value::Integer(1))
    );
    assert_eq!(
        array.get_field("[foo][-1]").unwrap(),
        Some(Value::Float(1.0))
    );
    assert!(event.get_field("[").is_err());
    assert!(Event::new().set_field("[", Value::from("value")).is_err());

    let mut created = Event::new();
    created.set_field("foo", Value::from("bar")).unwrap();
    assert_eq!(created.get_field("foo").unwrap(), Some(Value::from("bar")));
    let mut created = Event::new();
    created.set_field("[foo][bar]", Value::from("baz")).unwrap();
    assert_eq!(
        created.get_field("[foo][bar]").unwrap(),
        Some(Value::from("baz"))
    );
    created.set_field("[list][0]", Value::from("bar")).unwrap();
    created.set_field("[list][1]", Value::Integer(1)).unwrap();
    created.set_field("[list][2]", Value::Float(1.0)).unwrap();
    assert_eq!(
        created.get_field("[list][2]").unwrap(),
        Some(Value::Float(1.0))
    );
    created.set_field("[foo_nil]", Value::Null).unwrap();
    assert_eq!(json_of(&created)["foo_nil"], serde_json::Value::Null);

    let mut special = Event::new();
    let mut inner = Map::new();
    inner.insert("this[field]", Value::from("okay"));
    special
        .set_field("[some][field]", Value::Map(inner))
        .unwrap();
    match special.get_field("[some][field]").unwrap() {
        Some(Value::Map(map)) => assert_eq!(map.get("this[field]"), Some(&Value::from("okay"))),
        other => panic!("expected map, got {other:?}"),
    }

    let mut appended = Event::from_data(field_map(&[("message", Value::from("hello world"))]));
    appended.append(&Event::from_data(field_map(&[(
        "message",
        Value::from("another thing"),
    )])));
    assert_eq!(
        appended.get_field("message").unwrap(),
        Some(Value::Array(vec![
            Value::from("hello world"),
            Value::from("another thing")
        ]))
    );

    let mut tagged = Event::from_data(field_map(&[("message", Value::from("hello world"))]));
    assert_eq!(tagged.get_field("tags").unwrap(), None);
    tagged.tag("foo");
    assert_eq!(
        tagged.get_field("tags").unwrap(),
        Some(Value::Array(vec![Value::from("foo")]))
    );

    let source = Event::from_data(field_map(&[
        ("a", Value::Integer(1)),
        (
            "b",
            Value::Array(vec![
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3),
                Value::Map(field_map(&[
                    ("h", Value::Integer(1)),
                    ("i", Value::from("baz")),
                ])),
            ]),
        ),
        (
            "c",
            Value::Map(field_map(&[
                ("d", Value::from("foo")),
                ("e", Value::from("bar")),
                (
                    "f",
                    Value::Array(vec![
                        Value::Integer(4),
                        Value::Integer(5),
                        Value::from("six"),
                    ]),
                ),
            ])),
        ),
        (
            "@metadata",
            Value::Map(field_map(&[
                ("a", Value::Integer(1)),
                ("b", Value::Integer(2)),
            ])),
        ),
    ]));
    let body = json_of(&source);
    assert!(body.get("@timestamp").is_some());
    assert_eq!(body["@version"], "1");
    assert!(body.get("@metadata").is_none());
    assert_eq!(body["a"], 1);
    assert_eq!(
        source.get_field("[@metadata][a]").unwrap(),
        Some(Value::Integer(1))
    );
    assert_eq!(
        source.get_field("[@metadata][b]").unwrap(),
        Some(Value::Integer(2))
    );

    let loaded = Event::from_json("{\"foo\":1, \"bar\":\"baz\"}").unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(
        loaded[0].get_field("[foo]").unwrap(),
        Some(Value::Integer(1))
    );
    assert_eq!(
        loaded[0].get_field("[bar]").unwrap(),
        Some(Value::from("baz"))
    );
    for blank in ["", "  ", "   "] {
        assert!(Event::from_json(blank).unwrap().is_empty());
    }
    for bare in ["aa", "  aa", "aa  "] {
        assert!(Event::from_json(bare).is_err());
    }
    let made = Event::from_json_with("{\"foo\":1, \"bar\":\"baz\"}", |data| {
        let mut event = Event::from_data(data);
        event.set_field("answer", Value::Integer(42)).unwrap();
        event
    })
    .unwrap();
    assert_eq!(made.len(), 1);
    assert_eq!(
        made[0].get_field("answer").unwrap(),
        Some(Value::Integer(42))
    );
    assert_eq!(made[0].get_field("[foo]").unwrap(), Some(Value::Integer(1)));

    let mut decimal = Event::new();
    decimal
        .set_field("[foo]", Value::Decimal(Decimal::exact("1")))
        .unwrap();
    assert_eq!(
        decimal.get_field("foo").unwrap(),
        Some(Value::Decimal(Decimal::exact("1")))
    );

    let moment = DateTime::parse_from_rfc3339("2015-05-28T23:02:05.350Z")
        .unwrap()
        .with_timezone(&Utc);
    let mut timed = Event::new();
    timed.set_field("[foo]", Value::Timestamp(moment)).unwrap();
    assert_eq!(
        timed.get_field("foo").unwrap(),
        Some(Value::Timestamp(moment))
    );
    timed
        .set_field("@timestamp", Value::Timestamp(moment))
        .unwrap();
    assert_eq!(
        timed.get_field("@timestamp").unwrap(),
        Some(Value::Timestamp(moment))
    );

    let initialized = Event::from_data(field_map(&[
        ("foo", Value::Integer(1)),
        ("@timestamp", Value::from("2015-05-28T23:02:05.350Z")),
    ]));
    assert_eq!(
        initialized.get_field("foo").unwrap(),
        Some(Value::Integer(1))
    );
    assert_eq!(
        initialized
            .get_field("@timestamp")
            .unwrap()
            .unwrap()
            .to_string(),
        "2015-05-28T23:02:05.350Z"
    );
    let awkward = Event::from_data(field_map(&[
        (
            "nested",
            Value::Map(field_map(&[("i][egal", Value::from("okay"))])),
        ),
        ("n[0]", Value::from("bene")),
    ]));
    assert_eq!(
        awkward.get_field("nested").unwrap(),
        Some(Value::Map(field_map(&[("i][egal", Value::from("okay"))])))
    );
    assert_eq!(json_of(&awkward)["n[0]"], "bene");

    let mut big = Event::new();
    big.set_field("[foo]", Value::Integer(-9_223_372_036_854_776_000))
        .unwrap();
    assert_eq!(
        big.get_field("foo").unwrap(),
        Some(Value::Integer(-9_223_372_036_854_776_000))
    );

    let original = Event::from_data(field_map(&[
        ("hello", Value::from("world")),
        (
            "@metadata",
            Value::Map(field_map(&[("fancy", Value::from("pants"))])),
        ),
    ]));
    let mut cloned = original.clone();
    assert_eq!(
        cloned.get_field("[@metadata][fancy]").unwrap(),
        Some(Value::from("pants"))
    );
    assert!(json_of(&cloned).get("@metadata").is_none());
    cloned.set_field("hello", Value::from("foobar")).unwrap();
    assert_eq!(
        original.get_field("hello").unwrap(),
        Some(Value::from("world"))
    );
    cloned
        .set_field("[@metadata][fancy]", Value::from("foobar"))
        .unwrap();
    assert_eq!(
        original.get_field("[@metadata][fancy]").unwrap(),
        Some(Value::from("pants"))
    );

    let stamp = "2015-05-28T23:02:05.350Z";
    let expect_json = |event: &Event, document: &str| {
        assert_eq!(
            json_of(event),
            serde_json::from_str::<serde_json::Value>(document).unwrap()
        );
    };
    let null_event = Event::from_data(field_map(&[
        ("null_value", Value::Null),
        ("@timestamp", Value::from(stamp)),
    ]));
    expect_json(
        &null_event,
        "{\"null_value\":null,\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"@version\":\"1\"}",
    );
    let simple = Event::from_data(field_map(&[
        ("foo", Value::from("bar")),
        ("bar", Value::Integer(1)),
        ("baz", Value::Float(1.0)),
        ("@timestamp", Value::from(stamp)),
    ]));
    expect_json(
        &simple,
        "{\"foo\":\"bar\",\"bar\":1,\"baz\":1.0,\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"@version\":\"1\"}",
    );
    let deep_hash = Event::from_data(field_map(&[
        (
            "foo",
            Value::Map(field_map(&[
                ("bar", Value::Integer(1)),
                ("baz", Value::Float(1.0)),
                ("biz", Value::from("boz")),
            ])),
        ),
        ("@timestamp", Value::from(stamp)),
    ]));
    expect_json(
        &deep_hash,
        "{\"foo\":{\"bar\":1,\"baz\":1.0,\"biz\":\"boz\"},\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"@version\":\"1\"}",
    );
    let deep_array = Event::from_data(field_map(&[
        (
            "foo",
            Value::Array(vec![
                Value::from("bar"),
                Value::Integer(1),
                Value::Float(1.0),
            ]),
        ),
        ("@timestamp", Value::from(stamp)),
    ]));
    expect_json(
        &deep_array,
        "{\"foo\":[\"bar\",1,1.0],\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"@version\":\"1\"}",
    );

    let mut indexed = Event::new();
    indexed.set_field("[foo][0]", Value::from("bar")).unwrap();
    assert_eq!(
        indexed.get_field("[foo][0]").unwrap(),
        Some(Value::from("bar"))
    );
    indexed.set_field("[foo][1]", Value::Integer(1)).unwrap();
    assert_eq!(
        indexed.get_field("[foo][1]").unwrap(),
        Some(Value::Integer(1))
    );
    indexed.set_field("[foo][2]", Value::Float(1.0)).unwrap();
    assert_eq!(
        indexed.get_field("[foo][2]").unwrap(),
        Some(Value::Float(1.0))
    );
    assert_eq!(indexed.get_field("[foo][3]").unwrap(), None);

    let mapped = null_event;
    let mut returned = mapped.to_map();
    returned.insert("extra", Value::from("nope"));
    assert_eq!(mapped.get_field("extra").unwrap(), None);
    let with_meta = mapped.to_map_with_metadata();
    assert!(matches!(with_meta.get("@metadata"), Some(Value::Map(_))));

    for (metadata, field, expected) in [
        (
            Value::Map(field_map(&[("fancy2", Value::from("pants2"))])),
            "[@metadata][fancy]",
            Value::Map(field_map(&[("fancy2", Value::from("pants2"))])),
        ),
        (
            Value::Map(field_map(&[(
                "fancy2",
                Value::Map(field_map(&[("fancy3", Value::from("pants2"))])),
            )])),
            "[@metadata][fancy]",
            Value::Map(field_map(&[(
                "fancy2",
                Value::Map(field_map(&[("fancy3", Value::from("pants2"))])),
            )])),
        ),
        (
            Value::Map(field_map(&[(
                "fancy2",
                Value::Array(vec![Value::from("pants1"), Value::from("pants2")]),
            )])),
            "[@metadata][fancy]",
            Value::Map(field_map(&[(
                "fancy2",
                Value::Array(vec![Value::from("pants1"), Value::from("pants2")]),
            )])),
        ),
    ] {
        let event = Event::from_data(field_map(&[
            ("hello", Value::from("world")),
            ("@metadata", Value::Map(field_map(&[("fancy", metadata)]))),
        ]));
        let cloned = event.clone();
        assert_eq!(cloned.get_field(field).unwrap(), Some(expected));
        assert!(json_of(&cloned).get("@metadata").is_none());
        assert!(cloned.to_map_with_metadata().get("@metadata").is_some());
    }
}

/// `accessors_spec.rb` field get, set, and delete.
#[test]
fn accessors_spec() {
    let event = Event::from_data(field_map(&[("hello", Value::from("world"))]));
    assert_eq!(
        event.get_field("hello").unwrap(),
        Some(Value::from("world"))
    );
    let spaced = Event::from_data(field_map(&[("hel lo", Value::from("world"))]));
    assert_eq!(
        spaced.get_field("hel lo").unwrap(),
        Some(Value::from("world"))
    );
    assert_eq!(
        spaced.get_field("[hel lo]").unwrap(),
        Some(Value::from("world"))
    );
    let numeric = Event::from_data(field_map(&[("1", Value::from("world"))]));
    assert_eq!(numeric.get_field("1").unwrap(), Some(Value::from("world")));
    assert_eq!(
        numeric.get_field("[1]").unwrap(),
        Some(Value::from("world"))
    );

    let mut simple = Event::from_data(field_map(&[("simple", Value::from("things"))]));
    assert_eq!(
        simple.remove_field("simple").unwrap(),
        Some(Value::from("things"))
    );
    assert!(simple.to_map().get("simple").is_none());

    let mut kept = Event::from_data(field_map(&[("hello", Value::from("world"))]));
    assert_eq!(kept.remove_field("[foo][bar]").unwrap(), None);
    assert_eq!(kept.get_field("foo").unwrap(), None);
    assert_eq!(kept.get_field("hello").unwrap(), Some(Value::from("world")));

    let mut created = Event::new();
    created.set_field("simple", Value::from("things")).unwrap();
    assert_eq!(
        created.get_field("simple").unwrap(),
        Some(Value::from("things"))
    );
    created
        .set_field(
            "simple",
            Value::Array(vec![Value::from("foo"), Value::from("bar")]),
        )
        .unwrap();
    assert_eq!(
        created.get_field("simple").unwrap(),
        Some(Value::Array(vec![Value::from("foo"), Value::from("bar")]))
    );

    let nested = Event::from_data(field_map(&[(
        "hello",
        Value::Map(field_map(&[
            ("world", Value::from("foo")),
            ("bar", Value::from("baz")),
        ])),
    )]));
    assert_eq!(
        nested.get_field("[hello][world]").unwrap(),
        Some(Value::from("foo"))
    );
    let mut empty = Event::new();
    assert_eq!(empty.get_field("[hello][world]").unwrap(), None);
    empty
        .set_field("[hello][world]", Value::from("foo"))
        .unwrap();
    assert_eq!(
        empty.get_field("[hello][world]").unwrap(),
        Some(Value::from("foo"))
    );

    let mut deep = Event::from_data(field_map(&[(
        "hello",
        Value::Map(field_map(&[
            ("world", Value::from("foo")),
            ("bar", Value::from("baz")),
        ])),
    )]));
    assert_eq!(
        deep.remove_field("[hello][world]").unwrap(),
        Some(Value::from("foo"))
    );
    assert_eq!(
        deep.get_field("[hello]").unwrap(),
        Some(Value::Map(field_map(&[("bar", Value::from("baz"))])))
    );

    let mut array_field = Event::from_data(field_map(&[(
        "hello",
        Value::Array(vec![Value::from("foo"), Value::from("bar")]),
    )]));
    array_field
        .set_field("[hello][0]", Value::from("world"))
        .unwrap();
    assert_eq!(
        array_field.get_field("hello").unwrap(),
        Some(Value::Array(vec![Value::from("world"), Value::from("bar")]))
    );

    let rows = Event::from_data(field_map(&[(
        "hello",
        Value::Map(field_map(&[
            (
                "world",
                Value::Array(vec![
                    Value::Map(field_map(&[("a", Value::Integer(123))])),
                    Value::Map(field_map(&[("b", Value::Integer(345))])),
                ]),
            ),
            ("bar", Value::from("baz")),
        ])),
    )]));
    assert_eq!(
        rows.get_field("[hello][world][0][a]").unwrap(),
        Some(Value::Integer(123))
    );
    assert_eq!(
        rows.get_field("[hello][world][1][b]").unwrap(),
        Some(Value::Integer(345))
    );

    let mut coords = Event::from_data(field_map(&[(
        "geocoords",
        Value::Array(vec![Value::Integer(4), Value::Integer(2)]),
    )]));
    assert_eq!(
        coords.remove_field("[geocoords][0]").unwrap(),
        Some(Value::Integer(4))
    );
    assert_eq!(
        coords.get_field("geocoords").unwrap(),
        Some(Value::Array(vec![Value::Integer(2)]))
    );
}

#[test]
fn string_interpolation_test() {
    let stamp = DateTime::parse_from_rfc3339("2015-10-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let mut event = Event::at(stamp);
    event.set_field("bar", Value::from("foo")).unwrap();
    event.set_field("awesome", Value::from("logstash")).unwrap();
    let mut inner = Map::new();
    inner.insert("k1", Value::from("v"));
    event.set_field("j", Value::Map(inner)).unwrap();

    assert_eq!(
        event.sprintf("/full/path/awesome").unwrap(),
        "/full/path/awesome"
    );
    assert_eq!(
        event.sprintf("/full/%{bar}/awesome").unwrap(),
        "/full/foo/awesome"
    );
    assert_eq!(
        event.sprintf("/full/%{bar}/%{awesome}").unwrap(),
        "/full/foo/logstash"
    );
    assert_eq!(
        event.sprintf("/full/%{do-not-exist}").unwrap(),
        "/full/%{do-not-exist}"
    );
    assert_eq!(event.sprintf("/full/%{+YYYY}").unwrap(), "/full/2015");
    assert_eq!(
        event.sprintf("/full/%{+YYYY}/weeee/%{bar}").unwrap(),
        "/full/2015/weeee/foo"
    );
    assert_eq!(
        event.sprintf("/full/%{{YYYY-DDD}}/weeee/%{bar}").unwrap(),
        "/full/2015-274/weeee/foo"
    );
    assert_eq!(
        event.sprintf("/full/%{+YYY/web").unwrap(),
        "/full/%{+YYY/web"
    );
    assert_eq!(event.sprintf("%{+YYYY}").unwrap(), "2015");
    assert_eq!(event.sprintf("%{{YYYY-'W'ww}}").unwrap(), "2015-W40");
    assert_eq!(event.sprintf("%{[j][k1]}").unwrap(), "v");
    assert_eq!(event.sprintf("%{+%ss}").unwrap(), "%00");
    assert_eq!(event.sprintf("%{+%s}").unwrap(), "1443657600");
    event
        .set_field(
            "message",
            Value::Array(vec![Value::from("Hello"), Value::from("world")]),
        )
        .unwrap();
    assert_eq!(event.sprintf("%{message}").unwrap(), "Hello,world");
    assert_eq!(event.sprintf("%{j}").unwrap(), "{\"k1\":\"v\"}");
    assert!(event.sprintf("%{{BAD_TIME_NOW}}").is_err());

    let before = {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        DateTime::from_timestamp(elapsed.as_secs() as i64, elapsed.subsec_nanos()).unwrap()
    };
    thread::sleep(Duration::from_millis(5));
    let fresh = DateTime::parse_from_rfc3339(&event.sprintf("%{{TIME_NOW}}").unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert!(fresh > before);
}

#[test]
fn field_reference_test() {
    let single = parse_field("foo").unwrap();
    assert!(single.path.is_empty());
    assert_eq!(single.key, "foo");
    let bracket = parse_field("[foo]").unwrap();
    assert!(bracket.path.is_empty());
    assert_eq!(bracket.key, "foo");
    let two = parse_field("[foo][bar]").unwrap();
    assert_eq!(two.path, vec!["foo".to_string()]);
    assert_eq!(two.key, "bar");
    let three = parse_field("[foo][bar][baz]").unwrap();
    assert_eq!(three.path, vec!["foo".to_string(), "bar".to_string()]);
    assert_eq!(three.key, "baz");
    let embedded = parse_field("[[foo]][bar]").unwrap();
    assert_eq!(embedded.path, vec!["foo".to_string()]);
    assert_eq!(embedded.key, "bar");
    let deep = parse_field("[[foo][bar]][baz]").unwrap();
    assert_eq!(deep.path, vec!["foo".to_string(), "bar".to_string()]);
    assert_eq!(deep.key, "baz");
    let meta = parse_field("[@metadata]").unwrap();
    assert!(meta.path.is_empty());
    assert_eq!(meta.key, "@metadata");
    assert_eq!(meta.target, Target::MetadataRoot);
    let meta_child = parse_field("[@metadata][nested][field]").unwrap();
    assert_eq!(meta_child.path, vec!["nested".to_string()]);
    assert_eq!(meta_child.key, "field");
    assert_eq!(meta_child.target, Target::Metadata);
    assert_eq!(
        parse_field("@timestamp").unwrap(),
        parse_field("[@timestamp]").unwrap()
    );
    assert!(same_interned_field("@timestamp", "[@timestamp]").unwrap());
    assert!(same_interned_field("", "").unwrap());
    assert_eq!(field_cache_len_after_distinct(10_001).unwrap(), 10_000);
    let empty = parse_field("").unwrap();
    assert_eq!(empty.key, "");

    for bad in [
        "[[foo][bar]nope][baz]",
        "[nope[foo][bar]][baz]",
        "[foo][bar][baz",
        "foo[bar][baz]",
        "[foo]bar[baz]",
        "[",
        "]",
        "[[[[[[[[[[[]",
        "[foo]][bar]",
        "[this[is]terrible]",
        "[this[is]terrible][and][it[should-not[work]]]",
        "this[index]",
    ] {
        assert!(parse_field(bad).is_err(), "{bad}");
    }

    let percent = parse_field_escaped("[foo][bar%5Bbingo%5D][okay]", FieldEscape::Percent).unwrap();
    assert_eq!(
        percent.path,
        vec!["foo".to_string(), "bar[bingo]".to_string()]
    );
    assert_eq!(percent.key, "okay");
    let percent_key =
        parse_field_escaped("[foo][okay][bar%5Bbingo%5D]", FieldEscape::Percent).unwrap();
    assert_eq!(percent_key.key, "bar[bingo]");
    let percent_literal = parse_field_escaped("[foo][bar][95%]", FieldEscape::Percent).unwrap();
    assert_eq!(percent_literal.key, "95%");

    let amp =
        parse_field_escaped("[foo][bar&#91;bingo&#93;][okay]", FieldEscape::Ampersand).unwrap();
    assert_eq!(amp.path[1], "bar[bingo]");
    assert_eq!(amp.key, "okay");
    let amp_key =
        parse_field_escaped("[foo][okay][bar&#91;bingo&#93;]", FieldEscape::Ampersand).unwrap();
    assert_eq!(amp_key.key, "bar[bingo]");
    let amp_literal = parse_field_escaped("[foo][bar][this&that]", FieldEscape::Ampersand).unwrap();
    assert_eq!(amp_literal.key, "this&that");
}

#[test]
fn string_escape_spec() {
    let cases = [
        ("\\\"", "\""),
        ("\\'", "'"),
        ("\\n", "\n"),
        ("\\r", "\r"),
        ("\\t", "\t"),
        ("\\\\", "\\"),
        ("\\0", "\u{0}"),
    ];
    for (input, expected) in cases {
        assert_eq!(process_string_escapes(input), expected, "{input:?}");
    }
}
