//! Official plugin specs for the gems shipped with Logstash 9.5.2.
//!
//! Sources, at the versions in the 9.5.2 distribution:
//! `logstash-codec-plain` 3.1.0 `spec/codecs/plain_spec.rb`,
//! `logstash-codec-line` 3.1.1 `spec/codecs/line_spec.rb`,
//! `logstash-filter-drop` 3.0.5 `spec/filters/drop_spec.rb`,
//! `logstash-input-generator` 3.1.0 `spec/inputs/generator_spec.rb`,
//! `logstash-output-stdout` 3.1.4 `spec/outputs/stdout_spec.rb`,
//! `logstash-filter-mutate` 3.6.0 `spec/filters/mutate_spec.rb`,
//! plus `runner_spec.rb` `--config.test_and_exit` and `-w`,
//! `multi_local_spec.rb`, and `java_pipeline_spec.rb`
//! "should not propagate cancelled events from filter to output".

use rstash::{
    Ecs, Event, Settings, TextCodec, Value, apply_filter, cli::execute, load_pipelines_yml, run,
};
use std::time::Duration;

fn one_worker(ecs: Ecs) -> Settings {
    Settings {
        workers: 1,
        batch_size: 125,
        batch_delay: Duration::from_millis(50),
        ecs,
        test_and_exit: false,
        stdin: None,
        workers_set: false,
    }
}

fn filter_json(config: &str, json: &str) -> Event {
    let mut event = Event::from_json(json)
        .unwrap_or_else(|error| panic!("{error}"))
        .into_iter()
        .next()
        .expect("event");
    apply_filter(config, &mut event).unwrap_or_else(|error| panic!("{error}"));
    event
}

fn field(event: &Event, name: &str) -> Option<Value> {
    event.get_field(name).expect("field")
}

#[test]
fn plain_spec_decode_and_encode() {
    for ecs in [Ecs::Disabled, Ecs::V1, Ecs::V8] {
        let mut codec = TextCodec::plain(ecs);
        let events = codec.decode(b"Testing decoding.").expect("decode");
        assert_eq!(events.len(), 1);
        assert_eq!(
            field(&events[0], "message"),
            Some(Value::from("Testing decoding."))
        );
        if ecs != Ecs::Disabled {
            assert_eq!(
                field(&events[0], "[event][original]"),
                Some(Value::from("Testing decoding."))
            );
        } else {
            assert_eq!(field(&events[0], "[event][original]"), None);
        }
    }

    let mut codec = TextCodec::plain(Ecs::Disabled);
    for data in ["foobar", "κόσμε"] {
        let event = codec.decode(data.as_bytes()).expect("utf8").remove(0);
        assert_eq!(field(&event, "message"), Some(Value::from(data)));
    }

    let invalid = [b"foo \xED\xB9\x81\xC3".as_slice(), b"bar \xAD".as_slice()];
    let expected = ["foo \\xED\\xB9\\x81\\xC3", "bar \\xAD"];
    for (data, message) in invalid.iter().zip(expected) {
        let event = codec.decode(data).expect("invalid").remove(0);
        assert_eq!(field(&event, "message"), Some(Value::from(message)));
    }

    codec.charset = "ISO-8859-1".to_string();
    let latin1 = [0xE0, b' ', b'M', b'o', b'n', b't', b'r', 0xE9, b'a', b'l'];
    let event = codec.decode(&latin1).expect("latin1").remove(0);
    assert_eq!(field(&event, "message"), Some(Value::from("à Montréal")));

    codec.charset = "ASCII-8BIT".to_string();
    let event = codec.decode(&latin1).expect("binary").remove(0);
    assert_eq!(field(&event, "message"), Some(Value::from("� Montr�al")));
    let greek = [0xCE, 0xBA, 0xCF, 0x8C, 0xCF, 0x83, 0xCE, 0xBC, 0xCE, 0xB5];
    let event = codec.decode(&greek).expect("greek").remove(0);
    assert_eq!(field(&event, "message"), Some(Value::from("����������")));

    let event = Event::from_json(r#"{"message":"Hello World."}"#)
        .unwrap()
        .remove(0);
    codec.charset = "UTF-8".to_string();
    assert_eq!(codec.encode(&event).unwrap(), event.plain_string());

    codec.format = Some("%{[hello]} %{[something][fancy]}".to_string());
    let event = Event::from_json(r#"{"hello":"world","something":{"fancy":123}}"#)
        .unwrap()
        .remove(0);
    assert_eq!(codec.encode(&event).unwrap(), "world 123");
}

#[test]
fn line_spec_decode_and_encode() {
    let mut codec = TextCodec::line(Ecs::Disabled);
    let event = Event::from_json(r#"{"message":"hello world","host":"test"}"#)
        .unwrap()
        .remove(0);
    assert_eq!(
        codec.encode(&event).unwrap(),
        format!("{}\n", event.plain_string())
    );
    codec.format = Some("%{host}".to_string());
    assert_eq!(codec.encode(&event).unwrap(), "test\n");
    codec.format = None;
    codec.delimiter = "|".to_string();
    assert_eq!(
        codec.encode(&event).unwrap(),
        format!("{}|", event.plain_string())
    );

    codec.delimiter = "\n".to_string();
    let decoded = codec.decode(b"hello world\n").unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(
        field(&decoded[0], "message"),
        Some(Value::from("hello world"))
    );

    for ecs in [Ecs::V1, Ecs::V8] {
        let mut ecs_codec = TextCodec::line(ecs);
        let decoded = ecs_codec.decode("München\n".as_bytes()).unwrap();
        assert_eq!(field(&decoded[0], "message"), Some(Value::from("München")));
        assert_eq!(
            field(&decoded[0], "[event][original]"),
            Some(Value::from("München"))
        );
    }

    let mut custom = TextCodec::line(Ecs::Disabled);
    custom.delimiter = "|".to_string();
    let mut result = custom.decode(b"line1\nline2\nline3\n").unwrap();
    result.extend(custom.flush().unwrap());
    assert_eq!(result.len(), 1);
    assert_eq!(
        field(&result[0], "message"),
        Some(Value::from("line1\nline2\nline3\n"))
    );
    let mut result = custom.decode(b"line1|line2|line3|").unwrap();
    result.extend(custom.flush().unwrap());
    assert_eq!(result.len(), 3);
    assert_eq!(field(&result[0], "message"), Some(Value::from("line1")));
    assert_eq!(field(&result[1], "message"), Some(Value::from("line2")));
    assert_eq!(field(&result[2], "message"), Some(Value::from("line3")));

    let mut codec = TextCodec::line(Ecs::Disabled);
    assert!(codec.decode(&[0xD0]).unwrap().is_empty());
    let flushed = codec.flush().unwrap();
    assert_eq!(flushed.len(), 1);
    assert_eq!(field(&flushed[0], "message"), Some(Value::from("\\xD0")));
}

#[test]
fn drop_spec() {
    let mut event = Event::from_json(r#"{"message":"hello"}"#)
        .unwrap()
        .remove(0);
    apply_filter("filter { drop { } }", &mut event).unwrap();
    assert!(event.is_cancelled());

    let mut event = Event::from_json(r#"{"message":"hello"}"#)
        .unwrap()
        .remove(0);
    apply_filter("filter { drop { percentage => 0 } }", &mut event).unwrap();
    assert!(!event.is_cancelled());
}

#[test]
fn generator_spec_message_and_stdin() {
    for ecs in [Ecs::Disabled, Ecs::V1, Ecs::V8] {
        let sequence = if ecs == Ecs::Disabled {
            "sequence"
        } else {
            "[event][sequence]"
        };
        let mut settings = one_worker(ecs);
        let result = run(
            r#"input { generator { count => 2 message => "foo" } } output { stdout { codec => plain } }"#,
            &settings,
        )
        .unwrap();
        assert!(
            result
                .events
                .iter()
                .all(|event| { field(event, "message") == Some(Value::from("foo")) })
        );
        let mut sequences: Vec<i128> = result
            .events
            .iter()
            .map(|event| match field(event, sequence) {
                Some(Value::Integer(number)) => number,
                other => panic!("sequence {other:?}"),
            })
            .collect();
        sequences.sort();
        assert_eq!(sequences, vec![0, 1]);

        settings.stdin = Some("bar".to_string());
        let result = run(
            r#"input { generator { count => 2 message => "stdin" } } output { stdout { codec => plain } }"#,
            &settings,
        )
        .unwrap();
        assert!(
            result
                .events
                .iter()
                .all(|event| { field(event, "message") == Some(Value::from("bar")) })
        );
        let mut sequences: Vec<i128> = result
            .events
            .iter()
            .map(|event| match field(event, sequence) {
                Some(Value::Integer(number)) => number,
                other => panic!("sequence {other:?}"),
            })
            .collect();
        sequences.sort();
        assert_eq!(sequences, vec![0, 1]);
    }
}

#[test]
fn stdout_spec_writes_the_encoded_payload() {
    let result = run(
        r#"input { generator { count => 1 message => "This is a message!" } } output { stdout { codec => plain } }"#,
        &one_worker(Ecs::V8),
    )
    .unwrap();
    let encoded: String = result
        .events
        .iter()
        .map(|event| TextCodec::plain(Ecs::V8).encode(event).unwrap())
        .collect();
    assert_eq!(result.stdout, encoded);
}

#[test]
fn java_pipeline_spec_does_not_propagate_cancelled_events() {
    let result = run(
        r#"
        input { generator { lines => ["1", "2", "END"] count => 1 } }
        filter {
          if [message] == "1" { drop { } }
          mutate { add_tag => ["notdropped"] }
        }
        output { stdout { codec => plain } }
        "#,
        &one_worker(Ecs::V8),
    )
    .unwrap();
    assert_eq!(result.events.len(), 2);
    assert!(
        result
            .events
            .iter()
            .any(|event| { field(event, "message") == Some(Value::from("END")) })
    );
    for event in &result.events {
        match field(event, "tags") {
            Some(Value::Array(tags)) => assert!(tags.contains(&Value::from("notdropped"))),
            other => panic!("tags {other:?}"),
        }
    }
}

#[test]
fn runner_spec_config_test_and_exit_and_workers() {
    let mut out = Vec::new();
    let code = execute(
        &[
            "-t".into(),
            "-e".into(),
            "input { } filter { } output { }".into(),
        ],
        &mut out,
    )
    .expect("good config");
    assert_eq!(code, 0);

    let error = execute(
        &["-t".into(), "-e".into(), "rlwekjhrewlqrkjh".into()],
        &mut Vec::new(),
    );
    assert!(error.is_err());

    let error = execute(
        &[
            "-t".into(),
            "-e".into(),
            "input { } output { if [[f[[[oo] == [bar] { } }".into(),
        ],
        &mut Vec::new(),
    );
    assert!(error.is_err());

    let error = execute(
        &[
            "-e".into(),
            "input { generator { count => 1 } } output { stdout { codec => plain } }".into(),
            "-w".into(),
        ],
        &mut Vec::new(),
    );
    assert!(error.is_err());

    let mut out = Vec::new();
    let code = execute(
        &[
            "-w".into(),
            "2".into(),
            "-e".into(),
            "input { generator { count => 1 } } output { stdout { codec => plain } }".into(),
        ],
        &mut out,
    )
    .expect("workers");
    assert_eq!(code, 0);
}

#[test]
fn multi_local_spec_pipelines_yml() {
    let error = load_pipelines_yml(
        "- pipeline.id: main\n  config.string: input {} output {}\n- pipeline.id: main\n  config.string: input {} output {}\n",
    );
    assert!(error.is_err());

    let loaded = load_pipelines_yml(
        "- pipeline.id: main\n  config.string: input {} output {}\n- pipeline.id: backup\n  config.string: input {} output {}\n",
    )
    .unwrap();
    assert_eq!(loaded.len(), 2);

    let error =
        load_pipelines_yml("- pipeline.id: main\n  config.string: \"\"\n  api.http.port: 22222\n");
    let message = error.expect_err("non pipeline setting").to_string();
    assert!(message.contains("Only pipeline related settings are expected"));

    load_pipelines_yml(
        "- pipeline.id: main\n  path.dead_letter_queue: /tmp\n  dead_letter_queue.max_bytes: 10000\n  config.string: input {} output {}\n",
    )
    .expect("dead letter queue settings are pipeline settings");

    let error = load_pipelines_yml("# blah\n# blah\n");
    assert!(
        error
            .unwrap_err()
            .to_string()
            .contains("Pipelines YAML file is empty")
    );
}

#[test]
fn mutate_spec_case_strip_split_copy_and_failure_tag() {
    let event = filter_json(
        r#"filter { mutate { uppercase => ["array_of"] } }"#,
        r#"{"array_of":["a",2,"C"]}"#,
    );
    assert_eq!(
        field(&event, "array_of"),
        Some(Value::Array(vec![
            Value::from("A"),
            Value::Integer(2),
            Value::from("C")
        ]))
    );
    let event = filter_json(
        r#"filter { mutate { capitalize => ["array_of"] } }"#,
        r#"{"array_of":["ab",2,"CDE"]}"#,
    );
    assert_eq!(
        field(&event, "array_of"),
        Some(Value::Array(vec![
            Value::from("Ab"),
            Value::Integer(2),
            Value::from("Cde")
        ]))
    );
    let event = filter_json(
        r#"filter { mutate { lowercase => ["array_of"] } }"#,
        r#"{"array_of":["a",2,"C"]}"#,
    );
    assert_eq!(
        field(&event, "array_of"),
        Some(Value::Array(vec![
            Value::from("a"),
            Value::Integer(2),
            Value::from("c")
        ]))
    );
    for operation in ["lowercase", "uppercase", "capitalize"] {
        let event = filter_json(
            &format!("filter {{ mutate {{ {operation} => [\"fake_field\"] }} }}"),
            r#"{}"#,
        );
        assert_eq!(field(&event, "fake_field"), None);
    }

    let event = filter_json(
        r#"filter { mutate { strip => ["path"] } }"#,
        r#"{"path":" /store.php "}"#,
    );
    assert_eq!(field(&event, "path"), Some(Value::from("/store.php")));

    let event = filter_json(
        r#"filter { mutate { split => { "field" => "," } } }"#,
        r#"{"field":"foo,bar,baz"}"#,
    );
    assert_eq!(
        field(&event, "field"),
        Some(Value::Array(vec![
            Value::from("foo"),
            Value::from("bar"),
            Value::from("baz")
        ]))
    );
    let event = filter_json(
        r#"filter { mutate { split => { "field" => "," } } }"#,
        r#"{"field":"foo,"}"#,
    );
    assert_eq!(
        field(&event, "field"),
        Some(Value::Array(vec![Value::from("foo")]))
    );

    let event = filter_json(
        r#"filter { mutate { copy => { "field" => "target" } } }"#,
        r#"{"field":"foobar"}"#,
    );
    assert_eq!(field(&event, "target"), field(&event, "field"));

    let mut event = Event::from_json(r#"{"message":"foo"}"#).unwrap().remove(0);
    apply_filter(
        r#"filter { mutate { add_field => { "[[][[[[]message" => "nope" } } }"#,
        &mut event,
    )
    .unwrap();
    match field(&event, "tags") {
        Some(Value::Array(tags)) => assert!(tags.contains(&Value::from("_mutate_error"))),
        other => panic!("tags {other:?}"),
    }
}

#[test]
fn mutate_spec_convert_rename_gsub_merge_coerce() {
    let error = apply_filter(
        r#"filter { mutate { convert => [ "message", "int" ] } }"#,
        &mut Event::new(),
    );
    assert!(
        error
            .unwrap_err()
            .to_string()
            .contains("Invalid conversion type")
    );

    let error = apply_filter(
        r#"filter { mutate { gsub => [ "message", "toreplace" ] } }"#,
        &mut Event::new(),
    );
    assert!(
        error
            .unwrap_err()
            .to_string()
            .contains("Invalid gsub configuration")
    );

    let event = filter_json(
        r#"filter { mutate { convert => [ "unicorns", "string" ] } }"#,
        r#"{"unicorns":1234}"#,
    );
    assert_eq!(field(&event, "unicorns"), Some(Value::from("1234")));

    let event = filter_json(
        r#"
        filter {
          mutate {
            convert => { "true_field" => "boolean" }
            convert => { "false_field" => "boolean" }
            convert => { "wrong_field" => "boolean" }
            convert => { "integer_true" => "boolean" }
            convert => { "integer_false" => "boolean" }
            convert => { "integer_negative" => "boolean" }
            convert => { "float_true" => "boolean" }
            convert => { "float_wrong" => "boolean" }
            convert => { "array" => "boolean" }
            convert => { "hash" => "boolean" }
          }
        }
        "#,
        r#"{
          "true_field":"true","false_field":"false","wrong_field":"none of the above",
          "integer_true":1,"integer_false":0,"integer_negative":-1,
          "float_true":1.0,"float_wrong":1.0123,
          "array":["1","0",0,1,2],"hash":{"a":0}
        }"#,
    );
    assert_eq!(field(&event, "true_field"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "false_field"), Some(Value::Boolean(false)));
    assert_eq!(
        field(&event, "wrong_field"),
        Some(Value::from("none of the above"))
    );
    assert_eq!(field(&event, "integer_true"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "integer_false"), Some(Value::Boolean(false)));
    assert_eq!(field(&event, "integer_negative"), Some(Value::Integer(-1)));
    assert_eq!(field(&event, "float_true"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "float_wrong"), Some(Value::Float(1.0123)));
    assert_eq!(
        field(&event, "array"),
        Some(Value::Array(vec![
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Boolean(false),
            Value::Boolean(true),
            Value::Integer(2),
        ]))
    );
    assert_eq!(field(&event, "[hash][a]"), Some(Value::Integer(0)));

    let event = filter_json(
        r#"filter { mutate { convert => { "field" => "float" } } }"#,
        r#"{"field":"3,141.5926"}"#,
    );
    match field(&event, "field") {
        Some(Value::Float(number)) => assert!((number - 3141.5926).abs() < 0.0001),
        other => panic!("{other:?}"),
    }

    let event = filter_json(
        r#"filter { mutate { convert => { "field" => "float_eu" } } }"#,
        r#"{"field":"3.141,5926"}"#,
    );
    match field(&event, "field") {
        Some(Value::Float(number)) => assert!((number - 3141.5926).abs() < 0.0001),
        other => panic!("{other:?}"),
    }

    let event = filter_json(
        r#"filter { mutate { gsub => [ "unicorns", "but extinct", "and common" ] } }"#,
        r#"{"unicorns":"Magnificient, but extinct, animals"}"#,
    );
    assert_eq!(
        field(&event, "unicorns"),
        Some(Value::from("Magnificient, and common, animals"))
    );
    let event = filter_json(
        r#"filter { mutate { gsub => [ "colors", "\d$", "blue" ] } }"#,
        r#"{"colors":"red3"}"#,
    );
    assert_eq!(field(&event, "colors"), Some(Value::from("redblue")));

    let event = filter_json(
        r#"filter { mutate { rename => [ "nosuchfield", "hello" ] } }"#,
        r#"{"message":"whatever"}"#,
    );
    assert_eq!(field(&event, "hello"), None);

    let event = filter_json(
        r#"filter { mutate { rename => [ "field_%{x}", "destination" ] } }"#,
        r#"{"field_one":"value","x":"one"}"#,
    );
    assert_eq!(field(&event, "field_one"), None);
    assert_eq!(field(&event, "destination"), Some(Value::from("value")));

    let event = filter_json(
        r#"filter { mutate { convert => [ "[foo][bar]", "integer" ] } }"#,
        r#"{"foo":{"bar":"1000"}}"#,
    );
    assert_eq!(field(&event, "[foo][bar]"), Some(Value::Integer(1000)));

    let event = filter_json(
        r#"filter { mutate { convert => [ "[foo][0]", "integer", "[foo][1]", "integer", "[foo][2]", "integer" ] } }"#,
        r#"{"foo":["1,000","1,234,567.8","123.4"]}"#,
    );
    assert_eq!(field(&event, "[foo][0]"), Some(Value::Integer(1000)));
    assert_eq!(field(&event, "[foo][1]"), Some(Value::Integer(1234567)));
    assert_eq!(field(&event, "[foo][2]"), Some(Value::Integer(123)));

    let event = filter_json(
        r#"filter { mutate { convert => [ "[foo][0]", "integer_eu", "[foo][1]", "integer_eu", "[foo][2]", "integer_eu" ] } }"#,
        r#"{"foo":["1.000","1.234.567,8","123,4"]}"#,
    );
    assert_eq!(field(&event, "[foo][0]"), Some(Value::Integer(1000)));
    assert_eq!(field(&event, "[foo][1]"), Some(Value::Integer(1234567)));
    assert_eq!(field(&event, "[foo][2]"), Some(Value::Integer(123)));

    let event = filter_json(
        r#"filter { mutate { convert => { "a" => "integer" } } }"#,
        r#"{"a":"0x7b"}"#,
    );
    assert_eq!(field(&event, "a"), Some(Value::Integer(123)));
    let event = filter_json(
        r#"filter { mutate { convert => { "a" => "integer" } } }"#,
        r#"{"a":"0x1.edcdp6"}"#,
    );
    assert_eq!(field(&event, "a"), Some(Value::Integer(123)));
    let event = filter_json(
        r#"filter { mutate { convert => { "a" => "float" } } }"#,
        r#"{"a":"0x1.edcdp6"}"#,
    );
    match field(&event, "a") {
        Some(Value::Float(number)) => assert!((number - 123.4501953125).abs() < 1e-9),
        other => panic!("{other:?}"),
    }
    let event = filter_json(
        r#"filter { mutate { convert => { "a" => "integer" } } }"#,
        r#"{"a":"9223372036854775808"}"#,
    );
    assert_eq!(
        field(&event, "a"),
        Some(Value::Integer(9223372036854775808))
    );

    let event = filter_json(
        r#"filter { mutate { merge => [ "list", "foo" ] } }"#,
        r#"{"foo":"bar"}"#,
    );
    assert_eq!(
        field(&event, "list"),
        Some(Value::Array(vec![Value::from("bar")]))
    );
    let event = filter_json(
        r#"filter { mutate { merge => [ "list", "foo" ] } }"#,
        r#"{"foo":"bar","list":["baz"]}"#,
    );
    assert_eq!(
        field(&event, "list"),
        Some(Value::Array(vec![Value::from("baz"), Value::from("bar")]))
    );

    let event = filter_json(
        r#"
        filter {
          mutate {
            coerce => { "field1" => "Hello" "field2" => "Bye" "field3" => 5 "field4" => false }
          }
        }
        "#,
        r#"{"field1":null,"field2":null,"field3":null,"field4":true}"#,
    );
    assert_eq!(field(&event, "field1"), Some(Value::from("Hello")));
    assert_eq!(field(&event, "field2"), Some(Value::from("Bye")));
    assert_eq!(field(&event, "field3"), Some(Value::from("5")));
    assert_eq!(field(&event, "field4"), Some(Value::Boolean(true)));

    let event = filter_json(
        r#"
        filter {
          mutate {
            lowercase => ["lowerme", "Lowerme", "lowerMe"]
            uppercase => ["upperme", "Upperme", "upperMe"]
            capitalize => ["capitalizeme", "Capitalizeme", "capitalizeMe"]
            convert => [ "intme", "integer", "floatme", "float" ]
            rename => [ "rename1", "rename2" ]
            replace => [ "replaceme", "hello world" ]
            replace => [ "newfield", "newnew" ]
            update => [ "nosuchfield", "weee" ]
            update => [ "updateme", "updated" ]
          }
        }
        "#,
        r#"{
          "lowerme":"example","upperme":"EXAMPLE","capitalizeme":"Example",
          "Lowerme":"ExAmPlE","Upperme":"ExAmPlE","Capitalizeme":"ExAmPlE",
          "lowerMe":["ExAmPlE","example"],"upperMe":["ExAmPlE","EXAMPLE"],
          "capitalizeMe":["ExAmPlE","Example"],
          "intme":["1234","7890.4","7.9"],"floatme":["1234.455"],
          "rename1":["hello world"],"updateme":["who cares"],"replaceme":["who cares"]
        }"#,
    );
    assert_eq!(field(&event, "lowerme"), Some(Value::from("example")));
    assert_eq!(field(&event, "Lowerme"), Some(Value::from("example")));
    assert_eq!(
        field(&event, "lowerMe"),
        Some(Value::Array(vec![
            Value::from("example"),
            Value::from("example")
        ]))
    );
    assert_eq!(field(&event, "upperme"), Some(Value::from("EXAMPLE")));
    assert_eq!(field(&event, "rename1"), None);
    assert_eq!(
        field(&event, "rename2"),
        Some(Value::Array(vec![Value::from("hello world")]))
    );
    assert_eq!(field(&event, "newfield"), Some(Value::from("newnew")));
    assert_eq!(field(&event, "nosuchfield"), None);
    assert_eq!(field(&event, "updateme"), Some(Value::from("updated")));
    assert_eq!(field(&event, "replaceme"), Some(Value::from("hello world")));
    match field(&event, "intme") {
        Some(Value::Array(items)) => {
            assert_eq!(items[0], Value::Integer(1234));
            assert_eq!(items[1], Value::Integer(7890));
            assert_eq!(items[2], Value::Integer(7));
        }
        other => panic!("{other:?}"),
    }
    match field(&event, "floatme") {
        Some(Value::Array(items)) => match &items[0] {
            Value::Float(number) => assert!((number - 1234.455).abs() < 0.0001),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }

    let event = filter_json(
        r#"
        filter {
          mutate {
            lowercase => ["lowerme"]
            uppercase => ["upperme"]
            capitalize => ["capitalizeme"]
          }
        }
        "#,
        "{\"lowerme\":[\"АБВГД\\u0000MMM\",\"こにちわ\",\"XyZółć\",\"NÎcË GÛŸ\"],\"upperme\":[\"аБвгд\\u0000mmm\",\"こにちわ\",\"xYzółć\",\"Nîcë gûÿ\"],\"capitalizeme\":[\"АБВГД\\u0000mmm\",\"こにちわ\",\"xyzółć\",\"nÎcË gÛŸ\"]}",
    );
    assert_eq!(
        field(&event, "lowerme"),
        Some(Value::Array(vec![
            Value::from("абвгд\u{0}mmm"),
            Value::from("こにちわ"),
            Value::from("xyzółć"),
            Value::from("nîcë gûÿ"),
        ]))
    );
    assert_eq!(
        field(&event, "upperme"),
        Some(Value::Array(vec![
            Value::from("АБВГД\u{0}MMM"),
            Value::from("こにちわ"),
            Value::from("XYZÓŁĆ"),
            Value::from("NÎCË GÛŸ"),
        ]))
    );
    assert_eq!(
        field(&event, "capitalizeme"),
        Some(Value::Array(vec![
            Value::from("Абвгд\u{0}mmm"),
            Value::from("こにちわ"),
            Value::from("Xyzółć"),
            Value::from("Nîcë gûÿ"),
        ]))
    );
}
