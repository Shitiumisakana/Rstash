//! Remaining samples from `logstash-filter-mutate` 3.6.0 `spec/filters/mutate_spec.rb`
//! and `spec/filters/integration/multi_stage_spec.rb`.
//!
//! Each row is one official `sample` or `it`. Expected values are the ones written
//! in that file. Numbers bigger than `i128` stay exact decimal text.

use rstash::{Event, Map, Value, apply_filter, parse_signed_hex_str};

fn field(event: &Event, name: &str) -> Option<Value> {
    event.get_field(name).expect("field")
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

fn includes(event: &Event, name: &str) -> bool {
    event.includes(name).expect("includes")
}

#[test]
fn mutate_spec_custom_failure_tag() {
    let mut event = Event::from_json(r#"{"message":"foo"}"#).unwrap().remove(0);
    apply_filter(
        r#"filter { mutate { tag_on_failure => "my_custom_tag" add_field => { "[[][[[[]message" => "nope" } } }"#,
        &mut event,
    )
    .unwrap();
    match field(&event, "tags") {
        Some(Value::Array(tags)) => assert!(tags.contains(&Value::from("my_custom_tag"))),
        other => panic!("tags {other:?}"),
    }
}

#[test]
fn mutate_spec_case_does_not_mutate_a_shared_string() {
    for (operation, cased) in [
        ("lowercase", "original value"),
        ("uppercase", "ORIGINAL VALUE"),
        ("capitalize", "Original value"),
    ] {
        let original = "oRiGiNaL vAlUe".to_string();
        let mut event = Event::new();
        event
            .set_field("field", Value::from(original.as_str()))
            .unwrap();
        apply_filter(
            &format!(r#"filter {{ mutate {{ {operation} => "field" }} }}"#),
            &mut event,
        )
        .unwrap();
        assert_eq!(original, "oRiGiNaL vAlUe", "{operation}");
        assert_eq!(
            field(&event, "field"),
            Some(Value::from(cased)),
            "{operation}"
        );
    }
}

#[test]
fn mutate_spec_strip_two_fields() {
    let event = filter_json(
        r#"filter { mutate { strip => ["foo", "bar"] } }"#,
        r#"{"foo":" /bar.php ","bar":" foo"}"#,
    );
    assert_eq!(field(&event, "foo"), Some(Value::from("/bar.php")));
    assert_eq!(field(&event, "bar"), Some(Value::from("foo")));
}

#[test]
fn mutate_spec_split_leaves_nil_array_and_hash() {
    let event = filter_json(
        r#"filter { mutate { split => { "field" => "," } } }"#,
        r#"{"field":null}"#,
    );
    assert_eq!(field(&event, "field"), None);

    let event = filter_json(
        r#"filter { mutate { split => { "field" => "," } } }"#,
        r#"{"field":["foo","bar"]}"#,
    );
    assert_eq!(
        field(&event, "field"),
        Some(Value::Array(vec![Value::from("foo"), Value::from("bar")]))
    );

    let event = filter_json(
        r#"filter { mutate { split => { "field" => "," } } }"#,
        r#"{"field":{"foo":"bar,baz"}}"#,
    );
    let mut map = Map::new();
    map.insert("foo", Value::from("bar,baz"));
    assert_eq!(field(&event, "field"), Some(Value::Map(map)));
}

#[test]
fn mutate_spec_copy_string_array_and_hash_stay_independent() {
    let mut event = filter_json(
        r#"filter { mutate { copy => { "field" => "target" } } }"#,
        r#"{"field":"foobar"}"#,
    );
    event.set_field("field", Value::Null).unwrap();
    assert_eq!(field(&event, "target"), Some(Value::from("foobar")));
    assert_eq!(field(&event, "field"), None);

    let mut event = filter_json(
        r#"filter { mutate { copy => { "field" => "target" } } }"#,
        r#"{"field":["foo","bar"]}"#,
    );
    event
        .set_field(
            "field",
            Value::Array(vec![
                Value::from("foo"),
                Value::from("bar"),
                Value::from("baz"),
            ]),
        )
        .unwrap();
    assert_eq!(
        field(&event, "target"),
        Some(Value::Array(vec![Value::from("foo"), Value::from("bar")]))
    );
    assert_ne!(field(&event, "target"), field(&event, "field"));

    let mut event = filter_json(
        r#"filter { mutate { copy => { "field" => "target" } } }"#,
        r#"{"field":{"foo":"bar"}}"#,
    );
    event.set_field("[field][foo]", Value::from("baz")).unwrap();
    assert_eq!(field(&event, "[target][foo]"), Some(Value::from("bar")));
    assert_ne!(
        field(&event, "[target][foo]"),
        field(&event, "[field][foo]")
    );
}

#[test]
fn mutate_spec_convert_strings_to_boolean_values() {
    let event = filter_json(
        r#"
        filter {
          mutate {
            convert => { "true_field" => "boolean" }
            convert => { "false_field" => "boolean" }
            convert => { "true_upper" => "boolean" }
            convert => { "false_upper" => "boolean" }
            convert => { "true_one" => "boolean" }
            convert => { "false_zero" => "boolean" }
            convert => { "true_yes" => "boolean" }
            convert => { "false_no" => "boolean" }
            convert => { "true_y" => "boolean" }
            convert => { "false_n" => "boolean" }
            convert => { "wrong_field" => "boolean" }
            convert => { "integer_false" => "boolean" }
            convert => { "integer_true" => "boolean" }
            convert => { "integer_negative" => "boolean" }
            convert => { "integer_wrong" => "boolean" }
            convert => { "float_true" => "boolean" }
            convert => { "float_false" => "boolean" }
            convert => { "float_negative" => "boolean" }
            convert => { "float_wrong" => "boolean" }
            convert => { "float_wrong2" => "boolean" }
            convert => { "array" => "boolean" }
            convert => { "hash" => "boolean" }
          }
        }
        "#,
        r#"{
          "true_field":"true","false_field":"false","true_upper":"True","false_upper":"False",
          "true_one":"1","false_zero":"0","true_yes":"yes","false_no":"no","true_y":"Y","false_n":"N",
          "wrong_field":"none of the above",
          "integer_false":0,"integer_true":1,"integer_negative":-1,"integer_wrong":2,
          "float_true":1.0,"float_false":0.0,"float_negative":-1.0,"float_wrong":1.0123,"float_wrong2":0.01,
          "array":["1","0",0,1,2],"hash":{"a":0}
        }"#,
    );
    assert_eq!(field(&event, "true_field"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "false_field"), Some(Value::Boolean(false)));
    assert_eq!(field(&event, "true_upper"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "false_upper"), Some(Value::Boolean(false)));
    assert_eq!(field(&event, "true_one"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "false_zero"), Some(Value::Boolean(false)));
    assert_eq!(field(&event, "true_yes"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "false_no"), Some(Value::Boolean(false)));
    assert_eq!(field(&event, "true_y"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "false_n"), Some(Value::Boolean(false)));
    assert_eq!(
        field(&event, "wrong_field"),
        Some(Value::from("none of the above"))
    );
    assert_eq!(field(&event, "integer_false"), Some(Value::Boolean(false)));
    assert_eq!(field(&event, "integer_true"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "integer_negative"), Some(Value::Integer(-1)));
    assert_eq!(field(&event, "integer_wrong"), Some(Value::Integer(2)));
    assert_eq!(field(&event, "float_true"), Some(Value::Boolean(true)));
    assert_eq!(field(&event, "float_false"), Some(Value::Boolean(false)));
    assert_eq!(field(&event, "float_negative"), Some(Value::Float(-1.0)));
    assert_eq!(field(&event, "float_wrong"), Some(Value::Float(1.0123)));
    assert_eq!(field(&event, "float_wrong2"), Some(Value::Float(0.01)));
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
    let mut hash = Map::new();
    hash.insert("a", Value::Integer(0));
    assert_eq!(field(&event, "hash"), Some(Value::Map(hash)));
}

#[test]
#[allow(clippy::approx_constant)]
fn mutate_spec_convert_to_float_contexts() {
    let config = r#"filter { mutate { convert => { "field" => "float" } } }"#;
    assert!(near(
        number(filter_json(config, r#"{"field":"3141.5926"}"#), "field"),
        3141.5926,
        0.0001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":"3,141.5926"}"#), "field"),
        3141.5926,
        0.0001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":"3,141"}"#), "field"),
        3141.0,
        0.0001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":"3141"}"#), "field"),
        3141.0,
        0.0001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":3.1415926}"#), "field"),
        3.1415926,
        0.000001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":3}"#), "field"),
        3.0,
        0.000001
    ));
    assert_eq!(
        field(&filter_json(config, r#"{"field":true}"#), "field"),
        Some(Value::Float(1.0))
    );
    assert_eq!(
        field(&filter_json(config, r#"{"field":false}"#), "field"),
        Some(Value::Float(0.0))
    );
    assert_eq!(
        field(&filter_json(config, r#"{"field":null}"#), "field"),
        None
    );
    assert_eq!(
        field(&filter_json(config, r#"{"field":null}"#), "field"),
        None
    );
}

#[test]
#[allow(clippy::approx_constant)]
fn mutate_spec_convert_to_float_eu_contexts() {
    let config = r#"filter { mutate { convert => { "field" => "float_eu" } } }"#;
    assert!(near(
        number(filter_json(config, r#"{"field":"3141,5926"}"#), "field"),
        3141.5926,
        0.0001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":"3.141,5926"}"#), "field"),
        3141.5926,
        0.0001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":"3.141"}"#), "field"),
        3141.0,
        0.0001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":"3141"}"#), "field"),
        3141.0,
        0.0001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":3.1415926}"#), "field"),
        3.1415926,
        0.000001
    ));
    assert!(near(
        number(filter_json(config, r#"{"field":3}"#), "field"),
        3.0,
        0.000001
    ));
    assert_eq!(
        field(&filter_json(config, r#"{"field":true}"#), "field"),
        Some(Value::Float(1.0))
    );
    assert_eq!(
        field(&filter_json(config, r#"{"field":false}"#), "field"),
        Some(Value::Float(0.0))
    );
    assert_eq!(
        field(&filter_json(config, r#"{"field":null}"#), "field"),
        None
    );
    assert_eq!(
        field(&filter_json(config, r#"{"field":null}"#), "field"),
        None
    );
}

#[test]
fn mutate_spec_gsub_array_multiple_fields_and_dynamic() {
    let event = filter_json(
        r#"filter { mutate { gsub => [ "unicorns", "extinct", "common" ] } }"#,
        r#"{"unicorns":["Magnificient extinct animals","Other extinct ideas"]}"#,
    );
    assert_eq!(
        field(&event, "unicorns"),
        Some(Value::Array(vec![
            Value::from("Magnificient common animals"),
            Value::from("Other common ideas"),
        ]))
    );

    let event = filter_json(
        r#"filter { mutate { gsub => [ "colors", "red", "blue", "shapes", "square", "circle" ] } }"#,
        r#"{"colors":"One red car","shapes":"Four red squares"}"#,
    );
    assert_eq!(field(&event, "colors"), Some(Value::from("One blue car")));
    assert_eq!(
        field(&event, "shapes"),
        Some(Value::from("Four red circles"))
    );

    let event = filter_json(
        r#"filter { mutate { gsub => [ "unicorns", "of type %{unicorn_type}", "green" ] } }"#,
        r#"{"unicorns":"Unicorns of type blue are common","unicorn_type":"blue"}"#,
    );
    assert_eq!(
        field(&event, "unicorns"),
        Some(Value::from("Unicorns green are common"))
    );

    let event = filter_json(
        r#"filter { mutate { gsub => [ "unicorns2", "of type %{unicorn_color}", "%{unicorn_color} and green" ] } }"#,
        r#"{"unicorns2":"Unicorns of type blue are common","unicorn_color":"blue"}"#,
    );
    assert_eq!(
        field(&event, "unicorns2"),
        Some(Value::from("Unicorns blue and green are common"))
    );

    let event = filter_json(
        r#"filter { mutate { gsub => [ "unicorns_array", "of type %{color}", "blue and green" ] } }"#,
        r#"{"unicorns_array":["Unicorns of type blue are found in Alaska","Unicorns of type blue are extinct"],"color":"blue"}"#,
    );
    assert_eq!(
        field(&event, "unicorns_array"),
        Some(Value::Array(vec![
            Value::from("Unicorns blue and green are found in Alaska"),
            Value::from("Unicorns blue and green are extinct"),
        ]))
    );
}

#[test]
fn mutate_spec_rename_dynamic_destination_when_origin_is_missing() {
    let event = filter_json(
        r#"filter { mutate { rename => [ "origin", "field_%{x}" ] } }"#,
        r#"{"field_one":"value","x":"one"}"#,
    );
    assert!(!includes(&event, "origin"));
    assert!(includes(&event, "field_one"));
}

#[test]
fn mutate_spec_convert_array_index_and_booleans_to_integer() {
    let event = filter_json(
        r#"filter { mutate { convert => [ "[foo][0]", "integer" ] } }"#,
        r#"{"foo":["100","200"]}"#,
    );
    assert_eq!(field(&event, "[foo][0]"), Some(Value::Integer(100)));
    assert_eq!(field(&event, "[foo][1]"), Some(Value::from("200")));

    let event = filter_json(
        r#"
        filter {
          mutate {
            convert => {
              "[foo][0]" => "integer"
              "[foo][1]" => "integer"
              "[foo][2]" => "integer"
              "[foo][3]" => "integer"
              "[foo][4]" => "integer"
            }
          }
        }
        "#,
        r#"{"foo":[false,true,"0","1","2"]}"#,
    );
    assert_eq!(
        field(&event, "foo"),
        Some(Value::Array(vec![
            Value::Integer(0),
            Value::Integer(1),
            Value::Integer(0),
            Value::Integer(1),
            Value::Integer(2),
        ]))
    );
}

#[test]
fn mutate_spec_convert_us_and_eu_floats_and_frozen_booleans() {
    let event = filter_json(
        r#"
        filter {
          mutate {
            convert => {
              "[foo][0]" => "float"
              "[foo][1]" => "float"
              "[foo][2]" => "float"
            }
          }
        }
        "#,
        r#"{"foo":["1,000","1,234,567.8","123.4"]}"#,
    );
    match field(&event, "foo") {
        Some(Value::Array(items)) => {
            assert_eq!(items[0], Value::Float(1000.0));
            assert!(near(float_of(&items[1]), 1_234_567.8, 0.0001));
            assert!(near(float_of(&items[2]), 123.4, 0.0001));
        }
        other => panic!("{other:?}"),
    }

    let event = filter_json(
        r#"
        filter {
          mutate {
            convert => {
              "[foo][0]" => "float_eu"
              "[foo][1]" => "float_eu"
              "[foo][2]" => "float_eu"
            }
          }
        }
        "#,
        r#"{"foo":["1.000","1.234.567,8","123,4"]}"#,
    );
    match field(&event, "foo") {
        Some(Value::Array(items)) => {
            assert_eq!(items[0], Value::Float(1000.0));
            assert!(near(float_of(&items[1]), 1_234_567.8, 0.0001));
            assert!(near(float_of(&items[2]), 123.4, 0.0001));
        }
        other => panic!("{other:?}"),
    }

    let event = filter_json(
        r#"
        filter {
          mutate {
            convert => { "true_field" => "string" "false_field" => "string" }
          }
        }
        "#,
        r#"{"true_field":true,"false_field":false}"#,
    );
    assert_eq!(field(&event, "true_field"), Some(Value::from("true")));
    assert_eq!(field(&event, "false_field"), Some(Value::from("false")));
}

#[test]
fn mutate_spec_merge_variants() {
    let merge = r#"filter { mutate { merge => [ "list", "foo" ] } }"#;

    let event = filter_json(merge, r#"{"foo":"bar","list":[]}"#);
    assert_eq!(
        field(&event, "list"),
        Some(Value::Array(vec![Value::from("bar")]))
    );
    assert_eq!(field(&event, "foo"), Some(Value::from("bar")));

    let event = filter_json(merge, r#"{"foo":["bar"],"list":["baz"]}"#);
    assert_eq!(
        field(&event, "list"),
        Some(Value::Array(vec![Value::from("baz"), Value::from("bar")]))
    );
    assert_eq!(
        field(&event, "foo"),
        Some(Value::Array(vec![Value::from("bar")]))
    );

    let event = filter_json(merge, r#"{"foo":[],"list":["baz"]}"#);
    assert_eq!(
        field(&event, "list"),
        Some(Value::Array(vec![Value::from("baz")]))
    );
    assert_eq!(field(&event, "foo"), Some(Value::Array(vec![])));

    let event = filter_json(merge, r#"{"foo":["bar"],"list":"baz"}"#);
    assert_eq!(
        field(&event, "list"),
        Some(Value::Array(vec![Value::from("baz"), Value::from("bar")]))
    );
    assert_eq!(
        field(&event, "foo"),
        Some(Value::Array(vec![Value::from("bar")]))
    );

    let event = filter_json(merge, r#"{"foo":"bar","list":"baz"}"#);
    assert_eq!(
        field(&event, "list"),
        Some(Value::Array(vec![Value::from("baz"), Value::from("bar")]))
    );
    assert_eq!(field(&event, "foo"), Some(Value::from("bar")));
}

#[test]
fn mutate_spec_convert_makes_type_conversions() {
    assert_eq!(ROWS.len(), 85, "official convert table has 85 samples");
    for row in ROWS {
        let value = converted(row.kind, row.json);
        match row.expect {
            Expect::Str(text) => assert_eq!(value, Value::from(text), "{}", row.label),
            Expect::Int(digits) => assert_eq!(integer_text(&value), digits, "{}", row.label),
            Expect::Float(number) => match value {
                Value::Float(got) => {
                    assert_eq!(got, number, "{}: {got} vs {number}", row.label);
                }
                other => panic!("{}: {other:?}", row.label),
            },
        }
    }
}

#[test]
fn mutate_spec_parse_signed_hex_str() {
    assert_eq!(parse_signed_hex_str("0x1A"), Some(26.0));
    assert_eq!(parse_signed_hex_str("-0x1A"), Some(-26.0));
    assert_eq!(parse_signed_hex_str("-0xFF"), Some(-255.0));
    assert_eq!(parse_signed_hex_str("0x1A"), Some(26.0));
    assert_eq!(parse_signed_hex_str("-0x1A"), Some(-26.0));
    assert_eq!(parse_signed_hex_str("0x1.8p+1"), Some(3.0));
    assert_eq!(parse_signed_hex_str("-0x1.8p+1"), Some(-3.0));
    assert_eq!(parse_signed_hex_str("-0x1.2p+2"), Some(-4.5));
    assert_eq!(parse_signed_hex_str("123"), None);
    assert_eq!(parse_signed_hex_str("-456"), None);
    assert_eq!(parse_signed_hex_str("1.23"), None);
    assert_eq!(parse_signed_hex_str("abc"), None);
    assert_eq!(parse_signed_hex_str("0b1010"), None);
}

#[test]
fn mutate_spec_lowercase_field_created_by_grok() {
    let event = filter_json(
        r#"
        filter {
          grok { match => { "message" => "%{WORD:foo}" } }
          mutate { lowercase => "foo" }
        }
        "#,
        r#"{"message":"HELLO WORLD"}"#,
    );
    assert_eq!(field(&event, "foo"), Some(Value::from("hello")));
}

#[test]
fn mutate_spec_multi_stage_grok_and_lowercase() {
    let event = filter_json(
        r#"
        filter {
          grok {
            match => { "message" => "(?:hello) %{WORD:bar}" }
            break_on_match => false
          }
          mutate { lowercase => [ "bar", "lower1", "lower2" ] }
        }
        "#,
        r#"{"message":"hello WORLD","lower1":"PPQQRRSS","lower2":"pppqqq"}"#,
    );
    assert_eq!(field(&event, "bar"), Some(Value::from("world")));
    assert_eq!(field(&event, "lower1"), Some(Value::from("ppqqrrss")));
    assert_eq!(field(&event, "lower2"), Some(Value::from("pppqqq")));
}

fn converted(kind: &str, json: &str) -> Value {
    let event = filter_json(
        &format!(r#"filter {{ mutate {{ convert => {{ "a" => "{kind}" }} }} }}"#),
        json,
    );
    field(&event, "a").unwrap_or(Value::Null)
}

fn integer_text(value: &Value) -> String {
    match value {
        Value::Integer(number) => number.to_string(),
        Value::Decimal(decimal) => decimal.as_str().to_string(),
        other => panic!("expected an integer, got {other:?}"),
    }
}

fn number(event: Event, name: &str) -> f64 {
    float_of(&field(&event, name).unwrap_or_else(|| panic!("missing {name}")))
}

fn float_of(value: &Value) -> f64 {
    match value {
        Value::Float(number) => *number,
        other => panic!("expected a float, got {other:?}"),
    }
}

fn near(actual: f64, expected: f64, tolerance: f64) -> bool {
    (actual - expected).abs() <= tolerance
}

enum Expect {
    Str(&'static str),
    Int(&'static str),
    Float(f64),
}

struct Row {
    kind: &'static str,
    json: &'static str,
    expect: Expect,
    label: &'static str,
}

#[allow(clippy::excessive_precision)]
const ROWS: &[Row] = &[
    Row {
        kind: "string",
        json: r#"{"a":123}"#,
        expect: Expect::Str("123"),
        label: "to string / 123 / Integer",
    },
    Row {
        kind: "string",
        json: r#"{"a":123.0}"#,
        expect: Expect::Str("123.0"),
        label: "to string / 123 / Float",
    },
    Row {
        kind: "string",
        json: r#"{"a":"123"}"#,
        expect: Expect::Str("123"),
        label: "to string / 123 / String",
    },
    Row {
        kind: "string",
        json: r#"{"a":"0x7b"}"#,
        expect: Expect::Str("0x7b"),
        label: "to string / 123 / 0x7b",
    },
    Row {
        kind: "string",
        json: r#"{"a":"123.0"}"#,
        expect: Expect::Str("123.0"),
        label: "to string / 123 / 123.0",
    },
    Row {
        kind: "string",
        json: r#"{"a":"1.230000e+02"}"#,
        expect: Expect::Str("1.230000e+02"),
        label: "to string / 123 / scientific",
    },
    Row {
        kind: "string",
        json: r#"{"a":123.45}"#,
        expect: Expect::Str("123.45"),
        label: "to string / 123.45 / Float",
    },
    Row {
        kind: "string",
        json: r#"{"a":"123.45"}"#,
        expect: Expect::Str("123.45"),
        label: "to string / 123.45 / String",
    },
    Row {
        kind: "string",
        json: r#"{"a":"1.234500e+02"}"#,
        expect: Expect::Str("1.234500e+02"),
        label: "to string / 123.45 / scientific",
    },
    Row {
        kind: "string",
        json: r#"{"a":"0x1.edcdp6"}"#,
        expect: Expect::Str("0x1.edcdp6"),
        label: "to string / 123.45 / hex float",
    },
    Row {
        kind: "string",
        json: r#"{"a":16777217}"#,
        expect: Expect::Str("16777217"),
        label: "to string / 16777217 / Integer",
    },
    Row {
        kind: "string",
        json: r#"{"a":1.6777217E7}"#,
        expect: Expect::Str("16777217.0"),
        label: "to string / 16777217 / Float",
    },
    Row {
        kind: "string",
        json: r#"{"a":"16777217"}"#,
        expect: Expect::Str("16777217"),
        label: "to string / 16777217 / String",
    },
    Row {
        kind: "string",
        json: r#"{"a":"16777217.0"}"#,
        expect: Expect::Str("16777217.0"),
        label: "to string / 16777217 / 16777217.0",
    },
    Row {
        kind: "string",
        json: r#"{"a":2147483648}"#,
        expect: Expect::Str("2147483648"),
        label: "to string / 2147483648 / Long",
    },
    Row {
        kind: "string",
        json: r#"{"a":2.147483648E9}"#,
        expect: Expect::Str("2147483648.0"),
        label: "to string / 2147483648 / Double",
    },
    Row {
        kind: "string",
        json: r#"{"a":"2147483648"}"#,
        expect: Expect::Str("2147483648"),
        label: "to string / 2147483648 / String",
    },
    Row {
        kind: "string",
        json: r#"{"a":"2147483648.0"}"#,
        expect: Expect::Str("2147483648.0"),
        label: "to string / 2147483648 / .0",
    },
    Row {
        kind: "string",
        json: r#"{"a":9007199254740993}"#,
        expect: Expect::Str("9007199254740993"),
        label: "to string / 9007199254740993 / Long",
    },
    Row {
        kind: "string",
        json: r#"{"a":"9007199254740993"}"#,
        expect: Expect::Str("9007199254740993"),
        label: "to string / 9007199254740993 / String",
    },
    Row {
        kind: "string",
        json: r#"{"a":"9007199254740993.0"}"#,
        expect: Expect::Str("9007199254740993.0"),
        label: "to string / 9007199254740993 / .0",
    },
    Row {
        kind: "string",
        json: r#"{"a":"9223372036854775808"}"#,
        expect: Expect::Str("9223372036854775808"),
        label: "to string / 9223372036854775808",
    },
    Row {
        kind: "string",
        json: r#"{"a":"9223372036854775808.0"}"#,
        expect: Expect::Str("9223372036854775808.0"),
        label: "to string / 9223372036854775808.0",
    },
    Row {
        kind: "string",
        json: r#"{"a":"680564693277057720000000000000000000000"}"#,
        expect: Expect::Str("680564693277057720000000000000000000000"),
        label: "to string / 39-digit",
    },
    Row {
        kind: "string",
        json: r#"{"a":"680564693277057720000000000000000000000.0"}"#,
        expect: Expect::Str("680564693277057720000000000000000000000.0"),
        label: "to string / 39-digit .0",
    },
    Row {
        kind: "integer",
        json: r#"{"a":123}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123 / Integer",
    },
    Row {
        kind: "integer",
        json: r#"{"a":123.0}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123 / Float",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"123"}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123 / String",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"0x7b"}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123 / 0x7b",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"123.0"}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123 / 123.0",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"1.230000e+02"}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123 / scientific",
    },
    Row {
        kind: "integer",
        json: r#"{"a":123.45}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123.45 / Float",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"123.45"}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123.45 / String",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"1.234500e+02"}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123.45 / scientific",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"0x1.edcdp6"}"#,
        expect: Expect::Int("123"),
        label: "to integer / 123.45 / hex float",
    },
    Row {
        kind: "integer",
        json: r#"{"a":-123.45}"#,
        expect: Expect::Int("-123"),
        label: "to integer / -123.45 / Float",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"-123.45"}"#,
        expect: Expect::Int("-123"),
        label: "to integer / -123.45 / String",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"-1.234500e+02"}"#,
        expect: Expect::Int("-123"),
        label: "to integer / -123.45 / scientific",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"-0x1.edcdp6"}"#,
        expect: Expect::Int("-123"),
        label: "to integer / -123.45 / hex float",
    },
    Row {
        kind: "integer",
        json: r#"{"a":16777217}"#,
        expect: Expect::Int("16777217"),
        label: "to integer / 16777217 / Integer",
    },
    Row {
        kind: "integer",
        json: r#"{"a":1.6777217E7}"#,
        expect: Expect::Int("16777217"),
        label: "to integer / 16777217 / Double",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"16777217"}"#,
        expect: Expect::Int("16777217"),
        label: "to integer / 16777217 / String",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"16777217.0"}"#,
        expect: Expect::Int("16777217"),
        label: "to integer / 16777217 / .0",
    },
    Row {
        kind: "integer",
        json: r#"{"a":2147483648}"#,
        expect: Expect::Int("2147483648"),
        label: "to integer / 2147483648 / Long",
    },
    Row {
        kind: "integer",
        json: r#"{"a":2.147483648E9}"#,
        expect: Expect::Int("2147483648"),
        label: "to integer / 2147483648 / Double",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"2147483648"}"#,
        expect: Expect::Int("2147483648"),
        label: "to integer / 2147483648 / String",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"2147483648.0"}"#,
        expect: Expect::Int("2147483648"),
        label: "to integer / 2147483648 / .0",
    },
    Row {
        kind: "integer",
        json: r#"{"a":9007199254740993}"#,
        expect: Expect::Int("9007199254740993"),
        label: "to integer / 9007199254740993 / Long",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"9007199254740993"}"#,
        expect: Expect::Int("9007199254740993"),
        label: "to integer / 9007199254740993 / String",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"9007199254740993.0"}"#,
        expect: Expect::Int("9007199254740993"),
        label: "to integer / 9007199254740993 / .0",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"9.007199254740993e+15"}"#,
        expect: Expect::Int("9007199254740993"),
        label: "to integer / 9007199254740993 / scientific",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"9223372036854775808"}"#,
        expect: Expect::Int("9223372036854775808"),
        label: "to integer / 9223372036854775808",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"9223372036854775808.0"}"#,
        expect: Expect::Int("9223372036854775808"),
        label: "to integer / 9223372036854775808.0",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"680564693277057720000000000000000000000"}"#,
        expect: Expect::Int("680564693277057720000000000000000000000"),
        label: "to integer / 39-digit",
    },
    Row {
        kind: "integer",
        json: r#"{"a":"680564693277057720000000000000000000000.0"}"#,
        expect: Expect::Int("680564693277057720000000000000000000000"),
        label: "to integer / 39-digit .0",
    },
    Row {
        kind: "float",
        json: r#"{"a":123}"#,
        expect: Expect::Float(123.0),
        label: "to float / 123 / Integer",
    },
    Row {
        kind: "float",
        json: r#"{"a":123.0}"#,
        expect: Expect::Float(123.0),
        label: "to float / 123 / Float",
    },
    Row {
        kind: "float",
        json: r#"{"a":"123"}"#,
        expect: Expect::Float(123.0),
        label: "to float / 123 / String",
    },
    Row {
        kind: "float",
        json: r#"{"a":"0x7b"}"#,
        expect: Expect::Float(123.0),
        label: "to float / 123 / 0x7b",
    },
    Row {
        kind: "float",
        json: r#"{"a":"123.0"}"#,
        expect: Expect::Float(123.0),
        label: "to float / 123 / 123.0",
    },
    Row {
        kind: "float",
        json: r#"{"a":"1.230000e+02"}"#,
        expect: Expect::Float(123.0),
        label: "to float / 123 / scientific",
    },
    Row {
        kind: "float",
        json: r#"{"a":123.45}"#,
        expect: Expect::Float(123.45),
        label: "to float / 123.45 / Float",
    },
    Row {
        kind: "float",
        json: r#"{"a":"123.45"}"#,
        expect: Expect::Float(123.45),
        label: "to float / 123.45 / String",
    },
    Row {
        kind: "float",
        json: r#"{"a":"1.234500e+02"}"#,
        expect: Expect::Float(123.45),
        label: "to float / 123.45 / scientific",
    },
    Row {
        kind: "float",
        json: r#"{"a":"0x1.edcdp6"}"#,
        expect: Expect::Float(123.4501953125),
        label: "to float / 123.45 / hex float",
    },
    Row {
        kind: "float",
        json: r#"{"a":-123.45}"#,
        expect: Expect::Float(-123.45),
        label: "to float / -123.45 / Float",
    },
    Row {
        kind: "float",
        json: r#"{"a":"-123.45"}"#,
        expect: Expect::Float(-123.45),
        label: "to float / -123.45 / String",
    },
    Row {
        kind: "float",
        json: r#"{"a":"-1.234500e+02"}"#,
        expect: Expect::Float(-123.45),
        label: "to float / -123.45 / scientific",
    },
    Row {
        kind: "float",
        json: r#"{"a":"-0x1.edcdp6"}"#,
        expect: Expect::Float(-123.4501953125),
        label: "to float / -123.45 / hex float",
    },
    Row {
        kind: "float",
        json: r#"{"a":16777217}"#,
        expect: Expect::Float(1.6777217E7),
        label: "to float / 16777217 / Integer",
    },
    Row {
        kind: "float",
        json: r#"{"a":1.6777217E7}"#,
        expect: Expect::Float(1.6777217E7),
        label: "to float / 16777217 / Float",
    },
    Row {
        kind: "float",
        json: r#"{"a":"16777217"}"#,
        expect: Expect::Float(1.6777217E7),
        label: "to float / 16777217 / String",
    },
    Row {
        kind: "float",
        json: r#"{"a":"16777217.0"}"#,
        expect: Expect::Float(1.6777217E7),
        label: "to float / 16777217 / .0",
    },
    Row {
        kind: "float",
        json: r#"{"a":2147483648}"#,
        expect: Expect::Float(2.147483648E9),
        label: "to float / 2147483648 / Long",
    },
    Row {
        kind: "float",
        json: r#"{"a":2.147483648E9}"#,
        expect: Expect::Float(2.147483648E9),
        label: "to float / 2147483648 / Double",
    },
    Row {
        kind: "float",
        json: r#"{"a":"2147483648"}"#,
        expect: Expect::Float(2.147483648E9),
        label: "to float / 2147483648 / String",
    },
    Row {
        kind: "float",
        json: r#"{"a":"2147483648.0"}"#,
        expect: Expect::Float(2.147483648E9),
        label: "to float / 2147483648 / .0",
    },
    Row {
        kind: "float",
        json: r#"{"a":9007199254740993}"#,
        expect: Expect::Float(9.007199254740992E15),
        label: "to float / 9007199254740993 / Long",
    },
    Row {
        kind: "float",
        json: r#"{"a":"9007199254740993"}"#,
        expect: Expect::Float(9.007199254740992E15),
        label: "to float / 9007199254740993 / String",
    },
    Row {
        kind: "float",
        json: r#"{"a":"9007199254740993.0"}"#,
        expect: Expect::Float(9.007199254740992E15),
        label: "to float / 9007199254740993 / .0",
    },
    Row {
        kind: "float",
        json: r#"{"a":"9.007199254740993e+15"}"#,
        expect: Expect::Float(9007199254740992.0),
        label: "to float / 9007199254740993 / scientific",
    },
    Row {
        kind: "float",
        json: r#"{"a":"9223372036854775808"}"#,
        expect: Expect::Float(9.223372036854775808E18),
        label: "to float / 9223372036854775808",
    },
    Row {
        kind: "float",
        json: r#"{"a":"9223372036854775808.0"}"#,
        expect: Expect::Float(9.223372036854775808E18),
        label: "to float / 9223372036854775808.0",
    },
    Row {
        kind: "float",
        json: r#"{"a":"680564693277057720000000000000000000000"}"#,
        expect: Expect::Float(6.805646932770577e38),
        label: "to float / 39-digit",
    },
    Row {
        kind: "float",
        json: r#"{"a":"680564693277057720000000000000000000000.0"}"#,
        expect: Expect::Float(6.805646932770577e38),
        label: "to float / 39-digit .0",
    },
];
