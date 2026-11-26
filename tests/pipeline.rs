//! Slice 5, 7, and 8: memory pipeline, codecs, drop, mutate, and separate pipelines.
//!
//! Field names and the drop/mutate order follow the 9.5.2 gems
//! `logstash-input-generator`, `logstash-codec-plain`, `logstash-codec-line`,
//! `logstash-filter-drop`, and `logstash-filter-mutate`. Host and `@timestamp`
//! change every run, so the assertions lock the stable fields.

use rstash::{Ecs, Settings, Value, load_pipelines_yml, run, run_many};
use std::time::Duration;

fn settings() -> Settings {
    Settings {
        workers: 1,
        batch_size: 125,
        batch_delay: Duration::from_millis(50),
        ecs: Ecs::V8,
        test_and_exit: false,
        stdin: None,
        workers_set: false,
    }
}

#[test]
fn pipeline_generator_stdout() {
    let config = r#"
        input { generator { count => 2 } }
        output { stdout { codec => plain } }
    "#;
    let result = run(config, &Settings::default()).expect("pipeline");
    assert_eq!(result.events.len(), 2);
    let mut sequences = Vec::new();
    for event in &result.events {
        assert_eq!(
            event.get_field("message").unwrap(),
            Some(Value::from("Hello world!"))
        );
        assert_eq!(
            event.get_field("[event][original]").unwrap(),
            Some(Value::from("Hello world!"))
        );
        assert_eq!(event.get_field("@version").unwrap(), Some(Value::from("1")));
        let host = event.get_field("[host][name]").unwrap().expect("host");
        assert!(!host.to_string().is_empty());
        match event.get_field("[event][sequence]").unwrap() {
            Some(Value::Integer(number)) => sequences.push(number),
            other => panic!("sequence {other:?}"),
        }
        assert!(result.stdout.contains("Hello world!"));
    }
    sequences.sort();
    assert_eq!(sequences, vec![0, 1]);
}

#[test]
fn drop_mutate_and_line_codec() {
    let dropped = run(
        r#"
            input { generator { count => 2 message => "keep" } }
            filter { if [message] == "keep" { drop { } } }
            output { stdout { codec => plain } }
        "#,
        &settings(),
    )
    .expect("drop");
    assert!(dropped.events.is_empty());
    assert!(dropped.stdout.is_empty());

    let kept = run(
        r#"
            input { generator { count => 1 message => "keep" } }
            filter { drop { percentage => 0 } }
            output { stdout { codec => line } }
        "#,
        &settings(),
    )
    .expect("keep");
    assert_eq!(kept.events.len(), 1);
    assert!(kept.stdout.ends_with('\n'));

    let mutated = run(
        r#"
            input { generator { count => 1 message => "12" } }
            filter {
                mutate { add_field => { "flag" => "yes" "extra" => "gone" } }
                mutate {
                    rename => { "message" => "body" }
                    convert => { "body" => "integer" "flag" => "boolean" }
                    remove_field => ["extra"]
                }
            }
            output { stdout { codec => plain } }
        "#,
        &settings(),
    )
    .expect("mutate");
    let event = &mutated.events[0];
    assert_eq!(event.get_field("message").unwrap(), None);
    assert_eq!(event.get_field("body").unwrap(), Some(Value::Integer(12)));
    assert_eq!(event.get_field("flag").unwrap(), Some(Value::Boolean(true)));
    assert_eq!(event.get_field("extra").unwrap(), None);

    let missing = run(
        r#"
            input { generator { count => 1 } }
            output { elasticsearch { } }
        "#,
        &settings(),
    );
    let error = missing.expect_err("elasticsearch");
    assert!(error.to_string().contains("output elasticsearch"));
}

#[test]
fn pipelines_do_not_mix_events() {
    let text = r#"
- pipeline.id: alpha
  config.string: input { generator { count => 1 message => "alpha" } } output { stdout { codec => plain } }
- pipeline.id: beta
  config.string: input { generator { count => 1 message => "beta" } } output { stdout { codec => plain } }
"#;
    let loaded = load_pipelines_yml(text).expect("yml");
    assert_eq!(
        loaded
            .iter()
            .map(|pipeline| pipeline.id.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "beta"]
    );
    let named: Vec<(String, String)> = loaded
        .into_iter()
        .map(|pipeline| (pipeline.id, pipeline.config))
        .collect();
    let results = run_many(&named, &settings()).expect("run");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, "alpha");
    assert_eq!(results[1].0, "beta");
    assert_eq!(
        results[0].1.events[0].get_field("message").unwrap(),
        Some(Value::from("alpha"))
    );
    assert_eq!(
        results[1].1.events[0].get_field("message").unwrap(),
        Some(Value::from("beta"))
    );
    assert!(!results[0].1.stdout.contains("beta"));
    assert!(!results[1].1.stdout.contains("alpha"));
}
