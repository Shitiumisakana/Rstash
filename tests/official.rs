//! Cases taken from Elastic Logstash 9.5.2.
//! Compiler expectations come from `compile_imperative` on that release.
//! Event expectations are the assertions in `EventTest`, `event_spec.rb`,
//! and `StringInterpolationTest`.

use chrono::{TimeZone, Utc};
use rstash::{
    ConfigSource, Event, Map, PipelineVertex, Value, compile_imperative, compile_sources,
};

struct Case {
    name: String,
    escapes: bool,
    config: String,
    expected: Result<Sections, String>,
}

struct Sections {
    input: String,
    filter: String,
    output: String,
}

fn cases() -> Vec<Case> {
    let text = include_str!("fixtures/oracle/official_compiler.txt").replace("\r\n", "\n");
    let body = text.split_once("BEGIN CASES\n").expect("fixture header").1;
    let mut loaded = Vec::new();
    for chunk in body.split("===== END =====") {
        let chunk = chunk.trim_start_matches('\n');
        if chunk.is_empty() {
            continue;
        }
        let chunk = chunk.strip_prefix("===== CASE ").expect("case header");
        let (head, rest) = chunk.split_once(" =====\n").expect("case title");
        let (name, escapes) = head.split_once(" escapes=").expect("escapes flag");
        let rest = rest
            .strip_prefix("----- CONFIG -----\n")
            .expect("config marker");
        let (config, outcome) =
            if let Some((config, result)) = rest.split_once("\n----- RESULT -----\n") {
                let result = result
                    .strip_prefix("----- input -----\n")
                    .expect("input section");
                let (input, rest) = result.split_once("\n----- filter -----\n").expect("filter");
                let (filter, output) = rest.split_once("\n----- output -----\n").expect("output");
                let output = output.strip_suffix('\n').unwrap_or(output);
                (
                    config.to_string(),
                    Ok(Sections {
                        input: input.to_string(),
                        filter: filter.to_string(),
                        output: output.to_string(),
                    }),
                )
            } else {
                let (config, error) = rest.split_once("\n----- ERROR -----\n").expect("error");
                let error = error.strip_suffix('\n').unwrap_or(error);
                (config.to_string(), Err(error.to_string()))
            };
        loaded.push(Case {
            name: name.to_string(),
            escapes: escapes == "true",
            config,
            expected: outcome,
        });
    }
    loaded
}

#[test]
fn official_compiler_spec() {
    let loaded: Vec<_> = cases()
        .into_iter()
        .filter(|case| !case.name.starts_with("spec_integer_"))
        .collect();
    assert_eq!(
        loaded.len(),
        83,
        "compiler_spec and config_ast_spec cases should stay intact"
    );
    let mut failures = Vec::new();
    for case in &loaded {
        let actual = compile_imperative(&case.config, case.escapes);
        let mismatch = match (&case.expected, &actual) {
            (Ok(expected), Ok(pipeline)) => {
                let mut parts = Vec::new();
                if pipeline.input_text() != expected.input {
                    parts.push(format!(
                        "input\n  rust: {}\n  java: {}",
                        pipeline.input_text(),
                        expected.input
                    ));
                }
                if pipeline.filter_text() != expected.filter {
                    parts.push(format!(
                        "filter\n  rust: {}\n  java: {}",
                        pipeline.filter_text(),
                        expected.filter
                    ));
                }
                if pipeline.output_text() != expected.output {
                    parts.push(format!(
                        "output\n  rust: {}\n  java: {}",
                        pipeline.output_text(),
                        expected.output
                    ));
                }
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join("\n"))
                }
            }
            (Err(expected), Err(error)) => {
                let actual = error.to_string();
                if actual == *expected {
                    None
                } else {
                    Some(format!("error\n  rust: {actual}\n  java: {expected}"))
                }
            }
            (Ok(_), Err(error)) => Some(format!("rust errored: {error}")),
            (Err(expected), Ok(pipeline)) => Some(format!(
                "java errored: {expected}\n  rust input: {}",
                pipeline.input_text()
            )),
        };
        if let Some(detail) = mismatch {
            failures.push(format!("{}:\n{detail}", case.name));
        }
    }
    assert!(
        failures.is_empty(),
        "{} official compiler cases failed:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// Official event and sprintf assertions that this crate's public API can express.
/// Expected strings are copied from the Elastic tests, not from a previous Rust run.
#[test]
fn official_event_and_sprintf() {
    let stamp = Utc.with_ymd_and_hms(2015, 10, 1, 0, 0, 0).unwrap();
    let mut event = Event::at(stamp);
    event.set_field("bar", Value::from("foo")).unwrap();
    event.set_field("awesome", Value::from("logstash")).unwrap();
    let mut inner = Map::new();
    inner.insert("k1", Value::from("v"));
    event.set_field("j", Value::Map(inner)).unwrap();

    let mut checks: Vec<(&str, Result<String, String>, &str)> = vec![
        (
            "static",
            Ok(event.sprintf("/full/path/awesome").unwrap()),
            "/full/path/awesome",
        ),
        (
            "one field",
            Ok(event.sprintf("/full/%{bar}/awesome").unwrap()),
            "/full/foo/awesome",
        ),
        (
            "two fields",
            Ok(event.sprintf("/full/%{bar}/%{awesome}").unwrap()),
            "/full/foo/logstash",
        ),
        (
            "missing",
            Ok(event.sprintf("/full/%{do-not-exist}").unwrap()),
            "/full/%{do-not-exist}",
        ),
        (
            "joda year",
            Ok(event.sprintf("/full/%{+YYYY}").unwrap()),
            "/full/2015",
        ),
        (
            "joda and field",
            Ok(event.sprintf("/full/%{+YYYY}/weeee/%{bar}").unwrap()),
            "/full/2015/weeee/foo",
        ),
        (
            "unclosed",
            Ok(event.sprintf("/full/%{+YYY/web").unwrap()),
            "/full/%{+YYY/web",
        ),
        ("only year", Ok(event.sprintf("%{+YYYY}").unwrap()), "2015"),
        (
            "nested field",
            Ok(event.sprintf("%{[j][k1]}").unwrap()),
            "v",
        ),
        ("epoch", Ok(event.sprintf("%{+%s}").unwrap()), "1443657600"),
    ];

    event
        .set_field(
            "message",
            Value::Array(vec![Value::from("Hello"), Value::from("world")]),
        )
        .unwrap();
    checks.push((
        "array join",
        Ok(event.sprintf("%{message}").unwrap()),
        "Hello,world",
    ));
    checks.push((
        "hash json",
        Ok(event.sprintf("%{j}").unwrap()),
        "{\"k1\":\"v\"}",
    ));
    checks.push((
        "java day-of-year",
        event
            .sprintf("%{{YYYY-DDD}}")
            .map_err(|error| error.to_string()),
        "2015-274",
    ));
    checks.push((
        "java week",
        event
            .sprintf("%{{YYYY-'W'ww}}")
            .map_err(|error| error.to_string()),
        "2015-W40",
    ));
    checks.push((
        "joda percent seconds",
        event.sprintf("%{+%ss}").map_err(|error| error.to_string()),
        "%00",
    ));

    // EventTest.testDeepMapFieldToJson: setField("[foo][0][baz]") stores a map
    // whose key is the string "0", not a list.
    let mut fresh = Event::at(stamp);
    fresh.set_field("[foo][0]", Value::from("bar")).unwrap();
    let stored = fresh.get_field("foo").unwrap();
    let Value::Map(map) = stored.expect("foo") else {
        panic!("[foo][0] must create a map, official JSON is {{\"0\":...}}");
    };
    let expected = Value::from("bar");
    assert_eq!(map.get("0"), Some(&expected));

    let mut list_event = Event::at(stamp);
    list_event
        .set_field(
            "foo",
            Value::Array(vec![
                Value::from("bar"),
                Value::Integer(1),
                Value::Float(1.0),
            ]),
        )
        .unwrap();
    assert_eq!(
        list_event.get_field("[foo][0]").unwrap(),
        Some(Value::from("bar"))
    );
    assert_eq!(
        list_event.get_field("[foo][-1]").unwrap(),
        Some(Value::Float(1.0))
    );
    assert_eq!(list_event.get_field("[foo][3]").unwrap(), None);

    let mut failures = Vec::new();
    for (name, actual, expected) in checks {
        match actual {
            Ok(actual) if actual == expected => {}
            Ok(actual) => failures.push(format!(
                "{name}: got {actual:?}, official expects {expected:?}"
            )),
            Err(error) => failures.push(format!(
                "{name}: error {error}, official expects {expected:?}"
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "official event cases outside the current event model:\n{}",
        failures.join("\n")
    );
}

fn digest(text: &str) -> String {
    rstash::sha256_hex(text)
}

/// `compiler_spec` source metadata: protocol, id, and the plugin's own source text.
#[test]
fn compiler_spec_source_metadata() {
    let protocol = "test_proto";
    let id = "fake_sourcefile";
    let single = compile_sources(
        &[ConfigSource {
            protocol,
            id,
            text: "input { generator {} }",
        }],
        false,
    )
    .unwrap();
    let input = single
        .plugin_vertices()
        .into_iter()
        .find(|plugin| plugin.role == "input")
        .unwrap();
    assert_eq!(input.protocol, protocol);
    assert_eq!(input.id, id);
    assert_eq!(input.name, "generator");

    let generator = compile_sources(
        &[ConfigSource {
            protocol,
            id,
            text: "input { generator {} } output { }",
        }],
        false,
    )
    .unwrap();
    assert_eq!(
        generator
            .plugin_vertices()
            .into_iter()
            .find(|plugin| plugin.name == "generator")
            .unwrap()
            .text,
        "generator {}"
    );

    for section in ["filter", "output"] {
        let source = format!(
            "          {section} {{\n            aplugin {{ count => 1 }}\n            aplugin {{ count => 2 }}\n            }}\n"
        );
        let pipeline = compile_sources(
            &[ConfigSource {
                protocol,
                id,
                text: &source,
            }],
            false,
        )
        .unwrap();
        let first = pipeline
            .plugin_vertices()
            .into_iter()
            .find(|plugin| plugin.name == "aplugin")
            .unwrap();
        assert_eq!(first.text, "aplugin { count => 1 }");
        assert_eq!(first.line, 2);
        assert_eq!(first.column, 13);
        assert_eq!(first.id, id);
        assert_eq!(first.protocol, protocol);
    }

    for (source, name) in [
        ("input { } filter { grok {} } output { }", "grok"),
        ("input { } output { stdout {} }", "stdout"),
    ] {
        let pipeline = compile_sources(
            &[ConfigSource {
                protocol,
                id,
                text: source,
            }],
            false,
        )
        .unwrap();
        let plugin = pipeline
            .plugin_vertices()
            .into_iter()
            .find(|plugin| plugin.name == name)
            .unwrap();
        assert_eq!(plugin.protocol, protocol);
        assert_eq!(plugin.id, id);
    }
}

/// `compiler_spec` reads the plugin argument, not only the printed graph.
#[test]
fn compiler_spec_support_escapes() {
    let source = "input {\n  foo {\n    bar => \"The computer says, \\\"No\\\"\"\n  }\n}\n";
    let processed = "The computer says, \"No\"";
    let on = compile_imperative(source, true).unwrap();
    assert_eq!(
        on.plugin_string_argument("foo", "bar").as_deref(),
        Some(processed)
    );
    let off = compile_imperative(source, false).unwrap();
    assert_ne!(
        off.plugin_string_argument("foo", "bar").as_deref(),
        Some(processed)
    );
}

/// `ConfigCompilerTest`.
#[test]
fn config_compiler_test() {
    let simple = compile_imperative("input {stdin{}} output{stdout{}}", false).unwrap();
    assert_eq!(
        simple
            .plugin_vertices()
            .iter()
            .filter(|plugin| plugin.role == "output")
            .count(),
        1
    );
    assert_eq!(
        simple
            .plugin_vertices()
            .iter()
            .filter(|plugin| plugin.role == "filter")
            .count(),
        0
    );

    let mut repeated = String::from("filter {\n");
    for _ in 0..100 {
        repeated.push_str("if [message] == 'foo' {\nif [message] == 'foo' {drop {}}}\n");
    }
    repeated.push('}');
    let first_hash = compile_imperative(&repeated, false).unwrap().unique_hash();
    assert_eq!(first_hash, digest(&repeated));
    for _ in 0..5 {
        assert_eq!(
            compile_imperative(&repeated, false).unwrap().unique_hash(),
            first_hash
        );
    }

    let complex = include_str!(
        "../target/upstream/logstash/logstash-core/src/test/resources/org/logstash/config/ir/complex.cfg"
    );
    let complex_hash = compile_imperative(complex, false).unwrap().unique_hash();
    assert_eq!(complex_hash, digest(complex));
    assert_eq!(
        compile_imperative(complex, false).unwrap().unique_hash(),
        complex_hash
    );

    let empty = compile_sources(
        &[
            ConfigSource {
                protocol: "str",
                id: "in_plugin",
                text: "input { input_0 {} } ",
            },
            ConfigSource {
                protocol: "str",
                id: "out_plugin",
                text: "output { output_0 {} } ",
            },
            ConfigSource {
                protocol: "str",
                id: "<empty>",
                text: "     ",
            },
        ],
        false,
    )
    .unwrap();
    assert_eq!(empty.plugin_vertices().len(), 2);

    let commented = compile_sources(
        &[
            ConfigSource {
                protocol: "str",
                id: "in_plugin",
                text: "input { input_0 {} } ",
            },
            ConfigSource {
                protocol: "str",
                id: "commented_filter",
                text: "#filter{...}\n",
            },
            ConfigSource {
                protocol: "str",
                id: "out_plugin",
                text: "output { output_0 {} } ",
            },
        ],
        false,
    )
    .unwrap();
    assert_eq!(commented.plugin_vertices().len(), 2);

    let sources = [
        "input { input_0 {} } filter { filter_0 {} } output { output_0 {} }",
        "input { input_1 {} } filter { filter_1 {} } output { output_1 {} }",
    ];
    let merged = compile_sources(
        &[
            ConfigSource {
                protocol: "test_proto_0",
                id: "fake_sourcefile_0",
                text: sources[0],
            },
            ConfigSource {
                protocol: "test_proto_1",
                id: "fake_sourcefile_1",
                text: sources[1],
            },
        ],
        false,
    )
    .unwrap();
    assert_eq!(merged.original_source(), sources.join("\n"));
    assert_eq!(merged.unique_hash(), digest(merged.original_source()));
    assert!(!merged.unique_hash().is_empty());
    for plugin in merged.plugin_vertices() {
        let name_index = plugin.name.rsplit('_').next().unwrap();
        let protocol_index = plugin.protocol.rsplit('_').next().unwrap();
        let id_index = plugin.id.rsplit('_').next().unwrap();
        assert_eq!(name_index, protocol_index);
        assert_eq!(name_index, id_index);
    }
}

/// `PipelineIRTest` plugin counts, source digest, and the single queue before the filter.
#[test]
fn pipeline_ir_test() {
    let source = "\
input { generator {} stdin {} }
filter { if [foo] == [bar] { grok {} } else { kv {} } }
output { if [baz] > 1000 { s3 {} elasticsearch {} } else { stdout {} } }";
    let pipeline = compile_imperative(source, false).unwrap();
    let plugins = pipeline.plugin_vertices();
    assert_eq!(
        plugins
            .iter()
            .filter(|plugin| plugin.role == "input")
            .count(),
        2
    );
    assert_eq!(
        plugins
            .iter()
            .filter(|plugin| plugin.role == "filter")
            .count(),
        2
    );
    assert_eq!(
        plugins
            .iter()
            .filter(|plugin| plugin.role == "output")
            .count(),
        3
    );
    assert_eq!(pipeline.unique_hash(), digest(source));
    let blank = compile_imperative("   \n", false).unwrap();
    assert_eq!(blank.unique_hash(), blank.graph_unique_hash());
    assert_eq!(blank.graph_unique_hash(), digest(""));
    let one = compile_imperative("input { generator {} }", false).unwrap();
    let plugin = one.plugin_vertices().into_iter().next().unwrap();
    let source_hash = digest(&format!(
        "{}|{}|{}|{}|{}",
        plugin.id, plugin.protocol, plugin.line, plugin.column, plugin.text
    ));
    assert_eq!(one.graph_unique_hash(), digest(&source_hash));
    assert!(
        pipeline
            .post_queue()
            .iter()
            .all(|vertex| !matches!(vertex, PipelineVertex::Queue))
    );
    assert_eq!(
        pipeline
            .vertices()
            .iter()
            .filter(|vertex| matches!(vertex, PipelineVertex::Queue))
            .count(),
        1
    );
}

/// `ConfigCompilerTest.testComplexConfigs`: every file under `spec/support/lscl_configs` compiles.
#[test]
fn config_compiler_lscl_configs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/upstream/logstash/spec/support/lscl_configs");
    let mut paths: Vec<_> = std::fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("{}: {error}", root.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    assert_eq!(paths.len(), 6, "lscl_configs lost files");
    for path in paths {
        let source = std::fs::read_to_string(&path).unwrap();
        let pipeline = compile_imperative(&source, false)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert!(!pipeline.unique_hash().is_empty(), "{}", path.display());
        assert_eq!(
            pipeline.unique_hash(),
            digest(&source),
            "{}",
            path.display()
        );
    }
}
