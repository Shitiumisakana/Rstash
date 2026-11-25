use rstash::{ConfigError, compile_imperative};

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

fn cases(keep: fn(&str) -> bool) -> Vec<Case> {
    let text = include_str!("fixtures/oracle/lscl_compile.txt").replace("\r\n", "\n");
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
        if !keep(name) {
            continue;
        }
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
    assert!(!loaded.is_empty());
    loaded
}

fn assert_case(case: &Case) {
    let actual = compile_imperative(&case.config, case.escapes);
    match (&case.expected, actual) {
        (Ok(expected), Ok(pipeline)) => {
            assert_eq!(pipeline.input_text(), expected.input, "{}", case.name);
            assert_eq!(pipeline.filter_text(), expected.filter, "{}", case.name);
            assert_eq!(pipeline.output_text(), expected.output, "{}", case.name);
        }
        (Err(expected), Err(error)) => assert_error(&case.name, expected, &error),
        (Ok(_), Err(error)) => panic!("{} compiled with {}", case.name, error),
        (Err(expected), Ok(_)) => panic!("{} expected error {expected}", case.name),
    }
}

fn assert_error(name: &str, expected: &str, error: &ConfigError) {
    let actual = error.to_string();
    if expected.starts_with("ArgumentError: Unexpected operator") {
        assert!(
            actual.starts_with("ArgumentError: Unexpected operator"),
            "{name}: {actual}"
        );
    } else {
        assert_eq!(actual, expected, "{name}");
    }
}

#[test]
fn parse_sections() {
    for case in cases(|name| name.starts_with("parse_") || name.starts_with("error_parse_")) {
        assert_case(&case);
    }
}

#[test]
fn conditions() {
    for case in cases(|name| name.starts_with("cond_") || name.starts_with("error_cond_")) {
        assert_case(&case);
    }
}

#[test]
fn compile_graph() {
    for case in cases(|name| name.starts_with("graph_")) {
        assert_case(&case);
    }
}
