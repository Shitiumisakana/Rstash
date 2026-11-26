//! `plugin list` names the gems compiled into this binary.
//! Keystore commands stop because the 9.5.2 file is PKCS12.

use rstash::cli::execute;

#[test]
fn plugin_list_names_the_compiled_gems() {
    let mut out = Vec::new();
    let code = execute(&["plugin".to_string(), "list".to_string()], &mut out).expect("list");
    assert_eq!(code, 0);
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("logstash-filter-mutate\n"), "{text}");
    assert!(text.contains("logstash-codec-plain\n"), "{text}");
    assert!(
        text.contains(
            "logstash-integration-kafka\n ├── logstash-input-kafka\n └── logstash-output-kafka\n"
        ),
        "{text}"
    );
    assert!(!text.contains("logstash-filter-dns"), "{text}");
    assert!(!text.contains("jdbc_streaming"), "{text}");
    assert!(!text.contains("elastic_agent"), "{text}");
    let mutate = text.find("logstash-filter-mutate").expect("mutate");
    let grok = text.find("logstash-filter-grok").expect("grok");
    assert!(grok < mutate, "list is sorted by gem name");
}

#[test]
fn plugin_list_verbose_group_and_misses() {
    let mut out = Vec::new();
    let code = execute(
        &[
            "plugin".to_string(),
            "list".to_string(),
            "--verbose".to_string(),
            "--group".to_string(),
            "filter".to_string(),
            "mutate".to_string(),
        ],
        &mut out,
    )
    .expect("verbose");
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8(out).expect("utf8"),
        "logstash-filter-mutate (3.6.0)\n"
    );

    let mut missing = Vec::new();
    let error = execute(
        &[
            "plugin".to_string(),
            "list".to_string(),
            "no-such-plugin".to_string(),
        ],
        &mut missing,
    )
    .expect_err("missing");
    assert_eq!(error, "No plugins found");

    let mut group = Vec::new();
    let error = execute(
        &[
            "plugin".to_string(),
            "list".to_string(),
            "--group".to_string(),
            "nope".to_string(),
        ],
        &mut group,
    )
    .expect_err("group");
    assert_eq!(
        error,
        "should be one of: input, output, filter, codec, integration"
    );

    let mut install = Vec::new();
    let error = execute(
        &[
            "plugin".to_string(),
            "install".to_string(),
            "logstash-filter-dns".to_string(),
        ],
        &mut install,
    )
    .expect_err("install");
    assert!(
        error.contains("plugin install is not implemented"),
        "{error}"
    );
}

#[test]
fn keystore_help_is_printed_and_create_is_refused() {
    let mut out = Vec::new();
    let code = execute(&["keystore".to_string(), "--help".to_string()], &mut out).expect("help");
    assert_eq!(code, 0);
    let text = String::from_utf8(out).expect("utf8");
    assert!(
        text.contains("This is should be the same directory"),
        "{text}"
    );
    assert!(text.contains("rstash keystore create"), "{text}");

    let mut created = Vec::new();
    let error = execute(
        &[
            "keystore".to_string(),
            "--path.settings".to_string(),
            "config".to_string(),
            "create".to_string(),
        ],
        &mut created,
    )
    .expect_err("create");
    assert!(
        error.contains("keystore files are PKCS12. Reading and writing them is not implemented."),
        "{error}"
    );

    let mut empty = Vec::new();
    let error = execute(
        &["keystore".to_string(), "--path.settings".to_string()],
        &mut empty,
    )
    .expect_err("empty path");
    assert!(
        error.contains("'--path.settings' found, but it is empty"),
        "{error}"
    );
}
