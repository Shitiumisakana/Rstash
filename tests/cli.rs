use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use rstash::cli::execute;

fn temp_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rstash-cli-{nanos}"));
    fs::create_dir_all(&path).expect("temp");
    path
}

#[test]
fn cli_test_and_exit() {
    let mut good = Vec::new();
    let code = execute(
        &[
            "-t".to_string(),
            "-e".to_string(),
            "input { generator { count => 1 } } output { stdout { codec => plain } }".to_string(),
        ],
        &mut good,
    )
    .expect("valid config");
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8(good).unwrap().trim(), "Configuration OK");

    let mut bad = Vec::new();
    let error = execute(
        &["-t".to_string(), "-e".to_string(), "input {".to_string()],
        &mut bad,
    )
    .expect_err("broken config");
    assert!(!error.is_empty());

    let mut missing = Vec::new();
    let error = execute(
        &[
            "-e".to_string(),
            "input { generator { count => 1 } } output { s3 { } }".to_string(),
        ],
        &mut missing,
    )
    .expect_err("unimplemented");
    assert!(error.contains("s3"));

    let mut ran = Vec::new();
    let code = execute(
        &[
            "-w".to_string(),
            "1".to_string(),
            "-b".to_string(),
            "10".to_string(),
            "-e".to_string(),
            "input { generator { count => 1 message => \"from-cli\" } } output { stdout { codec => plain } }"
                .to_string(),
        ],
        &mut ran,
    )
    .expect("run");
    assert_eq!(code, 0);
    assert!(String::from_utf8(ran).unwrap().contains("from-cli"));

    let dir = temp_dir();
    fs::write(
        dir.join("pipe.conf"),
        "input { generator { count => 1 message => \"from-file\" } } output { stdout { codec => plain } }\n",
    )
    .expect("conf");
    let mut from_file = Vec::new();
    let code = execute(
        &[
            "-f".to_string(),
            dir.join("pipe.conf").to_string_lossy().into_owned(),
        ],
        &mut from_file,
    )
    .expect("file");
    assert_eq!(code, 0);
    assert!(String::from_utf8(from_file).unwrap().contains("from-file"));

    fs::write(
        dir.join("logstash.yml"),
        "pipeline.workers: 1\npipeline.batch.size: 10\npipeline.ecs_compatibility: v8\n",
    )
    .expect("yml");
    fs::write(
        dir.join("pipelines.yml"),
        "- pipeline.id: alpha\n  config.string: input { generator { count => 1 message => \"alpha\" } } output { stdout { codec => plain } }\n- pipeline.id: beta\n  config.string: input { generator { count => 1 message => \"beta\" } } output { stdout { codec => plain } }\n",
    )
    .expect("pipelines");
    let mut from_settings = Vec::new();
    let code = execute(
        &[
            "--path.settings".to_string(),
            dir.to_string_lossy().into_owned(),
        ],
        &mut from_settings,
    )
    .expect("settings");
    assert_eq!(code, 0);
    let text = String::from_utf8(from_settings).unwrap();
    assert!(text.contains("alpha"));
    assert!(text.contains("beta"));
    let _ = fs::remove_dir_all(&dir);
}
