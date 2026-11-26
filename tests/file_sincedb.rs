//! File input sincedb from logstash-input-file 4.4.7.
//!
//! The on-disk line is `inode major minor position changed_at path`.
//! A second run continues at `position`. `mode => read` ignores
//! `start_position` and still resumes from the checkpoint.

use rstash::{Ecs, Settings, Value, run};
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

fn field_message(event: &rstash::Event) -> String {
    match event.get_field("message").expect("field") {
        Some(Value::String(text)) => text,
        other => panic!("{other:?}"),
    }
}

#[test]
fn sincedb_v2_resumes_and_tail_starts_at_the_end() {
    let dir = std::env::temp_dir().join("rstash-file-sincedb");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("app.log");
    let db = dir.join("since.db");
    let done = dir.join("done.log");
    std::fs::write(&log, "one\ntwo\n").unwrap();
    let log_text = log.to_string_lossy().replace('\\', "/");
    let db_text = db.to_string_lossy().replace('\\', "/");
    let done_text = done.to_string_lossy().replace('\\', "/");
    let config = format!(
        r#"input {{ file {{ path => "{log_text}" mode => "read" sincedb_path => "{db_text}" file_completed_action => "log" file_completed_log_path => "{done_text}" }} }} output {{ stdout {{ codec => plain }} }}"#
    );
    let first = run(&config, &settings()).unwrap();
    assert_eq!(first.events.len(), 2);
    assert_eq!(field_message(&first.events[0]), "one");
    assert_eq!(field_message(&first.events[1]), "two");
    let stored = std::fs::read_to_string(&db).unwrap();
    let mut parts = stored.split_whitespace();
    let inode = parts.next().unwrap();
    assert!(inode.contains('-') || inode.chars().all(|ch| ch.is_ascii_digit()));
    let major: i64 = parts.next().unwrap().parse().unwrap();
    assert!(major >= 0);
    let _minor = parts.next().unwrap();
    let position: u64 = parts.next().unwrap().parse().unwrap();
    assert_eq!(position, std::fs::metadata(&log).unwrap().len());
    assert!(stored.contains("app.log"));
    assert!(std::fs::read_to_string(&done).unwrap().contains("app.log"));

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    file.write_all(b"three\n").unwrap();
    let second = run(&config, &settings()).unwrap();
    assert_eq!(second.events.len(), 1);
    assert_eq!(field_message(&second.events[0]), "three");

    let tail_log = dir.join("tail.log");
    let tail_db = dir.join("tail.db");
    std::fs::write(&tail_log, "old\n").unwrap();
    let tail_config = format!(
        r#"input {{ file {{ path => "{}" sincedb_path => "{}" start_position => "end" file_completed_action => "log" }} }} output {{ stdout {{ codec => plain }} }}"#,
        tail_log.to_string_lossy().replace('\\', "/"),
        tail_db.to_string_lossy().replace('\\', "/")
    );
    let skipped = run(&tail_config, &settings()).unwrap();
    assert!(skipped.events.is_empty());
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&tail_log)
        .unwrap();
    file.write_all(b"new\n").unwrap();
    let tailed = run(&tail_config, &settings()).unwrap();
    assert_eq!(tailed.events.len(), 1);
    assert_eq!(field_message(&tailed.events[0]), "new");

    let relative = run(
        r#"input { file { path => "relative.log" mode => "read" file_completed_action => "log" file_completed_log_path => "done.txt" } } output { stdout { codec => plain } }"#,
        &settings(),
    );
    let error = relative.expect_err("relative path");
    assert!(error.to_string().contains("File paths must be absolute"));
}
