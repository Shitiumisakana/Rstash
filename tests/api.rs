//! Monitoring API. JVM heap, GC, and hot-thread stacks are absent.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use rstash::cli::execute;
use rstash::{Ecs, Settings, run};

fn settings(port: u16) -> Settings {
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
        api_port: Some(port),
    }
}

fn get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("write");
    let mut body = String::new();
    stream.read_to_string(&mut body).expect("read");
    body
}

#[test]
fn stats_omit_jvm_and_report_the_build() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let port_slot = port;
    let worker = thread::spawn(move || {
        run(
            r#"
            input { generator { count => 1 message => "api" } }
            filter { sleep { time => "1" } }
            output { stdout { codec => plain } }
            "#,
            &settings(port_slot),
        )
    });
    let mut stats = String::new();
    let mut root = String::new();
    let mut node = String::new();
    let mut threads = String::new();
    for _ in 0..40 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            stats = get(port, "/_node/stats");
            root = get(port, "/");
            node = get(port, "/_node");
            threads = get(port, "/_node/hot_threads");
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    worker.join().expect("join").expect("run");
    assert!(
        root.contains("81753940099b4c9df5dba0da3fe6adb2f190a880"),
        "{root}"
    );
    assert!(root.contains("2026-08-17T18:16:06+00:00"), "{root}");
    assert!(root.contains("\"version\":\"9.5.2\""), "{root}");
    assert!(!stats.contains("\"jvm\""), "{stats}");
    assert!(stats.contains("\"events\""), "{stats}");
    assert!(stats.contains("\"status\":\"green\""), "{stats}");
    assert!(!node.contains("\"jvm\""), "{node}");
    assert!(threads.contains("\"threads\":[]"), "{threads}");
}

#[test]
fn cli_accepts_a_local_port_and_refuses_reload() {
    let config =
        "input { generator { count => 1 } } output { stdout { codec => plain } }".to_string();
    let mut out = Vec::new();
    let code = execute(
        &[
            "-t".to_string(),
            "--api.http.port".to_string(),
            "9600".to_string(),
            "--api.http.host".to_string(),
            "127.0.0.1".to_string(),
            "-e".to_string(),
            config.clone(),
        ],
        &mut out,
    )
    .expect("test and exit");
    assert_eq!(code, 0);

    let error = execute(
        &[
            "--api.http.host".to_string(),
            "0.0.0.0".to_string(),
            "-e".to_string(),
            config.clone(),
        ],
        &mut out,
    )
    .expect_err("public host");
    assert!(error.contains("api.http.host other than 127.0.0.1 is not implemented"));

    let error = execute(
        &[
            "--config.reload.automatic".to_string(),
            "true".to_string(),
            "-t".to_string(),
            "-e".to_string(),
            config,
        ],
        &mut out,
    )
    .expect_err("reload");
    assert!(error.contains("pipeline reload is not implemented"));
}

#[test]
fn automatic_reload_is_refused() {
    let mut settings = Settings::default();
    let error = rstash::apply_logstash_yml(&mut settings, "config.reload.automatic: true")
        .expect_err("reload");
    assert!(
        error
            .to_string()
            .contains("pipeline reload is not implemented")
    );
}
