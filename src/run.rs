//! Memory pipeline for the compiled statement tree.
//!
//! Workers, batch size, and batch delay follow `environment.rb`: CPU count,
//! 125, and 50 ms. Inputs push into one in-memory queue. Each worker takes a
//! batch, runs the filter tree, then the output tree. A plugin that is not in
//! this slice returns an error instead of being skipped.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::event::Event;
use crate::lscl::Key;
use crate::lscl::{Arg, Expr, Kind, Pipeline, Plugin, Statement, compile_imperative};
use crate::value::Value;

/// `pipeline.ecs_compatibility`. `v8` selects the v1 field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecs {
    Disabled,
    V1,
    V8,
}

/// Pipeline settings from `environment.rb`, `logstash.yml`, and the CLI.
#[derive(Debug, Clone)]
pub struct Settings {
    pub workers: usize,
    pub batch_size: usize,
    pub batch_delay: Duration,
    pub ecs: Ecs,
    pub test_and_exit: bool,
    /// `generator` `message => "stdin"` reads this instead of the process stdin.
    /// `None` reads one line from stdin, the way `IO#readline` does.
    pub stdin: Option<String>,
    /// True when `-w` or `pipeline.workers` in a settings file set the value.
    pub workers_set: bool,
    /// `path.data`. The file input writes its sincedb under `plugins/inputs/file`.
    pub path_data: Option<String>,
    /// `path.queue`. Defaults to `path.data/queue` when the queue is persisted.
    pub path_queue: Option<String>,
    /// `queue.type`. `persisted` writes `MmapPageIOV2` pages under the queue path.
    pub persisted_queue: bool,
    /// `queue.page_capacity`, in bytes. The 9.5.2 default is 64 MiB.
    pub queue_page_capacity: usize,
    /// Directory name under the queue path. `run_many` sets this from `pipeline.id`.
    pub pipeline_id: String,
    /// `dead_letter_queue.enable`.
    pub dlq_enabled: bool,
    /// `path.dead_letter_queue`. Defaults to `path.data/dead_letter_queue`.
    pub path_dlq: Option<String>,
    /// `dead_letter_queue.max_bytes`. The 9.5.2 default is 1024mb.
    pub dlq_max_bytes: u64,
    /// `dead_letter_queue.storage_policy`: `drop_newer` or `drop_older`.
    pub dlq_storage_policy: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            workers: thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1),
            batch_size: 125,
            batch_delay: Duration::from_millis(50),
            ecs: Ecs::V8,
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
        }
    }
}

/// Events that reached an output, and the bytes those outputs wrote.
#[derive(Debug, Clone, PartialEq)]
pub struct RunResult {
    pub stdout: String,
    pub events: Vec<Event>,
}

#[derive(Debug)]
pub struct RunError {
    pub message: String,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RunError {}

pub(crate) fn fail(message: impl Into<String>) -> RunError {
    RunError {
        message: message.into(),
    }
}

/// Compile and, unless `test_and_exit` is set, run one memory pipeline.
pub fn run(config: &str, settings: &Settings) -> Result<RunResult, RunError> {
    let pipeline = compile_imperative(config, false).map_err(|error| fail(error.to_string()))?;
    if settings.test_and_exit {
        check_plugins(&pipeline)?;
        return Ok(RunResult {
            stdout: String::new(),
            events: Vec::new(),
        });
    }
    execute(&pipeline, settings)
}

/// Run several pipelines. Each has its own queue, so events cannot cross.
pub fn run_many(
    pipelines: &[(String, String)],
    settings: &Settings,
) -> Result<Vec<(String, RunResult)>, RunError> {
    let mut results = Vec::new();
    for (id, config) in pipelines {
        let mut settings = settings.clone();
        settings.pipeline_id = id.clone();
        results.push((id.clone(), run(config, &settings)?));
    }
    Ok(results)
}

fn execute(pipeline: &Pipeline, settings: &Settings) -> Result<RunResult, RunError> {
    check_plugins(pipeline)?;
    let inputs = input_plugins(&pipeline.input);
    if inputs.is_empty() {
        return Ok(RunResult {
            stdout: String::new(),
            events: Vec::new(),
        });
    }
    let queue = Queue::new(inputs.len());
    let disk = if settings.persisted_queue {
        Some(crate::queue::DiskQueue::open(
            &queue_dir(settings)?,
            settings.queue_page_capacity,
        )?)
    } else {
        None
    };
    let shared = Arc::new(Shared {
        queue,
        filter: pipeline.filter.clone(),
        output: pipeline.output.clone(),
        settings: settings.clone(),
        stdout: Mutex::new(String::new()),
        events: Mutex::new(Vec::new()),
        error: Mutex::new(None),
        disk: Mutex::new(disk),
    });
    if let Some(disk) = shared.disk.lock().expect("disk").as_ref() {
        for event in disk.unacked_events()? {
            shared.queue.push(event);
        }
    }
    let mut producers = Vec::new();
    for plugin in inputs {
        let shared = Arc::clone(&shared);
        let plugin = plugin.clone();
        producers.push(thread::spawn(move || {
            let produced = match plugin.name.as_str() {
                "generator" => generator(&plugin, &shared.settings),
                _ => crate::plugins::produce(&plugin, &shared.settings),
            };
            match produced {
                Ok(events) => {
                    for event in events {
                        if let Some(disk) = shared.disk.lock().expect("disk").as_mut()
                            && let Err(error) = disk.append(&event)
                        {
                            *shared.error.lock().expect("error") = Some(error.message);
                            break;
                        }
                        shared.queue.push(event);
                    }
                }
                Err(error) => {
                    *shared.error.lock().expect("error") = Some(error.message);
                }
            }
            shared.queue.close_input();
        }));
    }
    let workers = settings.workers.max(1);
    let mut consumers = Vec::new();
    for _ in 0..workers {
        let shared = Arc::clone(&shared);
        consumers.push(thread::spawn(move || worker(&shared)));
    }
    for producer in producers {
        producer.join().expect("input thread");
    }
    for consumer in consumers {
        consumer.join().expect("worker thread");
    }
    if let Some(message) = shared.error.lock().expect("error").clone() {
        return Err(fail(message));
    }
    if let Some(disk) = shared.disk.lock().expect("disk").as_mut() {
        let pending = disk.unacked_events()?.len();
        disk.ack(pending)?;
    }
    Ok(RunResult {
        stdout: shared.stdout.lock().expect("stdout").clone(),
        events: shared.events.lock().expect("events").clone(),
    })
}

struct Shared {
    queue: Queue,
    filter: Statement,
    output: Statement,
    settings: Settings,
    stdout: Mutex<String>,
    events: Mutex<Vec<Event>>,
    error: Mutex<Option<String>>,
    disk: Mutex<Option<crate::queue::DiskQueue>>,
}

fn worker(shared: &Shared) {
    let batch_size = shared.settings.batch_size.max(1);
    while let Some(batch) = shared
        .queue
        .read_batch(batch_size, shared.settings.batch_delay)
    {
        for event in batch {
            match apply(&shared.filter, event, shared) {
                Ok(events) => {
                    for event in events {
                        if let Err(error) = apply(&shared.output, event, shared) {
                            *shared.error.lock().expect("error") = Some(error.message);
                        }
                    }
                }
                Err(error) => {
                    *shared.error.lock().expect("error") = Some(error.message);
                }
            }
        }
    }
}

/// Events that continue. An empty list means the event was cancelled.
fn apply(statement: &Statement, event: Event, shared: &Shared) -> Result<Vec<Event>, RunError> {
    if event.is_cancelled() {
        return Ok(Vec::new());
    }
    match statement {
        Statement::Noop => Ok(vec![event]),
        Statement::Sequence(children) | Statement::Parallel(children) => {
            let mut batch = vec![event];
            for child in children {
                let mut next = Vec::new();
                for item in batch {
                    next.extend(apply(child, item, shared)?);
                }
                batch = next;
            }
            Ok(batch)
        }
        Statement::If {
            condition,
            when_true,
            when_false,
            ..
        } => {
            if eval(condition, &event)? {
                apply(when_true, event, shared)
            } else {
                apply(when_false, event, shared)
            }
        }
        Statement::Plugin(plugin) => dispatch(plugin, event, shared),
    }
}

fn dispatch(plugin: &Plugin, mut event: Event, shared: &Shared) -> Result<Vec<Event>, RunError> {
    match (plugin.kind, plugin.name.as_str()) {
        (Kind::Filter, "drop") => {
            if drop_event(plugin) {
                event.cancel();
                return Ok(Vec::new());
            }
            Ok(vec![event])
        }
        (Kind::Filter, "mutate") => {
            crate::mutate::apply(plugin, &mut event)?;
            Ok(vec![event])
        }
        (Kind::Filter, "grok") => {
            crate::grok::apply(plugin, &mut event, shared.settings.ecs)?;
            Ok(vec![event])
        }
        (Kind::Filter, _) => crate::plugins::filter(plugin, event, &shared.settings),
        (Kind::Output, "stdout") => {
            let encoded = encode_stdout(plugin, &event)?;
            shared.stdout.lock().expect("stdout").push_str(&encoded);
            shared.events.lock().expect("events").push(event.clone());
            Ok(vec![event])
        }
        (Kind::Output, "null" | "sink") => {
            shared.events.lock().expect("events").push(event);
            Ok(Vec::new())
        }
        (Kind::Output, "file") => {
            let encoded = encode_stdout(plugin, &event)?;
            crate::plugins::write_file(plugin, &encoded)?;
            shared.events.lock().expect("events").push(event);
            Ok(Vec::new())
        }
        (Kind::Output, "tcp") => {
            let encoded = encode_event(plugin, &event, "json")?;
            crate::netio::tcp_send(plugin, &encoded)?;
            shared.events.lock().expect("events").push(event);
            Ok(Vec::new())
        }
        (Kind::Output, "udp") => {
            let encoded = encode_event(plugin, &event, "json")?;
            crate::netio::udp_send(plugin, &event, &encoded)?;
            shared.events.lock().expect("events").push(event);
            Ok(Vec::new())
        }
        (Kind::Output, "http") => {
            crate::netio::http_send(plugin, &event)?;
            shared.events.lock().expect("events").push(event);
            Ok(Vec::new())
        }
        (Kind::Output, "elasticsearch") => {
            crate::elastic::send(plugin, &event, &shared.settings)?;
            shared.events.lock().expect("events").push(event);
            Ok(Vec::new())
        }
        (Kind::Output, "kafka") => {
            crate::kafka::send(plugin, &event)?;
            shared.events.lock().expect("events").push(event);
            Ok(Vec::new())
        }
        (kind, name) => Err(fail(unimplemented(kind, name))),
    }
}

fn unimplemented(kind: Kind, name: &str) -> String {
    let role = match kind {
        Kind::Input => "input",
        Kind::Filter => "filter",
        Kind::Output => "output",
        Kind::Codec => "codec",
    };
    format!("plugin {role} {name} is not implemented")
}

fn check_plugins(pipeline: &Pipeline) -> Result<(), RunError> {
    check_input(&pipeline.input)?;
    check_statement(&pipeline.filter)?;
    check_statement(&pipeline.output)?;
    Ok(())
}

fn check_input(statement: &Statement) -> Result<(), RunError> {
    match statement {
        Statement::If { .. } => Err(fail(
            "conditional inputs are not implemented; an if in the input section would have to choose one branch",
        )),
        Statement::Sequence(children) | Statement::Parallel(children) => {
            for child in children {
                check_input(child)?;
            }
            Ok(())
        }
        other => check_statement(other),
    }
}

fn check_statement(statement: &Statement) -> Result<(), RunError> {
    match statement {
        Statement::Noop => Ok(()),
        Statement::Sequence(children) | Statement::Parallel(children) => {
            for child in children {
                check_statement(child)?;
            }
            Ok(())
        }
        Statement::If {
            when_true,
            when_false,
            ..
        } => {
            check_statement(when_true)?;
            check_statement(when_false)?;
            Ok(())
        }
        Statement::Plugin(plugin) => {
            let known = matches!(
                (plugin.kind, plugin.name.as_str()),
                (Kind::Input, "generator")
                    | (Kind::Filter, "drop" | "mutate" | "grok")
                    | (Kind::Output, "stdout")
                    | (Kind::Codec, "plain" | "line")
            ) || crate::plugins::known(plugin.kind, &plugin.name);
            if !known {
                return Err(fail(unimplemented(plugin.kind, &plugin.name)));
            }
            if matches!(
                (plugin.kind, plugin.name.as_str()),
                (Kind::Output, "stdout" | "file" | "tcp" | "udp" | "kafka")
                    | (Kind::Input, "kafka")
            ) && let Some(name) = codec_name(plugin)
                && !codec_known(name)
            {
                return Err(fail(unimplemented(Kind::Codec, name)));
            }
            for (_, value) in &plugin.args {
                check_arg(value)?;
            }
            Ok(())
        }
    }
}

fn check_arg(arg: &Arg) -> Result<(), RunError> {
    match arg {
        Arg::Plugin(plugin) => {
            if plugin.kind == Kind::Codec && !codec_known(&plugin.name) {
                return Err(fail(unimplemented(plugin.kind, &plugin.name)));
            }
            if plugin.kind != Kind::Codec {
                return Err(fail(unimplemented(plugin.kind, &plugin.name)));
            }
            Ok(())
        }
        Arg::Array(items) => {
            for item in items {
                check_arg(item)?;
            }
            Ok(())
        }
        Arg::Map(entries) => {
            for (_, value) in entries {
                check_arg(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn input_plugins(statement: &Statement) -> Vec<&Plugin> {
    let mut found = Vec::new();
    collect_inputs(statement, &mut found);
    found
}

fn collect_inputs<'a>(statement: &'a Statement, found: &mut Vec<&'a Plugin>) {
    match statement {
        Statement::Plugin(plugin) => found.push(plugin),
        Statement::Sequence(children) | Statement::Parallel(children) => {
            for child in children {
                collect_inputs(child, found);
            }
        }
        Statement::If {
            when_true,
            when_false,
            ..
        } => {
            collect_inputs(when_true, found);
            collect_inputs(when_false, found);
        }
        Statement::Noop => {}
    }
}

fn generator(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    let count = arg_i64(plugin, "count").unwrap_or(0);
    if count <= 0 {
        return Err(fail(
            "generator count must be greater than 0; 0 means unlimited and this pipeline does not run forever",
        ));
    }
    let lines = match arg(plugin, "lines") {
        Some(Arg::Array(items)) => items
            .iter()
            .map(|item| match item {
                Arg::String(text) => Ok(text.clone()),
                _ => Err(fail("generator lines entries must be strings")),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(fail("generator lines must be an array")),
        None => {
            let message = if arg_string(plugin, "message").as_deref() == Some("stdin") {
                if let Some(text) = &settings.stdin {
                    text.clone()
                } else {
                    let mut buf = String::new();
                    std::io::stdin()
                        .read_line(&mut buf)
                        .map_err(|error| fail(error.to_string()))?;
                    buf
                }
            } else {
                arg_string(plugin, "message").unwrap_or_else(|| "Hello world!".to_string())
            };
            vec![message]
        }
    };
    let host = hostname();
    let ecs_v1 = settings.ecs != Ecs::Disabled;
    let (host_field, sequence_field) = if ecs_v1 {
        ("[host][name]", "[event][sequence]")
    } else {
        ("host", "sequence")
    };
    let codec = codec_of(plugin, "plain")?;
    let mut pending = String::new();
    let mut events = Vec::new();
    for number in 0..count {
        for line in &lines {
            for message in codec_decode(&codec, &mut pending, line)? {
                events.push(finish_generated(
                    plugin,
                    message,
                    Some(number),
                    &host,
                    host_field,
                    sequence_field,
                    ecs_v1,
                )?);
            }
        }
    }
    if codec.name == "line" && !pending.is_empty() {
        let message = std::mem::take(&mut pending);
        events.push(finish_generated(
            plugin,
            message,
            None,
            &host,
            host_field,
            sequence_field,
            ecs_v1,
        )?);
    }
    Ok(events)
}

fn finish_generated(
    plugin: &Plugin,
    message: String,
    sequence: Option<i64>,
    host: &str,
    host_field: &str,
    sequence_field: &str,
    ecs_v1: bool,
) -> Result<Event, RunError> {
    let mut event = Event::new();
    event
        .set_field("message", Value::from(message.clone()))
        .map_err(event_fail)?;
    if ecs_v1 {
        event
            .set_field("[event][original]", Value::from(message))
            .map_err(event_fail)?;
    }
    decorate(plugin, &mut event)?;
    if !event.includes(host_field).map_err(event_fail)? {
        event
            .set_field(host_field, Value::from(host))
            .map_err(event_fail)?;
    }
    if let Some(sequence) = sequence {
        event
            .set_field(sequence_field, Value::Integer(i128::from(sequence)))
            .map_err(event_fail)?;
    }
    Ok(event)
}

fn codec_decode(
    codec: &CodecSpec,
    pending: &mut String,
    data: &str,
) -> Result<Vec<String>, RunError> {
    match codec.name.as_str() {
        "plain" => Ok(vec![data.to_string()]),
        "line" => {
            pending.push_str(data);
            let mut lines = Vec::new();
            while let Some(index) = pending.find(&codec.delimiter) {
                let line = pending[..index].to_string();
                pending.replace_range(..index + codec.delimiter.len(), "");
                lines.push(line);
            }
            Ok(lines)
        }
        other => Err(fail(format!("plugin codec {other} is not implemented"))),
    }
}

fn decorate(plugin: &Plugin, event: &mut Event) -> Result<(), RunError> {
    if let Some(Arg::Map(entries)) = arg(plugin, "add_field") {
        for (key, value) in entries {
            let field = event.sprintf(&key_text(key)).map_err(event_fail)?;
            let text = event.sprintf(&arg_text(value)?).map_err(event_fail)?;
            crate::mutate::add_field(event, &field, Value::from(text))?;
        }
    }
    if let Some(Arg::Array(tags)) = arg(plugin, "add_tag").or_else(|| arg(plugin, "tags")) {
        for tag in tags {
            event.tag(&event.sprintf(&arg_text(tag)?).map_err(event_fail)?);
        }
    }
    Ok(())
}

fn codec_known(name: &str) -> bool {
    matches!(name, "plain" | "line") || crate::plugins::known(Kind::Codec, name)
}

fn encode_stdout(plugin: &Plugin, event: &Event) -> Result<String, RunError> {
    encode_event(plugin, event, "rubydebug")
}

pub(crate) fn encode_event(
    plugin: &Plugin,
    event: &Event,
    default_codec: &str,
) -> Result<String, RunError> {
    let codec = codec_of(plugin, default_codec)?;
    let body = if let Some(format) = &codec.format {
        event.sprintf(format).map_err(event_fail)?
    } else {
        match codec.name.as_str() {
            "plain" | "line" => event.plain_string(),
            name => crate::plugins::encode(name, &codec.delimiter, codec.metadata, event)?,
        }
    };
    Ok(if codec.name == "line" || codec.name == "json_lines" {
        if codec.name == "json_lines" {
            body
        } else {
            body + &codec.delimiter
        }
    } else {
        body
    })
}

struct CodecSpec {
    name: String,
    delimiter: String,
    format: Option<String>,
    metadata: bool,
}

fn codec_name(plugin: &Plugin) -> Option<&str> {
    match arg(plugin, "codec") {
        Some(Arg::String(name)) => Some(name),
        Some(Arg::Plugin(codec)) => Some(codec.name.as_str()),
        _ => None,
    }
}

fn codec_of(plugin: &Plugin, default_name: &str) -> Result<CodecSpec, RunError> {
    match arg(plugin, "codec") {
        None => Ok(CodecSpec {
            name: default_name.to_string(),
            delimiter: "\n".to_string(),
            format: None,
            metadata: false,
        }),
        Some(Arg::String(name)) => Ok(CodecSpec {
            name: name.clone(),
            delimiter: "\n".to_string(),
            format: None,
            metadata: false,
        }),
        Some(Arg::Plugin(codec)) => Ok(CodecSpec {
            name: codec.name.clone(),
            delimiter: arg_string(codec, "delimiter").unwrap_or_else(|| "\n".to_string()),
            format: arg_string(codec, "format"),
            metadata: arg_string(codec, "metadata").as_deref() == Some("true"),
        }),
        Some(_) => Err(fail("codec must be a name or a codec block")),
    }
}

fn event_fail(error: crate::EventError) -> RunError {
    fail(error.to_string())
}

/// `logstash-filter-drop`: percentage 100 always cancels. Any other value
/// cancels when a unit random draw is strictly below percentage/100.
fn drop_event(plugin: &Plugin) -> bool {
    let percentage = arg_f64(plugin, "percentage").unwrap_or(100.0);
    if (percentage - 100.0).abs() < f64::EPSILON {
        return true;
    }
    unit_random() < percentage / 100.0
}

fn unit_random() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    f64::from(nanos % 1_000_000) / 1_000_000.0
}

fn eval(expr: &Expr, event: &Event) -> Result<bool, RunError> {
    Ok(match expr {
        Expr::Truthy(inner) => match inner.as_ref() {
            Expr::Event(field) => match event.get_field(field).map_err(event_fail)? {
                None | Some(Value::Null) | Some(Value::Boolean(false)) => false,
                Some(_) => true,
            },
            Expr::Value(Arg::String(text)) => !text.is_empty(),
            other => eval(other, event)?,
        },
        Expr::Not(inner) => !eval(inner, event)?,
        Expr::And(left, right) => eval(left, event)? && eval(right, event)?,
        Expr::Or(left, right) => eval(left, event)? || eval(right, event)?,
        Expr::Eq(left, right) => {
            values_equal(&eval_value(left, event)?, &eval_value(right, event)?)
        }
        Expr::Neq(left, right) => {
            !values_equal(&eval_value(left, event)?, &eval_value(right, event)?)
        }
        Expr::Gt(left, right) => compare(left, right, event)? == Some(std::cmp::Ordering::Greater),
        Expr::Lt(left, right) => compare(left, right, event)? == Some(std::cmp::Ordering::Less),
        Expr::Gte(left, right) => {
            matches!(
                compare(left, right, event)?,
                Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
            )
        }
        Expr::Lte(left, right) => {
            matches!(
                compare(left, right, event)?,
                Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
            )
        }
        Expr::In(left, right) => value_in(&eval_value(left, event)?, &eval_value(right, event)?),
        Expr::RegexEq(left, right) => {
            let text = eval_value(left, event)?.to_string();
            let pattern = match right.as_ref() {
                Expr::Regex(pattern) | Expr::Value(Arg::String(pattern)) => pattern.clone(),
                other => eval_value(other, event)?.to_string(),
            };
            regex_match(&text, &pattern)?
        }
        Expr::Event(_) | Expr::Value(_) | Expr::Regex(_) => false,
    })
}

fn eval_value(expr: &Expr, event: &Event) -> Result<Value, RunError> {
    match expr {
        Expr::Event(field) => Ok(event
            .get_field(field)
            .map_err(event_fail)?
            .unwrap_or(Value::Null)),
        Expr::Value(Arg::String(text)) => Ok(Value::from(text.as_str())),
        Expr::Value(Arg::Int(number)) => Ok(Value::Integer(i128::from(*number))),
        Expr::Value(Arg::Float(number)) => Ok(Value::Float(*number)),
        Expr::Value(Arg::Big(text)) => Ok(Value::from(text.as_str())),
        Expr::Value(Arg::Array(items)) => {
            let mut values = Vec::new();
            for item in items {
                values.push(eval_value(&Expr::Value(item.clone()), event)?);
            }
            Ok(Value::Array(values))
        }
        other => Err(fail(format!(
            "condition value is not supported: {}",
            other.to_ruby()
        ))),
    }
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Integer(left), Value::Integer(right)) => left == right,
        (Value::Float(left), Value::Float(right)) => left.to_bits() == right.to_bits(),
        (Value::Integer(left), Value::Float(right)) => *left as f64 == *right,
        (Value::Float(left), Value::Integer(right)) => *left == *right as f64,
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Boolean(left), Value::Boolean(right)) => left == right,
        (Value::Null, Value::Null) => true,
        _ => false,
    }
}

fn compare(
    left: &Expr,
    right: &Expr,
    event: &Event,
) -> Result<Option<std::cmp::Ordering>, RunError> {
    let left = eval_value(left, event)?;
    let right = eval_value(right, event)?;
    let (Some(left), Some(right)) = (as_f64(&left), as_f64(&right)) else {
        return Ok(None);
    };
    Ok(left.partial_cmp(&right))
}

fn as_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Integer(number) => Some(*number as f64),
        Value::Float(number) => Some(*number),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn value_in(needle: &Value, haystack: &Value) -> bool {
    match haystack {
        Value::Array(items) => items.iter().any(|item| values_equal(item, needle)),
        Value::String(text) => text.contains(&needle.to_string()),
        _ => false,
    }
}

/// `=~` for the patterns these slices compile: literals, `^`, `$`, and `.*`.
fn regex_match(text: &str, pattern: &str) -> Result<bool, RunError> {
    let start = pattern.starts_with('^');
    let end = pattern.ends_with('$');
    let body = pattern.trim_start_matches('^').trim_end_matches('$');
    if body.contains(".*") {
        let mut parts = body.split(".*");
        let head = parts.next().unwrap_or("");
        let tail = parts.next().unwrap_or("");
        if parts.next().is_some() {
            return Err(fail(format!(
                "condition regex {pattern} is outside the implemented pattern subset"
            )));
        }
        let head_at = if start {
            text.starts_with(head).then_some(0)
        } else {
            text.find(head)
        };
        let Some(head_at) = head_at else {
            return Ok(false);
        };
        let after = head_at + head.len();
        return Ok(if end {
            text[after..].ends_with(tail)
        } else {
            text[after..].contains(tail)
        });
    }
    if body.chars().any(|ch| {
        matches!(
            ch,
            '.' | '*' | '(' | ')' | '[' | ']' | '+' | '?' | '{' | '}' | '|' | '\\'
        )
    }) {
        return Err(fail(format!(
            "condition regex {pattern} is outside the implemented pattern subset"
        )));
    }
    Ok(match (start, end) {
        (true, true) => text == body,
        (true, false) => text.starts_with(body),
        (false, true) => text.ends_with(body),
        (false, false) => text.contains(body),
    })
}

fn arg<'a>(plugin: &'a Plugin, name: &str) -> Option<&'a Arg> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn arg_string(plugin: &Plugin, name: &str) -> Option<String> {
    match arg(plugin, name) {
        Some(Arg::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn arg_i64(plugin: &Plugin, name: &str) -> Option<i64> {
    match arg(plugin, name) {
        Some(Arg::Int(value)) => Some(*value),
        Some(Arg::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn arg_f64(plugin: &Plugin, name: &str) -> Option<f64> {
    match arg(plugin, name) {
        Some(Arg::Int(value)) => Some(*value as f64),
        Some(Arg::Float(value)) => Some(*value),
        Some(Arg::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn arg_text(arg: &Arg) -> Result<String, RunError> {
    match arg {
        Arg::String(value) => Ok(value.clone()),
        Arg::Int(value) => Ok(value.to_string()),
        Arg::Float(value) => Ok(value.to_string()),
        Arg::Big(value) => Ok(value.clone()),
        _ => Err(fail("plugin option value must be a scalar")),
    }
}

fn key_text(key: &Key) -> String {
    match key {
        Key::String(value) => value.clone(),
        Key::Int(value) => value.to_string(),
        Key::Big(value) => value.clone(),
        Key::Float(value) => value.to_string(),
    }
}

pub(crate) fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string())
}

/// `logstash.yml` keys this slice reads. Other keys are ignored.
pub fn apply_logstash_yml(settings: &mut Settings, text: &str) -> Result<(), RunError> {
    for raw in text.lines() {
        let line = strip_yaml_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(fail(format!(
                "logstash.yml entry is not key: value: {line}"
            )));
        };
        let key = key.trim();
        let value = unquote(value.trim());
        match key {
            "pipeline.workers" => {
                settings.workers = value
                    .parse()
                    .map_err(|_| fail(format!("pipeline.workers is not an integer: {value}")))?;
                settings.workers_set = true;
            }
            "pipeline.batch.size" => {
                settings.batch_size = value
                    .parse()
                    .map_err(|_| fail(format!("pipeline.batch.size is not an integer: {value}")))?;
            }
            "pipeline.batch.delay" => {
                let millis: u64 = value.parse().map_err(|_| {
                    fail(format!("pipeline.batch.delay is not an integer: {value}"))
                })?;
                settings.batch_delay = Duration::from_millis(millis);
            }
            "queue.type" => {
                settings.persisted_queue = match value.as_str() {
                    "memory" => false,
                    "persisted" => true,
                    other => {
                        return Err(fail(format!("queue.type {other} is not implemented")));
                    }
                };
            }
            "queue.page_capacity" => {
                settings.queue_page_capacity = parse_byte_size(&value)?;
            }
            "queue.compression" => {
                if !matches!(value.as_str(), "disabled" | "none") {
                    return Err(fail(format!(
                        "queue.compression {value} is not implemented"
                    )));
                }
            }
            "path.data" => settings.path_data = Some(value),
            "path.queue" => settings.path_queue = Some(value),
            "path.dead_letter_queue" => settings.path_dlq = Some(value),
            "dead_letter_queue.enable" => {
                settings.dlq_enabled = matches!(value.as_str(), "true");
            }
            "dead_letter_queue.max_bytes" => {
                settings.dlq_max_bytes = u64::try_from(parse_byte_size(&value)?).map_err(|_| {
                    fail(format!("dead_letter_queue.max_bytes is too large: {value}"))
                })?;
            }
            "dead_letter_queue.storage_policy" => {
                if !matches!(value.as_str(), "drop_newer" | "drop_older") {
                    return Err(fail(format!(
                        "dead_letter_queue.storage_policy {value} is not implemented"
                    )));
                }
                settings.dlq_storage_policy = value;
            }
            "pipeline.ecs_compatibility" => {
                settings.ecs = match value.as_str() {
                    "disabled" => Ecs::Disabled,
                    "v1" => Ecs::V1,
                    "v8" => Ecs::V8,
                    other => {
                        return Err(fail(format!(
                            "pipeline.ecs_compatibility {other} is not implemented"
                        )));
                    }
                };
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineConfig {
    pub id: String,
    pub config: String,
}

/// Subset of `pipelines.yml`: a list of `pipeline.id` plus `config.string` or `path.config`.
pub fn load_pipelines_yml(text: &str) -> Result<Vec<PipelineConfig>, RunError> {
    let mut pipelines = Vec::new();
    let mut current: Option<PipelineConfig> = None;
    for raw in text.lines() {
        let line = strip_yaml_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("- ") {
            if let Some(done) = current.take() {
                pipelines.push(done);
            }
            current = Some(PipelineConfig {
                id: String::new(),
                config: String::new(),
            });
            if !rest.is_empty() {
                assign_pipeline(current.as_mut().expect("current"), rest)?;
            }
        } else if let Some(pipeline) = current.as_mut() {
            assign_pipeline(pipeline, line)?;
        } else {
            return Err(fail(
                "pipelines.yml must be a list of pipeline.id entries".to_string(),
            ));
        }
    }
    if let Some(done) = current {
        pipelines.push(done);
    }
    if pipelines.is_empty() {
        return Err(fail("Pipelines YAML file is empty"));
    }
    let mut seen = HashSet::new();
    for pipeline in &pipelines {
        if pipeline.id.is_empty() {
            return Err(fail(
                "each pipelines.yml entry needs pipeline.id and config.string or path.config",
            ));
        }
        if !seen.insert(pipeline.id.clone()) {
            return Err(fail(format!(
                "ConfigurationError: duplicate pipeline ids {}",
                pipeline.id
            )));
        }
    }
    Ok(pipelines)
}

fn pipeline_setting(key: &str) -> bool {
    matches!(
        key,
        "config.debug"
            | "config.support_escapes"
            | "config.string"
            | "dead_letter_queue.enable"
            | "dead_letter_queue.flush_interval"
            | "dead_letter_queue.flush_check_interval"
            | "dead_letter_queue.max_bytes"
            | "dead_letter_queue.storage_policy"
            | "dead_letter_queue.retain.age"
            | "metric.collect"
            | "pipeline.plugin_classloaders"
            | "path.config"
            | "path.dead_letter_queue"
            | "path.queue"
            | "pipeline.batch.delay"
            | "pipeline.batch.output_chunking.growth_threshold_factor"
            | "pipeline.batch.metrics.sampling_mode"
            | "pipeline.batch.size"
            | "pipeline.id"
            | "pipeline.reloadable"
            | "pipeline.recoverable"
            | "pipeline.system"
            | "pipeline.workers"
            | "pipeline.ordered"
            | "pipeline.ecs_compatibility"
            | "queue.checkpoint.acks"
            | "queue.checkpoint.interval"
            | "queue.checkpoint.writes"
            | "queue.checkpoint.retry"
            | "queue.compression"
            | "queue.drain"
            | "queue.max_bytes"
            | "queue.max_events"
            | "queue.page_capacity"
            | "queue.type"
    )
}

/// Run the filter section of a config against one event.
/// Configs that are only a `filter` block are wrapped so the existing compiler can read them.
pub fn apply_filter(config: &str, event: &mut Event) -> Result<(), RunError> {
    let source = format!(
        "input {{ generator {{ count => 1 }} }}\n{config}\noutput {{ stdout {{ codec => plain }} }}"
    );
    let pipeline = compile_imperative(&source, false).map_err(|error| fail(error.to_string()))?;
    let shared = Shared {
        queue: Queue::new(0),
        filter: pipeline.filter.clone(),
        output: Statement::Noop,
        settings: Settings::default(),
        stdout: Mutex::new(String::new()),
        events: Mutex::new(Vec::new()),
        error: Mutex::new(None),
        disk: Mutex::new(None),
    };
    let owned = std::mem::take(event);
    let mut produced = apply(&pipeline.filter, owned, &shared)?;
    if produced.is_empty() {
        event.cancel();
    } else {
        *event = produced.remove(0);
    }
    if let Some(message) = shared.error.lock().expect("error").clone() {
        return Err(fail(message));
    }
    Ok(())
}

fn assign_pipeline(pipeline: &mut PipelineConfig, line: &str) -> Result<(), RunError> {
    let Some((key, value)) = line.split_once(':') else {
        return Err(fail(format!(
            "pipelines.yml entry is not key: value: {line}"
        )));
    };
    let value = unquote(value.trim());
    match key.trim() {
        "pipeline.id" => pipeline.id = value,
        "config.string" => pipeline.config = value,
        "path.config" => {
            pipeline.config = std::fs::read_to_string(&value)
                .map_err(|error| fail(format!("cannot read path.config {value}: {error}")))?;
        }
        "config.reload.automatic" | "config.reload.interval" => {}
        other if pipeline_setting(other) => {}
        other => {
            return Err(fail(format!(
                "Only pipeline related settings are expected. Received \"{other}\"."
            )));
        }
    }
    Ok(())
}

fn queue_dir(settings: &Settings) -> Result<std::path::PathBuf, RunError> {
    let root = if let Some(path) = &settings.path_queue {
        std::path::PathBuf::from(path)
    } else if let Some(path) = &settings.path_data {
        std::path::PathBuf::from(path).join("queue")
    } else {
        return Err(fail("persisted queue requires path.data or path.queue"));
    };
    Ok(root.join(&settings.pipeline_id))
}

fn parse_byte_size(value: &str) -> Result<usize, RunError> {
    let text = value.trim().to_ascii_lowercase();
    let (number, factor) = if let Some(number) = text.strip_suffix("kb") {
        (number, 1024usize)
    } else if let Some(number) = text.strip_suffix("mb") {
        (number, 1024 * 1024)
    } else if let Some(number) = text.strip_suffix("gb") {
        (number, 1024 * 1024 * 1024)
    } else {
        (text.as_str(), 1)
    };
    let number: usize = number
        .trim()
        .parse()
        .map_err(|_| fail(format!("queue.page_capacity is not a size: {value}")))?;
    Ok(number.saturating_mul(factor))
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..index],
            _ => {}
        }
    }
    line
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

struct Queue {
    state: Mutex<QueueState>,
    ready: Condvar,
}

struct QueueState {
    items: VecDeque<Event>,
    inputs_alive: usize,
}

impl Queue {
    fn new(inputs: usize) -> Self {
        Self {
            state: Mutex::new(QueueState {
                items: VecDeque::new(),
                inputs_alive: inputs,
            }),
            ready: Condvar::new(),
        }
    }

    fn push(&self, event: Event) {
        let mut state = self.state.lock().expect("queue");
        state.items.push_back(event);
        self.ready.notify_all();
    }

    fn close_input(&self) {
        let mut state = self.state.lock().expect("queue");
        state.inputs_alive = state.inputs_alive.saturating_sub(1);
        self.ready.notify_all();
    }

    fn read_batch(&self, batch_size: usize, delay: Duration) -> Option<Vec<Event>> {
        let mut state = self.state.lock().expect("queue");
        let mut waited = Duration::ZERO;
        let started = Instant::now();
        loop {
            if state.items.len() >= batch_size {
                return Some(drain(&mut state, batch_size));
            }
            if state.inputs_alive == 0 {
                if state.items.is_empty() {
                    return None;
                }
                return Some(drain(&mut state, batch_size));
            }
            let timeout = if state.items.is_empty() {
                Duration::from_secs(30)
            } else {
                delay.saturating_sub(waited)
            };
            let (next, status) = self.ready.wait_timeout(state, timeout).expect("queue wait");
            state = next;
            waited = started.elapsed();
            if status.timed_out() && !state.items.is_empty() {
                return Some(drain(&mut state, batch_size));
            }
        }
    }
}

fn drain(state: &mut QueueState, batch_size: usize) -> Vec<Event> {
    let count = state.items.len().min(batch_size);
    state.items.drain(..count).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_subset_reads_workers_and_two_pipelines() {
        let mut settings = Settings::default();
        apply_logstash_yml(
            &mut settings,
            "pipeline.workers: 2\npipeline.batch.size: 10\npipeline.ecs_compatibility: disabled\n",
        )
        .expect("yml");
        assert_eq!(settings.workers, 2);
        assert_eq!(settings.batch_size, 10);
        assert_eq!(settings.ecs, Ecs::Disabled);
        let pipelines = load_pipelines_yml(
            "- pipeline.id: alpha\n  config.string: input { generator { count => 1 } }\n- pipeline.id: beta\n  config.string: input { generator { count => 1 } }\n",
        )
        .expect("pipelines");
        assert_eq!(pipelines.len(), 2);
        assert_eq!(pipelines[0].id, "alpha");
        assert_eq!(pipelines[1].id, "beta");
    }

    #[test]
    fn line_codec_emits_complete_lines_and_keeps_the_tail() {
        let codec = CodecSpec {
            name: "line".to_string(),
            delimiter: "\n".to_string(),
            format: None,
            metadata: false,
        };
        let mut pending = String::new();
        let lines = codec_decode(&codec, &mut pending, "one\ntwo").expect("decode");
        assert_eq!(lines, vec!["one".to_string()]);
        assert_eq!(pending, "two");
    }
}
