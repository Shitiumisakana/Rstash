//! In-process pipeline bus from Logstash 9.5.2 `PipelineBusV2`.
//!
//! `output { pipeline { send_to => ... } }` clones each event onto the named
//! addresses. `input { pipeline { address => ... } }` reads those clones.
//! Official `ensure_delivery` retries once a second until shutdown. This
//! process has no shutdown signal, so a missing input, a missing sender, or a
//! cycle fails the run instead of waiting forever.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};

use crate::event::Event;
use crate::lscl::{Arg, Key, Kind, Plugin, Statement};
use crate::run::{RunError, fail};
use crate::value::Value;

struct Slot {
    listener: bool,
    senders: usize,
    finished: usize,
    events: VecDeque<Event>,
}

pub(crate) struct Bus {
    inner: Mutex<HashMap<String, Slot>>,
    cv: Condvar,
}

impl Bus {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            cv: Condvar::new(),
        }
    }

    pub(crate) fn listen(&self, address: &str) -> Result<(), RunError> {
        let mut guard = self.inner.lock().expect("bus");
        let slot = guard.entry(address.to_string()).or_insert_with(empty_slot);
        if slot.listener {
            return Err(fail(format!(
                "Internal input at '{address}' already bound! Addresses must be globally unique across pipelines."
            )));
        }
        slot.listener = true;
        self.cv.notify_all();
        Ok(())
    }

    fn add_sender(&self, address: &str) {
        let mut guard = self.inner.lock().expect("bus");
        let slot = guard.entry(address.to_string()).or_insert_with(empty_slot);
        slot.senders += 1;
    }

    pub(crate) fn finish_sender(&self, address: &str) {
        let mut guard = self.inner.lock().expect("bus");
        if let Some(slot) = guard.get_mut(address) {
            slot.finished += 1;
        }
        self.cv.notify_all();
    }

    pub(crate) fn send(&self, address: &str, event: Event, ensure: bool) -> Result<(), RunError> {
        let mut pending = Some(event);
        let mut guard = self.inner.lock().expect("bus");
        loop {
            let delivered = {
                let Some(slot) = guard.get_mut(address) else {
                    if ensure {
                        return Err(fail(format!(
                            "pipeline output send_to \"{address}\" has no pipeline input in this process"
                        )));
                    }
                    return Ok(());
                };
                if slot.listener {
                    slot.events
                        .push_back(pending.take().expect("pipeline event"));
                    true
                } else if ensure {
                    false
                } else {
                    return Ok(());
                }
            };
            if delivered {
                self.cv.notify_all();
                return Ok(());
            }
            guard = self.cv.wait(guard).expect("bus");
        }
    }

    pub(crate) fn recv(&self, address: &str) -> Result<Option<Event>, RunError> {
        let mut guard = self.inner.lock().expect("bus");
        loop {
            enum Step {
                Event(Event),
                Done,
                Wait,
            }
            let step = {
                let Some(slot) = guard.get_mut(address) else {
                    return Err(fail(format!(
                        "pipeline input address \"{address}\" has no sender in this process"
                    )));
                };
                if let Some(event) = slot.events.pop_front() {
                    Step::Event(event)
                } else if slot.finished >= slot.senders {
                    Step::Done
                } else {
                    Step::Wait
                }
            };
            match step {
                Step::Event(event) => return Ok(Some(event)),
                Step::Done => return Ok(None),
                Step::Wait => guard = self.cv.wait(guard).expect("bus"),
            }
        }
    }
}

fn empty_slot() -> Slot {
    Slot {
        listener: false,
        senders: 0,
        finished: 0,
        events: VecDeque::new(),
    }
}

pub(crate) struct Launch {
    pub(crate) bus: Option<Arc<Bus>>,
    pub(crate) senders: HashMap<String, Vec<String>>,
}

pub(crate) fn prepare(pipelines: &[(String, crate::lscl::Pipeline)]) -> Result<Launch, RunError> {
    let mut listeners: HashMap<String, String> = HashMap::new();
    let mut sends: Vec<(String, Vec<String>, bool)> = Vec::new();
    let mut used = false;
    for (id, pipeline) in pipelines {
        for plugin in plugins(&pipeline.input, Kind::Input, "pipeline") {
            used = true;
            validate(plugin)?;
            let address = address(plugin)?;
            if listeners.contains_key(&address) {
                return Err(fail(format!(
                    "Internal input at '{address}' already bound! Addresses must be globally unique across pipelines."
                )));
            }
            listeners.insert(address, id.clone());
        }
        for plugin in plugins(&pipeline.output, Kind::Output, "pipeline") {
            used = true;
            validate(plugin)?;
            sends.push((id.clone(), send_to(plugin)?, ensure_delivery(plugin)?));
        }
    }
    if !used {
        return Ok(Launch {
            bus: None,
            senders: HashMap::new(),
        });
    }
    for address in listeners.keys() {
        let has_sender = sends
            .iter()
            .any(|(_, addresses, _)| addresses.contains(address));
        if !has_sender {
            return Err(fail(format!(
                "pipeline input address \"{address}\" has no sender in this process"
            )));
        }
    }
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    let mut sender_addresses: HashMap<String, Vec<String>> = HashMap::new();
    for (id, addresses, ensure) in &sends {
        for address in addresses {
            if let Some(listener) = listeners.get(address) {
                edges.entry(id.clone()).or_default().push(listener.clone());
                sender_addresses
                    .entry(id.clone())
                    .or_default()
                    .push(address.clone());
            } else if *ensure {
                return Err(fail(format!(
                    "pipeline output send_to \"{address}\" has no pipeline input in this process"
                )));
            }
        }
    }
    if cycle(&edges) {
        return Err(fail("pipeline send cycle is not implemented".to_string()));
    }
    let bus = Arc::new(Bus::new());
    for addresses in sender_addresses.values() {
        for address in addresses {
            bus.add_sender(address);
        }
    }
    Ok(Launch {
        bus: Some(bus),
        senders: sender_addresses,
    })
}

pub(crate) fn validate(plugin: &Plugin) -> Result<(), RunError> {
    let role = match plugin.kind {
        Kind::Input => "input",
        Kind::Output => "output",
        Kind::Filter => "filter",
        Kind::Codec => "codec",
    };
    for (name, _) in &plugin.args {
        if let Some(extra) = obsolete(plugin.kind, name) {
            return Err(fail(obsolete_message(name, extra)));
        }
        if !allowed(plugin.kind, name) {
            return Err(fail(format!("Unknown setting '{name}' for pipeline")));
        }
    }
    match plugin.kind {
        Kind::Input => {
            address(plugin)?;
        }
        Kind::Output => {
            if arg(plugin, "send_to").is_none() {
                return Err(fail(missing(role, "send_to")));
            }
            if send_to(plugin)?.is_empty() {
                return Err(fail(missing(role, "send_to")));
            }
            ensure_delivery(plugin)?;
        }
        Kind::Filter | Kind::Codec => {}
    }
    if let Some(value) = arg(plugin, "enable_metric") {
        boolean(value)?;
    }
    Ok(())
}

pub(crate) fn deliver(bus: &Bus, plugin: &Plugin, event: &Event) -> Result<(), RunError> {
    let ensure = ensure_delivery(plugin)?;
    for address in send_to(plugin)? {
        bus.send(&address, event.clone(), ensure)?;
    }
    Ok(())
}

pub(crate) fn address(plugin: &Plugin) -> Result<String, RunError> {
    match arg(plugin, "address") {
        Some(Arg::String(value)) => Ok(value.clone()),
        Some(_) => Err(fail(
            "Expected string for pipeline input address".to_string(),
        )),
        None => Err(fail(missing("input", "address"))),
    }
}

pub(crate) fn decorate(plugin: &Plugin, event: &mut Event) -> Result<(), RunError> {
    if let Some(Arg::String(kind)) = arg(plugin, "type")
        && !event
            .includes("type")
            .map_err(|error| fail(error.to_string()))?
    {
        event
            .set_field("type", Value::from(kind.as_str()))
            .map_err(|error| fail(error.to_string()))?;
    }
    if let Some(Arg::Map(entries)) = arg(plugin, "add_field") {
        for (key, value) in entries {
            let field = event
                .sprintf(&key_text(key))
                .map_err(|error| fail(error.to_string()))?;
            for item in field_values(value)? {
                let text = event
                    .sprintf(&item)
                    .map_err(|error| fail(error.to_string()))?;
                crate::mutate::add_field(event, &field, Value::from(text))?;
            }
        }
    }
    if let Some(Arg::Array(tags)) = arg(plugin, "tags") {
        for tag in tags {
            let tag = scalar_text(tag)?;
            let tag = event
                .sprintf(&tag)
                .map_err(|error| fail(error.to_string()))?;
            event.tag(&tag);
        }
    }
    Ok(())
}

fn plugins<'a>(statement: &'a Statement, kind: Kind, name: &str) -> Vec<&'a Plugin> {
    let mut found = Vec::new();
    walk(statement, kind, name, &mut found);
    found
}

fn walk<'a>(statement: &'a Statement, kind: Kind, name: &str, found: &mut Vec<&'a Plugin>) {
    match statement {
        Statement::Plugin(plugin) => {
            if plugin.kind == kind && plugin.name == name {
                found.push(plugin);
            }
        }
        Statement::Sequence(children) | Statement::Parallel(children) => {
            for child in children {
                walk(child, kind, name, found);
            }
        }
        Statement::If {
            when_true,
            when_false,
            ..
        } => {
            walk(when_true, kind, name, found);
            walk(when_false, kind, name, found);
        }
        Statement::Noop => {}
    }
}

fn cycle(edges: &HashMap<String, Vec<String>>) -> bool {
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for node in edges.keys() {
        if walk_cycle(node, edges, &mut visiting, &mut visited) {
            return true;
        }
    }
    false
}

fn walk_cycle(
    node: &str,
    edges: &HashMap<String, Vec<String>>,
    visiting: &mut HashSet<String>,
    visited: &mut HashSet<String>,
) -> bool {
    if visited.contains(node) {
        return false;
    }
    if !visiting.insert(node.to_string()) {
        return true;
    }
    if let Some(next) = edges.get(node) {
        for child in next {
            if walk_cycle(child, edges, visiting, visited) {
                return true;
            }
        }
    }
    visiting.remove(node);
    visited.insert(node.to_string());
    false
}

fn allowed(kind: Kind, name: &str) -> bool {
    match kind {
        Kind::Input => matches!(
            name,
            "address" | "type" | "tags" | "add_field" | "codec" | "id" | "enable_metric"
        ),
        Kind::Output => matches!(
            name,
            "send_to" | "ensure_delivery" | "codec" | "id" | "enable_metric" | "workers"
        ),
        Kind::Filter | Kind::Codec => false,
    }
}

fn obsolete(kind: Kind, name: &str) -> Option<&'static str> {
    match (kind, name) {
        (Kind::Input, "debug") => Some(
            "This setting no longer has any effect. In past releases, it existed, but almost no plugin made use of it.",
        ),
        (Kind::Input, "format") => Some("You should use the newer 'codec' setting instead."),
        (Kind::Input, "charset") => Some(
            "Use the codec setting instead. For example: input { pipeline { codec => plain { charset => \"UTF-8\" } }",
        ),
        (Kind::Input, "message_format") => Some("Setting is no longer valid."),
        (Kind::Output, "type") => Some(
            "You can achieve this same behavior with the new conditionals, like: `if [type] == \"sometype\" { pipeline { ... } }`.",
        ),
        (Kind::Output, "tags") => Some(
            "You can achieve similar behavior with the new conditionals, like: `if \"sometag\" in [tags] { pipeline { ... } }`",
        ),
        (Kind::Output, "exclude_tags") => Some(
            "You can achieve similar behavior with the new conditionals, like: `if (\"sometag\" not in [tags]) { pipeline { ... } }`",
        ),
        _ => None,
    }
}

fn obsolete_message(name: &str, extra: &str) -> String {
    format!(
        "The setting `{name}` in plugin `pipeline` is obsolete and is no longer available. {extra} If you have any questions about this, you are invited to visit https://discuss.elastic.co/c/logstash and ask."
    )
}

fn missing(role: &str, setting: &str) -> String {
    format!(
        "Missing a required setting for the pipeline {role} plugin:\n\n  {role} {{\n    pipeline {{\n      {setting} => # SETTING MISSING\n      ...\n    }}\n  }}"
    )
}

fn send_to(plugin: &Plugin) -> Result<Vec<String>, RunError> {
    match arg(plugin, "send_to") {
        Some(Arg::String(value)) => Ok(vec![value.clone()]),
        Some(Arg::Array(items)) => items.iter().map(scalar_text).collect(),
        Some(_) => Err(fail(
            "pipeline output send_to must be a string or a list of strings",
        )),
        None => Ok(Vec::new()),
    }
}

fn ensure_delivery(plugin: &Plugin) -> Result<bool, RunError> {
    match arg(plugin, "ensure_delivery") {
        Some(value) => boolean(value),
        None => Ok(true),
    }
}

fn boolean(value: &Arg) -> Result<bool, RunError> {
    match value {
        Arg::String(text) if text == "true" => Ok(true),
        Arg::String(text) if text == "false" => Ok(false),
        Arg::String(text) => Err(fail(format!(
            "Expected boolean 'true' or 'false', got \"{text}\""
        ))),
        _ => Err(fail("Expected boolean 'true' or 'false'".to_string())),
    }
}

fn arg<'a>(plugin: &'a Plugin, name: &str) -> Option<&'a Arg> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn field_values(value: &Arg) -> Result<Vec<String>, RunError> {
    match value {
        Arg::Array(items) => items.iter().map(scalar_text).collect(),
        other => Ok(vec![scalar_text(other)?]),
    }
}

fn scalar_text(value: &Arg) -> Result<String, RunError> {
    match value {
        Arg::String(text) => Ok(text.clone()),
        Arg::Int(number) => Ok(number.to_string()),
        Arg::Big(text) => Ok(text.clone()),
        Arg::Float(number) => Ok(number.to_string()),
        _ => Err(fail("plugin option value must be a scalar")),
    }
}

fn key_text(key: &Key) -> String {
    match key {
        Key::String(text) => text.clone(),
        Key::Int(number) => number.to_string(),
        Key::Big(text) => text.clone(),
        Key::Float(number) => number.to_string(),
    }
}
