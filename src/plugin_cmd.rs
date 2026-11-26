//! `logstash-plugin list` for the plugins compiled into this binary.
//!
//! Versions are the 9.5.2 gem versions. `install`, `remove`, and `update`
//! change a Ruby gem home; this process has no gem home, so those commands
//! fail. `jdbc_streaming` and `jdbc_static` are not listed under the jdbc
//! integration because they are not implemented. The `elastic_agent` alias of
//! beats is not listed because that config name is not accepted.

use fancy_regex::Regex;

struct Gem {
    name: &'static str,
    version: &'static str,
    group: &'static str,
    children: &'static [&'static str],
}

const GEMS: &[Gem] = &[
    Gem {
        name: "logstash-codec-dots",
        version: "3.0.6",
        group: "codec",
        children: &[],
    },
    Gem {
        name: "logstash-codec-json",
        version: "3.1.1",
        group: "codec",
        children: &[],
    },
    Gem {
        name: "logstash-codec-json_lines",
        version: "3.2.2",
        group: "codec",
        children: &[],
    },
    Gem {
        name: "logstash-codec-line",
        version: "3.1.1",
        group: "codec",
        children: &[],
    },
    Gem {
        name: "logstash-codec-multiline",
        version: "3.1.2",
        group: "codec",
        children: &[],
    },
    Gem {
        name: "logstash-codec-plain",
        version: "3.1.0",
        group: "codec",
        children: &[],
    },
    Gem {
        name: "logstash-codec-rubydebug",
        version: "3.1.0",
        group: "codec",
        children: &[],
    },
    Gem {
        name: "logstash-filter-anonymize",
        version: "3.0.8",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-clone",
        version: "4.2.0",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-csv",
        version: "3.1.1",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-date",
        version: "3.2.1",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-de_dot",
        version: "1.2.0",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-dissect",
        version: "1.3.0",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-drop",
        version: "3.0.5",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-elasticsearch",
        version: "4.4.1",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-fingerprint",
        version: "3.5.0",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-grok",
        version: "4.4.4",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-json",
        version: "3.2.1",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-kv",
        version: "4.7.0",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-mutate",
        version: "3.6.0",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-prune",
        version: "3.0.4",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-sleep",
        version: "3.0.7",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-split",
        version: "3.1.10",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-syslog_pri",
        version: "3.2.1",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-truncate",
        version: "1.0.6",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-urldecode",
        version: "3.0.6",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-filter-uuid",
        version: "3.0.5",
        group: "filter",
        children: &[],
    },
    Gem {
        name: "logstash-input-beats",
        version: "7.0.13",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-dead_letter_queue",
        version: "2.0.2",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-elasticsearch",
        version: "5.3.2",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-exec",
        version: "3.6.0",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-file",
        version: "4.4.7",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-generator",
        version: "3.1.0",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-heartbeat",
        version: "3.1.1",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-http",
        version: "4.1.13",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-stdin",
        version: "3.4.0",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-tcp",
        version: "7.0.12",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-input-udp",
        version: "3.5.0",
        group: "input",
        children: &[],
    },
    Gem {
        name: "logstash-integration-jdbc",
        version: "5.6.4",
        group: "integration",
        children: &["logstash-input-jdbc"],
    },
    Gem {
        name: "logstash-integration-kafka",
        version: "12.1.5",
        group: "integration",
        children: &["logstash-input-kafka", "logstash-output-kafka"],
    },
    Gem {
        name: "logstash-output-elasticsearch",
        version: "12.1.6",
        group: "output",
        children: &[],
    },
    Gem {
        name: "logstash-output-file",
        version: "4.3.0",
        group: "output",
        children: &[],
    },
    Gem {
        name: "logstash-output-http",
        version: "6.0.1",
        group: "output",
        children: &[],
    },
    Gem {
        name: "logstash-output-null",
        version: "3.0.5",
        group: "output",
        children: &[],
    },
    Gem {
        name: "logstash-output-stdout",
        version: "3.1.4",
        group: "output",
        children: &[],
    },
    Gem {
        name: "logstash-output-tcp",
        version: "7.0.1",
        group: "output",
        children: &[],
    },
    Gem {
        name: "logstash-output-udp",
        version: "3.3.0",
        group: "output",
        children: &[],
    },
];

pub(crate) fn execute(args: &[String]) -> Result<String, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("plugin command is required".to_string());
    };
    if command == "--help" || command == "-h" {
        return Ok(usage());
    }
    match command {
        "list" => list(&args[1..]),
        "install"
        | "remove"
        | "update"
        | "pack"
        | "unpack"
        | "generate"
        | "uninstall"
        | "prepare-offline-pack" => Err(format!(
            "plugin {command} is not implemented; plugins are compiled into this binary"
        )),
        other => Err(format!("plugin command {other} is not implemented")),
    }
}

fn usage() -> String {
    "\
Usage: rstash plugin list [PATTERN] [--verbose] [--group NAME] [--installed] [--no-expand]
Commands that change a gem install (install, remove, update, pack, unpack, generate, prepare-offline-pack) are not implemented.
"
    .to_string()
}

fn list(args: &[String]) -> Result<String, String> {
    let mut verbose = false;
    let mut installed = false;
    let mut expand = true;
    let mut group = None;
    let mut pattern = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--verbose" => verbose = true,
            "--installed" => installed = true,
            "--expand" => expand = true,
            "--no-expand" => expand = false,
            "--group" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--group needs a value".to_string())?;
                if !matches!(
                    value.as_str(),
                    "input" | "output" | "filter" | "codec" | "pack" | "integration"
                ) {
                    return Err(
                        "should be one of: input, output, filter, codec, integration".to_string(),
                    );
                }
                group = Some(value.clone());
            }
            "--help" | "-h" => return Ok("List all installed Logstash plugins\n".to_string()),
            other if other.starts_with('-') => {
                return Err(format!("unknown plugin list flag {other}"));
            }
            other => pattern = Some(other.to_string()),
        }
        index += 1;
    }
    if installed {
        return Err("No plugins found".to_string());
    }
    let regex = match &pattern {
        Some(text) => Some(
            Regex::new(&format!("(?i){text}"))
                .map_err(|error| format!("plugin list pattern is invalid: {error}"))?,
        ),
        None => None,
    };
    let mut lines = Vec::new();
    for gem in GEMS {
        if group.as_deref().is_some_and(|wanted| gem.group != wanted) {
            continue;
        }
        if let Some(regex) = &regex {
            let child_hit = gem.children.iter().any(|child| regex_match(regex, child));
            if !regex_match(regex, gem.name) && !child_hit {
                continue;
            }
        }
        let mut line = gem.name.to_string();
        if verbose {
            line.push_str(&format!(" ({})", gem.version));
        }
        lines.push(line);
        if expand && !gem.children.is_empty() {
            let last = gem.children.len() - 1;
            for (index, child) in gem.children.iter().enumerate() {
                let branch = if index == last {
                    " └── "
                } else {
                    " ├── "
                };
                lines.push(format!("{branch}{child}"));
            }
        }
    }
    if lines.is_empty() {
        return Err("No plugins found".to_string());
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn regex_match(regex: &Regex, text: &str) -> bool {
    regex.is_match(text).unwrap_or(false)
}
