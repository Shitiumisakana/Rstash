//! `logstash` flags this slice accepts: `-e`, `-f`, `-t`, `-w`, `-b`,
//! `--path.settings`, `--api.http.port`, `--api.http.host`, and
//! `--config.reload.automatic`. Subcommands: `pqcheck`, `pqrepair`, `plugin`,
//! `keystore`.

use std::io::Write;
use std::path::Path;

use crate::run::{
    PipelineConfig, RunError, Settings, apply_logstash_yml, load_pipelines_yml, run, run_many,
};

pub fn execute(args: &[String], stdout: &mut dyn Write) -> Result<i32, String> {
    let mut config_string = None;
    let mut config_path = None;
    let mut settings_path = None;
    let mut workers = None;
    let mut batch_size = None;
    let mut api_port = None;
    let mut api_host = None;
    let mut reload_automatic = None;
    let mut index = 0;
    let mut test_and_exit = false;
    if args.first().map(String::as_str) == Some("plugin") {
        let text = crate::plugin_cmd::execute(&args[1..])?;
        let _ = write!(stdout, "{text}");
        return Ok(0);
    }
    if args.first().map(String::as_str) == Some("keystore") {
        let text = crate::keystore::execute(&args[1..])?;
        let _ = write!(stdout, "{text}");
        return Ok(0);
    }
    if args.first().map(String::as_str) == Some("pqcheck") {
        let path = args
            .get(1)
            .ok_or_else(|| "pqcheck needs a queue directory".to_string())?;
        crate::queue::check_directory(Path::new(path)).map_err(show)?;
        let _ = writeln!(stdout, "OK");
        return Ok(0);
    }
    if args.first().map(String::as_str) == Some("pqrepair") {
        let path = args
            .get(1)
            .ok_or_else(|| "No queue directory given.".to_string())?;
        crate::queue::repair(Path::new(path)).map_err(show)?;
        let _ = writeln!(stdout, "Repair is done");
        return Ok(0);
    }
    while index < args.len() {
        let arg = args[index].as_str();
        let next = || {
            args.get(index + 1)
                .cloned()
                .ok_or_else(|| format!("flag {arg} needs a value"))
        };
        match arg {
            "-e" | "--config.string" => {
                config_string = Some(next()?);
                index += 2;
            }
            "-f" | "--path.config" => {
                config_path = Some(next()?);
                index += 2;
            }
            "-w" | "--pipeline.workers" => {
                workers = Some(parse_usize(&next()?, "pipeline.workers")?);
                index += 2;
            }
            "-b" | "--pipeline.batch.size" => {
                batch_size = Some(parse_usize(&next()?, "pipeline.batch.size")?);
                index += 2;
            }
            "--path.settings" => {
                settings_path = Some(next()?);
                index += 2;
            }
            "--api.http.port" => {
                api_port = Some(parse_u16(&next()?, "api.http.port")?);
                index += 2;
            }
            "--api.http.host" => {
                api_host = Some(next()?);
                index += 2;
            }
            "--config.reload.automatic" => {
                reload_automatic = Some(next()?);
                index += 2;
            }
            "-t" | "--config.test_and_exit" => {
                test_and_exit = true;
                index += 1;
            }
            "-h" | "--help" => {
                let _ = writeln!(
                    stdout,
                    "rstash [-e CONFIG | -f PATH | --path.settings DIR] [-t] [-w N] [-b N]"
                );
                return Ok(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }

    let mut settings = Settings::default();
    if let Some(dir) = &settings_path {
        let yml = Path::new(dir).join("logstash.yml");
        if yml.is_file() {
            let text = std::fs::read_to_string(&yml)
                .map_err(|error| format!("cannot read {}: {error}", yml.display()))?;
            apply_logstash_yml(&mut settings, &text).map_err(show)?;
        }
    }
    if let Some(workers) = workers {
        settings.workers = workers;
        settings.workers_set = true;
    }
    if let Some(batch_size) = batch_size {
        settings.batch_size = batch_size;
    }
    if let Some(port) = api_port {
        settings.api_port = Some(port);
    }
    if let Some(host) = api_host
        && !matches!(host.as_str(), "127.0.0.1" | "localhost")
    {
        return Err("api.http.host other than 127.0.0.1 is not implemented".to_string());
    }
    if reload_automatic.as_deref() == Some("true") {
        return Err("pipeline reload is not implemented".to_string());
    }
    settings.test_and_exit = test_and_exit;

    if config_string.is_some() && config_path.is_some() {
        return Err("use either -e or -f, not both".to_string());
    }

    let pipelines = if let Some(text) = config_string {
        vec![PipelineConfig {
            id: "main".to_string(),
            config: text,
        }]
    } else if let Some(path) = config_path {
        vec![PipelineConfig {
            id: "main".to_string(),
            config: read_config_path(Path::new(&path))?,
        }]
    } else if let Some(dir) = &settings_path {
        let yml = Path::new(dir).join("pipelines.yml");
        if yml.is_file() {
            let text = std::fs::read_to_string(&yml)
                .map_err(|error| format!("cannot read {}: {error}", yml.display()))?;
            load_pipelines_yml(&text).map_err(show)?
        } else {
            return Err(format!(
                "Failed to read pipelines yaml file. Location: {}",
                yml.display()
            ));
        }
    } else {
        return Err(
            "no configuration. Use -e, -f, or --path.settings with pipelines.yml".to_string(),
        );
    };

    if settings.test_and_exit {
        for pipeline in &pipelines {
            run(&pipeline.config, &settings).map_err(show)?;
        }
        let _ = writeln!(stdout, "Configuration OK");
        return Ok(0);
    }

    let named: Vec<(String, String)> = pipelines
        .into_iter()
        .map(|pipeline| (pipeline.id, pipeline.config))
        .collect();
    let results = run_many(&named, &settings).map_err(show)?;
    for (_, result) in results {
        stdout
            .write_all(result.stdout.as_bytes())
            .map_err(|error| error.to_string())?;
    }
    Ok(0)
}

fn read_config_path(path: &Path) -> Result<String, String> {
    if path.is_dir() {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(path).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let file = entry.path();
            if file.extension().and_then(|ext| ext.to_str()) == Some("conf") {
                files.push(file);
            }
        }
        files.sort();
        if files.is_empty() {
            return Err(format!("no .conf files in {}", path.display()));
        }
        let mut text = String::new();
        for file in files {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(
                &std::fs::read_to_string(&file)
                    .map_err(|error| format!("cannot read {}: {error}", file.display()))?,
            );
        }
        Ok(text)
    } else {
        std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))
    }
}

fn parse_u16(text: &str, name: &str) -> Result<u16, String> {
    text.parse()
        .map_err(|_| format!("{name} is not an integer: {text}"))
}

fn parse_usize(text: &str, name: &str) -> Result<usize, String> {
    text.parse()
        .map_err(|_| format!("{name} is not an integer: {text}"))
}

fn show(error: RunError) -> String {
    error.message
}
