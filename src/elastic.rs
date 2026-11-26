//! Elasticsearch output from logstash-output-elasticsearch 12.1.6.
//!
//! The default path follows the 9.5.2 plugin. ECS on and `data_stream` left at
//! `auto` writes a `create` bulk action to `logs-generic-default`. ECS off uses
//! the rollover alias (`logstash` or `ecs-logstash`) when ILM stays at `auto`,
//! installs the shipped index template, and creates the default ILM policy.
//! Action metadata keeps nil `_id` and `routing`, matching JrJackson.
//!
//! `https`, `ssl_enabled`, sniffing, and `api_key` stop with an error. Bulk
//! gzip uses stored deflate blocks so a normal inflater recovers the same
//! NDJSON; the compressed bytes are not zlib level 1. A failed bulk is not
//! retried forever: this pipeline has no shutdown signal.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use crate::event::Event;
use crate::lscl::{Arg, Plugin};
use crate::run::{Ecs, RunError, Settings, fail};

const POLICY: &str = "logstash-policy";
const ILM_PATTERN: &str = "{now/d}-000001";

pub(crate) fn send(plugin: &Plugin, event: &Event, settings: &Settings) -> Result<(), RunError> {
    let config = Config::from_plugin(plugin, settings.ecs)?;
    let hosts = endpoints(plugin)?;
    let host = hosts
        .first()
        .ok_or_else(|| fail("elasticsearch host is empty"))?;
    let auth = authorization(plugin, host)?;
    let root = http(host, &auth, "GET", &root_path(&host.prefix), &[], None)?;
    if !(200..300).contains(&root.status) {
        return Err(fail(format!(
            "Got response code '{}' contacting Elasticsearch at URL '{}'",
            root.status,
            host.url("/")
        )));
    }
    let info = cluster_info(&root)?;
    if config.data_stream && !supports_data_streams(info.major, info.minor) {
        return Err(fail(format!(
            "A data_stream configuration is only supported since Elasticsearch 7.9.0 (detected version {}), please upgrade your cluster",
            info.number
        )));
    }
    if info.serverless {
        if config.ilm_enabled == "true" {
            return Err(fail(
                "Invalid ILM configuration `ilm_enabled => true`. Serverless Elasticsearch cluster does not support Index Lifecycle Management.",
            ));
        }
        if config.template_api == "legacy" {
            return Err(fail(
                "Invalid template configuration `template_api => legacy`. Serverless Elasticsearch does not support legacy template API.",
            ));
        }
    }
    let extra = if info.serverless {
        vec![("Elastic-Api-Version".to_string(), "2023-10-31".to_string())]
    } else {
        Vec::new()
    };
    let ilm = ilm_in_use(&config, info.serverless);
    if config.manage_template {
        install_template(host, &auth, &extra, &config, &info, ilm)?;
    }
    if ilm {
        setup_ilm(host, &auth, &extra, &config)?;
    }
    let index = bulk_index(event, &config, ilm)?;
    let action = resolve_action(event, &config)?;
    let params = action_params(event, &config, &action, &index)?;
    let body = bulk_body(&action, &params, event, &config)?;
    let mut headers = extra;
    headers.push(("Content-Type".to_string(), "application/json".to_string()));
    headers.push(("X-Elastic-Event-Count".to_string(), "1".to_string()));
    headers.push((
        "X-Elastic-Uncompressed-Request-Length".to_string(),
        body.len().to_string(),
    ));
    let payload = if config.compression_level == 0 {
        body.into_bytes()
    } else {
        headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
        gzip_store(body.as_bytes())
    };
    let response = http(
        host,
        &auth,
        "POST",
        &join_path(&host.prefix, "_bulk"),
        &headers,
        Some(&payload),
    )?;
    if response.status == 413 {
        return Err(fail(format!(
            "Got response code '413' contacting Elasticsearch at URL '{}'",
            host.url("/_bulk")
        )));
    }
    if !(200..300).contains(&response.status) {
        return Err(fail(format!(
            "Got response code '{}' contacting Elasticsearch at URL '{}'",
            response.status,
            host.url("/_bulk")
        )));
    }
    let text = String::from_utf8_lossy(&response.body);
    accept_bulk(&text, event, settings, plugin)
}

pub(crate) struct Cluster {
    pub(crate) number: String,
    pub(crate) major: u64,
    pub(crate) minor: u64,
    pub(crate) serverless: bool,
}

struct Config {
    action: Option<String>,
    index: Option<String>,
    document_id: Option<String>,
    routing: Option<String>,
    pipeline: Option<String>,
    version: Option<String>,
    version_type: Option<String>,
    manage_template: bool,
    template_name: Option<String>,
    template_overwrite: bool,
    template_api: String,
    ilm_enabled: String,
    ilm_rollover_alias: Option<String>,
    ilm_pattern: String,
    ilm_policy: String,
    data_stream: bool,
    ds_type: String,
    ds_dataset: String,
    ds_namespace: String,
    ds_sync: bool,
    ds_auto_routing: bool,
    compression_level: u8,
    doc_as_upsert: bool,
    script: String,
    script_type: String,
    script_lang: String,
    script_var_name: String,
    scripted_upsert: bool,
    upsert: String,
    retry_on_conflict: i64,
    default_index: String,
    default_alias: String,
    default_template: String,
    ecs: Ecs,
}

pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) prefix: String,
    pub(crate) scheme: String,
    pub(crate) user: Option<String>,
    pub(crate) password: Option<String>,
}

impl Endpoint {
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}://{}:{}{}", self.scheme, self.host, self.port, path)
    }
}

pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Config {
    fn from_plugin(plugin: &Plugin, ecs: Ecs) -> Result<Self, RunError> {
        refuse_unknown(plugin)?;
        refuse_transport(plugin)?;
        let (default_index, default_alias, default_template) = ecs_defaults(ecs);
        let data_stream = data_stream_enabled(plugin, ecs)?;
        let manage_template = match flag(plugin, "manage_template") {
            Some(value) => value,
            None if data_stream => false,
            None => true,
        };
        let compression_level = compression(plugin)?;
        check_actions(plugin)?;
        Ok(Self {
            action: text(plugin, "action"),
            index: text(plugin, "index"),
            document_id: text(plugin, "document_id"),
            routing: text(plugin, "routing"),
            pipeline: text(plugin, "pipeline"),
            version: text(plugin, "version"),
            version_type: text(plugin, "version_type"),
            manage_template,
            template_name: text(plugin, "template_name"),
            template_overwrite: flag(plugin, "template_overwrite").unwrap_or(false),
            template_api: text(plugin, "template_api").unwrap_or_else(|| "auto".to_string()),
            ilm_enabled: text(plugin, "ilm_enabled").unwrap_or_else(|| "auto".to_string()),
            ilm_rollover_alias: text(plugin, "ilm_rollover_alias"),
            ilm_pattern: text(plugin, "ilm_pattern").unwrap_or_else(|| ILM_PATTERN.to_string()),
            ilm_policy: text(plugin, "ilm_policy").unwrap_or_else(|| POLICY.to_string()),
            data_stream,
            ds_type: text(plugin, "data_stream_type").unwrap_or_else(|| "logs".to_string()),
            ds_dataset: text(plugin, "data_stream_dataset")
                .unwrap_or_else(|| "generic".to_string()),
            ds_namespace: text(plugin, "data_stream_namespace")
                .unwrap_or_else(|| "default".to_string()),
            ds_sync: flag(plugin, "data_stream_sync_fields").unwrap_or(true),
            ds_auto_routing: flag(plugin, "data_stream_auto_routing").unwrap_or(true),
            compression_level,
            doc_as_upsert: flag(plugin, "doc_as_upsert").unwrap_or(false),
            script: text(plugin, "script").unwrap_or_default(),
            script_type: text(plugin, "script_type").unwrap_or_else(|| "inline".to_string()),
            script_lang: text(plugin, "script_lang").unwrap_or_else(|| "painless".to_string()),
            script_var_name: text(plugin, "script_var_name").unwrap_or_else(|| "event".to_string()),
            scripted_upsert: flag(plugin, "scripted_upsert").unwrap_or(false),
            upsert: text(plugin, "upsert").unwrap_or_default(),
            retry_on_conflict: number(plugin, "retry_on_conflict").unwrap_or(1),
            default_index: default_index.to_string(),
            default_alias: default_alias.to_string(),
            default_template: default_template.to_string(),
            ecs,
        })
    }

    fn rollover_alias(&self) -> String {
        self.ilm_rollover_alias
            .clone()
            .unwrap_or_else(|| self.default_alias.clone())
    }
}

fn ecs_defaults(ecs: Ecs) -> (&'static str, &'static str, &'static str) {
    match ecs {
        Ecs::Disabled => ("logstash-%{+yyyy.MM.dd}", "logstash", "logstash"),
        Ecs::V1 | Ecs::V8 => (
            "ecs-logstash-%{+yyyy.MM.dd}",
            "ecs-logstash",
            "ecs-logstash",
        ),
    }
}

fn refuse_unknown(plugin: &Plugin) -> Result<(), RunError> {
    const KNOWN: &[&str] = &[
        "action",
        "index",
        "document_id",
        "routing",
        "pipeline",
        "version",
        "version_type",
        "manage_template",
        "template_name",
        "template_overwrite",
        "template_api",
        "ilm_enabled",
        "ilm_rollover_alias",
        "ilm_pattern",
        "ilm_policy",
        "data_stream",
        "data_stream_type",
        "data_stream_dataset",
        "data_stream_namespace",
        "data_stream_sync_fields",
        "data_stream_auto_routing",
        "hosts",
        "user",
        "password",
        "compression_level",
        "http_compression",
        "doc_as_upsert",
        "script",
        "script_type",
        "script_lang",
        "script_var_name",
        "scripted_upsert",
        "upsert",
        "retry_on_conflict",
        "id",
        "enable_metric",
        "ssl_enabled",
        "ssl",
        "sniffing",
        "api_key",
        "cloud_id",
        "cloud_auth",
        "proxy",
    ];
    for (name, _) in &plugin.args {
        if !KNOWN.contains(&name.as_str()) {
            return Err(fail(format!(
                "elasticsearch option {name} is not implemented"
            )));
        }
    }
    Ok(())
}

fn refuse_transport(plugin: &Plugin) -> Result<(), RunError> {
    if text(plugin, "cloud_id").is_some() && has(plugin, "hosts") {
        return Err(fail(
            "Both cloud_id and hosts specified, please only use one of those.",
        ));
    }
    if text(plugin, "cloud_id").is_some() || text(plugin, "cloud_auth").is_some() {
        return Err(fail("plugin elasticsearch ssl_enabled is not implemented"));
    }
    let auths = [
        text(plugin, "user").is_some() || text(plugin, "password").is_some(),
        text(plugin, "api_key").is_some(),
        text(plugin, "cloud_auth").is_some(),
    ]
    .into_iter()
    .filter(|item| *item)
    .count();
    if auths > 1 {
        return Err(fail(
            "Multiple authentication options are specified, please only use one of user/password, cloud_auth or api_key",
        ));
    }
    if text(plugin, "api_key").is_some() && flag(plugin, "ssl_enabled") != Some(true) {
        return Err(fail(
            "Using api_key authentication requires SSL/TLS secured communication using the `ssl => true` option",
        ));
    }
    if flag(plugin, "sniffing") == Some(true) {
        return Err(fail("elasticsearch sniffing is not implemented"));
    }
    if let Some(proxy) = text(plugin, "proxy")
        && !proxy.is_empty()
    {
        return Err(fail("elasticsearch proxy is not implemented"));
    }
    Ok(())
}

fn check_actions(plugin: &Plugin) -> Result<(), RunError> {
    if let Some(action) = text(plugin, "action") {
        if action.is_empty() {
            return Err(fail("No action specified!"));
        }
        if !action.contains("%{")
            && !matches!(action.as_str(), "index" | "delete" | "create" | "update")
        {
            return Err(fail(format!(
                "Action '{action}' is invalid! Pick one of index, delete, create, update or use a sprintf style statement"
            )));
        }
    }
    let external = matches!(
        text(plugin, "version_type").as_deref(),
        Some("external" | "external_gt" | "external_gte")
    );
    if external && text(plugin, "version").is_none() {
        return Err(fail(
            "External versioning requires the presence of a version number.",
        ));
    }
    if text(plugin, "action").as_deref() == Some("create") && external {
        return Err(fail(
            "External versioning is not supported by the create action.",
        ));
    }
    if flag(plugin, "doc_as_upsert") == Some(true) && flag(plugin, "scripted_upsert") == Some(true)
    {
        return Err(fail(
            "doc_as_upsert and scripted_upsert are mutually exclusive.",
        ));
    }
    if text(plugin, "action").as_deref() == Some("update")
        && text(plugin, "document_id").unwrap_or_default().is_empty()
    {
        return Err(fail("Specifying action => 'update' needs a document_id."));
    }
    if text(plugin, "action").as_deref() == Some("update") && external {
        return Err(fail(
            "External versioning is not supported by the update action. See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update.html.",
        ));
    }
    Ok(())
}

fn data_stream_enabled(plugin: &Plugin, ecs: Ecs) -> Result<bool, RunError> {
    match text(plugin, "data_stream").as_deref() {
        Some("false") => {
            let extra = data_stream_keys(plugin);
            if !extra.is_empty() {
                return Err(fail(format!(
                    "Ambiguous configuration; data stream settings must not be present when data streams are disabled: {extra:?}"
                )));
            }
            Ok(false)
        }
        Some("true") => {
            if ecs == Ecs::Disabled {
                return Err(fail(
                    "Invalid data stream configuration: `ecs_compatibility => disabled`",
                ));
            }
            let invalid = invalid_data_stream_keys(plugin);
            if !invalid.is_empty() {
                return Err(fail(format!(
                    "Invalid data stream configuration: {invalid:?}"
                )));
            }
            Ok(true)
        }
        Some("auto") | None => {
            if ecs == Ecs::Disabled {
                let extra = data_stream_keys(plugin);
                if !extra.is_empty() {
                    return Err(fail(format!(
                        "Ambiguous configuration; data stream settings must not be present when data streams are disabled: {extra:?}"
                    )));
                }
                return Ok(false);
            }
            let invalid = invalid_data_stream_keys(plugin);
            if !invalid.is_empty() {
                let extra = data_stream_keys(plugin);
                if !extra.is_empty() {
                    return Err(fail(format!(
                        "Ambiguous configuration; data stream settings must not be present when data streams are disabled: {extra:?}"
                    )));
                }
                return Ok(false);
            }
            Ok(true)
        }
        Some(other) => Err(fail(format!(
            "elasticsearch data_stream {other} is not implemented"
        ))),
    }
}

fn data_stream_keys(plugin: &Plugin) -> Vec<&str> {
    plugin
        .args
        .iter()
        .filter(|(name, _)| name.starts_with("data_stream_"))
        .map(|(name, _)| name.as_str())
        .collect()
}

fn invalid_data_stream_keys(plugin: &Plugin) -> Vec<&str> {
    const SHARED: &[&str] = &[
        "hosts",
        "user",
        "password",
        "api_key",
        "cloud_id",
        "cloud_auth",
        "ssl_enabled",
        "ssl",
        "sniffing",
        "compression_level",
        "http_compression",
        "proxy",
        "id",
        "enable_metric",
        "pipeline",
        "routing",
    ];
    plugin
        .args
        .iter()
        .filter(|(name, value)| !data_stream_key_ok(name, value, SHARED))
        .map(|(name, _)| name.as_str())
        .collect()
}

fn data_stream_key_ok(name: &str, value: &Arg, shared: &[&str]) -> bool {
    match name {
        "action" => matches!(scalar(value), Some(text) if text == "create" || text.contains("%{")),
        "data_stream" => scalar(value) == Some("true") || scalar(value) == Some("auto"),
        "manage_template" => scalar(value) == Some("false"),
        "routing" | "pipeline" => true,
        other if other.starts_with("data_stream_") => true,
        other => shared.contains(&other),
    }
}

fn ilm_in_use(config: &Config, serverless: bool) -> bool {
    if serverless || config.data_stream {
        return false;
    }
    let alias_set = config.index.as_deref() == Some(config.default_index.as_str())
        || config.index.is_none()
        || config.ilm_rollover_alias.as_deref() != Some(config.default_alias.as_str())
            && config.ilm_rollover_alias.is_some();
    match config.ilm_enabled.as_str() {
        "false" => false,
        "true" | "auto" => alias_set,
        _ => false,
    }
}

fn endpoints(plugin: &Plugin) -> Result<Vec<Endpoint>, RunError> {
    let mut raws = Vec::new();
    match arg(plugin, "hosts") {
        Some(Arg::Array(items)) => {
            for item in items {
                raws.push(scalar(item).ok_or_else(|| fail("elasticsearch hosts must be strings"))?);
            }
        }
        Some(value) => {
            raws.push(scalar(value).ok_or_else(|| fail("elasticsearch hosts must be strings"))?)
        }
        None => raws.push("127.0.0.1:9200"),
    }
    if raws.is_empty() {
        raws.push("127.0.0.1:9200");
    }
    let mut hosts = Vec::new();
    for raw in raws {
        let mut endpoint = parse_endpoint(raw)?;
        if endpoint.scheme == "https" {
            let ssl = flag(plugin, "ssl_enabled").or_else(|| flag(plugin, "ssl"));
            if ssl == Some(false) {
                return Err(fail(
                    "SSL option was explicitly set to false but a URL was also declared with a scheme of 'https'. Please reconcile this",
                ));
            }
            return Err(fail("plugin elasticsearch ssl_enabled is not implemented"));
        }
        if flag(plugin, "ssl_enabled") == Some(true) || flag(plugin, "ssl") == Some(true) {
            return Err(fail("plugin elasticsearch ssl_enabled is not implemented"));
        }
        if let Some(user) = text(plugin, "user") {
            endpoint.user = Some(user);
            endpoint.password = text(plugin, "password");
        }
        hosts.push(endpoint);
    }
    Ok(hosts)
}

pub(crate) fn parse_endpoint(raw: &str) -> Result<Endpoint, RunError> {
    let (scheme, rest) = if let Some(rest) = raw.strip_prefix("http://") {
        ("http", rest)
    } else if let Some(rest) = raw.strip_prefix("https://") {
        ("https", rest)
    } else if let Some((scheme, _)) = raw.split_once("://") {
        return Err(fail(format!(
            "Bad scheme '{scheme}' found should be one of http/https"
        )));
    } else {
        ("http", raw)
    };
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, rest),
    };
    let (hostport, path) = match hostport.split_once('/') {
        Some((host, path)) => {
            let path = format!("/{path}");
            let path = path.trim_end_matches('/').to_string();
            (host, if path == "/" { String::new() } else { path })
        }
        None => (hostport, String::new()),
    };
    let (host, port) = if let Some((host, port)) = hostport.rsplit_once(':') {
        if host.starts_with('[') {
            return Err(fail("elasticsearch ipv6 hosts are not implemented"));
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| fail(format!("elasticsearch host port is invalid: {raw}")))?;
        (host.to_string(), port)
    } else {
        (hostport.to_string(), 9200)
    };
    if host.is_empty() {
        return Err(fail("elasticsearch host is empty"));
    }
    let (user, password) = match userinfo {
        Some(value) => {
            let (user, password) = value.split_once(':').unwrap_or((value, ""));
            (Some(user.to_string()), Some(password.to_string()))
        }
        None => (None, None),
    };
    Ok(Endpoint {
        host,
        port,
        prefix: path,
        scheme: scheme.to_string(),
        user,
        password,
    })
}

fn authorization(plugin: &Plugin, host: &Endpoint) -> Result<Option<String>, RunError> {
    if text(plugin, "api_key").is_some() {
        return Err(fail("plugin elasticsearch ssl_enabled is not implemented"));
    }
    match (&host.user, &host.password) {
        (Some(user), password) => Ok(Some(format!(
            "Basic {}",
            base64(format!("{user}:{}", password.as_deref().unwrap_or("")).as_bytes())
        ))),
        _ => Ok(None),
    }
}

pub(crate) fn cluster_info(response: &Response) -> Result<Cluster, RunError> {
    let text = String::from_utf8_lossy(&response.body);
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| fail(error.to_string()))?;
    let version = value
        .get("version")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let number = version
        .get("number")
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_string();
    let Some((major, minor, _)) = parse_version(&number) else {
        return Err(fail(
            "Could not connect to a compatible version of Elasticsearch",
        ));
    };
    if major < 7 {
        return Err(fail(
            "Could not connect to a compatible version of Elasticsearch",
        ));
    }
    let flavor = version
        .get("build_flavor")
        .and_then(|item| item.as_str())
        .unwrap_or("");
    if major == 7 && minor < 14 {
        let tagline = value.get("tagline").and_then(|item| item.as_str());
        if flavor != "default" || tagline != Some("You Know, for Search") {
            return Err(fail(
                "Could not connect to a compatible version of Elasticsearch",
            ));
        }
    } else {
        let product = header(response, "x-elastic-product");
        if product.as_deref() != Some("Elasticsearch") {
            return Err(fail(
                "Could not connect to a compatible version of Elasticsearch",
            ));
        }
    }
    Ok(Cluster {
        number,
        major,
        minor,
        serverless: flavor == "serverless",
    })
}

fn parse_version(number: &str) -> Option<(u64, u64, u64)> {
    let core = number.split('-').next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

fn supports_data_streams(major: u64, minor: u64) -> bool {
    major > 7 || (major == 7 && minor >= 9)
}

fn install_template(
    host: &Endpoint,
    auth: &Option<String>,
    extra: &[(String, String)],
    config: &Config,
    info: &Cluster,
    ilm: bool,
) -> Result<(), RunError> {
    let composable = match config.template_api.as_str() {
        "legacy" => false,
        "composable" => true,
        _ => info.major >= 8,
    };
    let endpoint = if composable {
        "_index_template"
    } else {
        "_template"
    };
    let name = if ilm && config.template_name.is_none() {
        config.rollover_alias()
    } else {
        config
            .template_name
            .clone()
            .unwrap_or_else(|| config.default_template.clone())
    };
    let path = join_path(&host.prefix, &format!("{endpoint}/{name}"));
    let exists = exists(host, auth, extra, "HEAD", &path)?;
    if exists && !config.template_overwrite {
        return Ok(());
    }
    let body = template_json(info.major, config, ilm)?;
    let mut headers = extra.to_vec();
    headers.push(("Content-Type".to_string(), "application/json".to_string()));
    let response = http(host, auth, "PUT", &path, &headers, Some(body.as_bytes()))?;
    if response.status == 404 {
        return Ok(());
    }
    if !(200..300).contains(&response.status) {
        return Err(fail(format!(
            "Got response code '{}' contacting Elasticsearch at URL '{}'",
            response.status,
            host.url(&path)
        )));
    }
    Ok(())
}

fn template_json(major: u64, config: &Config, ilm: bool) -> Result<String, RunError> {
    let raw = raw_template(config.ecs, major)?;
    let mut value: serde_json::Value =
        serde_json::from_str(raw).map_err(|error| fail(error.to_string()))?;
    if ilm {
        if major == 7
            && let Some(object) = value.as_object_mut()
        {
            object.remove("template");
        }
        value["index_patterns"] =
            serde_json::Value::String(format!("{}-*", config.rollover_alias()));
        write_lifecycle(&mut value, &config.ilm_policy, &config.rollover_alias());
    }
    serde_json::to_string(&value).map_err(|error| fail(error.to_string()))
}

fn write_lifecycle(value: &mut serde_json::Value, policy: &str, alias: &str) {
    let Some(root) = value.as_object_mut() else {
        return;
    };
    let settings = if root.contains_key("template") {
        let template = root
            .entry("template")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        let Some(template) = template.as_object_mut() else {
            return;
        };
        template
            .entry("settings")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
    } else {
        root.entry("settings")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
    };
    let Some(settings) = settings.as_object_mut() else {
        return;
    };
    settings.insert(
        "index.lifecycle.name".to_string(),
        serde_json::Value::String(policy.to_string()),
    );
    settings.insert(
        "index.lifecycle.rollover_alias".to_string(),
        serde_json::Value::String(alias.to_string()),
    );
}

fn raw_template(ecs: Ecs, major: u64) -> Result<&'static str, RunError> {
    let raw = match (ecs, major) {
        (Ecs::Disabled, 7) => include_str!("elastic_templates/ecs-disabled-7x.json"),
        (Ecs::Disabled, 8) => include_str!("elastic_templates/ecs-disabled-8x.json"),
        (Ecs::Disabled, 9) => include_str!("elastic_templates/ecs-disabled-9x.json"),
        (Ecs::V1, 7) => include_str!("elastic_templates/ecs-v1-7x.json"),
        (Ecs::V1, 8) => include_str!("elastic_templates/ecs-v1-8x.json"),
        (Ecs::V1, 9) => include_str!("elastic_templates/ecs-v1-9x.json"),
        (Ecs::V8, 7) => include_str!("elastic_templates/ecs-v8-7x.json"),
        (Ecs::V8, 8) => include_str!("elastic_templates/ecs-v8-8x.json"),
        (Ecs::V8, 9) => include_str!("elastic_templates/ecs-v8-9x.json"),
        _ => "",
    };
    if raw.is_empty() {
        return Err(fail(format!(
            "Failed to load default template for Elasticsearch v{major}"
        )));
    }
    Ok(raw)
}

fn setup_ilm(
    host: &Endpoint,
    auth: &Option<String>,
    extra: &[(String, String)],
    config: &Config,
) -> Result<(), RunError> {
    let alias = config.rollover_alias();
    let alias_path = join_path(&host.prefix, &alias);
    if !exists(host, auth, extra, "HEAD", &alias_path)? {
        let target = format!("<{alias}-{}>", config.ilm_pattern);
        let path = join_path(&host.prefix, &cgi_escape(&target));
        let body = format!("{{\"aliases\":{{\"{alias}\":{{\"is_write_index\":true}}}}}}");
        let mut headers = extra.to_vec();
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
        let response = http(host, auth, "PUT", &path, &headers, Some(body.as_bytes()))?;
        if response.status != 400 && !(200..300).contains(&response.status) {
            return Err(fail(format!(
                "Got response code '{}' contacting Elasticsearch at URL '{}'",
                response.status,
                host.url(&path)
            )));
        }
    }
    let policy_path = join_path(&host.prefix, &format!("_ilm/policy/{}", config.ilm_policy));
    if config.ilm_policy == POLICY {
        if !exists(host, auth, extra, "GET", &policy_path)? {
            let mut headers = extra.to_vec();
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
            let body = include_str!("elastic_templates/default-ilm-policy.json");
            let response = http(
                host,
                auth,
                "PUT",
                &policy_path,
                &headers,
                Some(body.as_bytes()),
            )?;
            if !(200..300).contains(&response.status) {
                return Err(fail(format!(
                    "Got response code '{}' contacting Elasticsearch at URL '{}'",
                    response.status,
                    host.url(&policy_path)
                )));
            }
        }
    } else if !exists(host, auth, extra, "GET", &policy_path)? {
        return Err(fail(format!(
            "The specified ILM policy {} does not exist on your Elasticsearch instance",
            config.ilm_policy
        )));
    }
    Ok(())
}

fn exists(
    host: &Endpoint,
    auth: &Option<String>,
    extra: &[(String, String)],
    method: &str,
    path: &str,
) -> Result<bool, RunError> {
    let response = http(host, auth, method, path, extra, None)?;
    if (200..300).contains(&response.status) {
        Ok(true)
    } else if response.status == 404 {
        Ok(false)
    } else {
        Err(fail(format!(
            "Got response code '{}' contacting Elasticsearch at URL '{}'",
            response.status,
            host.url(path)
        )))
    }
}

fn bulk_index(event: &Event, config: &Config, ilm: bool) -> Result<String, RunError> {
    let raw = if config.data_stream {
        data_stream_index(event, config)
    } else if ilm {
        event
            .sprintf(&config.rollover_alias())
            .map_err(|error| fail(error.to_string()))?
    } else {
        let pattern = config.index.as_deref().unwrap_or(&config.default_index);
        event
            .sprintf(pattern)
            .map_err(|error| fail(error.to_string()))?
    };
    if raw.contains("%{") {
        return Err(fail(format!(
            "Badly formatted index, after interpolation still contains placeholder: [{raw}]"
        )));
    }
    Ok(raw)
}

fn data_stream_index(event: &Event, config: &Config) -> String {
    if !config.ds_auto_routing {
        return format!(
            "{}-{}-{}",
            config.ds_type, config.ds_dataset, config.ds_namespace
        );
    }
    let part = |key: &str, default: &str| match event.get_field(&format!("[data_stream][{key}]")) {
        Ok(Some(value)) => value.to_string(),
        _ => default.to_string(),
    };
    format!(
        "{}-{}-{}",
        part("type", &config.ds_type),
        part("dataset", &config.ds_dataset),
        part("namespace", &config.ds_namespace)
    )
}

fn resolve_action(event: &Event, config: &Config) -> Result<String, RunError> {
    let action = if config.data_stream {
        "create".to_string()
    } else if let Some(action) = &config.action {
        event
            .sprintf(action)
            .map_err(|error| fail(error.to_string()))?
    } else {
        "index".to_string()
    };
    if !matches!(action.as_str(), "index" | "delete" | "create" | "update") {
        return Err(fail(format!(
            "Elasticsearch doesn't support [{action}] action"
        )));
    }
    Ok(action)
}

fn action_params(
    event: &Event,
    config: &Config,
    action: &str,
    index: &str,
) -> Result<String, RunError> {
    let id = match &config.document_id {
        Some(template) => Some(
            event
                .sprintf(template)
                .map_err(|error| fail(error.to_string()))?,
        ),
        None => metadata_string(event, "[@metadata][_ingest_document][id]"),
    };
    let routing = match &config.routing {
        Some(template) => Some(
            event
                .sprintf(template)
                .map_err(|error| fail(error.to_string()))?,
        ),
        None => metadata_string(event, "[@metadata][_ingest_document][routing]"),
    };
    let pipeline = resolve_pipeline(event, config)?;
    let version = match &config.version {
        Some(template) => Some(
            event
                .sprintf(template)
                .map_err(|error| fail(error.to_string()))?,
        ),
        None => metadata_string(event, "[@metadata][_ingest_document][version]"),
    };
    let version_type = match &config.version_type {
        Some(template) => Some(
            event
                .sprintf(template)
                .map_err(|error| fail(error.to_string()))?,
        ),
        None => metadata_string(event, "[@metadata][_ingest_document][version_type]"),
    };
    let mut out = String::from("{");
    let mut first = true;
    push_field(&mut out, &mut first, "_id", &json_or_null(id.as_deref()));
    push_field(
        &mut out,
        &mut first,
        "_index",
        &serde_json::Value::String(index.to_string()).to_string(),
    );
    push_field(
        &mut out,
        &mut first,
        "routing",
        &json_or_null(routing.as_deref()),
    );
    if let Some(pipeline) = pipeline.as_deref()
        && !pipeline.is_empty()
    {
        push_field(
            &mut out,
            &mut first,
            "pipeline",
            &serde_json::Value::String(pipeline.to_string()).to_string(),
        );
    }
    if action == "update" {
        push_field(
            &mut out,
            &mut first,
            "retry_on_conflict",
            &config.retry_on_conflict.to_string(),
        );
    }
    if let Some(version) = version.as_deref() {
        push_field(
            &mut out,
            &mut first,
            "version",
            &serde_json::Value::String(version.to_string()).to_string(),
        );
    }
    if let Some(version_type) = version_type.as_deref() {
        push_field(
            &mut out,
            &mut first,
            "version_type",
            &serde_json::Value::String(version_type.to_string()).to_string(),
        );
    }
    out.push('}');
    Ok(out)
}

fn resolve_pipeline(event: &Event, config: &Config) -> Result<Option<String>, RunError> {
    if let Some(template) = &config.pipeline {
        let value = event
            .sprintf(template)
            .map_err(|error| fail(error.to_string()))?;
        return Ok(if value.is_empty() { None } else { Some(value) });
    }
    Ok(metadata_string(
        event,
        "[@metadata][target_ingest_pipeline]",
    ))
}

fn metadata_string(event: &Event, field: &str) -> Option<String> {
    match event.get_field(field) {
        Ok(Some(crate::value::Value::String(text))) if !text.is_empty() => Some(text),
        Ok(Some(crate::value::Value::Integer(number))) => Some(number.to_string()),
        _ => None,
    }
}

fn push_field(out: &mut String, first: &mut bool, key: &str, json: &str) {
    if !*first {
        out.push(',');
    }
    *first = false;
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(json);
}

fn json_or_null(value: Option<&str>) -> String {
    match value {
        Some(text) => serde_json::Value::String(text.to_string()).to_string(),
        None => "null".to_string(),
    }
}

fn bulk_body(
    action: &str,
    params: &str,
    event: &Event,
    config: &Config,
) -> Result<String, RunError> {
    let mut body = format!("{{\"{action}\":{params}}}\n");
    if action == "delete" {
        return Ok(body);
    }
    let document = if config.data_stream {
        data_stream_document(event, config)?
    } else {
        event.to_json().map_err(|error| fail(error.to_string()))?
    };
    if action == "update" {
        body.push_str(&update_source(&document, config)?);
    } else {
        body.push_str(&document);
    }
    body.push('\n');
    Ok(body)
}

fn data_stream_document(event: &Event, config: &Config) -> Result<String, RunError> {
    let mut copy = event.clone();
    if config.ds_sync {
        for (key, value) in [
            ("type", config.ds_type.as_str()),
            ("dataset", config.ds_dataset.as_str()),
            ("namespace", config.ds_namespace.as_str()),
        ] {
            let path = format!("[data_stream][{key}]");
            let present = matches!(copy.get_field(&path), Ok(Some(_)));
            if !present {
                copy.set_field(&path, crate::value::Value::from(value))
                    .map_err(|error| fail(error.to_string()))?;
            }
        }
    }
    copy.to_json().map_err(|error| fail(error.to_string()))
}

fn update_source(document: &str, config: &Config) -> Result<String, RunError> {
    let parsed: serde_json::Value =
        serde_json::from_str(document).map_err(|error| fail(error.to_string()))?;
    let mut source = serde_json::Map::new();
    if !config.script.is_empty() {
        let mut script = serde_json::Map::new();
        let mut params = serde_json::Map::new();
        params.insert(config.script_var_name.clone(), parsed.clone());
        script.insert("params".to_string(), serde_json::Value::Object(params));
        let key = match config.script_type.as_str() {
            "indexed" => "id",
            "file" => "file",
            _ => "inline",
        };
        script.insert(
            key.to_string(),
            serde_json::Value::String(config.script.clone()),
        );
        if !config.script_lang.is_empty() {
            script.insert(
                "lang".to_string(),
                serde_json::Value::String(config.script_lang.clone()),
            );
        }
        source.insert("script".to_string(), serde_json::Value::Object(script));
        if config.scripted_upsert {
            source.insert("scripted_upsert".to_string(), serde_json::Value::Bool(true));
            source.insert(
                "upsert".to_string(),
                serde_json::Value::Object(serde_json::Map::new()),
            );
        } else if config.doc_as_upsert {
            source.insert("upsert".to_string(), parsed);
        } else if !config.upsert.is_empty() {
            let upsert: serde_json::Value =
                serde_json::from_str(&config.upsert).map_err(|error| fail(error.to_string()))?;
            source.insert("upsert".to_string(), upsert);
        }
    } else {
        source.insert("doc".to_string(), parsed);
        if config.doc_as_upsert {
            source.insert("doc_as_upsert".to_string(), serde_json::Value::Bool(true));
        } else if !config.upsert.is_empty() {
            let upsert: serde_json::Value =
                serde_json::from_str(&config.upsert).map_err(|error| fail(error.to_string()))?;
            source.insert("upsert".to_string(), upsert);
        }
    }
    serde_json::to_string(&serde_json::Value::Object(source))
        .map_err(|error| fail(error.to_string()))
}

fn accept_bulk(
    body: &str,
    event: &Event,
    settings: &Settings,
    plugin: &Plugin,
) -> Result<(), RunError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| fail(error.to_string()))?;
    if value.get("errors").and_then(|item| item.as_bool()) != Some(true) {
        return Ok(());
    }
    let Some(items) = value.get("items").and_then(|item| item.as_array()) else {
        return Err(fail("elasticsearch bulk reported errors"));
    };
    for item in items {
        let Some(inner) = item.as_object().and_then(|object| object.values().next()) else {
            continue;
        };
        let status = inner
            .get("status")
            .and_then(|item| item.as_u64())
            .unwrap_or(0);
        match status {
            200 | 201 | 409 => {}
            400 | 404 => {
                if settings.dlq_enabled {
                    let reason = inner
                        .get("error")
                        .and_then(|item| item.get("reason"))
                        .and_then(|item| item.as_str())
                        .unwrap_or("elasticsearch document error")
                        .to_string();
                    let dir = dlq_directory(settings)?;
                    let id = text(plugin, "id").unwrap_or_else(|| "elasticsearch".to_string());
                    crate::dlq::write_entry(
                        &dir,
                        event,
                        "output",
                        &id,
                        &reason,
                        settings.dlq_max_bytes,
                        &settings.dlq_storage_policy,
                    )?;
                }
            }
            _ => {
                return Err(fail(format!(
                    "Got response code '{status}' contacting Elasticsearch at URL '/_bulk'"
                )));
            }
        }
    }
    Ok(())
}

fn dlq_directory(settings: &Settings) -> Result<PathBuf, RunError> {
    let root = if let Some(path) = &settings.path_dlq {
        PathBuf::from(path)
    } else if let Some(data) = &settings.path_data {
        PathBuf::from(data).join("dead_letter_queue")
    } else {
        return Err(fail(
            "dead letter queue requires path.dead_letter_queue or path.data",
        ));
    };
    Ok(root.join(&settings.pipeline_id))
}

pub(crate) fn http(
    host: &Endpoint,
    auth: &Option<String>,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<Response, RunError> {
    let address = (host.host.as_str(), host.port)
        .to_socket_addrs()
        .map_err(|error| {
            fail(format!(
                "Elasticsearch Unreachable: [{}] {error}",
                host.url(path)
            ))
        })?
        .next()
        .ok_or_else(|| fail(format!("Elasticsearch Unreachable: [{}]", host.url(path))))?;
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(2)).map_err(|error| {
            fail(format!(
                "Elasticsearch Unreachable: [{}] {error}",
                host.url(path)
            ))
        })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| fail(error.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| fail(error.to_string()))?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nAccept: application/json\r\n",
        host.host, host.port
    );
    if let Some(auth) = auth {
        request.push_str("Authorization: ");
        request.push_str(auth);
        request.push_str("\r\n");
    }
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        stream
            .write_all(request.as_bytes())
            .map_err(|error| fail(error.to_string()))?;
        stream
            .write_all(body)
            .map_err(|error| fail(error.to_string()))?;
    } else {
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|error| fail(error.to_string()))?;
    }
    read_response(&mut stream)
}

fn read_response(stream: &mut TcpStream) -> Result<Response, RunError> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(response) = parse_response(&buf) {
            return Ok(response);
        }
        match stream.read(&mut tmp) {
            Ok(0) => {
                return parse_response(&buf)
                    .ok_or_else(|| fail("elasticsearch response was incomplete"));
            }
            Ok(size) => buf.extend_from_slice(&tmp[..size]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                if let Some(response) = parse_response(&buf) {
                    return Ok(response);
                }
                return Err(fail(format!("elasticsearch response timed out: {error}")));
            }
            Err(error) => return Err(fail(error.to_string())),
        }
    }
}

fn parse_response(buf: &[u8]) -> Option<Response> {
    let split = buf.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..split]).ok()?;
    let mut lines = head.lines();
    let status_line = lines.next()?;
    let status = status_line.split_whitespace().nth(1)?.parse().ok()?;
    let mut headers = Vec::new();
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_string();
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        }
        if name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
        headers.push((name, value));
    }
    let rest = &buf[split + 4..];
    if chunked {
        let body = decode_chunks(rest)?;
        return Some(Response {
            status,
            headers,
            body,
        });
    }
    match content_length {
        Some(length) if rest.len() >= length => Some(Response {
            status,
            headers,
            body: rest[..length].to_vec(),
        }),
        Some(_) => None,
        None if rest.is_empty() && status_line.contains("HTTP/") => Some(Response {
            status,
            headers,
            body: Vec::new(),
        }),
        None => None,
    }
}

fn decode_chunks(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = rest.windows(2).position(|window| window == b"\r\n")?;
        let size = std::str::from_utf8(&rest[..line_end]).ok()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        rest = &rest[line_end + 2..];
        if rest.len() < size + 2 {
            return None;
        }
        if size == 0 {
            return Some(body);
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

pub(crate) fn header(response: &Response, name: &str) -> Option<String> {
    response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

pub(crate) fn root_path(prefix: &str) -> String {
    if prefix.is_empty() {
        "/".to_string()
    } else {
        format!("{prefix}/")
    }
}

pub(crate) fn join_path(prefix: &str, path: &str) -> String {
    let path = path.trim_start_matches('/');
    if prefix.is_empty() {
        format!("/{path}")
    } else {
        format!("{prefix}/{path}")
    }
}

pub(crate) fn cgi_escape(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn gzip_store(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff];
    if data.is_empty() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    } else {
        let mut offset = 0;
        while offset < data.len() {
            let size = (data.len() - offset).min(65535);
            let last = offset + size == data.len();
            out.push(if last { 1 } else { 0 });
            let len = size as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice((!len).to_le_bytes().as_slice());
            out.extend_from_slice(&data[offset..offset + size]);
            offset += size;
        }
    }
    out.extend_from_slice(&crate::queue::crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

pub(crate) fn base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        let chunk = u32::from_be_bytes([0, data[index], data[index + 1], data[index + 2]]);
        for shift in [18, 12, 6, 0] {
            out.push(TABLE[((chunk >> shift) & 0x3f) as usize] as char);
        }
        index += 3;
    }
    let rest = data.len() - index;
    if rest == 1 {
        let chunk = u32::from(data[index]) << 16;
        out.push(TABLE[((chunk >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rest == 2 {
        let chunk = (u32::from(data[index]) << 16) | (u32::from(data[index + 1]) << 8);
        out.push(TABLE[((chunk >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((chunk >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

fn compression(plugin: &Plugin) -> Result<u8, RunError> {
    if let Some(level) = number(plugin, "compression_level") {
        if !(0..=9).contains(&level) {
            return Err(fail(
                "elasticsearch compression_level must be an integer from 0 to 9",
            ));
        }
        return Ok(level as u8);
    }
    if let Some(enabled) = flag(plugin, "http_compression") {
        return Ok(if enabled { 1 } else { 0 });
    }
    Ok(1)
}

fn arg<'a>(plugin: &'a Plugin, name: &str) -> Option<&'a Arg> {
    plugin
        .args
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn has(plugin: &Plugin, name: &str) -> bool {
    arg(plugin, name).is_some()
}

fn text(plugin: &Plugin, name: &str) -> Option<String> {
    arg(plugin, name).and_then(scalar).map(str::to_string)
}

fn scalar(arg: &Arg) -> Option<&str> {
    match arg {
        Arg::String(value) => Some(value),
        _ => None,
    }
}

fn number(plugin: &Plugin, name: &str) -> Option<i64> {
    match arg(plugin, name) {
        Some(Arg::Int(value)) => Some(*value),
        Some(Arg::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn flag(plugin: &Plugin, name: &str) -> Option<bool> {
    match arg(plugin, name) {
        Some(Arg::String(value)) => Some(value != "false"),
        Some(Arg::Int(value)) => Some(*value != 0),
        Some(_) => Some(true),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_gzip_roundtrip() {
        let payload = b"{\"create\":{\"_id\":null}}\n{\"message\":\"hello\"}\n";
        let compressed = gzip_store(payload);
        assert_eq!(&compressed[..2], &[0x1f, 0x8b]);
        assert_eq!(gunzip_store(&compressed), payload);
    }

    fn gunzip_store(data: &[u8]) -> Vec<u8> {
        assert_eq!(&data[..10], &[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff]);
        let mut rest = &data[10..];
        let mut out = Vec::new();
        loop {
            let header = rest[0];
            rest = &rest[1..];
            let len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
            rest = &rest[4..];
            out.extend_from_slice(&rest[..len]);
            rest = &rest[len..];
            if header & 1 == 1 {
                break;
            }
        }
        out
    }
}
