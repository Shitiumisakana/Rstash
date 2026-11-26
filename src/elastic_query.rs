//! Elasticsearch input 5.3.2 and filter 4.4.1.
//!
//! The input reads one query, then returns. `schedule` is refused because this
//! pipeline has no shutdown signal. Elasticsearch 8 uses a point-in-time and
//! `search_after`. Elasticsearch 7 uses scroll. The filter sends the query
//! string as `q` unless `query_template` supplies a DSL body. A lookup failure
//! tags the event and leaves the pipeline running.

use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value as Json;

use crate::elastic::{self, Endpoint};
use crate::event::Event;
use crate::lscl::{Arg, Key, Plugin};
use crate::mutate::filter_matched;
use crate::run::{Ecs, RunError, Settings, fail};
use crate::value::{Map, Value};

const ORIGIN: &str = "logstash-input-elasticsearch";

pub(crate) fn read(plugin: &Plugin, settings: &Settings) -> Result<Vec<Event>, RunError> {
    if text(plugin, "schedule").is_some() {
        return Err(fail("elasticsearch input schedule is not implemented"));
    }
    refuse_transport(plugin)?;
    let host = first_host(plugin, "localhost:9200")?;
    let auth = basic_auth(&host);
    let info = ping(&host, &auth, Some(ORIGIN))?;
    let query_type = text(plugin, "query_type").unwrap_or_else(|| "dsl".to_string());
    if query_type == "esql" {
        return read_esql(plugin, &host, &auth, &info);
    }
    if query_type != "dsl" {
        return Err(fail(format!(
            "elasticsearch query_type {query_type} is not implemented"
        )));
    }
    let response_type = text(plugin, "response_type").unwrap_or_else(|| "hits".to_string());
    let index = text(plugin, "index").unwrap_or_else(|| "logstash-*".to_string());
    let size = number(plugin, "size").unwrap_or(1000);
    let scroll = text(plugin, "scroll").unwrap_or_else(|| "1m".to_string());
    let retries = number(plugin, "retries").unwrap_or(0);
    if let Some(slices) = number(plugin, "slices")
        && slices > 1
    {
        return Err(fail("elasticsearch slices is not implemented"));
    }
    if retries < 0 {
        return Err(fail(format!(
            "Elasticsearch Input Plugin's `retries` option must be equal or greater than zero, got `{retries}`"
        )));
    }
    let mut query =
        text(plugin, "query").unwrap_or_else(|| "{ \"sort\": [ \"_doc\" ] }".to_string());
    if let Some(field) = text(plugin, "tracking_field") {
        let search_api = resolved_search_api(plugin, info.major)?;
        if search_api != "search_after" || response_type != "hits" {
            return Err(fail(
                "The `tracking_field` feature can only be used with `search_after` non-aggregation queries",
            ));
        }
        let seed = text(plugin, "tracking_field_seed")
            .unwrap_or_else(|| "1970-01-01T00:00:00.000000000Z".to_string());
        let cursor = read_cursor(plugin, settings, &seed)?;
        let present = format_instant(SystemTime::now() - Duration::from_secs(30));
        query = query
            .replace(":last_value", &cursor)
            .replace(":present", &present);
        let events = dispatch_hits(
            plugin,
            settings,
            &host,
            &auth,
            &info,
            &index,
            &query,
            size,
            &scroll,
            retries,
            &response_type,
        )?;
        let next = events
            .iter()
            .filter_map(|event| event.get_field(&field).ok().flatten())
            .map(|value| value.to_string())
            .max()
            .unwrap_or(cursor);
        write_cursor(plugin, settings, &next)?;
        return Ok(events);
    }
    dispatch_hits(
        plugin,
        settings,
        &host,
        &auth,
        &info,
        &index,
        &query,
        size,
        &scroll,
        retries,
        &response_type,
    )
}

#[allow(clippy::too_many_arguments)]
fn dispatch_hits(
    plugin: &Plugin,
    settings: &Settings,
    host: &Endpoint,
    auth: &Option<String>,
    info: &elastic::Cluster,
    index: &str,
    query: &str,
    size: i64,
    scroll: &str,
    retries: i64,
    response_type: &str,
) -> Result<Vec<Event>, RunError> {
    if response_type == "aggregations" {
        return read_aggregation(plugin, settings, host, auth, index, query, retries);
    }
    if response_type != "hits" {
        return Err(fail(format!(
            "elasticsearch response_type {response_type} is not implemented"
        )));
    }
    let search_api = resolved_search_api(plugin, info.major)?;
    if search_api == "search_after" {
        read_search_after(
            plugin, settings, host, auth, index, query, size, scroll, retries,
        )
    } else if search_api == "scroll" {
        read_scroll(
            plugin, settings, host, auth, index, query, size, scroll, retries,
        )
    } else {
        Err(fail(format!(
            "elasticsearch search_api {search_api} is not implemented"
        )))
    }
}

pub(crate) fn lookup(plugin: &Plugin, event: &mut Event) -> Result<(), RunError> {
    let prepared = prepare_lookup(plugin)?;
    if let Err(_error) = run_lookup(plugin, event, &prepared) {
        for tag in failure_tags(plugin) {
            event.tag(&tag);
        }
    }
    Ok(())
}

struct PreparedLookup {
    host: Endpoint,
    auth: Option<String>,
    index: String,
    request: LookupRequest,
}

enum LookupRequest {
    Query {
        query: String,
        size: i64,
        sort: Option<String>,
    },
    Template(String),
}

fn prepare_lookup(plugin: &Plugin) -> Result<PreparedLookup, RunError> {
    refuse_transport(plugin)?;
    let query_type = text(plugin, "query_type").unwrap_or_else(|| "dsl".to_string());
    if query_type == "esql" {
        return Err(fail("elasticsearch filter esql is not implemented"));
    }
    if query_type != "dsl" {
        return Err(fail(format!(
            "elasticsearch query_type {query_type} is not implemented"
        )));
    }
    if has(plugin, "query_params") {
        return Err(fail(
            "`query_params` is not allowed when `query_type => 'dsl'`.",
        ));
    }
    let query = text(plugin, "query");
    let template = text(plugin, "query_template");
    match (&query, &template) {
        (None, None) => {
            return Err(fail(
                "Both `query` and `query_template` are empty. Require either `query` or `query_template`.",
            ));
        }
        (Some(_), Some(_)) => {
            return Err(fail(
                "Both `query` and `query_template` are set. Use either `query` or `query_template`.",
            ));
        }
        _ => {}
    }
    let host = first_host(plugin, "localhost:9200")?;
    let auth = basic_auth(&host);
    let _info = ping(&host, &auth, None)?;
    let index = text(plugin, "index").unwrap_or_default();
    let request = if let Some(template) = template {
        let raw = fs::read_to_string(&template).map_err(|error| fail(error.to_string()))?;
        if raw.is_empty() {
            return Err(fail("template is empty"));
        }
        LookupRequest::Template(raw)
    } else {
        let size = number(plugin, "result_size").unwrap_or(1);
        let sort = if flag(plugin, "enable_sort").unwrap_or(true) {
            Some(text(plugin, "sort").unwrap_or_else(|| "@timestamp:desc".to_string()))
        } else {
            None
        };
        LookupRequest::Query {
            query: query.unwrap_or_default(),
            size,
            sort,
        }
    };
    Ok(PreparedLookup {
        host,
        auth,
        index,
        request,
    })
}

fn run_lookup(
    plugin: &Plugin,
    event: &mut Event,
    prepared: &PreparedLookup,
) -> Result<(), RunError> {
    let PreparedLookup {
        host,
        auth,
        index,
        request,
    } = prepared;
    let index = event
        .sprintf(index)
        .map_err(|error| fail(error.to_string()))?;
    let path = search_path(&host.prefix, &index);
    let (path, body) = match request {
        LookupRequest::Template(raw) => {
            let rendered = event
                .sprintf(raw)
                .map_err(|error| fail(error.to_string()))?;
            let parsed: Json =
                serde_json::from_str(&rendered).map_err(|error| fail(error.to_string()))?;
            (path, Some(parsed.to_string()))
        }
        LookupRequest::Query { query, size, sort } => {
            let rendered = event
                .sprintf(query)
                .map_err(|error| fail(error.to_string()))?;
            let mut params = format!("q={}&size={size}", elastic::cgi_escape(&rendered));
            if let Some(sort) = sort {
                params.push_str("&sort=");
                params.push_str(&elastic::cgi_escape(sort));
            }
            (format!("{path}?{params}"), None)
        }
    };
    let response = elastic::http(
        host,
        auth,
        if body.is_some() { "POST" } else { "GET" },
        &path,
        &json_headers(None),
        body.as_deref().map(str::as_bytes),
    )?;
    if !(200..300).contains(&response.status) {
        return Err(fail(format!(
            "Got response code '{}' contacting Elasticsearch at URL '{}'",
            response.status,
            host.url(&path)
        )));
    }
    let payload: Json =
        serde_json::from_slice(&response.body).map_err(|error| fail(error.to_string()))?;
    if payload
        .get("_shards")
        .and_then(|item| item.get("failures"))
        .is_some()
    {
        return Err(fail(format!(
            "Elasticsearch query error: {}",
            payload["_shards"]["failures"]
        )));
    }
    let hits = payload.get("hits").cloned().unwrap_or(Json::Null);
    let total = match hits.get("total") {
        Some(Json::Object(object)) => object.get("value").and_then(Json::as_i64).unwrap_or(0),
        Some(Json::Number(number)) => number.as_i64().unwrap_or(0),
        _ => 0,
    };
    event
        .set_field("[@metadata][total_hits]", Value::Integer(i128::from(total)))
        .map_err(|error| fail(error.to_string()))?;
    let mut matched = false;
    if let Some(documents) = hits.get("hits").and_then(Json::as_array)
        && !documents.is_empty()
    {
        matched = true;
        copy_mapped(event, documents, plugin, "fields", true)?;
        copy_mapped(event, documents, plugin, "docinfo_fields", false)?;
    }
    if let Some(aggregations) = payload.get("aggregations").and_then(Json::as_object)
        && !aggregations.is_empty()
    {
        matched = true;
        for (name, field) in hash_pairs(plugin, "aggregation_fields") {
            if let Some(value) = aggregations.get(&name) {
                set_target(event, plugin, &field, json_to_value(value))?;
            }
        }
    }
    if matched {
        filter_matched(plugin, event)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn read_search_after(
    plugin: &Plugin,
    settings: &Settings,
    host: &Endpoint,
    auth: &Option<String>,
    index: &str,
    query: &str,
    size: i64,
    scroll: &str,
    retries: i64,
) -> Result<Vec<Event>, RunError> {
    let pit_path = format!(
        "{}?keep_alive={}",
        elastic::join_path(&host.prefix, &format!("{}/_pit", encode_index(index))),
        elastic::cgi_escape(scroll)
    );
    let opened = call_with_retries(host, auth, "POST", &pit_path, None, retries)?;
    let pit: Json =
        serde_json::from_slice(&opened.body).map_err(|error| fail(error.to_string()))?;
    let pit_id = pit
        .get("id")
        .and_then(Json::as_str)
        .ok_or_else(|| fail("elasticsearch point in time response has no id"))?
        .to_string();
    let mut events = Vec::new();
    let mut search_after: Option<Json> = None;
    let result = (|| {
        loop {
            let mut body: Json =
                serde_json::from_str(query).map_err(|error| fail(error.to_string()))?;
            if body.get("sort").is_none() {
                body["sort"] = serde_json::json!({"_shard_doc": "asc"});
            }
            body["pit"] = serde_json::json!({"id": pit_id, "keep_alive": scroll});
            if let Some(cursor) = &search_after {
                body["search_after"] = cursor.clone();
            }
            let path = format!(
                "{}?size={size}",
                elastic::join_path(&host.prefix, "_search")
            );
            let page =
                call_with_retries(host, auth, "POST", &path, Some(body.to_string()), retries)?;
            let payload: Json =
                serde_json::from_slice(&page.body).map_err(|error| fail(error.to_string()))?;
            let hits = payload
                .pointer("/hits/hits")
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default();
            if hits.is_empty() {
                break;
            }
            search_after = hits.last().and_then(|hit| hit.get("sort")).cloned();
            events.extend(hits_to_events(plugin, settings, &hits)?);
            if search_after.is_none() {
                break;
            }
        }
        Ok(())
    })();
    let _ = call_with_retries(
        host,
        auth,
        "DELETE",
        &elastic::join_path(&host.prefix, "_pit"),
        Some(format!(
            "{{\"id\":{}}}",
            serde_json::to_string(&pit_id).unwrap_or_default()
        )),
        0,
    );
    result?;
    Ok(events)
}

#[allow(clippy::too_many_arguments)]
fn read_scroll(
    plugin: &Plugin,
    settings: &Settings,
    host: &Endpoint,
    auth: &Option<String>,
    index: &str,
    query: &str,
    size: i64,
    scroll: &str,
    retries: i64,
) -> Result<Vec<Event>, RunError> {
    let path = format!(
        "{}?scroll={}&size={size}",
        elastic::join_path(&host.prefix, &format!("{}/_search", encode_index(index))),
        elastic::cgi_escape(scroll)
    );
    let mut page = call_with_retries(host, auth, "POST", &path, Some(query.to_string()), retries)?;
    let mut events = Vec::new();
    #[allow(unused_assignments)]
    let mut scroll_id = String::new();
    loop {
        let payload: Json =
            serde_json::from_slice(&page.body).map_err(|error| fail(error.to_string()))?;
        scroll_id = payload
            .get("_scroll_id")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        let hits = payload
            .pointer("/hits/hits")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        if hits.is_empty() {
            break;
        }
        events.extend(hits_to_events(plugin, settings, &hits)?);
        if scroll_id.is_empty() {
            break;
        }
        let body = serde_json::json!({"scroll": scroll, "scroll_id": scroll_id}).to_string();
        page = call_with_retries(
            host,
            auth,
            "POST",
            &elastic::join_path(&host.prefix, "_search/scroll"),
            Some(body),
            retries,
        )?;
    }
    if !scroll_id.is_empty() {
        let body = serde_json::json!({"scroll_id": scroll_id}).to_string();
        let _ = call_with_retries(
            host,
            auth,
            "DELETE",
            &elastic::join_path(&host.prefix, "_search/scroll"),
            Some(body),
            0,
        );
    }
    Ok(events)
}

fn read_aggregation(
    plugin: &Plugin,
    settings: &Settings,
    host: &Endpoint,
    auth: &Option<String>,
    index: &str,
    query: &str,
    retries: i64,
) -> Result<Vec<Event>, RunError> {
    let path = format!(
        "{}?size=0",
        elastic::join_path(&host.prefix, &format!("{}/_search", encode_index(index)))
    );
    let page = call_with_retries(host, auth, "POST", &path, Some(query.to_string()), retries)?;
    let payload: Json =
        serde_json::from_slice(&page.body).map_err(|error| fail(error.to_string()))?;
    Ok(vec![event_from_root(
        plugin,
        settings,
        &payload,
        "aggregations",
    )?])
}

fn read_esql(
    plugin: &Plugin,
    host: &Endpoint,
    auth: &Option<String>,
    info: &elastic::Cluster,
) -> Result<Vec<Event>, RunError> {
    let query = text(plugin, "query").unwrap_or_default();
    if query.trim().is_empty() {
        return Err(fail("`query` cannot be empty"));
    }
    let allowed = ["FROM", "ROW", "SHOW"];
    if !allowed.iter().any(|word| query.trim().starts_with(word)) {
        return Err(fail(format!(
            "`query` needs to start with any of {allowed:?}"
        )));
    }
    if info.major < 8 || (info.major == 8 && info.minor < 11) {
        return Err(fail(format!(
            "Connected Elasticsearch {} version does not supports ES|QL. ES|QL feature requires at least Elasticsearch 8.11.0 version.",
            info.number
        )));
    }
    let path = format!(
        "{}?format=json&drop_null_columns=true",
        elastic::join_path(&host.prefix, "_query")
    );
    let body = serde_json::json!({"query": query}).to_string();
    let retries = number(plugin, "retries").unwrap_or(0);
    let response = call_with_retries(host, auth, "POST", &path, Some(body), retries)?;
    let payload: Json =
        serde_json::from_slice(&response.body).map_err(|error| fail(error.to_string()))?;
    let columns = payload
        .get("columns")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    let values = payload
        .get("values")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    let names: Vec<&str> = columns
        .iter()
        .map(|column| column.get("name").and_then(Json::as_str).unwrap_or(""))
        .collect();
    let mut events = Vec::new();
    for row in values {
        let Some(cells) = row.as_array() else {
            continue;
        };
        match esql_row(plugin, &columns, &names, cells) {
            Ok(event) => events.push(event),
            Err(_) => events.push(esql_failure(&columns, cells)?),
        }
    }
    Ok(events)
}

fn esql_row(
    plugin: &Plugin,
    columns: &[Json],
    names: &[&str],
    cells: &[Json],
) -> Result<Event, RunError> {
    let mut event = Event::new();
    for (column, cell) in columns.iter().zip(cells) {
        if cell.is_null() || cell.as_bool() == Some(false) {
            continue;
        }
        let name = column.get("name").and_then(Json::as_str).unwrap_or("");
        if esql_subfield(name, names) {
            continue;
        }
        let reference = format!("[{}]", name.replace('.', "]["));
        let field = match text(plugin, "target") {
            Some(target) => format!("[{target}][{reference}]"),
            None => reference,
        };
        let kind = column.get("type").and_then(Json::as_str).unwrap_or("");
        event
            .set_field(&field, esql_value(kind, cell)?)
            .map_err(|error| fail(error.to_string()))?;
    }
    decorate_input(plugin, &mut event)?;
    Ok(event)
}

fn esql_subfield(name: &str, names: &[&str]) -> bool {
    let mut parts = name.split('.');
    let Some(mut prefix) = parts.next() else {
        return false;
    };
    let mut nested = false;
    for part in parts {
        if names.contains(&prefix) {
            nested = true;
        }
        prefix = &name[..prefix.len() + 1 + part.len()];
    }
    nested
}

fn esql_value(kind: &str, cell: &Json) -> Result<Value, RunError> {
    if kind == "date" {
        let text = cell
            .as_str()
            .ok_or_else(|| fail("elasticsearch esql date column is not a string"))?;
        let parsed = chrono::DateTime::parse_from_rfc3339(text)
            .or_else(|_| chrono::DateTime::parse_from_rfc3339(&format!("{text}Z")))
            .map_err(|error| fail(error.to_string()))?;
        return Ok(Value::Timestamp(parsed.with_timezone(&chrono::Utc)));
    }
    Ok(json_to_value(cell))
}

fn esql_failure(columns: &[Json], cells: &[Json]) -> Result<Event, RunError> {
    let mut event = Event::new();
    event
        .set_field("columns", json_to_value(&Json::Array(columns.to_vec())))
        .map_err(|error| fail(error.to_string()))?;
    event
        .set_field(
            "values",
            json_to_value(&Json::Array(vec![Json::Array(cells.to_vec())])),
        )
        .map_err(|error| fail(error.to_string()))?;
    event.tag("_elasticsearch_input_failure");
    Ok(event)
}

fn hits_to_events(
    plugin: &Plugin,
    settings: &Settings,
    hits: &[Json],
) -> Result<Vec<Event>, RunError> {
    let mut events = Vec::new();
    for hit in hits {
        events.push(event_from_root(plugin, settings, hit, "_source")?);
    }
    Ok(events)
}

fn event_from_root(
    plugin: &Plugin,
    settings: &Settings,
    hit: &Json,
    root: &str,
) -> Result<Event, RunError> {
    let mut event = match build_hit_event(plugin, settings, hit, root) {
        Ok(event) => event,
        Err(_) => input_failure(hit)?,
    };
    decorate_input(plugin, &mut event)?;
    Ok(event)
}

fn build_hit_event(
    plugin: &Plugin,
    settings: &Settings,
    hit: &Json,
    root: &str,
) -> Result<Event, RunError> {
    let source = hit.get(root).cloned().unwrap_or(Json::Null);
    if source.is_null() {
        return Err(fail("elasticsearch hit source is null"));
    }
    let mut event = event_from_json(&source, text(plugin, "target").as_deref())?;
    if flag(plugin, "docinfo").unwrap_or(false) {
        merge_docinfo(plugin, settings, hit, &mut event)?;
    }
    Ok(event)
}

fn input_failure(hit: &Json) -> Result<Event, RunError> {
    let mut event = Event::new();
    event
        .set_field("[event][original]", Value::from(hit.to_string()))
        .map_err(|error| fail(error.to_string()))?;
    event.tag("_elasticsearch_input_failure");
    Ok(event)
}

fn merge_docinfo(
    plugin: &Plugin,
    settings: &Settings,
    hit: &Json,
    event: &mut Event,
) -> Result<(), RunError> {
    let target = text(plugin, "docinfo_target").unwrap_or_else(|| {
        if settings.ecs == Ecs::Disabled {
            "@metadata".to_string()
        } else {
            "[@metadata][input][elasticsearch]".to_string()
        }
    });
    let fields = if has(plugin, "docinfo_fields") {
        string_list(plugin, "docinfo_fields")
    } else {
        vec!["_index".to_string(), "_type".to_string(), "_id".to_string()]
    };
    if target == "@metadata" {
        for field in fields {
            let value = hit.get(&field).cloned().unwrap_or(Json::Null);
            event
                .set_field(&format!("[@metadata][{field}]"), json_to_value(&value))
                .map_err(|error| fail(error.to_string()))?;
        }
        return Ok(());
    }
    let existing = event
        .get_field(&target)
        .map_err(|error| fail(error.to_string()))?;
    let mut map = match existing {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Map(map)) => map,
        Some(_) => {
            return Err(fail(format!(
                "Incompatible event; unable to merge docinfo fields into docinfo_target=`{target}`"
            )));
        }
    };
    for field in fields {
        map.insert(
            field.clone(),
            json_to_value(hit.get(&field).unwrap_or(&Json::Null)),
        );
    }
    event
        .set_field(&target, Value::Map(map))
        .map_err(|error| fail(error.to_string()))
}

fn decorate_input(plugin: &Plugin, event: &mut Event) -> Result<(), RunError> {
    if let Some(kind) = text(plugin, "type") {
        event
            .set_field("type", Value::from(kind.as_str()))
            .map_err(|error| fail(error.to_string()))?;
    }
    for tag in string_list(plugin, "tags") {
        event.tag(&tag);
    }
    filter_matched(plugin, event)
}

fn event_from_json(value: &Json, target: Option<&str>) -> Result<Event, RunError> {
    let Some(target) = target else {
        let rendered = serde_json::to_string(value).map_err(|error| fail(error.to_string()))?;
        let parsed = Event::from_json(&rendered).map_err(|error| fail(error.to_string()))?;
        return Ok(parsed.into_iter().next().unwrap_or_else(Event::new));
    };
    let mut event = Event::new();
    event
        .set_field(target, json_to_value(value))
        .map_err(|error| fail(error.to_string()))?;
    Ok(event)
}

fn copy_mapped(
    event: &mut Event,
    documents: &[Json],
    plugin: &Plugin,
    option: &str,
    from_source: bool,
) -> Result<(), RunError> {
    for (old_key, new_key) in hash_pairs(plugin, option) {
        let values: Vec<Value> = documents
            .iter()
            .map(|document| {
                let root = if from_source {
                    document.get("_source").unwrap_or(&Json::Null)
                } else {
                    document
                };
                json_to_value(&dig(root, &old_key))
            })
            .collect();
        let value = if values.len() > 1 {
            Value::Array(values)
        } else {
            values.into_iter().next().unwrap_or(Value::Null)
        };
        set_target(event, plugin, &new_key, value)?;
    }
    Ok(())
}

fn set_target(event: &mut Event, plugin: &Plugin, key: &str, value: Value) -> Result<(), RunError> {
    let path = match text(plugin, "target") {
        Some(target) => format!("[{target}][{key}]"),
        None => key.to_string(),
    };
    event
        .set_field(&path, value)
        .map_err(|error| fail(error.to_string()))
}

fn dig(value: &Json, reference: &str) -> Json {
    let path: Vec<&str> = if reference.starts_with('[') && reference.ends_with(']') {
        reference[1..reference.len() - 1].split("][").collect()
    } else {
        vec![reference]
    };
    let mut current = value;
    for part in path {
        match current.get(part) {
            Some(next) => current = next,
            None => return Json::Null,
        }
    }
    current.clone()
}

fn resolved_search_api(plugin: &Plugin, major: u64) -> Result<String, RunError> {
    match text(plugin, "search_api").as_deref() {
        Some("search_after") => Ok("search_after".to_string()),
        Some("scroll") => Ok("scroll".to_string()),
        Some("auto") | None => Ok(if major >= 8 {
            "search_after".to_string()
        } else {
            "scroll".to_string()
        }),
        Some(other) => Err(fail(format!(
            "elasticsearch search_api {other} is not implemented"
        ))),
    }
}

fn ping(
    host: &Endpoint,
    auth: &Option<String>,
    origin: Option<&str>,
) -> Result<elastic::Cluster, RunError> {
    let response = elastic::http(
        host,
        auth,
        "GET",
        &elastic::root_path(&host.prefix),
        &json_headers(origin),
        None,
    )?;
    if !(200..300).contains(&response.status) {
        return Err(fail(format!(
            "Got response code '{}' contacting Elasticsearch at URL '{}'",
            response.status,
            host.url("/")
        )));
    }
    elastic::cluster_info(&response)
}

fn call_with_retries(
    host: &Endpoint,
    auth: &Option<String>,
    method: &str,
    path: &str,
    body: Option<String>,
    retries: i64,
) -> Result<elastic::Response, RunError> {
    let mut attempt = 0;
    let times = retries + 1;
    loop {
        attempt += 1;
        match elastic::http(
            host,
            auth,
            method,
            path,
            &json_headers(Some(ORIGIN)),
            body.as_deref().map(str::as_bytes),
        ) {
            Ok(response) if (200..300).contains(&response.status) => return Ok(response),
            Ok(response) if attempt >= times => {
                return Err(fail(format!(
                    "Got response code '{}' contacting Elasticsearch at URL '{}'",
                    response.status,
                    host.url(path)
                )));
            }
            Err(error) if attempt >= times => return Err(error),
            _ => {}
        }
    }
}

fn json_headers(origin: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    if let Some(origin) = origin {
        headers.push(("x-elastic-product-origin".to_string(), origin.to_string()));
    }
    headers
}

fn first_host(plugin: &Plugin, default_host: &str) -> Result<Endpoint, RunError> {
    let raw = match arg(plugin, "hosts") {
        Some(Arg::Array(items)) => items
            .first()
            .and_then(scalar)
            .unwrap_or(default_host)
            .to_string(),
        Some(value) => scalar(value)
            .ok_or_else(|| fail("elasticsearch hosts must be strings"))?
            .to_string(),
        None => default_host.to_string(),
    };
    let endpoint = elastic::parse_endpoint(&raw)?;
    if endpoint.scheme == "https" || flag(plugin, "ssl_enabled") == Some(true) {
        return Err(fail("plugin elasticsearch ssl_enabled is not implemented"));
    }
    let mut endpoint = endpoint;
    if let Some(user) = text(plugin, "user") {
        endpoint.user = Some(user);
        endpoint.password = text(plugin, "password");
    }
    Ok(endpoint)
}

fn basic_auth(host: &Endpoint) -> Option<String> {
    let user = host.user.as_deref()?;
    let password = host.password.as_deref().unwrap_or("");
    Some(format!(
        "Basic {}",
        elastic::base64(format!("{user}:{password}").as_bytes())
    ))
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
    if text(plugin, "api_key").is_some() && flag(plugin, "ssl_enabled") != Some(true) {
        return Err(fail(
            "Using api_key authentication requires SSL/TLS secured communication using the `ssl_enabled => true` option",
        ));
    }
    if let Some(proxy) = text(plugin, "proxy")
        && !proxy.is_empty()
    {
        return Err(fail("elasticsearch proxy is not implemented"));
    }
    Ok(())
}

fn failure_tags(plugin: &Plugin) -> Vec<String> {
    if has(plugin, "tag_on_failure") {
        string_list(plugin, "tag_on_failure")
    } else {
        vec!["_elasticsearch_lookup_failure".to_string()]
    }
}

fn read_cursor(plugin: &Plugin, settings: &Settings, seed: &str) -> Result<String, RunError> {
    let path = cursor_path(plugin, settings)?;
    match fs::read_to_string(&path) {
        Ok(value) => Ok(value),
        Err(_) => Ok(seed.to_string()),
    }
}

fn write_cursor(plugin: &Plugin, settings: &Settings, value: &str) -> Result<(), RunError> {
    let path = cursor_path(plugin, settings)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| fail(error.to_string()))?;
    }
    fs::write(path, value).map_err(|error| fail(error.to_string()))
}

fn cursor_path(plugin: &Plugin, settings: &Settings) -> Result<std::path::PathBuf, RunError> {
    if let Some(path) = text(plugin, "last_run_metadata_path") {
        return Ok(std::path::PathBuf::from(path));
    }
    let data = settings.path_data.as_deref().ok_or_else(|| {
        fail("elasticsearch tracking_field requires path.data or last_run_metadata_path")
    })?;
    Ok(std::path::PathBuf::from(data)
        .join("plugins")
        .join("inputs")
        .join("elasticsearch")
        .join(&settings.pipeline_id)
        .join("last_run_value"))
}

fn format_instant(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = duration.as_secs() as i64;
    let nanos = duration.subsec_nanos();
    chrono::DateTime::from_timestamp(seconds, nanos)
        .map(|timestamp| timestamp.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00.000000000Z".to_string())
}

fn search_path(prefix: &str, index: &str) -> String {
    if index.is_empty() {
        elastic::join_path(prefix, "_search")
    } else {
        elastic::join_path(prefix, &format!("{}/_search", encode_index(index)))
    }
}

fn encode_index(index: &str) -> String {
    let mut out = String::new();
    for byte in index.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'*' | b',') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn json_to_value(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Boolean(*flag),
        Json::Number(number) => {
            if let Some(integer) = number.as_i64() {
                Value::Integer(i128::from(integer))
            } else if let Some(float) = number.as_f64() {
                Value::Float(float)
            } else {
                Value::from(number.to_string())
            }
        }
        Json::String(text) => Value::from(text.as_str()),
        Json::Array(items) => Value::Array(items.iter().map(json_to_value).collect()),
        Json::Object(fields) => {
            let mut map = Map::new();
            for (key, value) in fields {
                map.insert(key, json_to_value(value));
            }
            Value::Map(map)
        }
    }
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

fn string_list(plugin: &Plugin, name: &str) -> Vec<String> {
    match arg(plugin, name) {
        Some(Arg::Array(items)) => items
            .iter()
            .filter_map(scalar)
            .map(str::to_string)
            .collect(),
        Some(value) => scalar(value)
            .map(|item| vec![item.to_string()])
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

fn hash_pairs(plugin: &Plugin, name: &str) -> Vec<(String, String)> {
    let Some(Arg::Map(entries)) = arg(plugin, name) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|(key, value)| Some((key_text(key), scalar(value)?.to_string())))
        .collect()
}

fn key_text(key: &Key) -> String {
    match key {
        Key::String(value) => value.clone(),
        Key::Int(value) => value.to_string(),
        Key::Big(value) => value.clone(),
        Key::Float(value) => value.to_string(),
    }
}
