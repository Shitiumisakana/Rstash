//! Logstash event model: fields, metadata, sprintf, and timestamps.
//!
//! Field-reference scanning uses Unicode scalar values. The 9.5.2 oracle
//! references are ASCII, where that matches Java's UTF-16 indexing.

pub mod cli;

mod codec;
mod digest;
mod error;
mod event;
mod field;
mod filewatch;
mod grok;
mod lscl;
mod mutate;
mod netio;
mod pattern_files;
mod plugins;
mod run;
mod timefmt;
mod value;

pub use digest::sha256_hex;
pub use lscl::{
    CompiledPlugin, ConfigError, ConfigSource, Pipeline, PipelineVertex, SourceMeta,
    compile_imperative, compile_sources, process_string_escapes,
};

pub use codec::TextCodec;
pub use error::EventError;
pub use event::Event;
pub use field::{
    FieldEscape, FieldRef, Target, field_cache_len_after_distinct, intern_field, parse_field,
    parse_field_escaped, same_interned_field,
};
pub use mutate::parse_signed_hex_str;
pub use run::{
    Ecs, PipelineConfig, RunError, RunResult, Settings, apply_filter, apply_logstash_yml,
    load_pipelines_yml, run, run_many,
};
pub use value::{Decimal, Map, Value};
