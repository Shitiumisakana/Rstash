//! Logstash 9.5.2 configuration language.
//!
//! The grammar is `lscl_grammar.treetop`. The tree shape is `compiler/lscl.rb`:
//! shunting-yard booleans, elsif rewritten as nested if/else, filters composed
//! in sequence, inputs and outputs composed in parallel.

mod model;
mod parse;

pub(crate) use model::{Arg, Expr, Key, Kind, Plugin, Statement};
pub use model::{CompiledPlugin, ConfigError, Pipeline, PipelineVertex, SourceMeta};

/// One `SourceWithMetadata` passed to `ConfigCompiler.compileSources`.
pub struct ConfigSource<'a> {
    pub protocol: &'a str,
    pub id: &'a str,
    pub text: &'a str,
}

/// Compile one configuration the way `LogStash::Compiler.compile_imperative` does.
/// `support_escapes` is the 9.5.2 `config.support_escapes` setting and defaults to false.
/// Protocol and id default to `config_ast`, matching a missing base source.
pub fn compile_imperative(source: &str, support_escapes: bool) -> Result<Pipeline, ConfigError> {
    compile_sources(
        &[ConfigSource {
            protocol: "config_ast",
            id: "config_ast",
            text: source,
        }],
        support_escapes,
    )
}

/// `ConfigCompiler.compileSources`. Sources are joined with a newline for the original text.
pub fn compile_sources(
    sources: &[ConfigSource<'_>],
    support_escapes: bool,
) -> Result<Pipeline, ConfigError> {
    parse::compile_sources(sources, support_escapes)
}

/// `LogStash::Config::StringEscape.process_escapes`.
pub fn process_string_escapes(text: &str) -> String {
    parse::process_escapes(text)
}
