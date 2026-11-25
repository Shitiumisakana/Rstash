//! Logstash 9.5.2 configuration language.
//!
//! The grammar is `lscl_grammar.treetop`. The tree shape is `compiler/lscl.rb`:
//! shunting-yard booleans, elsif rewritten as nested if/else, filters composed
//! in sequence, inputs and outputs composed in parallel.

mod model;
mod parse;

pub use model::{ConfigError, Pipeline};

/// Compile one configuration the way `LogStash::Compiler.compile_imperative` does.
/// `support_escapes` is the 9.5.2 `config.support_escapes` setting and defaults to false.
pub fn compile_imperative(source: &str, support_escapes: bool) -> Result<Pipeline, ConfigError> {
    parse::compile(source, support_escapes)
}
