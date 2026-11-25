//! Logstash event model: fields, metadata, sprintf, and timestamps.
//!
//! Field-reference scanning uses Unicode scalar values. The 9.5.2 oracle
//! references are ASCII, where that matches Java's UTF-16 indexing.

mod error;
mod event;
mod field;
mod timefmt;
mod value;

pub use error::EventError;
pub use event::Event;
pub use value::{Map, Value};
