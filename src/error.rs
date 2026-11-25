use std::fmt::{self, Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub enum EventError {
    InvalidField { reference: String },
    InvalidFieldSet { message: String },
    InvalidTags,
    UnsupportedTimePattern { pattern: String },
    TimestampOutOfRange,
    Json { message: String },
}

impl Display for EventError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            EventError::InvalidField { reference } => {
                write!(formatter, "Invalid FieldReference: `{reference}`")
            }
            EventError::InvalidFieldSet { message } => formatter.write_str(message),
            EventError::InvalidTags => formatter.write_str("invalid tags type"),
            EventError::UnsupportedTimePattern { pattern } => {
                write!(formatter, "unsupported time pattern: {pattern}")
            }
            EventError::TimestampOutOfRange => formatter.write_str("timestamp out of range"),
            EventError::Json { message } => write!(formatter, "json: {message}"),
        }
    }
}

impl std::error::Error for EventError {}
