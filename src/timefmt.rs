use chrono::{DateTime, Datelike, Timelike, Utc};

use crate::error::EventError;

/// Logstash `Timestamp.toString`.
///
/// Zero nanoseconds always print three fractional digits. Any other value
/// prints 3, 6, or 9 digits, dropping trailing zero groups.
pub fn format_timestamp(timestamp: DateTime<Utc>) -> String {
    let nanos = timestamp.nanosecond();
    let fraction = if nanos.is_multiple_of(1_000_000) {
        format!("{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        format!("{:06}", nanos / 1_000)
    } else {
        format!("{:09}", nanos)
    };
    format!(
        "{}T{}.{}Z",
        timestamp.format("%Y-%m-%d"),
        timestamp.format("%H:%M:%S"),
        fraction
    )
}

pub fn format_joda_pattern(timestamp: DateTime<Utc>, pattern: &str) -> Result<String, EventError> {
    let truncated = DateTime::<Utc>::from_timestamp_millis(timestamp.timestamp_millis())
        .ok_or(EventError::TimestampOutOfRange)?;
    format_letters(truncated, pattern)
}

pub fn format_java_pattern(timestamp: DateTime<Utc>, pattern: &str) -> Result<String, EventError> {
    format_letters(timestamp, pattern)
}

fn format_letters(timestamp: DateTime<Utc>, pattern: &str) -> Result<String, EventError> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut output = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\'' {
            index += 1;
            while index < chars.len() {
                if chars[index] == '\'' {
                    if chars.get(index + 1) == Some(&'\'') {
                        output.push('\'');
                        index += 2;
                    } else {
                        index += 1;
                        break;
                    }
                } else {
                    output.push(chars[index]);
                    index += 1;
                }
            }
            continue;
        }
        let letter = chars[index];
        if letter.is_ascii_alphabetic() {
            let mut end = index + 1;
            while end < chars.len() && chars[end] == letter {
                end += 1;
            }
            let width = end - index;
            let number = match letter {
                'y' => timestamp.year(),
                'Y' => timestamp.iso_week().year(),
                'M' => timestamp.month() as i32,
                'd' => timestamp.day() as i32,
                'D' => timestamp.ordinal() as i32,
                'w' => timestamp.iso_week().week() as i32,
                's' => timestamp.second() as i32,
                _ => {
                    return Err(EventError::UnsupportedTimePattern {
                        pattern: pattern.to_string(),
                    });
                }
            };
            output.push_str(&format!("{number:0width$}"));
            index = end;
        } else {
            output.push(letter);
            index += 1;
        }
    }
    Ok(output)
}
