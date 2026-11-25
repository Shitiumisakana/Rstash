use crate::error::EventError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldRef {
    pub path: Vec<String>,
    pub key: String,
    pub target: Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Data,
    Metadata,
    MetadataRoot,
}

pub fn parse_field(input: &str) -> Result<FieldRef, EventError> {
    let tokens = tokenize(input)?;
    from_tokens(tokens)
}

fn from_tokens(mut tokens: Vec<String>) -> Result<FieldRef, EventError> {
    let Some(key) = tokens.pop() else {
        return Err(EventError::InvalidField {
            reference: String::new(),
        });
    };
    if tokens.is_empty() && key == "@metadata" {
        return Ok(FieldRef {
            path: Vec::new(),
            key,
            target: Target::MetadataRoot,
        });
    }
    if tokens.first().is_some_and(|segment| segment == "@metadata") {
        return Ok(FieldRef {
            path: tokens.into_iter().skip(1).collect(),
            key,
            target: Target::Metadata,
        });
    }
    Ok(FieldRef {
        path: tokens,
        key,
        target: Target::Data,
    })
}

/// Bracket rules copied from `FieldReference.StrictTokenizer` in Logstash 9.5.2.
fn tokenize(input: &str) -> Result<Vec<String>, EventError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut error = false;
    let mut seen_bracket = false;
    let mut depth = 0i32;
    let mut token_start = 0usize;
    let mut current = '\0';
    let mut previous;
    let mut index = 0usize;
    while index < chars.len() {
        previous = current;
        current = chars[index];
        match current {
            '[' => {
                seen_bracket = true;
                if token_start != index {
                    error = true;
                    break;
                }
                depth += 1;
                token_start = index + 1;
            }
            ']' => {
                seen_bracket = true;
                if depth <= 0 {
                    error = true;
                    break;
                }
                if token_start == index && previous != ']' {
                    error = true;
                    break;
                }
                if token_start < index {
                    tokens.push(chars[token_start..index].iter().collect());
                }
                depth -= 1;
                token_start = index + 1;
            }
            _ => {
                if seen_bracket && previous == ']' {
                    error = true;
                    break;
                }
            }
        }
        index += 1;
    }
    if !seen_bracket {
        return Ok(vec![input.to_string()]);
    }
    if depth > 0 {
        error = true;
    }
    if error {
        return Err(EventError::InvalidField {
            reference: input.to_string(),
        });
    }
    Ok(tokens)
}
