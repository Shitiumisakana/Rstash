use std::fmt::{self, Display, Formatter};

/// Failure from the LSCL parser or the imperative compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub message: String,
}

impl ConfigError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Input,
    Filter,
    Output,
    Codec,
}

impl Kind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Kind::Input => "input",
            Kind::Filter => "filter",
            Kind::Output => "output",
            Kind::Codec => "codec",
        }
    }

    pub(crate) fn composes_in_sequence(self) -> bool {
        matches!(self, Kind::Filter)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Arg {
    String(String),
    Int(i64),
    Big(String),
    Float(f64),
    Array(Vec<Arg>),
    Map(Vec<(Key, Arg)>),
    Plugin(Plugin),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Key {
    String(String),
    Int(i64),
    Big(String),
    Float(f64),
}

impl Key {
    pub(crate) fn same(&self, other: &Key) -> bool {
        match (self, other) {
            (Key::String(left), Key::String(right)) => left == right,
            (Key::Int(left), Key::Int(right)) => left == right,
            (Key::Big(left), Key::Big(right)) => left == right,
            (Key::Float(left), Key::Float(right)) => left.to_bits() == right.to_bits(),
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Plugin {
    pub(crate) kind: Kind,
    pub(crate) name: String,
    pub(crate) args: Vec<(String, Arg)>,
    pub(crate) line: usize,
}

#[derive(Debug, Clone)]
pub(crate) enum Expr {
    Event(String),
    Value(Arg),
    Regex(String),
    Eq(Box<Expr>, Box<Expr>),
    Neq(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    Lt(Box<Expr>, Box<Expr>),
    Gte(Box<Expr>, Box<Expr>),
    Lte(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    In(Box<Expr>, Box<Expr>),
    RegexEq(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Truthy(Box<Expr>),
}

impl Expr {
    pub(crate) fn is_boolean(&self) -> bool {
        !matches!(self, Expr::Event(_) | Expr::Value(_) | Expr::Regex(_))
    }

    /// `Expression#toRubyString` from the 9.5.2 IR.
    pub(crate) fn to_ruby(&self) -> String {
        match self {
            Expr::Event(field) => format!("event.getField('{field}')"),
            Expr::Value(value) => value.to_ruby(),
            Expr::Regex(pattern) => pattern.clone(),
            Expr::Eq(left, right) => bin(left, "==", right),
            Expr::Neq(left, right) => bin(left, "!=", right),
            Expr::Gt(left, right) => bin(left, ">", right),
            Expr::Lt(left, right) => bin(left, "<", right),
            Expr::Gte(left, right) => bin(left, ">=", right),
            Expr::Lte(left, right) => bin(left, "<=", right),
            Expr::And(left, right) => bin(left, "&&", right),
            Expr::Or(left, right) => bin(left, "||", right),
            Expr::In(left, right) => bin(left, ".include?", right),
            Expr::RegexEq(left, right) => bin(left, "=~", right),
            Expr::Not(inner) => format!("!({})", inner.to_ruby()),
            // Truthy prints the child with toString. EventValue overrides that;
            // every other expression's toString is toRubyString.
            Expr::Truthy(inner) => format!("({})", inner.to_display()),
        }
    }

    fn to_display(&self) -> String {
        match self {
            Expr::Event(field) => format!("event.get('{field}')"),
            Expr::Regex(pattern) => pattern.clone(),
            other => other.to_ruby(),
        }
    }
}

fn bin(left: &Expr, op: &str, right: &Expr) -> String {
    format!("({}{}{})", left.to_ruby(), op, right.to_ruby())
}

/// `eTruthy`: boolean expressions stay as they are.
pub(crate) fn truthy(expr: Expr) -> Expr {
    if expr.is_boolean() {
        expr
    } else {
        Expr::Truthy(Box::new(expr))
    }
}

impl Arg {
    fn to_ruby(&self) -> String {
        match self {
            Arg::String(value) => format!("'{value}'"),
            Arg::Int(value) => value.to_string(),
            Arg::Big(value) => value.clone(),
            Arg::Float(value) => format_ruby_float(*value),
            Arg::Array(_) | Arg::Map(_) | Arg::Plugin(_) => ruby_inspect_arg(self),
        }
    }
}

pub(crate) fn ruby_inspect_string(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::from("\"");
    for (index, ch) in chars.iter().copied().enumerate() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '#' if matches!(chars.get(index + 1), Some('{' | '$' | '@')) => {
                out.push_str("\\#");
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn ruby_inspect_key(key: &Key) -> String {
    match key {
        Key::String(value) => ruby_inspect_string(value),
        Key::Int(value) => value.to_string(),
        Key::Big(value) => value.clone(),
        Key::Float(value) => format_ruby_float(*value),
    }
}

pub(crate) fn ruby_inspect_arg(value: &Arg) -> String {
    match value {
        Arg::String(text) => ruby_inspect_string(text),
        Arg::Int(number) => number.to_string(),
        Arg::Big(number) => number.clone(),
        Arg::Float(number) => format_ruby_float(*number),
        Arg::Array(items) => {
            let body = items
                .iter()
                .map(ruby_inspect_arg)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{body}]")
        }
        Arg::Map(entries) => inspect_entries(entries),
        Arg::Plugin(plugin) => format!(
            "{}-{}{}",
            plugin.kind.as_str(),
            plugin.name,
            inspect_string_args(&plugin.args)
        ),
    }
}

fn inspect_entries(entries: &[(Key, Arg)]) -> String {
    let body = entries
        .iter()
        .map(|(key, value)| format!("{} => {}", ruby_inspect_key(key), ruby_inspect_arg(value)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{body}}}")
}

pub(crate) fn inspect_string_args(args: &[(String, Arg)]) -> String {
    let body = args
        .iter()
        .map(|(key, value)| {
            format!(
                "{} => {}",
                ruby_inspect_string(key),
                ruby_inspect_arg(value)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{body}}}")
}

pub(crate) fn format_ruby_float(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }
    let text = format!("{value}");
    if text.contains('.') || text.contains('e') || text.contains('E') {
        text
    } else {
        format!("{text}.0")
    }
}

pub(crate) fn ruby_eq(left: &Arg, right: &Arg) -> bool {
    match (left, right) {
        (Arg::String(a), Arg::String(b)) => a == b,
        (Arg::Int(a), Arg::Int(b)) => a == b,
        (Arg::Big(a), Arg::Big(b)) => a == b,
        (Arg::Float(a), Arg::Float(b)) => a.to_bits() == b.to_bits(),
        (Arg::Int(a), Arg::Float(b)) | (Arg::Float(b), Arg::Int(a)) => *b == (*a as f64),
        (Arg::Array(a), Arg::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| ruby_eq(x, y))
        }
        (Arg::Map(a), Arg::Map(b)) => {
            a.len() == b.len()
                && a.iter().all(|(key, value)| {
                    b.iter()
                        .any(|(other, other_value)| key.same(other) && ruby_eq(value, other_value))
                })
        }
        (Arg::Plugin(a), Arg::Plugin(b)) => {
            a.kind == b.kind
                && a.name == b.name
                && a.args.len() == b.args.len()
                && a.args
                    .iter()
                    .zip(&b.args)
                    .all(|((ak, av), (bk, bv))| ak == bk && ruby_eq(av, bv))
        }
        _ => false,
    }
}

/// `Plugin#map_expr_attributes`: hashes merge, arrays concatenate, equal scalars stay.
pub(crate) fn merge_attribute(existing: Arg, incoming: Arg) -> Arg {
    match existing {
        Arg::Map(mut destination) => match incoming {
            Arg::Map(source) => {
                merge_into(&mut destination, source, true);
                Arg::Map(destination)
            }
            other => Arg::Array(vec![Arg::Map(destination), other]),
        },
        Arg::Array(mut items) => {
            match incoming {
                Arg::Array(more) => items.extend(more),
                other => items.push(other),
            }
            Arg::Array(items)
        }
        other if ruby_eq(&other, &incoming) => other,
        other => Arg::Array(vec![other, incoming]),
    }
}

/// `LogStash::Util.hash_merge_with_dups` when `concat_arrays` is true,
/// and `hash_merge` (array union) when it is false. Nested hashes always use union.
fn merge_into(destination: &mut Vec<(Key, Arg)>, source: Vec<(Key, Arg)>, concat_arrays: bool) {
    for (key, incoming) in source {
        if let Some(position) = destination
            .iter()
            .position(|(existing, _)| existing.same(&key))
        {
            let current = destination[position].1.clone();
            destination[position].1 = combine_hash_values(current, incoming, concat_arrays);
        } else {
            destination.push((key, incoming));
        }
    }
}

fn combine_hash_values(current: Arg, incoming: Arg, concat_arrays: bool) -> Arg {
    match (current, incoming) {
        (Arg::Map(mut destination), Arg::Map(source)) => {
            merge_into(&mut destination, source, false);
            Arg::Map(destination)
        }
        (current, Arg::Array(incoming)) => {
            let mut items = match current {
                Arg::Array(items) => items,
                other => vec![other],
            };
            if concat_arrays {
                items.extend(incoming);
            } else {
                for item in incoming {
                    if !items.iter().any(|existing| ruby_eq(existing, &item)) {
                        items.push(item);
                    }
                }
            }
            Arg::Array(items)
        }
        (Arg::Array(mut items), incoming) => {
            if !items.iter().any(|existing| ruby_eq(existing, &incoming)) {
                items.push(incoming);
            }
            Arg::Array(items)
        }
        (current, incoming) => {
            if ruby_eq(&current, &incoming) {
                current
            } else {
                Arg::Array(vec![current, incoming])
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Statement {
    Noop,
    Plugin(Plugin),
    If {
        condition: Expr,
        when_true: Box<Statement>,
        when_false: Box<Statement>,
    },
    Sequence(Vec<Statement>),
    Parallel(Vec<Statement>),
}

impl Statement {
    /// Java `Statement#toString(indent)`. `toString()` starts at indent 2.
    pub(crate) fn render(&self, indent: usize) -> String {
        match self {
            Statement::Noop => format!("{}(Noop)", " ".repeat(indent)),
            Statement::Plugin(plugin) => format!(
                "{}{}-{}{}",
                " ".repeat(indent),
                plugin.kind.as_str(),
                plugin.name,
                inspect_string_args(&plugin.args)
            ),
            Statement::If {
                condition,
                when_true,
                when_false,
            } => format!(
                "{}(if {}\n{}\n{})",
                " ".repeat(indent),
                condition.to_ruby(),
                when_true.render(2),
                when_false.render(2)
            ),
            Statement::Sequence(statements) => render_composed("do-sequence", statements, indent),
            Statement::Parallel(statements) => {
                render_composed("composed-parallel", statements, indent)
            }
        }
    }
}

fn render_composed(label: &str, statements: &[Statement], indent: usize) -> String {
    let body = statements
        .iter()
        .map(|statement| statement.render(indent + 2))
        .collect::<Vec<_>>()
        .join("\n");
    format!("({label}\n{body}\n")
}

/// `DSL.iCompose`: empty is noop, one statement is returned as itself.
pub(crate) fn compose(kind: Kind, statements: Vec<Statement>) -> Statement {
    match statements.len() {
        0 => Statement::Noop,
        1 => statements.into_iter().next().unwrap_or(Statement::Noop),
        _ if kind.composes_in_sequence() => Statement::Sequence(statements),
        _ => Statement::Parallel(statements),
    }
}

#[derive(Debug, Clone)]
pub struct Pipeline {
    pub(crate) input: Statement,
    pub(crate) filter: Statement,
    pub(crate) output: Statement,
}

impl Pipeline {
    pub fn input_text(&self) -> String {
        self.input.render(2)
    }

    pub fn filter_text(&self) -> String {
        self.filter.render(2)
    }

    pub fn output_text(&self) -> String {
        self.output.render(2)
    }
}
