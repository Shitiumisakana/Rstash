use super::model::{
    Arg, ConfigError, Expr, Key, Kind, Pipeline, Plugin, Statement, compose, merge_attribute,
    truthy,
};

pub(crate) fn compile(source: &str, support_escapes: bool) -> Result<Pipeline, ConfigError> {
    let mut parser = Parser::new(source, support_escapes);
    parser.skip_cs();
    let mut input = Vec::new();
    let mut filter = Vec::new();
    let mut output = Vec::new();
    while !parser.eof() {
        let (kind, statements) = parser.parse_section()?;
        match kind {
            Kind::Input => input.extend(statements),
            Kind::Filter => filter.extend(statements),
            Kind::Output => output.extend(statements),
            Kind::Codec => {}
        }
        parser.skip_cs();
    }
    Ok(Pipeline {
        input: compose(Kind::Input, input),
        filter: compose(Kind::Filter, filter),
        output: compose(Kind::Output, output),
    })
}

struct Parser<'a> {
    src: &'a str,
    index: usize,
    escapes: bool,
    max_failure: Option<usize>,
    failures: Vec<String>,
}

#[derive(Clone, Copy)]
enum BoolOp {
    And,
    Or,
    Nand,
    Xor,
}

enum CompareOp {
    Eq,
    Neq,
    Gt,
    Lt,
    Gte,
    Lte,
}

enum Atom {
    Selector(String),
    Expr(Expr),
}

enum RValue {
    Selector(String),
    Expr(Expr),
}

enum Elem {
    Expr(Expr),
    Op(BoolOp),
}

struct Arm {
    cond: Expr,
    body: Vec<Statement>,
}

enum Tail {
    Body(Vec<Statement>),
    Nested(Box<BuiltIf>),
}

struct BuiltIf {
    cond: Expr,
    body: Vec<Statement>,
    tail: Option<Tail>,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str, escapes: bool) -> Self {
        Self {
            src,
            index: 0,
            escapes,
            max_failure: None,
            failures: Vec::new(),
        }
    }

    fn eof(&self) -> bool {
        self.index >= self.src.len()
    }

    fn peek(&self) -> Option<char> {
        self.src[self.index..].chars().next()
    }

    fn bump(&mut self) {
        if let Some(ch) = self.peek() {
            self.index += ch.len_utf8();
        }
    }

    fn starts_with(&self, text: &str) -> bool {
        self.src[self.index..].starts_with(text)
    }

    fn consume_str(&mut self, text: &str) -> bool {
        if self.starts_with(text) {
            self.index += text.len();
            true
        } else {
            false
        }
    }

    fn consume_char(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn consume_keyword(&mut self, word: &str) -> bool {
        if self.starts_with(word) {
            let after = self.index + word.len();
            let boundary = self.src[after..].chars().next();
            if matches!(boundary, Some(ch) if ch.is_ascii_alphanumeric() || ch == '_') {
                return false;
            }
            self.index = after;
            true
        } else {
            false
        }
    }

    fn fail_terminal(&mut self, index: usize, expected: &str) {
        match self.max_failure {
            Some(max) if index < max => {}
            Some(max) if index == max => {
                if !self.failures.iter().any(|existing| existing == expected) {
                    self.failures.push(expected.to_string());
                }
            }
            _ => {
                self.max_failure = Some(index);
                self.failures.clear();
                self.failures.push(expected.to_string());
            }
        }
    }

    fn syntax_error(&self) -> ConfigError {
        let index = self.max_failure.unwrap_or(self.index);
        let expected = match self.failures.as_slice() {
            [] => "value".to_string(),
            [only] => only.clone(),
            many => format!("one of {}", many.join(", ")),
        };
        let (line, column) = line_column(self.src, index);
        let after = if index > 0 {
            format!(" after {}", &self.src[..index])
        } else {
            String::new()
        };
        ConfigError::new(format!(
            "LogStash::ConfigurationError: Expected {expected} at line {line}, column {column} (byte {}){after}",
            index + 1
        ))
    }

    fn consume_whitespace(&mut self) -> bool {
        let start = self.index;
        while matches!(self.peek(), Some(' ' | '\t' | '\r' | '\n')) {
            self.bump();
        }
        self.index != start
    }

    fn consume_newline(&mut self) -> bool {
        self.consume_str("\r\n") || self.consume_char('\n') || self.consume_char('\r')
    }

    /// Comment, then whitespace. A failed comment still records the terminals
    /// treetop reports at the stopping index: the whitespace class, then "#".
    fn try_comment(&mut self) -> bool {
        let start = self.index;
        let _ = self.consume_whitespace();
        if self.consume_char('#') {
            while matches!(self.peek(), Some(ch) if ch != '\n' && ch != '\r') {
                self.bump();
            }
            if self.eof() || self.consume_newline() {
                return true;
            }
        } else {
            self.fail_terminal(self.index, "[ \\t\\r\\n]");
            self.fail_terminal(self.index, "\"#\"");
        }
        self.index = start;
        false
    }

    fn skip_cs(&mut self) {
        loop {
            if self.try_comment() {
                continue;
            }
            if self.consume_whitespace() {
                continue;
            }
            self.fail_terminal(self.index, "[ \\t\\r\\n]");
            break;
        }
    }

    fn parse_section(&mut self) -> Result<(Kind, Vec<Statement>), ConfigError> {
        let kind = if self.consume_keyword("input") {
            Kind::Input
        } else if self.consume_keyword("filter") {
            Kind::Filter
        } else if self.consume_keyword("output") {
            Kind::Output
        } else {
            self.fail_terminal(self.index, "\"input\"");
            self.fail_terminal(self.index, "\"filter\"");
            self.fail_terminal(self.index, "\"output\"");
            return Err(self.syntax_error());
        };
        self.skip_cs();
        if !self.consume_char('{') {
            self.fail_terminal(self.index, "\"{\"");
            return Err(self.syntax_error());
        }
        let mut statements = Vec::new();
        loop {
            self.skip_cs();
            if self.consume_char('}') {
                break;
            }
            if self.eof() {
                self.fail_terminal(self.index, "\"}\"");
                return Err(self.syntax_error());
            }
            statements.push(self.parse_branch_or_plugin(kind)?);
        }
        Ok((kind, statements))
    }

    fn parse_branch_or_plugin(&mut self, kind: Kind) -> Result<Statement, ConfigError> {
        if let Some(statement) = self.parse_branch(kind)? {
            return Ok(statement);
        }
        let plugin = self.parse_plugin(kind)?;
        Ok(Statement::Plugin(plugin))
    }

    fn parse_branch(&mut self, kind: Kind) -> Result<Option<Statement>, ConfigError> {
        if !self.consume_keyword("if") {
            return Ok(None);
        }
        self.skip_cs();
        let cond = self.parse_condition()?;
        self.skip_cs();
        let body = self.parse_block(kind)?;
        let mut elsifs = Vec::new();
        let mut else_body = None;
        loop {
            let save = self.index;
            self.skip_cs();
            if !self.consume_str("else") {
                self.index = save;
                break;
            }
            self.skip_cs();
            if self.consume_keyword("if") {
                self.skip_cs();
                let cond = self.parse_condition()?;
                self.skip_cs();
                let body = self.parse_block(kind)?;
                elsifs.push(Arm { cond, body });
                continue;
            }
            if self.consume_char('{') {
                else_body = Some(self.parse_block_body(kind)?);
                break;
            }
            self.index = save;
            break;
        }
        Ok(Some(compile_if(
            Arm { cond, body },
            elsifs,
            else_body,
            kind,
        )))
    }

    fn parse_block(&mut self, kind: Kind) -> Result<Vec<Statement>, ConfigError> {
        if !self.consume_char('{') {
            self.fail_terminal(self.index, "\"{\"");
            return Err(self.syntax_error());
        }
        self.parse_block_body(kind)
    }

    fn parse_block_body(&mut self, kind: Kind) -> Result<Vec<Statement>, ConfigError> {
        let mut body = Vec::new();
        loop {
            self.skip_cs();
            if self.consume_char('}') {
                break;
            }
            if self.eof() {
                self.fail_terminal(self.index, "\"}\"");
                return Err(self.syntax_error());
            }
            body.push(self.parse_branch_or_plugin(kind)?);
        }
        Ok(body)
    }

    fn parse_plugin(&mut self, kind: Kind) -> Result<Plugin, ConfigError> {
        let start = self.index;
        let Some(name) = self.parse_plugin_name()? else {
            self.fail_terminal(self.index, "plugin name");
            return Err(self.syntax_error());
        };
        let line = line_of(self.src, start);
        self.skip_cs();
        if !self.consume_char('{') {
            self.fail_terminal(self.index, "\"{\"");
            return Err(self.syntax_error());
        }
        let args = self.parse_attributes()?;
        let plugin = Plugin {
            kind,
            name,
            args,
            line,
        };
        check_codecs(&plugin)?;
        Ok(plugin)
    }

    fn try_plugin(&mut self) -> Result<Option<Plugin>, ConfigError> {
        let save = self.index;
        let Some(name) = self.parse_plugin_name()? else {
            return Ok(None);
        };
        let line = line_of(self.src, save);
        self.skip_cs();
        if !self.consume_char('{') {
            self.fail_terminal(self.index, "\"{\"");
            self.index = save;
            return Ok(None);
        }
        let args = self.parse_attributes()?;
        let plugin = Plugin {
            kind: Kind::Codec,
            name,
            args,
            line,
        };
        check_codecs(&plugin)?;
        Ok(Some(plugin))
    }

    fn parse_plugin_name(&mut self) -> Result<Option<String>, ConfigError> {
        if matches!(self.peek(), Some('"' | '\'')) {
            let start = self.index;
            self.parse_quoted()?;
            return Ok(Some(self.src[start..self.index].to_string()));
        }
        Ok(self.consume_while(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
    }

    fn parse_attributes(&mut self) -> Result<Vec<(String, Arg)>, ConfigError> {
        let mut args: Vec<(String, Arg)> = Vec::new();
        loop {
            self.skip_cs();
            if self.peek() == Some('}') || self.eof() {
                break;
            }
            let key = self.parse_attribute_name()?;
            self.skip_cs();
            if !self.consume_str("=>") {
                self.fail_terminal(self.index, "\"=>\"");
                return Err(self.syntax_error());
            }
            self.skip_cs();
            let value = self.parse_value()?;
            if let Some(position) = args.iter().position(|(existing, _)| existing == &key) {
                let current = args[position].1.clone();
                args[position].1 = merge_attribute(current, value);
            } else {
                args.push((key, value));
            }
            let save = self.index;
            if !self.consume_whitespace() {
                break;
            }
            self.skip_cs();
            if self.peek() == Some('}') || self.eof() || !self.looks_like_name() {
                self.index = save;
                break;
            }
        }
        self.skip_cs();
        if !self.consume_char('}') {
            self.fail_terminal(self.index, "\"}\"");
            return Err(self.syntax_error());
        }
        Ok(args)
    }

    fn looks_like_name(&self) -> bool {
        matches!(
            self.peek(),
            Some('"' | '\'' | 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-')
        )
    }

    fn parse_attribute_name(&mut self) -> Result<String, ConfigError> {
        if matches!(self.peek(), Some('"' | '\'')) {
            let raw = self.parse_quoted()?.ok_or_else(|| self.syntax_error())?;
            return Ok(raw[1..raw.len() - 1].to_string());
        }
        if let Some(name) =
            self.consume_while(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        {
            return Ok(name);
        }
        self.fail_terminal(self.index, "attribute");
        Err(self.syntax_error())
    }

    fn parse_value(&mut self) -> Result<Arg, ConfigError> {
        if let Some(plugin) = self.try_plugin()? {
            return Ok(Arg::Plugin(plugin));
        }
        if let Some(word) = self.parse_bareword() {
            return Ok(Arg::String(word));
        }
        if let Some(text) = self.parse_string_value()? {
            return Ok(Arg::String(text));
        }
        if let Some(number) = self.parse_number()? {
            return Ok(number);
        }
        if self.peek() == Some('[') {
            return self.parse_array();
        }
        if self.peek() == Some('{') {
            return self.parse_hash();
        }
        self.fail_terminal(self.index, "value");
        Err(self.syntax_error())
    }

    fn parse_bareword(&mut self) -> Option<String> {
        let start = self.index;
        let ch = self.peek()?;
        if !(ch.is_ascii_alphabetic() || ch == '_') {
            return None;
        }
        self.bump();
        let mut continued = false;
        while matches!(self.peek(), Some(ch) if ch.is_ascii_alphanumeric() || ch == '_') {
            self.bump();
            continued = true;
        }
        if !continued {
            self.fail_terminal(self.index, "[A-Za-z0-9_]");
            self.index = start;
            return None;
        }
        Some(self.src[start..self.index].to_string())
    }

    fn parse_string_value(&mut self) -> Result<Option<String>, ConfigError> {
        let Some(raw) = self.parse_quoted()? else {
            return Ok(None);
        };
        let interior = &raw[1..raw.len() - 1];
        let text = if self.escapes {
            process_escapes(interior)
        } else {
            interior.to_string()
        };
        Ok(Some(text))
    }

    fn parse_quoted(&mut self) -> Result<Option<String>, ConfigError> {
        let Some(quote) = self.peek() else {
            return Ok(None);
        };
        if quote != '"' && quote != '\'' {
            return Ok(None);
        }
        let start = self.index;
        self.bump();
        loop {
            let Some(ch) = self.peek() else {
                let marker = if quote == '"' { "\"\\\"\"" } else { "\"'\"" };
                self.fail_terminal(self.index, marker);
                return Err(self.syntax_error());
            };
            if ch == '\\' {
                self.bump();
                if self.peek() == Some(quote) {
                    self.bump();
                }
                continue;
            }
            if ch == quote {
                self.bump();
                return Ok(Some(self.src[start..self.index].to_string()));
            }
            self.bump();
        }
    }

    fn parse_number(&mut self) -> Result<Option<Arg>, ConfigError> {
        let start = self.index;
        if self.peek() == Some('-') {
            let digits = self.src[self.index + 1..].chars().next();
            if !matches!(digits, Some(ch) if ch.is_ascii_digit()) {
                return Ok(None);
            }
            self.bump();
        }
        if !matches!(self.peek(), Some(ch) if ch.is_ascii_digit()) {
            self.index = start;
            return Ok(None);
        }
        while matches!(self.peek(), Some(ch) if ch.is_ascii_digit()) {
            self.bump();
        }
        let mut is_float = false;
        if self.peek() == Some('.') {
            is_float = true;
            self.bump();
            while matches!(self.peek(), Some(ch) if ch.is_ascii_digit()) {
                self.bump();
            }
        }
        let token = &self.src[start..self.index];
        if is_float {
            if token.ends_with('.') {
                return Err(ConfigError::new(format!(
                    "ArgumentError: invalid value for Float(): \"{token}\""
                )));
            }
            let value = token.parse::<f64>().map_err(|_| {
                ConfigError::new(format!(
                    "ArgumentError: invalid value for Float(): \"{token}\""
                ))
            })?;
            Ok(Some(Arg::Float(value)))
        } else {
            Ok(Some(integer_arg(token)))
        }
    }

    fn parse_array(&mut self) -> Result<Arg, ConfigError> {
        if !self.consume_char('[') {
            self.fail_terminal(self.index, "\"[\"");
            return Err(self.syntax_error());
        }
        self.skip_cs();
        let mut items = Vec::new();
        if self.peek() != Some(']') {
            items.push(self.parse_value()?);
            loop {
                let save = self.index;
                self.skip_cs();
                if self.consume_char(',') {
                    self.skip_cs();
                    items.push(self.parse_value()?);
                } else {
                    self.index = save;
                    break;
                }
            }
            self.skip_cs();
        }
        if !self.consume_char(']') {
            self.fail_terminal(self.index, "\"]\"");
            return Err(self.syntax_error());
        }
        Ok(Arg::Array(items))
    }

    fn parse_hash(&mut self) -> Result<Arg, ConfigError> {
        let start = self.index;
        if !self.consume_char('{') {
            self.fail_terminal(self.index, "\"{\"");
            return Err(self.syntax_error());
        }
        let mut raw_keys = Vec::new();
        let mut entries: Vec<(Key, Arg)> = Vec::new();
        loop {
            self.skip_cs();
            if self.peek() == Some('}') || self.eof() {
                break;
            }
            let (raw, key) = self.parse_hash_key()?;
            self.skip_cs();
            if !self.consume_str("=>") {
                self.fail_terminal(self.index, "\"=>\"");
                return Err(self.syntax_error());
            }
            self.skip_cs();
            let value = self.parse_value()?;
            if let Some(position) = entries.iter().position(|(existing, _)| existing.same(&key)) {
                entries[position].1 = value;
            } else {
                entries.push((key, value));
            }
            raw_keys.push(raw);
        }
        let duplicates = duplicate_keys(&raw_keys);
        if !duplicates.is_empty() {
            return Err(duplicate_key_error(self.src, start, &duplicates));
        }
        if !self.consume_char('}') {
            self.fail_terminal(self.index, "\"}\"");
            return Err(self.syntax_error());
        }
        Ok(Arg::Map(entries))
    }

    fn parse_hash_key(&mut self) -> Result<(String, Key), ConfigError> {
        let start = self.index;
        if let Some(number) = self.parse_number()? {
            let raw = self.src[start..self.index].to_string();
            let key = match number {
                Arg::Int(value) => Key::Int(value),
                Arg::Big(value) => Key::Big(value),
                Arg::Float(value) => Key::Float(value),
                _ => {
                    return Err(ConfigError::new(
                        "ArgumentError: hash key was not a number".to_string(),
                    ));
                }
            };
            return Ok((raw, key));
        }
        if let Some(word) = self.parse_bareword() {
            return Ok((word.clone(), Key::String(word)));
        }
        if let Some(text) = self.parse_string_value()? {
            let raw = self.src[start..self.index].to_string();
            return Ok((raw, Key::String(text)));
        }
        Err(self.syntax_error())
    }

    fn parse_condition(&mut self) -> Result<Expr, ConfigError> {
        let mut atoms = vec![self.parse_atom()?];
        let mut ops = Vec::new();
        loop {
            let save = self.index;
            self.skip_cs();
            if let Some(op) = self.match_bool_op() {
                ops.push(op);
                self.skip_cs();
                atoms.push(self.parse_atom()?);
            } else {
                self.index = save;
                break;
            }
        }
        finish_condition(atoms, ops)
    }

    fn match_bool_op(&mut self) -> Option<BoolOp> {
        if self.consume_keyword("nand") {
            Some(BoolOp::Nand)
        } else if self.consume_keyword("xor") {
            Some(BoolOp::Xor)
        } else if self.consume_keyword("and") {
            Some(BoolOp::And)
        } else if self.consume_keyword("or") {
            Some(BoolOp::Or)
        } else {
            None
        }
    }

    fn parse_atom(&mut self) -> Result<Atom, ConfigError> {
        if self.consume_char('(') {
            self.skip_cs();
            let inner = self.parse_condition()?;
            self.skip_cs();
            if !self.consume_char(')') {
                self.fail_terminal(self.index, "\")\"");
                return Err(self.syntax_error());
            }
            return Ok(Atom::Expr(inner));
        }
        if self.consume_char('!') {
            self.skip_cs();
            if self.consume_char('(') {
                self.skip_cs();
                let inner = self.parse_condition()?;
                self.skip_cs();
                if !self.consume_char(')') {
                    self.fail_terminal(self.index, "\")\"");
                    return Err(self.syntax_error());
                }
                return Ok(Atom::Expr(Expr::Not(Box::new(inner))));
            }
            if let Some(field) = self.parse_selector() {
                return Ok(Atom::Expr(Expr::Not(Box::new(Expr::Event(field)))));
            }
            self.fail_terminal(self.index, "selector");
            return Err(self.syntax_error());
        }
        if let Some(expr) = self.try_in()? {
            return Ok(Atom::Expr(expr));
        }
        if let Some(expr) = self.try_not_in()? {
            return Ok(Atom::Expr(expr));
        }
        if let Some(expr) = self.try_compare()? {
            return Ok(Atom::Expr(expr));
        }
        if let Some(expr) = self.try_regexp()? {
            return Ok(Atom::Expr(expr));
        }
        match self.parse_rvalue()? {
            Some(RValue::Selector(field)) => Ok(Atom::Selector(field)),
            Some(RValue::Expr(expr)) => Ok(Atom::Expr(expr)),
            None => {
                self.fail_terminal(self.index, "expression");
                Err(self.syntax_error())
            }
        }
    }

    fn try_in(&mut self) -> Result<Option<Expr>, ConfigError> {
        let save = self.index;
        let Some(left) = self.parse_rvalue_expr()? else {
            return Ok(None);
        };
        self.skip_cs();
        if !self.consume_keyword("in") {
            self.index = save;
            return Ok(None);
        }
        self.skip_cs();
        let Some(right) = self.parse_rvalue_expr()? else {
            self.index = save;
            return Ok(None);
        };
        Ok(Some(Expr::In(Box::new(left), Box::new(right))))
    }

    fn try_not_in(&mut self) -> Result<Option<Expr>, ConfigError> {
        let save = self.index;
        let Some(left) = self.parse_rvalue_expr()? else {
            return Ok(None);
        };
        self.skip_cs();
        if !self.consume_str("not ") {
            self.index = save;
            return Ok(None);
        }
        self.skip_cs();
        if !self.consume_keyword("in") {
            self.index = save;
            return Ok(None);
        }
        self.skip_cs();
        let Some(right) = self.parse_rvalue_expr()? else {
            self.index = save;
            return Ok(None);
        };
        Ok(Some(Expr::Not(Box::new(Expr::In(
            Box::new(left),
            Box::new(right),
        )))))
    }

    fn try_compare(&mut self) -> Result<Option<Expr>, ConfigError> {
        let save = self.index;
        let Some(left) = self.parse_rvalue_expr()? else {
            return Ok(None);
        };
        self.skip_cs();
        let Some(op) = self.match_compare() else {
            self.index = save;
            return Ok(None);
        };
        self.skip_cs();
        let Some(right) = self.parse_rvalue_expr()? else {
            self.index = save;
            return Ok(None);
        };
        Ok(Some(apply_compare(op, left, right)))
    }

    fn match_compare(&mut self) -> Option<CompareOp> {
        if self.consume_str("==") {
            Some(CompareOp::Eq)
        } else if self.consume_str("!=") {
            Some(CompareOp::Neq)
        } else if self.consume_str("<=") {
            Some(CompareOp::Lte)
        } else if self.consume_str(">=") {
            Some(CompareOp::Gte)
        } else if self.consume_str("<") {
            Some(CompareOp::Lt)
        } else if self.consume_str(">") {
            Some(CompareOp::Gt)
        } else {
            None
        }
    }

    fn try_regexp(&mut self) -> Result<Option<Expr>, ConfigError> {
        let save = self.index;
        let Some(left) = self.parse_rvalue_expr()? else {
            return Ok(None);
        };
        self.skip_cs();
        let negated = if self.consume_str("!~") {
            true
        } else if self.consume_str("=~") {
            false
        } else {
            self.index = save;
            return Ok(None);
        };
        self.skip_cs();
        let pattern = if let Some(pattern) = self.parse_regexp_literal() {
            pattern
        } else if let Some(text) = self.parse_string_value()? {
            text
        } else {
            self.index = save;
            return Ok(None);
        };
        if !matches!(left, Expr::Event(_)) {
            return Err(ConfigError::new(
                "Expected a selector in regexp expression!".to_string(),
            ));
        }
        let compared = Expr::RegexEq(Box::new(left), Box::new(Expr::Regex(pattern)));
        Ok(Some(if negated {
            Expr::Not(Box::new(compared))
        } else {
            compared
        }))
    }

    fn parse_rvalue_expr(&mut self) -> Result<Option<Expr>, ConfigError> {
        match self.parse_rvalue()? {
            Some(RValue::Selector(field)) => Ok(Some(Expr::Event(field))),
            Some(RValue::Expr(expr)) => Ok(Some(expr)),
            None => Ok(None),
        }
    }

    fn parse_rvalue(&mut self) -> Result<Option<RValue>, ConfigError> {
        if let Some(text) = self.parse_string_value()? {
            return Ok(Some(RValue::Expr(Expr::Value(Arg::String(text)))));
        }
        if let Some(number) = self.parse_number()? {
            return Ok(Some(RValue::Expr(Expr::Value(number))));
        }
        if let Some(field) = self.parse_selector() {
            return Ok(Some(RValue::Selector(field)));
        }
        if self.peek() == Some('[') {
            return Ok(Some(RValue::Expr(Expr::Value(self.parse_array()?))));
        }
        if let Some(expr) = self.parse_method()? {
            return Ok(Some(RValue::Expr(expr)));
        }
        if let Some(pattern) = self.parse_regexp_literal() {
            return Ok(Some(RValue::Expr(Expr::Regex(pattern))));
        }
        Ok(None)
    }

    fn parse_selector(&mut self) -> Option<String> {
        let start = self.index;
        if self.peek() != Some('[') {
            return None;
        }
        while self.peek() == Some('[') {
            self.bump();
            let content = self.index;
            while matches!(self.peek(), Some(ch) if ch != ']' && ch != '[' && ch != ',') {
                self.bump();
            }
            if self.index == content || !self.consume_char(']') {
                self.index = start;
                return None;
            }
        }
        Some(self.src[start..self.index].to_string())
    }

    /// `length([field])` is not implemented in 9.5.2. The compiler's expression
    /// walk still returns the single selector inside the call.
    fn parse_method(&mut self) -> Result<Option<Expr>, ConfigError> {
        let save = self.index;
        if self.parse_bareword().is_none() {
            return Ok(None);
        }
        self.skip_cs();
        if !self.consume_char('(') {
            self.index = save;
            return Ok(None);
        }
        self.skip_cs();
        let mut selectors = Vec::new();
        if self.peek() != Some(')') {
            loop {
                match self.parse_rvalue()? {
                    Some(RValue::Selector(field)) => selectors.push(field),
                    Some(RValue::Expr(Expr::Event(field))) => selectors.push(field),
                    Some(_) => {}
                    None => {
                        self.fail_terminal(self.index, "rvalue");
                        return Err(self.syntax_error());
                    }
                }
                self.skip_cs();
                if self.consume_char(',') {
                    self.skip_cs();
                    continue;
                }
                break;
            }
        }
        if !self.consume_char(')') {
            self.fail_terminal(self.index, "\")\"");
            return Err(self.syntax_error());
        }
        if selectors.len() == 1 {
            Ok(Some(Expr::Event(selectors.remove(0))))
        } else {
            Err(ConfigError::new(
                "Exprs should only have one part!".to_string(),
            ))
        }
    }

    fn parse_regexp_literal(&mut self) -> Option<String> {
        if self.peek() != Some('/') {
            return None;
        }
        let start = self.index;
        self.bump();
        while let Some(ch) = self.peek() {
            if ch == '\\' {
                self.bump();
                if self.peek() == Some('/') {
                    self.bump();
                }
                continue;
            }
            if ch == '/' {
                self.bump();
                return Some(self.src[start + 1..self.index - 1].to_string());
            }
            self.bump();
        }
        self.index = start;
        None
    }

    fn consume_while(&mut self, class: impl Fn(char) -> bool) -> Option<String> {
        let start = self.index;
        while matches!(self.peek(), Some(ch) if class(ch)) {
            self.bump();
        }
        if self.index == start {
            None
        } else {
            Some(self.src[start..self.index].to_string())
        }
    }
}

fn finish_condition(atoms: Vec<Atom>, ops: Vec<BoolOp>) -> Result<Expr, ConfigError> {
    if ops.is_empty() {
        return Ok(
            match atoms
                .into_iter()
                .next()
                .unwrap_or(Atom::Expr(Expr::Value(Arg::String(String::new()))))
            {
                Atom::Selector(field) => Expr::Truthy(Box::new(Expr::Event(field))),
                Atom::Expr(expr) => expr,
            },
        );
    }
    let mut elements = Vec::new();
    for (offset, atom) in atoms.into_iter().enumerate() {
        if offset > 0 {
            elements.push(Elem::Op(ops[offset - 1]));
        }
        elements.push(Elem::Expr(match atom {
            Atom::Selector(field) => Expr::Event(field),
            Atom::Expr(expr) => expr,
        }));
    }
    join_conditions(elements)
}

/// `Condition#join_conditions`: pop only when the previous operator has
/// strictly greater precedence, so equal operators stay right-associative.
fn join_conditions(elements: Vec<Elem>) -> Result<Expr, ConfigError> {
    let mut out = Vec::new();
    let mut operators = Vec::new();
    for element in elements {
        match element {
            Elem::Op(op) => {
                if let Some(previous) = operators.last().copied()
                    && precedence(previous)? > precedence(op)?
                    && let Some(popped) = operators.pop()
                {
                    out.push(Elem::Op(popped));
                }
                operators.push(op);
            }
            expr => out.push(expr),
        }
    }
    for op in operators.into_iter().rev() {
        out.push(Elem::Op(op));
    }
    let mut pending = out;
    pending.reverse();
    let mut stack = Vec::new();
    while let Some(element) = pending.pop() {
        match element {
            Elem::Op(op) => {
                let right = stack.pop().ok_or_else(|| {
                    ConfigError::new("ArgumentError: boolean expression is incomplete".to_string())
                })?;
                let left = stack.pop().ok_or_else(|| {
                    ConfigError::new("ArgumentError: boolean expression is incomplete".to_string())
                })?;
                stack.push(apply_bool(op, left, right));
            }
            Elem::Expr(expr) => stack.push(expr),
        }
    }
    stack
        .pop()
        .ok_or_else(|| ConfigError::new("ArgumentError: boolean expression is empty".to_string()))
}

fn precedence(op: BoolOp) -> Result<u8, ConfigError> {
    match op {
        BoolOp::And => Ok(2),
        BoolOp::Or => Ok(1),
        BoolOp::Nand => Err(ConfigError::new(
            "ArgumentError: Unexpected operator nand".to_string(),
        )),
        BoolOp::Xor => Err(ConfigError::new(
            "ArgumentError: Unexpected operator xor".to_string(),
        )),
    }
}

fn apply_compare(op: CompareOp, left: Expr, right: Expr) -> Expr {
    match op {
        CompareOp::Eq => Expr::Eq(Box::new(left), Box::new(right)),
        CompareOp::Neq => Expr::Neq(Box::new(left), Box::new(right)),
        CompareOp::Gt => Expr::Gt(Box::new(left), Box::new(right)),
        CompareOp::Lt => Expr::Lt(Box::new(left), Box::new(right)),
        CompareOp::Gte => Expr::Gte(Box::new(left), Box::new(right)),
        CompareOp::Lte => Expr::Lte(Box::new(left), Box::new(right)),
    }
}

fn apply_bool(op: BoolOp, left: Expr, right: Expr) -> Expr {
    match op {
        BoolOp::And => Expr::And(Box::new(left), Box::new(right)),
        BoolOp::Or => Expr::Or(Box::new(left), Box::new(right)),
        BoolOp::Nand => Expr::Not(Box::new(Expr::And(Box::new(left), Box::new(right)))),
        BoolOp::Xor => {
            let neither = Expr::And(
                Box::new(Expr::Not(Box::new(left.clone()))),
                Box::new(right.clone()),
            );
            let only_left = Expr::And(Box::new(left), Box::new(Expr::Not(Box::new(right))));
            Expr::Or(Box::new(neither), Box::new(only_left))
        }
    }
}

fn compile_if(
    first: Arm,
    elsifs: Vec<Arm>,
    else_body: Option<Vec<Statement>>,
    kind: Kind,
) -> Statement {
    let mut nodes: Vec<BuiltIf> = elsifs
        .into_iter()
        .map(|arm| BuiltIf {
            cond: arm.cond,
            body: arm.body,
            tail: None,
        })
        .collect();
    if let Some(body) = else_body {
        if let Some(last) = nodes.last_mut() {
            last.tail = Some(Tail::Body(body));
        } else {
            return lower_if(
                BuiltIf {
                    cond: first.cond,
                    body: first.body,
                    tail: Some(Tail::Body(body)),
                },
                kind,
            );
        }
    }
    while nodes.len() >= 2 {
        if let Some(later) = nodes.pop()
            && let Some(earlier) = nodes.last_mut()
        {
            earlier.tail = Some(Tail::Nested(Box::new(later)));
        }
    }
    let tail = nodes.pop().map(|node| Tail::Nested(Box::new(node)));
    lower_if(
        BuiltIf {
            cond: first.cond,
            body: first.body,
            tail,
        },
        kind,
    )
}

fn lower_if(node: BuiltIf, kind: Kind) -> Statement {
    let when_true = compose(kind, node.body);
    let when_false = match node.tail {
        Some(Tail::Body(body)) => compose(kind, body),
        Some(Tail::Nested(inner)) => lower_if(*inner, kind),
        None => Statement::Noop,
    };
    Statement::If {
        condition: truthy(node.cond),
        when_true: Box::new(when_true),
        when_false: Box::new(when_false),
    }
}

fn check_codecs(plugin: &Plugin) -> Result<(), ConfigError> {
    if !matches!(plugin.kind, Kind::Input | Kind::Output) {
        return Ok(());
    }
    let multiple = plugin
        .args
        .iter()
        .any(|(key, value)| key == "codec" && matches!(value, Arg::Array(_)));
    if multiple {
        return Err(ConfigError::new(format!(
            "LogStash::ConfigurationError: The {} plugin {} at line {} has multiple `codec` declarations - this is not a valid configuration, only one top-level `codec` per {} plugin is supported.",
            plugin.kind.as_str(),
            plugin.name,
            plugin.line,
            plugin.kind.as_str()
        )));
    }
    Ok(())
}

fn duplicate_keys(keys: &[String]) -> Vec<String> {
    let mut duplicates = Vec::new();
    for key in keys {
        if keys.iter().filter(|other| *other == key).count() > 1
            && !duplicates.iter().any(|existing| existing == key)
        {
            duplicates.push(key.clone());
        }
    }
    duplicates
}

fn duplicate_key_error(source: &str, brace: usize, keys: &[String]) -> ConfigError {
    let (line, column) = line_column(source, brace);
    let after = &source[..=brace.min(source.len().saturating_sub(1))];
    ConfigError::new(format!(
        "LogStash::ConfigurationError: Duplicate keys found in your configuration: [{}]\nAt line: {line}, column {column} (byte {})\nafter {after}",
        keys.join(", "),
        brace + 1
    ))
}

fn integer_arg(token: &str) -> Arg {
    let canonical = canonical_integer(token);
    match canonical.parse::<i64>() {
        Ok(value) => Arg::Int(value),
        Err(_) => Arg::Big(canonical),
    }
}

fn canonical_integer(token: &str) -> String {
    let (negative, digits) = if let Some(rest) = token.strip_prefix('-') {
        (true, rest)
    } else {
        (false, token)
    };
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        "0".to_string()
    } else if negative {
        format!("-{digits}")
    } else {
        digits.to_string()
    }
}

fn process_escapes(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\\' && index + 1 < chars.len() {
            match chars[index + 1] {
                '"' | '\'' | '\\' => out.push(chars[index + 1]),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '0' => out.push('\0'),
                other => {
                    out.push('\\');
                    out.push(other);
                }
            }
            index += 2;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

fn line_of(source: &str, index: usize) -> usize {
    source[..index.min(source.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn line_column(source: &str, index: usize) -> (usize, usize) {
    let index = index.min(source.len());
    let prefix = &source[..index];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = match prefix.rfind('\n') {
        Some(position) => source[position + 1..index].chars().count() + 1,
        None => prefix.chars().count() + 1,
    };
    (line, column)
}
