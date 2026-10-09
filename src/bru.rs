use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct Document {
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub name: String,
    pub content: String,
    pub line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pair {
    pub key: String,
    pub value: String,
    pub enabled: bool,
    pub is_list: bool,
}

impl Document {
    /// Parse a Bruno v2 document without interpreting its executable blocks.
    pub fn parse(source: &str) -> Result<Self> {
        let mut blocks = Vec::new();
        let mut lines = source.trim_start_matches('\u{feff}').lines().enumerate();
        while let Some((index, line)) = lines.next() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }
            let Some(name) = trimmed.strip_suffix('{').map(str::trim) else {
                return Err(parse_error(
                    index + 1,
                    "expected a block name followed by '{'",
                ));
            };
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_'))
            {
                return Err(parse_error(index + 1, "invalid block name"));
            }
            let mut content = Vec::new();
            let mut closed = false;
            // Bruno v2 terminates blocks at a closing brace in column one.
            for (_, inner) in lines.by_ref() {
                if inner.trim_end() == "}" {
                    closed = true;
                    break;
                }
                content.push(inner);
            }
            if !closed {
                return Err(parse_error(index + 1, format!("unclosed '{name}' block")));
            }
            if blocks.iter().any(|block: &Block| block.name == name)
                && !matches!(name, "example" | "body:ws" | "body:grpc")
            {
                return Err(parse_error(index + 1, format!("duplicate '{name}' block")));
            }
            blocks.push(Block {
                name: name.to_owned(),
                content: outdent(&content),
                line: index + 1,
            });
        }
        Ok(Self { blocks })
    }

    pub fn block(&self, name: &str) -> Option<&Block> {
        self.blocks.iter().find(|block| block.name == name)
    }

    pub fn pairs(&self, name: &str) -> Result<Vec<Pair>> {
        self.block(name)
            .map_or_else(|| Ok(Vec::new()), Block::pairs)
    }

    pub fn value(&self, block: &str, key: &str) -> Result<Option<String>> {
        let pairs = self.pairs(block)?;
        Ok(pairs
            .into_iter()
            .rev()
            .find(|pair| pair.enabled && pair.key == key)
            .map(|pair| pair.value))
    }
}

impl Block {
    pub fn pairs(&self) -> Result<Vec<Pair>> {
        let mut pairs = Vec::new();
        let mut lines = self.content.lines().enumerate();
        while let Some((index, line)) = lines.next() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if line.starts_with('@') && !line.contains(':') {
                return Err(Error::Unsupported {
                    feature: "dictionary annotations".into(),
                });
            }
            let enabled = !line.starts_with('~');
            let entry = line.strip_prefix('~').unwrap_or(line);
            let mut quoted = false;
            let mut escaped = false;
            let mut separator = None;
            for (offset, ch) in entry.char_indices() {
                if ch == ':' && !quoted {
                    separator = Some(offset);
                    break;
                }
                if ch == '"' && !escaped {
                    quoted = !quoted;
                }
                escaped = ch == '\\' && !escaped;
            }
            let Some(separator) = separator else {
                return Err(parse_error(
                    self.line + index + 1,
                    "expected a key and value separated by ':'",
                ));
            };
            let raw_key = entry[..separator].trim();
            let key = if raw_key.starts_with('"') {
                serde_json::from_str::<String>(raw_key)
                    .map_err(|_| parse_error(self.line + index + 1, "invalid quoted key"))?
            } else {
                raw_key.to_owned()
            };
            if key.is_empty() {
                return Err(parse_error(self.line + index + 1, "empty key"));
            }
            let raw_value = entry[separator + 1..].trim();
            let is_list = raw_value == "[";
            let value = if raw_value == "[" {
                let mut items = Vec::new();
                let mut closed = false;
                for (_, item) in lines.by_ref() {
                    if item.trim() == "]" {
                        closed = true;
                        break;
                    }
                    items.push(item.trim().to_owned());
                }
                if !closed {
                    return Err(parse_error(self.line + index + 1, "unclosed list"));
                }
                items.join("\n")
            } else if let Some(rest) = raw_value.strip_prefix("'''") {
                if let Some((value, suffix)) = rest.split_once("'''") {
                    append_annotation(value, suffix, self.line + index + 1)?
                } else {
                    let mut items = Vec::new();
                    if !rest.is_empty() {
                        items.push(rest.to_owned());
                    }
                    let mut closed = false;
                    for (_, item) in lines.by_ref() {
                        if let Some((last, suffix)) = item.split_once("'''") {
                            if !last.trim().is_empty() {
                                items.push(last.to_owned());
                            }
                            let value = append_annotation(
                                &items.join("\n"),
                                suffix,
                                self.line + index + 1,
                            )?;
                            items = vec![value];
                            closed = true;
                            break;
                        }
                        items.push(item.to_owned());
                    }
                    if !closed {
                        return Err(parse_error(
                            self.line + index + 1,
                            "unclosed multiline value",
                        ));
                    }
                    items.join("\n")
                }
            } else {
                raw_value.to_owned()
            };
            pairs.push(Pair {
                key,
                value,
                enabled,
                is_list,
            });
        }
        Ok(pairs)
    }
}

fn append_annotation(value: &str, suffix: &str, line: usize) -> Result<String> {
    let suffix = suffix.trim();
    if suffix.is_empty() {
        return Ok(value.to_owned());
    }
    if suffix.starts_with("@contentType(") && suffix.ends_with(')') {
        return Ok(format!("{value} {suffix}"));
    }
    Err(parse_error(line, "unexpected text after a multiline value"))
}

fn outdent(lines: &[&str]) -> String {
    let width = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.bytes()
                .take_while(|ch| matches!(ch, b' ' | b'\t'))
                .count()
        })
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|line| line.get(width..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_error(line: usize, reason: impl Into<String>) -> Error {
    Error::Parse {
        line,
        reason: reason.into(),
    }
}
