use serde_json::Value;

use crate::{Error, Result, engine::Response};

pub(crate) enum Selector {
    Status,
    Time,
    Body(Vec<Segment>),
    Header(String),
}

pub(crate) enum Segment {
    Key(String),
    Index(usize),
}

impl Selector {
    pub(crate) fn parse(expression: &str) -> Result<Self> {
        let expression = expression
            .trim()
            .strip_prefix('$')
            .unwrap_or(expression.trim());
        match expression {
            "res.status" => return Ok(Self::Status),
            "res.responseTime" => return Ok(Self::Time),
            "res.body" => return Ok(Self::Body(Vec::new())),
            _ => {}
        }
        if let Some(header) = expression.strip_prefix("res.headers.") {
            reqwest::header::HeaderName::from_bytes(header.as_bytes())
                .map_err(|_| unsupported(expression))?;
            return Ok(Self::Header(header.to_ascii_lowercase()));
        }
        let mut remainder = expression
            .strip_prefix("res.body")
            .ok_or_else(|| unsupported(expression))?;
        let mut path = Vec::new();
        while !remainder.is_empty() {
            if let Some(rest) = remainder.strip_prefix('.') {
                let end = rest.find(['.', '[']).unwrap_or(rest.len());
                let key = &rest[..end];
                if key.is_empty()
                    || !key
                        .chars()
                        .all(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '-' | '$'))
                {
                    return Err(unsupported(expression));
                }
                if let Ok(index) = key.parse::<usize>() {
                    path.push(Segment::Index(index));
                } else {
                    path.push(Segment::Key(key.to_owned()));
                }
                remainder = &rest[end..];
            } else if let Some(rest) = remainder.strip_prefix('[') {
                let mut quoted = false;
                let mut escaped = false;
                let mut end = None;
                for (offset, ch) in rest.char_indices() {
                    if ch == '"' && !escaped {
                        quoted = !quoted;
                    }
                    if ch == ']' && !quoted {
                        end = Some(offset);
                        break;
                    }
                    escaped = ch == '\\' && !escaped;
                }
                let end = end.ok_or_else(|| unsupported(expression))?;
                let key = rest[..end].trim();
                if key.starts_with('"') {
                    let key =
                        serde_json::from_str::<String>(key).map_err(|_| unsupported(expression))?;
                    path.push(Segment::Key(key));
                } else {
                    let index = key.parse::<usize>().map_err(|_| unsupported(expression))?;
                    path.push(Segment::Index(index));
                }
                remainder = &rest[end + 1..];
            } else {
                return Err(unsupported(expression));
            }
        }
        Ok(Self::Body(path))
    }

    pub(crate) fn read(&self, response: &Response) -> Option<String> {
        match self {
            Self::Status => Some(response.status.to_string()),
            Self::Time => Some(response.elapsed_ms.to_string()),
            Self::Header(header) => response.headers.get(header).cloned(),
            Self::Body(path) if path.is_empty() => Some(response.body.clone()),
            Self::Body(path) => {
                let body = serde_json::from_str::<Value>(&response.body).ok()?;
                let mut current = &body;
                for segment in path {
                    current = match segment {
                        Segment::Key(key) => current.get(key)?,
                        Segment::Index(index) => current.get(*index)?,
                    };
                }
                Some(
                    current
                        .as_str()
                        .map_or_else(|| current.to_string(), str::to_owned),
                )
            }
        }
    }
}

fn unsupported(expression: &str) -> Error {
    Error::Unsupported {
        feature: format!("response selector '{expression}'"),
    }
}
