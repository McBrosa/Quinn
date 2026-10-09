use std::ops::Range;

use crate::{
    Error, Result,
    bru::{Block, Document, Pair},
};

/// Replace dictionary entries without rewriting untouched entries or other blocks.
pub fn replace_pairs(source: &str, name: &str, pairs: &[Pair]) -> Result<String> {
    let document = Document::parse(source)?;
    let old = document.pairs(name)?;
    if old == pairs {
        return Ok(source.to_owned());
    }
    let Some(block) = document.block(name) else {
        let content = pairs
            .iter()
            .map(encode_pair)
            .collect::<Result<Vec<_>>>()?
            .join("");
        let result = replace_block(source, name, Some(&content))?;
        if Document::parse(&result)?.pairs(name)? != pairs {
            return Err(invalid(
                "cannot represent these dictionary values; edit Source instead",
            ));
        }
        return Ok(result);
    };
    let span = block_span(source, block)?;
    let content_start = source[span.clone()]
        .find('\n')
        .map(|offset| span.start + offset + 1)
        .ok_or_else(|| invalid("cannot locate block contents"))?;
    let content_end = source[..span.end]
        .rfind('}')
        .ok_or_else(|| invalid("cannot locate block end"))?;
    let raw = &source[content_start..content_end];
    let spans = pair_spans(raw, block)?;
    let mut content = String::new();
    let mut cursor = 0;
    for (index, span) in spans.iter().enumerate() {
        content.push_str(&raw[cursor..span.start]);
        if let Some(pair) = pairs.get(index) {
            if old.get(index) == Some(pair) {
                content.push_str(&raw[span.clone()]);
            } else {
                content.push_str(&encode_pair(pair)?);
            }
        }
        cursor = span.end;
    }
    content.push_str(&raw[cursor..]);
    for pair in pairs.iter().skip(spans.len()) {
        content.push_str(&encode_pair(pair)?);
    }
    let mut result = source.to_owned();
    result.replace_range(content_start..content_end, &content);
    if Document::parse(&result)?.pairs(name)? != pairs {
        return Err(invalid(
            "cannot represent these dictionary values; edit Source instead",
        ));
    }
    Ok(result)
}

/// Change one field while retaining all other dictionary fields.
pub fn set_value(source: &str, block: &str, key: &str, value: &str) -> Result<String> {
    let mut pairs = Document::parse(source)?.pairs(block)?;
    if let Some(pair) = pairs
        .iter_mut()
        .rev()
        .find(|pair| pair.key == key && pair.enabled)
    {
        pair.value = value.to_owned();
        pair.is_list = false;
    } else {
        pairs.push(Pair {
            key: key.to_owned(),
            value: value.to_owned(),
            enabled: true,
            is_list: false,
        });
    }
    replace_pairs(source, block, &pairs)
}

/// Rename a block without changing its contents.
pub fn rename_block(source: &str, old: &str, new: &str) -> Result<String> {
    let document = Document::parse(source)?;
    let block = document
        .block(old)
        .ok_or_else(|| invalid("cannot locate request block"))?;
    let span = block_span(source, block)?;
    let line_end = source[span.clone()]
        .find('\n')
        .map(|offset| span.start + offset)
        .unwrap_or(span.end);
    let mut result = source.to_owned();
    let bom = if source[span.clone()].starts_with('\u{feff}') {
        "\u{feff}"
    } else {
        ""
    };
    result.replace_range(span.start..line_end, &format!("{bom}{new} {{"));
    Document::parse(&result)?;
    Ok(result)
}

/// Replace or remove one block, preserving every other byte of the document.
pub fn replace_block(source: &str, name: &str, content: Option<&str>) -> Result<String> {
    let document = Document::parse(source)?;
    let replacement = content
        .map(|content| {
            let mut block = format!("{name} {{\n");
            for line in content.lines() {
                block.push_str("  ");
                block.push_str(line);
                block.push('\n');
            }
            block.push_str("}\n");
            block
        })
        .unwrap_or_default();
    let mut result = source.to_owned();
    if let Some(block) = document.block(name) {
        let span = block_span(source, block)?;
        let replacement = if source[span.clone()].starts_with('\u{feff}') {
            format!("\u{feff}{replacement}")
        } else {
            replacement
        };
        result.replace_range(span, &replacement);
    } else if content.is_some() {
        if !result.is_empty() && !result.ends_with('\n') {
            result.push('\n');
        }
        result.push('\n');
        result.push_str(&replacement);
    }
    Document::parse(&result)?;
    Ok(result)
}

fn block_span(source: &str, block: &Block) -> Result<Range<usize>> {
    let mut offset = 0;
    let mut start = None;
    for (index, line) in source.split_inclusive('\n').enumerate() {
        if index + 1 == block.line {
            start = Some(offset);
        }
        offset += line.len();
        if let Some(start) = start
            && index + 1 > block.line
            && line.trim_end() == "}"
        {
            return Ok(start..offset);
        }
    }
    Err(invalid("cannot locate block boundary"))
}

fn pair_spans(raw: &str, block: &Block) -> Result<Vec<Range<usize>>> {
    let mut spans = Vec::new();
    let mut offset = 0;
    let mut start = None;
    for line in raw.split_inclusive('\n') {
        let trimmed = line.trim();
        if start.is_none()
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !trimmed.starts_with("//")
        {
            start = Some(offset);
        }
        offset += line.len();
        if let Some(begin) = start {
            let candidate = Block {
                name: block.name.clone(),
                content: raw[begin..offset].to_owned(),
                line: block.line,
            };
            if let Ok(pairs) = candidate.pairs()
                && pairs.len() == 1
            {
                spans.push(begin..offset);
                start = None;
            }
        }
    }
    if start.is_some() {
        return Err(invalid("cannot locate dictionary entry boundary"));
    }
    Ok(spans)
}

fn encode_pair(pair: &Pair) -> Result<String> {
    if pair.key.is_empty() {
        return Err(invalid("enter a field name or remove the row"));
    }
    let key = serde_json::to_string(&pair.key).map_err(|error| invalid(error.to_string()))?;
    let prefix = if pair.enabled { "" } else { "~" };
    let value = &pair.value;
    if pair.is_list {
        let lines = value
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect::<String>();
        Ok(format!("  {prefix}{key}: [\n{lines}  ]\n"))
    } else if value.contains('\n')
        || value.trim() != value
        || value == "["
        || value.starts_with("'''")
    {
        if value.contains("'''") {
            return Err(invalid("cannot encode triple quotes; edit Source instead"));
        }
        let lines = value
            .split('\n')
            .map(|line| format!("  {line}\n"))
            .collect::<String>();
        Ok(format!("  {prefix}{key}: '''\n{lines}  '''\n"))
    } else {
        Ok(format!("  {prefix}{key}: {value}\n"))
    }
}

fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid {
        reason: reason.into(),
    }
}
