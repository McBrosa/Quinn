use std::collections::{BTreeMap, BTreeSet};

use crate::{Error, Result};

pub type Variables = BTreeMap<String, String>;

/// Expand nested Bruno variables, rejecting missing values and cycles.
pub fn interpolate(input: &str, variables: &Variables) -> Result<String> {
    expand(input, variables, &mut BTreeSet::new())
}

fn expand(input: &str, variables: &Variables, visiting: &mut BTreeSet<String>) -> Result<String> {
    let mut output = String::new();
    let mut remainder = input;
    while let Some(start) = remainder.find("{{") {
        output.push_str(&remainder[..start]);
        let value = &remainder[start + 2..];
        let Some(end) = value.find("}}") else {
            return Err(Error::invalid("unclosed variable placeholder"));
        };
        let name = value[..end].trim();
        if visiting.len() >= 64 || !visiting.insert(name.to_owned()) {
            return Err(Error::invalid(format!(
                "variable cycle or excessive nesting at '{name}'"
            )));
        }
        let raw = variables.get(name).ok_or_else(|| Error::Variable {
            name: name.to_owned(),
        })?;
        output.push_str(&expand(raw, variables, visiting)?);
        visiting.remove(name);
        remainder = &value[end + 2..];
        if output.len() > 1024 * 1024 {
            return Err(Error::invalid("expanded variable exceeds 1 MiB"));
        }
    }
    output.push_str(remainder);
    Ok(output)
}
