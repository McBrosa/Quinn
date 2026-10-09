use serde_json::{Map, Value};

use crate::{
    Error, Result,
    bru::{Block, Document},
    variables::Variables,
};

/// Convert supported OpenCollection fields to the existing execution model.
pub(crate) fn parse(source: &str, collection: bool, folder: bool) -> Result<Document> {
    let value = decode(source)?;
    let object = object(&value, "document")?;
    keys(
        object,
        if collection {
            &[
                "opencollection",
                "info",
                "request",
                "config",
                "extensions",
                "docs",
            ]
        } else if folder {
            &["info", "request", "docs"]
        } else {
            &["info", "http", "runtime", "settings", "docs", "examples"]
        },
    )?;
    let mut document = metadata_value(object)?;
    if let Some(info) = object.get("info") {
        let info = self::object(info, "info")?;
        if !collection && !folder && info.get("type").is_some_and(|v| v != "http") {
            return unsupported("request type other than HTTP");
        }
    }
    if collection {
        if object.get("opencollection").and_then(Value::as_str) != Some("1.0.0") {
            return unsupported("OpenCollection version other than 1.0.0");
        }
        if let Some(config) = object.get("config") {
            let config = self::object(config, "config")?;
            keys(config, &["environments"])?;
        }
        if let Some(extensions) = object.get("extensions") {
            let extensions = self::object(extensions, "extensions")?;
            keys(extensions, &["bruno"])?;
            if let Some(bruno) = extensions.get("bruno") {
                let bruno = self::object(bruno, "extensions.bruno")?;
                keys(bruno, &["ignore", "presets", "openapi"])?;
                if let Some(ignore) = bruno.get("ignore") {
                    for entry in array(ignore, "ignore")? {
                        if !matches!(scalar(entry)?.as_str(), "node_modules" | ".git" | ".quinn") {
                            return unsupported("custom ignore pattern");
                        }
                    }
                }
            }
        }
    }
    if collection || folder {
        if let Some(request) = object.get("request") {
            defaults(&mut document, request)?;
        }
    } else {
        let http = self::object(
            object
                .get("http")
                .ok_or_else(|| Error::invalid("OpenCollection request has no http field"))?,
            "http",
        )?;
        keys(
            http,
            &["method", "url", "headers", "params", "auth", "body"],
        )?;
        let method = text(http, "method", "GET")?.to_lowercase();
        if !matches!(
            method.as_str(),
            "get" | "post" | "put" | "patch" | "delete" | "options" | "head" | "trace" | "connect"
        ) {
            return unsupported("HTTP method");
        }
        let mut mode = "none".to_owned();
        if let Some(body) = http.get("body") {
            mode = body_blocks(&mut document, body)?;
        }
        let auth = authentication(&mut document, http.get("auth"))?;
        dictionary(
            &mut document,
            &method,
            vec![
                ("url".into(), text(http, "url", "")?, true),
                ("body".into(), mode, true),
                ("auth".into(), auth, true),
            ],
        )?;
        list_pairs(&mut document, "headers", http.get("headers"), false)?;
        if let Some(params) = http.get("params") {
            for kind in ["query", "path"] {
                let entries = array(params, "params")?
                    .iter()
                    .filter(|value| {
                        value.get("type").and_then(Value::as_str).unwrap_or("query") == kind
                    })
                    .cloned()
                    .collect();
                list_pairs(
                    &mut document,
                    &format!("params:{kind}"),
                    Some(&Value::Array(entries)),
                    true,
                )?;
            }
            for parameter in array(params, "params")? {
                if !matches!(
                    parameter
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("query"),
                    "query" | "path"
                ) {
                    return unsupported("parameter type");
                }
            }
        }
        if let Some(runtime) = object.get("runtime") {
            runtime_blocks(&mut document, runtime)?;
        }
        if let Some(settings) = object.get("settings") {
            let settings = self::object(settings, "settings")?;
            keys(
                settings,
                &[
                    "encodeUrl",
                    "timeout",
                    "followRedirects",
                    "maxRedirects",
                    "forwardAuthorizationHeader",
                    "omitHeaders",
                ],
            )?;
            for (name, setting) in settings {
                let default = match name.as_str() {
                    "encodeUrl" | "followRedirects" => setting == &Value::Bool(true),
                    "timeout" => setting.is_null() || setting.as_u64() == Some(0),
                    "maxRedirects" => setting.as_u64() == Some(10),
                    "forwardAuthorizationHeader" => setting == &Value::Bool(false),
                    "omitHeaders" => setting.as_array().is_some_and(Vec::is_empty),
                    _ => false,
                };
                if !default {
                    return unsupported(&format!("request setting '{name}'"));
                }
            }
        }
    }
    Ok(document)
}

pub(crate) fn metadata(source: &str) -> Result<Document> {
    let value = decode(source)?;
    metadata_value(object(&value, "document")?)
}

pub(crate) fn request_metadata(source: &str) -> Result<Option<Document>> {
    let value = decode(source)?;
    let value = object(&value, "document")?;
    if !["http", "graphql", "grpc", "websocket"]
        .iter()
        .any(|key| value.contains_key(*key))
        && value
            .get("info")
            .and_then(|info| info.get("type"))
            .is_none_or(|kind| kind == "folder" || kind == "collection")
    {
        return Ok(None);
    }
    metadata_value(value).map(Some)
}

pub(crate) fn validate_syntax(source: &str) -> Result<()> {
    let value = decode(source)?;
    object(&value, "document")?;
    Ok(())
}

fn metadata_value(value: &Map<String, Value>) -> Result<Document> {
    let mut document = Document { blocks: Vec::new() };
    if let Some(info) = value.get("info") {
        let info = object(info, "info")?;
        keys(
            info,
            &["name", "type", "seq", "tags", "description", "version"],
        )?;
        let mut pairs = Vec::new();
        for key in ["name", "seq"] {
            if let Some(value) = info.get(key) {
                pairs.push((key.into(), scalar(value)?, true));
            }
        }
        dictionary(&mut document, "meta", pairs)?;
    }
    Ok(document)
}

pub(crate) fn environment(source: &str) -> Result<(Variables, Option<String>)> {
    let value = decode(source)?;
    let environment = object(&value, "environment")?;
    keys(
        environment,
        &["name", "variables", "color", "description", "extends"],
    )?;
    let mut document = Document { blocks: Vec::new() };
    variables(&mut document, environment.get("variables"), "vars")?;
    let variables = document
        .pairs("vars")?
        .into_iter()
        .filter(|pair| pair.enabled)
        .map(|pair| (pair.key, pair.value))
        .collect();
    let parent = environment
        .get("extends")
        .filter(|value| !value.is_null())
        .map(scalar)
        .transpose()?
        .filter(|name| !name.is_empty());
    Ok((variables, parent))
}

pub(crate) fn embedded_environments(source: &str) -> Result<Vec<(String, String)>> {
    let value = decode(source)?;
    let mut environments = Vec::new();
    if let Some(values) = value
        .get("config")
        .and_then(|config| config.get("environments"))
    {
        for value in array(values, "environments")? {
            let name = text(object(value, "environment")?, "name", "")?;
            if name.is_empty() || environments.iter().any(|(existing, _)| existing == &name) {
                return Err(Error::invalid(
                    "embedded environments need unique nonempty names",
                ));
            }
            let source = serde_yaml_ng::to_string(value)
                .map_err(|error| Error::invalid(error.to_string()))?;
            environment(&source)?;
            environments.push((name, source));
        }
    }
    Ok(environments)
}

fn defaults(document: &mut Document, value: &Value) -> Result<()> {
    let value = object(value, "request defaults")?;
    keys(
        value,
        &["headers", "auth", "variables", "scripts", "actions"],
    )?;
    list_pairs(document, "headers", value.get("headers"), false)?;
    let mode = authentication(document, value.get("auth"))?;
    if value.contains_key("auth") {
        dictionary(document, "auth", vec![("mode".into(), mode, true)])?;
    }
    let runtime = value
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "headers" | "auth"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    runtime_blocks(document, &Value::Object(runtime))
}

fn runtime_blocks(document: &mut Document, value: &Value) -> Result<()> {
    let value = object(value, "runtime")?;
    keys(value, &["variables", "scripts", "assertions", "actions"])?;
    variables(document, value.get("variables"), "vars:pre-request")?;
    if let Some(scripts) = value.get("scripts") {
        for script in array(scripts, "scripts")? {
            let script = object(script, "script")?;
            keys(script, &["type", "code"])?;
            let name = match text(script, "type", "")?.as_str() {
                "before-request" => "script:pre-request",
                "after-response" => "script:post-response",
                "tests" => "tests",
                _ => return unsupported("script phase"),
            };
            if document.block(name).is_some() {
                return Err(Error::invalid("duplicate OpenCollection script phase"));
            }
            raw(document, name, text(script, "code", "")?);
        }
    }
    let mut assertions = Vec::new();
    if let Some(values) = value.get("assertions") {
        for value in array(values, "assertions")? {
            let value = object(value, "assertion")?;
            keys(
                value,
                &["expression", "operator", "value", "disabled", "description"],
            )?;
            assertions.push((
                text(value, "expression", "")?,
                format!(
                    "{} {}",
                    text(value, "operator", "eq")?,
                    text(value, "value", "")?
                ),
                enabled(value)?,
            ));
        }
    }
    dictionary(document, "assert", assertions)?;
    let mut actions = Vec::new();
    if let Some(values) = value.get("actions") {
        for value in array(values, "actions")? {
            let value = object(value, "action")?;
            keys(
                value,
                &[
                    "type",
                    "phase",
                    "selector",
                    "variable",
                    "disabled",
                    "description",
                ],
            )?;
            if text(value, "type", "")? != "set-variable"
                || text(value, "phase", "")? != "after-response"
            {
                return unsupported("action type or phase");
            }
            let selector = object(
                value
                    .get("selector")
                    .ok_or_else(|| Error::invalid("action has no selector"))?,
                "selector",
            )?;
            keys(selector, &["expression", "method"])?;
            if text(selector, "method", "jsonq")? != "jsonq" {
                return unsupported("selector method");
            }
            let variable = object(
                value
                    .get("variable")
                    .ok_or_else(|| Error::invalid("action has no variable"))?,
                "action variable",
            )?;
            keys(variable, &["name", "scope"])?;
            if text(variable, "scope", "runtime")? != "runtime" {
                return unsupported("action variable scope other than runtime");
            }
            actions.push((
                text(variable, "name", "")?,
                text(selector, "expression", "")?,
                enabled(value)?,
            ));
        }
    }
    dictionary(document, "vars:post-response", actions)
}

fn variables(document: &mut Document, value: Option<&Value>, name: &str) -> Result<()> {
    let mut pairs = Vec::new();
    if let Some(values) = value {
        for value in array(values, "variables")? {
            let value = object(value, "variable")?;
            keys(
                value,
                &["name", "value", "disabled", "secret", "description"],
            )?;
            if value.get("secret") == Some(&Value::Bool(true)) {
                return unsupported("secret variable storage");
            }
            pairs.push((
                text(value, "name", "")?,
                text(value, "value", "")?,
                enabled(value)?,
            ));
        }
    }
    dictionary(document, name, pairs)
}

fn list_pairs(
    document: &mut Document,
    name: &str,
    value: Option<&Value>,
    params: bool,
) -> Result<()> {
    let mut pairs = Vec::new();
    if let Some(values) = value {
        for value in array(values, name)? {
            let value = object(value, name)?;
            keys(
                value,
                if params {
                    &["name", "value", "type", "disabled", "description"]
                } else {
                    &["name", "value", "disabled", "description"]
                },
            )?;
            pairs.push((
                text(value, "name", "")?,
                text(value, "value", "")?,
                enabled(value)?,
            ));
        }
    }
    dictionary(document, name, pairs)
}

fn authentication(document: &mut Document, value: Option<&Value>) -> Result<String> {
    let Some(value) = value else {
        return Ok("none".into());
    };
    if value == "inherit" {
        return Ok("inherit".into());
    }
    let value = object(value, "authentication")?;
    let kind = text(value, "type", "")?;
    let fields: &[&str] = match kind.as_str() {
        "basic" => &["username", "password"],
        "bearer" => &["token"],
        "apikey" => &["key", "value", "placement"],
        _ => return unsupported("authentication type"),
    };
    let mut allowed = fields.to_vec();
    allowed.push("type");
    keys(value, &allowed)?;
    let mut pairs = Vec::new();
    for field in fields {
        let mut content = text(value, field, "")?;
        if kind == "apikey" && *field == "placement" {
            content = match content.as_str() {
                "query" => "queryparams".into(),
                "header" | "" => "header".into(),
                _ => return unsupported("API key placement"),
            };
        }
        pairs.push(((*field).into(), content, true));
    }
    dictionary(document, &format!("auth:{kind}"), pairs)?;
    Ok(kind)
}

fn body_blocks(document: &mut Document, value: &Value) -> Result<String> {
    let value = object(value, "body")?;
    keys(value, &["type", "data"])?;
    let kind = text(value, "type", "")?;
    match kind.as_str() {
        "json" | "text" | "xml" | "sparql" => {
            raw(document, &format!("body:{kind}"), text(value, "data", "")?)
        }
        "form-urlencoded" => list_pairs(document, "body:formUrlEncoded", value.get("data"), false)?,
        "multipart-form" | "file" => {
            let data = value
                .get("data")
                .ok_or_else(|| Error::invalid("upload body has no data"))?;
            let mut pairs = Vec::new();
            for field in array(data, "upload data")? {
                let field = object(field, "upload field")?;
                keys(
                    field,
                    if kind == "file" {
                        &["filePath", "contentType", "selected", "description"]
                    } else {
                        &[
                            "name",
                            "value",
                            "type",
                            "contentType",
                            "disabled",
                            "description",
                        ]
                    },
                )?;
                let is_file = kind == "file" || text(field, "type", "text")? == "file";
                if kind != "file"
                    && !matches!(text(field, "type", "text")?.as_str(), "text" | "file")
                {
                    return unsupported("multipart field type");
                }
                let name = if kind == "file" {
                    "file".into()
                } else {
                    text(field, "name", "")?
                };
                let mut content = if is_file {
                    let paths = match field.get("value") {
                        Some(Value::Array(paths)) => {
                            paths.iter().map(scalar).collect::<Result<Vec<_>>>()?
                        }
                        _ => vec![text(
                            field,
                            if kind == "file" { "filePath" } else { "value" },
                            "",
                        )?],
                    };
                    if paths
                        .iter()
                        .any(|path| path.is_empty() || path.contains(['|', ')', '\n', '\r']))
                    {
                        return Err(Error::invalid("cannot represent upload file path"));
                    }
                    format!("@file({})", paths.join("|"))
                } else {
                    text(field, "value", "")?
                };
                let mime = text(field, "contentType", "")?;
                if !mime.is_empty() {
                    if mime.contains([')', '\r', '\n']) {
                        return Err(Error::invalid("cannot represent upload content type"));
                    }
                    content.push_str(&format!(" @contentType({mime})"));
                }
                let enabled = if kind == "file" {
                    match field.get("selected") {
                        None | Some(Value::Bool(true)) => true,
                        Some(Value::Bool(false)) => false,
                        _ => return Err(Error::invalid("file selected field must be boolean")),
                    }
                } else {
                    enabled(field)?
                };
                pairs.push((name, content, enabled));
            }
            dictionary(
                document,
                if kind == "file" {
                    "body:file"
                } else {
                    "body:multipartForm"
                },
                pairs,
            )?;
        }
        _ => return unsupported("body type"),
    }
    Ok(match kind.as_str() {
        "form-urlencoded" => "formUrlEncoded".into(),
        "multipart-form" => "multipartForm".into(),
        _ => kind,
    })
}

fn dictionary(
    document: &mut Document,
    name: &str,
    values: Vec<(String, String, bool)>,
) -> Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    let mut content = String::new();
    for (key, value, enabled) in values {
        if key.is_empty() || value.contains("'''") {
            return Err(Error::invalid(
                "cannot represent empty key or triple-quote value in the request model",
            ));
        }
        let key = serde_json::to_string(&key).map_err(|error| Error::invalid(error.to_string()))?;
        content.push_str(&format!(
            "{}{key}: '''\n{value}\n'''\n",
            if enabled { "" } else { "~" }
        ));
    }
    raw(document, name, content);
    Ok(())
}

fn raw(document: &mut Document, name: &str, content: String) {
    document.blocks.push(Block {
        name: name.into(),
        content,
        line: 1,
    });
}

fn object<'v>(value: &'v Value, field: &str) -> Result<&'v Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| Error::invalid(format!("OpenCollection {field} must be a mapping")))
}

fn array<'v>(value: &'v Value, field: &str) -> Result<&'v Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| Error::invalid(format!("OpenCollection {field} must be a list")))
}

fn text(value: &Map<String, Value>, key: &str, fallback: &str) -> Result<String> {
    value.get(key).map_or_else(|| Ok(fallback.into()), scalar)
}

fn scalar(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Null => Ok(String::new()),
        _ => unsupported("typed or non-scalar value"),
    }
}

fn enabled(value: &Map<String, Value>) -> Result<bool> {
    match value.get("disabled") {
        None | Some(Value::Bool(false)) => Ok(true),
        Some(Value::Bool(true)) => Ok(false),
        _ => Err(Error::invalid(
            "OpenCollection disabled field must be boolean",
        )),
    }
}

fn keys(value: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    for key in value.keys() {
        if !allowed.contains(&key.as_str()) {
            return unsupported(&format!("field '{key}'"));
        }
    }
    Ok(())
}

fn unsupported<T>(feature: &str) -> Result<T> {
    Err(Error::Unsupported {
        feature: format!("OpenCollection {feature}"),
    })
}

fn decode(source: &str) -> Result<Value> {
    let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(source)
        .map_err(|error| Error::invalid(format!("cannot parse OpenCollection YAML: {error}")))?;
    reject_tags(&yaml)?;
    serde_json::to_value(yaml)
        .map_err(|error| Error::invalid(format!("cannot represent OpenCollection YAML: {error}")))
}

fn reject_tags(value: &serde_yaml_ng::Value) -> Result<()> {
    match value {
        serde_yaml_ng::Value::Tagged(_) => unsupported("custom YAML tag"),
        serde_yaml_ng::Value::Mapping(values) => {
            for (key, value) in values {
                if !key.is_string() {
                    return Err(Error::invalid(
                        "OpenCollection mapping keys must be strings",
                    ));
                }
                reject_tags(value)?;
            }
            Ok(())
        }
        serde_yaml_ng::Value::Sequence(values) => {
            for value in values {
                reject_tags(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
