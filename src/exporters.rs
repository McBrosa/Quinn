use std::{fs::OpenOptions, io::Write, path::Path};

use serde_json::{Value, json};

use crate::{
    Error, Result,
    bru::{Document, Pair},
    collection,
    variables::{Variables, interpolate},
};

#[derive(Clone, Copy, Debug)]
pub enum Format {
    Postman,
    OpenApi,
}

/// Export supported HTTP requests without executing scripts or sending requests.
pub fn export(format: Format, path: &Path, environment: Option<&str>) -> Result<String> {
    let root = collection::root(path)?;
    let environment = environment.map_or_else(
        || Ok(Variables::new()),
        |name| collection::environment(&root, name),
    )?;
    let entries = collection::discover(path)?;
    if entries.is_empty() || entries.len() > 10_000 {
        return Err(Error::invalid(
            "export must contain between 1 and 10000 requests",
        ));
    }
    let mut items = Vec::new();
    for entry in entries {
        let request = collection::load(&entry.path)?;
        let defaults = collection::defaults(&root, &entry.path)?;
        let documents: Vec<_> = defaults.iter().chain([&request]).collect();
        validate(&documents)?;
        let mut variables = Variables::new();
        for document in &documents {
            for pair in document.pairs("vars:pre-request")? {
                if pair.enabled {
                    variables.insert(pair.key, pair.value);
                }
            }
        }
        variables.extend(environment.clone());
        items.push(postman_item(&entry.name, &request, &documents, &variables)?);
    }
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Quinn");
    let document = match format {
        Format::Postman => json!({
            "info": {"name":name, "schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item":items,
        }),
        Format::OpenApi => openapi(name, &items)?,
    };
    serde_json::to_string_pretty(&document).map_err(|error| Error::invalid(error.to_string()))
}

/// Create an export file without replacing an existing path or following a symlink.
pub fn write_new(destination: &Path, source: &str) -> Result<()> {
    let _: Value = serde_json::from_str(source)
        .map_err(|error| Error::invalid(format!("cannot parse export JSON: {error}")))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|source| Error::io(destination, source))?;
    file.write_all(source.as_bytes())
        .map_err(|source| Error::io(destination, source))?;
    file.sync_all()
        .map_err(|source| Error::io(destination, source))
}

fn unsupported(feature: impl Into<String>) -> Error {
    Error::Unsupported {
        feature: feature.into(),
    }
}

fn validate(documents: &[&Document]) -> Result<()> {
    for document in documents {
        for block in &document.blocks {
            if block.content.trim().is_empty() {
                continue;
            }
            if !matches!(
                block.name.as_str(),
                "meta"
                    | "docs"
                    | "get"
                    | "post"
                    | "put"
                    | "patch"
                    | "delete"
                    | "head"
                    | "options"
                    | "trace"
                    | "connect"
                    | "http"
                    | "headers"
                    | "params:query"
                    | "params:path"
                    | "vars:pre-request"
                    | "auth"
                    | "auth:basic"
                    | "auth:bearer"
                    | "auth:apikey"
                    | "body:json"
                    | "body:text"
                    | "body:xml"
                    | "body:sparql"
                    | "body:graphql"
                    | "body:graphql:vars"
                    | "body:form-urlencoded"
                    | "body:formUrlEncoded"
                    | "body:multipart-form"
                    | "body:multipartForm"
            ) {
                return Err(unsupported(format!(
                    "export of block '{}'; no executable behavior is omitted",
                    block.name
                )));
            }
            let allowed: Option<&[&str]> = match block.name.as_str() {
                "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace"
                | "connect" => Some(&["url", "body", "auth"]),
                "http" => Some(&["url", "body", "auth", "method"]),
                "auth" => Some(&["mode"]),
                "auth:basic" => Some(&["username", "password"]),
                "auth:bearer" => Some(&["token"]),
                "auth:apikey" => Some(&["key", "value", "placement"]),
                _ => None,
            };
            if let Some(allowed) = allowed {
                for pair in block.pairs()? {
                    if pair.enabled && !allowed.contains(&pair.key.as_str()) {
                        return Err(unsupported(format!(
                            "export field '{}.{}'",
                            block.name, pair.key
                        )));
                    }
                    if pair.is_list {
                        return Err(unsupported("export of list-valued dictionaries"));
                    }
                }
            }
            if block.name == "vars:pre-request" {
                for pair in block.pairs()? {
                    if pair.is_list || pair.value.contains("@persistent") {
                        return Err(unsupported(
                            "export of list-valued or persistent static variables",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn pairs(documents: &[&Document], block: &str) -> Result<Vec<Pair>> {
    let mut merged: Vec<Pair> = Vec::new();
    for document in documents {
        let pairs = document.pairs(block)?;
        for pair in pairs {
            if pair.is_list {
                return Err(unsupported("export of list-valued dictionaries"));
            }
            if block == "headers" {
                merged.retain(|old| !old.key.eq_ignore_ascii_case(&pair.key));
            }
            merged.push(pair);
        }
    }
    Ok(merged)
}

fn wire_pairs(pairs: Vec<Pair>) -> Vec<Value> {
    pairs
        .into_iter()
        .map(|pair| {
            json!({
                "key":pair.key, "value":pair.value, "disabled":!pair.enabled,
            })
        })
        .collect()
}

fn postman_item(
    name: &str,
    request: &Document,
    documents: &[&Document],
    variables: &Variables,
) -> Result<Value> {
    let mut method = None;
    for block in &request.blocks {
        if matches!(
            block.name.as_str(),
            "get"
                | "post"
                | "put"
                | "patch"
                | "delete"
                | "head"
                | "options"
                | "trace"
                | "connect"
                | "http"
        ) {
            if method.is_some() {
                return Err(Error::invalid(
                    "export request contains multiple HTTP method blocks",
                ));
            }
            method = Some(block.name.as_str());
        }
    }
    let method = method.ok_or_else(|| unsupported("export of non-HTTP requests"))?;
    let url = request
        .value(method, "url")?
        .ok_or_else(|| Error::invalid("export request has no URL"))?;
    let verb = if method == "http" {
        request
            .value(method, "method")?
            .ok_or_else(|| Error::invalid("HTTP export request has no method"))?
    } else {
        method.to_owned()
    };
    if !matches!(
        verb.to_ascii_lowercase().as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace" | "connect"
    ) {
        return Err(unsupported("export of custom HTTP methods"));
    }
    let mut wire = json!({
        "method":verb.to_ascii_uppercase(),
        "header":wire_pairs(pairs(documents, "headers")?),
        "url":{"raw":url, "query":wire_pairs(pairs(&[request], "params:query")?),
               "variable":wire_pairs(pairs(&[request], "params:path")?)},
    });
    // The Postman importer separates query entries from raw URL query text.
    // Avoid losing embedded query data in either export format.
    if url.contains('?') {
        return Err(unsupported(
            "export of embedded URL query strings; move them to params:query",
        ));
    }
    let mut mode = request
        .value(method, "auth")?
        .unwrap_or_else(|| "none".into());
    let mut auth_document = request;
    if mode == "inherit" {
        mode = "none".into();
        for document in documents.iter().rev().skip(1) {
            if let Some(inherited) = document.value("auth", "mode")?
                && inherited != "inherit"
            {
                mode = inherited;
                auth_document = document;
                break;
            }
        }
    }
    wire["auth"] = match mode.as_str() {
        "none" => json!({"type":"noauth"}),
        "basic" | "bearer" | "apikey" => {
            let keys: &[&str] = match mode.as_str() {
                "basic" => &["username", "password"],
                "bearer" => &["token"],
                _ => &["key", "value", "placement"],
            };
            let mut entries = Vec::new();
            for key in keys {
                let value = auth_document
                    .value(&format!("auth:{mode}"), key)?
                    .ok_or_else(|| Error::invalid(format!("export {mode} auth has no {key}")))?;
                let (key, value) = if *key == "placement" {
                    (
                        "in",
                        match value.as_str() {
                            "header" => "header".to_owned(),
                            "queryparams" | "query" => "query".to_owned(),
                            _ => return Err(unsupported("export API key placement")),
                        },
                    )
                } else {
                    (*key, value)
                };
                entries.push(json!({"key":key,"value":value,"type":"string"}));
            }
            let mut auth = json!({"type":mode});
            auth[&mode] = Value::Array(entries);
            auth
        }
        mode => return Err(unsupported(format!("export authentication '{mode}'"))),
    };
    let body = request
        .value(method, "body")?
        .unwrap_or_else(|| "none".into());
    let canonical = match body.as_str() {
        "formUrlEncoded" => "form-urlencoded",
        "multipartForm" => "multipart-form",
        _ => body.as_str(),
    };
    for document in documents {
        for block in &document.blocks {
            if block.name.starts_with("body:") && !block.content.trim().is_empty() {
                let selected = block.name == format!("body:{body}")
                    || block.name == format!("body:{canonical}")
                    || (body == "graphql" && block.name == "body:graphql:vars");
                if !std::ptr::eq(*document, request) || !selected {
                    return Err(unsupported(
                        "export of inherited or conflicting body blocks",
                    ));
                }
            }
        }
    }
    match body.as_str() {
        "none" => {}
        "json" | "text" | "xml" | "sparql" => {
            let raw = &request
                .block(&format!("body:{body}"))
                .ok_or_else(|| Error::invalid("export request has no body block"))?
                .content;
            wire["body"] = json!({"mode":"raw","raw":raw,"options":{"raw":{"language":if body == "sparql" {"text"} else {&body}}}});
            if body == "sparql" {
                return Err(unsupported("export SPARQL bodies"));
            }
        }
        "graphql" => {
            let query = &request
                .block("body:graphql")
                .ok_or_else(|| Error::invalid("export has no GraphQL body"))?
                .content;
            let variables = request
                .block("body:graphql:vars")
                .map(|block| block.content.clone())
                .unwrap_or_else(|| "{}".into());
            wire["body"] =
                json!({"mode":"graphql","graphql":{"query":query,"variables":variables}});
        }
        "form-urlencoded" | "formUrlEncoded" | "multipart-form" | "multipartForm" => {
            let multipart = matches!(body.as_str(), "multipart-form" | "multipartForm");
            let canonical = if multipart {
                "multipart-form"
            } else {
                "form-urlencoded"
            };
            let block = if request.block(&format!("body:{body}")).is_some() {
                &body
            } else {
                canonical
            };
            let entries = pairs(&[request], &format!("body:{block}"))?;
            if entries
                .iter()
                .any(|pair| pair.value.contains("@file(") || pair.value.contains("@contentType("))
            {
                return Err(unsupported("export multipart files or per-part MIME types"));
            }
            let mode = if multipart { "formdata" } else { "urlencoded" };
            let mut body = json!({"mode":mode});
            body[mode] = Value::Array(wire_pairs(entries));
            wire["body"] = body;
        }
        kind => return Err(unsupported(format!("export body type '{kind}'"))),
    }
    Ok(json!({
        "name":name, "request":wire,
        "variable":variables.iter().map(|(key,value)| json!({"key":key,"value":value,"type":"string"})).collect::<Vec<_>>(),
    }))
}

fn openapi(name: &str, items: &[Value]) -> Result<Value> {
    let mut paths = serde_json::Map::new();
    for item in items {
        let variables: Variables = item["variable"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                Some((
                    entry["key"].as_str()?.into(),
                    entry["value"].as_str()?.into(),
                ))
            })
            .collect();
        let wire = &item["request"];
        let raw = interpolate(wire["url"]["raw"].as_str().unwrap_or(""), &variables)?;
        let url = reqwest::Url::parse(&raw)
            .map_err(|error| Error::invalid(format!("cannot export URL: {error}")))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(unsupported(
                "OpenAPI export URL scheme, credentials, or fragment",
            ));
        }
        let server = url.origin().ascii_serialization();
        let mut path = url.path().to_owned();
        let mut parameters = Vec::new();
        for (kind, entries) in [
            ("query", &wire["url"]["query"]),
            ("path", &wire["url"]["variable"]),
            ("header", &wire["header"]),
        ] {
            let mut keys = std::collections::BTreeSet::new();
            for entry in entries
                .as_array()
                .into_iter()
                .flatten()
                .filter(|entry| entry["disabled"] != true)
            {
                let key = interpolate(entry["key"].as_str().unwrap_or(""), &variables)?;
                if kind == "header"
                    && (key.eq_ignore_ascii_case("accept")
                        || key.eq_ignore_ascii_case("authorization")
                        || (key.eq_ignore_ascii_case("content-type") && wire.get("body").is_none()))
                {
                    return Err(unsupported(
                        "OpenAPI cannot represent explicit Accept, Authorization, or bodyless Content-Type headers",
                    ));
                }
                if !keys.insert(key.clone()) {
                    return Err(unsupported("OpenAPI export duplicate parameter names"));
                }
                let value = interpolate(entry["value"].as_str().unwrap_or(""), &variables)?;
                if kind == "path" {
                    let marker = format!(":{key}");
                    if !path.split('/').any(|segment| segment == marker) {
                        return Err(unsupported(
                            "OpenAPI export path parameters must match a whole segment",
                        ));
                    }
                    path = path
                        .split('/')
                        .map(|segment| {
                            if segment == marker {
                                format!("{{{key}}}")
                            } else {
                                segment.to_owned()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("/");
                }
                parameters.push(json!({"in":kind,"name":key,"required":true,"schema":{"type":"string"},"example":value}));
            }
        }
        if wire["auth"]["type"] != "noauth" {
            return Err(unsupported(
                "OpenAPI export of authentication credentials; use Postman export",
            ));
        }
        let mut operation = json!({"summary":item["name"],"parameters":parameters,
            "servers":[{"url":server}],"responses":{"default":{"description":"Response"}}});
        if let Some(body) = wire.get("body") {
            if body["mode"] != "raw" {
                return Err(unsupported(
                    "OpenAPI export supports only raw JSON, XML, and text bodies",
                ));
            }
            let raw = interpolate(body["raw"].as_str().unwrap_or(""), &variables)?;
            let language = body
                .pointer("/options/raw/language")
                .and_then(Value::as_str)
                .unwrap_or("text");
            let default_mime = match language {
                "json" => "application/json",
                "xml" => "application/xml",
                _ => "text/plain",
            };
            let mime = operation["parameters"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|parameter| {
                    parameter["in"] == "header"
                        && parameter["name"]
                            .as_str()
                            .is_some_and(|name| name.eq_ignore_ascii_case("content-type"))
                })
                .and_then(|parameter| parameter["example"].as_str())
                .unwrap_or(default_mime)
                .to_owned();
            if !((language == "json" && (mime == "application/json" || mime.ends_with("+json")))
                || (language != "json" && (mime.starts_with("text/") || mime == "application/xml")))
            {
                return Err(unsupported(
                    "OpenAPI export body language does not match the Content-Type",
                ));
            }
            let example = if language == "json" {
                serde_json::from_str(&raw)
                    .map_err(|error| Error::invalid(format!("cannot export JSON body: {error}")))?
            } else {
                Value::String(raw)
            };
            operation["requestBody"] =
                json!({"required":true,"content":{mime:{"example":example}}});
            // Content-Type is emitted by the importer from requestBody, not twice.
            operation["parameters"]
                .as_array_mut()
                .ok_or_else(|| Error::invalid("invalid export parameters"))?
                .retain(|parameter| {
                    !(parameter["in"] == "header"
                        && parameter["name"]
                            .as_str()
                            .is_some_and(|name| name.eq_ignore_ascii_case("content-type")))
                });
        }
        let method = wire["method"].as_str().unwrap_or("").to_ascii_lowercase();
        if method == "connect" {
            return Err(unsupported("OpenAPI CONNECT method"));
        }
        let path_item = paths.entry(path).or_insert_with(|| json!({}));
        if path_item.get(&method).is_some() {
            return Err(unsupported(
                "OpenAPI cannot represent multiple requests with the same path and method",
            ));
        }
        path_item[&method] = operation;
    }
    Ok(json!({"openapi":"3.0.3","info":{"title":name,"version":"1.0.0"},"paths":paths}))
}
