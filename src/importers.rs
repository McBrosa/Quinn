use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use serde_json::{Value, json};

use crate::{Error, Result, bru::Document, variables::Variables};

const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_REQUESTS: usize = 10_000;

#[derive(Clone, Copy, Debug)]
pub enum Format {
    Postman,
    OpenApi,
    Curl,
    Insomnia,
}

#[derive(Clone, Debug)]
pub struct ImportedRequest {
    pub name: String,
    pub source: String,
}

#[derive(Clone, Debug)]
pub struct ImportedCollection {
    pub name: String,
    pub requests: Vec<ImportedRequest>,
    pub variables: Variables,
}

/// Convert an offline export without executing commands or making network requests.
pub fn parse(format: Format, input: &str) -> Result<ImportedCollection> {
    if input.len() > MAX_INPUT {
        return Err(invalid("import exceeds the 16 MiB limit"));
    }
    let imported = match format {
        Format::Postman => postman(
            &serde_json::from_str(input)
                .map_err(|error| invalid(format!("cannot parse Postman JSON: {error}")))?,
        )?,
        Format::OpenApi => {
            let document: Value = serde_yaml_ng::from_str(input)
                .map_err(|error| invalid(format!("cannot parse OpenAPI JSON or YAML: {error}")))?;
            openapi(&document)?
        }
        Format::Curl => curl(input)?,
        Format::Insomnia => insomnia(
            &serde_json::from_str(input)
                .map_err(|error| invalid(format!("cannot parse Insomnia JSON: {error}")))?,
        )?,
    };
    if imported.requests.is_empty() {
        return Err(invalid("import contains no requests"));
    }
    for request in &imported.requests {
        Document::parse(&request.source)?;
    }
    Ok(imported)
}

impl ImportedCollection {
    /// Write a new collection; never replace an existing path or follow its symlink.
    pub fn write_to(&self, destination: &Path) -> Result<()> {
        if self.requests.is_empty() || self.requests.len() > MAX_REQUESTS {
            return Err(invalid("import must contain between 1 and 10000 requests"));
        }
        // Validate the complete plan before creating anything.
        let mut files = vec![(
            "bruno.json".to_owned(),
            serde_json::to_string_pretty(&json!({
                "version": "1", "name": self.name, "type": "collection"
            }))
            .map_err(|error| invalid(error.to_string()))?,
        )];
        let mut defaults = String::new();
        dictionary(
            &mut defaults,
            "vars:pre-request",
            &self
                .variables
                .iter()
                .map(|(key, value)| (key.clone(), value.clone(), true))
                .collect::<Vec<_>>(),
        )?;
        if !defaults.is_empty() {
            files.push(("collection.bru".into(), defaults));
        }
        for (index, request) in self.requests.iter().enumerate() {
            Document::parse(&request.source)?;
            files.push((
                format!("{:05}-{}.bru", index + 1, filename(&request.name)),
                request.source.clone(),
            ));
        }
        fs::create_dir(destination).map_err(|source| io(destination, source))?;
        for (name, source) in files {
            let path = destination.join(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|source| io(&path, source))?;
            file.write_all(source.as_bytes())
                .map_err(|source| io(&path, source))?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Request {
    name: String,
    method: String,
    url: String,
    headers: Vec<(String, String, bool)>,
    query: Vec<(String, String, bool)>,
    path: Vec<(String, String, bool)>,
    variables: Variables,
    auth: String,
    auth_pairs: Vec<(String, String, bool)>,
    body: String,
    body_kind: String,
    body_pairs: Vec<(String, String, bool)>,
    graphql_variables: Option<Value>,
}

impl Request {
    fn render(self, sequence: usize) -> Result<ImportedRequest> {
        let mut header_names = std::collections::BTreeSet::new();
        for (key, _, enabled) in &self.headers {
            if *enabled && !header_names.insert(key.to_ascii_lowercase()) {
                return Err(unsupported(format!("duplicate imported header '{key}'")));
            }
        }
        let method = self.method.to_ascii_lowercase();
        if ![
            "get", "post", "put", "patch", "delete", "head", "options", "trace", "connect",
        ]
        .contains(&method.as_str())
        {
            return Err(unsupported(format!(
                "imported HTTP method '{}'",
                self.method
            )));
        }
        if !(self.url.starts_with("http://")
            || self.url.starts_with("https://")
            || self.url.starts_with("{{"))
        {
            return Err(invalid(
                "imported URL must use HTTP, HTTPS, or a Bruno variable",
            ));
        }
        let auth = if self.auth.is_empty() {
            "none"
        } else {
            &self.auth
        };
        let body_kind = if self.body_kind.is_empty() {
            "none"
        } else {
            &self.body_kind
        };
        let mut source = String::new();
        dictionary(
            &mut source,
            "meta",
            &[
                ("name".into(), self.name.clone(), true),
                ("type".into(), "http".into(), true),
                ("seq".into(), sequence.to_string(), true),
            ],
        )?;
        dictionary(
            &mut source,
            &method,
            &[
                ("url".into(), self.url, true),
                ("body".into(), body_kind.into(), true),
                ("auth".into(), auth.into(), true),
            ],
        )?;
        dictionary(&mut source, "headers", &self.headers)?;
        dictionary(&mut source, "params:query", &self.query)?;
        dictionary(&mut source, "params:path", &self.path)?;
        dictionary(
            &mut source,
            "vars:pre-request",
            &self
                .variables
                .into_iter()
                .map(|(key, value)| (key, value, true))
                .collect::<Vec<_>>(),
        )?;
        dictionary(&mut source, &format!("auth:{auth}"), &self.auth_pairs)?;
        if !self.body_pairs.is_empty() {
            dictionary(&mut source, &format!("body:{body_kind}"), &self.body_pairs)?;
        } else if body_kind != "none" {
            block(&mut source, &format!("body:{body_kind}"), &self.body);
        }
        if let Some(variables) = self.graphql_variables {
            block(
                &mut source,
                "body:graphql:vars",
                &serde_json::to_string_pretty(&variables)
                    .map_err(|error| invalid(error.to_string()))?,
            );
        }
        let document = Document::parse(&source)?;
        for name in [
            "meta",
            &method,
            "headers",
            "params:query",
            "params:path",
            "vars:pre-request",
            &format!("auth:{auth}"),
        ] {
            document.pairs(name)?;
        }
        Ok(ImportedRequest {
            name: self.name,
            source,
        })
    }
}

fn postman(document: &Value) -> Result<ImportedCollection> {
    let schema = required(&document["info"], "schema")?;
    if !schema.ends_with("/v2.1.0/collection.json") {
        return Err(unsupported("Postman formats other than collection v2.1"));
    }
    let name = required(&document["info"], "name")?.to_owned();
    let variables = postman_variables(document)?;
    let mut requests = Vec::new();
    postman_items(
        document,
        "",
        &Variables::new(),
        document.get("auth"),
        &mut requests,
        0,
    )?;
    Ok(ImportedCollection {
        name,
        requests,
        variables,
    })
}

fn insomnia(document: &Value) -> Result<ImportedCollection> {
    if document["_type"] != "export" || document["__export_format"] != 4 {
        return Err(unsupported(
            "Insomnia formats other than native JSON export v4",
        ));
    }
    let resources = document["resources"]
        .as_array()
        .ok_or_else(|| invalid("Insomnia export needs a resources array"))?;
    if resources.len() > MAX_REQUESTS * 4 {
        return Err(invalid("Insomnia export exceeds 40000 resources"));
    }
    let mut ids = BTreeMap::new();
    for resource in resources {
        let id = required(resource, "_id")?;
        if ids.insert(id, resource).is_some() {
            return Err(invalid(format!("duplicate Insomnia resource '{id}'")));
        }
        match required(resource, "_type")? {
            "workspace" | "request_group" | "request" | "environment" => {}
            kind => return Err(unsupported(format!("Insomnia resource type '{kind}'"))),
        }
        for key in ["preRequestScript", "afterResponseScript", "scripts"] {
            if resource.get(key).is_some_and(|value| {
                !value.is_null()
                    && value != ""
                    && !value.as_array().is_some_and(Vec::is_empty)
                    && !value.as_object().is_some_and(serde_json::Map::is_empty)
            }) {
                return Err(unsupported(format!("Insomnia executable '{key}'")));
            }
        }
        if resource["settingEncodeUrl"] == false
            || resource.get("settingFollowRedirects").is_some_and(|value| {
                !value.is_null() && value != true && value != "global" && value != "on"
            })
            || resource["settingSendCookies"] == false
            || resource["settingStoreCookies"] == false
            || resource["settingDisableRenderRequestBody"] == true
            || resource
                .get("settingTimeout")
                .is_some_and(|value| !value.is_null() && value != 0)
        {
            return Err(unsupported(
                "Insomnia non-default URL, redirect, or cookie settings",
            ));
        }
        if resource["_type"] != "request"
            && resource.get("authentication").is_some_and(|value| {
                !value.is_null() && !value.as_object().is_some_and(serde_json::Map::is_empty)
            })
        {
            return Err(unsupported(
                "Insomnia inherited workspace or folder authentication",
            ));
        }
        if resource["_type"] != "request"
            && ["headers", "parameters"].iter().any(|key| {
                resource.get(*key).is_some_and(|value| {
                    !value.is_null() && !value.as_array().is_some_and(Vec::is_empty)
                })
            })
        {
            return Err(unsupported(
                "Insomnia inherited workspace or folder headers/parameters",
            ));
        }
    }
    let workspaces: Vec<_> = resources
        .iter()
        .filter(|value| value["_type"] == "workspace")
        .collect();
    if workspaces.len() != 1 {
        return Err(invalid("Insomnia import needs exactly one workspace"));
    }
    let workspace = workspaces[0];
    let workspace_id = required(workspace, "_id")?;
    let name = required(workspace, "name")?.to_owned();
    let mut variables = Variables::new();
    let mut environment = false;
    for resource in resources
        .iter()
        .filter(|value| value["_type"] != "workspace")
    {
        insomnia_ancestors(resource, &ids, workspace_id)?;
        if resource["_type"] == "environment" {
            if required(resource, "parentId")? != workspace_id || environment {
                return Err(unsupported(
                    "Insomnia child or multiple environments; export only the base environment",
                ));
            }
            environment = true;
            for (key, value) in resource["data"]
                .as_object()
                .ok_or_else(|| invalid("Insomnia environment data must be an object"))?
            {
                if key.contains(['.', '{', '}', ' ']) {
                    return Err(unsupported(
                        "Insomnia nested or non-identifier environment keys",
                    ));
                }
                variables.insert(key.clone(), insomnia_value(value)?);
            }
        }
        if resource["_type"] == "request_group"
            && resource.get("environment").is_some_and(|value| {
                !value.is_null() && !value.as_object().is_some_and(serde_json::Map::is_empty)
            })
        {
            return Err(unsupported("Insomnia folder environment overrides"));
        }
    }
    let mut requests = Vec::new();
    for wire in resources.iter().filter(|value| value["_type"] == "request") {
        if requests.len() >= MAX_REQUESTS {
            return Err(invalid("Insomnia export exceeds 10000 requests"));
        }
        let mut names = insomnia_ancestors(wire, &ids, workspace_id)?;
        names.reverse();
        names.push(required(wire, "name")?.to_owned());
        let mut request = Request {
            name: names.join(" / "),
            method: required(wire, "method")?.into(),
            url: insomnia_value(&wire["url"])?,
            ..Request::default()
        };
        request.headers = insomnia_pairs(wire.get("headers"))?;
        request.query = insomnia_pairs(wire.get("parameters"))?;
        request.path = insomnia_pairs(wire.get("pathParameters"))?;
        let auth = &wire["authentication"];
        if auth["disabled"] != true {
            if let Some(fields) = auth.as_object() {
                let allowed: &[&str] = match auth["type"].as_str().unwrap_or("") {
                    "" | "none" => &["type", "disabled"],
                    "basic" => &["type", "disabled", "username", "password"],
                    "bearer" => &["type", "disabled", "token", "prefix"],
                    _ => &[],
                };
                if fields.keys().any(|key| !allowed.contains(&key.as_str())) {
                    return Err(unsupported("Insomnia unknown authentication fields"));
                }
            } else if !auth.is_null() {
                return Err(invalid("Insomnia authentication must be an object"));
            }
            match auth["type"].as_str().unwrap_or("") {
                "" | "none" => {}
                "basic" => {
                    request.auth = "basic".into();
                    for key in ["username", "password"] {
                        request
                            .auth_pairs
                            .push((key.into(), insomnia_value(&auth[key])?, true));
                    }
                }
                "bearer" => {
                    if auth["prefix"]
                        .as_str()
                        .is_some_and(|prefix| !prefix.is_empty() && prefix != "Bearer")
                    {
                        return Err(unsupported("Insomnia custom bearer prefix"));
                    }
                    request.auth = "bearer".into();
                    request.auth_pairs.push((
                        "token".into(),
                        insomnia_value(&auth["token"])?,
                        true,
                    ));
                }
                kind => return Err(unsupported(format!("Insomnia authentication '{kind}'"))),
            }
        }
        let body = &wire["body"];
        let mime = body["mimeType"].as_str().unwrap_or("");
        match mime.split(';').next().unwrap_or("") {
            "" if body["text"].as_str().is_none_or(str::is_empty) => {
                if body
                    .get("params")
                    .is_some_and(|params| !params.as_array().is_some_and(Vec::is_empty))
                {
                    return Err(unsupported("Insomnia body parameters without a MIME type"));
                }
            }
            "" | "text/plain" | "application/json" | "text/xml" | "application/xml" => {
                request.body = insomnia_value(&body["text"])?;
                request.body_kind = match mime.split(';').next().unwrap_or("") {
                    "application/json" => "json",
                    "text/xml" | "application/xml" => "xml",
                    _ => "text",
                }
                .into();
                if !mime.is_empty()
                    && !request.headers.iter().any(|(key, _, enabled)| {
                        *enabled && key.eq_ignore_ascii_case("content-type")
                    })
                {
                    request
                        .headers
                        .push(("Content-Type".into(), mime.into(), true));
                }
            }
            "application/x-www-form-urlencoded" | "multipart/form-data" => {
                request.body_kind = if mime.split(';').next() == Some("multipart/form-data") {
                    "multipart-form"
                } else {
                    "form-urlencoded"
                }
                .into();
                if body["params"].as_array().is_some_and(|params| {
                    params.iter().any(|param| {
                        param["type"].as_str().is_some_and(|kind| kind != "text")
                            || param.get("fileName").is_some()
                            || param.get("contentType").is_some()
                    })
                }) {
                    return Err(unsupported("Insomnia file uploads or per-part MIME types"));
                }
                request.body_pairs = insomnia_pairs(body.get("params"))?;
                if request.body_pairs.iter().any(|(_, value, _)| {
                    value.contains("@file(") || value.contains("@contentType(")
                }) {
                    return Err(unsupported(
                        "Insomnia text containing Bruno upload annotations",
                    ));
                }
            }
            mime => return Err(unsupported(format!("Insomnia body MIME type '{mime}'"))),
        }
        requests.push(request.render(requests.len() + 1)?);
    }
    Ok(ImportedCollection {
        name,
        requests,
        variables,
    })
}

fn insomnia_ancestors(
    resource: &Value,
    ids: &BTreeMap<&str, &Value>,
    workspace: &str,
) -> Result<Vec<String>> {
    let mut parent = required(resource, "parentId")?;
    let mut names = Vec::new();
    let mut visited = std::collections::BTreeSet::new();
    while parent != workspace {
        if names.len() >= 32 || !visited.insert(parent) {
            return Err(invalid("Insomnia parent cycle or nesting exceeds 32"));
        }
        let resource = ids
            .get(parent)
            .ok_or_else(|| invalid(format!("missing Insomnia parent '{parent}'")))?;
        if resource["_type"] != "request_group" {
            return Err(unsupported(
                "Insomnia parent must be a folder in the selected workspace",
            ));
        }
        names.push(required(resource, "name")?.into());
        parent = required(resource, "parentId")?;
    }
    Ok(names)
}

fn insomnia_pairs(values: Option<&Value>) -> Result<Vec<(String, String, bool)>> {
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    values
        .as_array()
        .ok_or_else(|| invalid("Insomnia name/value entries must be an array"))?
        .iter()
        .map(|value| {
            Ok((
                required(value, "name")?.into(),
                insomnia_value(&value["value"])?,
                value["disabled"] != true,
            ))
        })
        .collect()
}

fn insomnia_value(value: &Value) -> Result<String> {
    let input = scalar(value)?;
    if input.contains("{%") {
        return Err(unsupported("Insomnia template tags"));
    }
    let mut output = String::new();
    let mut rest = input.as_str();
    while let Some((prefix, placeholder)) = rest.split_once("{{") {
        output.push_str(prefix);
        let (name, suffix) = placeholder
            .split_once("}}")
            .ok_or_else(|| invalid("unclosed Insomnia variable"))?;
        let name = name.trim().strip_prefix("_.").unwrap_or(name.trim());
        if name.is_empty()
            || !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Err(unsupported("Insomnia dynamic or nested template variables"));
        }
        output.push_str(&format!("{{{{{name}}}}}"));
        rest = suffix;
    }
    output.push_str(rest);
    Ok(output)
}

fn postman_items(
    node: &Value,
    prefix: &str,
    inherited_variables: &Variables,
    inherited_auth: Option<&Value>,
    requests: &mut Vec<ImportedRequest>,
    depth: usize,
) -> Result<()> {
    if depth > 32 {
        return Err(invalid("Postman folder nesting exceeds 32 levels"));
    }
    if node
        .get("event")
        .is_some_and(|events| !events.as_array().is_some_and(Vec::is_empty))
    {
        return Err(unsupported(
            "Postman scripts and tests; remove event blocks before importing",
        ));
    }
    if node
        .get("protocolProfileBehavior")
        .is_some_and(|value| value.as_object().is_none_or(|object| !object.is_empty()))
    {
        return Err(unsupported("Postman protocol profile behavior"));
    }
    let mut variables = inherited_variables.clone();
    if depth > 0 {
        variables.extend(postman_variables(node)?);
    }
    let auth = node
        .get("auth")
        .filter(|value| !value.is_null())
        .or(inherited_auth);
    let items = node
        .get("item")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Postman collection or folder needs an item array"))?;
    for item in items {
        let name = required(item, "name")?;
        let full_name = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix} / {name}")
        };
        if item.get("request").is_none() {
            postman_items(item, &full_name, &variables, auth, requests, depth + 1)?;
            continue;
        }
        if requests.len() >= MAX_REQUESTS {
            return Err(invalid("import exceeds 10000 requests"));
        }
        if item
            .get("event")
            .is_some_and(|events| !events.as_array().is_some_and(Vec::is_empty))
        {
            return Err(unsupported(format!(
                "Postman scripts or tests in '{full_name}'"
            )));
        }
        let wire = &item["request"];
        if !wire.is_object() {
            return Err(unsupported("Postman string shorthand requests"));
        }
        if wire.get("protocolProfileBehavior").is_some()
            || item.get("protocolProfileBehavior").is_some()
        {
            return Err(unsupported("Postman request protocol profile behavior"));
        }
        let mut request = Request {
            name: full_name,
            method: required(wire, "method")?.into(),
            variables: variables.clone(),
            ..Request::default()
        };
        request.variables.extend(postman_variables(item)?);
        let url = &wire["url"];
        request.url = if let Some(url) = url.as_str() {
            url.to_owned()
        } else {
            required(url, "raw")?.to_owned()
        };
        if url.is_object() {
            if let Some(query) = url.get("query") {
                request.url = request
                    .url
                    .split('?')
                    .next()
                    .unwrap_or(&request.url)
                    .to_owned();
                request.query = postman_pairs(query)?;
            }
            if let Some(path) = url.get("variable") {
                request.path = postman_pairs(path)?;
            }
        }
        if let Some(headers) = wire.get("header").filter(|value| !value.is_null()) {
            request.headers = postman_pairs(headers)?;
        }
        postman_auth(
            wire.get("auth").filter(|value| !value.is_null()).or(auth),
            &mut request,
        )?;
        if let Some(body) = wire.get("body").filter(|value| !value.is_null()) {
            postman_body(body, &mut request)?;
        }
        requests.push(request.render(requests.len() + 1)?);
    }
    Ok(())
}

fn postman_variables(node: &Value) -> Result<Variables> {
    let Some(values) = node.get("variable") else {
        return Ok(Variables::new());
    };
    let mut result = Variables::new();
    for (key, value, enabled) in postman_pairs(values)? {
        if enabled && result.insert(key.clone(), value).is_some() {
            return Err(invalid(format!("duplicate Postman variable '{key}'")));
        }
    }
    Ok(result)
}

fn postman_pairs(values: &Value) -> Result<Vec<(String, String, bool)>> {
    let array = values
        .as_array()
        .ok_or_else(|| invalid("Postman key/value entries must be an array"))?;
    array
        .iter()
        .map(|entry| {
            let key = required(entry, "key")?.to_owned();
            let value = scalar(entry.get("value").unwrap_or(&Value::Null))?;
            let enabled = !entry["disabled"].as_bool().unwrap_or(false);
            Ok((key, value, enabled))
        })
        .collect()
}

fn postman_auth(auth: Option<&Value>, request: &mut Request) -> Result<()> {
    let Some(auth) = auth else {
        return Ok(());
    };
    let kind = required(auth, "type")?;
    request.auth = match kind {
        "noauth" => return Ok(()),
        "basic" | "bearer" | "apikey" => kind.into(),
        "digest" | "awsv4" => {
            postman_credentials(auth, kind, request)?;
            return Ok(());
        }
        _ => return Err(unsupported(format!("Postman authentication '{kind}'"))),
    };
    let pairs: BTreeMap<_, _> = postman_pairs(&auth[kind])?
        .into_iter()
        .map(|(key, value, _)| (key, value))
        .collect();
    let keys: &[(&str, &str)] = match kind {
        "basic" => &[("username", "username"), ("password", "password")],
        "bearer" => &[("token", "token")],
        "apikey" => &[("key", "key"), ("value", "value"), ("in", "placement")],
        _ => &[],
    };
    for (old, new) in keys {
        let value = pairs
            .get(*old)
            .ok_or_else(|| invalid(format!("Postman {kind} auth needs '{old}'")))?;
        let value = if *old == "in" {
            match value.as_str() {
                "header" => "header".into(),
                "query" => "queryparams".into(),
                _ => return Err(unsupported("Postman API key placement")),
            }
        } else {
            value.clone()
        };
        request.auth_pairs.push(((*new).into(), value, true));
    }
    Ok(())
}

fn postman_credentials(auth: &Value, kind: &str, request: &mut Request) -> Result<()> {
    let object = auth
        .as_object()
        .ok_or_else(|| invalid("Postman authentication must be an object"))?;
    if object.keys().any(|key| key != "type" && key != kind) {
        return Err(unsupported(format!(
            "additional Postman {kind} auth options"
        )));
    }
    let keys: &[(&str, &str)] = match kind {
        "digest" => &[("username", "username"), ("password", "password")],
        "awsv4" => &[
            ("accessKey", "accessKeyId"),
            ("secretKey", "secretAccessKey"),
            ("region", "region"),
            ("service", "service"),
            ("sessionToken", "sessionToken"),
        ],
        _ => return Err(unsupported("Postman credential auth type")),
    };
    let entries = auth[kind]
        .as_array()
        .ok_or_else(|| invalid(format!("Postman {kind} auth needs a credential array")))?;
    let mut pairs = BTreeMap::new();
    for entry in entries {
        if entry.as_object().is_none_or(|object| {
            object.keys().any(|key| {
                !["key", "value", "type", "disabled", "description"].contains(&key.as_str())
            })
        }) {
            return Err(unsupported(format!(
                "additional Postman {kind} credential options"
            )));
        }
        let key = required(entry, "key")?;
        if !keys.iter().any(|(old, _)| *old == key) {
            return Err(unsupported(format!(
                "additional Postman {kind} auth options"
            )));
        }
        if entry
            .get("type")
            .is_some_and(|value| value.as_str() != Some("string"))
            || entry
                .get("disabled")
                .is_some_and(|value| value.as_bool() != Some(false))
        {
            return Err(unsupported(format!(
                "non-string or disabled Postman {kind} credentials"
            )));
        }
        let value = entry
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("Postman {kind} credentials need string values")))?;
        if pairs.insert(key, value).is_some() {
            return Err(invalid(format!("duplicate Postman {kind} credential")));
        }
    }
    for (old, new) in keys {
        let Some(value) = pairs.get(old) else {
            if *old == "sessionToken" {
                continue;
            }
            return Err(invalid(format!("Postman {kind} auth needs '{old}'")));
        };
        if kind == "awsv4" && *old != "sessionToken" && value.is_empty() {
            return Err(invalid(format!(
                "Postman {kind} auth needs nonempty '{old}'"
            )));
        }
        if kind == "awsv4"
            && matches!(*old, "region" | "service")
            && !value.contains("{{")
            && !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(invalid(format!(
                "Postman {kind} '{old}' has an invalid format"
            )));
        }
        request
            .auth_pairs
            .push(((*new).into(), (*value).into(), true));
    }
    request.auth = kind.into();
    Ok(())
}

fn postman_body(body: &Value, request: &mut Request) -> Result<()> {
    if body["disabled"].as_bool() == Some(true) {
        return Ok(());
    }
    match required(body, "mode")? {
        "raw" => {
            request.body = body["raw"]
                .as_str()
                .ok_or_else(|| invalid("Postman raw body needs a string"))?
                .into();
            request.body_kind = match body
                .pointer("/options/raw/language")
                .and_then(Value::as_str)
                .unwrap_or("text")
            {
                "json" => "json",
                "xml" => "xml",
                "text" | "javascript" | "html" => "text",
                language => {
                    return Err(unsupported(format!(
                        "Postman raw body language '{language}'"
                    )));
                }
            }
            .into();
        }
        "urlencoded" => {
            request.body_kind = "form-urlencoded".into();
            request.body_pairs = postman_pairs(&body["urlencoded"])?;
        }
        "formdata" => {
            let fields = body["formdata"]
                .as_array()
                .ok_or_else(|| invalid("Postman formdata needs an array"))?;
            if fields.iter().any(|entry| {
                entry["type"].as_str().unwrap_or("text") != "text"
                    || entry.get("contentType").is_some()
            }) {
                return Err(unsupported(
                    "Postman multipart files or per-part content types",
                ));
            }
            request.body_kind = "multipart-form".into();
            request.body_pairs = postman_pairs(&body["formdata"])?;
            if request
                .body_pairs
                .iter()
                .any(|(_, value, _)| value.contains("@file(") || value.contains("@contentType("))
            {
                return Err(unsupported(
                    "multipart text containing Bruno upload annotations",
                ));
            }
        }
        "graphql" => {
            request.body_kind = "graphql".into();
            request.body = required(&body["graphql"], "query")?.into();
            if let Some(variables) = body
                .pointer("/graphql/variables")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                let value: Value = serde_json::from_str(variables)
                    .map_err(|error| invalid(format!("cannot parse GraphQL variables: {error}")))?;
                if !value.is_object() {
                    return Err(invalid("Postman GraphQL variables must be an object"));
                }
                request.graphql_variables = Some(value);
            }
        }
        mode => return Err(unsupported(format!("Postman body mode '{mode}'"))),
    }
    Ok(())
}

fn curl(input: &str) -> Result<ImportedCollection> {
    let words = shlex::split(input).ok_or_else(|| invalid("cannot parse curl quoting"))?;
    if words.first().map(String::as_str) != Some("curl") {
        return Err(invalid(
            "curl import needs one command starting with 'curl'",
        ));
    }
    let mut request = Request {
        name: "Imported curl request".into(),
        method: "GET".into(),
        ..Request::default()
    };
    let mut data = Vec::new();
    let mut explicit_method = false;
    let mut head = false;
    let mut args = words[1..].iter();
    while let Some(word) = args.next() {
        let (flag, inline) = if word.starts_with("--") {
            word.split_once('=')
                .map_or((word.as_str(), None), |(flag, value)| (flag, Some(value)))
        } else {
            (word.as_str(), None)
        };
        match flag {
            "-X" | "--request" | "-H" | "--header" | "-d" | "--data" | "--data-raw"
            | "--data-binary" | "-u" | "--user" | "--url" => {
                let value = inline
                    .or_else(|| args.next().map(String::as_str))
                    .ok_or_else(|| invalid(format!("curl '{flag}' needs a value")))?;
                match flag {
                    "-X" | "--request" => {
                        request.method = value.into();
                        explicit_method = true;
                    }
                    "-H" | "--header" => {
                        if value.starts_with('@') {
                            return Err(unsupported("curl header files"));
                        }
                        let (key, value) = value
                            .split_once(':')
                            .ok_or_else(|| unsupported("curl headers without a colon"))?;
                        request
                            .headers
                            .push((key.trim().into(), value.trim().into(), true));
                    }
                    "-u" | "--user" => {
                        let (username, password) = value
                            .split_once(':')
                            .ok_or_else(|| unsupported("interactive curl passwords"))?;
                        request.auth = "basic".into();
                        request.auth_pairs = vec![
                            ("username".into(), username.into(), true),
                            ("password".into(), password.into(), true),
                        ];
                    }
                    "--url" => {
                        if !request.url.is_empty() {
                            return Err(unsupported("curl multiple URLs"));
                        }
                        request.url = value.into();
                    }
                    _ => {
                        if flag != "--data-raw" && value.starts_with('@') {
                            return Err(unsupported(
                                "curl data files; no local files are read during import",
                            ));
                        }
                        data.push(value.to_owned());
                    }
                }
            }
            "-I" | "--head" => {
                if inline.is_some() {
                    return Err(invalid(format!("curl '{flag}' does not take a value")));
                }
                head = true;
            }
            "-s" | "-S" | "-sS" | "--silent" | "--show-error" | "--compressed" | "-L"
            | "--location" => {
                if inline.is_some() {
                    return Err(invalid(format!("curl '{flag}' does not take a value")));
                }
            }
            _ if word.starts_with('-') => return Err(unsupported(format!("curl option '{flag}'"))),
            _ => {
                if !request.url.is_empty() {
                    return Err(unsupported("curl multiple URLs or shell operators"));
                }
                request.url = word.clone();
            }
        }
    }
    if head {
        if !data.is_empty() {
            return Err(unsupported("curl --head combined with request data"));
        }
        if !explicit_method {
            request.method = "HEAD".into();
        }
    }
    if !data.is_empty() {
        if !explicit_method {
            request.method = "POST".into();
        }
        request.body_kind = "text".into();
        request.body = data.join("&");
        if !request
            .headers
            .iter()
            .any(|(key, _, _)| key.eq_ignore_ascii_case("content-type"))
        {
            request.headers.push((
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
                true,
            ));
        }
    }
    let imported = request.render(1)?;
    Ok(ImportedCollection {
        name: "Imported curl collection".into(),
        requests: vec![imported],
        variables: Variables::new(),
    })
}

fn openapi(document: &Value) -> Result<ImportedCollection> {
    if !required(document, "openapi")?.starts_with("3.") {
        return Err(unsupported("OpenAPI versions other than 3.x"));
    }
    let name = required(&document["info"], "title")?.into();
    let mut requests = Vec::new();
    let paths = document["paths"]
        .as_object()
        .ok_or_else(|| invalid("OpenAPI needs a paths object"))?;
    for (path, path_item) in paths {
        if !path.starts_with('/') {
            return Err(invalid("OpenAPI path must start with '/'"));
        }
        for segment in path.split('/') {
            if segment.contains(['{', '}'])
                && !(segment.starts_with('{')
                    && segment.ends_with('}')
                    && !segment[1..segment.len() - 1].contains(['{', '}']))
            {
                return Err(unsupported(
                    "OpenAPI path parameters inside a partial segment",
                ));
            }
        }
        let path_item = resolve(document, path_item)?;
        for method in [
            "get", "post", "put", "patch", "delete", "head", "options", "trace",
        ] {
            let Some(operation) = path_item.get(method) else {
                continue;
            };
            if requests.len() >= MAX_REQUESTS {
                return Err(invalid("import exceeds 10000 requests"));
            }
            if operation
                .get("callbacks")
                .is_some_and(|value| value.as_object().is_none_or(|object| !object.is_empty()))
            {
                return Err(unsupported("OpenAPI callbacks"));
            }
            let mut request = Request {
                name: operation["summary"]
                    .as_str()
                    .or(operation["operationId"].as_str())
                    .map_or_else(
                        || format!("{} {path}", method.to_uppercase()),
                        str::to_owned,
                    ),
                method: method.into(),
                url: format!(
                    "{}{}",
                    openapi_server(
                        operation
                            .get("servers")
                            .or(path_item.get("servers"))
                            .or(document.get("servers"))
                    )?
                    .trim_end_matches('/'),
                    path
                ),
                ..Request::default()
            };
            let mut parameters = BTreeMap::new();
            for list in [path_item.get("parameters"), operation.get("parameters")]
                .into_iter()
                .flatten()
            {
                for parameter in list
                    .as_array()
                    .ok_or_else(|| invalid("OpenAPI parameters must be an array"))?
                {
                    let parameter = resolve(document, parameter)?;
                    parameters.insert(
                        (
                            required(parameter, "in")?.to_owned(),
                            required(parameter, "name")?.to_owned(),
                        ),
                        parameter,
                    );
                }
            }
            for ((placement, key), parameter) in parameters {
                let schema = resolve(document, &parameter["schema"])?;
                if matches!(schema["type"].as_str(), Some("object" | "array"))
                    || parameter.get("content").is_some()
                    || parameter["allowReserved"].as_bool() == Some(true)
                {
                    return Err(unsupported(
                        "OpenAPI structured parameters or allowReserved",
                    ));
                }
                let default_style = if placement == "query" || placement == "cookie" {
                    "form"
                } else {
                    "simple"
                };
                if parameter["style"]
                    .as_str()
                    .is_some_and(|style| style != default_style)
                {
                    return Err(unsupported("OpenAPI non-default parameter serialization"));
                }
                let explicit_value = parameter
                    .get("example")
                    .or(schema.get("example"))
                    .or(schema.get("default"));
                let value = explicit_value
                    .map(scalar)
                    .transpose()?
                    .unwrap_or_else(|| format!("{{{{{key}}}}}"));
                let enabled =
                    parameter["required"].as_bool() == Some(true) || explicit_value.is_some();
                match placement.as_str() {
                    "path" => {
                        if parameter["required"].as_bool() != Some(true)
                            || !path
                                .split('/')
                                .any(|segment| segment == format!("{{{key}}}"))
                        {
                            return Err(invalid(
                                "OpenAPI path parameters must be required and match a whole path segment",
                            ));
                        }
                        request.url = request
                            .url
                            .replace(&format!("{{{key}}}"), &format!(":{key}"));
                        request.path.push((key, value, true));
                    }
                    "query" => request.query.push((key, value, enabled)),
                    "header" => request.headers.push((key, value, enabled)),
                    _ => {
                        return Err(unsupported(format!(
                            "OpenAPI parameter placement '{placement}'"
                        )));
                    }
                }
            }
            if request.url.contains(['{', '}']) {
                return Err(invalid(
                    "OpenAPI path contains a parameter without a definition",
                ));
            }
            openapi_auth(
                document,
                operation.get("security").or(document.get("security")),
                &mut request,
            )?;
            if let Some(body) = operation.get("requestBody") {
                openapi_body(document, resolve(document, body)?, &mut request)?;
            }
            requests.push(request.render(requests.len() + 1)?);
        }
    }
    Ok(ImportedCollection {
        name,
        requests,
        variables: Variables::new(),
    })
}

fn openapi_server(servers: Option<&Value>) -> Result<String> {
    let server = servers
        .and_then(Value::as_array)
        .and_then(|servers| servers.first())
        .ok_or_else(|| {
            invalid("OpenAPI needs an absolute server URL; add servers before importing")
        })?;
    let mut url = required(server, "url")?.to_owned();
    if let Some(variables) = server.get("variables") {
        for (key, variable) in variables
            .as_object()
            .ok_or_else(|| invalid("OpenAPI server variables must be an object"))?
        {
            url = url.replace(&format!("{{{key}}}"), required(variable, "default")?);
        }
    }
    if url.contains('{') || !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(invalid(
            "OpenAPI server URL must be absolute HTTP or HTTPS with resolved defaults",
        ));
    }
    Ok(url)
}

fn openapi_auth(document: &Value, security: Option<&Value>, request: &mut Request) -> Result<()> {
    let Some(security) = security else {
        return Ok(());
    };
    let alternatives = security
        .as_array()
        .ok_or_else(|| invalid("OpenAPI security must be an array"))?;
    if alternatives.is_empty() {
        return Ok(());
    }
    if alternatives.len() != 1 {
        return Err(unsupported("OpenAPI alternative security requirements"));
    }
    let schemes = alternatives[0]
        .as_object()
        .ok_or_else(|| invalid("OpenAPI security requirement must be an object"))?;
    if schemes.is_empty() {
        return Ok(());
    }
    if schemes.len() != 1 {
        return Err(unsupported("OpenAPI combined security schemes"));
    }
    for key in schemes.keys() {
        let scheme = document
            .pointer("/components/securitySchemes")
            .and_then(|schemes| schemes.get(key))
            .ok_or_else(|| invalid(format!("missing OpenAPI security scheme '{key}'")))?;
        let scheme = resolve(document, scheme)?;
        match (required(scheme, "type")?, scheme["scheme"].as_str()) {
            ("http", Some("basic")) => {
                request.auth = "basic".into();
                request.auth_pairs = vec![
                    ("username".into(), "{{username}}".into(), true),
                    ("password".into(), "{{password}}".into(), true),
                ];
            }
            ("http", Some("bearer")) => {
                request.auth = "bearer".into();
                request
                    .auth_pairs
                    .push(("token".into(), "{{token}}".into(), true));
            }
            ("apiKey", _) => {
                let placement = match required(scheme, "in")? {
                    "header" => "header",
                    "query" => "queryparams",
                    _ => return Err(unsupported("OpenAPI cookie API keys")),
                };
                request.auth = "apikey".into();
                request.auth_pairs = vec![
                    ("key".into(), required(scheme, "name")?.into(), true),
                    ("value".into(), format!("{{{{{key}}}}}"), true),
                    ("placement".into(), placement.into(), true),
                ];
            }
            _ => return Err(unsupported(format!("OpenAPI security scheme '{key}'"))),
        }
    }
    Ok(())
}

fn openapi_body(document: &Value, body: &Value, request: &mut Request) -> Result<()> {
    let content = body["content"]
        .as_object()
        .ok_or_else(|| invalid("OpenAPI request body needs content"))?;
    let (mime, media) = content
        .get_key_value("application/json")
        .or_else(|| content.iter().next())
        .ok_or_else(|| invalid("OpenAPI body content is empty"))?;
    let schema = resolve(document, &media["schema"])?;
    let example = if let Some(example) = media
        .get("example")
        .or(schema.get("example"))
        .or(schema.get("default"))
    {
        example.clone()
    } else if let Some(examples) = media
        .get("examples")
        .and_then(Value::as_object)
        .filter(|examples| !examples.is_empty())
    {
        let example = resolve(
            document,
            examples
                .values()
                .next()
                .ok_or_else(|| invalid("OpenAPI examples are empty"))?,
        )?;
        example
            .get("value")
            .cloned()
            .ok_or_else(|| unsupported("OpenAPI external examples"))?
    } else {
        return Err(unsupported(
            "OpenAPI bodies without an explicit example or default; add an example before importing",
        ));
    };
    if mime == "application/json" || mime.ends_with("+json") {
        request.body_kind = "json".into();
        request.body =
            serde_json::to_string_pretty(&example).map_err(|error| invalid(error.to_string()))?;
    } else if mime.starts_with("text/") || mime == "application/xml" {
        request.body_kind = if mime.contains("xml") { "xml" } else { "text" }.into();
        request.body = example
            .as_str()
            .ok_or_else(|| invalid("OpenAPI text or XML example must be a string"))?
            .into();
    } else {
        return Err(unsupported(format!("OpenAPI body content type '{mime}'")));
    }
    request
        .headers
        .push(("Content-Type".into(), mime.clone(), true));
    Ok(())
}

fn resolve<'document>(
    document: &'document Value,
    mut value: &'document Value,
) -> Result<&'document Value> {
    for _ in 0..32 {
        let Some(reference) = value.get("$ref") else {
            return Ok(value);
        };
        let reference = reference
            .as_str()
            .ok_or_else(|| invalid("OpenAPI $ref must be a string"))?;
        let pointer = reference.strip_prefix("#/").ok_or_else(|| {
            unsupported("OpenAPI external references; resolve them offline before importing")
        })?;
        value = document
            .pointer(&format!("/{pointer}"))
            .ok_or_else(|| invalid(format!("missing OpenAPI reference '{reference}'")))?;
    }
    Err(invalid("OpenAPI reference cycle or depth exceeds 32"))
}

fn dictionary(source: &mut String, name: &str, pairs: &[(String, String, bool)]) -> Result<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    let mut content = String::new();
    for (key, value, enabled) in pairs {
        if key.is_empty() || key.contains(['\r', '\n', '\0']) || value.contains(['\r', '\0']) {
            return Err(invalid(
                "imported dictionary entries contain an invalid key or control character",
            ));
        }
        if value.trim() != value || value.contains('\n') || value.starts_with("'''") || value == "["
        {
            // shortcut: multiline dictionaries cannot represent triple quotes; reject instead of corrupting values.
            if value.contains("'''") {
                return Err(unsupported(
                    "imported dictionary value containing triple quotes",
                ));
            }
            let key = serde_json::to_string(key).map_err(|error| invalid(error.to_string()))?;
            content.push_str(&format!(
                "{}{key}: '''{value}'''\n",
                if *enabled { "" } else { "~" }
            ));
        } else {
            let key = serde_json::to_string(key).map_err(|error| invalid(error.to_string()))?;
            content.push_str(&format!(
                "{}{key}: {value}\n",
                if *enabled { "" } else { "~" }
            ));
        }
    }
    block(source, name, content.trim_end_matches('\n'));
    Ok(())
}

fn block(source: &mut String, name: &str, content: &str) {
    source.push_str(&format!("{name} {{\n"));
    for line in content.split('\n') {
        source.push_str("  ");
        source.push_str(line);
        source.push('\n');
    }
    source.push_str("}\n\n");
}

fn filename(name: &str) -> String {
    let slug: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(80)
        .collect();
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "request".into()
    } else {
        slug.into()
    }
}

fn required<'value>(value: &'value Value, key: &str) -> Result<&'value str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("import needs a nonempty '{key}' string")))
}

fn scalar(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok(String::new()),
        Value::String(value) => Ok(value.clone()),
        Value::Bool(_) | Value::Number(_) => Ok(value.to_string()),
        _ => Err(unsupported("imported object or array dictionary value")),
    }
}

fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid {
        reason: reason.into(),
    }
}
fn unsupported(feature: impl Into<String>) -> Error {
    Error::Unsupported {
        feature: feature.into(),
    }
}
fn io(path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        path: path.to_owned(),
        source,
    }
}
