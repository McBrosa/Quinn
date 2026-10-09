use std::{
    collections::BTreeMap,
    io::Read,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{
    Method, Url,
    blocking::Client,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    Error, Result,
    aws::Signing,
    bru::{Document, Pair},
    digest,
    network::NetworkOptions,
    oauth::{TokenCache, TokenRequest},
    scripts,
    selectors::Selector,
    uploads,
    variables::{Variables, interpolate},
};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "connect", "trace", "http",
];

#[derive(Clone, Debug, Serialize)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub bytes: usize,
    pub elapsed_ms: u128,
    pub assertions: Vec<Assertion>,
    #[serde(skip_serializing)]
    pub variables: Variables,
    pub variable_errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Assertion {
    pub expression: String,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
}

pub struct Engine {
    client: Client,
    token_client: Client,
    digest_client: Client,
    timeout: Duration,
    custom_network: bool,
    token_cache: TokenCache,
}

impl Engine {
    pub fn new(timeout: Duration) -> Result<Self> {
        Self::with_network(timeout, &NetworkOptions::default())
    }

    /// Build an HTTP engine with explicit proxy and TLS configuration.
    pub fn with_network(timeout: Duration, options: &NetworkOptions) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::invalid("timeout must be greater than zero"));
        }
        let prepared = options.prepare()?;
        let redirects = if options.max_redirects == 0 {
            reqwest::redirect::Policy::none()
        } else {
            reqwest::redirect::Policy::limited(options.max_redirects)
        };
        let cookies = Arc::new(reqwest::cookie::Jar::default());
        let client = prepared
            .builder(timeout)
            .cookie_provider(cookies.clone())
            .user_agent(concat!("Quinn/", env!("CARGO_PKG_VERSION")))
            .redirect(redirects)
            .build()
            .map_err(Error::http)?;
        let token_client = prepared
            .builder(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(Error::http)?;
        let digest_client = prepared
            .builder(timeout)
            .cookie_provider(cookies)
            .user_agent(concat!("Quinn/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(Error::http)?;
        Ok(Self {
            client,
            token_client,
            digest_client,
            timeout,
            custom_network: options.is_custom(),
            token_cache: TokenCache::default(),
        })
    }

    /// Clear cached OAuth tokens and require acquisition on the next request.
    pub fn clear_oauth_tokens(&self) -> Result<()> {
        self.token_cache.clear()
    }

    /// Run one request with collection and folder defaults and environment variables.
    pub fn send(
        &self,
        request: &Document,
        defaults: &[Document],
        variables: &Variables,
    ) -> Result<Response> {
        let root = std::env::current_dir().map_err(|source| Error::io(Path::new("."), source))?;
        self.send_in(request, defaults, variables, &root)
    }

    /// Run a request with upload paths relative to the given collection root.
    pub fn send_in(
        &self,
        request: &Document,
        defaults: &[Document],
        variables: &Variables,
        root: &Path,
    ) -> Result<Response> {
        if request.block("ws").is_some() || request.block("grpc").is_some() {
            if self.custom_network {
                return Err(Error::Unsupported {
                    feature: "custom network options for gRPC and WebSockets".into(),
                });
            }
            return crate::protocols::send(request, defaults, variables, root, self.timeout);
        }
        let documents: Vec<&Document> = defaults.iter().chain(std::iter::once(request)).collect();
        for document in &documents {
            validate(document)?;
        }
        let mut all_variables = Variables::new();
        for document in &documents {
            for pair in document
                .pairs("vars:pre-request")?
                .into_iter()
                .filter(|pair| pair.enabled)
            {
                all_variables.insert(pair.key, pair.value);
            }
        }
        all_variables.extend(variables.clone());
        let method_block = METHODS
            .iter()
            .find(|name| request.block(name).is_some())
            .ok_or_else(|| Error::invalid("request has no HTTP method block"))?;
        let pre = scripts::run(
            &documents,
            &["script:pre-request"],
            request,
            method_block,
            &all_variables,
            None,
        )?;
        all_variables.extend(pre.variables.clone());
        let request = &pre.request;
        let documents: Vec<&Document> = defaults.iter().chain(std::iter::once(request)).collect();
        let methods: Vec<_> = METHODS
            .iter()
            .filter_map(|name| request.block(name))
            .collect();
        if methods.len() != 1 {
            return Err(Error::invalid(
                "request must contain exactly one HTTP method block",
            ));
        }
        let block = methods[0];
        let method = if block.name == "http" {
            request
                .value("http", "method")?
                .ok_or_else(|| Error::invalid("custom HTTP request has no method"))?
        } else {
            block.name.to_uppercase()
        };
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| Error::invalid("invalid HTTP method"))?;
        let raw_url = request
            .value(&block.name, "url")?
            .ok_or_else(|| Error::invalid("request has no URL"))?;
        let mut expanded_url = interpolate(&raw_url, &all_variables)?;
        for pair in request
            .pairs("params:path")?
            .into_iter()
            .filter(|pair| pair.enabled)
        {
            let value = interpolate(&pair.value, &all_variables)?;
            let encoded = utf8_percent_encode(&value, NON_ALPHANUMERIC).to_string();
            // Match whole path segments, never a substring such as :id in :identity.
            expanded_url = replace_path_parameter(&expanded_url, &pair.key, &encoded)?;
        }
        let mut url = Url::parse(&expanded_url)
            .map_err(|source| Error::invalid(format!("invalid URL: {source}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::invalid("URL scheme must be http or https"));
        }
        let (auth_document, auth) = resolve_auth(request, &block.name, defaults)?;
        for name in ["query", "params:query"] {
            for pair in request.pairs(name)?.into_iter().filter(|pair| pair.enabled) {
                let key = interpolate(&pair.key, &all_variables)?;
                let value = interpolate(&pair.value, &all_variables)?;
                if auth == "awsv4" {
                    crate::aws::append_query(&mut url, &key, &value);
                } else {
                    url.query_pairs_mut().append_pair(&key, &value);
                }
            }
        }
        let mut headers = HeaderMap::new();
        for document in &documents {
            for pair in document.pairs("headers")? {
                let name = HeaderName::from_bytes(pair.key.as_bytes())
                    .map_err(|_| Error::invalid(format!("invalid header name '{}'", pair.key)))?;
                if !pair.enabled {
                    headers.remove(name);
                    continue;
                }
                let expanded = interpolate(&pair.value, &all_variables)?;
                let value = HeaderValue::from_str(&expanded).map_err(|_| {
                    Error::invalid(format!("invalid value for header '{}'", pair.key))
                })?;
                headers.insert(name, value);
            }
        }
        let client = if matches!(auth.as_str(), "digest" | "awsv4") {
            &self.digest_client
        } else {
            &self.client
        };
        let mut builder = client.request(method, url.clone());
        let auth_value = |key: &str| -> Result<String> {
            let value = auth_document
                .value(&format!("auth:{auth}"), key)?
                .ok_or_else(|| Error::invalid(format!("{auth} auth has no {key}")))?;
            interpolate(&value, &all_variables)
        };
        let mut oauth = None;
        let mut digest = None;
        let mut aws = None;
        match auth.as_str() {
            "none" => {}
            "basic" => {
                builder = builder.basic_auth(auth_value("username")?, Some(auth_value("password")?))
            }
            "bearer" => builder = builder.bearer_auth(auth_value("token")?),
            "digest" => {
                if headers.contains_key(AUTHORIZATION)
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    return Err(Error::invalid(
                        "Digest auth cannot combine with an Authorization header or URL credentials",
                    ));
                }
                for pair in auth_document.pairs("auth:digest")? {
                    if pair.enabled && !matches!(pair.key.as_str(), "username" | "password") {
                        return Err(Error::Unsupported {
                            feature: format!("Digest field '{}'", pair.key),
                        });
                    }
                }
                digest = Some((auth_value("username")?, auth_value("password")?));
            }
            "oauth2" => oauth = Some(TokenRequest::prepare(auth_document, &all_variables)?),
            "awsv4" => {
                let signing = Signing::prepare(auth_document, &all_variables)?;
                signing.validate_url(&expanded_url, &url)?;
                aws = Some(signing);
            }
            "apikey" => {
                let key = auth_value("key")?;
                let value = auth_value("value")?;
                match auth_value("placement")?.as_str() {
                    "header" => {
                        let name = HeaderName::from_bytes(key.as_bytes())
                            .map_err(|_| Error::invalid("invalid API key header name"))?;
                        let value = HeaderValue::from_str(&value)
                            .map_err(|_| Error::invalid("invalid API key header value"))?;
                        headers.insert(name, value);
                    }
                    "queryparams" | "query" => builder = builder.query(&[(key, value)]),
                    placement => {
                        return Err(Error::Unsupported {
                            feature: format!("API key placement '{placement}'"),
                        });
                    }
                }
            }
            _ => {
                return Err(Error::Unsupported {
                    feature: format!("authentication '{auth}'"),
                });
            }
        }
        let body_type = request
            .value(&block.name, "body")?
            .unwrap_or_else(|| "none".into());
        if (digest.is_some() || aws.is_some())
            && matches!(
                body_type.as_str(),
                "file" | "multipartForm" | "multipart-form"
            )
        {
            return Err(Error::Unsupported {
                feature: format!("{auth} authentication with streaming file or multipart bodies"),
            });
        }
        match body_type.as_str() {
            "none" => {}
            "json" | "text" | "xml" | "sparql" => {
                let body = request
                    .block(&format!("body:{body_type}"))
                    .or_else(|| request.block("body"))
                    .ok_or_else(|| {
                        Error::invalid(format!("request has no {body_type} body block"))
                    })?;
                let expanded = interpolate(&body.content, &all_variables)?;
                let content_type = match body_type.as_str() {
                    "json" => {
                        serde_json::from_str::<Value>(&expanded).map_err(|source| {
                            Error::invalid(format!("invalid JSON body: {source}"))
                        })?;
                        "application/json"
                    }
                    "xml" => "application/xml",
                    "sparql" => "application/sparql-query",
                    _ => "text/plain",
                };
                headers
                    .entry(CONTENT_TYPE)
                    .or_insert(HeaderValue::from_static(content_type));
                builder = builder.body(expanded);
            }
            "formUrlEncoded" | "form-urlencoded" => {
                let pairs = expanded_pairs(request.pairs("body:form-urlencoded")?, &all_variables)?;
                builder = builder.form(&pairs);
            }
            "multipartForm" | "multipart-form" => {
                let pairs = request.pairs("body:multipart-form")?;
                let form = uploads::multipart(pairs, root, &all_variables)?;
                headers.remove(CONTENT_TYPE);
                builder = builder.multipart(form);
            }
            "file" => {
                let pairs = request.pairs("body:file")?;
                let (body, content_type) = uploads::binary(pairs, root, &all_variables)?;
                let content_type = HeaderValue::from_str(&content_type)
                    .map_err(|_| Error::invalid("invalid upload content type"))?;
                headers.entry(CONTENT_TYPE).or_insert(content_type);
                builder = builder.body(body);
            }
            "graphql" => {
                let query = request
                    .block("body:graphql")
                    .ok_or_else(|| Error::invalid("request has no GraphQL query"))?;
                let query = interpolate(&query.content, &all_variables)?;
                let graphql_variables = request.block("body:graphql:vars").map_or(
                    Ok(Value::Object(Default::default())),
                    |block| {
                        let expanded = interpolate(&block.content, &all_variables)?;
                        serde_json::from_str::<Value>(&expanded).map_err(|source| {
                            Error::invalid(format!("invalid GraphQL variables: {source}"))
                        })
                    },
                )?;
                if !graphql_variables.is_object() {
                    return Err(Error::invalid("GraphQL variables must be a JSON object"));
                }
                headers
                    .entry(CONTENT_TYPE)
                    .or_insert(HeaderValue::from_static("application/json"));
                builder = builder
                    .json(&serde_json::json!({"query": query, "variables": graphql_variables}));
            }
            _ => {
                return Err(Error::Unsupported {
                    feature: format!("body type '{body_type}'"),
                });
            }
        }
        let mut assertions: Vec<_> = documents
            .iter()
            .map(|doc| doc.pairs("assert"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .filter(|pair| pair.enabled)
            .collect();
        // Validate all assertions before sending a request with possible side effects.
        for pair in &mut assertions {
            pair.value = interpolate(&pair.value, &all_variables)?;
            validate_assertion(&pair.key, &pair.value)?;
        }
        let mut extractions = Vec::new();
        for document in &documents {
            for pair in document
                .pairs("vars:post-response")?
                .into_iter()
                .filter(|pair| pair.enabled)
            {
                if pair.key.starts_with('@') {
                    return Err(Error::Unsupported {
                        feature: "persistent post-response variables".into(),
                    });
                }
                let selector = Selector::parse(&pair.value)?;
                extractions.push((pair.key, selector));
            }
        }
        let mut builder = builder.headers(headers);
        if let Some(oauth) = oauth {
            builder = builder.header(
                AUTHORIZATION,
                self.token_cache.fetch(oauth, &self.token_client)?,
            );
        }
        let start = Instant::now();
        let mut raw_response = if let Some(aws) = aws {
            let mut request = builder.build().map_err(Error::http)?;
            aws.sign(&mut request)?;
            self.digest_client.execute(request).map_err(Error::http)?
        } else if let Some((username, password)) = digest {
            digest::send(
                &self.digest_client,
                builder.build().map_err(Error::http)?,
                &username,
                &password,
                self.timeout,
            )?
        } else {
            builder.send().map_err(Error::http)?
        };
        let status = raw_response.status().as_u16();
        let headers = raw_response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or("<binary>").to_owned(),
                )
            })
            .collect();
        let mut bytes = Vec::new();
        raw_response
            .by_ref()
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| Error::Http {
                reason: source.to_string(),
            })?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(Error::invalid("response exceeds the 16 MiB limit"));
        }
        let mut response = Response {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
            bytes: bytes.len(),
            elapsed_ms: start.elapsed().as_millis(),
            assertions: pre.assertions,
            variables: pre.variables,
            variable_errors: Vec::new(),
        };
        for pair in assertions {
            response
                .assertions
                .push(evaluate_assertion(pair, &response)?);
        }
        for (name, selector) in extractions {
            match selector.read(&response) {
                Some(value) => { response.variables.insert(name, value); },
                None => response.variable_errors.push(format!("cannot extract response variable '{name}': field is missing or body is not JSON")),
            }
        }
        all_variables.extend(response.variables.clone());
        match scripts::run(
            &documents,
            &["script:post-response", "tests"],
            request,
            &block.name,
            &all_variables,
            Some(&response),
        ) {
            Ok(post) => {
                response.variables.extend(post.variables);
                response.assertions.extend(post.assertions);
            }
            Err(error) => response.variable_errors.push(error.to_string()),
        }
        if !response.variable_errors.is_empty()
            || response
                .assertions
                .iter()
                .any(|assertion| !assertion.passed)
        {
            response.variables.clear();
        }
        Ok(response)
    }
}

impl Response {
    pub fn passed(&self) -> bool {
        self.status < 400
            && self.assertions.iter().all(|assertion| assertion.passed)
            && self.variable_errors.is_empty()
    }

    pub fn pretty_body(&self) -> String {
        serde_json::from_str::<Value>(&self.body)
            .and_then(|value| serde_json::to_string_pretty(&value))
            .unwrap_or_else(|_| self.body.clone())
    }
}

fn validate(document: &Document) -> Result<()> {
    scripts::validate(document)?;
    for block in &document.blocks {
        if METHODS.contains(&block.name.as_str())
            || matches!(
                block.name.as_str(),
                "meta"
                    | "docs"
                    | "headers"
                    | "auth"
                    | "auth:basic"
                    | "auth:digest"
                    | "auth:awsv4"
                    | "auth:bearer"
                    | "auth:apikey"
                    | "auth:oauth2"
                    | "params:query"
                    | "params:path"
                    | "query"
                    | "vars:pre-request"
                    | "vars:post-response"
                    | "assert"
                    | "body"
                    | "body:json"
                    | "body:text"
                    | "body:xml"
                    | "body:sparql"
                    | "body:form-urlencoded"
                    | "body:multipart-form"
                    | "body:file"
                    | "body:graphql"
                    | "body:graphql:vars"
                    | "script:pre-request"
                    | "script:post-response"
                    | "tests"
            )
        {
            continue;
        }
        if matches!(
            block.name.as_str(),
            "script:pre-request" | "script:post-response" | "tests"
        ) && block.content.trim().is_empty()
        {
            continue;
        }
        return Err(Error::Unsupported {
            feature: format!("block '{}'", block.name),
        });
    }
    Ok(())
}

pub(crate) fn resolve_auth<'doc>(
    request: &'doc Document,
    method: &str,
    defaults: &'doc [Document],
) -> Result<(&'doc Document, String)> {
    let auth = request
        .value(method, "auth")?
        .unwrap_or_else(|| "none".into());
    if auth != "inherit" {
        return Ok((request, auth));
    }
    for document in defaults.iter().rev() {
        if let Some(mode) = document.value("auth", "mode")?
            && mode != "inherit"
        {
            return Ok((document, mode));
        }
    }
    Ok((request, "none".into()))
}

fn expanded_pairs(pairs: Vec<Pair>, variables: &Variables) -> Result<Vec<(String, String)>> {
    pairs
        .into_iter()
        .filter(|pair| pair.enabled)
        .map(|pair| {
            Ok((
                interpolate(&pair.key, variables)?,
                interpolate(&pair.value, variables)?,
            ))
        })
        .collect()
}

fn replace_path_parameter(url: &str, key: &str, value: &str) -> Result<String> {
    let prefix_end = url
        .find("://")
        .ok_or_else(|| Error::invalid("URL has no scheme"))?
        + 3;
    let Some(path_offset) = url[prefix_end..].find('/') else {
        return Ok(url.to_owned());
    };
    let path_start = prefix_end + path_offset;
    let path_end = url[path_start..]
        .find(['?', '#'])
        .map_or(url.len(), |offset| path_start + offset);
    let marker = format!(":{key}");
    let segments: Vec<_> = url[path_start..path_end]
        .split('/')
        .map(|segment| if segment == marker { value } else { segment })
        .collect();
    Ok(format!(
        "{}{}{}",
        &url[..path_start],
        segments.join("/"),
        &url[path_end..]
    ))
}

pub(crate) fn validate_assertion(expression: &str, expected: &str) -> Result<()> {
    Selector::parse(expression)?;
    let operator = expected.split_whitespace().next().unwrap_or("");
    if !matches!(
        operator,
        "eq" | "neq"
            | "gt"
            | "gte"
            | "lt"
            | "lte"
            | "contains"
            | "notContains"
            | "exists"
            | "notExists"
            | "isJson"
    ) {
        return Err(Error::Unsupported {
            feature: format!("assertion operator '{operator}'; use 'eq VALUE' for equality"),
        });
    }
    Ok(())
}

pub(crate) fn evaluate_assertion(pair: Pair, response: &Response) -> Result<Assertion> {
    let Pair {
        key,
        value,
        enabled: _,
        is_list: _,
    } = pair;
    let (operator, expected) = value
        .split_once(char::is_whitespace)
        .unwrap_or((&value, ""));
    let expected = expected.trim();
    let actual = Selector::parse(&key)?.read(response);
    let passed = match operator {
        "exists" => actual.is_some(),
        "notExists" => actual.is_none(),
        "isJson" => actual
            .as_deref()
            .is_some_and(|value| serde_json::from_str::<Value>(value).is_ok()),
        _ => actual.as_deref().is_some_and(|actual| match operator {
            "eq" => actual == expected,
            "neq" => actual != expected,
            "contains" => actual.contains(expected),
            "notContains" => !actual.contains(expected),
            _ => actual
                .parse::<f64>()
                .ok()
                .zip(expected.parse::<f64>().ok())
                .is_some_and(|(actual, expected)| match operator {
                    "gt" => actual > expected,
                    "gte" => actual >= expected,
                    "lt" => actual < expected,
                    "lte" => actual <= expected,
                    _ => false,
                }),
        }),
    };
    Ok(Assertion {
        expression: key,
        expected: value,
        actual: actual.unwrap_or_else(|| "<missing>".into()),
        passed,
    })
}
