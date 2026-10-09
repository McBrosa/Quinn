use std::{
    collections::BTreeMap,
    fs,
    future::Future,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use http::{HeaderName, HeaderValue, uri::PathAndQuery};
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};
use reqwest::Url;
use serde_json::Value;
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, protocol::WebSocketConfig,
};
use tonic::{
    Status,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    metadata::{Ascii, Binary, KeyAndValueRef, MetadataKey, MetadataMap, MetadataValue},
    transport::{ClientTlsConfig, Endpoint},
};

use crate::{
    Error, Result,
    bru::{Document, Pair},
    engine::{Response, evaluate_assertion, resolve_auth, validate_assertion},
    selectors::Selector,
    variables::{Variables, interpolate},
};

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn send(
    request: &Document,
    defaults: &[Document],
    variables: &Variables,
    root: &Path,
    timeout: Duration,
) -> Result<Response> {
    let protocol = if request.block("ws").is_some() {
        "ws"
    } else {
        "grpc"
    };
    let method_count = request
        .blocks
        .iter()
        .filter(|block| {
            matches!(
                block.name.as_str(),
                "ws" | "grpc"
                    | "http"
                    | "get"
                    | "post"
                    | "put"
                    | "patch"
                    | "delete"
                    | "options"
                    | "head"
                    | "trace"
                    | "connect"
            )
        })
        .count();
    if method_count != 1 {
        return Err(Error::invalid(
            "request must contain exactly one protocol method block",
        ));
    }
    let documents: Vec<_> = defaults.iter().chain(std::iter::once(request)).collect();
    let mut values = Variables::new();
    for document in &documents {
        validate(document, protocol)?;
        for pair in document
            .pairs("vars:pre-request")?
            .into_iter()
            .filter(|pair| pair.enabled)
        {
            values.insert(pair.key, pair.value);
        }
    }
    values.extend(variables.clone());
    let mut assertions = Vec::new();
    let mut extractions = Vec::new();
    for document in &documents {
        for mut pair in document
            .pairs("assert")?
            .into_iter()
            .filter(|pair| pair.enabled)
        {
            pair.value = interpolate(&pair.value, &values)?;
            validate_assertion(&pair.key, &pair.value)?;
            assertions.push(pair);
        }
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
            extractions.push((pair.key, Selector::parse(&pair.value)?));
        }
    }
    let raw_url = request
        .value(protocol, "url")?
        .ok_or_else(|| Error::invalid("request has no URL"))?;
    let url = interpolate(&raw_url, &values)?;
    let auth = authorization(request, defaults, protocol, &values)?;
    let start = Instant::now();
    let mut response = if protocol == "ws" {
        websocket(request, &documents, &values, url, auth, timeout)?
    } else {
        grpc(request, &documents, &values, root, url, auth, timeout)?
    };
    response.elapsed_ms = start.elapsed().as_millis();
    for pair in assertions {
        response
            .assertions
            .push(evaluate_assertion(pair, &response)?);
    }
    for (name, selector) in extractions {
        if let Some(value) = selector.read(&response) {
            response.variables.insert(name, value);
        } else {
            response.variable_errors.push(format!(
                "cannot extract response variable '{name}': field is missing or body is not JSON"
            ));
        }
    }
    if !response.variable_errors.is_empty() {
        response.variables.clear();
    }
    Ok(response)
}

fn validate(document: &Document, protocol: &str) -> Result<()> {
    for pair in document.pairs(protocol)? {
        let supported = matches!(pair.key.as_str(), "url" | "body" | "auth")
            || (protocol == "grpc"
                && matches!(pair.key.as_str(), "method" | "methodType" | "descriptor"));
        if pair.enabled && !supported {
            return Err(Error::Unsupported {
                feature: format!("{protocol} request field '{}'", pair.key),
            });
        }
    }
    for block in &document.blocks {
        if matches!(
            block.name.as_str(),
            "meta"
                | "docs"
                | "auth"
                | "auth:basic"
                | "auth:bearer"
                | "auth:apikey"
                | "auth:oauth2"
                | "headers"
                | "vars:pre-request"
                | "vars:post-response"
                | "assert"
                | "query"
                | "params:query"
        ) || (protocol == "grpc" && block.name == "metadata")
            || block.name == protocol
            || block.name == format!("body:{protocol}")
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
            feature: format!("{protocol} block '{}'", block.name),
        });
    }
    Ok(())
}

fn authorization(
    request: &Document,
    defaults: &[Document],
    protocol: &str,
    values: &Variables,
) -> Result<Option<String>> {
    let (document, auth) = resolve_auth(request, protocol, defaults)?;
    let value = |key: &str| -> Result<String> {
        let raw = document
            .value(&format!("auth:{auth}"), key)?
            .ok_or_else(|| Error::invalid(format!("{auth} auth has no {key}")))?;
        interpolate(&raw, values)
    };
    match auth.as_str() {
        "none" => Ok(None),
        "bearer" => Ok(Some(format!("Bearer {}", value("token")?))),
        "basic" => Ok(Some(format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", value("username")?, value("password")?))
        ))),
        _ => Err(Error::Unsupported {
            feature: format!("{protocol} authentication '{auth}'; use basic or bearer"),
        }),
    }
}

fn payload(request: &Document, protocol: &str, values: &Variables) -> Result<Option<String>> {
    let body_type = request
        .value(protocol, "body")?
        .unwrap_or_else(|| "none".into());
    if !matches!(body_type.as_str(), "none" | "ws" | "grpc")
        || (body_type != "none" && body_type != protocol)
    {
        return Err(Error::Unsupported {
            feature: format!("{protocol} body type '{body_type}'"),
        });
    }
    let blocks: Vec<_> = request
        .blocks
        .iter()
        .filter(|block| block.name == format!("body:{protocol}"))
        .collect();
    if blocks.len() > 1 {
        return Err(Error::Unsupported {
            feature: format!("multiple {protocol} messages; send one message per request"),
        });
    }
    if body_type == "none" {
        if !blocks.is_empty() {
            return Err(Error::invalid(
                "message body is present but the request body mode is none",
            ));
        }
        return Ok(None);
    }
    let block = blocks
        .first()
        .ok_or_else(|| Error::invalid(format!("request has no body:{protocol} message")))?;
    let mut content = None;
    let mut kind = "text".to_owned();
    for pair in block.pairs()? {
        if !pair.enabled {
            continue;
        }
        match pair.key.as_str() {
            "name" => {}
            "type" => kind = pair.value,
            "content" => content = Some(interpolate(&pair.value, values)?),
            _ => {
                return Err(Error::Unsupported {
                    feature: format!("{protocol} message field '{}'", pair.key),
                });
            }
        }
    }
    let content = content.ok_or_else(|| Error::invalid("message has no content"))?;
    if content.len() > MAX_MESSAGE_BYTES {
        return Err(Error::invalid("message exceeds the 16 MiB limit"));
    }
    if !matches!(kind.as_str(), "text" | "json") {
        return Err(Error::Unsupported {
            feature: format!("{protocol} message type '{kind}'"),
        });
    }
    if protocol == "ws" {
        match kind.as_str() {
            "text" => {}
            "json" => {
                serde_json::from_str::<Value>(&content).map_err(|source| {
                    Error::invalid(format!("invalid WebSocket JSON message: {source}"))
                })?;
            }
            _ => {
                return Err(Error::Unsupported {
                    feature: format!("WebSocket message type '{kind}'"),
                });
            }
        }
    }
    Ok(Some(content))
}

fn websocket(
    request: &Document,
    documents: &[&Document],
    values: &Variables,
    raw_url: String,
    auth: Option<String>,
    timeout: Duration,
) -> Result<Response> {
    let mut url = Url::parse(&raw_url).map_err(|_| Error::invalid("invalid WebSocket URL"))?;
    if !matches!(url.scheme(), "ws" | "wss")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid(
            "WebSocket URL must use ws or wss with no credentials or fragment",
        ));
    }
    for name in ["query", "params:query"] {
        for pair in request.pairs(name)?.into_iter().filter(|pair| pair.enabled) {
            url.query_pairs_mut().append_pair(
                &interpolate(&pair.key, values)?,
                &interpolate(&pair.value, values)?,
            );
        }
    }
    let payload = payload(request, "ws", values)?;
    let mut upgrade = url
        .as_str()
        .into_client_request()
        .map_err(|_| Error::invalid("invalid WebSocket handshake URL"))?;
    for document in documents {
        for pair in document.pairs("headers")? {
            let key = HeaderName::from_bytes(pair.key.as_bytes())
                .map_err(|_| Error::invalid("invalid WebSocket header name"))?;
            if key == "sec-websocket-version" && (!pair.enabled || pair.value == "13") {
                continue;
            }
            if matches!(
                key.as_str(),
                "host" | "connection" | "upgrade" | "sec-websocket-key" | "sec-websocket-version"
            ) {
                return Err(Error::invalid(
                    "WebSocket handshake headers are managed by Quinn",
                ));
            }
            if pair.enabled {
                let value = HeaderValue::from_str(&interpolate(&pair.value, values)?)
                    .map_err(|_| Error::invalid("invalid WebSocket header value"))?;
                upgrade.headers_mut().insert(key, value);
            } else {
                upgrade.headers_mut().remove(key);
            }
        }
    }
    if let Some(auth) = auth {
        let mut value = HeaderValue::from_str(&auth)
            .map_err(|_| Error::invalid("invalid WebSocket authorization"))?;
        value.set_sensitive(true);
        upgrade
            .headers_mut()
            .insert(http::header::AUTHORIZATION, value);
    }
    bounded(timeout, async move {
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES));
        // Never follow a handshake redirect with credentials to another host.
        let (mut socket, handshake) =
            tokio_tungstenite::connect_async_with_config(upgrade, Some(config), true)
                .await
                .map_err(|source| transport(format!("WebSocket connection failed: {source}")))?;
        let mut headers: BTreeMap<_, _> = handshake
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or("<binary>").to_owned(),
                )
            })
            .collect();
        if let Some(payload) = payload {
            socket
                .send(Message::Text(payload.into()))
                .await
                .map_err(|source| transport(format!("WebSocket send failed: {source}")))?;
        }
        loop {
            let message = socket
                .next()
                .await
                .ok_or_else(|| transport("WebSocket closed before a response message"))?
                .map_err(|source| transport(format!("WebSocket receive failed: {source}")))?;
            let (body, bytes, kind) = match message {
                Message::Text(text) => (text.to_string(), text.len(), "text"),
                Message::Binary(bytes) => (STANDARD.encode(&bytes), bytes.len(), "binary-base64"),
                Message::Ping(_) | Message::Pong(_) => {
                    socket.flush().await.map_err(transport)?;
                    continue;
                }
                Message::Close(_) => {
                    return Err(transport("WebSocket closed before a response message"));
                }
                Message::Frame(_) => continue,
            };
            headers.insert("x-quinn-message-type".into(), kind.into());
            // A close write is enough for one-shot operation; do not wait for peer acknowledgement.
            let _ = socket.close(None).await;
            return Ok(response(101, headers, body, bytes));
        }
    })
}

fn grpc(
    request: &Document,
    documents: &[&Document],
    values: &Variables,
    root: &Path,
    raw_url: String,
    auth: Option<String>,
    timeout: Duration,
) -> Result<Response> {
    if request
        .value("grpc", "methodType")?
        .as_deref()
        .is_some_and(|value| value != "unary")
    {
        return Err(Error::Unsupported {
            feature: "streaming gRPC methods".into(),
        });
    }
    for document in documents {
        if !document.pairs("query")?.is_empty() || !document.pairs("params:query")?.is_empty() {
            return Err(Error::Unsupported {
                feature: "gRPC query parameters".into(),
            });
        }
    }
    let url = if let Some(rest) = raw_url.strip_prefix("grpc://") {
        format!("http://{rest}")
    } else if let Some(rest) = raw_url.strip_prefix("grpcs://") {
        format!("https://{rest}")
    } else {
        raw_url
    };
    let parsed_url = Url::parse(&url).map_err(|_| Error::invalid("invalid gRPC URL"))?;
    if !matches!(parsed_url.scheme(), "http" | "https")
        || !parsed_url.username().is_empty()
        || parsed_url.password().is_some()
        || parsed_url.query().is_some()
        || parsed_url.fragment().is_some()
        || parsed_url.path() != "/"
    {
        return Err(Error::invalid(
            "gRPC URL must be an http/https or grpc/grpcs origin with no credentials, path, query, or fragment",
        ));
    }
    let raw_method = request
        .value("grpc", "method")?
        .ok_or_else(|| Error::invalid("gRPC request has no method"))?;
    let method = interpolate(&raw_method, values)?;
    let (service, name) = method
        .strip_prefix('/')
        .and_then(|value| value.split_once('/'))
        .filter(|(service, name)| !service.is_empty() && !name.is_empty() && !name.contains('/'))
        .ok_or_else(|| Error::invalid("gRPC method must be /package.Service/Method"))?;
    let pool = descriptors(request, values, root)?;
    let descriptor = pool
        .services()
        .find(|descriptor| descriptor.full_name() == service)
        .and_then(|service| {
            service
                .methods()
                .find(|descriptor| descriptor.name() == name)
        })
        .ok_or_else(|| {
            Error::invalid("gRPC method is not defined in the configured protobuf files")
        })?;
    if descriptor.is_client_streaming() || descriptor.is_server_streaming() {
        return Err(Error::Unsupported {
            feature: "streaming gRPC methods".into(),
        });
    }
    let payload = payload(request, "grpc", values)?
        .ok_or_else(|| Error::invalid("gRPC unary request needs a body:grpc message"))?;
    let mut json = serde_json::Deserializer::from_str(&payload);
    let message = DynamicMessage::deserialize(descriptor.input(), &mut json)
        .map_err(|source| Error::invalid(format!("invalid protobuf JSON request: {source}")))?;
    json.end()
        .map_err(|source| Error::invalid(format!("invalid protobuf JSON request: {source}")))?;
    if message.encoded_len() > MAX_MESSAGE_BYTES {
        return Err(Error::invalid("protobuf message exceeds the 16 MiB limit"));
    }
    let metadata = metadata(documents, values, auth)?;
    let path =
        PathAndQuery::try_from(method).map_err(|_| Error::invalid("invalid gRPC method path"))?;
    let mut endpoint = Endpoint::from_shared(url)
        .map_err(|_| Error::invalid("invalid gRPC endpoint"))?
        .connect_timeout(timeout)
        .timeout(timeout);
    if parsed_url.scheme() == "https" {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(transport)?;
    }
    let codec = DynamicCodec {
        output: descriptor.output(),
    };
    bounded(timeout, async move {
        let channel = endpoint
            .connect()
            .await
            .map_err(|source| transport(format!("gRPC connection failed: {source}")))?;
        let mut client = tonic::client::Grpc::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);
        client.ready().await.map_err(transport)?;
        let mut request = tonic::Request::new(message);
        *request.metadata_mut() = metadata;
        request.set_timeout(timeout);
        match client.unary(request, path, codec).await {
            Ok(reply) => {
                let mut headers = response_metadata(reply.metadata());
                headers.insert("grpc-status".into(), "0".into());
                let body = serde_json::to_string(reply.get_ref()).map_err(|source| {
                    Error::invalid(format!("cannot encode protobuf JSON response: {source}"))
                })?;
                if body.len() > MAX_MESSAGE_BYTES {
                    return Err(Error::invalid(
                        "protobuf JSON response exceeds the 16 MiB limit",
                    ));
                }
                let bytes = reply.get_ref().encoded_len();
                Ok(response(200, headers, body, bytes))
            }
            Err(status) => {
                let mut headers = response_metadata(status.metadata());
                headers.insert("grpc-status".into(), (status.code() as i32).to_string());
                headers.insert("grpc-message".into(), status.message().to_owned());
                let body =
                    serde_json::json!({"code": status.code() as i32, "message": status.message()})
                        .to_string();
                let bytes = body.len();
                Ok(response(500, headers, body, bytes))
            }
        }
    })
}

fn descriptors(request: &Document, values: &Variables, root: &Path) -> Result<DescriptorPool> {
    if let Some(raw_path) = request.value("grpc", "descriptor")? {
        let path = root.join(interpolate(&raw_path, values)?);
        let bytes = read_limited(&path)?;
        return DescriptorPool::decode(bytes.as_slice()).map_err(|source| {
            Error::invalid(format!("invalid protobuf descriptor set: {source}"))
        });
    }
    let path = root.join("bruno.json");
    let source = read_limited(&path)?;
    let config: Value = serde_json::from_slice(&source)
        .map_err(|source| Error::invalid(format!("invalid bruno.json: {source}")))?;
    let protobuf = &config["protobuf"];
    let proto_files = protobuf["protoFiles"].as_array().ok_or_else(|| {
        Error::invalid(
            "configure protobuf.protoFiles in bruno.json or grpc descriptor in the request",
        )
    })?;
    let mut files = Vec::new();
    let mut includes = Vec::new();
    if let Some(paths) = protobuf["importPaths"].as_array() {
        for path in paths.iter().filter(|path| path["enabled"] != false) {
            let path = path["path"]
                .as_str()
                .ok_or_else(|| Error::invalid("protobuf import directory has no path"))?;
            includes.push(root.join(path));
        }
    }
    for file in proto_files {
        if file["enabled"] == false {
            continue;
        }
        if file["type"].as_str().is_some_and(|kind| kind != "file") {
            return Err(Error::Unsupported {
                feature: "protobuf directory imports; list individual .proto files".into(),
            });
        }
        let path = file["path"]
            .as_str()
            .ok_or_else(|| Error::invalid("protobuf file has no path"))?;
        let path = root.join(path);
        if let Some(parent) = path.parent() {
            includes.push(parent.to_path_buf());
        }
        files.push(path);
    }
    if files.is_empty() {
        return Err(Error::invalid("no enabled protobuf files are configured"));
    }
    includes.push(root.to_path_buf());
    let descriptors = protox::compile(files, includes)
        .map_err(|source| Error::invalid(format!("cannot compile protobuf files: {source}")))?;
    DescriptorPool::from_file_descriptor_set(descriptors)
        .map_err(|source| Error::invalid(format!("invalid protobuf descriptors: {source}")))
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|source| Error::io(path, source))?;
    let mut bytes = Vec::new();
    file.take((MAX_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::io(path, source))?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::invalid(
            "protobuf configuration exceeds the 16 MiB limit",
        ));
    }
    Ok(bytes)
}

fn metadata(
    documents: &[&Document],
    values: &Variables,
    auth: Option<String>,
) -> Result<MetadataMap> {
    let mut metadata = MetadataMap::new();
    for document in documents {
        for block in ["headers", "metadata"] {
            for Pair {
                key,
                value,
                enabled,
                is_list: _,
            } in document.pairs(block)?
            {
                if key.starts_with("grpc-")
                    || matches!(key.as_str(), "te" | "content-type" | "host")
                {
                    return Err(Error::invalid(
                        "gRPC transport metadata is managed by Quinn",
                    ));
                }
                if key.ends_with("-bin") {
                    let key = MetadataKey::<Binary>::from_bytes(key.as_bytes())
                        .map_err(|_| Error::invalid("invalid binary gRPC metadata key"))?;
                    if enabled {
                        let value = interpolate(&value, values)?;
                        // Bruno binary metadata values are UTF-8 content, not pre-encoded base64.
                        metadata.insert_bin(key, MetadataValue::from_bytes(value.as_bytes()));
                    } else {
                        metadata.remove_bin(key);
                    }
                } else {
                    let key = MetadataKey::<Ascii>::from_bytes(key.as_bytes())
                        .map_err(|_| Error::invalid("invalid gRPC metadata key"))?;
                    if enabled {
                        let value = MetadataValue::try_from(interpolate(&value, values)?)
                            .map_err(|_| Error::invalid("invalid gRPC metadata value"))?;
                        metadata.insert(key, value);
                    } else {
                        metadata.remove(key);
                    }
                }
            }
        }
    }
    if let Some(auth) = auth {
        let mut value = MetadataValue::try_from(auth)
            .map_err(|_| Error::invalid("invalid gRPC authorization"))?;
        value.set_sensitive(true);
        metadata.insert("authorization", value);
    }
    Ok(metadata)
}

fn response_metadata(metadata: &MetadataMap) -> BTreeMap<String, String> {
    metadata
        .iter()
        .map(|entry| match entry {
            KeyAndValueRef::Ascii(key, value) => (
                key.to_string(),
                value.to_str().unwrap_or("<binary>").to_owned(),
            ),
            KeyAndValueRef::Binary(key, value) => (
                key.to_string(),
                value
                    .to_bytes()
                    .map(|bytes| STANDARD.encode(bytes))
                    .unwrap_or_else(|_| "<invalid binary>".into()),
            ),
        })
        .collect()
}

fn response(
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
    bytes: usize,
) -> Response {
    Response {
        status,
        headers,
        body,
        bytes,
        elapsed_ms: 0,
        assertions: Vec::new(),
        variables: Variables::new(),
        variable_errors: Vec::new(),
    }
}

fn bounded<F>(timeout: Duration, future: F) -> Result<Response>
where
    F: Future<Output = Result<Response>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(transport)?;
    runtime.block_on(async {
        tokio::time::timeout(timeout, future)
            .await
            .map_err(|_| transport("protocol request timed out"))?
    })
}

fn transport(reason: impl std::fmt::Display) -> Error {
    Error::Http {
        reason: reason.to_string(),
    }
}

struct DynamicCodec {
    output: MessageDescriptor,
}
struct DynamicEncoder;
struct DynamicDecoder {
    output: MessageDescriptor,
}

impl Codec for DynamicCodec {
    type Encode = DynamicMessage;
    type Decode = DynamicMessage;
    type Encoder = DynamicEncoder;
    type Decoder = DynamicDecoder;
    fn encoder(&mut self) -> Self::Encoder {
        DynamicEncoder
    }
    fn decoder(&mut self) -> Self::Decoder {
        DynamicDecoder {
            output: self.output.clone(),
        }
    }
}

impl Encoder for DynamicEncoder {
    type Item = DynamicMessage;
    type Error = Status;
    fn encode(
        &mut self,
        item: DynamicMessage,
        dst: &mut EncodeBuf<'_>,
    ) -> std::result::Result<(), Status> {
        item.encode(dst)
            .map_err(|source| Status::internal(format!("cannot encode protobuf message: {source}")))
    }
}

impl Decoder for DynamicDecoder {
    type Item = DynamicMessage;
    type Error = Status;
    fn decode(
        &mut self,
        src: &mut DecodeBuf<'_>,
    ) -> std::result::Result<Option<DynamicMessage>, Status> {
        DynamicMessage::decode(self.output.clone(), src)
            .map(Some)
            .map_err(|source| Status::internal(format!("cannot decode protobuf message: {source}")))
    }
}
