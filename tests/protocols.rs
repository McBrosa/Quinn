#![allow(clippy::unwrap_used, clippy::expect_used, clippy::result_large_err)]

use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::Duration,
};

use bytes::Bytes;
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage};
use quinn_api::{bru::Document, engine::Engine, variables::Variables};
use serde_json::Value;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer},
};
use tokio_tungstenite::tungstenite::{
    Message, accept_hdr,
    handshake::server::{Request, Response},
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/protocols")
}
fn engine(timeout: Duration) -> Engine {
    Engine::new(timeout).unwrap()
}

fn websocket_server(binary: bool) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}/echo", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let callback = |request: &Request, response: Response| {
            assert_eq!(request.uri().query(), Some("token=a%26b"));
            assert_eq!(request.headers()["authorization"], "Bearer test-token");
            assert_eq!(request.headers()["x-test"], "inherited");
            Ok(response)
        };
        let mut socket = accept_hdr(stream, callback).unwrap();
        assert_eq!(socket.read().unwrap().into_text().unwrap(), "hello Quinn");
        if binary {
            socket
                .send(Message::Binary(vec![0, 255, 128].into()))
                .unwrap();
        } else {
            socket
                .send(Message::Text("{\"reply\":\"hello Quinn\"}".into()))
                .unwrap();
        }
        let _ = socket.read();
    });
    (url, worker)
}

fn websocket_request(url: &str) -> Document {
    Document::parse(&format!("ws {{\n  url: {url}\n  body: ws\n  auth: bearer\n}}\nauth:bearer {{\n  token: test-token\n}}\nparams:query {{\n  token: a&b\n}}\nbody:ws {{\n  name: message 1\n  type: text\n  content: hello {{{{name}}}}\n}}\n")).unwrap()
}

#[test]
fn websocket_exchange_inherits_headers_expands_variables_and_extracts_response() {
    let (url, server) = websocket_server(false);
    let mut request = websocket_request(&url);
    request.blocks.extend(Document::parse("assert {\n  res.status: eq 101\n  res.body.reply: eq hello Quinn\n}\nvars:post-response {\n  reply: res.body.reply\n}\n").unwrap().blocks);
    let defaults = vec![Document::parse("headers {\n  x-test: inherited\n}\n").unwrap()];
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let response = engine(Duration::from_secs(5))
        .send(&request, &defaults, &values)
        .unwrap();
    assert!(response.passed());
    assert_eq!(response.variables["reply"], "hello Quinn");
    assert_eq!(response.headers["x-quinn-message-type"], "text");
    server.join().unwrap();
}

#[test]
fn websocket_binary_response_is_base64_not_lossy_text() {
    let (url, server) = websocket_server(true);
    let request = websocket_request(&url);
    let defaults = vec![Document::parse("headers {\n  x-test: inherited\n}\n").unwrap()];
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let response = engine(Duration::from_secs(5))
        .send(&request, &defaults, &values)
        .unwrap();
    assert_eq!(response.body, "AP+A");
    assert_eq!(response.bytes, 3);
    assert_eq!(response.headers["x-quinn-message-type"], "binary-base64");
    server.join().unwrap();
}

#[test]
fn failed_websocket_assertion_preserves_response_but_publishes_no_variables() {
    let (url, server) = websocket_server(false);
    let mut request = websocket_request(&url);
    request.blocks.extend(Document::parse("assert {\n  res.body.reply: eq wrong value\n}\nvars:post-response {\n  reply: res.body.reply\n}\n").unwrap().blocks);
    let defaults = vec![Document::parse("headers {\n  x-test: inherited\n}\n").unwrap()];
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let response = engine(Duration::from_secs(5))
        .send(&request, &defaults, &values)
        .unwrap();
    assert!(!response.passed());
    assert_eq!(response.body, "{\"reply\":\"hello Quinn\"}");
    assert!(response.variables.is_empty());
    assert!(response.variable_errors.is_empty());
    assert_eq!(values["name"], "Quinn");
    server.join().unwrap();
}

fn untrusted_tls_server() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    // Use the same automatically selected crypto provider as the client dependency graph.
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key.into())
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let error = acceptor
                    .accept(stream)
                    .await
                    .expect_err("client accepted an untrusted certificate");
                let reason = error.to_string().to_lowercase();
                assert!(
                    reason.contains("certificate") || reason.contains("unknownca"),
                    "{error}"
                );
            })
            .await
            .expect("TLS server did not shut down within five seconds");
        });
    });
    (address, worker)
}

#[test]
fn websocket_rejects_an_untrusted_local_tls_certificate() {
    let (address, server) = untrusted_tls_server();
    let request = Document::parse(&format!(
        "ws {{\n  url: wss://{address}/echo\n  body: none\n}}\n"
    ))
    .unwrap();
    let error = engine(Duration::from_secs(5))
        .send(&request, &[], &Variables::new())
        .unwrap_err();
    let reason = error.to_string().to_lowercase();
    assert!(
        reason.contains("certificate") || reason.contains("unknownissuer"),
        "{error}"
    );
    assert!(!reason.contains("timed out"), "{error}");
    server.join().unwrap();
}

#[test]
fn grpc_rejects_an_untrusted_local_tls_certificate() {
    let (address, server) = untrusted_tls_server();
    let request = grpc_request(&format!("https://{address}"));
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let error = engine(Duration::from_secs(5))
        .send_in(&request, &[], &values, &fixtures())
        .unwrap_err();
    assert!(matches!(error, quinn_api::Error::Http { .. }), "{error}");
    assert!(
        error.to_string().contains("gRPC connection failed"),
        "{error}"
    );
    assert!(!error.to_string().contains("timed out"), "{error}");
    server.join().unwrap();
}

#[test]
fn websocket_timeout_covers_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let request = Document::parse(&format!(
        "ws {{\n  url: ws://{}\n  body: none\n}}\n",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let error = engine(Duration::from_millis(100))
        .send(&request, &[], &Variables::new())
        .unwrap_err();
    assert!(error.to_string().contains("timed out"));
}

fn grpc_server(code: &str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("grpc://{}", listener.local_addr().unwrap());
    let code = code.to_owned();
    let worker = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(stream).await.unwrap();
                let (mut request, mut respond) = connection.accept().await.unwrap().unwrap();
                // Drive HTTP/2 while reading request DATA; it may arrive after the HEADERS.
                let connection_task =
                    tokio::spawn(async move { while connection.accept().await.is_some() {} });
                assert_eq!(request.uri().path(), "/quinn.test.EchoService/EchoMessage");
                assert_eq!(request.headers()["x-user"], "Quinn");
                assert_eq!(request.headers()["data-bin"], "aGVsbG8");
                let mut bytes = Vec::new();
                while let Some(data) = request.body_mut().data().await {
                    bytes.extend_from_slice(&data.unwrap());
                }
                let files = protox::compile([fixtures().join("echo.proto")], [fixtures()]).unwrap();
                let pool = DescriptorPool::from_file_descriptor_set(files).unwrap();
                let descriptor = pool.get_message_by_name("quinn.test.Echo").unwrap();
                let message = DynamicMessage::decode(descriptor, &bytes[5..]).unwrap();
                assert_eq!(
                    serde_json::to_value(&message).unwrap()["text"],
                    "hello Quinn"
                );
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("x-server", "quinn-test")
                    .body(())
                    .unwrap();
                let mut stream = respond.send_response(response, false).unwrap();
                if code == "0" {
                    let bytes = message.encode_to_vec();
                    let mut framed = vec![0];
                    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                    framed.extend(bytes);
                    stream.send_data(Bytes::from(framed), false).unwrap();
                }
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", code.parse().unwrap());
                if code != "0" {
                    trailers.insert("grpc-message", "permission denied".parse().unwrap());
                }
                trailers.insert("x-trailer", "finished".parse().unwrap());
                stream.send_trailers(trailers).unwrap();
                connection_task.await.unwrap();
            })
            .await
            .unwrap();
        });
    });
    (url, worker)
}

fn grpc_request(url: &str) -> Document {
    Document::parse(&format!("grpc {{\n  url: {url}\n  method: /quinn.test.EchoService/EchoMessage\n  methodType: unary\n  body: grpc\n}}\nmetadata {{\n  x-user: {{{{name}}}}\n  data-bin: hello\n}}\nbody:grpc {{\n  name: message 1\n  content: '''\n    {{\"text\":\"hello {{{{name}}}}\"}}\n  '''\n}}\n")).unwrap()
}

#[test]
fn yaml_grpc_executes_canonical_metadata_and_message_on_local_server() {
    let (url, server) = grpc_server("0");
    let request = quinn_api::collection::parse(Path::new("request.yml"), &format!("info: {{type: grpc}}\ngrpc:\n  url: '{url}'\n  method: /quinn.test.EchoService/EchoMessage\n  methodType: unary\n  protoFilePath: echo.proto\n  metadata:\n    - {{name: x-user, value: '{{{{name}}}}'}}\n    - {{name: data-bin, value: hello}}\n  message: '{{\"text\":\"hello {{{{name}}}}\"}}'\n")).unwrap();
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let response = engine(Duration::from_secs(5))
        .send_in(&request, &[], &values, &fixtures())
        .unwrap();
    assert!(response.passed());
    assert_eq!(response.headers["grpc-status"], "0");
    assert_eq!(
        serde_json::from_str::<Value>(&response.body).unwrap()["text"],
        "hello Quinn"
    );
    server.join().unwrap();
}

#[test]
fn yaml_websocket_selected_message_executes_with_inherited_auth() {
    let (url, server) = websocket_server(false);
    let request = quinn_api::collection::parse(Path::new("request.yml"), &format!("info: {{type: websocket}}\nwebsocket:\n  url: '{url}?token=a%26b'\n  auth: inherit\n  message:\n    - title: unused\n      message: {{type: text, data: unused}}\n    - title: selected\n      selected: true\n      message: {{type: text, data: 'hello {{{{name}}}}'}}\n")).unwrap();
    let defaults = Document::parse("auth {\n  mode: bearer\n}\nauth:bearer {\n  token: test-token\n}\nheaders {\n  x-test: inherited\n}\n").unwrap();
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let response = engine(Duration::from_secs(5))
        .send(&request, &[defaults], &values)
        .unwrap();
    assert!(response.passed());
    assert_eq!(response.status, 101);
    server.join().unwrap();
}

#[test]
fn grpc_compiles_bruno_protos_and_runs_unary_without_protoc() {
    let (url, server) = grpc_server("0");
    let mut request = grpc_request(&url);
    request.blocks.extend(Document::parse("assert {\n  res.status: eq 200\n  res.body.text: eq hello Quinn\n  res.headers.grpc-status: eq 0\n}\nvars:post-response {\n  text: res.body.text\n}\n").unwrap().blocks);
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let response = engine(Duration::from_secs(5))
        .send_in(&request, &[], &values, &fixtures())
        .unwrap();
    assert!(response.passed());
    assert_eq!(response.variables["text"], "hello Quinn");
    assert_eq!(response.headers["grpc-status"], "0");
    assert_eq!(response.headers["x-server"], "quinn-test");
    assert_eq!(response.headers["x-trailer"], "finished");
    server.join().unwrap();
}

#[test]
fn grpc_nonzero_status_fails_runner_and_preserves_metadata() {
    let (url, server) = grpc_server("7");
    let request = grpc_request(&url);
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let response = engine(Duration::from_secs(5))
        .send_in(&request, &[], &values, &fixtures())
        .unwrap();
    assert!(!response.passed());
    assert_eq!(response.status, 500);
    assert_eq!(response.headers["grpc-status"], "7", "{response:?}");
    assert_eq!(response.headers["grpc-message"], "permission denied");
    server.join().unwrap();
}

#[test]
fn grpc_runs_with_an_explicit_descriptor_set() {
    let (url, server) = grpc_server("0");
    let directory = tempfile::tempdir().unwrap();
    let descriptors = protox::compile([fixtures().join("echo.proto")], [fixtures()]).unwrap();
    std::fs::write(
        directory.path().join("echo.bin"),
        descriptors.encode_to_vec(),
    )
    .unwrap();
    let mut request = grpc_request(&url);
    request
        .blocks
        .iter_mut()
        .find(|block| block.name == "grpc")
        .unwrap()
        .content
        .push_str("\ndescriptor: echo.bin");
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let response = engine(Duration::from_secs(5))
        .send_in(&request, &[], &values, directory.path())
        .unwrap();
    assert!(response.passed());
    server.join().unwrap();
}

#[test]
fn grpc_proto_imports_use_collection_relative_include_directories() {
    let (url, server) = grpc_server("0");
    let directory = tempfile::tempdir().unwrap();
    let protos = directory.path().join("protos");
    std::fs::create_dir(&protos).unwrap();
    std::fs::write(
        protos.join("message.proto"),
        "syntax = \"proto3\"; package quinn.test; message Echo { string text = 1; }",
    )
    .unwrap();
    std::fs::write(protos.join("service.proto"), "syntax = \"proto3\"; package quinn.test; import \"message.proto\"; service EchoService { rpc EchoMessage(Echo) returns (Echo); }").unwrap();
    let config = serde_json::json!({"protobuf": {
        "protoFiles": [{"path":"protos/message.proto","type":"file"}, {"path":"protos/service.proto","type":"file"}, {"path":"missing.proto","enabled":false}],
        "importPaths": [{"path":"missing","enabled":false}, {"path":"protos","enabled":true}]
    }});
    std::fs::write(directory.path().join("bruno.json"), config.to_string()).unwrap();
    let request = grpc_request(&url);
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let response = engine(Duration::from_secs(5))
        .send_in(&request, &[], &values, directory.path())
        .unwrap();
    assert!(response.passed());
    server.join().unwrap();
}

#[test]
fn grpc_timeout_bounds_http2_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let request = grpc_request(&format!("grpc://{}", listener.local_addr().unwrap()));
    let values = Variables::from([("name".into(), "Quinn".into())]);
    let start = std::time::Instant::now();
    let result = engine(Duration::from_millis(100)).send_in(&request, &[], &values, &fixtures());
    assert!(start.elapsed() < Duration::from_secs(1));
    match result {
        Ok(response) => assert!(!response.passed()),
        Err(error) => assert!(error.to_string().contains("timed out")),
    }
}

#[test]
fn protocols_reject_invalid_config_before_network_io() {
    for source in [
        "ws {\n  url: ws://127.0.0.1:1\n  body: ws\n}\nbody:ws {\n  type: json\n  content: invalid-json\n}\n",
        "ws {\n  url: ws://127.0.0.1:1\n}\nassert {\n  res.status: imaginary 101\n}\n",
        "ws {\n  url: ws://127.0.0.1:1\n  custom-option: ignored\n}\n",
        "ws {\n  url: ws://127.0.0.1:1\n}\nmetadata {\n  key: value\n}\n",
        "ws {\n  url: ws://127.0.0.1:1\n  body: ws\n}\nbody:ws {\n  content: first\n}\nbody:ws {\n  content: second\n}\n",
        "grpc {\n  url: grpc://127.0.0.1:1\n  method: /quinn.test.EchoService/StreamMessages\n  body: grpc\n}\nbody:grpc {\n  content: {}\n}\n",
        "grpc {\n  url: grpc://127.0.0.1:1\n  method: /quinn.test.EchoService/EchoMessage\n  body: grpc\n}\nbody:grpc {\n  content: {\"unknown\":1}\n}\n",
    ] {
        let request = Document::parse(source).unwrap();
        let error = engine(Duration::from_secs(1))
            .send_in(&request, &[], &Variables::new(), &fixtures())
            .unwrap_err();
        assert!(!matches!(error, quinn_api::Error::Http { .. }), "{error}");
    }
}

#[test]
fn cli_runs_grpc_request_and_reports_json() {
    let (url, server) = grpc_server("0");
    let directory = tempfile::tempdir().unwrap();
    std::fs::copy(
        fixtures().join("bruno.json"),
        directory.path().join("bruno.json"),
    )
    .unwrap();
    std::fs::copy(
        fixtures().join("echo.proto"),
        directory.path().join("echo.proto"),
    )
    .unwrap();
    let request = grpc_request(&url);
    let source = request
        .blocks
        .iter()
        .map(|block| {
            format!(
                "{} {{\n{}\n}}\n",
                block.name,
                block
                    .content
                    .lines()
                    .map(|line| format!("  {line}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })
        .collect::<String>();
    std::fs::write(directory.path().join("request.bru"), source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args([
            "run",
            directory.path().to_str().unwrap(),
            "--var",
            "name=Quinn",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report[0]["response"]["headers"]["grpc-status"], "0");
    assert_eq!(report[0]["passed"], true);
    server.join().unwrap();
}
