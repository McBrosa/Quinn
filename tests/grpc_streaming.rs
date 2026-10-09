#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use quinn_api::{bru::Document, engine::Engine, variables::Variables};
use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/protocols")
}

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    Alpha,
    Denied,
    PartialError,
    Many,
    Stall,
    MissingDependency,
    Empty,
}

fn server(mode: Mode) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("grpc://{}", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            tokio::time::timeout(Duration::from_secs(10), async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (socket, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(socket).await.unwrap();
                let mut tasks = Vec::new();
                let mut paths = Vec::new();
                while let Some(Ok((request, respond))) = connection.accept().await {
                    paths.push(request.uri().path().to_owned());
                    tasks.push(tokio::spawn(handle(request, respond, mode)));
                }
                for task in tasks {
                    task.await.unwrap();
                }
                paths
            })
            .await
            .expect("local gRPC server exceeded deadline")
        })
    });
    (url, worker)
}

async fn handle(
    mut request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    mode: Mode,
) {
    assert_eq!(
        request.headers()["authorization"],
        "Bearer reflection-token"
    );
    assert_eq!(request.headers()["x-user"], "Quinn");
    let path = request.uri().path().to_owned();
    let mut bytes = Vec::new();
    while let Some(data) = request.body_mut().data().await {
        let data = data.unwrap();
        request
            .body_mut()
            .flow_control()
            .release_capacity(data.len())
            .unwrap();
        bytes.extend_from_slice(&data);
    }
    let mut messages = Vec::new();
    while !bytes.is_empty() {
        assert_eq!(bytes[0], 0);
        let length = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
        messages.push(bytes[5..5 + length].to_vec());
        bytes.drain(..5 + length);
    }
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("x-server", "local-streams")
        .body(())
        .unwrap();
    let mut output = respond.send_response(response, false).unwrap();
    let descriptors = protox::compile([fixtures().join("streams.proto")], [fixtures()]).unwrap();
    let mut code = "0";
    if path.contains("ServerReflection") {
        assert_eq!(messages.len(), 1);
        if matches!(mode, Mode::Alpha) && path.contains(".v1.") {
            code = "12";
        } else if matches!(mode, Mode::Denied) {
            code = "7";
        } else {
            let request = ReflectionRequest::decode(messages[0].as_slice()).unwrap();
            let name = if request.symbol.as_deref() == Some("quinn.stream.Streams") {
                "streams.proto"
            } else {
                assert_eq!(request.filename.as_deref(), Some("echo.proto"));
                "echo.proto"
            };
            let name = if matches!(mode, Mode::MissingDependency) {
                "streams.proto"
            } else {
                name
            };
            let file = descriptors
                .file
                .iter()
                .find(|file| file.name.as_deref() == Some(name))
                .unwrap();
            let reply = ReflectionReply {
                files: Some(ReflectionFiles {
                    files: vec![file.encode_to_vec()],
                }),
            };
            output
                .send_data(frame(reply.encode_to_vec()), false)
                .unwrap();
        }
    } else {
        let pool = DescriptorPool::from_file_descriptor_set(descriptors).unwrap();
        let descriptor = pool.get_message_by_name("quinn.test.Echo").unwrap();
        let messages: Vec<_> = messages
            .iter()
            .map(|bytes| DynamicMessage::decode(descriptor.clone(), bytes.as_slice()).unwrap())
            .collect();
        assert!(!messages.is_empty());
        assert_eq!(serde_json::to_value(&messages[0]).unwrap()["text"], "first");
        if path.ends_with("/Client") || path.ends_with("/Bidi") {
            assert_eq!(messages.len(), 2);
            assert_eq!(
                serde_json::to_value(&messages[1]).unwrap()["text"],
                "second"
            );
        } else {
            assert_eq!(messages.len(), 1);
        }
        let count = if matches!(mode, Mode::Empty) {
            0
        } else if matches!(mode, Mode::Many) {
            1025
        } else if path.ends_with("/Server") || path.ends_with("/Bidi") {
            2
        } else {
            1
        };
        for index in 0..count {
            let message = &messages[index.min(messages.len() - 1)];
            if output
                .send_data(frame(message.encode_to_vec()), false)
                .is_err()
            {
                return;
            }
            if matches!(mode, Mode::PartialError | Mode::Stall) {
                break;
            }
        }
        if matches!(mode, Mode::PartialError) {
            code = "7";
        }
        if matches!(mode, Mode::Stall) {
            tokio::time::sleep(Duration::from_millis(350)).await;
        }
    }
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", code.parse().unwrap());
    if code != "0" {
        trailers.insert("grpc-message", "permission denied".parse().unwrap());
    }
    trailers.insert("x-trailer", "complete".parse().unwrap());
    let _ = output.send_trailers(trailers);
}

fn frame(bytes: Vec<u8>) -> Bytes {
    let mut framed = vec![0];
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend(bytes);
    framed.into()
}

fn request(url: &str, method: &str, kind: &str, local: bool) -> Document {
    let proto = if local {
        "  protoPath: streams.proto\n"
    } else {
        ""
    };
    let mut source = format!(
        "grpc {{\n  url: {url}\n  method: /quinn.stream.Streams/{method}\n  methodType: {kind}\n  body: grpc\n  auth: bearer\n{proto}}}\nauth:bearer {{\n  token: reflection-token\n}}\nmetadata {{\n  x-user: Quinn\n}}\nbody:grpc {{\n  name: first\n  content: {{\"text\":\"first\"}}\n}}\n"
    );
    if kind == "client-streaming" || kind == "bidi-streaming" {
        source.push_str("body:grpc {\n  name: second\n  content: {\"text\":\"second\"}\n}\n");
    }
    Document::parse(&source).unwrap()
}

#[test]
fn finite_streams_and_unary_share_reflection_metadata_and_preserve_trailers() {
    for (method, kind) in [
        ("Unary", "unary"),
        ("Server", "server-streaming"),
        ("Client", "client-streaming"),
        ("Bidi", "bidi-streaming"),
    ] {
        let (url, worker) = server(Mode::Normal);
        let directory = tempfile::tempdir().unwrap();
        let mut request = request(&url, method, kind, false);
        if method == "Server" {
            request.blocks.extend(Document::parse("assert {\n  res.body[0].text: eq first\n}\nvars:post-response {\n  first: res.body[0].text\n}\n").unwrap().blocks);
        }
        let response = Engine::new(Duration::from_secs(5))
            .unwrap()
            .send_in(&request, &[], &Variables::new(), directory.path())
            .unwrap();
        assert!(response.passed(), "{response:?}");
        assert_eq!(response.headers["x-server"], "local-streams");
        assert_eq!(response.headers["x-trailer"], "complete");
        let body: Value = serde_json::from_str(&response.body).unwrap();
        if method == "Server" || method == "Bidi" {
            assert_eq!(body.as_array().unwrap().len(), 2);
            assert_eq!(body[0]["text"], "first");
        } else {
            assert_eq!(body["text"], "first");
        }
        if method == "Server" {
            assert_eq!(response.variables["first"], "first");
        }
        let paths = worker.join().unwrap();
        assert_eq!(paths.len(), 3);
        assert_eq!(
            paths[0],
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
        );
    }
}

#[test]
fn reflection_falls_back_to_alpha_only_for_unimplemented() {
    for mode in [Mode::Alpha, Mode::Denied] {
        let (url, worker) = server(mode);
        let directory = tempfile::tempdir().unwrap();
        let request = request(&url, "Unary", "unary", false);
        let result = Engine::new(Duration::from_secs(5)).unwrap().send_in(
            &request,
            &[],
            &Variables::new(),
            directory.path(),
        );
        let paths = worker.join().unwrap();
        if matches!(mode, Mode::Alpha) {
            assert!(result.unwrap().passed());
            assert_eq!(paths.len(), 4);
            assert!(paths[1].contains("v1alpha"));
        } else {
            let error = result.unwrap_err();
            assert!(
                error
                    .to_string()
                    .to_lowercase()
                    .contains("permission denied"),
                "{error}"
            );
            assert_eq!(paths.len(), 1);
        }
    }
}

#[test]
fn streaming_error_keeps_partial_messages_and_fails_assertions_and_extraction() {
    let (url, worker) = server(Mode::PartialError);
    let mut request = request(&url, "Server", "server-streaming", true);
    request.blocks.extend(
        Document::parse("vars:post-response {\n  first: res.body[0].text\n}\n")
            .unwrap()
            .blocks,
    );
    let response = Engine::new(Duration::from_secs(5))
        .unwrap()
        .send_in(&request, &[], &Variables::new(), &fixtures())
        .unwrap();
    assert!(!response.passed());
    assert!(response.variables.is_empty());
    assert_eq!(response.headers["grpc-status"], "7");
    assert_eq!(response.headers["x-trailer"], "complete");
    assert_eq!(
        serde_json::from_str::<Value>(&response.body).unwrap()[0]["text"],
        "first"
    );
    worker.join().unwrap();
}

#[test]
fn grpc_streams_have_a_total_deadline_and_message_limit() {
    for mode in [Mode::Many, Mode::Stall] {
        let (url, worker) = server(mode);
        let request = request(&url, "Server", "server-streaming", true);
        let timeout = if matches!(mode, Mode::Stall) {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(5)
        };
        let start = Instant::now();
        let result =
            Engine::new(timeout)
                .unwrap()
                .send_in(&request, &[], &Variables::new(), &fixtures());
        match result {
            Err(error) => assert!(
                error.to_string().contains(if matches!(mode, Mode::Stall) {
                    "timed out"
                } else {
                    "1024 message limit"
                }),
                "{error}"
            ),
            Ok(response) => {
                assert!(matches!(mode, Mode::Stall));
                assert!(!response.passed());
                assert_ne!(response.headers["grpc-status"], "0");
            }
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    }
}

#[test]
fn reflection_rejects_missing_dependencies_without_an_infinite_loop() {
    let (url, worker) = server(Mode::MissingDependency);
    let directory = tempfile::tempdir().unwrap();
    let request = request(&url, "Unary", "unary", false);
    let error = Engine::new(Duration::from_secs(5))
        .unwrap()
        .send_in(&request, &[], &Variables::new(), directory.path())
        .unwrap_err();
    assert!(
        error.to_string().contains("required protobuf dependencies"),
        "{error}"
    );
    assert_eq!(worker.join().unwrap().len(), 2);
}

#[test]
fn local_stream_validation_fails_before_connecting() {
    for (method, kind) in [
        ("Server", "unary"),
        ("Unary", "server-streaming"),
        ("Unary", "not-a-method-type"),
    ] {
        let request = request("grpc://127.0.0.1:1", method, kind, true);
        let error = Engine::new(Duration::from_millis(100))
            .unwrap()
            .send_in(&request, &[], &Variables::new(), &fixtures())
            .unwrap_err();
        assert!(matches!(error, quinn_api::Error::Invalid { .. }), "{error}");
    }
    let mut request = request("grpc://127.0.0.1:1", "Bidi", "bidi-streaming", true);
    let block = request
        .blocks
        .iter()
        .find(|block| block.name == "body:grpc")
        .unwrap()
        .clone();
    request.blocks.extend(std::iter::repeat_n(block, 1023));
    let error = Engine::new(Duration::from_millis(100))
        .unwrap()
        .send_in(&request, &[], &Variables::new(), &fixtures())
        .unwrap_err();
    assert!(error.to_string().contains("1024 message limit"), "{error}");
}

#[test]
fn empty_server_stream_succeeds_but_empty_unary_response_fails() {
    for (method, kind) in [("Server", "server-streaming"), ("Unary", "unary")] {
        let (url, worker) = server(Mode::Empty);
        let request = request(&url, method, kind, true);
        let result = Engine::new(Duration::from_secs(5)).unwrap().send_in(
            &request,
            &[],
            &Variables::new(),
            &fixtures(),
        );
        if method == "Server" {
            let response = result.unwrap();
            assert!(response.passed());
            assert_eq!(response.body, "[]");
            assert_eq!(response.headers["x-trailer"], "complete");
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("exactly one message")
            );
        }
        worker.join().unwrap();
    }
}

#[derive(prost::Message)]
struct ReflectionRequest {
    #[prost(string, optional, tag = "3")]
    filename: Option<String>,
    #[prost(string, optional, tag = "4")]
    symbol: Option<String>,
}
#[derive(prost::Message)]
struct ReflectionReply {
    #[prost(message, optional, tag = "4")]
    files: Option<ReflectionFiles>,
}
#[derive(prost::Message)]
struct ReflectionFiles {
    #[prost(bytes = "vec", repeated, tag = "1")]
    files: Vec<Vec<u8>>,
}
