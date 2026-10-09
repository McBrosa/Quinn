#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use hmac::{Hmac, Mac};
use quinn_api::{bru::Document, engine::Engine, network::NetworkOptions, variables::Variables};
use sha2::{Digest, Sha256};

const AUTH: &str = "auth:awsv4 {\n  accessKeyId: AKIDEXAMPLE\n  secretAccessKey: test-signing-secret\n  sessionToken: test-session-token\n  region: us-east-1\n  service: execute-api\n}\n";

fn engine() -> Engine {
    Engine::with_network(
        Duration::from_secs(5),
        &NetworkOptions {
            no_proxy: true,
            ..NetworkOptions::default()
        },
    )
    .unwrap()
}

fn server(reply: String) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("cannot accept test connection: {error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut byte = [0];
        while !bytes.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 65536);
        }
        let length = String::from_utf8_lossy(&bytes)
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap_or(0);
        assert!(length < 1024 * 1024);
        let start = bytes.len();
        bytes.resize(start + length, 0);
        socket.read_exact(&mut bytes[start..]).unwrap();
        socket.write_all(reply.as_bytes()).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (url, handle)
}

fn ok() -> String {
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hmac(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

// Verify the received bytes, not the engine's pre-transmission request representation.
fn verify(wire: &str, path: &str, query: &str, service: &str) -> BTreeMap<String, String> {
    let (head, body) = wire.split_once("\r\n\r\n").unwrap();
    let headers: BTreeMap<String, String> = head
        .lines()
        .skip(1)
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    let authorization = &headers["authorization"];
    let signed = authorization
        .split("SignedHeaders=")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap();
    let canonical_headers = signed
        .split(';')
        .map(|name| {
            format!(
                "{name}:{}\n",
                headers[name]
                    .split_ascii_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        })
        .collect::<String>();
    let method = head.split_ascii_whitespace().next().unwrap();
    let payload_hash = hex(&Sha256::digest(body.as_bytes()));
    let canonical_request =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}");
    let timestamp = &headers["x-amz-date"];
    let date = &timestamp[..8];
    let scope = format!("{date}/us-east-1/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let key = hmac(b"AWS4test-signing-secret", date.as_bytes());
    let key = hmac(&key, b"us-east-1");
    let key = hmac(&key, service.as_bytes());
    let key = hmac(&key, b"aws4_request");
    let signature = hex(&hmac(&key, string_to_sign.as_bytes()));
    assert_eq!(
        authorization,
        &format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope}, SignedHeaders={signed}, Signature={signature}"
        )
    );
    assert!(!wire.contains("test-signing-secret"));
    assert!(signed.split(';').any(|name| name == "x-amz-security-token"));
    headers
}

#[test]
fn inherited_auth_signs_post_script_headers_expanded_query_and_final_json_bytes() {
    let (url, server) = server(ok());
    let defaults = Document::parse(&format!(
        "auth {{\n  mode: awsv4\n}}\n{}",
        AUTH.replace("us-east-1", "{{region}}")
    ))
    .unwrap();
    let request = Document::parse(&format!("post {{\n  url: {url}/a%20b?Z=one&repeated=z&a=%2B\n  auth: inherit\n  body: json\n}}\nparams:query {{\n  repeated: a\n  space: hello world\n}}\nbody:json {{\n  {{\"old\":true}}\n}}\nscript:pre-request {{\n  bru.setVar('region', 'us-east-1');\n  req.setHeader('x-custom', 'scripted');\n  req.setBody({{message: 'changed'}});\n}}\n")).unwrap();
    assert!(
        engine()
            .send(&request, &[defaults], &Variables::new())
            .unwrap()
            .passed()
    );
    let wire = server.join().unwrap();
    assert!(
        wire.starts_with(
            "POST /a%20b?Z=one&repeated=z&a=%2B&repeated=a&space=hello%20world HTTP/1.1"
        )
    );
    let headers = verify(
        &wire,
        "/a%2520b",
        "Z=one&a=%2B&repeated=a&repeated=z&space=hello%20world",
        "execute-api",
    );
    assert_eq!(headers["x-custom"], "scripted");
    assert!(wire.ends_with(r#"{"message":"changed"}"#));
    assert_eq!(headers["content-type"], "application/json");
}

#[test]
fn replayable_form_and_graphql_bodies_are_signed_as_transmitted() {
    for (kind, block) in [
        (
            "formUrlEncoded",
            "body:form-urlencoded {\n  message: hello world\n  repeated: a\n  repeated: b\n}\n",
        ),
        (
            "graphql",
            "body:graphql {\n  query { hello }\n}\nbody:graphql:vars {\n  {\"value\":1}\n}\n",
        ),
    ] {
        let (url, server) = server(ok());
        let request = Document::parse(&format!(
            "post {{\n  url: {url}/\n  auth: awsv4\n  body: {kind}\n}}\n{AUTH}{block}"
        ))
        .unwrap();
        assert!(
            engine()
                .send(&request, &[], &Variables::new())
                .unwrap()
                .passed()
        );
        verify(&server.join().unwrap(), "/", "", "execute-api");
    }
}

#[test]
fn transmitted_query_distinguishes_literal_url_plus_from_document_spaces() {
    let (url, server) = server(ok());
    let request = Document::parse(&format!("get {{\n  url: {url}/?literal=hello+world&encoded=a%2Bb&utf8=caf%C3%A9\n  auth: awsv4\n}}\n{AUTH}params:query {{\n  space: hello world\n}}\n")).unwrap();
    assert!(
        engine()
            .send(&request, &[], &Variables::new())
            .unwrap()
            .passed()
    );
    let wire = server.join().unwrap();
    let canonical_query = "encoded=a%2Bb&literal=hello%2Bworld&space=hello%20world&utf8=caf%C3%A9";
    let wire_query = "literal=hello%2Bworld&encoded=a%2Bb&utf8=caf%C3%A9&space=hello%20world";
    assert!(wire.starts_with(&format!("GET /?{wire_query} HTTP/1.1")));
    verify(&wire, "/", canonical_query, "execute-api");
}

#[test]
fn s3_keeps_repeated_slashes_and_single_encoding_and_hashes_payload() {
    let (url, server) = server(ok());
    let auth = AUTH.replace("execute-api", "s3");
    let request = Document::parse(&format!("put {{\n  url: {url}/bucket/a//b%20c?acl\n  auth: awsv4\n  body: text\n}}\n{auth}body:text {{\n  payload\n}}\n")).unwrap();
    assert!(
        engine()
            .send(&request, &[], &Variables::new())
            .unwrap()
            .passed()
    );
    let wire = server.join().unwrap();
    assert!(wire.starts_with("PUT /bucket/a//b%20c?acl= HTTP/1.1"));
    let headers = verify(&wire, "/bucket/a//b%20c", "acl=", "s3");
    let body = wire.split_once("\r\n\r\n").unwrap().1;
    assert_eq!(
        headers["x-amz-content-sha256"],
        hex(&Sha256::digest(body.as_bytes()))
    );
}

#[test]
fn signed_requests_never_follow_cross_origin_or_same_origin_redirects() {
    for same_origin in [false, true] {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let location = if same_origin {
            "/unsigned".to_owned()
        } else {
            format!("http://{}/unsigned", destination.local_addr().unwrap())
        };
        let (url, server) = server(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ));
        let request =
            Document::parse(&format!("get {{\n  url: {url}/\n  auth: awsv4\n}}\n{AUTH}")).unwrap();
        assert_eq!(
            engine()
                .send(&request, &[], &Variables::new())
                .unwrap()
                .status,
            307
        );
        verify(&server.join().unwrap(), "/", "", "execute-api");
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn s3_signs_exact_escaped_wire_path_without_changing_object_keys() {
    for (input_path, wire_path) in [
        ("/bucket/%41//%2f", "/bucket/%41//%2f"),
        ("/bucket/café//%2F", "/bucket/caf%C3%A9//%2F"),
        ("/bucket/key+!", "/bucket/key+!"),
    ] {
        let (url, server) = server(ok());
        let auth = AUTH.replace("execute-api", "s3");
        let request = Document::parse(&format!(
            "get {{\n  url: {url}{input_path}\n  auth: awsv4\n}}\n{auth}"
        ))
        .unwrap();
        assert!(
            engine()
                .send(&request, &[], &Variables::new())
                .unwrap()
                .passed()
        );
        let wire = server.join().unwrap();
        assert!(wire.starts_with(&format!("GET {wire_path} HTTP/1.1")));
        verify(&wire, wire_path, "", "s3");
    }
}

#[test]
fn invalid_auth_conflicting_headers_and_nonreplayable_bodies_fail_before_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let engine = engine();
    let base = format!("get {{\n  url: {url}/\n  auth: awsv4\n}}\n{AUTH}");
    let mut cases = vec![
        base.replace("region: us-east-1", "region:"),
        base.replace(
            "service: execute-api",
            "service: execute-api\n  profileName: secret-profile",
        ),
        base.replace("accessKeyId: AKIDEXAMPLE", "accessKeyId: bad/key"),
        base.replace(
            "service: execute-api",
            "service: execute-api\n  unknown: secret-unknown",
        ),
        base.replace(
            &format!("{url}/"),
            &format!("{url}/?X-Amz-Signature=secret-query"),
        ),
        base.replace(&format!("{url}/"), &format!("{url}/#secret-fragment")),
        base.replace("http://", "http://user:secret-url@"),
        base.replace(&format!("{url}/"), &format!("{url}/?bad=%FF")),
        format!("{base}params:query {{\n  X-Amz-Signature: secret-query\n}}\n"),
        base.replace("execute-api", "s3")
            .replace(&format!("{url}/"), &format!("{url}/a/%2e%2e/b")),
        base.replace("execute-api", "s3")
            .replace(&format!("{url}/"), &format!("{url}/a\\b")),
        base.replace("auth: awsv4", "auth: awsv4\n  body: file"),
        base.replace("auth: awsv4", "auth: awsv4\n  body: multipartForm"),
        format!("{base}assert {{\n  res.status: unknown secret-assert\n}}\n"),
    ];
    for name in [
        "Authorization",
        "Host",
        "X-Amz-Date",
        "X-Amz-Security-Token",
        "X-Amz-Content-Sha256",
        "X-Amz-Region-Set",
    ] {
        cases.push(format!("{base}headers {{\n  {name}: secret-header\n}}\n"));
    }
    for source in cases {
        let request = Document::parse(&source).unwrap();
        let error = engine
            .send(&request, &[], &Variables::new())
            .unwrap_err()
            .to_string();
        assert!(
            !error.contains("secret-"),
            "error disclosed secret: {error}"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn cli_executes_a_bruno_sigv4_request() {
    let (url, server) = server(ok());
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("bruno.json"),
        r#"{"version":"1","name":"AWS"}"#,
    )
    .unwrap();
    fs::write(directory.path().join("request.bru"), format!("meta {{\n  name: signed\n  type: http\n  seq: 1\n}}\nget {{\n  url: {url}/\n  auth: awsv4\n}}\n{AUTH}")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["run", "--no-proxy"])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    verify(&server.join().unwrap(), "/", "", "execute-api");
}
