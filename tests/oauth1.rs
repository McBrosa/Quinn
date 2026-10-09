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

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use quinn_api::{bru::Document, engine::Engine, network::NetworkOptions, variables::Variables};
use reqwest::Url;
use sha1::Sha1;
use sha2::Sha256;

const AUTH: &str = "auth:oauth1 {\n  consumer_key: consumer/key\n  consumer_secret: consumer/+ é\n  access_token: access/token\n  token_secret: token&secret\n  realm: Test realm\n}\n";
const RFC_ENCODING: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn encode(value: &str) -> String {
    utf8_percent_encode(value, RFC_ENCODING).to_string()
}

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

fn server(response: String) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
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
                Err(error) => panic!("cannot accept test request: {error}"),
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
        socket.write_all(response.as_bytes()).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (url, handle)
}

fn ok() -> String {
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".into()
}

fn pairs(query: &str) -> Vec<(String, String)> {
    Url::parse(&format!("http://parse.invalid/?{query}"))
        .unwrap()
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn verify(wire: &str, method: &str) -> BTreeMap<String, String> {
    let (head, body) = wire.split_once("\r\n\r\n").unwrap();
    let headers: BTreeMap<String, String> = head
        .lines()
        .skip(1)
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    let authorization = headers["authorization"].strip_prefix("OAuth ").unwrap();
    assert!(authorization.starts_with("realm=\"Test realm\", "));
    let oauth: BTreeMap<String, String> = authorization
        .split(", ")
        .map(|field| {
            let (name, value) = field.split_once('=').unwrap();
            let value = value.strip_prefix('"').unwrap().strip_suffix('"').unwrap();
            (
                name.to_owned(),
                percent_encoding::percent_decode_str(value)
                    .decode_utf8()
                    .unwrap()
                    .into_owned(),
            )
        })
        .collect();
    assert_eq!(oauth["realm"], "Test realm");
    assert_eq!(oauth["oauth_consumer_key"], "consumer/key");
    assert_eq!(oauth["oauth_token"], "access/token");
    assert_eq!(oauth["oauth_signature_method"], method);
    assert_eq!(oauth["oauth_version"], "1.0");
    assert_eq!(oauth["oauth_nonce"].len(), 48);
    assert!(oauth["oauth_timestamp"].parse::<u64>().unwrap() > 1_700_000_000);
    let mut parts = head.lines().next().unwrap().split_ascii_whitespace();
    let http_method = parts.next().unwrap();
    let target = parts.next().unwrap();
    let mut url = Url::parse(&format!("http://{}{target}", headers["host"])).unwrap();
    let mut parameters = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if headers.get("content-type").is_some_and(|content_type| {
        content_type
            .split(';')
            .next()
            .unwrap()
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        parameters.extend(pairs(body));
    }
    parameters.extend(
        oauth
            .iter()
            .filter(|(key, _)| key.starts_with("oauth_") && key.as_str() != "oauth_signature")
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    let mut parameters = parameters
        .iter()
        .map(|(key, value)| (encode(key), encode(value)))
        .collect::<Vec<_>>();
    parameters.sort();
    let parameters = parameters
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    url.set_query(None);
    let base = format!(
        "{}&{}&{}",
        encode(&http_method.to_ascii_uppercase()),
        encode(url.as_str()),
        encode(&parameters)
    );
    let key = format!("{}&{}", encode("consumer/+ é"), encode("token&secret"));
    let expected = if method == "HMAC-SHA256" {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(base.as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    } else {
        let mut mac = Hmac::<Sha1>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(base.as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    };
    assert_eq!(oauth["oauth_signature"], expected);
    assert!(!wire.contains("consumer/+ é"));
    assert!(!wire.contains("token&secret"));
    headers
}

#[test]
fn hmac_sha1_and_sha256_sign_actual_form_query_duplicates_and_unicode_credentials() {
    for algorithm in ["HMAC-SHA1", "HMAC-SHA256"] {
        let (url, server) = server(ok());
        let auth = AUTH.replace(
            "realm: Test realm",
            &format!("realm: Test realm\n  signature_method: {algorithm}"),
        );
        let request = Document::parse(&format!("post {{\n  url: {url}/resource%20path?repeat=z&repeat=a&space=a+b&literal=%2B\n  auth: oauth1\n  body: formUrlEncoded\n}}\n{auth}params:query {{\n  extra: café\n}}\nbody:form-urlencoded {{\n  duplicate: z\n  duplicate: a\n  empty:\n  value: one + two\n}}\n")).unwrap();
        assert!(
            engine()
                .send(&request, &[], &Variables::new())
                .unwrap()
                .passed()
        );
        let wire = server.join().unwrap();
        assert!(wire.starts_with(
            "POST /resource%20path?repeat=z&repeat=a&space=a+b&literal=%2B&extra=caf%C3%A9 HTTP/1.1"
        ));
        assert!(wire.ends_with("duplicate=z&duplicate=a&empty=&value=one+%2B+two"));
        verify(&wire, algorithm);
    }
}

#[test]
fn inherited_auth_signs_final_post_script_method_url_and_runtime_credentials() {
    let (url, server) = server(ok());
    let defaults = Document::parse(&format!(
        "auth {{\n  mode: oauth1\n}}\n{}",
        AUTH.replace("consumer_key: consumer/key", "consumer_key: {{key}}")
    ))
    .unwrap();
    let request = Document::parse(&format!("post {{\n  url: {url}/old\n  auth: inherit\n  body: text\n}}\nbody:text {{\n  old-body\n}}\nscript:pre-request {{\n  bru.setVar('key', 'consumer/key');\n  req.setMethod('PATCH');\n  req.setUrl('{url}/new?from=script');\n  req.setHeader('x-custom', 'mutated');\n  req.setBody('changed-body');\n}}\n")).unwrap();
    assert!(
        engine()
            .send(&request, &[defaults], &Variables::new())
            .unwrap()
            .passed()
    );
    let wire = server.join().unwrap();
    assert!(wire.starts_with("PATCH /new?from=script HTTP/1.1"));
    assert!(wire.ends_with("changed-body"));
    assert_eq!(verify(&wire, "HMAC-SHA1")["x-custom"], "mutated");
}

#[test]
fn nonform_json_payload_is_transmitted_but_not_added_to_rfc_signature_parameters() {
    let (url, server) = server(ok());
    let request = Document::parse(&format!("post {{\n  url: {url}/\n  auth: oauth1\n  body: json\n}}\n{AUTH}body:json {{\n  {{\"oauth_token\":\"business-data\",\"value\":42}}\n}}\n")).unwrap();
    assert!(
        engine()
            .send(&request, &[], &Variables::new())
            .unwrap()
            .passed()
    );
    let wire = server.join().unwrap();
    assert!(wire.ends_with(r#"{"oauth_token":"business-data","value":42}"#));
    verify(&wire, "HMAC-SHA1");
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
        let request = Document::parse(&format!(
            "get {{\n  url: {url}/\n  auth: oauth1\n}}\n{AUTH}"
        ))
        .unwrap();
        assert_eq!(
            engine()
                .send(&request, &[], &Variables::new())
                .unwrap()
                .status,
            307
        );
        verify(&server.join().unwrap(), "HMAC-SHA1");
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn invalid_auth_collision_encoding_and_streaming_bodies_fail_before_io_without_secrets() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let base = format!("get {{\n  url: {url}/\n  auth: oauth1\n}}\n{AUTH}");
    let mut cases = vec![
        base.replace("consumer_secret: consumer/+ é", "consumer_secret:"),
        base.replace("consumer_key: consumer/key", "consumer_key:"),
        base.replace("access_token: access/token", "access_token:"),
        base.replace("auth: oauth1", "auth: oauth1\n  body: file"),
        base.replace("auth: oauth1", "auth: oauth1\n  body: multipartForm"),
        base.replace(
            &format!("{url}/"),
            &format!("{url}/?%6fauth_signature=secret-query"),
        ),
        base.replace(&format!("{url}/"), &format!("{url}/?invalid=%FF")),
        base.replace(&format!("{url}/"), &format!("{url}/?invalid=%Q")),
        base.replace(&format!("{url}/"), &format!("{url}/#secret-fragment")),
        base.replace("http://", "http://user:secret-url@"),
        format!("{base}params:query {{\n  oauth_token: secret-param\n}}\n"),
        format!(
            "{}body:form-urlencoded {{\n  oauth_consumer_key: secret-form\n}}\n",
            base.replace("auth: oauth1", "auth: oauth1\n  body: formUrlEncoded")
        ),
    ];
    for field in [
        "nonce",
        "timestamp",
        "callback_url",
        "verifier",
        "private_key",
        "include_body_hash",
        "placement",
        "version",
        "signature_method",
        "unknown",
    ] {
        cases.push(base.replace(
            "realm: Test realm",
            &format!("realm: Test realm\n  {field}: secret-option"),
        ));
    }
    for name in ["Authorization", "Host", "OAuth-Token", "oauth_nonce"] {
        cases.push(format!("{base}headers {{\n  {name}: secret-header\n}}\n"));
    }
    let engine = engine();
    for source in cases {
        let request = Document::parse(&source).unwrap();
        let error = engine
            .send(&request, &[], &Variables::new())
            .unwrap_err()
            .to_string();
        assert!(
            !error.contains("secret-"),
            "error disclosed credentials: {error}"
        );
        assert!(!error.contains("consumer/+ é"));
        assert!(!error.contains("token&secret"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn cli_executes_canonical_bruno_oauth1_authentication() {
    let (url, server) = server(ok());
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("bruno.json"),
        r#"{"version":"1","name":"OAuth1"}"#,
    )
    .unwrap();
    fs::write(directory.path().join("request.bru"), format!("meta {{\n  name: signed\n  type: http\n  seq: 1\n}}\nget {{\n  url: {url}/\n  auth: oauth1\n}}\n{AUTH}")).unwrap();
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
    verify(&server.join().unwrap(), "HMAC-SHA1");
}
