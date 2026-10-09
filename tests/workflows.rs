#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use quinn_api::{bru::Document, engine::Engine, variables::Variables};

fn server(responses: Vec<&'static str>) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
    server_with_status(
        responses
            .into_iter()
            .map(|body| ("200 OK", "", body))
            .collect(),
    )
}

fn server_with_status(
    responses: Vec<(&'static str, &'static str, &'static str)>,
) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, extra_headers, body) in responses {
            let start = Instant::now();
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            start.elapsed() < Duration::from_secs(10),
                            "client did not connect"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("cannot accept test connection: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let length = socket.read(&mut buffer).unwrap();
                assert!(length > 0, "client disconnected before completing request");
                request.extend_from_slice(&buffer[..length]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    assert!(
                        !headers.contains("transfer-encoding: chunked"),
                        "test requires a known body length"
                    );
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:").map(str::trim))
                        .unwrap_or("0")
                        .parse::<usize>()
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            write!(socket, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}", body.len()).unwrap();
            requests.push(request);
        }
        requests
    });
    (url, handle)
}

fn oauth_request(url: &str, placement: &str) -> Document {
    Document::parse(&format!("get {{\n  url: {url}/api\n  auth: oauth2\n}}\nauth:oauth2 {{\n  grant_type: client_credentials\n  access_token_url: {url}/token\n  client_id: user\n  client_secret: pass\n  credentials_placement: {placement}\n  scope: read write\n}}\n")).unwrap()
}

#[test]
fn oauth_client_credentials_supports_body_and_basic_header_authentication() {
    for placement in ["body", "header"] {
        let (url, server) = server(vec![
            r#"{"access_token":"access","token_type":"Bearer","expires_in":3600}"#,
            "{}",
        ]);
        let request = oauth_request(&url, placement);
        let response = engine().send(&request, &[], &Variables::new()).unwrap();
        assert!(response.passed());
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with(b"POST /token HTTP/1.1"));
        let form = String::from_utf8_lossy(body(&requests[0]));
        assert!(form.contains("grant_type=client_credentials"));
        assert!(form.contains("scope=read+write"));
        if placement == "body" {
            assert!(form.contains("client_id=user&client_secret=pass"));
        } else {
            assert!(
                String::from_utf8_lossy(&requests[0]).contains("authorization: Basic dXNlcjpwYXNz")
            );
            assert!(!form.contains("client_secret"));
        }
        assert!(String::from_utf8_lossy(&requests[1]).contains("authorization: Bearer access"));
    }
}

#[test]
fn oauth_configuration_inherits_and_resolves_variables() {
    let (url, server) = server(vec![
        r#"{"access_token":"inherited","token_type":"bearer"}"#,
        "{}",
    ]);
    let defaults = vec![Document::parse("auth {\n  mode: oauth2\n}\nauth:oauth2 {\n  grant_type: client_credentials\n  access_token_url: {{url}}/token\n  client_id: {{client}}\n  client_secret: {{secret}}\n}\n").unwrap()];
    let request =
        Document::parse(&format!("get {{\n  url: {url}/api\n  auth: inherit\n}}\n")).unwrap();
    let variables = Variables::from([
        ("url".into(), url),
        ("client".into(), "user".into()),
        ("secret".into(), "pass".into()),
    ]);
    engine().send(&request, &defaults, &variables).unwrap();
    let requests = server.join().unwrap();
    assert!(String::from_utf8_lossy(&requests[1]).contains("authorization: Bearer inherited"));
}

#[test]
fn oauth_rejects_invalid_token_responses_without_sending_the_api_request() {
    for token in [
        r#"{"access_token":"","token_type":"Bearer"}"#,
        r#"{"access_token":"SECRET","token_type":"Unsupported"}"#,
        r#"{"error":"SECRET"}"#,
    ] {
        let (url, server) = server(vec![token]);
        let error = engine()
            .send(&oauth_request(&url, "body"), &[], &Variables::new())
            .unwrap_err();
        assert!(!error.to_string().contains("SECRET"), "{error}");
        assert_eq!(server.join().unwrap().len(), 1);
    }
}

#[test]
fn oauth_does_not_follow_token_endpoint_redirects() {
    let (url, server) = server_with_status(vec![(
        "307 Temporary Redirect",
        "Location: http://127.0.0.1:1/secret\r\n",
        "{}",
    )]);
    let error = engine()
        .send(&oauth_request(&url, "body"), &[], &Variables::new())
        .unwrap_err();
    assert!(error.to_string().contains("HTTP 307"), "{error}");
    server.join().unwrap();
}

#[test]
fn unsupported_request_features_are_rejected_before_oauth_token_acquisition() {
    let mut request = oauth_request("http://127.0.0.1:1", "body");
    request.blocks.extend(
        Document::parse("assert {\n  res.status: unknown 200\n}\n")
            .unwrap()
            .blocks,
    );
    let error = engine().send(&request, &[], &Variables::new()).unwrap_err();
    assert!(error.to_string().contains("unsupported"), "{error}");
}

#[test]
fn cli_uploads_nested_request_files_from_the_collection_root() {
    let (url, server) = server(vec!["{}"]);
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("nested")).unwrap();
    fs::write(directory.path().join("bruno.json"), "{}").unwrap();
    fs::write(directory.path().join("payload.bin"), [0, 255, 42]).unwrap();
    let request = directory.path().join("nested/upload.bru");
    fs::write(&request, format!("post {{\n  url: {url}\n  body: file\n}}\nbody:file {{\n  file: @file(payload.bin)\n}}\n")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .arg("run")
        .arg(&request)
        .args(["--json", "--timeout", "3"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(body(&server.join().unwrap()[0]), [0, 255, 42]);
}

#[test]
fn multipart_lists_become_repeated_fields_and_preserve_multiline_text() {
    let (url, server) = server(vec!["{}"]);
    let request = Document::parse(&format!("post {{\n  url: {url}\n  body: multipartForm\n}}\nbody:multipart-form {{\n  colors: [\n    red\n    blue\n  ]\n  multiline: '''red\nblue'''\n}}\n")).unwrap();
    engine().send(&request, &[], &Variables::new()).unwrap();
    let text = String::from_utf8(server.join().unwrap().remove(0)).unwrap();
    assert_eq!(text.matches("name=\"colors\"").count(), 2);
    assert_eq!(text.matches("name=\"multiline\"").count(), 1);
    assert!(text.contains("red\nblue"));
}

#[test]
fn bruno_form_urlencoded_body_mode_encodes_fields() {
    let (url, server) = server(vec!["{}"]);
    let request = Document::parse(&format!("post {{\n  url: {url}\n  body: formUrlEncoded\n}}\nbody:form-urlencoded {{\n  q: a b&c\n}}\n")).unwrap();
    engine().send(&request, &[], &Variables::new()).unwrap();
    assert_eq!(body(&server.join().unwrap()[0]), b"q=a+b%26c");
}

fn engine() -> Engine {
    Engine::new(Duration::from_secs(3)).unwrap()
}

fn body(request: &[u8]) -> &[u8] {
    let start = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    &request[start..]
}

#[test]
fn multipart_streams_multiple_files_and_annotated_text() {
    let (url, server) = server(vec!["{}"]);
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("one.bin"), [0, 255, 1, 2]).unwrap();
    fs::write(directory.path().join("two.bin"), b"SECOND_FILE").unwrap();
    let request = Document::parse(&format!("post {{\n  url: {url}\n  body: multipartForm\n}}\nheaders {{\n  Content-Type: application/json\n}}\nbody:multipart-form {{\n  data: @file(one.bin|two.bin) @contentType(application/octet-stream)\n  metadata: {{\"name\":\"Quinn\"}} @contentType(application/json)\n  multiline: '''\n  first\n  second\n  ''' @contentType(text/plain)\n  ~disabled: @file(missing-file)\n}}\n")).unwrap();
    let response = engine()
        .send_in(&request, &[], &Variables::new(), directory.path())
        .unwrap();
    assert!(response.passed());
    let wire = server.join().unwrap().remove(0);
    let text = String::from_utf8_lossy(&wire);
    assert!(
        text.contains("content-type: multipart/form-data; boundary="),
        "{text}"
    );
    assert!(text.contains("filename=\"one.bin\""));
    assert!(text.contains("filename=\"two.bin\""));
    assert!(
        text.contains("Content-Type: application/json\r\n\r\n{\"name\":\"Quinn\"}"),
        "{text}"
    );
    assert!(text.contains("first\nsecond"));
    assert!(!text.contains("@contentType"));
    assert!(!text.contains("missing-file"));
    assert!(wire.windows(4).any(|bytes| bytes == [0, 255, 1, 2]));
}

#[test]
fn binary_upload_preserves_bytes_and_resolves_variables() {
    let (url, server) = server(vec!["{}"]);
    let directory = tempfile::tempdir().unwrap();
    let bytes = [0, 255, 254, 10, 13, 42];
    fs::write(directory.path().join("payload.bin"), bytes).unwrap();
    let request = Document::parse(&format!("post {{\n  url: {url}\n  body: file\n}}\nbody:file {{\n  file: @file({{{{filename}}}}) @contentType(application/octet-stream)\n  ~file: @file(missing-file)\n}}\n")).unwrap();
    let variables = Variables::from([("filename".into(), "payload.bin".into())]);
    engine()
        .send_in(&request, &[], &variables, directory.path())
        .unwrap();
    let wire = server.join().unwrap().remove(0);
    assert_eq!(body(&wire), bytes);
    assert!(String::from_utf8_lossy(&wire).contains("content-type: application/octet-stream"));
}

#[test]
fn invalid_uploads_fail_before_network_io() {
    let directory = tempfile::tempdir().unwrap();
    for file in [
        "@file(missing)",
        "@file(one|two)",
        "@file()",
        "@file(unclosed",
        "not-a-file",
    ] {
        let request = Document::parse(&format!("post {{\n  url: http://127.0.0.1:1\n  body: file\n}}\nbody:file {{\n  file: {file}\n}}\n")).unwrap();
        let error = engine()
            .send_in(&request, &[], &Variables::new(), directory.path())
            .unwrap_err();
        assert!(
            !error.to_string().starts_with("cannot send HTTP request"),
            "{error}"
        );
    }
}

#[test]
fn response_variables_and_assertions_support_arrays_quoted_keys_and_legacy_selectors() {
    let (url, server) = server(vec![
        r#"{"accounts":[{"user.name":"Quinn","token":"abc"}],"null":null}"#,
    ]);
    let request = Document::parse(&format!("get {{\n  url: {url}\n}}\nvars:post-response {{\n  token: res.body.accounts[0].token\n  name: $res.body.accounts[0][\"user.name\"]\n  status: res.status\n  nothing: res.body.null\n  ~disabled: res.body.missing\n}}\nassert {{\n  $res.status: eq 200\n  res.body.accounts[0][\"user.name\"]: eq Quinn\n  res.body.accounts.0.token: eq abc\n}}\n")).unwrap();
    let response = engine().send(&request, &[], &Variables::new()).unwrap();
    server.join().unwrap();
    assert!(response.passed());
    assert_eq!(response.variables["token"], "abc");
    assert_eq!(response.variables["name"], "Quinn");
    assert_eq!(response.variables["status"], "200");
    assert_eq!(response.variables["nothing"], "null");
    assert!(
        serde_json::to_value(&response)
            .unwrap()
            .get("variables")
            .is_none()
    );
}

#[test]
fn failed_extraction_keeps_the_response_and_publishes_no_partial_variables() {
    let (url, server) = server(vec![r#"{"token":"abc"}"#]);
    let request = Document::parse(&format!("get {{\n  url: {url}\n}}\nvars:post-response {{\n  token: res.body.token\n  missing: res.body.missing\n}}\n")).unwrap();
    let response = engine().send(&request, &[], &Variables::new()).unwrap();
    server.join().unwrap();
    assert_eq!(response.status, 200);
    assert!(!response.passed());
    assert!(response.variables.is_empty());
    assert_eq!(response.variable_errors.len(), 1);
    assert!(response.variable_errors[0].contains("missing"));
}

#[test]
fn unsupported_response_expressions_fail_before_network_io() {
    for selector in [
        "res.body.token.toUpperCase()",
        "res.body.items[-1]",
        "res.body.items[",
        "res.body.items[foo]",
        "process.env.SECRET",
    ] {
        let request = Document::parse(&format!("get {{\n  url: http://127.0.0.1:1\n}}\nvars:post-response {{\n  token: {selector}\n}}\n")).unwrap();
        let error = engine().send(&request, &[], &Variables::new()).unwrap_err();
        assert!(error.to_string().contains("unsupported"), "{error}");
    }
}

#[test]
fn cli_chains_response_variables_and_preserves_explicit_overrides() {
    for explicit in [false, true] {
        let (url, server) = server(vec![r#"{"token":"extracted"}"#, "{}"]);
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("bruno.json"), "{}").unwrap();
        fs::write(directory.path().join("01-login.bru"), format!("get {{\n  url: {url}/login\n}}\nvars:post-response {{\n  token: res.body.token\n}}\n")).unwrap();
        fs::write(directory.path().join("02-api.bru"), format!("get {{\n  url: {url}/api\n  auth: bearer\n}}\nauth:bearer {{\n  token: {{{{token}}}}\n}}\n")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_quinn"));
        command
            .arg("run")
            .arg(directory.path())
            .args(["--json", "--timeout", "3"]);
        if explicit {
            command.args(["--var", "token=explicit"]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let requests = server.join().unwrap();
        let token = if explicit { "explicit" } else { "extracted" };
        assert!(
            String::from_utf8_lossy(&requests[1])
                .contains(&format!("authorization: Bearer {token}"))
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report.as_array().unwrap().len(), 2);
        assert!(report[0]["response"].get("variables").is_none());
    }
}
