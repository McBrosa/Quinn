#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
    time::Duration,
};

use quinn_api::{
    bru::Document,
    collection,
    engine::Engine,
    variables::{Variables, interpolate},
};

#[test]
fn parser_keeps_nested_bodies_quoted_keys_and_disabled_pairs() {
    let document = Document::parse("\u{feff}meta {\r\n  name: Example\r\n  tags: [\r\n    api\r\n  ]\r\n}\r\nheaders {\r\n  \"colon:key\": value\r\n  ~unused: {{missing}}\r\n}\r\nbody:json {\r\n  {\r\n    \"nested\": {\"key\": true}\r\n  }\r\n}\r\n").unwrap();
    assert_eq!(
        document.value("meta", "name").unwrap().as_deref(),
        Some("Example")
    );
    let pairs = document.pairs("headers").unwrap();
    assert_eq!(pairs[0].key, "colon:key");
    assert!(!pairs[1].enabled);
    assert_eq!(
        document.block("body:json").unwrap().content,
        "{\n  \"nested\": {\"key\": true}\n}"
    );
}

#[test]
fn parser_rejects_malformed_input_and_reads_multiline_values() {
    assert!(Document::parse("get {\n  url: http://localhost").is_err());
    assert!(Document::parse("get {\n}\nget {\n}\n").is_err());
    assert!(Document::parse("get {\n}\nstray").is_err());
    let document =
        Document::parse("vars {\n  message: '''\n  first\n  second\n  '''\n}\n").unwrap();
    assert_eq!(
        document.value("vars", "message").unwrap().as_deref(),
        Some("first\nsecond")
    );
}

#[test]
fn variables_support_nesting_and_reject_cycles_and_missing_values() {
    let mut values = Variables::from([
        ("host".into(), "http://localhost".into()),
        ("url".into(), "{{host}}/api".into()),
    ]);
    assert_eq!(
        interpolate("{{url}}?x={{host}}", &values).unwrap(),
        "http://localhost/api?x=http://localhost"
    );
    assert!(interpolate("{{missing}}", &values).is_err());
    assert!(interpolate("{{host", &values).is_err());
    values.insert("host".into(), "{{url}}".into());
    assert!(interpolate("{{url}}", &values).is_err());
}

#[test]
fn discovery_orders_requests_and_loads_folder_defaults() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("folder")).unwrap();
    fs::create_dir(root.join("environments")).unwrap();
    fs::write(root.join("bruno.json"), "{}").unwrap();
    fs::write(
        root.join("collection.bru"),
        "headers {\n  x-root: root\n}\n",
    )
    .unwrap();
    fs::write(
        root.join("folder/folder.bru"),
        "headers {\n  x-folder: folder\n}\n",
    )
    .unwrap();
    for (name, seq) in [("A", 2), ("B", 1)] {
        fs::write(
            root.join(format!("folder/{name}.bru")),
            format!(
                "meta {{\n  name: {name}\n  seq: {seq}\n}}\nget {{\n  url: http://localhost\n}}\n"
            ),
        )
        .unwrap();
    }
    fs::write(
        root.join("environments/Local.bru"),
        "vars {\n  host: http://localhost\n  ~disabled: secret\n}\n",
    )
    .unwrap();
    let entries = collection::discover(root).unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["B", "A"]
    );
    assert_eq!(
        collection::root(&entries[0].path).unwrap(),
        fs::canonicalize(root).unwrap()
    );
    let defaults = collection::defaults(root, &entries[0].path).unwrap();
    assert_eq!(defaults.len(), 2);
    assert_eq!(collection::environment(root, "Local").unwrap().len(), 1);
    assert!(collection::environment(root, "../Local").is_err());
}

#[test]
fn save_preserves_source_and_refuses_external_changes_or_invalid_input() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("request.bru");
    let original = "get {\n  url: http://localhost\n}\n";
    let edited = "get {\n  url: http://localhost/changed\n}\n";
    fs::write(&path, original).unwrap();
    collection::save(&path, original, edited).unwrap();
    assert_eq!(collection::read(&path).unwrap(), edited);
    assert!(collection::save(&path, original, original).is_err());
    assert_eq!(collection::read(&path).unwrap(), edited);
    assert!(collection::save(&path, edited, "get {\n").is_err());
    assert_eq!(collection::read(&path).unwrap(), edited);
}

#[cfg(unix)]
#[test]
fn discovery_ignores_symbolic_link_loops() {
    let directory = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(directory.path(), directory.path().join("loop")).unwrap();
    assert!(collection::discover(directory.path()).unwrap().is_empty());
}

#[test]
fn engine_sends_form_data_and_basic_auth() {
    let (url, server) = serve_once("{}", "200 OK");
    let request = Document::parse(&format!("post {{\n  url: {url}\n  body: form-urlencoded\n  auth: basic\n}}\nauth:basic {{\n  username: user\n  password: pass\n}}\nbody:form-urlencoded {{\n  value: a b&c\n  ~disabled: {{{{missing}}}}\n}}\n")).unwrap();
    Engine::new(Duration::from_secs(5))
        .unwrap()
        .send(&request, &[], &Variables::new())
        .unwrap();
    let wire = server.join().unwrap();
    assert!(wire.contains("authorization: Basic dXNlcjpwYXNz"), "{wire}");
    assert!(
        wire.contains("content-type: application/x-www-form-urlencoded"),
        "{wire}"
    );
    assert!(wire.ends_with("value=a+b%26c"), "{wire}");
}

#[test]
fn engine_resolves_assertion_variables_before_sending() {
    let request = Document::parse(
        "get {\n  url: http://127.0.0.1:1\n}\nassert {\n  res.status: eq {{missing}}\n}\n",
    )
    .unwrap();
    let error = Engine::new(Duration::from_secs(1))
        .unwrap()
        .send(&request, &[], &Variables::new())
        .unwrap_err();
    assert!(
        error.to_string().contains("cannot resolve variable"),
        "{error}"
    );
}

#[test]
fn engine_sends_api_key_as_query_parameter() {
    let (url, server) = serve_once("{}", "200 OK");
    let request = Document::parse(&format!("get {{\n  url: {url}/key\n  auth: apikey\n}}\nauth:apikey {{\n  key: api_key\n  value: a b\n  placement: queryparams\n}}\n")).unwrap();
    Engine::new(Duration::from_secs(5))
        .unwrap()
        .send(&request, &[], &Variables::new())
        .unwrap();
    assert!(
        server
            .join()
            .unwrap()
            .starts_with("GET /key?api_key=a+b HTTP/1.1")
    );
}

fn serve_once(body: &'static str, status: &'static str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let length = socket.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..length]);
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                let length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:").map(str::trim))
                    .unwrap_or("0")
                    .parse::<usize>()
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
        }
        write!(socket, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (url, handle)
}

#[test]
fn engine_sends_json_inherits_headers_auth_and_checks_assertions() {
    let (url, server) = serve_once("{\"ok\":true,\"count\":3}", "200 OK");
    let defaults = vec![Document::parse("headers {\n  x-inherited: yes\n  x-disabled: inherited\n}\nauth {\n  mode: bearer\n}\nauth:bearer {\n  token: {{token}}\n}\n").unwrap()];
    let source = "post {\n  url: {{url}}/items/:id/:identity\n  body: json\n  auth: inherit\n}\nparams:path {\n  id: a/b\n}\nparams:query {\n  q: a b&c\n  ~disabled: {{missing}}\n}\nheaders {\n  ~x-disabled: ignored\n}\nbody:json {\n  {\"message\": \"hello\"}\n}\nassert {\n  res.status: eq 200\n  res.body.ok: eq true\n  res.body.count: gte 2\n  res.headers.content-type: contains json\n}\n";
    let request = Document::parse(source).unwrap();
    let variables = Variables::from([("url".into(), url), ("token".into(), "test-token".into())]);
    let response = Engine::new(Duration::from_secs(5))
        .unwrap()
        .send(&request, &defaults, &variables)
        .unwrap();
    let wire = server.join().unwrap();
    assert!(
        wire.starts_with("POST /items/a%2Fb/:identity?q=a+b%26c HTTP/1.1"),
        "{wire}"
    );
    assert!(wire.contains("authorization: Bearer test-token"), "{wire}");
    assert!(wire.contains("x-inherited: yes"));
    assert!(!wire.contains("x-disabled:"));
    assert!(wire.ends_with("{\"message\": \"hello\"}"));
    assert!(response.passed());
    assert_eq!(response.assertions.len(), 4);
}

#[test]
fn engine_sends_graphql_and_reports_failed_assertion() {
    let (url, server) = serve_once("{\"data\":{\"name\":\"Quinn\"}}", "200 OK");
    let request = Document::parse(&format!("post {{\n  url: {url}\n  body: graphql\n}}\nbody:graphql {{\n  query {{ name }}\n}}\nbody:graphql:vars {{\n  {{\"id\":3}}\n}}\nassert {{\n  res.body.data.name: eq Bruno\n}}\n")).unwrap();
    let response = Engine::new(Duration::from_secs(5))
        .unwrap()
        .send(&request, &[], &Variables::new())
        .unwrap();
    let wire = server.join().unwrap();
    let body = wire.split("\r\n\r\n").nth(1).unwrap();
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(value["variables"]["id"], 3);
    assert_eq!(value["query"], "query { name }");
    assert!(!response.passed());
}

#[test]
fn engine_rejects_unsupported_features_before_network_io() {
    let engine = Engine::new(Duration::from_secs(1)).unwrap();
    for extra in [
        "script:pre-request {\n  console.log('hi');\n}\n",
        "tests {\n  expect(true);\n}\n",
        "assert {\n  res.status: mystery 200\n}\n",
    ] {
        let request =
            Document::parse(&format!("get {{\n  url: http://127.0.0.1:1\n}}\n{extra}")).unwrap();
        let error = engine.send(&request, &[], &Variables::new()).unwrap_err();
        assert!(error.to_string().contains("unsupported"), "{error}");
    }
}

#[test]
fn cli_returns_json_and_nonzero_for_http_errors() {
    let (url, server) = serve_once("{\"error\":\"missing\"}", "404 Not Found");
    let directory = tempfile::tempdir().unwrap();
    let request = directory.path().join("request.bru");
    fs::write(&request, format!("get {{\n  url: {url}\n}}\n")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["run", request.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value[0]["response"]["status"], 404);
    assert_eq!(value[0]["passed"], false);
}
