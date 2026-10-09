#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use quinn_api::{collection, engine::Engine, variables::Variables};

fn http_server(replies: Vec<&'static str>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        replies.into_iter().map(|body| {
        let started = Instant::now();
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(started.elapsed() < Duration::from_secs(10));
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = socket.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&buffer[..count]);
            assert!(bytes.len() < 1_048_576);
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                let length = headers.lines().find_map(|line| line.strip_prefix("content-length: ")).unwrap_or("0").parse::<usize>().unwrap();
                if bytes.len() >= end + 4 + length { break; }
            }
        }
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        String::from_utf8(bytes).unwrap()
    }).collect()
    });
    (url, worker)
}

#[test]
fn graphql_selected_variant_runs_in_cli_and_keeps_yaml_source() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("opencollection.yml"),
        "opencollection: 1.0.0\ninfo: {name: GraphQL}\n",
    )
    .unwrap();
    let (url, server) = http_server(vec![r#"{"data":{"user":{"id":42}}}"#]);
    let source = format!(
        "# This source stays unchanged.\ninfo: {{name: User, type: graphql}}\ngraphql:\n  url: '{url}/graphql'\n  headers: [{{name: X-Request, value: graphql}}]\n  body:\n    - title: unused\n      body: {{query: unused, variables: unused}}\n    - title: selected\n      selected: true\n      body:\n        query: 'query User($id: Int!) {{ user(id: $id) {{ id }} }}'\n        variables: '{{\"id\":42}}'\nruntime:\n  assertions: [{{expression: res.body.data.user.id, operator: eq, value: '42'}}]\n"
    );
    let path = directory.path().join("user.yml");
    fs::write(&path, &source).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["run", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let request = server.join().unwrap().remove(0);
    assert!(request.starts_with("POST /graphql HTTP/1.1"));
    let body: serde_json::Value =
        serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["variables"]["id"], 42);
    assert!(body["query"].as_str().unwrap().contains("query User"));
    assert_eq!(collection::read(&path).unwrap(), source);
}

#[test]
fn yaml_inherited_oauth_fetches_and_reuses_token_with_canonical_defaults() {
    let (url, server) = http_server(vec![
        r#"{"access_token":"yaml-token","token_type":"Bearer","expires_in":3600}"#,
        "{}",
        "{}",
    ]);
    let defaults = collection::parse(Path::new("folder.yml"), &format!("info: {{name: OAuth}}\nrequest:\n  auth:\n    type: oauth2\n    flow: client_credentials\n    accessTokenUrl: '{url}/token'\n    credentials:\n      clientId: yaml-client\n      clientSecret: yaml-secret\n      placement: basic_auth_header\n    tokenConfig: {{id: credentials, placement: {{header: Bearer}}}}\n")).unwrap();
    assert_eq!(
        defaults
            .value("auth:oauth2", "auto_refresh_token")
            .unwrap()
            .as_deref(),
        Some("true")
    );
    let request = collection::parse(
        Path::new("request.yml"),
        &format!("info: {{type: http}}\nhttp: {{url: '{url}/api', auth: inherit}}\n"),
    )
    .unwrap();
    let engine = Engine::new(Duration::from_secs(5)).unwrap();
    for _ in 0..2 {
        assert!(
            engine
                .send(&request, std::slice::from_ref(&defaults), &Variables::new())
                .unwrap()
                .passed()
        );
    }
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with("POST /token"));
    assert!(requests[0].contains("grant_type=client_credentials"));
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: basic ")
    );
    for request in &requests[1..] {
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer yaml-token")
        );
    }
}

#[test]
fn canonical_oauth_authorization_code_and_refresh_fields_map_to_bru() {
    let document = collection::parse(Path::new("request.yml"), "graphql:\n  url: https://api.example/graphql\n  auth:\n    type: oauth2\n    flow: authorization_code\n    authorizationUrl: https://identity.example/authorize\n    accessTokenUrl: https://identity.example/token\n    refreshTokenUrl: https://identity.example/refresh\n    callbackUrl: http://127.0.0.1:0/callback\n    credentials: {clientId: public-client, placement: body}\n    pkce: {method: S256}\n    settings: {autoFetchToken: true, autoRefreshToken: false}\n").unwrap();
    for (key, value) in [
        ("grant_type", "authorization_code"),
        ("pkce", "true"),
        ("client_id", "public-client"),
        ("refresh_token_url", "https://identity.example/refresh"),
        ("auto_refresh_token", "false"),
    ] {
        assert_eq!(
            document.value("auth:oauth2", key).unwrap().as_deref(),
            Some(value)
        );
    }
    assert_eq!(
        document.value("post", "auth").unwrap().as_deref(),
        Some("oauth2")
    );
}

#[test]
fn grpc_ordered_messages_and_selected_websocket_variant_map_to_bru() {
    let grpc = collection::parse(Path::new("request.yml"), "info: {type: grpc}\ngrpc:\n  url: grpc://localhost:50051\n  method: /quinn.stream.Streams/Client\n  methodType: client-streaming\n  protoFilePath: streams.proto\n  metadata: [{name: X-User, value: Quinn}]\n  message:\n    - title: first\n      message: '{\"text\":\"first\"}'\n    - title: second\n      message: '{\"text\":\"second\"}'\n").unwrap();
    assert_eq!(
        grpc.value("grpc", "protoPath").unwrap().as_deref(),
        Some("streams.proto")
    );
    let messages: Vec<_> = grpc
        .blocks
        .iter()
        .filter(|block| block.name == "body:grpc")
        .collect();
    assert_eq!(messages.len(), 2);
    assert!(messages[0].content.contains("first"));
    assert!(messages[1].content.contains("second"));
    let websocket = collection::parse(Path::new("request.yml"), "info: {type: websocket}\nwebsocket:\n  url: ws://localhost:3000\n  message:\n    - title: unused\n      message: {type: text, data: unused}\n    - title: selected\n      selected: true\n      message: {type: text, data: hello}\n").unwrap();
    assert_eq!(
        websocket.value("body:ws", "content").unwrap().as_deref(),
        Some("hello")
    );
}

#[test]
fn unsupported_yaml_protocol_and_oauth_semantics_fail_before_io() {
    for source in [
        "info: {type: graphql}\nhttp: {url: http://localhost}\n",
        "http: {}\ngraphql: {}\n",
        "graphql: {body: {query: query, variables: {id: 42}}}\n",
        "graphql: {body: [{selected: true, body: {}}, {selected: true, body: {}}]}\n",
        "http: {auth: {type: oauth2, flow: implicit}}\n",
        "http: {auth: {type: oauth2, credentials: {placement: other}}}\n",
        "http: {auth: {type: oauth2, tokenConfig: {placement: {query: token}}}}\n",
        "http: {auth: {type: oauth2, settings: {autoFetchToken: false}}}\n",
        "http: {auth: {type: oauth2, flow: authorization_code}}\n",
        "http: {auth: {type: oauth2, flow: authorization_code, pkce: {disabled: true}}}\n",
        "websocket: {message: {type: binary, data: abc}}\n",
        "websocket: {message: [{selected: true, message: {}}, {selected: true, message: {}}]}\n",
        "grpc: {message: [{message: '{}', selected: true}]}\n",
        "grpc: {message: []}\n",
        "grpc: {tls: {rejectUnauthorized: false}}\n",
        "http: {auth: {type: oauth2, tokenConfig: {source: id_token}}}\n",
        "http: {auth: {type: awsv4, profileName: shared-profile}}\n",
    ] {
        assert!(
            collection::parse(Path::new("request.yml"), source).is_err(),
            "{source}"
        );
    }
}

#[test]
fn yaml_aws_explicit_credentials_map_to_canonical_auth_block() {
    let document = collection::parse(Path::new("request.yml"), "http:\n  url: https://example.execute-api.us-east-1.amazonaws.com\n  auth:\n    type: awsv4\n    accessKeyId: '{{accessKey}}'\n    secretAccessKey: '{{secretKey}}'\n    sessionToken: '{{sessionToken}}'\n    region: us-east-1\n    service: execute-api\n").unwrap();
    assert_eq!(
        document.value("get", "auth").unwrap().as_deref(),
        Some("awsv4")
    );
    assert_eq!(
        document
            .value("auth:awsv4", "accessKeyId")
            .unwrap()
            .as_deref(),
        Some("{{accessKey}}")
    );
    assert_eq!(
        document.value("auth:awsv4", "service").unwrap().as_deref(),
        Some("execute-api")
    );
}

#[test]
fn yaml_invalid_graphql_json_and_websocket_messages_fail_before_connect() {
    let engine = Engine::new(Duration::from_secs(5)).unwrap();
    for (source, expected) in [
        (
            "graphql: {url: 'http://127.0.0.1:1', body: {query: query, variables: invalid}}\n",
            "GraphQL",
        ),
        (
            "websocket: {url: 'ws://127.0.0.1:1', message: {type: json, data: invalid}}\n",
            "WebSocket JSON",
        ),
        (
            "http: {url: 'http://127.0.0.1:1', auth: {type: oauth2, flow: authorization_code, authorizationUrl: 'http://example.com/authorize', accessTokenUrl: 'https://example.com/token', credentials: {clientId: public-client}, pkce: {}}}\n",
            "https",
        ),
    ] {
        let document = collection::parse(Path::new("request.yml"), source).unwrap();
        let error = engine
            .send(&document, &[], &Variables::new())
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("connection failed"), "{error}");
    }
}

#[test]
fn http_body_variants_select_one_existing_body_type_without_reading_inactive_data() {
    for (body, mode, block) in [
        (
            serde_json::json!({"type":"json", "data":"{\"active\":true}"}),
            "json",
            "body:json",
        ),
        (
            serde_json::json!({"type":"text", "data":"active"}),
            "text",
            "body:text",
        ),
        (
            serde_json::json!({"type":"xml", "data":"<active/>"}),
            "xml",
            "body:xml",
        ),
        (
            serde_json::json!({"type":"sparql", "data":"SELECT * WHERE {?s ?p ?o}"}),
            "sparql",
            "body:sparql",
        ),
        (
            serde_json::json!({"type":"form-urlencoded", "data":[{"name":"active", "value":"yes"}]}),
            "formUrlEncoded",
            "body:form-urlencoded",
        ),
        (
            serde_json::json!({"type":"multipart-form", "data":[{"name":"active", "type":"text", "value":"yes"}]}),
            "multipartForm",
            "body:multipart-form",
        ),
        (
            serde_json::json!({"type":"file", "data":[{"filePath":"active.txt", "selected":true}]}),
            "file",
            "body:file",
        ),
    ] {
        let source = serde_yaml_ng::to_string(&serde_json::json!({"http": {
            "method":"POST", "url":"http://localhost", "body":[
                {"title":"inactive", "body":{"type":"unsupported", "dangerous":"{{missing}}"}},
                {"title":"active", "selected":true, "body":body}
            ]
        }}))
        .unwrap();
        let document = collection::parse(Path::new("request.yml"), &source).unwrap();
        assert_eq!(
            document.value("post", "body").unwrap().as_deref(),
            Some(mode)
        );
        assert!(document.block(block).is_some());
    }
    let first = collection::parse(Path::new("request.yml"), "http:\n  method: POST\n  body:\n    - title: first\n      body: {type: text, data: first}\n    - title: second\n      body: {type: text, data: second}\n").unwrap();
    assert_eq!(first.block("body:text").unwrap().content, "first");
}

#[test]
fn selected_http_body_runs_in_cli_with_interpolation_and_unchanged_source() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("opencollection.yml"),
        "opencollection: 1.0.0\n",
    )
    .unwrap();
    let (url, server) = http_server(vec!["{}"]);
    let source = serde_yaml_ng::to_string(&serde_json::json!({
        "info":{"type":"http", "name":"Selected JSON"},
        "http":{"method":"POST", "url":url, "body":[
            {"title":"inactive upload", "body":{"type":"file", "data":[{"filePath":"does-not-exist", "selected":true}]}},
            {"title":"active JSON", "selected":true, "body":{"type":"json", "data":"{\"message\":\"{{name}}\",\"active\":true}"}}
        ]},
        "runtime":{"variables":[{"name":"name", "value":"Quinn"}]}
    })).unwrap();
    let source = format!("# Preserve this source.\n{source}");
    let path = directory.path().join("request.yml");
    fs::write(&path, &source).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["run", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let wire = server.join().unwrap().remove(0);
    assert!(
        wire.to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(wire.split_once("\r\n\r\n").unwrap().1).unwrap(),
        serde_json::json!({"message":"Quinn", "active":true})
    );
    assert_eq!(collection::read(&path).unwrap(), source);
}

#[test]
fn selected_form_multipart_and_file_variants_execute_existing_upload_paths() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("active.txt"), "active file").unwrap();
    for (body, expected) in [
        (
            serde_json::json!({"type":"form-urlencoded", "data":[{"name":"message", "value":"active form"}]}),
            "message=active+form",
        ),
        (
            serde_json::json!({"type":"multipart-form", "data":[{"name":"message", "type":"text", "value":"active multipart"}]}),
            "active multipart",
        ),
        (
            serde_json::json!({"type":"file", "data":[{"filePath":"active.txt", "selected":true}]}),
            "active file",
        ),
    ] {
        let (url, server) = http_server(vec!["{}"]);
        let source = serde_yaml_ng::to_string(&serde_json::json!({"http": {
            "method":"POST", "url":url, "body":[
                {"title":"inactive", "body":{"type":"file", "data":[{"filePath":"missing", "selected":true}]}},
                {"title":"active", "selected":true, "body":body}
            ]
        }})).unwrap();
        let document = collection::parse(Path::new("request.yml"), &source).unwrap();
        assert!(
            Engine::new(Duration::from_secs(5))
                .unwrap()
                .send_in(&document, &[], &Variables::new(), directory.path())
                .unwrap()
                .passed()
        );
        let wire = server.join().unwrap().remove(0);
        assert!(
            wire.split_once("\r\n\r\n").unwrap().1.contains(expected),
            "{wire}"
        );
    }
}

#[test]
fn graphql_json_variable_text_keeps_interpolation_nested_objects_arrays_and_nulls() {
    let (url, server) = http_server(vec!["{}"]);
    let source = serde_yaml_ng::to_string(&serde_json::json!({"graphql":{
        "url":url, "body":{"query":"query User($id: Int!) { user(id: $id) { id } }", "variables":r#"{"id":{{id}},"name":"{{name}}","list":[1,null,{"flag":true}]}"#}
    }})).unwrap();
    let document = collection::parse(Path::new("request.yml"), &source).unwrap();
    let variables = Variables::from([("id".into(), "42".into()), ("name".into(), "Quinn".into())]);
    assert!(
        Engine::new(Duration::from_secs(5))
            .unwrap()
            .send(&document, &[], &variables)
            .unwrap()
            .passed()
    );
    let wire = server.join().unwrap().remove(0);
    let body: serde_json::Value =
        serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(
        body["variables"],
        serde_json::json!({"id":42,"name":"Quinn","list":[1,null,{"flag":true}]})
    );
    for variables in [
        serde_json::json!({"id":42}),
        serde_json::json!([1, 2]),
        serde_json::json!(42),
        serde_json::json!(true),
        serde_json::Value::Null,
    ] {
        let source = serde_yaml_ng::to_string(
            &serde_json::json!({"graphql":{"body":{"variables":variables}}}),
        )
        .unwrap();
        assert!(collection::parse(Path::new("request.yml"), &source).is_err());
    }
}

#[test]
fn invalid_selected_http_variants_fail_before_cli_network_and_oauth() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("opencollection.yml"),
        "opencollection: 1.0.0\n",
    )
    .unwrap();
    for body in [
        serde_json::json!([]),
        serde_json::json!([{"title":"one", "selected":true, "body":{"type":"text","data":"one"}}, {"title":"two", "selected":true, "body":{"type":"text","data":"two"}}]),
        serde_json::json!([{"title":"bad", "selected":"true", "body":{"type":"text","data":"one"}}]),
        serde_json::json!([{"title":"bad", "selected":true}]),
        serde_json::json!([{"title":"bad", "body":{"type":"execute","data":"dangerous"}}]),
        serde_json::json!([{"title":"bad", "body":{"type":"json","data":"{}","execute":"dangerous"}}]),
        serde_json::json!([{"title":"bad", "selected":true, "body":{"type":"json","data":"invalid"}}]),
        serde_json::json!([{"title":"bad", "selected":true, "body":{"type":"text","data":"{{missing}}"}}]),
        serde_json::json!([{"title":"bad", "selected":true, "body":{"type":"file","data":[{"filePath":"missing","selected":true}]}}]),
    ] {
        let source = serde_yaml_ng::to_string(&serde_json::json!({"http": {
            "method":"POST", "url":url, "body":body,
            "auth":{"type":"oauth2", "flow":"client_credentials", "accessTokenUrl":format!("{url}/token"), "credentials":{"clientId":"client", "clientSecret":"secret"}}
        }})).unwrap();
        let path = directory.path().join("request.yml");
        fs::write(&path, source).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_quinn"))
            .args(["run", path.to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
