#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

use quinn_api::{
    bru::Document,
    collection,
    engine::Engine,
    exporters,
    importers::{self, Format},
    variables::Variables,
};
use serde_json::{Value, json};

fn insomnia() -> Value {
    json!({
        "_type":"export","__export_format":4,
        "resources":[
            {"_id":"req","_type":"request","parentId":"folder","name":"../Send",
             "url":"{{ _.base }}/users/:id","method":"POST",
             "parameters":[{"name":"q","value":"{{ _.search }}"}],
             "pathParameters":[{"name":"id","value":"42"}],
             "headers":[{"name":"X-Off","value":"no","disabled":true}],
             "authentication":{"type":"bearer","token":"{{ _.token }}"},
             "body":{"mimeType":"application/json","text":"{\"value\":\"{{ _.search }}\"}"}},
            {"_id":"folder","_type":"request_group","parentId":"workspace","name":"Folder"},
            {"_id":"workspace","_type":"workspace","name":"Workspace"},
            {"_id":"env","_type":"environment","parentId":"workspace",
             "data":{"base":"https://example.test","search":"a b","token":"secret"}}
        ]
    })
}

#[test]
fn insomnia_v4_resolves_folders_base_environment_and_templates() {
    let imported = importers::parse(Format::Insomnia, &insomnia().to_string()).unwrap();
    assert_eq!(imported.name, "Workspace");
    assert_eq!(imported.variables["base"], "https://example.test");
    assert_eq!(imported.requests[0].name, "Folder / ../Send");
    let document = Document::parse(&imported.requests[0].source).unwrap();
    assert_eq!(
        document.value("post", "url").unwrap().unwrap(),
        "{{base}}/users/:id"
    );
    assert_eq!(
        document.value("auth:bearer", "token").unwrap().unwrap(),
        "{{token}}"
    );
    assert!(!document.pairs("headers").unwrap()[0].enabled);
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("imported");
    imported.write_to(&destination).unwrap();
    assert_eq!(collection::discover(&destination).unwrap().len(), 1);
    assert!(!dir.path().join("Send.bru").exists());
}

#[test]
fn insomnia_rejects_cycles_duplicate_ids_missing_parents_and_other_workspaces() {
    let mut input = insomnia();
    input["resources"][1]["parentId"] = json!("folder");
    assert!(importers::parse(Format::Insomnia, &input.to_string()).is_err());
    let mut input = insomnia();
    input["resources"][0]["parentId"] = json!("missing");
    assert!(importers::parse(Format::Insomnia, &input.to_string()).is_err());
    let mut input = insomnia();
    input["resources"][1]["_id"] = json!("req");
    assert!(importers::parse(Format::Insomnia, &input.to_string()).is_err());
    let mut input = insomnia();
    input["resources"]
        .as_array_mut()
        .unwrap()
        .push(json!({"_type":"workspace","_id":"other","name":"Other"}));
    assert!(importers::parse(Format::Insomnia, &input.to_string()).is_err());
}

#[test]
fn insomnia_rejects_scripts_dynamic_templates_settings_files_and_child_environments() {
    for (key, value) in [
        ("preRequestScript", json!("insomnia.sendRequest()")),
        ("afterResponseScript", json!("throw 1")),
        ("url", json!("https://example.test/{% uuid 'v4' %}")),
        ("url", json!("https://example.test/{{ _.nested.value }}")),
        ("settingFollowRedirects", json!(false)),
        ("authentication", json!({"type":"oauth2"})),
        (
            "authentication",
            json!({"type":"bearer", "token":"abc", "sendTo":"query"}),
        ),
        (
            "body",
            json!({"mimeType":"multipart/form-data","params":[{"name":"file","type":"file","fileName":"secret"}]}),
        ),
    ] {
        let mut input = insomnia();
        input["resources"][0][key] = value;
        assert!(
            importers::parse(Format::Insomnia, &input.to_string()).is_err(),
            "{key}"
        );
    }
    let mut input = insomnia();
    input["resources"][3]["parentId"] = json!("env");
    assert!(importers::parse(Format::Insomnia, &input.to_string()).is_err());
}

fn fixture(root: &Path, base: &str) {
    fs::write(
        root.join("bruno.json"),
        r#"{"name":"API","version":"1","type":"collection"}"#,
    )
    .unwrap();
    fs::write(root.join("collection.bru"), format!("vars:pre-request {{\n  base: {base}\n  token: parent\n}}\nauth {{\n  mode: bearer\n}}\nauth:bearer {{\n  token: {{{{token}}}}\n}}\nheaders {{\n  X-Parent: yes\n}}\n")).unwrap();
    fs::write(root.join("request.bru"), "meta {\n  name: Send\n  type: http\n  seq: 1\n}\npost {\n  url: {{base}}/users/:id\n  body: json\n  auth: inherit\n}\nvars:pre-request {\n  token: secret\n}\nparams:path {\n  id: 42\n}\nparams:query {\n  q: a b\n  ~off: ignored\n}\nheaders {\n  X-Parent: overridden\n  ~X-Off: ignored\n}\nbody:json {\n  {\"ok\":true}\n}\n").unwrap();
}

#[test]
fn postman_export_flattens_defaults_without_changing_vars_auth_or_disabled_pairs() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), "https://example.test");
    let output = exporters::export(exporters::Format::Postman, root.path(), None).unwrap();
    let imported = importers::parse(Format::Postman, &output).unwrap();
    let document = Document::parse(&imported.requests[0].source).unwrap();
    assert_eq!(
        document.value("post", "url").unwrap().unwrap(),
        "{{base}}/users/:id"
    );
    assert_eq!(document.value("post", "auth").unwrap().unwrap(), "bearer");
    assert_eq!(
        document
            .value("vars:pre-request", "token")
            .unwrap()
            .unwrap(),
        "secret"
    );
    assert_eq!(
        document.value("headers", "X-Parent").unwrap().unwrap(),
        "overridden"
    );
    assert!(!document.pairs("params:query").unwrap()[1].enabled);
}

#[test]
fn converter_roundtrips_execute_same_wire_request_offline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut messages = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while messages.len() < 3 {
            let Ok((mut stream, _)) = listener.accept() else {
                assert!(std::time::Instant::now() < deadline, "server deadline");
                thread::sleep(Duration::from_millis(5));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    let length: usize = headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse().unwrap())
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            messages.push(String::from_utf8(bytes).unwrap());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
        }
        messages
    });
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), &base);
    let request_path = root.path().join("request.bru");
    let source = collection::read(&request_path)
        .unwrap()
        .replace("auth: inherit", "auth: none");
    fs::write(&request_path, source).unwrap();
    let engine = Engine::new(Duration::from_secs(5)).unwrap();
    let original =
        Document::parse(&collection::read(&root.path().join("request.bru")).unwrap()).unwrap();
    let defaults = collection::defaults(root.path(), &root.path().join("request.bru")).unwrap();
    assert!(
        engine
            .send(&original, &defaults, &Variables::new())
            .unwrap()
            .passed()
    );
    for format in [exporters::Format::Postman, exporters::Format::OpenApi] {
        let output = exporters::export(format, root.path(), None).unwrap();
        let format = match format {
            exporters::Format::Postman => Format::Postman,
            exporters::Format::OpenApi => Format::OpenApi,
        };
        let imported = importers::parse(format, &output).unwrap();
        let document = Document::parse(&imported.requests[0].source).unwrap();
        assert!(
            engine
                .send(&document, &[], &imported.variables)
                .unwrap()
                .passed()
        );
    }
    let messages = server.join().unwrap();
    for message in messages {
        let lower = message.to_ascii_lowercase();
        assert!(message.starts_with("POST /users/42?q=a+b HTTP/1.1"));
        assert!(!lower.contains("authorization:"));
        assert!(lower.contains("x-parent: overridden\r\n"));
        assert!(!lower.contains("x-off:"));
        assert!(message.ends_with("{\"ok\":true}") || message.ends_with("{\n  \"ok\": true\n}"));
    }
}

#[test]
fn insomnia_import_executes_headers_query_and_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).unwrap();
        let message = String::from_utf8_lossy(&bytes[..count]).to_string();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .unwrap();
        message
    });
    let mut input = insomnia();
    input["resources"][3]["data"]["base"] = json!(base);
    let imported = importers::parse(Format::Insomnia, &input.to_string()).unwrap();
    let document = Document::parse(&imported.requests[0].source).unwrap();
    let engine = Engine::new(Duration::from_secs(5)).unwrap();
    assert!(
        engine
            .send(&document, &[], &imported.variables)
            .unwrap()
            .passed()
    );
    let message = server.join().unwrap();
    assert!(message.starts_with("POST /users/42?q=a+b HTTP/1.1"));
    assert!(
        message
            .to_ascii_lowercase()
            .contains("authorization: bearer secret")
    );
}

#[test]
fn unsupported_exports_fail_before_output_creation_and_openapi_rejects_collisions() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), "https://example.test");
    let file = root.path().join("request.bru");
    let original = collection::read(&file).unwrap();
    for block in [
        "script:pre-request",
        "tests",
        "vars:post-response",
        "assert",
        "settings",
        "grpc",
    ] {
        fs::write(
            &file,
            format!("{original}\n{block} {{\n  unsupported\n}}\n"),
        )
        .unwrap();
        assert!(
            exporters::export(exporters::Format::Postman, root.path(), None).is_err(),
            "{block}"
        );
    }
    fs::write(&file, &original).unwrap();
    fs::write(root.path().join("duplicate.bru"), &original).unwrap();
    assert!(exporters::export(exporters::Format::OpenApi, root.path(), None).is_err());
    assert!(exporters::export(exporters::Format::Postman, root.path(), None).is_ok());
}

#[test]
fn export_cli_creates_new_file_and_never_overwrites_existing_output() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), "https://example.test");
    let file = root.path().join("output.json");
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["export", "postman"])
        .arg(root.path())
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let original = fs::read(&file).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["export", "postman"])
        .arg(root.path())
        .arg(&file)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(&file).unwrap(), original);
    assert!(exporters::write_new(&file, "not JSON").is_err());
    assert_eq!(fs::read(&file).unwrap(), original);
}

#[test]
fn export_rejects_unknown_enabled_fields_conflicting_bodies_and_list_vars() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), "https://example.test");
    let file = root.path().join("request.bru");
    let original = collection::read(&file).unwrap();
    for source in [
        original.replace(
            "auth: inherit",
            "auth: inherit\n  unsupported-setting: true",
        ),
        original.replace("auth: inherit", "auth: bearer")
            + "\nauth:bearer {\n  token: abc\n  unsupported-setting: true\n}\n",
        original.clone() + "\nbody:text {\n  ignored\n}\n",
        original.replace("token: secret", "token: [\n    a\n    b\n  ]"),
    ] {
        fs::write(&file, source).unwrap();
        let destination = root.path().join("never-created.json");
        let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
            .args(["export", "postman"])
            .arg(root.path())
            .arg(&destination)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!destination.exists());
    }
    fs::write(&file, original).unwrap();
    assert!(exporters::export(exporters::Format::OpenApi, root.path(), None).is_err());
}

#[cfg(unix)]
#[test]
fn export_does_not_follow_existing_destination_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("secret.json");
    fs::write(&target, "keep me").unwrap();
    let output = root.path().join("output.json");
    std::os::unix::fs::symlink(&target, &output).unwrap();
    assert!(exporters::write_new(&output, "{}").is_err());
    assert_eq!(fs::read_to_string(target).unwrap(), "keep me");
}

#[test]
fn yaml_collections_export_through_the_shared_loader() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("opencollection.yml"), "opencollection: 1.0.0\ninfo:\n  name: YAML\nrequest:\n  headers:\n    - name: X-Parent\n      value: inherited\n").unwrap();
    fs::write(root.path().join("request.yml"), "info:\n  name: Get users\n  type: http\n  seq: 1\nhttp:\n  method: GET\n  url: https://example.test/users\nsettings:\n  timeout: 0\n  encodeUrl: true\n  followRedirects: true\n").unwrap();
    for (format, import) in [
        (exporters::Format::Postman, Format::Postman),
        (exporters::Format::OpenApi, Format::OpenApi),
    ] {
        let output = exporters::export(format, root.path(), None).unwrap();
        let imported = importers::parse(import, &output).unwrap();
        let request = Document::parse(&imported.requests[0].source).unwrap();
        assert_eq!(
            request.value("get", "url").unwrap().unwrap(),
            "https://example.test/users"
        );
        assert_eq!(
            request.value("headers", "X-Parent").unwrap().unwrap(),
            "inherited"
        );
    }
}
