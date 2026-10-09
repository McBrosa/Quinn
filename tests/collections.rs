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

use quinn_api::{collection, engine::Engine, variables::Variables};

const COLLECTION: &str = "opencollection: 1.0.0\ninfo:\n  name: Canonical fixture\nrequest:\n  headers:\n    - name: X-Collection\n      value: inherited\n  variables:\n    - name: endpoint\n      value: /original\n";
const REQUEST: &str = "info:\n  name: Get Users\n  type: http\n  seq: 1\nhttp:\n  method: GET\n  url: '{{baseUrl}}{{endpoint}}'\n  auth: inherit\n  params:\n    - name: search\n      value: a b\n      type: query\n    - name: unused\n      value: '{{missing}}'\n      disabled: true\n  headers:\n    - name: X-Request\n      value: request\nruntime:\n  variables:\n    - name: endpoint\n      value: /users\n  scripts:\n    - type: before-request\n      code: bru.setVar('endpoint', '/script');\n    - type: tests\n      code: test('status', () => expect(res.status).to.equal(200));\n  assertions:\n    - expression: res.body.id\n      operator: eq\n      value: '42'\n  actions:\n    - type: set-variable\n      phase: after-response\n      selector:\n        expression: res.body.id\n        method: jsonq\n      variable:\n        name: userId\n        scope: runtime\nsettings:\n  encodeUrl: true\n  timeout: 0\n  followRedirects: true\n  maxRedirects: 10\n  forwardAuthorizationHeader: false\n";

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("users")).unwrap();
    fs::create_dir(directory.path().join("environments")).unwrap();
    fs::write(directory.path().join("opencollection.yml"), COLLECTION).unwrap();
    fs::write(directory.path().join("users/folder.yml"), "info:\n  name: Users\n  seq: 1\nrequest:\n  auth:\n    type: bearer\n    token: inherited-token\n  headers:\n    - name: X-Folder\n      value: folder\n").unwrap();
    fs::write(directory.path().join("users/get-users.yml"), REQUEST).unwrap();
    directory
}

#[test]
fn canonical_yaml_executes_in_cli_with_environment_defaults_scripts_and_assertions() {
    let directory = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    fs::write(
        directory.path().join("environments/dev.yml"),
        format!("name: Development\nvariables:\n  - name: baseUrl\n    value: '{url}'\n"),
    )
    .unwrap();
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let started = std::time::Instant::now();
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
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = socket.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&buffer[..count]);
        }
        let body = r#"{"id":42}"#;
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    let result = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args([
            "run",
            directory.path().to_str().unwrap(),
            "--env",
            "dev",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report[0]["passed"], true);
    let request = server.join().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /script?search=a+b http/1.1"));
    for header in [
        "x-collection: inherited",
        "x-folder: folder",
        "x-request: request",
        "authorization: bearer inherited-token",
    ] {
        assert!(request.contains(header), "{request}");
    }
    assert_eq!(
        collection::read(&directory.path().join("users/get-users.yml")).unwrap(),
        REQUEST
    );
}

#[test]
fn folder_sequence_matches_bruno_insertion_and_folders_precede_requests() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::write(root.join("bruno.json"), "{}").unwrap();
    for (folder, sequence) in [
        ("alpha", 0),
        ("beta", 0),
        ("z-first", 1),
        ("y-first", 1),
        ("last", 99),
    ] {
        fs::create_dir(root.join(folder)).unwrap();
        fs::write(
            root.join(folder).join("folder.bru"),
            format!("meta {{\n  seq: {sequence}\n}}\n"),
        )
        .unwrap();
        fs::write(
            root.join(folder).join("request.bru"),
            format!(
                "meta {{\n  name: {folder}\n  seq: 1\n}}\nget {{\n  url: http://localhost\n}}\n"
            ),
        )
        .unwrap();
    }
    fs::write(
        root.join("root.bru"),
        "meta {\n  name: root\n  seq: 0\n}\nget {\n  url: http://localhost\n}\n",
    )
    .unwrap();
    let entries = collection::discover(root).unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["y-first", "z-first", "alpha", "beta", "last", "root"]
    );
}

#[test]
fn yaml_collection_wins_over_stale_bru_and_preserves_atomic_source_saves() {
    let directory = fixture();
    fs::write(directory.path().join("bruno.json"), "{}").unwrap();
    let stale = directory.path().join("stale.bru");
    fs::write(&stale, "get {\n  url: http://localhost\n}\n").unwrap();
    fs::write(
        directory.path().join("notes.yml"),
        "info: {name: Notes}\ndocs: passive metadata\n",
    )
    .unwrap();
    assert_eq!(collection::discover(directory.path()).unwrap().len(), 1);
    assert!(collection::discover(&stale).is_err());
    let path = directory.path().join("users/get-users.yml");
    let source = format!("# Keep this comment.\n{REQUEST}");
    collection::save(&path, REQUEST, &source).unwrap();
    assert_eq!(collection::read(&path).unwrap(), source);
    assert!(collection::save(&path, REQUEST, REQUEST).is_err());
    assert!(collection::save(&path, &source, "http: [broken").is_err());
    assert_eq!(collection::read(&path).unwrap(), source);
}

#[test]
fn yaml_environments_inherit_and_embedded_environments_are_selectable() {
    let directory = fixture();
    fs::write(directory.path().join("opencollection.yml"), format!("{COLLECTION}config:\n  environments:\n    - name: base\n      variables:\n        - name: one\n          value: inherited\n        - name: two\n          value: original\n")).unwrap();
    fs::write(directory.path().join("environments/child.yml"), "name: child\nextends: base\nvariables:\n  - name: two\n    value: changed\n  - name: disabled\n    value: no\n    disabled: true\n").unwrap();
    assert_eq!(
        collection::environment_names(directory.path()).unwrap(),
        ["base", "child"]
    );
    let values = collection::environment(directory.path(), "child").unwrap();
    assert_eq!(values.get("one").unwrap(), "inherited");
    assert_eq!(values.get("two").unwrap(), "changed");
    assert!(!values.contains_key("disabled"));
    fs::write(
        directory.path().join("environments/cycle.yml"),
        "name: cycle\nextends: cycle\n",
    )
    .unwrap();
    assert!(collection::environment(directory.path(), "cycle").is_err());
}

#[test]
fn yaml_rejects_unknown_executable_fields_and_nondefault_settings_before_io() {
    let path = Path::new("request.yml");
    for source in [
        "info: {type: websocket}\nhttp: {url: http://localhost}\n",
        "http: {url: http://localhost, secretExecution: true}\n",
        "http: {url: http://localhost}\nruntime:\n  scripts: [{type: unknown, code: dangerous()}]\n",
        "http: {url: http://localhost}\nsettings: {encodeUrl: false}\n",
        "http: {url: http://localhost}\nsettings: {forwardAuthorizationHeader: true}\n",
        "http: {url: http://localhost}\nruntime:\n  actions: [{type: exec, phase: after-response}]\n",
        "http: {url: http://localhost}\nruntime:\n  variables: [{name: typed, value: {type: number, data: 42}}]\n",
    ] {
        assert!(collection::parse(path, source).is_err(), "{source}");
    }
    assert!(
        collection::parse(
            Path::new("opencollection.yml"),
            "opencollection: 1.0.0\nconfig: {proxy: {disabled: false}}\n"
        )
        .is_err()
    );
    assert!(
        collection::parse(
            path,
            "http: {url: http://localhost}\nhttp: {url: http://other}\n"
        )
        .is_err()
    );
}

#[test]
fn unsupported_yaml_requests_remain_editable_but_fail_before_execution() {
    let directory = fixture();
    let path = directory.path().join("users/unsupported.yml");
    let original = "info: {name: Unsupported, type: http}\nhttp: {url: http://localhost}\nsettings: {encodeUrl: false}\n";
    fs::write(&path, original).unwrap();
    assert_eq!(collection::discover(directory.path()).unwrap().len(), 2);
    assert!(collection::load(&path).is_err());
    let edited = original.replace("false", "true");
    collection::save(&path, original, &edited).unwrap();
    assert_eq!(collection::read(&path).unwrap(), edited);
    assert!(collection::load(&path).is_ok());
    assert!(collection::save(&path, &edited, original).is_ok());
    let result = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["run", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report[0]["error"].as_str().unwrap().contains("encodeUrl"));
}

#[test]
fn yaml_bodies_disabled_fields_and_api_key_convert_without_source_rewrites() {
    let path = Path::new("request.yml");
    let source = "http:\n  method: POST\n  url: http://localhost\n  auth: {type: apikey, key: key, value: token, placement: query}\n  body:\n    type: multipart-form\n    data:\n      - name: files\n        type: file\n        value: [one.bin, two.bin]\n        contentType: application/octet-stream\n      - name: text\n        value: text\n      - name: disabled\n        value: unused\n        disabled: true\n";
    let document = collection::parse(path, source).unwrap();
    assert_eq!(
        document.value("post", "body").unwrap().as_deref(),
        Some("multipartForm")
    );
    assert_eq!(
        document
            .value("auth:apikey", "placement")
            .unwrap()
            .as_deref(),
        Some("queryparams")
    );
    let pairs = document.pairs("body:multipartForm").unwrap();
    assert_eq!(
        pairs[0].value,
        "@file(one.bin|two.bin) @contentType(application/octet-stream)"
    );
    assert!(!pairs[2].enabled);
    let form = collection::parse(path, "http:\n  method: POST\n  url: http://localhost\n  body:\n    type: form-urlencoded\n    data: [{name: field, value: a b}]\n").unwrap();
    assert_eq!(
        form.value("body:formUrlEncoded", "field")
            .unwrap()
            .as_deref(),
        Some("a b")
    );
    let binary = collection::parse(path, "http:\n  method: POST\n  url: http://localhost\n  body:\n    type: file\n    data: [{filePath: data.bin, selected: true}]\n").unwrap();
    assert_eq!(
        binary.value("body:file", "file").unwrap().as_deref(),
        Some("@file(data.bin)")
    );
    assert!(
        Engine::new(Duration::from_secs(1))
            .unwrap()
            .send(&binary, &[], &Variables::new())
            .is_err()
    );
    let multiline = collection::parse(path, "http: {url: http://localhost}\nruntime:\n  variables:\n    - name: message\n      value: '\n\n        first\n\n        second\n\n        '\n").unwrap();
    let value = multiline
        .value("vars:pre-request", "message")
        .unwrap()
        .unwrap();
    assert_eq!(value, "\nfirst\nsecond\n");
}

#[cfg(unix)]
#[test]
fn yaml_ignores_symlink_requests_and_refuses_symlink_metadata_and_environments() {
    let directory = fixture();
    let root = directory.path();
    std::os::unix::fs::symlink(root.join("users/get-users.yml"), root.join("linked.yml")).unwrap();
    assert_eq!(collection::discover(root).unwrap().len(), 1);
    assert!(
        collection::discover(&root.join("linked.yml"))
            .unwrap()
            .is_empty()
    );
    assert!(collection::save(&root.join("linked.yml"), REQUEST, REQUEST).is_err());
    std::os::unix::fs::symlink(
        root.join("users/folder.yml"),
        root.join("environments/link.yml"),
    )
    .unwrap();
    assert!(collection::environment(root, "link").is_err());
    fs::create_dir(root.join("shadow")).unwrap();
    std::os::unix::fs::symlink(
        root.join("users/folder.yml"),
        root.join("shadow/folder.yml"),
    )
    .unwrap();
    assert!(collection::discover(root).is_err());
}

#[cfg(unix)]
#[test]
fn collection_root_rejects_symbolic_link_markers() {
    for marker in ["bruno.json", "opencollection.yml"] {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("real"), "{}").unwrap();
        std::os::unix::fs::symlink(directory.path().join("real"), directory.path().join(marker))
            .unwrap();
        assert!(collection::root(directory.path()).is_err());
        assert!(collection::discover(directory.path()).is_err());
    }
}
