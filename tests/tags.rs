#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, net::TcpListener, process::Command};

use quinn_api::collection;

#[cfg(unix)]
#[test]
fn parent_symlinks_do_not_inherit_tags_from_an_unrelated_logical_collection() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(root.path().join("bruno.json"), "{}").unwrap();
    fs::create_dir(root.path().join("nested")).unwrap();
    fs::write(
        root.path().join("nested/folder.bru"),
        "meta {\n  tags: [\n    unrelated\n  ]\n}\n",
    )
    .unwrap();
    fs::write(outside.path().join("bruno.json"), "{}").unwrap();
    fs::write(
        outside.path().join("request.bru"),
        "get {\n  url: http://localhost\n}\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("nested/alias")).unwrap();
    let request = root.path().join("nested/alias/request.bru");
    assert_eq!(
        collection::root(&request).unwrap(),
        outside.path().canonicalize().unwrap()
    );
    let entries = collection::discover(&request).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].tags.is_empty());
}

fn fixture(yaml: bool) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir_all(root.join("api/v2")).unwrap();
    if yaml {
        fs::write(
            root.join("opencollection.yml"),
            "opencollection: 1.0.0\ninfo:\n  name: Tags\n  tags: [collection-only]\n",
        )
        .unwrap();
        fs::write(
            root.join("api/folder.yml"),
            "info:\n  name: api\n  tags: [api, shared]\n",
        )
        .unwrap();
        fs::write(
            root.join("api/v2/folder.yml"),
            "info:\n  name: v2\n  tags: [v2, shared]\n",
        )
        .unwrap();
        fs::write(root.join("api/v2/01.yml"), "info:\n  name: first\n  type: http\n  seq: 2\n  tags: [' smoke ', shared, shared, '', 42, null]\nhttp:\n  method: GET\n  url: invalid\n").unwrap();
        fs::write(root.join("api/v2/02.yml"), "info:\n  name: second\n  type: http\n  seq: 1\n  tags: [wip]\nhttp:\n  method: GET\n  url: invalid\n").unwrap();
        fs::write(
            root.join("root.yml"),
            "info:\n  name: root\n  type: http\nhttp:\n  method: GET\n  url: invalid\n",
        )
        .unwrap();
    } else {
        fs::write(root.join("bruno.json"), "{\"name\":\"Tags\"}").unwrap();
        fs::write(
            root.join("collection.bru"),
            "meta {\n  tags: [\n    collection-only\n  ]\n}\n",
        )
        .unwrap();
        fs::write(
            root.join("api/folder.bru"),
            "meta {\n  tags: [\n    api\n    shared\n  ]\n}\n",
        )
        .unwrap();
        fs::write(
            root.join("api/v2/folder.bru"),
            "meta {\n  tags: [\n    v2\n    shared\n  ]\n}\n",
        )
        .unwrap();
        fs::write(root.join("api/v2/01.bru"), "meta {\n  name: first\n  seq: 2\n  tags: [\n    smoke\n    shared\n    shared\n\n  ]\n}\nget {\n  url: invalid\n}\n").unwrap();
        fs::write(root.join("api/v2/02.bru"), "meta {\n  name: second\n  seq: 1\n  tags: [\n    wip\n  ]\n}\nget {\n  url: invalid\n}\n").unwrap();
        fs::write(
            root.join("root.bru"),
            "meta {\n  name: root\n}\nget {\n  url: invalid\n}\n",
        )
        .unwrap();
    }
    directory
}

#[test]
fn both_formats_inherit_nearest_folder_tags_without_leaking_collection_tags() {
    for yaml in [false, true] {
        let directory = fixture(yaml);
        let entries = collection::discover(directory.path()).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["second", "first", "root"]
        );
        assert_eq!(entries[0].tags, ["wip", "v2", "shared", "api"]);
        assert_eq!(entries[1].tags, ["smoke", "shared", "v2", "api"]);
        assert!(entries[2].tags.is_empty());
        for path in [directory.path().join("api/v2"), entries[1].path.clone()] {
            let selected = collection::discover(&path).unwrap();
            assert!(
                selected
                    .iter()
                    .all(|entry| entry.tags.contains(&"api".into()))
            );
        }
        assert!(collection::matches_tags(
            &entries[1],
            &["absent".into(), "smoke".into()],
            &[]
        ));
        assert!(!collection::matches_tags(
            &entries[1],
            &["Smoke".into()],
            &[]
        ));
        assert!(!collection::matches_tags(
            &entries[1],
            &["smoke".into()],
            &["api".into()]
        ));
    }
}

#[test]
fn cli_tag_filters_preserve_order_bail_and_repeated_comma_values() {
    for yaml in [false, true] {
        let directory = fixture(yaml);
        for (args, expected) in [
            (
                vec!["--tags", "api,absent", "--tags", "smoke"],
                vec!["second", "first"],
            ),
            (
                vec!["--tags", "api", "--exclude-tags", "wip"],
                vec!["first"],
            ),
            (vec!["--exclude-tags", "api"], vec!["root"]),
            (
                vec!["--tags", "api", "--bail", "--delay", "10000"],
                vec!["second"],
            ),
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
                .arg("run")
                .arg(directory.path())
                .args(["--json", "--no-proxy"])
                .args(args)
                .output()
                .unwrap();
            assert!(!output.status.success());
            let report: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                report
                    .iter()
                    .map(|item| item["name"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
}

#[test]
fn no_match_errors_before_environment_network_token_or_script_preparation() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let directory = fixture(false);
    fs::write(directory.path().join("root.bru"), format!("get {{\n  url: http://{}\n  auth: oauth2\n}}\nauth:oauth2 {{\n  grant_type: client_credentials\n  access_token_url: http://{}\n  client_id: test\n}}\nscript:pre-request {{\n  require('not-supported');\n}}\n", listener.local_addr().unwrap(), listener.local_addr().unwrap())).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .arg("run")
        .arg(directory.path())
        .args([
            "--tags",
            "absent",
            "--env",
            "nonexistent",
            "--cacert",
            "nonexistent.pem",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no requests match the tag filters"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn excluded_requests_do_not_execute_or_contact_token_endpoints() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let directory = fixture(false);
    fs::write(directory.path().join("root.bru"), format!("get {{\n  url: http://{}\n  auth: oauth2\n}}\nauth:oauth2 {{\n  grant_type: client_credentials\n  access_token_url: http://{}\n  client_id: test\n}}\nscript:pre-request {{\n  while(true) {{}}\n}}\n", listener.local_addr().unwrap(), listener.local_addr().unwrap())).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .arg("run")
        .arg(directory.path())
        .args(["--json", "--no-proxy", "--tags", "smoke"])
        .output()
        .unwrap();
    let report: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.len(), 1);
    assert_eq!(report[0]["name"], "first");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
