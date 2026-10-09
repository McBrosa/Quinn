#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

fn collection(first: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("bruno.json"), r#"{"name":"Runner"}"#).unwrap();
    fs::write(directory.path().join("01-first.bru"), first).unwrap();
    fs::write(
        directory.path().join("02-second.bru"),
        "get {\n  url: http://127.0.0.1:1\n}\nscript:pre-request {\n  require('unsupported');\n}\n",
    )
    .unwrap();
    directory
}

fn run(directory: &tempfile::TempDir, arguments: &[&str]) -> (Output, Vec<serde_json::Value>) {
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .arg("run")
        .arg(directory.path())
        .args(["--json", "--no-proxy"])
        .args(arguments)
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid report: {error}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, report)
}

#[test]
fn bail_stops_after_preflight_error_and_default_continues() {
    let directory = collection(
        "get {\n  url: http://127.0.0.1:1\n}\nscript:pre-request {\n  require('unsupported');\n}\n",
    );
    for (arguments, expected) in [(vec!["--bail"], 1), (vec![], 2)] {
        let (output, report) = run(&directory, &arguments);
        assert!(!output.status.success());
        assert_eq!(report.len(), expected);
        assert!(report.iter().all(|item| item["passed"] == false));
        assert!(report[0]["error"].is_string());
    }
}

#[test]
fn bail_stops_after_http_assertion_and_script_failures() {
    for (status, suffix) in [
        ("500 Internal Server Error", ""),
        ("200 OK", "assert {\n  res.status: eq 201\n}\n"),
        (
            "200 OK",
            "tests {\n  test('fails', () => { expect(res.status).to.equal(201); });\n}\n",
        ),
        (
            "200 OK",
            "vars:post-response {\n  missing: res.body.missing\n}\n",
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "request did not arrive");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("cannot accept request: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let length = socket.read(&mut buffer).unwrap();
                assert!(length > 0);
                request.extend_from_slice(&buffer[..length]);
                assert!(request.len() < 16 * 1024);
            }
            write!(
                socket,
                "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .unwrap();
        });
        let directory = collection(&format!("get {{\n  url: {url}\n}}\n{suffix}"));
        let (output, report) = run(&directory, &["--bail"]);
        server.join().unwrap();
        assert!(!output.status.success());
        assert_eq!(report.len(), 1);
        assert_eq!(report[0]["passed"], false);
        assert!(report[0]["response"].is_object());
    }
}

#[test]
fn delay_occurs_between_attempts_but_not_before_the_first_or_after_bail() {
    let directory = collection("get {\n  url: not-a-url\n}\n");
    let start = Instant::now();
    let (_, report) = run(&directory, &["--delay", "200"]);
    assert_eq!(report.len(), 2);
    assert!(start.elapsed() >= Duration::from_millis(200));
    let start = Instant::now();
    let (_, report) = run(&directory, &["--bail", "--delay", "10000"]);
    assert_eq!(report.len(), 1);
    assert!(start.elapsed() < Duration::from_secs(5));
    for value in ["-1", "3600001", "not-a-number"] {
        let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
            .args(["run", "--delay", value])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}
