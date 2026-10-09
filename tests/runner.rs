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
fn junit_records_success_and_bail_stops_after_http_assertion_and_script_failures() {
    for (status, suffix) in [
        ("200 OK", ""),
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
        let junit_path = directory.path().join("results.xml");
        let success = status == "200 OK" && suffix.is_empty();
        let first_path = directory.path().join("01-first.bru");
        let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
            .arg("run")
            .arg(if success {
                first_path.as_path()
            } else {
                directory.path()
            })
            .args(["--json", "--no-proxy", "--bail", "--reporter-junit"])
            .arg(&junit_path)
            .output()
            .unwrap();
        let report: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        server.join().unwrap();
        assert_eq!(output.status.success(), success);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0]["passed"], success);
        assert!(report[0]["response"].is_object());
        let xml = fs::read_to_string(junit_path).unwrap();
        assert!(
            xml.contains(&format!(
                "tests=\"1\" failures=\"{}\" errors=\"0\"",
                usize::from(!success)
            )),
            "{xml}"
        );
        assert_eq!(xml.contains("<failure message=\""), !success);
        assert!(report[0]["response"].get("variables").is_none());
    }
}

#[test]
fn reporter_files_preserve_json_shape_and_partial_bail_results() {
    let directory = collection("get {\n  url: not-a-url\n}\n");
    let json_path = directory.path().join("results.json");
    let junit_path = directory.path().join("results.xml");
    let (output, report) = run(
        &directory,
        &[
            "--bail",
            "--reporter-json",
            json_path.to_str().unwrap(),
            "--reporter-junit",
            junit_path.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert_eq!(report.len(), 1);
    let file_report: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(json_path).unwrap()).unwrap();
    assert_eq!(report, file_report);
    assert!(!report[0].as_object().unwrap().contains_key("response"));
    let xml = fs::read_to_string(junit_path).unwrap();
    assert!(xml.contains("tests=\"1\" failures=\"0\" errors=\"1\""));
    assert!(xml.contains("<error message=\""));
    assert_eq!(xml.matches("<testcase ").count(), 1);
}

#[test]
fn existing_report_destinations_fail_before_network_or_overwrite() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let directory = collection(&format!(
        "get {{\n  url: http://{}\n}}\n",
        listener.local_addr().unwrap()
    ));
    let destination = directory.path().join("preserve.json");
    fs::write(&destination, "user data").unwrap();
    for flag in ["--reporter-json", "--reporter-junit"] {
        let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
            .arg("run")
            .arg(directory.path())
            .args(["--no-proxy", flag])
            .arg(&destination)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
        assert_eq!(fs::read_to_string(&destination).unwrap(), "user data");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[cfg(unix)]
    {
        let link = directory.path().join("report-link.json");
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
            .arg("run")
            .arg(directory.path())
            .arg("--reporter-json")
            .arg(&link)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&destination).unwrap(), "user data");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn second_report_reservation_failure_prevents_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let directory = collection(&format!(
        "get {{\n  url: http://{}\n}}\n",
        listener.local_addr().unwrap()
    ));
    let first = directory.path().join("results.json");
    let second = directory.path().join("missing-parent/results.xml");
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .arg("run")
        .arg(directory.path())
        .arg("--reporter-json")
        .arg(&first)
        .arg("--reporter-junit")
        .arg(&second)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(&first).unwrap(), b"");
    assert!(!second.exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn reporter_destinations_must_be_distinct_before_network() {
    let directory = collection("get {\n  url: http://127.0.0.1:1\n}\n");
    let destination = directory.path().join("same.json");
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .arg("run")
        .arg(directory.path())
        .arg("--reporter-json")
        .arg(&destination)
        .arg("--reporter-junit")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("distinct destinations"));
    assert!(!destination.exists());
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
