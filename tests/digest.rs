#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use md5::Md5;
use quinn_api::{bru::Document, engine::Engine, variables::Variables};
use sha2::{Digest, Sha256};

fn request(url: &str) -> Document {
    Document::parse(&format!("post {{\n  url: {url}\n  body: json\n  auth: digest\n}}\nauth:digest {{\n  username: {{{{user}}}}\n  password: Circle Of Life\n}}\nbody:json {{\n  {{\"message\":\"hello\"}}\n}}\nparams:query {{\n  value: a&b\n}}\n")).unwrap()
}

fn values() -> Variables {
    Variables::from([("user".into(), "Mufasa".into())])
}

fn read_request(stream: &mut TcpStream) -> (String, BTreeMap<String, String>, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let end = loop {
        let mut chunk = [0u8; 4096];
        let length = stream.read(&mut chunk).unwrap();
        assert_ne!(length, 0);
        bytes.extend_from_slice(&chunk[..length]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let mut lines = head.lines();
    let first = lines.next().unwrap().to_owned();
    let headers: BTreeMap<_, _> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .get("content-length")
        .map_or(0, |value| value.parse().unwrap());
    while bytes.len() < end + length {
        let mut chunk = [0u8; 4096];
        let length = stream.read(&mut chunk).unwrap();
        assert_ne!(length, 0);
        bytes.extend_from_slice(&chunk[..length]);
    }
    (first, headers, bytes[end..].to_vec())
}

fn reply(stream: &mut TcpStream, code: u16, headers: &str) {
    let body = "{\"ok\":true}";
    let message = format!(
        "HTTP/1.1 {code} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(message.as_bytes());
}

fn listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/resource%20name", listener.local_addr().unwrap());
    (listener, url)
}

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => panic!("local Digest server did not accept a request: {error}"),
        }
    }
}

fn hash(algorithm: &str, value: &str) -> String {
    if algorithm == "SHA-256" {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    } else {
        format!("{:x}", Md5::digest(value.as_bytes()))
    }
}

#[test]
fn digest_challenge_replays_identical_json_with_correct_uri_hash_cookies_and_inheritance() {
    for (algorithm, qop) in [("MD5", true), ("SHA-256", true), ("MD5", false)] {
        let (listener, url) = listener();
        let worker = thread::spawn(move || {
            let mut first = accept(&listener);
            let (method, headers, body) = read_request(&mut first);
            assert_eq!(method, "POST /resource%20name?value=a%26b HTTP/1.1");
            assert!(!headers.contains_key("authorization"));
            let qop_header = if qop { ", qop=\"auth,auth-int\"" } else { "" };
            reply(
                &mut first,
                401,
                &format!(
                    "WWW-Authenticate: Digest realm=\"test\", nonce=\"nonce\", algorithm={algorithm}{qop_header}, opaque=\"opaque\"\r\nSet-Cookie: session=ready; Path=/\r\n"
                ),
            );
            let mut second = accept(&listener);
            let (retry_method, retry_headers, retry_body) = read_request(&mut second);
            assert_eq!(retry_method, method);
            assert_eq!(retry_body, body);
            assert_eq!(retry_headers["cookie"], "session=ready");
            let auth = retry_headers["authorization"]
                .strip_prefix("Digest ")
                .unwrap();
            let fields: BTreeMap<_, _> = auth
                .split(", ")
                .map(|entry| {
                    let (key, value) = entry.split_once('=').unwrap();
                    (key, value.trim_matches('"'))
                })
                .collect();
            assert_eq!(fields["username"], "Mufasa");
            assert_eq!(fields["uri"], "/resource%20name?value=a%26b");
            assert_eq!(fields["opaque"], "opaque");
            let ha1 = hash(algorithm, "Mufasa:test:Circle Of Life");
            let ha2 = hash(algorithm, "POST:/resource%20name?value=a%26b");
            let expected = if qop {
                assert_eq!(fields["nc"], "00000001");
                assert_eq!(fields["qop"], "auth");
                hash(
                    algorithm,
                    &format!("{ha1}:nonce:00000001:{}:auth:{ha2}", fields["cnonce"]),
                )
            } else {
                assert!(!fields.contains_key("qop"));
                hash(algorithm, &format!("{ha1}:nonce:{ha2}"))
            };
            assert_eq!(fields["response"], expected);
            reply(&mut second, 200, "");
        });
        let mut request = request(&url);
        let auth = request
            .blocks
            .iter()
            .find(|block| block.name == "auth:digest")
            .unwrap()
            .clone();
        request.blocks.retain(|block| block.name != "auth:digest");
        request
            .blocks
            .iter_mut()
            .find(|block| block.name == "post")
            .unwrap()
            .content = request
            .blocks
            .iter()
            .find(|block| block.name == "post")
            .unwrap()
            .content
            .replace("auth: digest", "auth: inherit");
        request.blocks.extend(
            Document::parse(
                "assert {\n  res.body.ok: eq true\n}\nvars:post-response {\n  ok: res.body.ok\n}\n",
            )
            .unwrap()
            .blocks,
        );
        let mut defaults = Document::parse("auth {\n  mode: digest\n}\n").unwrap();
        defaults.blocks.push(auth);
        let response = Engine::new(Duration::from_secs(5))
            .unwrap()
            .send(&request, &[defaults], &values())
            .unwrap();
        assert!(response.passed(), "{response:?}");
        assert_eq!(response.variables["ok"], "true");
        worker.join().unwrap();
    }
}

#[test]
fn digest_retries_once_and_keeps_final_401_response() {
    let (listener, url) = listener();
    let worker = thread::spawn(move || {
        for authorized in [false, true] {
            let mut stream = accept(&listener);
            let (_, headers, _) = read_request(&mut stream);
            assert_eq!(headers.contains_key("authorization"), authorized);
            reply(
                &mut stream,
                401,
                "WWW-Authenticate: Digest realm=\"test\", nonce=\"nonce\", qop=auth, stale=true\r\n",
            );
        }
    });
    let response = Engine::new(Duration::from_secs(5))
        .unwrap()
        .send(&request(&url), &[], &values())
        .unwrap();
    assert_eq!(response.status, 401);
    assert!(!response.passed());
    worker.join().unwrap();
}

#[test]
fn invalid_or_unsupported_digest_challenges_never_send_credentials() {
    for challenge in [
        "realm=\"test\", nonce=\"n\", algorithm=SHA-512",
        "realm=\"test\", nonce=\"n\", algorithm=MD5-sess",
        "realm=\"test\", nonce=\"n\", qop=auth-int",
        "realm=\"test\", nonce=\"n\", userhash=true",
        "realm=\"test\", nonce=\"n\", charset=ISO-8859-1",
        "realm=\"test\", nonce=\"n\", nonce=\"duplicate\"",
        "realm=\"test\"",
        "realm=\"unterminated",
    ] {
        let (listener, url) = listener();
        let worker = thread::spawn(move || {
            let mut stream = accept(&listener);
            let (_, headers, _) = read_request(&mut stream);
            assert!(!headers.contains_key("authorization"));
            reply(
                &mut stream,
                401,
                &format!("WWW-Authenticate: Digest {challenge}\r\n"),
            );
        });
        let error = Engine::new(Duration::from_secs(5))
            .unwrap()
            .send(&request(&url), &[], &values())
            .unwrap_err();
        assert!(!matches!(error, quinn_api::Error::Http { .. }), "{error}");
        worker.join().unwrap();
    }
}

#[test]
fn digest_never_follows_initial_or_authenticated_redirects() {
    for authenticated in [false, true] {
        let (target, target_url) = listener();
        target.set_nonblocking(true).unwrap();
        let (listener, url) = listener();
        let worker = thread::spawn(move || {
            if authenticated {
                let mut stream = accept(&listener);
                read_request(&mut stream);
                reply(
                    &mut stream,
                    401,
                    "WWW-Authenticate: Digest realm=\"test\", nonce=\"n\"\r\n",
                );
            }
            let mut stream = accept(&listener);
            let (_, headers, _) = read_request(&mut stream);
            assert_eq!(headers.contains_key("authorization"), authenticated);
            reply(&mut stream, 302, &format!("Location: {target_url}\r\n"));
        });
        let response = Engine::new(Duration::from_secs(5))
            .unwrap()
            .send(&request(&url), &[], &values())
            .unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        worker.join().unwrap();
    }
}

#[test]
fn digest_rejects_nonreplayable_bodies_conflicting_headers_and_invalid_assertions_before_network() {
    let (listener, url) = listener();
    listener.set_nonblocking(true).unwrap();
    for addition in [
        "headers {\n  Authorization: Bearer explicit\n}\n",
        "assert {\n  res.status: not-an-operator 200\n}\n",
    ] {
        let mut request = request(&url);
        request
            .blocks
            .extend(Document::parse(addition).unwrap().blocks);
        assert!(
            Engine::new(Duration::from_secs(1))
                .unwrap()
                .send(&request, &[], &values())
                .is_err()
        );
    }
    for mode in ["file", "multipartForm"] {
        let source = format!(
            "post {{\n  url: {url}\n  body: {mode}\n  auth: digest\n}}\nauth:digest {{\n  username: Mufasa\n  password: secret\n}}\n"
        );
        let error = Engine::new(Duration::from_secs(1))
            .unwrap()
            .send(&Document::parse(&source).unwrap(), &[], &Variables::new())
            .unwrap_err();
        assert!(
            matches!(error, quinn_api::Error::Unsupported { .. }),
            "{error}"
        );
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn digest_challenge_and_retry_share_one_deadline() {
    let (listener, url) = listener();
    let worker = thread::spawn(move || {
        let mut first = accept(&listener);
        read_request(&mut first);
        thread::sleep(Duration::from_millis(60));
        reply(
            &mut first,
            401,
            "WWW-Authenticate: Digest realm=\"test\", nonce=\"n\"\r\n",
        );
        let mut second = accept(&listener);
        read_request(&mut second);
        thread::sleep(Duration::from_millis(100));
        reply(&mut second, 200, "");
    });
    let start = Instant::now();
    let result =
        Engine::new(Duration::from_millis(100))
            .unwrap()
            .send(&request(&url), &[], &values());
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_millis(400));
    worker.join().unwrap();
}
