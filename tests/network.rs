#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use quinn_api::{bru::Document, engine::Engine, network::NetworkOptions, variables::Variables};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer, server::WebPkiClientVerifier,
    },
};

fn request(url: &str) -> Document {
    Document::parse(&format!("get {{\n  url: {url}\n}}\n")).unwrap()
}

fn http_server(reply: &'static str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => panic!("cannot accept test request: {error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut byte = [0];
        while !bytes.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 65536);
        }
        socket.write_all(reply.as_bytes()).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (url, handle)
}

#[test]
fn explicit_proxy_receives_absolute_url_and_keeps_proxy_credentials_out_of_target_headers() {
    let (proxy, server) =
        http_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    let proxy = proxy.replacen("http://", "http://proxy-user:proxy-secret@", 1);
    let options = NetworkOptions {
        proxy: Some(proxy),
        ..NetworkOptions::default()
    };
    let engine = Engine::with_network(Duration::from_secs(3), &options).unwrap();
    assert!(
        engine
            .send(
                &request("http://example.invalid/api?a=1"),
                &[],
                &Variables::new()
            )
            .unwrap()
            .passed()
    );
    let wire = server.join().unwrap();
    assert!(wire.starts_with("GET http://example.invalid/api?a=1 HTTP/1.1"));
    assert!(wire.to_lowercase().contains("proxy-authorization: basic "));
    assert!(!wire.to_lowercase().contains("\r\nauthorization:"));
}

#[test]
fn zero_redirect_limit_preserves_redirect_response() {
    let (url, server) = http_server(
        "HTTP/1.1 302 Found\r\nLocation: http://example.invalid/no-send\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let options = NetworkOptions {
        no_proxy: true,
        max_redirects: 0,
        ..NetworkOptions::default()
    };
    let response = Engine::with_network(Duration::from_secs(3), &options)
        .unwrap()
        .send(&request(&url), &[], &Variables::new())
        .unwrap();
    assert_eq!(response.status, 302);
    server.join().unwrap();
}

fn pem(label: &str, bytes: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(bytes)
    )
}

#[test]
fn custom_ca_and_client_certificate_complete_a_verified_mutual_tls_handshake() {
    let temporary = tempfile::tempdir().unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.distinguished_name
        .push(rcgen::DnType::CommonName, "Quinn test CA");
    let ca_certificate = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca, &ca_key);
    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Quinn test client");
    let client_certificate = client_params.signed_by(&client_key, &issuer).unwrap();
    let ca_path = temporary.path().join("ca.pem");
    let certificate_path = temporary.path().join("client.pem");
    let key_path = temporary.path().join("client-key.pem");
    std::fs::write(&ca_path, pem("CERTIFICATE", ca_certificate.der())).unwrap();
    std::fs::write(
        &certificate_path,
        pem("CERTIFICATE", client_certificate.der()),
    )
    .unwrap();
    std::fs::write(&key_path, pem("PRIVATE KEY", &client_key.serialize_der())).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca_certificate.der().clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_certificate.der().clone()],
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                tokio::time::timeout(Duration::from_secs(5), async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut stream = TlsAcceptor::from(Arc::new(config))
                        .accept(socket)
                        .await
                        .unwrap();
                    assert!(
                        stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .is_some_and(|certificates| !certificates.is_empty())
                    );
                    let mut bytes = Vec::new();
                    while !bytes.ends_with(b"\r\n\r\n") {
                        bytes.push(stream.read_u8().await.unwrap());
                        assert!(bytes.len() < 65536);
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await
                        .unwrap();
                    stream.shutdown().await.unwrap();
                })
                .await
                .unwrap();
            });
    });
    let options = NetworkOptions {
        no_proxy: true,
        ca_certificates: vec![ca_path],
        client_certificate: Some(certificate_path),
        client_key: Some(key_path),
        ..NetworkOptions::default()
    };
    let response = Engine::with_network(Duration::from_secs(3), &options)
        .unwrap()
        .send(&request(&url), &[], &Variables::new())
        .unwrap();
    assert_eq!(response.status, 200);
    server.join().unwrap();
}

#[test]
fn invalid_network_configuration_fails_without_exposing_secrets() {
    for options in [
        NetworkOptions {
            proxy: Some("http://secret-user:secret-pass@example.test/not-origin".into()),
            ..NetworkOptions::default()
        },
        NetworkOptions {
            proxy: Some("http://example.test".into()),
            no_proxy: true,
            ..NetworkOptions::default()
        },
        NetworkOptions {
            client_certificate: Some("missing.pem".into()),
            ..NetworkOptions::default()
        },
        NetworkOptions {
            max_redirects: 101,
            ..NetworkOptions::default()
        },
    ] {
        let error = Engine::with_network(Duration::from_secs(1), &options)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("secret-user"));
        assert!(!error.contains("secret-pass"));
    }
    let directory = tempfile::tempdir().unwrap();
    for (name, contents) in [
        ("invalid.pem", b"private-material".to_vec()),
        ("huge.pem", vec![b'A'; 1024 * 1024 + 1]),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, contents).unwrap();
        let options = NetworkOptions {
            ca_certificates: vec![path],
            ..NetworkOptions::default()
        };
        assert!(Engine::with_network(Duration::from_secs(1), &options).is_err());
    }
    let options = NetworkOptions {
        ca_certificates: vec![directory.path().to_path_buf()],
        ..NetworkOptions::default()
    };
    assert!(Engine::with_network(Duration::from_secs(1), &options).is_err());
}

#[test]
fn cli_network_flags_validate_pairs_and_run_through_a_proxy() {
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["run", "--client-cert", "client.pem"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--client-key"));
    let (proxy, server) =
        http_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("request.bru");
    std::fs::write(&path, "get {\n  url: http://example.invalid/proxied\n}\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .arg("run")
        .arg(&path)
        .args(["--proxy", &proxy, "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        server
            .join()
            .unwrap()
            .contains("http://example.invalid/proxied")
    );
}

#[test]
fn protocol_requests_reject_http_only_network_options() {
    let engine = Engine::with_network(
        Duration::from_secs(1),
        &NetworkOptions {
            no_proxy: true,
            ..NetworkOptions::default()
        },
    )
    .unwrap();
    let request = Document::parse("ws {\n  url: ws://127.0.0.1:1\n  body: none\n}\n").unwrap();
    assert!(
        engine
            .send(&request, &[], &Variables::new())
            .err()
            .unwrap()
            .to_string()
            .contains("custom network options")
    );
}
