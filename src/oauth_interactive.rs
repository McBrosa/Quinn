use std::{
    io::{Read, Write},
    net::{IpAddr, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub(crate) struct Authorization {
    pub(crate) url: Url,
    pub(crate) callback: Url,
    pub(crate) timeout: Duration,
}

pub(crate) struct Code {
    pub(crate) value: String,
    pub(crate) verifier: String,
    pub(crate) redirect_uri: String,
}

impl Authorization {
    pub(crate) fn authorize(self, client_id: &str, scope: &str) -> Result<Code> {
        self.authorize_with(client_id, scope, |url| {
            webbrowser::open(url.as_str()).map_err(|_| {
                Error::invalid("cannot open the OAuth browser; check the default browser")
            })
        })
    }

    fn authorize_with(
        mut self,
        client_id: &str,
        scope: &str,
        open: impl FnOnce(&Url) -> Result<()>,
    ) -> Result<Code> {
        let address = callback_address(&self.callback)?;
        let listener = TcpListener::bind(address)
            .map_err(|_| Error::invalid("cannot bind the OAuth loopback callback address"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::invalid("cannot configure the OAuth callback listener"))?;
        let port = listener
            .local_addr()
            .map_err(|_| Error::invalid("cannot read the OAuth callback address"))?
            .port();
        self.callback
            .set_port(Some(port))
            .map_err(|_| Error::invalid("invalid OAuth callback port"))?;
        let state = random_secret()?;
        let verifier = random_secret()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        self.url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", self.callback.as_str())
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        if !scope.is_empty() {
            self.url.query_pairs_mut().append_pair("scope", scope);
        }
        // The listener is bound before launching the browser so fast redirects cannot be lost.
        open(&self.url)?;
        let value = wait_for_callback(&listener, &self.callback, &state, self.timeout)?;
        Ok(Code {
            value,
            verifier,
            redirect_uri: self.callback.into(),
        })
    }
}

pub(crate) fn callback_address(url: &Url) -> Result<(IpAddr, u16)> {
    let address: IpAddr = url
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .parse()
        .map_err(|_| Error::invalid("OAuth callback requires a numeric loopback IP address"))?;
    if url.scheme() != "http"
        || !address.is_loopback()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid(
            "OAuth callback requires http on a loopback IP, without credentials, query, or fragment",
        ));
    }
    Ok((address, url.port().unwrap_or(80)))
}

pub(crate) fn secure_endpoint(url: &Url) -> Result<()> {
    let loopback = url
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback());
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid(
            "interactive OAuth endpoints require https (http is allowed only on numeric loopback IPs), without credentials or fragments",
        ));
    }
    Ok(())
}

fn random_secret() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| Error::invalid("cannot generate secure OAuth state and PKCE verifier"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn wait_for_callback(
    listener: &TcpListener,
    callback: &Url,
    state: &str,
    timeout: Duration,
) -> Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(Error::invalid("OAuth browser authorization timed out"));
        }
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                // macOS inherits O_NONBLOCK from the listener.
                let remaining = deadline.saturating_duration_since(Instant::now());
                let read_timeout = remaining.min(Duration::from_millis(500));
                if stream.set_nonblocking(false).is_err()
                    || stream.set_read_timeout(Some(read_timeout)).is_err()
                    || stream.set_write_timeout(Some(read_timeout)).is_err()
                {
                    continue;
                }
                let request = read_request(&mut stream, Instant::now() + read_timeout);
                let result = request
                    .as_deref()
                    .ok()
                    .and_then(|request| parse_callback(request, callback, state));
                match result {
                    Some(Ok(code)) => {
                        reply(&mut stream, true);
                        return Ok(code);
                    }
                    Some(Err(error)) => {
                        reply(&mut stream, false);
                        return Err(error);
                    }
                    None => reply(&mut stream, false),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return Err(Error::invalid("cannot accept the OAuth callback")),
        }
    }
}

fn read_request(stream: &mut TcpStream, deadline: Instant) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    while bytes.len() < 8192 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        stream.set_read_timeout(Some(remaining))?;
        let size = stream.read(&mut chunk)?;
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..size]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid OAuth callback request",
    ))
}

fn parse_callback(request: &str, callback: &Url, state: &str) -> Option<Result<String>> {
    let mut parts = request.lines().next()?.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    if !target.starts_with('/') || target.starts_with("//") {
        return None;
    }
    if !matches!(parts.next()?, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
        return None;
    }
    let url = callback.join(target).ok()?;
    if url.origin() != callback.origin()
        || url.path() != callback.path()
        || url.fragment().is_some()
    {
        return None;
    }
    let pairs: Vec<_> = url.query_pairs().collect();
    let states: Vec<_> = pairs.iter().filter(|(key, _)| key == "state").collect();
    if states.len() != 1 || !equal_secret(&states[0].1, state) {
        return None;
    }
    let codes: Vec<_> = pairs.iter().filter(|(key, _)| key == "code").collect();
    let errors: Vec<_> = pairs.iter().filter(|(key, _)| key == "error").collect();
    if errors.len() == 1 && codes.is_empty() {
        return Some(Err(Error::invalid(
            "OAuth authorization was denied or cancelled by the provider",
        )));
    }
    if !errors.is_empty() || codes.len() != 1 || codes[0].1.is_empty() {
        return None;
    }
    Some(Ok(codes[0].1.to_string()))
}

fn equal_secret(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn reply(stream: &mut TcpStream, success: bool) {
    let (status, body) = if success {
        (
            "200 OK",
            "Authorization received. You can close this tab and return to Quinn.",
        )
    } else {
        (
            "400 Bad Request",
            "Authorization callback rejected. Return to Quinn.",
        )
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn callback_rejects_wrong_state_duplicates_paths_and_methods() {
        let callback = Url::parse("http://127.0.0.1:1234/callback").unwrap();
        for target in [
            "GET /callback?code=secret&state=wrong HTTP/1.1",
            "GET /callback?code=secret&state=s&state=s HTTP/1.1",
            "GET /callback?code=a&code=b&state=s HTTP/1.1",
            "GET /other?code=secret&state=s HTTP/1.1",
            "POST /callback?code=secret&state=s HTTP/1.1",
            "GET //evil.test/callback?code=secret&state=s HTTP/1.1",
        ] {
            assert!(parse_callback(target, &callback, "s").is_none(), "{target}");
        }
        assert_eq!(
            parse_callback("GET /callback?code=a%2Bb&state=s HTTP/1.1", &callback, "s")
                .unwrap()
                .unwrap(),
            "a+b"
        );
        assert!(
            parse_callback(
                "GET /callback?error=access_denied&state=s HTTP/1.1",
                &callback,
                "s"
            )
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn endpoint_validation_rejects_remote_plaintext_and_non_loopback_callbacks() {
        for endpoint in [
            "http://example.com/token",
            "https://u:p@example.com/token",
            "file:///a",
        ] {
            assert!(secure_endpoint(&Url::parse(endpoint).unwrap()).is_err());
        }
        assert!(secure_endpoint(&Url::parse("https://example.com/token").unwrap()).is_ok());
        for callback in [
            "http://0.0.0.0/callback",
            "http://localhost/callback",
            "https://127.0.0.1/callback",
            "http://127.0.0.1/callback?x=y",
        ] {
            assert!(callback_address(&Url::parse(callback).unwrap()).is_err());
        }
        assert!(callback_address(&Url::parse("http://[::1]:0/callback").unwrap()).is_ok());
    }

    #[test]
    fn browser_flow_generates_pkce_and_ignores_bad_state_before_valid_callback() {
        let authorization = Authorization {
            url: Url::parse("https://example.com/authorize").unwrap(),
            callback: Url::parse("http://127.0.0.1:0/callback").unwrap(),
            timeout: Duration::from_secs(2),
        };
        let mut expected_challenge = String::new();
        let mut callback_thread = None;
        let code = authorization
            .authorize_with("public-client", "read write", |url| {
                let pairs: std::collections::BTreeMap<_, _> =
                    url.query_pairs().into_owned().collect();
                assert_eq!(pairs["response_type"], "code");
                assert_eq!(pairs["code_challenge_method"], "S256");
                assert_eq!(pairs["scope"], "read write");
                assert!(!pairs.contains_key("client_secret"));
                expected_challenge = pairs["code_challenge"].clone();
                let mut callback = Url::parse(&pairs["redirect_uri"]).unwrap();
                let state = pairs["state"].clone();
                assert_ne!(callback.port(), Some(0));
                callback_thread = Some(thread::spawn(move || {
                    for candidate in ["wrong", state.as_str()] {
                        callback.set_query(None);
                        callback
                            .query_pairs_mut()
                            .append_pair("state", candidate)
                            .append_pair("code", "received-code");
                        let mut stream = TcpStream::connect((
                            callback.host_str().unwrap(),
                            callback.port().unwrap(),
                        ))
                        .unwrap();
                        write!(
                            stream,
                            "GET {}?{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
                            callback.path(),
                            callback.query().unwrap()
                        )
                        .unwrap();
                        let mut response = String::new();
                        stream.read_to_string(&mut response).unwrap();
                        assert!(!response.contains("received-code"));
                    }
                }));
                Ok(())
            })
            .unwrap();
        callback_thread.unwrap().join().unwrap();
        assert_eq!(code.value, "received-code");
        assert_eq!(code.verifier.len(), 43);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(code.verifier.as_bytes())),
            expected_challenge
        );
    }

    #[test]
    fn browser_flow_reports_timeout_and_browser_failure() {
        let authorization = || Authorization {
            url: Url::parse("https://example.com/authorize").unwrap(),
            callback: Url::parse("http://127.0.0.1:0/callback").unwrap(),
            timeout: Duration::from_millis(30),
        };
        assert!(
            authorization()
                .authorize_with("client", "", |_| Ok(()))
                .err()
                .unwrap()
                .to_string()
                .contains("timed out")
        );
        assert!(
            authorization()
                .authorize_with("client", "", |_| Err(Error::invalid("browser failed")))
                .err()
                .unwrap()
                .to_string()
                .contains("browser failed")
        );
    }
}
