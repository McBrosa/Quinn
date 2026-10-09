use std::{
    collections::HashMap,
    io::Read,
    sync::Mutex,
    time::{Duration, Instant},
};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Url, blocking::Client, header::HeaderValue};
use serde::{Deserialize, Deserializer};

use crate::{
    Error, Result,
    bru::Document,
    oauth_interactive::{Authorization, Code, callback_address, secure_endpoint},
    variables::{Variables, interpolate},
};

pub(crate) struct TokenRequest {
    url: Url,
    client_id: String,
    client_secret: String,
    scope: String,
    placement: Placement,
    authorization: Option<Authorization>,
    refresh_url: Url,
    auto_refresh: bool,
}

enum Placement {
    Header,
    Body,
}

#[derive(Default)]
pub(crate) struct TokenCache(Mutex<HashMap<Vec<String>, CachedToken>>);

struct CachedToken {
    header: HeaderValue,
    expires: Instant,
    refresh_token: Option<String>,
}

impl TokenCache {
    pub(crate) fn clear(&self) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| Error::invalid("cannot lock the OAuth token cache"))?
            .clear();
        Ok(())
    }

    pub(crate) fn fetch(&self, request: TokenRequest, client: &Client) -> Result<HeaderValue> {
        self.fetch_with(request, client, Authorization::authorize)
    }

    fn fetch_with(
        &self,
        request: TokenRequest,
        client: &Client,
        authorize: impl FnOnce(Authorization, &str, &str) -> Result<Code>,
    ) -> Result<HeaderValue> {
        let key = request.cache_key();
        // Hold the gate through acquisition so concurrent requests cannot open duplicate browser grants.
        let mut entries = self
            .0
            .lock()
            .map_err(|_| Error::invalid("cannot lock the OAuth token cache"))?;
        if let Some(token) = entries.get(&key)
            && token.expires > Instant::now()
        {
            return Ok(token.header.clone());
        }
        let previous = entries.remove(&key);
        let refresh = if request.auto_refresh {
            previous.and_then(|token| token.refresh_token)
        } else {
            None
        };
        // A failed refresh evicts the token and returns an error. Re-authentication requires another send.
        let token = request.fetch_token(client, refresh, authorize)?;
        let header = token.header.clone();
        entries.insert(key, token);
        Ok(header)
    }
}

impl TokenRequest {
    pub(crate) fn prepare(document: &Document, variables: &Variables) -> Result<Self> {
        let value = |key: &str, default: Option<&str>| -> Result<String> {
            let raw = document
                .value("auth:oauth2", key)?
                .or_else(|| default.map(str::to_owned))
                .ok_or_else(|| Error::invalid(format!("OAuth configuration has no {key}")))?;
            interpolate(&raw, variables)
        };
        let grant = value("grant_type", None)?;
        if !matches!(grant.as_str(), "client_credentials" | "authorization_code") {
            return Err(unsupported(format!("grant '{grant}'")));
        }
        if value("auto_fetch_token", Some("true"))? != "true" {
            return Err(unsupported("manual token acquisition"));
        }
        if value("token_placement", Some("header"))? != "header" {
            return Err(unsupported(
                "token placement outside the Authorization header",
            ));
        }
        if !value("token_header_prefix", Some("Bearer"))?.eq_ignore_ascii_case("Bearer") {
            return Err(unsupported("token prefix other than Bearer"));
        }
        if value("token_source", Some("access_token"))? != "access_token" {
            return Err(unsupported("token source other than access_token"));
        }
        let placement = match value("credentials_placement", Some("body"))?.as_str() {
            "body" => Placement::Body,
            "header" => Placement::Header,
            placement => return Err(unsupported(format!("credential placement '{placement}'"))),
        };
        let raw_url = value("access_token_url", None)?;
        let url = Url::parse(&raw_url).map_err(|_| Error::invalid("invalid OAuth token URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::invalid(
                "OAuth token URL requires http or https, without embedded credentials or a fragment",
            ));
        }
        let client_id = value("client_id", None)?;
        let client_secret = value("client_secret", Some(""))?;
        if client_id.is_empty() || (grant == "client_credentials" && client_secret.is_empty()) {
            return Err(Error::invalid(
                "OAuth client ID and secret must not be empty",
            ));
        }
        if client_secret.is_empty() && matches!(placement, Placement::Header) {
            return Err(Error::invalid(
                "OAuth public clients require credentials_placement: body",
            ));
        }
        let scope = value("scope", Some(""))?;
        let authorization = if grant == "authorization_code" {
            secure_endpoint(&url)?;
            if value("pkce", Some("true"))? != "true" {
                return Err(unsupported("authorization code without PKCE S256"));
            }
            let authorization_url = Url::parse(&value("authorization_url", None)?)
                .map_err(|_| Error::invalid("invalid OAuth authorization URL"))?;
            secure_endpoint(&authorization_url)?;
            // Existing endpoint queries are allowed, but cannot override security parameters.
            if authorization_url.query_pairs().any(|(key, _)| {
                matches!(
                    key.as_ref(),
                    "response_type"
                        | "client_id"
                        | "redirect_uri"
                        | "state"
                        | "code_challenge"
                        | "code_challenge_method"
                        | "scope"
                        | "client_secret"
                )
            }) {
                return Err(Error::invalid(
                    "OAuth authorization URL contains reserved parameters",
                ));
            }
            let callback = Url::parse(&value("callback_url", Some("http://127.0.0.1:0/callback"))?)
                .map_err(|_| Error::invalid("invalid OAuth callback URL"))?;
            callback_address(&callback)?;
            Some(Authorization {
                url: authorization_url,
                callback,
                timeout: Duration::from_secs(120),
            })
        } else {
            None
        };
        let raw_refresh_url = value("refresh_token_url", Some(""))?;
        let refresh_url = if raw_refresh_url.is_empty() {
            url.clone()
        } else {
            Url::parse(&raw_refresh_url).map_err(|_| Error::invalid("invalid OAuth refresh URL"))?
        };
        if !matches!(refresh_url.scheme(), "http" | "https")
            || !refresh_url.username().is_empty()
            || refresh_url.password().is_some()
            || refresh_url.fragment().is_some()
        {
            return Err(Error::invalid(
                "OAuth refresh URL requires http or https, without embedded credentials or a fragment",
            ));
        }
        if authorization.is_some() {
            secure_endpoint(&refresh_url)?;
        }
        let auto_refresh = match value("auto_refresh_token", Some("false"))?.as_str() {
            "true" => true,
            "false" => false,
            _ => {
                return Err(Error::invalid(
                    "OAuth auto_refresh_token requires true or false",
                ));
            }
        };
        Ok(Self {
            url,
            client_id,
            client_secret,
            scope,
            placement,
            authorization,
            refresh_url,
            auto_refresh,
        })
    }

    fn cache_key(&self) -> Vec<String> {
        vec![
            self.url.to_string(),
            self.client_id.clone(),
            self.client_secret.clone(),
            self.scope.clone(),
            match self.placement {
                Placement::Header => "header",
                Placement::Body => "body",
            }
            .into(),
            self.refresh_url.to_string(),
            self.auto_refresh.to_string(),
            self.authorization
                .as_ref()
                .map(|authorization| authorization.url.to_string())
                .unwrap_or_default(),
            self.authorization
                .as_ref()
                .map(|authorization| authorization.callback.to_string())
                .unwrap_or_default(),
        ]
    }

    #[cfg(test)]
    fn fetch_with(
        self,
        client: &Client,
        authorize: impl FnOnce(Authorization, &str, &str) -> Result<Code>,
    ) -> Result<HeaderValue> {
        Ok(self.fetch_token(client, None, authorize)?.header)
    }

    fn fetch_token(
        self,
        client: &Client,
        refresh_token: Option<String>,
        authorize: impl FnOnce(Authorization, &str, &str) -> Result<Code>,
    ) -> Result<CachedToken> {
        let Self {
            url,
            client_id,
            client_secret,
            scope,
            placement,
            authorization,
            refresh_url,
            auto_refresh: _,
        } = self;
        let refreshing = refresh_token.is_some();
        let mut form = if let Some(refresh) = &refresh_token {
            vec![
                ("grant_type", "refresh_token".to_owned()),
                ("refresh_token", refresh.clone()),
            ]
        } else if let Some(authorization) = authorization {
            let code = authorize(authorization, &client_id, &scope)?;
            vec![
                ("grant_type", "authorization_code".to_owned()),
                ("code", code.value),
                ("code_verifier", code.verifier),
                ("redirect_uri", code.redirect_uri),
            ]
        } else {
            let mut form = vec![("grant_type", "client_credentials".to_owned())];
            if !scope.is_empty() {
                form.push(("scope", scope));
            }
            form
        };
        let started = Instant::now();
        let mut builder = client.post(if refreshing { refresh_url } else { url });
        match placement {
            Placement::Body => {
                form.push(("client_id", client_id));
                if !client_secret.is_empty() {
                    form.push(("client_secret", client_secret));
                }
            }
            Placement::Header => {
                let id = utf8_percent_encode(&client_id, NON_ALPHANUMERIC).to_string();
                let secret = utf8_percent_encode(&client_secret, NON_ALPHANUMERIC).to_string();
                builder = builder.basic_auth(id, Some(secret));
            }
        }
        let mut response = builder
            .form(&form)
            .send()
            .map_err(|_| Error::invalid("cannot contact the OAuth token endpoint"))?;
        if !response.status().is_success() {
            return Err(Error::invalid(format!(
                "OAuth token endpoint returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::invalid("cannot read the OAuth token response"))?;
        if bytes.len() > 65536 {
            return Err(Error::invalid("OAuth token response exceeds 64 KiB"));
        }
        let token: TokenResponse = serde_json::from_slice(&bytes).map_err(|_| {
            Error::invalid("OAuth token endpoint returned an invalid token response")
        })?;
        if token.access_token.is_empty() || !token.token_type.eq_ignore_ascii_case("Bearer") {
            return Err(Error::invalid(
                "OAuth token response requires a nonempty access_token and Bearer token_type",
            ));
        }
        let mut header = HeaderValue::from_str(&format!("Bearer {}", token.access_token))
            .map_err(|_| Error::invalid("OAuth token is not valid for an Authorization header"))?;
        header.set_sensitive(true);
        let expires = started
            .checked_add(Duration::from_secs(token.expires_in.unwrap_or(0)))
            .ok_or_else(|| Error::invalid("OAuth expires_in exceeds the supported duration"))?;
        if token.refresh_token.as_ref().is_some_and(String::is_empty) {
            return Err(Error::invalid("OAuth refresh_token must not be empty"));
        }
        Ok(CachedToken {
            header,
            expires,
            refresh_token: token.refresh_token.or(refresh_token),
        })
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default, deserialize_with = "expires_in")]
    expires_in: Option<u64>,
    refresh_token: Option<String>,
}

fn expires_in<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error> {
    u64::deserialize(deserializer).map(Some)
}

fn unsupported(feature: impl Into<String>) -> Error {
    Error::Unsupported {
        feature: format!("OAuth 2 {}", feature.into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use reqwest::blocking::Client;

    use super::{TokenCache, TokenRequest};
    use crate::{bru::Document, oauth_interactive::Code, variables::Variables};

    fn configuration(endpoint: &str, extra: &str) -> Document {
        Document::parse(&format!(
            "auth:oauth2 {{\n  grant_type: authorization_code\n  authorization_url: https://identity.example/authorize\n  access_token_url: {endpoint}\n  client_id: public-client\n  {extra}\n}}\n"
        ))
        .unwrap()
    }

    #[test]
    fn code_exchange_sends_pkce_redirect_and_no_public_client_secret() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            let request = loop {
                let size = stream.read(&mut buffer).unwrap();
                assert_ne!(size, 0);
                bytes.extend_from_slice(&buffer[..size]);
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&bytes[..index]).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    if bytes.len() >= index + 4 + length {
                        break String::from_utf8(bytes).unwrap();
                    }
                }
            };
            assert!(request.contains("grant_type=authorization_code"));
            assert!(request.contains("code=authorization-secret"));
            assert!(request.contains("code_verifier=verifier-secret"));
            assert!(request.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback"));
            assert!(request.contains("client_id=public-client"));
            assert!(!request.contains("client_secret"));
            let body = r#"{"access_token":"token-secret","token_type":"Bearer"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let document = configuration(&format!("http://{address}/token"), "");
        let request = TokenRequest::prepare(&document, &Variables::new()).unwrap();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let token = request
            .fetch_with(&client, |_, id, _| {
                assert_eq!(id, "public-client");
                Ok(Code {
                    value: "authorization-secret".into(),
                    verifier: "verifier-secret".into(),
                    redirect_uri: "http://127.0.0.1:8765/callback".into(),
                })
            })
            .unwrap();
        assert_eq!(token.to_str().unwrap(), "Bearer token-secret");
        assert!(token.is_sensitive());
        server.join().unwrap();
    }

    #[test]
    fn code_configuration_rejects_insecure_endpoints_and_disabled_pkce_before_io() {
        for (endpoint, extra) in [
            ("http://example.com/token", ""),
            ("https://example.com/token", "pkce: false"),
            (
                "https://example.com/token",
                "callback_url: http://0.0.0.0/callback",
            ),
        ] {
            let document = configuration(endpoint, extra);
            assert!(TokenRequest::prepare(&document, &Variables::new()).is_err());
        }
        let document = configuration("https://example.com/token", "");
        assert!(TokenRequest::prepare(&document, &Variables::new()).is_ok());
    }

    fn client_configuration(endpoint: &str, extra: &str) -> Document {
        Document::parse(&format!(
            "auth:oauth2 {{\n  grant_type: client_credentials\n  access_token_url: {endpoint}\n  client_id: client\n  client_secret: secret\n  {extra}\n}}\n"
        )).unwrap()
    }

    fn token_server(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "token request timed out"
                            );
                            thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(error) => panic!("cannot accept token request: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let size = stream.read(&mut buffer).unwrap();
                    assert_ne!(size, 0);
                    bytes.extend_from_slice(&buffer[..size]);
                    if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..index]).unwrap();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap();
                        if bytes.len() >= index + 4 + length {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8(bytes).unwrap());
                write!(stream, "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        (format!("http://{address}/token"), server)
    }

    fn client() -> Client {
        Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    fn expire(cache: &TokenCache) {
        for token in cache.0.lock().unwrap().values_mut() {
            token.expires = std::time::Instant::now();
        }
    }

    #[test]
    fn cached_tokens_are_reused_isolated_and_explicitly_cleared() {
        let (endpoint, server) = token_server(vec![
            (
                200,
                r#"{"access_token":"one","token_type":"Bearer","expires_in":3600}"#
            );
            4
        ]);
        let client = client();
        let cache = TokenCache::default();
        let configuration = client_configuration(&endpoint, "");
        let fetch = || {
            cache
                .fetch(
                    TokenRequest::prepare(&configuration, &Variables::new()).unwrap(),
                    &client,
                )
                .unwrap()
        };
        assert_eq!(fetch(), fetch());
        let scoped = client_configuration(&endpoint, "scope: other");
        cache
            .fetch(
                TokenRequest::prepare(&scoped, &Variables::new()).unwrap(),
                &client,
            )
            .unwrap();
        let placement = client_configuration(&endpoint, "credentials_placement: header");
        cache
            .fetch(
                TokenRequest::prepare(&placement, &Variables::new()).unwrap(),
                &client,
            )
            .unwrap();
        cache.clear().unwrap();
        fetch();
        assert_eq!(server.join().unwrap().len(), 4);
    }

    #[test]
    fn expiry_refreshes_rotates_and_preserves_omitted_refresh_token() {
        let (endpoint, server) = token_server(vec![
            (
                200,
                r#"{"access_token":"one","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-one"}"#,
            ),
            (
                200,
                r#"{"access_token":"two","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-two"}"#,
            ),
            (
                200,
                r#"{"access_token":"three","token_type":"Bearer","expires_in":3600}"#,
            ),
            (
                200,
                r#"{"access_token":"four","token_type":"Bearer","expires_in":3600}"#,
            ),
        ]);
        let client = client();
        let cache = TokenCache::default();
        let configuration =
            client_configuration(&endpoint, "auto_refresh_token: true\n  refresh_token_url:");
        for expected in ["one", "two", "three", "four"] {
            let header = cache
                .fetch(
                    TokenRequest::prepare(&configuration, &Variables::new()).unwrap(),
                    &client,
                )
                .unwrap();
            assert_eq!(header.to_str().unwrap(), format!("Bearer {expected}"));
            expire(&cache);
        }
        let requests = server.join().unwrap();
        assert!(requests[0].contains("grant_type=client_credentials"));
        assert!(
            requests[1].contains("grant_type=refresh_token")
                && requests[1].contains("refresh_token=refresh-one")
        );
        assert!(requests[2].contains("refresh_token=refresh-two"));
        assert!(requests[3].contains("refresh_token=refresh-two"));
    }

    #[test]
    fn absent_expiry_and_disabled_refresh_reacquire_instead_of_reusing() {
        for extra in ["", "auto_refresh_token: false"] {
            let body = if extra.is_empty() {
                r#"{"access_token":"one","token_type":"Bearer"}"#
            } else {
                r#"{"access_token":"one","token_type":"Bearer","expires_in":0,"refresh_token":"unused"}"#
            };
            let (endpoint, server) = token_server(vec![(200, body); 2]);
            let cache = TokenCache::default();
            let client = client();
            let configuration = client_configuration(&endpoint, extra);
            for _ in 0..2 {
                cache
                    .fetch(
                        TokenRequest::prepare(&configuration, &Variables::new()).unwrap(),
                        &client,
                    )
                    .unwrap();
            }
            assert!(
                server
                    .join()
                    .unwrap()
                    .iter()
                    .all(|request| request.contains("grant_type=client_credentials"))
            );
        }
    }

    #[test]
    fn failed_refresh_evicts_without_retry_or_secret_error_body() {
        let (endpoint, server) = token_server(vec![
            (
                200,
                r#"{"access_token":"one","token_type":"Bearer","expires_in":0,"refresh_token":"private-refresh"}"#,
            ),
            (400, r#"{"error":"private-refresh secret one"}"#),
            (
                200,
                r#"{"access_token":"two","token_type":"Bearer","expires_in":3600}"#,
            ),
        ]);
        let cache = TokenCache::default();
        let client = client();
        let configuration = client_configuration(&endpoint, "auto_refresh_token: true");
        let request = || TokenRequest::prepare(&configuration, &Variables::new()).unwrap();
        cache.fetch(request(), &client).unwrap();
        let error = cache.fetch(request(), &client).unwrap_err().to_string();
        assert!(error.contains("HTTP 400"));
        assert!(!error.contains("private-refresh") && !error.contains("secret"));
        assert!(cache.0.lock().unwrap().is_empty());
        cache.fetch(request(), &client).unwrap();
        assert!(server.join().unwrap()[2].contains("grant_type=client_credentials"));
    }

    #[test]
    fn malformed_lifetimes_and_refresh_tokens_are_not_cached_or_disclosed() {
        for body in [
            r#"{"access_token":"private","token_type":"Bearer","expires_in":-1}"#,
            r#"{"access_token":"private","token_type":"Bearer","expires_in":"3600"}"#,
            r#"{"access_token":"private","token_type":"Bearer","expires_in":null}"#,
            r#"{"access_token":"private","token_type":"Bearer","expires_in":1.5}"#,
            r#"{"access_token":"private","token_type":"Bearer","expires_in":18446744073709551615}"#,
            r#"{"access_token":"private","token_type":"Bearer","refresh_token":""}"#,
        ] {
            let (endpoint, server) = token_server(vec![(200, body)]);
            let cache = TokenCache::default();
            let configuration = client_configuration(&endpoint, "");
            let error = cache
                .fetch(
                    TokenRequest::prepare(&configuration, &Variables::new()).unwrap(),
                    &client(),
                )
                .unwrap_err()
                .to_string();
            assert!(!error.contains("private"));
            assert!(cache.0.lock().unwrap().is_empty());
            server.join().unwrap();
        }
    }

    #[test]
    fn concurrent_browser_acquisition_is_serialized_and_cached() {
        let (endpoint, server) = token_server(vec![(
            200,
            r#"{"access_token":"one","token_type":"Bearer","expires_in":3600}"#,
        )]);
        let cache = std::sync::Arc::new(TokenCache::default());
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let client = client();
        thread::scope(|scope| {
            for _ in 0..4 {
                let cache = &cache;
                let calls = &calls;
                let client = &client;
                let document = configuration(&endpoint, "");
                scope.spawn(move || {
                    cache
                        .fetch_with(
                            TokenRequest::prepare(&document, &Variables::new()).unwrap(),
                            client,
                            |_, _, _| {
                                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                Ok(Code {
                                    value: "code".into(),
                                    verifier: "verifier".into(),
                                    redirect_uri: "http://127.0.0.1:1234/callback".into(),
                                })
                            },
                        )
                        .unwrap();
                });
            }
        });
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn expanded_secrets_and_authorization_configuration_isolate_cache_keys() {
        let document = configuration("http://127.0.0.1:4567/token", "client_secret: {{secret}}");
        let mut variables = Variables::from([("secret".into(), "one".into())]);
        let original = TokenRequest::prepare(&document, &variables)
            .unwrap()
            .cache_key();
        variables.insert("secret".into(), "two".into());
        assert_ne!(
            original,
            TokenRequest::prepare(&document, &variables)
                .unwrap()
                .cache_key()
        );
        variables.insert("secret".into(), "one".into());
        let mut request = TokenRequest::prepare(&document, &variables).unwrap();
        request.authorization.as_mut().unwrap().callback =
            reqwest::Url::parse("http://127.0.0.1:8765/other").unwrap();
        assert_ne!(original, request.cache_key());
        let mut request = TokenRequest::prepare(&document, &variables).unwrap();
        request.authorization.as_mut().unwrap().url =
            reqwest::Url::parse("https://different.example/authorize").unwrap();
        assert_ne!(original, request.cache_key());
    }

    #[test]
    fn refresh_uses_separate_endpoint_and_configured_basic_credentials() {
        let (endpoint, server) = token_server(vec![
            (
                200,
                r#"{"access_token":"one","token_type":"Bearer","expires_in":0,"refresh_token":"old"}"#,
            ),
            (
                200,
                r#"{"access_token":"two","token_type":"Bearer","expires_in":3600}"#,
            ),
        ]);
        let refresh_endpoint = endpoint.replace("/token", "/refresh");
        let configuration = client_configuration(
            &endpoint,
            &format!(
                "credentials_placement: header\n  refresh_token_url: {refresh_endpoint}\n  auto_refresh_token: true"
            ),
        );
        let client = client();
        let cache = TokenCache::default();
        for _ in 0..2 {
            cache
                .fetch(
                    TokenRequest::prepare(&configuration, &Variables::new()).unwrap(),
                    &client,
                )
                .unwrap();
        }
        let requests = server.join().unwrap();
        assert!(requests[1].starts_with("POST /refresh "));
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("authorization: basic ")
        );
        assert!(!requests[1].contains("client_secret="));
    }

    #[test]
    fn authorization_code_refresh_does_not_open_the_browser_again() {
        let (endpoint, server) = token_server(vec![
            (
                200,
                r#"{"access_token":"one","token_type":"Bearer","expires_in":0,"refresh_token":"refresh"}"#,
            ),
            (
                200,
                r#"{"access_token":"two","token_type":"Bearer","expires_in":3600}"#,
            ),
        ]);
        let document = configuration(&endpoint, "auto_refresh_token: true");
        let cache = TokenCache::default();
        let client = client();
        cache
            .fetch_with(
                TokenRequest::prepare(&document, &Variables::new()).unwrap(),
                &client,
                |_, _, _| {
                    Ok(Code {
                        value: "code".into(),
                        verifier: "verifier".into(),
                        redirect_uri: "http://127.0.0.1:1234/callback".into(),
                    })
                },
            )
            .unwrap();
        let token = cache
            .fetch_with(
                TokenRequest::prepare(&document, &Variables::new()).unwrap(),
                &client,
                |_, _, _| panic!("refresh must not open the browser"),
            )
            .unwrap();
        assert_eq!(token.to_str().unwrap(), "Bearer two");
        let requests = server.join().unwrap();
        assert!(requests[1].contains("grant_type=refresh_token"));
        assert!(!requests[1].contains("code_verifier") && !requests[1].contains("redirect_uri"));
    }
}
