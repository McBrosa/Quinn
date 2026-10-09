use std::{io::Read, time::Duration};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Url, blocking::Client, header::HeaderValue};
use serde::Deserialize;

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
}

enum Placement {
    Header,
    Body,
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
        Ok(Self {
            url,
            client_id,
            client_secret,
            scope,
            placement,
            authorization,
        })
    }

    pub(crate) fn fetch(self, client: &Client) -> Result<HeaderValue> {
        self.fetch_with(client, Authorization::authorize)
    }

    fn fetch_with(
        self,
        client: &Client,
        authorize: impl FnOnce(Authorization, &str, &str) -> Result<Code>,
    ) -> Result<HeaderValue> {
        let Self {
            url,
            client_id,
            client_secret,
            scope,
            placement,
            authorization,
        } = self;
        let mut form = if let Some(authorization) = authorization {
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
        let mut builder = client.post(url);
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
            .map_err(|source| Error::Http {
                reason: source.to_string(),
            })?;
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
        Ok(header)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
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

    use super::TokenRequest;
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
}
