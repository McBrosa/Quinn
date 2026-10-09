use std::io::Read;

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Url, blocking::Client, header::HeaderValue};
use serde::Deserialize;

use crate::{
    Error, Result,
    bru::Document,
    variables::{Variables, interpolate},
};

pub(crate) struct TokenRequest {
    url: Url,
    client_id: String,
    client_secret: String,
    scope: String,
    placement: Placement,
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
        if grant != "client_credentials" {
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
        let client_secret = value("client_secret", None)?;
        if client_id.is_empty() || client_secret.is_empty() {
            return Err(Error::invalid(
                "OAuth client ID and secret must not be empty",
            ));
        }
        let scope = value("scope", Some(""))?;
        Ok(Self {
            url,
            client_id,
            client_secret,
            scope,
            placement,
        })
    }

    pub(crate) fn fetch(self, client: &Client) -> Result<HeaderValue> {
        let Self {
            url,
            client_id,
            client_secret,
            scope,
            placement,
        } = self;
        let mut form = vec![("grant_type", "client_credentials".to_owned())];
        if !scope.is_empty() {
            form.push(("scope", scope));
        }
        let mut builder = client.post(url);
        match placement {
            Placement::Body => {
                form.push(("client_id", client_id));
                form.push(("client_secret", client_secret));
            }
            Placement::Header => {
                let id = utf8_percent_encode(&client_id, NON_ALPHANUMERIC).to_string();
                let secret = utf8_percent_encode(&client_secret, NON_ALPHANUMERIC).to_string();
                builder = builder.basic_auth(id, Some(secret));
            }
        }
        let mut response = builder.form(&form).send().map_err(Error::http)?;
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
