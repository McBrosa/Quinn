use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use md5::Md5;
use reqwest::{
    blocking::{Client, Request, Response},
    header::{AUTHORIZATION, HeaderValue, WWW_AUTHENTICATE},
};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Send the original request and replay a buffered body once after a Digest challenge.
pub(crate) fn send(
    client: &Client,
    mut request: Request,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<Response> {
    if !username.is_ascii() || username.chars().any(char::is_control) {
        return Err(Error::Unsupported {
            feature: "non-ASCII or control-character Digest usernames".into(),
        });
    }
    let mut retry = request.try_clone().ok_or_else(|| Error::Unsupported {
        feature: "Digest authentication with a non-replayable request body".into(),
    })?;
    let start = Instant::now();
    *request.timeout_mut() = Some(timeout);
    let response = client.execute(request).map_err(Error::http)?;
    if response.status() != 401 {
        return Ok(response);
    }
    if response.url().origin() != retry.url().origin() {
        return Err(Error::invalid(
            "cannot use a Digest challenge from another origin",
        ));
    }
    let mut challenge = None;
    for header in response.headers().get_all(WWW_AUTHENTICATE) {
        let raw = header
            .to_str()
            .map_err(|_| Error::invalid("Digest challenge must contain ASCII header text"))?;
        let raw = raw.trim();
        if raw
            .split_once(char::is_whitespace)
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("Digest"))
        {
            if challenge.is_some() {
                return Err(Error::Unsupported {
                    feature: "multiple Digest challenges".into(),
                });
            }
            challenge = Some(parse_challenge(raw)?);
        }
    }
    let Some(challenge) = challenge else {
        return Ok(response);
    };
    let uri = match retry.url().query() {
        Some(query) => format!("{}?{query}", retry.url().path()),
        None => retry.url().path().to_owned(),
    };
    let mut random = [0u8; 24];
    getrandom::fill(&mut random)
        .map_err(|_| Error::invalid("cannot generate Digest client nonce"))?;
    let cnonce = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let authorization = authorization(
        &challenge,
        username,
        password,
        retry.method().as_str(),
        &uri,
        &cnonce,
    )?;
    retry.headers_mut().insert(AUTHORIZATION, authorization);
    let remaining = timeout
        .checked_sub(start.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| Error::Http {
            reason: "Digest request timed out".into(),
        })?;
    *retry.timeout_mut() = Some(remaining);
    drop(response);
    client.execute(retry).map_err(Error::http)
}

fn parse_challenge(raw: &str) -> Result<BTreeMap<String, String>> {
    if raw.len() > 8192 {
        return Err(Error::invalid("Digest challenge exceeds the 8 KiB limit"));
    }
    let (_, mut tail) = raw
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::invalid("invalid Digest challenge"))?;
    let mut fields = BTreeMap::new();
    while !tail.trim().is_empty() {
        tail = tail.trim_start();
        let length = tail
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            .count();
        if length == 0 {
            return Err(Error::invalid("invalid Digest challenge parameter"));
        }
        let key = tail[..length].to_ascii_lowercase();
        tail = tail[length..]
            .trim_start()
            .strip_prefix('=')
            .ok_or_else(|| Error::invalid("invalid Digest challenge parameter"))?
            .trim_start();
        let value;
        if let Some(quoted) = tail.strip_prefix('"') {
            let mut text = String::new();
            let mut chars = quoted.char_indices();
            let mut end = None;
            while let Some((offset, ch)) = chars.next() {
                match ch {
                    '"' => {
                        end = Some(offset + 1);
                        break;
                    }
                    '\\' => {
                        let (_, escaped) = chars
                            .next()
                            .ok_or_else(|| Error::invalid("invalid Digest quoted value"))?;
                        text.push(escaped);
                    }
                    ch => text.push(ch),
                }
            }
            let end = end.ok_or_else(|| Error::invalid("unclosed Digest quoted value"))?;
            tail = &quoted[end..];
            value = text;
        } else {
            let length = tail
                .bytes()
                .take_while(|byte| {
                    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte)
                })
                .count();
            if length == 0 {
                return Err(Error::invalid("invalid Digest parameter value"));
            }
            value = tail[..length].into();
            tail = &tail[length..];
        }
        if value.chars().any(char::is_control) || fields.insert(key, value).is_some() {
            return Err(Error::invalid(
                "duplicate or invalid Digest challenge parameter",
            ));
        }
        tail = tail.trim_start();
        if !tail.is_empty() {
            tail = tail
                .strip_prefix(',')
                .ok_or_else(|| Error::invalid("invalid Digest challenge separator"))?;
            if tail.trim().is_empty() {
                return Err(Error::invalid("invalid Digest challenge separator"));
            }
        }
    }
    Ok(fields)
}

fn authorization(
    fields: &BTreeMap<String, String>,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    cnonce: &str,
) -> Result<HeaderValue> {
    let realm = fields
        .get("realm")
        .ok_or_else(|| Error::invalid("Digest challenge has no realm"))?;
    let nonce = fields
        .get("nonce")
        .filter(|nonce| !nonce.is_empty())
        .ok_or_else(|| Error::invalid("Digest challenge has no nonce"))?;
    let algorithm = fields.get("algorithm").map(String::as_str).unwrap_or("MD5");
    let algorithm = if algorithm.eq_ignore_ascii_case("MD5") {
        "MD5"
    } else if algorithm.eq_ignore_ascii_case("SHA-256") {
        "SHA-256"
    } else {
        return Err(Error::Unsupported {
            feature: format!("Digest algorithm '{algorithm}'"),
        });
    };
    let qop = if let Some(qop) = fields.get("qop") {
        if !qop
            .split(',')
            .any(|qop| qop.trim().eq_ignore_ascii_case("auth"))
        {
            return Err(Error::Unsupported {
                feature: "Digest qop without auth".into(),
            });
        }
        true
    } else {
        false
    };
    if fields
        .get("userhash")
        .is_some_and(|value| !value.eq_ignore_ascii_case("false"))
    {
        return Err(Error::Unsupported {
            feature: "Digest userhash".into(),
        });
    }
    let utf8 = if let Some(charset) = fields.get("charset") {
        if !charset.eq_ignore_ascii_case("UTF-8") {
            return Err(Error::Unsupported {
                feature: format!("Digest charset '{charset}'"),
            });
        }
        true
    } else {
        false
    };
    if !password.is_ascii() && !utf8 {
        return Err(Error::Unsupported {
            feature: "non-ASCII Digest passwords without charset UTF-8".into(),
        });
    }
    let ha1 = hash(algorithm, &format!("{username}:{realm}:{password}"));
    let ha2 = hash(algorithm, &format!("{method}:{uri}"));
    let response = if qop {
        hash(
            algorithm,
            &format!("{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}"),
        )
    } else {
        hash(algorithm, &format!("{ha1}:{nonce}:{ha2}"))
    };
    let mut header = format!(
        "Digest username={}, realm={}, nonce={}, uri={}, response={}, algorithm={algorithm}",
        quote(username),
        quote(realm),
        quote(nonce),
        quote(uri),
        quote(&response)
    );
    if qop {
        header.push_str(&format!(
            ", qop=auth, nc=00000001, cnonce={}",
            quote(cnonce)
        ));
    }
    if let Some(opaque) = fields.get("opaque") {
        header.push_str(&format!(", opaque={}", quote(opaque)));
    }
    let mut value = HeaderValue::from_str(&header)
        .map_err(|_| Error::invalid("invalid Digest authorization header"))?;
    value.set_sensitive(true);
    Ok(value)
}

fn hash(algorithm: &str, value: &str) -> String {
    if algorithm == "SHA-256" {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    } else {
        format!("{:x}", Md5::digest(value.as_bytes()))
    }
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{authorization, parse_challenge};

    #[test]
    fn matches_the_known_md5_digest_vector_and_handles_quoted_commas() {
        let fields = parse_challenge("Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"with,comma\"").unwrap();
        let header = authorization(
            &fields,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            "0a4f113b",
        )
        .unwrap();
        assert!(
            header
                .to_str()
                .unwrap()
                .contains("6629fae49393a05397450978507c4ef1")
        );
        assert!(header.to_str().unwrap().contains("opaque=\"with,comma\""));
        assert!(header.is_sensitive());
    }

    #[test]
    fn matches_the_rfc_7616_sha256_reference_vector() {
        // https://www.rfc-editor.org/rfc/rfc7616.html#section-3.9.1
        let fields = parse_challenge("Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=SHA-256, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\"").unwrap();
        let header = authorization(
            &fields,
            "Mufasa",
            "Circle of Life",
            "GET",
            "/dir/index.html",
            "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
        )
        .unwrap();
        assert!(
            header
                .to_str()
                .unwrap()
                .contains("753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1")
        );
        assert!(header.is_sensitive());
    }
}
