use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use reqwest::{
    Url,
    blocking::Request,
    header::{AUTHORIZATION, HOST, HeaderValue},
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{
    Error, Result,
    bru::Document,
    variables::{Variables, interpolate},
};

pub(crate) struct Signing {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    region: String,
    service: String,
}

impl Signing {
    pub(crate) fn prepare(document: &Document, variables: &Variables) -> Result<Self> {
        for pair in document.pairs("auth:awsv4")? {
            if pair.enabled
                && !matches!(
                    pair.key.as_str(),
                    "accessKeyId"
                        | "secretAccessKey"
                        | "sessionToken"
                        | "region"
                        | "service"
                        | "profileName"
                )
            {
                return Err(Error::Unsupported {
                    feature: "AWS Signature V4 auth field".into(),
                });
            }
        }
        let value = |name: &str| -> Result<String> {
            let value = document.value("auth:awsv4", name)?.unwrap_or_default();
            interpolate(&value, variables)
        };
        if !value("profileName")?.is_empty() {
            return Err(Error::Unsupported {
                feature: "AWS credential profiles; configure explicit credentials".into(),
            });
        }
        let access_key = value("accessKeyId")?;
        let secret_key = value("secretAccessKey")?;
        let session_token = value("sessionToken")?;
        let region = value("region")?;
        let service = value("service")?;
        if access_key.is_empty()
            || access_key.len() > 256
            || !access_key.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || secret_key.is_empty()
            || secret_key.len() > 16 * 1024
            || session_token.len() > 16 * 1024
        {
            return Err(Error::invalid("invalid AWS Signature V4 credentials"));
        }
        for scope in [&region, &service] {
            if scope.is_empty()
                || scope.len() > 256
                || !scope
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(Error::invalid(
                    "AWS Signature V4 requires an explicit lowercase region and service",
                ));
            }
        }
        let session_token = (!session_token.is_empty()).then_some(session_token);
        if let Some(token) = &session_token {
            HeaderValue::from_str(token)
                .map_err(|_| Error::invalid("invalid AWS session token"))?;
        }
        Ok(Self {
            access_key,
            secret_key,
            session_token,
            region,
            service,
        })
    }

    pub(crate) fn validate_url(&self, raw_url: &str, url: &Url) -> Result<()> {
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(Error::invalid(
                "AWS Signature V4 cannot use URL credentials or fragments",
            ));
        }
        if url.query_pairs().any(|(key, _)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "x-amz-algorithm"
                    | "x-amz-credential"
                    | "x-amz-date"
                    | "x-amz-expires"
                    | "x-amz-signedheaders"
                    | "x-amz-signature"
                    | "x-amz-security-token"
            )
        }) {
            return Err(Error::invalid(
                "AWS Signature V4 cannot combine with presigned URL parameters",
            ));
        }
        if let Some(query) = url.query() {
            for component in query.split(['&', '=']) {
                let decoded = decode(component.as_bytes())?;
                std::str::from_utf8(&decoded).map_err(|_| {
                    Error::invalid("AWS Signature V4 requires UTF-8 query parameters")
                })?;
            }
        }
        if self.service == "s3" {
            if raw_url.contains('\\') {
                return Err(Error::Unsupported {
                    feature: "S3 URLs with literal backslashes".into(),
                });
            }
            // URL parsing removes dot segments before signing; never silently change an S3 object key.
            let authority = raw_url
                .split_once("://")
                .map_or("", |(_, authority)| authority);
            let path = authority
                .find(['/', '?', '#'])
                .filter(|&start| authority.as_bytes()[start] == b'/')
                .map_or("/", |start| &authority[start..])
                .split(['?', '#'])
                .next()
                .unwrap_or("/");
            for segment in path.split('/') {
                let decoded = decode(segment.as_bytes())?;
                if decoded == b"." || decoded == b".." {
                    return Err(Error::Unsupported {
                        feature: "S3 object paths with dot segments".into(),
                    });
                }
            }
        }
        Ok(())
    }

    pub(crate) fn sign(&self, request: &mut Request) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let timestamp = format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        self.sign_at(request, &timestamp)
    }

    fn sign_at(&self, request: &mut Request, timestamp: &str) -> Result<()> {
        self.validate_url(request.url().as_str(), request.url())?;
        for name in [
            "authorization",
            "host",
            "x-amz-date",
            "x-amz-content-sha256",
            "x-amz-security-token",
            "x-amz-region-set",
        ] {
            if request.headers().contains_key(name) {
                return Err(Error::invalid(
                    "AWS Signature V4 cannot combine with explicit signing headers",
                ));
            }
        }
        let payload = match request.body() {
            Some(body) => body.as_bytes().ok_or_else(|| Error::Unsupported {
                feature: "AWS Signature V4 with a streaming request body".into(),
            })?,
            None => b"",
        };
        let payload_hash = hex(&Sha256::digest(payload));
        let path = canonical_path(request.url().path(), self.service == "s3")?;
        let query = query_string(request.url().query().unwrap_or(""), true)?;
        if request.url().query().is_some() {
            let wire_query = query_string(request.url().query().unwrap_or(""), false)?;
            request.url_mut().set_query(Some(&wire_query));
        }
        let host = request
            .url()
            .host()
            .ok_or_else(|| Error::invalid("AWS request has no host"))?
            .to_string();
        let host = request
            .url()
            .port()
            .map_or(host.clone(), |port| format!("{host}:{port}"));
        let headers = request.headers_mut();
        headers.insert(HOST, header(&host, false)?);
        headers.insert("x-amz-date", header(timestamp, false)?);
        if self.service == "s3" {
            headers.insert("x-amz-content-sha256", header(&payload_hash, false)?);
        }
        if let Some(token) = &self.session_token {
            headers.insert("x-amz-security-token", header(token, true)?);
        }
        let mut canonical = BTreeMap::new();
        for name in headers.keys() {
            if matches!(
                name.as_str(),
                "connection"
                    | "x-amzn-trace-id"
                    | "user-agent"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "te"
                    | "trailer"
                    | "upgrade"
                    | "proxy-authorization"
                    | "proxy-authenticate"
                    | "expect"
            ) {
                continue;
            }
            let values = headers
                .get_all(name)
                .iter()
                .map(|value| {
                    value
                        .to_str()
                        .map(|value| value.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
                        .map_err(|_| {
                            Error::invalid("AWS Signature V4 requires text request headers")
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            canonical.insert(name.as_str().to_owned(), values.join(","));
        }
        let canonical_headers = canonical
            .iter()
            .map(|(key, value)| format!("{key}:{value}\n"))
            .collect::<String>();
        let signed_headers = canonical.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical_request = format!(
            "{}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            request.method()
        );
        let date = &timestamp[..8];
        let scope = format!("{date}/{}/{}/aws4_request", self.region, self.service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            hex(&Sha256::digest(canonical_request.as_bytes()))
        );
        let date_key = hmac(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        )?;
        let region_key = hmac(&date_key, self.region.as_bytes())?;
        let service_key = hmac(&region_key, self.service.as_bytes())?;
        let signing_key = hmac(&service_key, b"aws4_request")?;
        let signature = hex(&hmac(&signing_key, string_to_sign.as_bytes())?);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );
        request
            .headers_mut()
            .insert(AUTHORIZATION, header(&authorization, true)?);
        Ok(())
    }
}

pub(crate) fn append_query(url: &mut Url, key: &str, value: &str) {
    let pair = format!(
        "{}={}",
        encode(key.as_bytes(), false),
        encode(value.as_bytes(), false)
    );
    let query = url
        .query()
        .filter(|query| !query.is_empty())
        .map_or_else(|| pair.clone(), |query| format!("{query}&{pair}"));
    url.set_query(Some(&query));
}

fn query_string(query: &str, canonical: bool) -> Result<String> {
    if query.is_empty() {
        return Ok(String::new());
    }
    let mut pairs = query
        .split('&')
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((
                encode(&decode(key.as_bytes())?, false),
                encode(&decode(value.as_bytes())?, false),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    if canonical {
        pairs.sort();
    }
    Ok(pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&"))
}

fn header(value: &str, sensitive: bool) -> Result<HeaderValue> {
    let mut value = HeaderValue::from_str(value)
        .map_err(|_| Error::invalid("invalid AWS Signature V4 header"))?;
    value.set_sensitive(sensitive);
    Ok(value)
}

fn canonical_path(path: &str, s3: bool) -> Result<String> {
    if s3 {
        decode(path.as_bytes())?;
        return Ok(path.to_owned());
    }
    let normalized = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    let normalized = format!(
        "/{normalized}{}",
        if path.ends_with('/') && !normalized.is_empty() {
            "/"
        } else {
            ""
        }
    );
    Ok(encode(normalized.as_bytes(), true))
}

fn decode(value: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%' {
            let pair = value
                .get(index + 1..index + 3)
                .ok_or_else(|| Error::invalid("invalid AWS URL percent escape"))?;
            let high = (pair[0] as char).to_digit(16);
            let low = (pair[1] as char).to_digit(16);
            let (Some(high), Some(low)) = (high, low) else {
                return Err(Error::invalid("invalid AWS URL percent escape"));
            };
            bytes.push((high * 16 + low) as u8);
            index += 3;
        } else {
            bytes.push(value[index]);
            index += 1;
        }
    }
    Ok(bytes)
}

fn encode(value: &[u8], preserve_slashes: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for &byte in value {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (preserve_slashes && byte == b'/')
        {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 15) as usize] as char);
        }
    }
    encoded
}

fn hmac(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Error::invalid("cannot initialize AWS Signature V4 signing key"))?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use reqwest::{
        Method, Url,
        blocking::{Body, Request},
        header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
    };

    use super::{Signing, append_query, canonical_path, query_string};

    #[test]
    fn query_preserves_literal_plus_utf8_duplicates_and_rfc3986_spaces() {
        assert_eq!(
            query_string("plus=a+b&space=a%20b&plus=a%2Bb&%C3%A9=caf%C3%A9&acl", true).unwrap(),
            "%C3%A9=caf%C3%A9&acl=&plus=a%2Bb&plus=a%2Bb&space=a%20b"
        );
        let mut url = Url::parse("https://example.com/?literal=hello+world").unwrap();
        append_query(&mut url, "space", "hello world");
        assert_eq!(url.query(), Some("literal=hello+world&space=hello%20world"));
        assert!(query_string("invalid=%Q", true).is_err());
        assert_eq!(
            query_string("repeat=z&repeat=a&plus=one+two", false).unwrap(),
            "repeat=z&repeat=a&plus=one%2Btwo"
        );
    }

    fn signing() -> Signing {
        Signing {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
            region: "us-east-1".into(),
            service: "service".into(),
        }
    }

    #[test]
    fn aws_published_fixed_signatures_cover_empty_body_query_order_and_form_body() {
        // AWS's published suite, mirrored by botocore: tests/unit/auth/aws4_testsuite.
        let vectors = [
            (
                Method::GET,
                "https://example.amazonaws.com/",
                None,
                "host;x-amz-date",
                "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            ),
            (
                Method::GET,
                "https://example.amazonaws.com/?Param2=value2&Param1=value1",
                None,
                "host;x-amz-date",
                "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
            ),
            (
                Method::POST,
                "https://example.amazonaws.com/",
                Some("Param1=value1"),
                "content-type;host;x-amz-date",
                "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
            ),
        ];
        for (method, url, body, headers, signature) in vectors {
            let mut request = Request::new(method, Url::parse(url).unwrap());
            if let Some(body) = body {
                *request.body_mut() = Some(Body::from(body.to_owned()));
                request.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
            }
            signing().sign_at(&mut request, "20150830T123600Z").unwrap();
            assert_eq!(
                request.headers()[AUTHORIZATION],
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders={headers}, Signature={signature}"
                )
            );
            assert!(request.headers()[AUTHORIZATION].is_sensitive());
        }
    }

    #[test]
    fn s3_preserves_object_paths_while_other_services_normalize_and_double_encode() {
        assert_eq!(
            canonical_path("/a//b%20c/%2F", true).unwrap(),
            "/a//b%20c/%2F"
        );
        assert_eq!(
            canonical_path("/a//b%20c/%2F", false).unwrap(),
            "/a/b%2520c/%252F"
        );
        assert_eq!(canonical_path("/caf%C3%A9/", true).unwrap(), "/caf%C3%A9/");
        assert_eq!(
            canonical_path("/bucket/%41//%2f", true).unwrap(),
            "/bucket/%41//%2f"
        );
        assert_eq!(canonical_path("/", false).unwrap(), "/");
        assert!(canonical_path("/broken%XZ", true).is_err());
        let mut signing = signing();
        signing.service = "s3".into();
        for raw in ["https://example.com/a/../b", "https://example.com/a/%2e/b"] {
            assert!(
                signing
                    .validate_url(raw, &Url::parse(raw).unwrap())
                    .is_err()
            );
        }
        let raw = "https://example.com?prefix=a/../b";
        signing
            .validate_url(raw, &Url::parse(raw).unwrap())
            .unwrap();
    }

    #[test]
    fn tokens_are_sensitive_and_multiply_valued_headers_have_canonical_whitespace() {
        let mut signing = signing();
        signing.session_token = Some("session-secret".into());
        let mut request = Request::new(
            Method::POST,
            Url::parse("https://example.com:8443/").unwrap(),
        );
        request
            .headers_mut()
            .append("custom", HeaderValue::from_static("  one\t  two  "));
        request
            .headers_mut()
            .append("custom", HeaderValue::from_static("three"));
        signing.sign_at(&mut request, "20150830T123600Z").unwrap();
        let signature = request.headers()[AUTHORIZATION].clone();
        assert_eq!(request.headers()["host"], "example.com:8443");
        assert!(request.headers()["x-amz-security-token"].is_sensitive());
        let mut equivalent = Request::new(
            Method::POST,
            Url::parse("https://example.com:8443/").unwrap(),
        );
        equivalent
            .headers_mut()
            .append("custom", HeaderValue::from_static("one two,three"));
        signing
            .sign_at(&mut equivalent, "20150830T123600Z")
            .unwrap();
        assert_eq!(signature, equivalent.headers()[AUTHORIZATION]);
    }
}
