use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use reqwest::{
    blocking::Request,
    header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue},
};
use sha1::Sha1;
use sha2::Sha256;

use crate::{
    Error, Result,
    bru::Document,
    variables::{Variables, interpolate},
};

const MAX_PARAMETERS: usize = 10_000;

pub(crate) struct Signing {
    consumer_key: String,
    consumer_secret: String,
    access_token: Option<String>,
    token_secret: String,
    algorithm: Algorithm,
    realm: Option<String>,
}

enum Algorithm {
    Sha1,
    Sha256,
}

impl Signing {
    pub(crate) fn prepare(document: &Document, variables: &Variables) -> Result<Self> {
        let mut names = BTreeSet::new();
        for pair in document
            .pairs("auth:oauth1")?
            .into_iter()
            .filter(|pair| pair.enabled)
        {
            if !matches!(
                pair.key.as_str(),
                "consumer_key"
                    | "consumer_secret"
                    | "access_token"
                    | "token_secret"
                    | "signature_method"
                    | "realm"
                    | "placement"
                    | "version"
                    | "nonce"
                    | "timestamp"
                    | "callback_url"
                    | "verifier"
                    | "private_key"
                    | "include_body_hash"
            ) {
                return Err(Error::Unsupported {
                    feature: "OAuth 1 authentication field".into(),
                });
            }
            if !names.insert(pair.key) {
                return Err(Error::invalid(
                    "OAuth 1 authentication fields must be unique",
                ));
            }
        }
        let value = |name: &str| -> Result<String> {
            let value = document.value("auth:oauth1", name)?.unwrap_or_default();
            let expanded = interpolate(&value, variables)?;
            if expanded.len() > 16 * 1024 {
                return Err(Error::invalid(
                    "OAuth 1 authentication field exceeds the 16 KiB limit",
                ));
            }
            Ok(expanded)
        };
        for name in [
            "nonce",
            "timestamp",
            "callback_url",
            "verifier",
            "private_key",
        ] {
            if !value(name)?.is_empty() {
                return Err(Error::Unsupported {
                    feature: "OAuth 1 acquisition, private keys, or nonce/timestamp overrides"
                        .into(),
                });
            }
        }
        if !matches!(value("placement")?.as_str(), "" | "header") {
            return Err(Error::Unsupported {
                feature: "OAuth 1 placement other than header".into(),
            });
        }
        if !matches!(value("version")?.as_str(), "" | "1.0") {
            return Err(Error::Unsupported {
                feature: "OAuth version other than 1.0".into(),
            });
        }
        if !matches!(value("include_body_hash")?.as_str(), "" | "false") {
            return Err(Error::Unsupported {
                feature: "OAuth 1 body-hash extension".into(),
            });
        }
        let algorithm = match value("signature_method")?.as_str() {
            "" | "HMAC-SHA1" => Algorithm::Sha1,
            "HMAC-SHA256" => Algorithm::Sha256,
            _ => {
                return Err(Error::Unsupported {
                    feature: "OAuth 1 signature method; use HMAC-SHA1 or HMAC-SHA256".into(),
                });
            }
        };
        let consumer_key = value("consumer_key")?;
        let consumer_secret = value("consumer_secret")?;
        if consumer_key.is_empty() || consumer_secret.is_empty() {
            return Err(Error::invalid(
                "OAuth 1 requires a consumer key and consumer secret",
            ));
        }
        let access_token = value("access_token")?;
        let token_secret = value("token_secret")?;
        if access_token.is_empty() && !token_secret.is_empty() {
            return Err(Error::invalid(
                "OAuth 1 token secret requires an access token",
            ));
        }
        let access_token = (!access_token.is_empty()).then_some(access_token);
        let realm = value("realm")?;
        if !realm.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
            return Err(Error::invalid("OAuth 1 realm must contain printable ASCII"));
        }
        let realm = (!realm.is_empty()).then_some(realm);
        Ok(Self {
            consumer_key,
            consumer_secret,
            access_token,
            token_secret,
            algorithm,
            realm,
        })
    }

    pub(crate) fn sign(&self, request: &mut Request) -> Result<()> {
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce)
            .map_err(|_| Error::invalid("cannot generate an OAuth 1 nonce"))?;
        let nonce = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::invalid("cannot determine the OAuth 1 timestamp"))?
            .as_secs()
            .to_string();
        self.sign_at(request, &nonce, &timestamp)
    }

    fn sign_at(&self, request: &mut Request, nonce: &str, timestamp: &str) -> Result<()> {
        validate(request)?;
        let mut parameters = vec![
            ("oauth_consumer_key".to_owned(), self.consumer_key.clone()),
            ("oauth_nonce".to_owned(), nonce.to_owned()),
            (
                "oauth_signature_method".to_owned(),
                self.algorithm.name().to_owned(),
            ),
            ("oauth_timestamp".to_owned(), timestamp.to_owned()),
            ("oauth_version".to_owned(), "1.0".to_owned()),
        ];
        if let Some(token) = &self.access_token {
            parameters.push(("oauth_token".to_owned(), token.clone()));
        }
        let signature = self.signature(request, &parameters)?;
        parameters.push(("oauth_signature".to_owned(), signature));
        parameters.sort();
        let mut fields = Vec::new();
        if let Some(realm) = &self.realm {
            let realm = realm.replace('\\', "\\\\").replace('"', "\\\"");
            fields.push(format!("realm=\"{realm}\""));
        }
        fields.extend(
            parameters
                .iter()
                .map(|(key, value)| format!("{}=\"{}\"", encode(key), encode(value))),
        );
        let authorization = format!("OAuth {}", fields.join(", "));
        let mut authorization = HeaderValue::from_str(&authorization)
            .map_err(|_| Error::invalid("cannot create the OAuth 1 authorization header"))?;
        authorization.set_sensitive(true);
        request.headers_mut().insert(AUTHORIZATION, authorization);
        Ok(())
    }

    fn signature(&self, request: &Request, oauth: &[(String, String)]) -> Result<String> {
        let mut parameters = request_parameters(request)?;
        parameters.extend_from_slice(oauth);
        let mut parameters = parameters
            .into_iter()
            .map(|(key, value)| (encode(&key), encode(&value)))
            .collect::<Vec<_>>();
        parameters.sort();
        let parameters = parameters
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        let mut base_url = request.url().clone();
        base_url.set_query(None);
        base_url.set_fragment(None);
        let base_string = format!(
            "{}&{}&{}",
            encode(&request.method().as_str().to_ascii_uppercase()),
            encode(base_url.as_str()),
            encode(&parameters)
        );
        let key = format!(
            "{}&{}",
            encode(&self.consumer_secret),
            encode(&self.token_secret)
        );
        let signature = match self.algorithm {
            Algorithm::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(key.as_bytes())
                    .map_err(|_| Error::invalid("cannot initialize the OAuth 1 signing key"))?;
                mac.update(base_string.as_bytes());
                STANDARD.encode(mac.finalize().into_bytes())
            }
            Algorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
                    .map_err(|_| Error::invalid("cannot initialize the OAuth 1 signing key"))?;
                mac.update(base_string.as_bytes());
                STANDARD.encode(mac.finalize().into_bytes())
            }
        };
        Ok(signature)
    }
}

impl Algorithm {
    fn name(&self) -> &'static str {
        match self {
            Self::Sha1 => "HMAC-SHA1",
            Self::Sha256 => "HMAC-SHA256",
        }
    }
}

fn validate(request: &Request) -> Result<()> {
    if request.headers().contains_key(AUTHORIZATION)
        || request.headers().contains_key(HOST)
        || request
            .headers()
            .keys()
            .any(|name| name.as_str().starts_with("oauth_") || name.as_str().starts_with("oauth-"))
    {
        return Err(Error::invalid(
            "OAuth 1 cannot combine with explicit authentication or Host headers",
        ));
    }
    if !request.url().username().is_empty()
        || request.url().password().is_some()
        || request.url().fragment().is_some()
    {
        return Err(Error::invalid(
            "OAuth 1 cannot use URL credentials or fragments",
        ));
    }
    if request.body().is_some_and(|body| body.as_bytes().is_none()) {
        return Err(Error::Unsupported {
            feature: "OAuth 1 with a streaming request body".into(),
        });
    }
    Ok(())
}

fn request_parameters(request: &Request) -> Result<Vec<(String, String)>> {
    let mut pairs = parse_pairs(request.url().query().unwrap_or(""))?;
    let form = request
        .headers()
        .get(CONTENT_TYPE)
        .map(|value| {
            value
                .to_str()
                .map(|value| {
                    value
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .eq_ignore_ascii_case("application/x-www-form-urlencoded")
                })
                .map_err(|_| Error::invalid("invalid OAuth 1 content type"))
        })
        .transpose()?
        .unwrap_or(false);
    if form {
        let body = request
            .body()
            .and_then(|body| body.as_bytes())
            .unwrap_or(b"");
        let body = std::str::from_utf8(body)
            .map_err(|_| Error::invalid("OAuth 1 requires UTF-8 form parameters"))?;
        pairs.extend(parse_pairs(body)?);
    }
    if pairs.len() > MAX_PARAMETERS {
        return Err(Error::invalid("OAuth 1 exceeds the 10000-parameter limit"));
    }
    if pairs
        .iter()
        .any(|(key, _)| key.to_ascii_lowercase().starts_with("oauth_"))
    {
        return Err(Error::invalid(
            "OAuth 1 cannot combine with OAuth query or form parameters",
        ));
    }
    Ok(pairs)
}

fn parse_pairs(value: &str) -> Result<Vec<(String, String)>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut pairs = Vec::new();
    for pair in value.split('&') {
        if pairs.len() == MAX_PARAMETERS {
            return Err(Error::invalid("OAuth 1 exceeds the 10000-parameter limit"));
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        pairs.push((decode(key)?, decode(value)?));
    }
    Ok(pairs)
}

fn decode(value: &str) -> Result<String> {
    let value = value.replace('+', " ");
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if !bytes
                .get(index + 1..index + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
            {
                return Err(Error::invalid("invalid OAuth 1 parameter percent escape"));
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    percent_encoding::percent_decode_str(&value)
        .decode_utf8()
        .map(String::from)
        .map_err(|_| Error::invalid("OAuth 1 requires UTF-8 parameters"))
}

fn encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 15) as usize] as char);
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use reqwest::{
        Method, Url,
        blocking::{Body, Request},
        header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
    };

    use crate::{bru::Document, variables::Variables};

    use super::{Signing, decode, encode, parse_pairs};

    fn signing(source: &str) -> Signing {
        Signing::prepare(&Document::parse(source).unwrap(), &Variables::new()).unwrap()
    }

    #[test]
    fn rfc5849_fixed_form_vector_keeps_duplicates_empty_parameters_and_encoded_secrets() {
        let signing = signing(
            "auth:oauth1 {\n  consumer_key: 9djdj82h48djs9d2\n  consumer_secret: j49sk3j29djd\n  access_token: kkk9d7dh3k39sjv7\n  token_secret: dh893hdasih9\n}\n",
        );
        let mut request = Request::new(
            Method::POST,
            Url::parse("http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b").unwrap(),
        );
        request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        *request.body_mut() = Some(Body::from("c2&a3=2+q"));
        let oauth = [
            ("oauth_consumer_key", "9djdj82h48djs9d2"),
            ("oauth_token", "kkk9d7dh3k39sjv7"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", "137131201"),
            ("oauth_nonce", "7d8f3e4a"),
        ]
        .map(|(key, value)| (key.to_owned(), value.to_owned()));
        // RFC 5849 erratum 2550 corrects the published POST signature; oauth_version is omitted.
        assert_eq!(
            signing.signature(&request, &oauth).unwrap(),
            "r6/TJjbCOr97/+UU0NsvSne7s5g="
        );
    }

    #[test]
    fn rfc5849_fixed_get_vector_normalizes_the_base_uri() {
        let signing = signing(
            "auth:oauth1 {\n  consumer_key: dpf43f3p2l4k3l03\n  consumer_secret: kd94hf93k423kf44\n  access_token: nnch734d00sl2jdk\n  token_secret: pfkkdhi9sl3r4s00\n}\n",
        );
        let request = Request::new(
            Method::GET,
            Url::parse("http://PHOTOS.example.net:80/photos?file=vacation.jpg&size=original")
                .unwrap(),
        );
        let oauth = [
            ("oauth_consumer_key", "dpf43f3p2l4k3l03"),
            ("oauth_token", "nnch734d00sl2jdk"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", "137131202"),
            ("oauth_nonce", "chapoH"),
        ]
        .map(|(key, value)| (key.to_owned(), value.to_owned()));
        assert_eq!(
            signing.signature(&request, &oauth).unwrap(),
            "MdpQcU8iPSUjWoN/UDMsK2sui9I="
        );
    }

    #[test]
    fn custom_methods_are_percent_encoded_in_the_signature_base_string() {
        let signing = signing("auth:oauth1 {\n  consumer_key: key\n  consumer_secret: secret\n}\n");
        // Fixed nonce/time and independently computed HMACs exercise RFC 5849 section 3.4.1.1.
        for (method, expected) in [
            ("A&B", "UebqZRl04QBSYS0XIwo/FVHIvIM="),
            ("M!THOD", "x288ouB+i8nZ9F1ftlRSVba4Srw="),
        ] {
            let mut request = Request::new(
                Method::from_bytes(method.as_bytes()).unwrap(),
                Url::parse("http://example.com/").unwrap(),
            );
            signing.sign_at(&mut request, "nonce", "137131201").unwrap();
            assert!(
                request.headers()[AUTHORIZATION]
                    .to_str()
                    .unwrap()
                    .contains(&format!("oauth_signature=\"{}\"", encode(expected)))
            );
        }
    }

    #[test]
    fn strict_rfc_encoding_distinguishes_form_spaces_from_literal_plus() {
        assert_eq!(encode("a b+!'()*~é"), "a%20b%2B%21%27%28%29%2A~%C3%A9");
        assert_eq!(
            parse_pairs("repeat=z&repeat=a&empty&=value&plus=%2B&space=+").unwrap(),
            vec![
                ("repeat".into(), "z".into()),
                ("repeat".into(), "a".into()),
                ("empty".into(), "".into()),
                ("".into(), "value".into()),
                ("plus".into(), "+".into()),
                ("space".into(), " ".into()),
            ]
        );
        for invalid in ["%", "%Q0", "%FF", "%C3"] {
            assert!(decode(invalid).is_err());
        }
    }

    #[test]
    fn generated_nonces_are_unique_and_authentication_headers_are_sensitive() {
        let signing = signing(
            "auth:oauth1 {\n  consumer_key: key\n  consumer_secret: secret\n  signature_method: HMAC-SHA256\n  realm: a\"b\\c\n  callback_url:\n  nonce:\n  timestamp:\n  private_key:\n  include_body_hash: false\n  placement: header\n  version: 1.0\n}\n",
        );
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..16 {
            let mut request =
                Request::new(Method::GET, Url::parse("https://example.com/").unwrap());
            signing.sign(&mut request).unwrap();
            let header = &request.headers()[AUTHORIZATION];
            assert!(header.is_sensitive());
            let header = header.to_str().unwrap();
            assert!(header.starts_with("OAuth realm=\"a\\\"b\\\\c\", "));
            assert!(header.contains("oauth_signature_method=\"HMAC-SHA256\""));
            assert!(header.contains("oauth_version=\"1.0\""));
            let nonce = header
                .split("oauth_nonce=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            assert_eq!(nonce.len(), 48);
            assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(seen.insert(nonce.to_owned()));
        }
    }
}
