use std::{fs::File, io::Write, path::PathBuf};

use quinn_api::{Error, Result, engine::Response};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Entry {
    pub path: PathBuf,
    pub name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(clap::Args, Default)]
pub(crate) struct Redaction {
    /// Omit all response headers from reports.
    #[arg(long = "reporter-skip-all-headers")]
    pub skip_all_headers: bool,
    /// Omit named response headers. Repeat or separate names with commas.
    #[arg(long = "reporter-skip-headers", value_delimiter = ',')]
    pub skip_headers: Vec<String>,
    /// Omit response bodies from reports and console output.
    #[arg(long = "reporter-skip-response-body", alias = "reporter-skip-body")]
    pub skip_response_body: bool,
}

impl Redaction {
    pub fn active(&self) -> bool {
        self.skip_all_headers || !self.skip_headers.is_empty() || self.skip_response_body
    }

    pub fn json(&self, entries: &[Entry]) -> Result<serde_json::Value> {
        let mut output = serde_json::to_value(entries).map_err(|error| Error::Invalid {
            reason: format!("cannot serialize JSON report: {error}"),
        })?;
        if let Some(entries) = output.as_array_mut() {
            for entry in entries {
                let Some(response) = entry
                    .get_mut("response")
                    .and_then(serde_json::Value::as_object_mut)
                else {
                    continue;
                };
                if let Some(headers) = response
                    .get_mut("headers")
                    .and_then(serde_json::Value::as_object_mut)
                {
                    headers.retain(|key, _| {
                        !self.skip_all_headers
                            && !self
                                .skip_headers
                                .iter()
                                .any(|name| name.eq_ignore_ascii_case(key))
                    });
                }
                if self.skip_response_body {
                    response.remove("body");
                }
                if self.active() {
                    if let Some(assertions) = response
                        .get_mut("assertions")
                        .and_then(serde_json::Value::as_array_mut)
                    {
                        for assertion in assertions {
                            if let Some(assertion) = assertion.as_object_mut() {
                                assertion.remove("expected");
                                assertion.remove("actual");
                            }
                        }
                    }
                    if let Some(errors) = response
                        .get_mut("variable_errors")
                        .and_then(serde_json::Value::as_array_mut)
                    {
                        for error in errors {
                            *error = serde_json::Value::String(
                                "post-response variable extraction failed".into(),
                            );
                        }
                    }
                }
            }
        }
        Ok(output)
    }
}

pub(crate) struct Reports {
    json: Option<(PathBuf, File)>,
    junit: Option<(PathBuf, File)>,
}

impl Reports {
    pub fn reserve(json: Option<PathBuf>, junit: Option<PathBuf>) -> Result<Self> {
        if json.is_some() && json == junit {
            return Err(Error::Invalid {
                reason: "JSON and JUnit reports require distinct destinations".into(),
            });
        }
        for path in [&json, &junit].into_iter().flatten() {
            match std::fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(Error::Invalid {
                        reason: format!("report destination already exists: {}", path.display()),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(Error::Io {
                        path: path.clone(),
                        source,
                    });
                }
            }
        }
        Ok(Self {
            json: json.map(reserve).transpose()?,
            junit: junit.map(reserve).transpose()?,
        })
    }

    pub fn write(self, entries: &[Entry], redaction: &Redaction) -> Result<()> {
        if let Some((path, mut file)) = self.json {
            let source = serde_json::to_vec_pretty(&redaction.json(entries)?).map_err(|error| {
                Error::Invalid {
                    reason: format!("cannot serialize JSON report: {error}"),
                }
            })?;
            file.write_all(&source)
                .map_err(|source| Error::Io { path, source })?;
        }
        if let Some((path, mut file)) = self.junit {
            file.write_all(junit(entries, redaction).as_bytes())
                .map_err(|source| Error::Io { path, source })?;
        }
        Ok(())
    }
}

fn reserve(path: PathBuf) -> Result<(PathBuf, File)> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    Ok((path, file))
}

fn junit(entries: &[Entry], redaction: &Redaction) -> String {
    let errors = entries.iter().filter(|entry| entry.error.is_some()).count();
    let failures = entries
        .iter()
        .filter(|entry| !entry.passed && entry.error.is_none())
        .count();
    let milliseconds: u128 = entries
        .iter()
        .filter_map(|entry| entry.response.as_ref())
        .map(|response| response.elapsed_ms)
        .sum();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites><testsuite name=\"Quinn\" tests=\"{}\" failures=\"{failures}\" errors=\"{errors}\" time=\"{:.3}\">\n",
        entries.len(),
        milliseconds as f64 / 1000.0,
    );
    for entry in entries {
        let time = entry
            .response
            .as_ref()
            .map_or(0, |response| response.elapsed_ms);
        xml.push_str(&format!(
            "  <testcase name=\"{}\" classname=\"{}\" time=\"{:.3}\">",
            escape(&entry.name),
            escape(&entry.path.to_string_lossy()),
            time as f64 / 1000.0,
        ));
        if let Some(error) = &entry.error {
            xml.push_str(&format!("<error message=\"{}\"/>", escape(error)));
        } else if !entry.passed {
            let message = entry.response.as_ref().map_or_else(
                || "request failed".to_owned(),
                |response| {
                    let mut messages = Vec::new();
                    if response.status >= 400 {
                        messages.push(format!("HTTP status {}", response.status));
                    }
                    for assertion in response
                        .assertions
                        .iter()
                        .filter(|assertion| !assertion.passed)
                    {
                        if redaction.active() {
                            messages.push(format!("{}: assertion failed", assertion.expression));
                        } else {
                            messages.push(format!(
                                "{}: expected {}; actual {}",
                                assertion.expression, assertion.expected, assertion.actual
                            ));
                        }
                    }
                    if redaction.active() && !response.variable_errors.is_empty() {
                        messages.push("post-response variable extraction failed".into());
                    } else {
                        messages.extend(response.variable_errors.iter().cloned());
                    }
                    messages.join("; ")
                },
            );
            xml.push_str(&format!("<failure message=\"{}\"/>", escape(&message)));
        }
        xml.push_str("</testcase>\n");
    }
    xml.push_str("</testsuite></testsuites>\n");
    xml
}

fn escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            '\t' | '\n' | '\r' => output.push_str(&format!("&#{};", character as u32)),
            '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}' => {
                output.push(character)
            }
            _ => output.push('\u{fffd}'),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn xml_escapes_attributes_and_replaces_forbidden_characters() {
        assert_eq!(
            escape("<&>\"'\n\0\u{ffff}東京"),
            "&lt;&amp;&gt;&quot;&apos;&#10;��東京"
        );
        let xml = junit(
            &[Entry {
                path: "one<&>.bru".into(),
                name: "Test \"one\"".into(),
                passed: false,
                response: None,
                error: Some("failed\n<&>".into()),
            }],
            &Redaction::default(),
        );
        assert!(xml.contains("tests=\"1\" failures=\"0\" errors=\"1\""));
        assert!(xml.contains("<error message=\"failed&#10;&lt;&amp;&gt;\"/>"));
        assert!(xml.contains("classname=\"one&lt;&amp;&gt;.bru\""));
    }

    #[test]
    fn redaction_omits_payloads_and_diagnostics_without_mutating_runtime_response() {
        let entries = [Entry {
            path: "test.bru".into(),
            name: "redaction".into(),
            passed: false,
            error: None,
            response: Some(Response {
                status: 200,
                headers: std::collections::BTreeMap::from([
                    ("x-secret".into(), "HEADER_SECRET".into()),
                    ("x-visible".into(), "public".into()),
                ]),
                body: "BODY_SECRET".into(),
                bytes: 11,
                elapsed_ms: 1,
                assertions: vec![quinn_api::engine::Assertion {
                    expression: "res.body".into(),
                    expected: "BODY_SECRET".into(),
                    actual: "HEADER_SECRET".into(),
                    passed: false,
                }],
                variables: quinn_api::variables::Variables::from([(
                    "token".into(),
                    "RUNTIME_SECRET".into(),
                )]),
                variable_errors: vec!["BODY_SECRET".into()],
            }),
        }];
        let policy = Redaction {
            skip_all_headers: true,
            skip_headers: Vec::new(),
            skip_response_body: true,
        };
        let output = policy.json(&entries).unwrap();
        let serialized = serde_json::to_string(&output).unwrap();
        for secret in ["HEADER_SECRET", "BODY_SECRET", "RUNTIME_SECRET"] {
            assert!(!serialized.contains(secret));
            assert!(!junit(&entries, &policy).contains(secret));
        }
        assert!(output[0]["response"].get("body").is_none());
        assert_eq!(output[0]["response"]["headers"], serde_json::json!({}));
        assert_eq!(entries[0].response.as_ref().unwrap().body, "BODY_SECRET");
        let unredacted = Redaction::default().json(&entries).unwrap();
        assert_eq!(
            unredacted[0]["response"]["assertions"][0]["actual"],
            "HEADER_SECRET"
        );
        let selected = Redaction {
            skip_all_headers: false,
            skip_headers: vec!["X-SeCrEt".into()],
            skip_response_body: false,
        }
        .json(&entries)
        .unwrap();
        assert!(selected[0]["response"]["headers"].get("x-secret").is_none());
        assert_eq!(selected[0]["response"]["headers"]["x-visible"], "public");
        assert_eq!(selected[0]["response"]["body"], "BODY_SECRET");
    }
}
