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

    pub fn write(self, entries: &[Entry]) -> Result<()> {
        if let Some((path, mut file)) = self.json {
            let source = serde_json::to_vec_pretty(entries).map_err(|error| Error::Invalid {
                reason: format!("cannot serialize JSON report: {error}"),
            })?;
            file.write_all(&source)
                .map_err(|source| Error::Io { path, source })?;
        }
        if let Some((path, mut file)) = self.junit {
            file.write_all(junit(entries).as_bytes())
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

fn junit(entries: &[Entry]) -> String {
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
                        messages.push(format!(
                            "{}: expected {}; actual {}",
                            assertion.expression, assertion.expected, assertion.actual
                        ));
                    }
                    messages.extend(response.variable_errors.iter().cloned());
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
    use super::*;

    #[test]
    fn xml_escapes_attributes_and_replaces_forbidden_characters() {
        assert_eq!(
            escape("<&>\"'\n\0\u{ffff}東京"),
            "&lt;&amp;&gt;&quot;&apos;&#10;��東京"
        );
        let xml = junit(&[Entry {
            path: "one<&>.bru".into(),
            name: "Test \"one\"".into(),
            passed: false,
            response: None,
            error: Some("failed\n<&>".into()),
        }]);
        assert!(xml.contains("tests=\"1\" failures=\"0\" errors=\"1\""));
        assert!(xml.contains("<error message=\"failed&#10;&lt;&amp;&gt;\"/>"));
        assert!(xml.contains("classname=\"one&lt;&amp;&gt;.bru\""));
    }
}
