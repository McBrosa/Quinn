use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot read or write {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse .bru line {line}: {reason}")]
    Parse { line: usize, reason: String },
    #[error("cannot run this request: {reason}")]
    Invalid { reason: String },
    #[error("cannot run unsupported feature: {feature}")]
    Unsupported { feature: String },
    #[error("cannot resolve variable '{name}'")]
    Variable { name: String },
    #[error("cannot send HTTP request: {reason}")]
    Http { reason: String },
}

impl Error {
    pub(crate) fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid {
            reason: reason.into(),
        }
    }

    pub(crate) fn http(source: reqwest::Error) -> Self {
        Self::Http {
            reason: source.to_string(),
        }
    }

    pub(crate) fn io(path: &std::path::Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }
}
