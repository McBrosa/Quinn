use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::{
    Certificate, Identity, Proxy, Url,
    blocking::{Client, ClientBuilder},
};

use crate::{Error, Result};

/// Configure HTTP transport without changing the operating system's trust store.
#[derive(Clone)]
pub struct NetworkOptions {
    pub proxy: Option<String>,
    pub no_proxy: bool,
    pub ca_certificates: Vec<PathBuf>,
    pub client_certificate: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub max_redirects: usize,
}

impl Default for NetworkOptions {
    fn default() -> Self {
        Self {
            proxy: None,
            no_proxy: false,
            ca_certificates: Vec::new(),
            client_certificate: None,
            client_key: None,
            max_redirects: 10,
        }
    }
}

impl NetworkOptions {
    pub(crate) fn is_custom(&self) -> bool {
        self.proxy.is_some()
            || self.no_proxy
            || !self.ca_certificates.is_empty()
            || self.client_certificate.is_some()
            || self.client_key.is_some()
            || self.max_redirects != 10
    }

    pub(crate) fn prepare(&self) -> Result<PreparedNetwork> {
        if self.no_proxy && self.proxy.is_some() {
            return Err(Error::invalid("cannot combine a proxy with no_proxy"));
        }
        if self.max_redirects > 100 {
            return Err(Error::invalid("redirect limit must not exceed 100"));
        }
        let proxy = self
            .proxy
            .as_ref()
            .map(|value| {
                let url = Url::parse(value).map_err(|_| Error::invalid("invalid proxy URL"))?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || url.fragment().is_some()
                    || url.query().is_some()
                    || url.path() != "/"
                {
                    return Err(Error::invalid("proxy URL must be an http or https origin"));
                }
                Proxy::all(url).map_err(|_| Error::invalid("cannot configure the proxy"))
            })
            .transpose()?;
        let mut certificates = Vec::new();
        for path in &self.ca_certificates {
            let bytes = read_pem(path)?;
            let bundle = Certificate::from_pem_bundle(&bytes)
                .map_err(|_| Error::invalid("cannot parse the CA certificate bundle"))?;
            if bundle.is_empty() {
                return Err(Error::invalid(
                    "CA certificate bundle contains no certificates",
                ));
            }
            certificates.extend(bundle);
        }
        let identity = match (&self.client_certificate, &self.client_key) {
            (None, None) => None,
            (Some(certificate), Some(key)) => {
                let mut bytes = read_pem(certificate)?;
                bytes.push(b'\n');
                bytes.extend(read_pem(key)?);
                Some(Identity::from_pem(&bytes).map_err(|_| {
                    Error::invalid("cannot parse the client certificate and private key")
                })?)
            }
            _ => {
                return Err(Error::invalid(
                    "client certificate and private key must be supplied together",
                ));
            }
        };
        Ok(PreparedNetwork {
            proxy,
            no_proxy: self.no_proxy,
            certificates,
            identity,
        })
    }
}

pub(crate) struct PreparedNetwork {
    proxy: Option<Proxy>,
    no_proxy: bool,
    certificates: Vec<Certificate>,
    identity: Option<Identity>,
}

impl PreparedNetwork {
    pub(crate) fn builder(&self, timeout: Duration) -> ClientBuilder {
        let mut builder = Client::builder().timeout(timeout);
        if self.no_proxy {
            builder = builder.no_proxy();
        } else if let Some(proxy) = &self.proxy {
            builder = builder.no_proxy().proxy(proxy.clone());
        }
        if !self.certificates.is_empty() {
            builder = builder.tls_certs_merge(self.certificates.clone());
        }
        if let Some(identity) = &self.identity {
            builder = builder.identity(identity.clone());
        }
        builder
    }
}

fn read_pem(path: &Path) -> Result<Vec<u8>> {
    // Validate regular files before opening to avoid blocking on devices and pipes.
    if !std::fs::metadata(path)
        .map_err(|source| Error::io(path, source))?
        .is_file()
    {
        return Err(Error::invalid(
            "TLS configuration requires a regular PEM file",
        ));
    }
    let mut file = File::open(path).map_err(|source| Error::io(path, source))?;
    if !file
        .metadata()
        .map_err(|source| Error::io(path, source))?
        .is_file()
    {
        return Err(Error::invalid(
            "TLS configuration requires a regular PEM file",
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::io(path, source))?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error::invalid("PEM file exceeds the 1 MiB limit"));
    }
    Ok(bytes)
}
