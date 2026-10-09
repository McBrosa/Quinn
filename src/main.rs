use std::{path::PathBuf, process::ExitCode, time::Duration};

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use quinn_api::{Error, Result, bru::Document, collection, engine::Engine, variables::Variables};

#[cfg(feature = "desktop")]
mod desktop;
#[cfg(feature = "desktop")]
mod request_form;

#[derive(Parser)]
#[command(
    name = "quinn",
    version,
    about = "A Rust API client for Bruno collections"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Import an offline export into a new Bruno collection directory.
    Import {
        #[arg(value_enum)]
        format: ImportFormat,
        /// Export file, or a text file containing one curl command.
        source: PathBuf,
        /// New directory. Existing paths are never overwritten.
        destination: PathBuf,
    },
    /// Open the native desktop client.
    Gui {
        /// Collection directory to open.
        path: Option<PathBuf>,
        #[command(flatten)]
        network: NetworkArgs,
    },
    /// Run a request, folder, or entire collection.
    Run {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Bruno environment name from environments/NAME.bru.
        #[arg(short, long)]
        env: Option<String>,
        /// Override an environment variable. Repeat for multiple variables.
        #[arg(long = "var", value_parser = parse_variable)]
        variables: Vec<(String, String)>,
        /// Request timeout in seconds.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        timeout: u64,
        /// Write a JSON report to stdout.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        network: NetworkArgs,
    },
    /// List requests without sending them.
    List {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Parse a request and show its blocks without sending it.
    Inspect { path: PathBuf },
}

#[derive(ClapArgs)]
struct NetworkArgs {
    /// HTTP/HTTPS proxy URL. Credentials in command arguments can be visible to other users.
    #[arg(long, conflicts_with = "no_proxy")]
    proxy: Option<String>,
    /// Disable system and environment HTTP proxies.
    #[arg(long)]
    no_proxy: bool,
    /// PEM CA bundle. Repeat to trust multiple bundles for this run only.
    #[arg(long = "cacert")]
    ca_certificates: Vec<PathBuf>,
    /// PEM client certificate chain for mutual TLS.
    #[arg(long, requires = "client_key")]
    client_cert: Option<PathBuf>,
    /// PEM client private key. Encrypted keys are not supported.
    #[arg(long, requires = "client_cert")]
    client_key: Option<PathBuf>,
    /// HTTP redirect limit; zero disables redirects. Token endpoints never redirect.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(0..=100))]
    max_redirects: u64,
}

impl Default for NetworkArgs {
    fn default() -> Self {
        Self {
            proxy: None,
            no_proxy: false,
            ca_certificates: Vec::new(),
            client_cert: None,
            client_key: None,
            max_redirects: 10,
        }
    }
}

impl NetworkArgs {
    fn into_options(self) -> quinn_api::network::NetworkOptions {
        quinn_api::network::NetworkOptions {
            proxy: self.proxy,
            no_proxy: self.no_proxy,
            ca_certificates: self.ca_certificates,
            client_certificate: self.client_cert,
            client_key: self.client_key,
            max_redirects: self.max_redirects as usize,
        }
    }
}

#[derive(Clone, ValueEnum)]
enum ImportFormat {
    Postman,
    Openapi,
    Curl,
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("quinn: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<bool> {
    match args.command.unwrap_or_else(|| Command::Gui {
        path: None,
        network: NetworkArgs::default(),
    }) {
        Command::Import {
            format,
            source,
            destination,
        } => {
            let format = match format {
                ImportFormat::Postman => quinn_api::importers::Format::Postman,
                ImportFormat::Openapi => quinn_api::importers::Format::OpenApi,
                ImportFormat::Curl => quinn_api::importers::Format::Curl,
            };
            let imported = quinn_api::importers::parse(format, &collection::read(&source)?)?;
            imported.write_to(&destination)?;
            println!(
                "Imported {} requests into {}",
                imported.requests.len(),
                destination.display()
            );
            Ok(true)
        }
        Command::Gui { path, network } => {
            #[cfg(feature = "desktop")]
            {
                let engine =
                    Engine::with_network(Duration::from_secs(30), &network.into_options())?;
                desktop::open(path, engine).map_err(|reason| Error::Invalid { reason })?;
            }
            #[cfg(not(feature = "desktop"))]
            {
                let _ = (path, network);
                Err(Error::Unsupported {
                    feature: "desktop; build with the default features or use 'quinn run'".into(),
                })
            }
            #[cfg(feature = "desktop")]
            Ok(true)
        }
        Command::List { path } => {
            for entry in collection::discover(&path)? {
                println!("{}\t{}", entry.path.display(), entry.name);
            }
            Ok(true)
        }
        Command::Inspect { path } => {
            let document = Document::parse(&collection::read(&path)?)?;
            for block in document.blocks {
                println!("{} (line {})", block.name, block.line);
            }
            Ok(true)
        }
        Command::Run {
            path,
            env,
            variables,
            timeout,
            json,
            network,
        } => {
            let root = collection::root(&path)?;
            let mut values = env.map_or_else(
                || Ok(Variables::new()),
                |name| collection::environment(&root, &name),
            )?;
            let overrides: Variables = variables.into_iter().collect();
            values.extend(overrides.clone());
            let entries = collection::discover(&path)?;
            if entries.is_empty() {
                return Err(Error::Invalid {
                    reason: "collection contains no request files".into(),
                });
            }
            let options = network.into_options();
            let engine = Engine::with_network(Duration::from_secs(timeout), &options)?;
            let mut passed = true;
            let mut report = Vec::new();
            for entry in entries {
                let result = (|| {
                    let document = Document::parse(&collection::read(&entry.path)?)?;
                    let defaults = collection::defaults(&root, &entry.path)?;
                    engine.send_in(&document, &defaults, &values, &root)
                })();
                match result {
                    Ok(response) => {
                        passed &= response.passed();
                        values.extend(response.variables.clone());
                        values.extend(overrides.clone());
                        if json {
                            report.push(serde_json::json!({"path": entry.path, "name": entry.name, "passed": response.passed(), "response": response}));
                        } else {
                            println!(
                                "{} {}  {}  {} ms  {} bytes",
                                if response.passed() { "PASS" } else { "FAIL" },
                                response.status,
                                entry.name,
                                response.elapsed_ms,
                                response.bytes
                            );
                            for assertion in &response.assertions {
                                println!(
                                    "  {} {}: {} (actual: {})",
                                    if assertion.passed { "PASS" } else { "FAIL" },
                                    assertion.expression,
                                    assertion.expected,
                                    assertion.actual
                                );
                            }
                            for error in &response.variable_errors {
                                eprintln!("  FAIL {error}");
                            }
                            println!("{}\n", response.pretty_body());
                        }
                    }
                    Err(error) => {
                        passed = false;
                        if json {
                            report.push(serde_json::json!({"path": entry.path, "name": entry.name, "passed": false, "error": error.to_string()}));
                        } else {
                            eprintln!("FAIL {}: {error}", entry.path.display());
                        }
                    }
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|error| Error::Invalid {
                        reason: error.to_string()
                    })?
                );
            }
            Ok(passed)
        }
    }
}

fn parse_variable(input: &str) -> std::result::Result<(String, String), String> {
    let (key, value) = input
        .split_once('=')
        .ok_or_else(|| "use KEY=VALUE".to_owned())?;
    if key.trim().is_empty() {
        return Err("variable name is empty".into());
    }
    Ok((key.trim().to_owned(), value.to_owned()))
}
