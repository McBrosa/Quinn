use std::{path::PathBuf, process::ExitCode, time::Duration};

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use quinn_api::{Error, Result, collection, engine::Engine, variables::Variables};

mod reports;

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
    /// Export supported HTTP requests to a new offline JSON file.
    Export {
        #[arg(value_enum)]
        format: ExportFormat,
        /// Collection, folder, or request to export.
        path: PathBuf,
        /// New JSON file. Existing paths are never overwritten.
        destination: PathBuf,
        /// Materialize this environment. Export files can contain secrets.
        #[arg(short, long)]
        env: Option<String>,
    },
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
        /// Bruno environment name from environments/NAME.bru or NAME.yml.
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
        /// Write JSON results to a new file. Reports can contain secrets.
        #[arg(long)]
        reporter_json: Option<PathBuf>,
        /// Write one JUnit test case per attempted request to a new XML file.
        #[arg(long)]
        reporter_junit: Option<PathBuf>,
        #[command(flatten)]
        reporter_redaction: reports::Redaction,
        /// Stop after the first failed request, assertion, script, or extraction.
        #[arg(long)]
        bail: bool,
        /// Delay between requests in milliseconds. No delay precedes the first request.
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=3_600_000))]
        delay: u64,
        /// Include requests matching any tag. Repeat or separate tags with commas.
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Exclude requests matching any tag, including inherited folder tags.
        #[arg(long, value_delimiter = ',')]
        exclude_tags: Vec<String>,
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
    Insomnia,
}

#[derive(Clone, ValueEnum)]
enum ExportFormat {
    Postman,
    Openapi,
}

fn main() -> ExitCode {
    match dispatch(Args::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("quinn: {error}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: Args) -> Result<bool> {
    if !matches!(&args.command, Some(Command::Run { .. })) {
        // Native windows must be created on the operating system's main thread.
        return run(args);
    }
    // Boa's parser needs more stack than the Windows main thread provides.
    std::thread::Builder::new()
        .name("quinn-runner".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || run(args))
        .map_err(|error| Error::Invalid {
            reason: format!("cannot start collection runner: {error}"),
        })?
        .join()
        .map_err(|_| Error::Invalid {
            reason: "collection runner panicked".into(),
        })?
}

fn run(args: Args) -> Result<bool> {
    match args.command.unwrap_or_else(|| Command::Gui {
        path: None,
        network: NetworkArgs::default(),
    }) {
        Command::Export {
            format,
            path,
            destination,
            env,
        } => {
            let format = match format {
                ExportFormat::Postman => quinn_api::exporters::Format::Postman,
                ExportFormat::Openapi => quinn_api::exporters::Format::OpenApi,
            };
            let source = quinn_api::exporters::export(format, &path, env.as_deref())?;
            quinn_api::exporters::write_new(&destination, &source)?;
            println!("Exported requests into {}", destination.display());
            Ok(true)
        }
        Command::Import {
            format,
            source,
            destination,
        } => {
            let format = match format {
                ImportFormat::Postman => quinn_api::importers::Format::Postman,
                ImportFormat::Openapi => quinn_api::importers::Format::OpenApi,
                ImportFormat::Curl => quinn_api::importers::Format::Curl,
                ImportFormat::Insomnia => quinn_api::importers::Format::Insomnia,
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
            let document = collection::load(&path)?;
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
            reporter_json,
            reporter_junit,
            reporter_redaction,
            bail,
            delay,
            tags,
            exclude_tags,
            network,
        } => {
            let root = collection::root(&path)?;
            let mut entries = collection::discover(&path)?;
            if entries.is_empty() {
                return Err(Error::Invalid {
                    reason: "collection contains no request files".into(),
                });
            }
            entries.retain(|entry| collection::matches_tags(entry, &tags, &exclude_tags));
            if entries.is_empty() {
                return Err(Error::Invalid {
                    reason: "no requests match the tag filters".into(),
                });
            }
            let collect_report = json || reporter_json.is_some() || reporter_junit.is_some();
            let output_reports = reports::Reports::reserve(reporter_json, reporter_junit)?;
            let mut values = env.map_or_else(
                || Ok(Variables::new()),
                |name| collection::environment(&root, &name),
            )?;
            let overrides: Variables = variables.into_iter().collect();
            values.extend(overrides.clone());
            let options = network.into_options();
            let engine = Engine::with_network(Duration::from_secs(timeout), &options)?;
            let mut passed = true;
            let mut report = Vec::new();
            for (index, entry) in entries.into_iter().enumerate() {
                if index > 0 && delay > 0 {
                    std::thread::sleep(Duration::from_millis(delay));
                }
                let result = (|| {
                    let document = collection::load(&entry.path)?;
                    let defaults = collection::defaults(&root, &entry.path)?;
                    engine.send_in(&document, &defaults, &values, &root)
                })();
                match result {
                    Ok(response) => {
                        passed &= response.passed();
                        values.extend(response.variables.clone());
                        values.extend(overrides.clone());
                        if !json {
                            println!(
                                "{} {}  {}  {} ms  {} bytes",
                                if response.passed() { "PASS" } else { "FAIL" },
                                response.status,
                                entry.name,
                                response.elapsed_ms,
                                response.bytes
                            );
                            for assertion in &response.assertions {
                                if reporter_redaction.active() {
                                    println!(
                                        "  {} {}",
                                        if assertion.passed { "PASS" } else { "FAIL" },
                                        assertion.expression
                                    );
                                } else {
                                    println!(
                                        "  {} {}: {} (actual: {})",
                                        if assertion.passed { "PASS" } else { "FAIL" },
                                        assertion.expression,
                                        assertion.expected,
                                        assertion.actual
                                    );
                                }
                            }
                            for error in &response.variable_errors {
                                if reporter_redaction.active() {
                                    eprintln!("  FAIL post-response variable extraction failed");
                                } else {
                                    eprintln!("  FAIL {error}");
                                }
                            }
                            if !reporter_redaction.skip_response_body {
                                println!("{}\n", response.pretty_body());
                            }
                        }
                        if collect_report {
                            report.push(reports::Entry {
                                path: entry.path,
                                name: entry.name,
                                passed: response.passed(),
                                response: Some(response),
                                error: None,
                            });
                        }
                    }
                    Err(error) => {
                        passed = false;
                        if !json {
                            eprintln!("FAIL {}: {error}", entry.path.display());
                        }
                        if collect_report {
                            report.push(reports::Entry {
                                path: entry.path,
                                name: entry.name,
                                passed: false,
                                response: None,
                                error: Some(error.to_string()),
                            });
                        }
                    }
                }
                if bail && !passed {
                    break;
                }
            }
            output_reports.write(&report, &reporter_redaction)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&reporter_redaction.json(&report)?).map_err(
                        |error| Error::Invalid {
                            reason: error.to_string()
                        }
                    )?
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
