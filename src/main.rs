use std::{path::PathBuf, process::ExitCode, time::Duration};

use clap::{Parser, Subcommand};
use quinn_api::{Error, Result, bru::Document, collection, engine::Engine, variables::Variables};

#[cfg(feature = "desktop")]
mod desktop;

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
    /// Open the native desktop client.
    Gui {
        /// Collection directory to open.
        path: Option<PathBuf>,
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
    },
    /// List requests without sending them.
    List {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Parse a request and show its blocks without sending it.
    Inspect { path: PathBuf },
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
    match args.command.unwrap_or(Command::Gui { path: None }) {
        Command::Gui { path } => {
            #[cfg(feature = "desktop")]
            desktop::open(path).map_err(|reason| Error::Invalid { reason })?;
            #[cfg(not(feature = "desktop"))]
            {
                let _ = path;
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
        } => {
            let root = collection::root(&path)?;
            let mut values = env.map_or_else(
                || Ok(Variables::new()),
                |name| collection::environment(&root, &name),
            )?;
            values.extend(variables);
            let entries = collection::discover(&path)?;
            if entries.is_empty() {
                return Err(Error::Invalid {
                    reason: "collection contains no request files".into(),
                });
            }
            let engine = Engine::new(Duration::from_secs(timeout))?;
            let mut passed = true;
            let mut report = Vec::new();
            for entry in entries {
                let result = (|| {
                    let document = Document::parse(&collection::read(&entry.path)?)?;
                    let defaults = collection::defaults(&root, &entry.path)?;
                    engine.send(&document, &defaults, &values)
                })();
                match result {
                    Ok(response) => {
                        passed &= response.passed();
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
