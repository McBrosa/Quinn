# Quinn

Quinn is a native Rust API client with a desktop app and CLI.
It reads local Bruno `.bru` collections and sends REST and GraphQL requests.
Collections stay on your filesystem and work with Git.

This is an initial port of [Bruno](https://github.com/usebruno/bruno), not a complete replacement.
The desktop interface uses a `.bru` source editor rather than Bruno's form editors.
See [COMPATIBILITY.md](COMPATIBILITY.md) for supported features and remaining work.

## Run the desktop app

Install [Rust 1.95 or newer](https://rustup.rs/).
Then run:

```sh
cargo run --locked -- gui examples/starter
```

Open a collection directory, select a request, and select an environment.
For the example collection, select **Local**.
Edit the request source, then click **Send**.
Send uses the current editor contents, including unsaved edits.
Save writes the request to its original `.bru` file.

Use `Cmd/Ctrl+Enter` to send and `Cmd/Ctrl+S` to save.
Quinn asks before discarding unsaved edits.
If a file changes externally, Quinn refuses to overwrite it during a save.

The example requests use the public httpbin service.
Only the example payloads are sent when you run them.

On Debian or Ubuntu, install the desktop build dependencies first:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libx11-dev libxi-dev libxcursor-dev libxrandr-dev libxinerama-dev libxkbcommon-dev libwayland-dev libgl1-mesa-dev
```

## Run the CLI

```sh
# List requests without sending them.
cargo run --locked -- list examples/starter

# Run a collection with a Bruno environment.
cargo run --locked -- run examples/starter --env Local

# Run one request and override a variable.
cargo run --locked -- run examples/starter/01-get.bru \
  --env Local --var baseUrl=https://httpbin.org

# Produce a JSON report for CI.
cargo run --locked -- run examples/starter --env Local --json

# Build the CLI without desktop dependencies.
cargo install --locked --path . --no-default-features
quinn run examples/starter --env Local
```

`quinn run` returns exit code `1` for HTTP errors, failed assertions, or request errors.
It runs requests sequentially and continues after a failed request.
The default timeout is 30 seconds. Use `--timeout SECONDS` to change it.

## Supported features

- HTTP methods, custom methods, query parameters, and path parameters.
- Headers, basic authentication, bearer tokens, API keys, and OAuth 2 client credentials or browser authorization with PKCE.
- JSON, text, XML, SPARQL, form-urlencoded, GraphQL, multipart, and binary request bodies.
- Bruno environments, nested variables, collection defaults, and folder defaults.
- Status, response body, header, and response-time assertions.
- Cookies within one app session or CLI run.
- Response variables that pass tokens and IDs between requests.
- Response bodies, headers, timing, byte counts, and JSON reports.

Quinn rejects unsupported executable blocks before it sends a request.
It does not silently skip scripts or JavaScript tests.
TLS certificate verification remains enabled.
Responses have a 16 MiB limit after decompression.

## Uploads and request chains

The starter collection includes a multipart upload example.
Upload paths are relative to the collection root, including requests in nested folders.
Quinn streams file contents rather than loading the complete file into memory.

Use `vars:post-response` to extract a value for later requests:

```bru
vars:post-response {
  token: res.body.access_token
  userId: res.body.users[0].id
}
```

Then reference `{{token}}` or `{{userId}}` in the next request.
The CLI keeps these variables for the current run.
The desktop keeps them until the collection or environment changes, or you click **Reset variables**.
Explicit overrides keep highest precedence.

OAuth 2 client credentials support credentials in the token request body or Basic authentication header.
Quinn fetches a fresh token for each request and sends it as a Bearer token.
Authorization-code requests open the system browser and receive the redirect on a local loopback address.
The browser step has a two-minute timeout. Provider denial cancels the request.
See [COMPATIBILITY.md](COMPATIBILITY.md) for configuration examples and limits.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo test --locked --no-default-features
cargo build --locked --release
```

Tests use a local HTTP server and do not require internet access.
GitHub Actions runs checks on macOS, Linux, and Windows and uploads native executables.

The library contains separate modules for parsing, collection files, variables, and HTTP requests.
The CLI and desktop app share this library.
The desktop app uses [egui/eframe](https://github.com/emilk/egui).
HTTP requests use [reqwest](https://github.com/seanmonstar/reqwest).
Quinn has no Electron or Node.js dependency.

## License and attribution

Quinn uses the MIT license.
Bruno's copyright notice is preserved in [LICENSE](LICENSE).
[NOTICE](NOTICE) records the upstream reference commit and attribution.
