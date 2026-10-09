# Bruno compatibility

Quinn implements the core HTTP workflow, unary gRPC, and one-shot WebSocket requests in Rust.
It does not implement every package or feature in Bruno.
The reference commit is recorded in [NOTICE](NOTICE).

## Collection format

Quinn reads Bruno v2 `.bru` files directly.
It uses `bruno.json` to locate the collection root.
It reads `collection.bru` and each enclosing `folder.bru` for defaults.
It reads `environments/NAME.bru` for environment variables.
It excludes environments, Git directories, and `node_modules` from request discovery.
Directory discovery does not follow symbolic links.

Requests run by folder path, then numeric `meta.seq`, then file path.
This ordering is deterministic but does not reproduce Bruno's complete folder sequencing behavior.
The desktop keeps the original source until the user edits it.

Forms patch only changed fields and blocks. Untouched entries, comments, scripts,
and unknown fields retain their original source bytes.
The Source tab remains available for malformed files and non-HTTP requests.
Save and Send apply form drafts first. Invalid form edits do not replace Source.

Forms include enabled/list dictionary rows and multiline values, authentication fields,
body text, upload entries, and GraphQL variables.
Triple-quote delimiters inside multiline dictionary values require Source editing.
The forms do not provide syntax highlighting, schema validation, or protocol-specific editors.

Save validates the block structure, checks the original file contents, and replaces the file atomically.

The parser supports CRLF, a UTF-8 byte-order mark, quoted dictionary keys, disabled pairs, lists, and multiline values.
Bruno block terminators must start in column one.
Text inside body blocks can contain indented nested braces.
Inline upload annotations are supported.
Dictionary decorators are not supported.

## Variables and inheritance

`vars:pre-request` supplies static variables from the collection, folders, and request.
Inner documents override outer documents.
The selected environment overrides these static variables.
Response variables from earlier requests override the environment.
CLI `--var KEY=VALUE` and desktop overrides take highest precedence.
This precedence is Quinn's initial contract, not a claim of exact Bruno runtime parity.

Nested `{{variable}}` placeholders are supported.
Missing variables and cycles produce errors.
Response variables support the selectors listed in the assertions table.
JavaScript expressions and dynamic variables are not supported.
Bruno environment secret blocks are not supported.
Explicit overrides can supply secrets for variables in other supported blocks.

The CLI keeps response variables in memory during one run.
The desktop keeps them across requests in the same collection and environment.
Changing the collection or environment clears them.
The desktop also provides a **Reset variables** button.
Quinn does not save extracted variables to collection or environment files.

Missing extraction fields fail the request but preserve the response for inspection.
If any extraction fails, Quinn publishes no variables from that response.
Previously extracted variables remain available.
Extracted strings remain strings. Other JSON values become JSON text.
JSON reports omit the extracted-variable map, but response bodies and headers can still contain secrets.

Headers inherit from the collection and enclosing folders.
A request header overrides the inherited header with the same case-insensitive name.
A disabled header removes the inherited value.
Other disabled dictionary pairs are ignored.
Query parameters do not inherit.

Requests inherit authentication only with `auth: inherit`.
The nearest `auth { mode: ... }` block supplies the mode and credentials.
Supported modes are `none`, `basic`, `bearer`, `apikey`, and `oauth2`.
API keys support `header` and `queryparams` placement.

## OAuth 2 client credentials

Quinn supports the [client-credentials grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.4).
For example:

```bru
get {
  url: {{baseUrl}}/api
  auth: oauth2
}

auth:oauth2 {
  grant_type: client_credentials
  access_token_url: {{tokenUrl}}
  client_id: {{clientId}}
  client_secret: {{clientSecret}}
  credentials_placement: header
  scope: read write
}
```

`credentials_placement` supports `header` and `body`. The default is `body`.
The token response must contain a nonempty `access_token` and a Bearer `token_type`.
Quinn fetches a token before each API request.
It does not cache tokens or run a refresh-token flow.
The token endpoint does not follow redirects.
The configured timeout applies separately to token acquisition and the API request.
API response timing excludes token acquisition.

Only automatic token acquisition and the Authorization header are supported.
Other grants (except authorization code below), token sources, token placement, and OAuth additional-parameter blocks are rejected.

## OAuth 2 browser authorization

The CLI and desktop support the authorization-code grant through the system browser.
Quinn uses [PKCE S256](https://www.rfc-editor.org/rfc/rfc7636) and a [loopback redirect](https://www.rfc-editor.org/rfc/rfc8252#section-7.3).
Set `auth: oauth2` on the request, with this block:

```bru
auth:oauth2 {
  grant_type: authorization_code
  authorization_url: https://identity.example.com/authorize
  access_token_url: https://identity.example.com/token
  callback_url: http://127.0.0.1:8765/callback
  client_id: {{clientId}}
  scope: read write
  pkce: true
  credentials_placement: body
}
```

Register the callback URL with your identity provider before you send the request.
The callback must use `http` and a numeric loopback IP such as `127.0.0.1` or `[::1]`.
Quinn does not accept `localhost`, remote callbacks, custom URI schemes, or callback queries.
Port `0` selects a free port. The default callback is `http://127.0.0.1:0/callback`.
If your provider requires an exact redirect URI, use a fixed port.

Authorization and token URLs must use HTTPS, except for numeric loopback addresses used for local development.

Quinn generates fresh random state and a PKCE verifier for each request.
It ignores the stored Bruno `state` value and rejects `pkce: false`.
The browser URL does not include the client secret.
Public clients can omit `client_secret` with `credentials_placement: body`.
Confidential clients can supply `client_secret` and use `body` or `header`.

The local listener checks the callback path and state. It rejects duplicate state or code parameters.
The browser page does not display the code or token.
Provider denial cancels authorization. Other invalid callbacks are rejected while Quinn waits for a valid one.
The browser step times out after two minutes. Closing the browser alone does not cancel the listener.
Ctrl+C stops the CLI. The desktop has no separate authorization-cancel button.

Tokens stay in memory for the current request.
Quinn does not support token caching, refresh, custom authorization parameters, or headless device authorization.

## Uploads

`body: multipartForm` uses a `body:multipart-form` block.
It supports text fields, repeated field names, lists, and `@file(PATH)` entries.
List items become separate parts with the same field name.
Use `@file(first.txt|second.txt)` for multiple files under one field name.
An optional `@contentType(TYPE)` suffix sets the part's MIME type.
Multiline text fields can also have this suffix.

`body: file` uses a `body:file` block.
It requires exactly one enabled `file: @file(PATH)` entry.
Its default content type is `application/octet-stream`.
An optional `@contentType(TYPE)` suffix changes that default.
An explicit request header takes precedence for binary uploads.

Relative file paths resolve from the collection root.
Absolute paths and variable placeholders are supported.
Quinn streams regular files and preserves their bytes.
Disabled upload entries are ignored.
Multipart requests use a generated boundary and Content-Type header.
Custom multipart boundaries are not supported.

## Assertions

The `assert` block supports these expressions:

| Expression | Value |
| --- | --- |
| `res.status` | HTTP status code |
| `res.responseTime` | Elapsed milliseconds, including the response body |
| `res.body` | Response text |
| `res.body.FIELD` | A JSON field, with dot-separated nested fields |
| `res.body.items.0.id` | A JSON array element |
| `res.body.items[0]["user.name"]` | An array element with a quoted JSON key |
| `res.headers.NAME` | A response header, matched without case sensitivity |

Supported operators are `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `contains`, `notContains`, `exists`, `notExists`, and `isJson`.
For example:

```bru
assert {
  res.status: eq 200
  res.body.user.name: eq Quinn
  res.body.items.0.id: exists
  res.responseTime: lt 3000
}
```

Missing JSON fields fail comparisons and pass `notExists`.
Numeric indexes and double-quoted keys are supported in bracket selectors.
Legacy `$res` prefixes are also supported.
JavaScript expressions, single-quoted keys, and regex assertions are not supported.
Failed assertions and HTTP status codes of 400 or greater fail the CLI run.

## JavaScript

Quinn executes collection, folder, and request scripts with the Rust Boa engine.
Pre-request scripts run outermost first, before request interpolation.
Post-response scripts run outermost first, followed by outermost-first tests.
Each phase has a fresh JavaScript context. Runtime variables carry across phases.
`bru.setVar` updates runtime variables only, without saving files.
If extraction, a script, or a test fails, Quinn publishes no variables from the request.
Post-response errors preserve the HTTP response for inspection.
Pre-request exceptions stop the request before network IO.

Supported `bru` methods: `getVar`, `hasVar`, `setVar`, and `interpolate`.
Variable values remain strings; other values passed to `setVar` become JSON text.
Supported `req` methods: `getUrl`, `getMethod`, `getHeader`, `getHeaders`,
`getBody`, `setUrl`, `setMethod`, `setHeader`, and `setBody`.
`setBody` supports existing JSON, text, XML, and SPARQL body blocks.
Request getters see configured source values before interpolation.
Headers are case-insensitive.
Supported `res` methods: `getStatus`, `getBody`, `getHeaders`, `getHeader`,
and `getResponseTime`. Corresponding `status`, `body`, `headers`, and `responseTime`
properties are also available. JSON response bodies are parsed; other bodies remain strings.

`test(name, callback)` records synchronous callback success or failure.
The `expect` subset includes equality, deep equality, inclusion, numeric ranges,
type checks, properties, `not`, and boolean/existence predicates.
`assert`, `assert.equal`, `assert.deepEqual`, `assert.isTrue`, and `assert.isFalse`
are supported. This is not a complete Chai implementation.
Unknown APIs fail explicitly. Dynamic code generation (`eval`, `Function`), Node modules, host IO, timers, console logging,
environment mutation, persistence, and request-runner control are not provided.
Promises and asynchronous tests are unsupported; Quinn does not drain Promise jobs.

Each phase limits execution to one million VM instructions, 100,000 loop iterations,
128 recursive calls, and 16,384 VM stack entries.
Each script is limited to 64 KiB and serialized output to 1 MiB.
These limits do not form a security sandbox: built-in operations and heap allocation
are not hard bounded. Run only trusted local collection scripts.

## gRPC and WebSockets

Both protocols use collection defaults, static variables, environment/runtime variables, assertions, and response-variable extraction.
They support inherited basic or bearer authentication. Other authentication modes are rejected.
Network operations have one total request timeout, including connection setup and message exchange.
Incoming and outgoing protocol messages have a 16 MiB limit.
TLS verification stays enabled for `wss://`, `https://`, and `grpcs://`.
Custom CAs, client certificates, and insecure TLS overrides are not supported.

### Unary gRPC

```bru
grpc {
  url: grpc://127.0.0.1:50051
  method: /hello.HelloService/SayHello
  methodType: unary
  body: grpc
  auth: none
}

metadata {
  x-request-id: {{requestId}}
}

body:grpc {
  name: message 1
  content: '''
    { "greeting": "{{name}}" }
  '''
}
```

Configure individual `.proto` files in `bruno.json`:

```json
{
  "version": "1",
  "name": "My collection",
  "type": "collection",
  "protobuf": {
    "protoFiles": [{ "path": "protos/hello.proto", "type": "file" }],
    "importPaths": [{ "path": "protos", "enabled": true }]
  }
}
```

Paths resolve from the collection root. Disabled files and import paths are ignored.
Quinn parses and compiles protobuf source files with [protox](https://docs.rs/protox/latest/protox/), without an external `protoc` process.
Protobuf directory entries are not supported; list individual files.
The Quinn-specific `descriptor` field in a `grpc` block can instead specify a binary `FileDescriptorSet` with all dependencies.
Message JSON follows the [protobuf JSON mapping](https://protobuf.dev/programming-guides/json/), including base64 byte fields and string-encoded 64-bit integers.
Unknown fields, missing methods, and streaming methods are rejected before connecting.

`grpc://` and `http://` use plaintext HTTP/2. `grpcs://` and `https://` use verified TLS.
The URL must be an origin with no path, query, credentials, or fragment.
Request `metadata` and inherited `headers` become gRPC metadata.
Keys ending in `-bin` send the UTF-8 bytes of their configured value, as Bruno does.
Binary response metadata is shown as base64.
Transport headers such as `grpc-*`, `content-type`, and `te` are managed by Quinn.

A successful RPC has `res.status: 200` and response header `grpc-status: 0`.
A nonzero gRPC status has `res.status: 500`, with the original code in `grpc-status` and message in `grpc-message`.
It fails the CLI run and remains available for inspection and assertions.
Responses contain protobuf JSON. Byte counts measure the protobuf payload, not the JSON preview.
Server reflection, server/client streaming, bidirectional streams, compression, and an interactive message history are not implemented.

### One-shot WebSockets

```bru
ws {
  url: ws://127.0.0.1:8080/echo
  body: ws
  auth: none
}

body:ws {
  name: message 1
  type: json
  content: '''
    { "message": "{{message}}" }
  '''
}
```

Quinn sends a single text frame and returns the first text or binary application message.
`type` can be `text` or `json`; JSON content is validated before connecting.
With `body: none`, Quinn receives without sending.
Query parameters and inherited headers are supported. Use `Sec-WebSocket-Protocol` for a subprotocol.
Quinn manages handshake headers and does not follow redirects.
Ping/pong frames are handled while waiting for the response.
The response has status `101` and includes handshake response headers.
The `x-quinn-message-type` response header is `text` or `binary-base64`.
Binary responses use base64 rather than lossy UTF-8; byte counts measure the original message.
The connection closes after one response. Multiple outgoing messages, binary uploads, interactive sessions, and session cookies are not implemented.
JavaScript scripts and tests on protocol requests are rejected before connecting.

## Remaining port work

| Area | Current status |
| --- | --- |
| Desktop request forms, tabs, syntax highlighting | HTTP forms and Source tabs. Syntax highlighting and protocol-specific forms remain unfinished. |
| JavaScript scripts and tests | Embedded synchronous subset; Node APIs, async jobs, full Chai, and runner control remain unfinished |
| OAuth | Client credentials and browser authorization code with PKCE S256 and loopback redirects. Token caching and refresh flows remain unfinished. |
| OAuth 1, AWS SigV4, digest, NTLM, WSSE | Not implemented |
| Multipart requests and binary uploads | Streamed file uploads. Custom boundaries remain unfinished. |
| gRPC and WebSockets | Unary RPCs with local protobuf files and one-shot WebSocket text exchange. Reflection, streaming, and interactive sessions remain unfinished. |
| OpenAPI, Postman, Insomnia, and cURL import/export | Not implemented |
| Bruno YAML collections | Not implemented |
| Proxy configuration, client certificates, custom CAs | No desktop configuration. reqwest handles its default networking. |
| Bruno secret storage and integrations | Not implemented |
| Response-variable extraction and runner scripting | JSON selectors, JavaScript runtime variables, and sequential chaining; runner control remains unfinished |
| Collection/folder tests and full ordering semantics | Inherited synchronous tests and assertions; full ordering remains unfinished |
| Large downloads, streaming, binary response preview | 16 MiB text preview limit |
| Installers, signing, auto-update | CI executable artifacts only |
