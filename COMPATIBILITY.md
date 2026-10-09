# Bruno compatibility

Quinn implements the core HTTP workflow, unary and finite streaming gRPC, and one-shot WebSocket requests in Rust.
It does not implement every package or feature in Bruno.
The reference commit is recorded in [NOTICE](NOTICE).

## Collection format

Quinn reads Bruno v2 `.bru` files directly.
It uses `bruno.json` to locate the collection root.
It reads `collection.bru` and each enclosing `folder.bru` for defaults.
It reads `environments/NAME.bru` for environment variables.
It excludes environments, Git directories, and `node_modules` from request discovery.
Directory discovery does not follow symbolic links.

Discovery uses Bruno's CLI folders-first traversal. Unsequenced folders start in filename order.
Positive folder sequences insert folders at their one-based positions. Equal sequences retain filename order.
Each folder runs recursively before requests in its parent directory. Requests use numeric `meta.seq`, then filename order.
Filename comparisons use Unicode lexical order, not a machine-dependent locale.

The CLI supports `--tags` and `--exclude-tags`, with comma-separated or repeated values.
Requests match any included tag. Any excluded tag overrides inclusion. Matching is case-sensitive.
`.bru` requests use `meta.tags` lists. YAML requests use `info.tags` arrays.
Tags inherit from all parent folders, nearest first, without duplicates. Collection-root tags do not inherit.
Empty tags and non-string YAML tags are ignored. Multiline YAML tags and the tag `]` return errors.
Filters preserve discovery order and run before environment, network, OAuth, or script preparation.
An empty selection returns an error. Desktop tag controls and script `req.getTags()` are not implemented.

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

## OpenCollection YAML

Quinn reads directory-based OpenCollection 1.0.0 files: `opencollection.yml`, `folder.yml`, request `.yml` files, and `environments/NAME.yml`.
If `opencollection.yml` exists, discovery ignores old `.bru` copies. Explicitly running an old copy returns an error.
The desktop opens YAML in the Source editor. Send converts supported fields in memory.
Save preserves the exact YAML source, including comments. New requests use the collection's format.
Discovery validates YAML syntax and request metadata. Save validates YAML syntax, not executable feature support.
Unsupported requests remain available for Source editing. Send, Run, and export validate the full execution model.
Atomic saves still reject external file changes. Symlink requests, metadata, and environments are not followed.

Supported YAML HTTP fields include methods, URLs, headers, query/path parameters, basic/bearer/Digest/API-key authentication, inherited defaults, and scalar variables.
Bodies include JSON, text, XML, SPARQL, URL-encoded forms, multipart text/files, and binary files.
Runtime fields include synchronous scripts/tests, assertions, and runtime-scope response-variable actions.
File-based and embedded environments support scalar variables, disabled entries, and parent inheritance through `extends`.

GraphQL supports query text, JSON-variable text, and selected body variants. The default method is POST.
gRPC supports URLs, methods, all four finite method types, `protoFilePath`, metadata, and ordered message blocks.
WebSocket requests support headers and one selected text or JSON message. They use the existing one-shot exchange.
GraphQL and WebSocket variants use the selected entry, or the first entry if none is selected. Multiple selected entries return errors.
These formats use the same protocol limits as `.bru` requests. Protocol scripts and OAuth for gRPC/WebSocket remain unsupported.

YAML OAuth2 supports client credentials and authorization code with PKCE S256, including inherited authentication and refresh configuration.
Credential placement supports `body` and `basic_auth_header`. Token placement supports only a Bearer header with the `access_token` source.
Authorization code requires an enabled `pkce` mapping. Missing OAuth settings default automatic acquisition and refresh to true, as Bruno's converter does.
Manual token acquisition, password/implicit flows, additional OAuth parameters, custom token prefixes, and query-token placement return errors.
AWS v4 authentication maps explicit credentials, region, and service. Nonempty AWS profile names return errors.

Secret storage, typed variables, inline collection `items`, and HTTP body variants are not supported yet.
Unknown executable fields return errors. Custom YAML tags, duplicate mapping keys, non-string mapping keys, and dictionary values with triple quotes also return errors.

Harmless request settings are accepted only at these values: `encodeUrl: true`, `timeout: 0` or null, `followRedirects: true`, `maxRedirects: 10`, `forwardAuthorizationHeader: false`, and empty `omitHeaders`.
The CLI's timeout and network options remain authoritative. Other request settings and embedded network configuration return errors.
Bruno's `forwardAuthorizationHeader: true` does not match Quinn's cross-origin credential protection and returns an error.
Custom ignore patterns and custom script-flow configuration also return errors.
Metadata descriptions, tags, examples, presets, and OpenAPI sync metadata do not execute.

## Variables and inheritance

`vars:pre-request` supplies static variables from the collection, folders, and request.
Inner documents override outer documents.
The selected environment overrides these static variables.
Response variables from earlier requests override the environment.
CLI `--var KEY=VALUE` and desktop overrides take highest precedence before scripts run.
HTTP pre-request scripts can replace values for the current request with `bru.setVar`.
The CLI and desktop apply explicit overrides again before the next request.
This precedence is Quinn's initial contract, not a claim of exact Bruno runtime parity.

Nested `{{variable}}` placeholders are supported.
Missing variables and cycles produce errors.
Response variables support the selectors listed in the assertions table.
JavaScript expressions in response-variable selectors and Bruno dynamic placeholders are not supported.
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
The CLI supports `--reporter-json PATH` and `--reporter-junit PATH` with new-file-only destinations.
JSON file reports match Quinn's `--json` output, not Bruno's report schema.
JUnit uses one test case per attempted request. It includes partial results after `--bail`.
Request errors produce JUnit errors. HTTP, assertion, script, and extraction failures produce JUnit failures.
JUnit omits response bodies and headers, but failure messages can contain sensitive assertion values.
HTML reports, reporter redaction flags, and separate test cases for each assertion are not implemented.

Headers inherit from the collection and enclosing folders.
A request header overrides the inherited header with the same case-insensitive name.
A disabled header removes the inherited value.
Other disabled dictionary pairs are ignored.
Query parameters do not inherit.

Requests inherit authentication only with `auth: inherit`.
The nearest `auth { mode: ... }` block supplies the mode and credentials.
Supported modes are `none`, `basic`, `bearer`, `apikey`, and `oauth2`.
API keys support `header` and `queryparams` placement.

## HTTP Digest authentication

```bru
get {
  url: https://example.com/protected
  auth: digest
}

auth:digest {
  username: {{username}}
  password: {{password}}
}
```

Digest uses Bruno's `username` and `password` fields, including variables and inherited authentication.
Native Forms provide the same fields. Quinn sends the original request without Digest credentials and handles one `401` challenge.
It sends no extra `HEAD` probe. After a supported challenge, it repeats the original method, URL, headers, and buffered body once.
Servers must authenticate requests before they perform application actions. The challenge exchange can send a body twice.

The [Digest standard](https://www.rfc-editor.org/rfc/rfc7616) defines the challenge and response calculation.
Quinn supports `MD5` and `SHA-256`, with `qop=auth` or legacy challenges without `qop`.
An offered `auth,auth-int` list selects `auth`. Quinn rejects `auth-int`-only challenges, session algorithms, unsupported algorithms, and username hashing.
Usernames and challenge header text must be ASCII. Non-ASCII passwords require the server's `charset=UTF-8` challenge parameter.
Quoted commas and escaped quotes are supported. Duplicate challenge parameters fail instead of silently replacing values.
Multiple Digest challenges and combined authentication schemes in one header are not supported.

Digest requests never follow redirects, including same-origin redirects, regardless of the session redirect limit.
The request and retry share one timeout. The retry uses the same proxy, certificate configuration, and cookie store as normal HTTP requests.
Explicit `Authorization` headers and URL credentials cannot combine with Digest authentication.
File and multipart bodies fail before network access because Quinn cannot safely clone their streamed content.
JSON, text, XML, SPARQL, GraphQL, URL-encoded forms, and requests without bodies can repeat their buffered content.
Challenge caching, stale-nonce retries, proxy Digest authentication, and `Authentication-Info` verification are not implemented.
The final response remains available for normal assertions, scripts, and response-variable extraction.
Digest does not replace TLS. Use HTTPS for real credentials.

## AWS Signature V4 authentication

HTTP requests support Bruno's `auth: awsv4` with explicit credentials:

```bru
get {
  url: https://example.execute-api.us-east-1.amazonaws.com/resource
  auth: awsv4
}
auth:awsv4 {
  accessKeyId: {{aws_access_key}}
  secretAccessKey: {{aws_secret_key}}
  sessionToken: {{aws_session_token}}
  region: us-east-1
  service: execute-api
}
```

`sessionToken` is optional. Region and service are required lowercase values.
Variables and collection/folder authentication inheritance work as with other HTTP authentication.
Quinn signs the final method, URL, query parameters, headers, and buffered body after pre-request scripts.
JSON, text, XML, SPARQL, form-urlencoded, and GraphQL bodies are supported.
The signing key and session token never appear in errors or debug output from the signer.

Quinn follows the [AWS signing procedure](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).
Query parameters use canonical encoding. Only the signing representation is sorted.
Wire order, duplicate keys, and literal URL plus signs are retained.
Spaces from request parameters use `%20`, not form-encoded plus signs.
Most services use normalized paths with double encoding of existing percent escapes.
S3 retains the transmitted path, including repeated slashes and existing percent escapes.
The payload hash header is included for S3.
S3 paths with dot segments or literal backslashes are rejected because URL parsing changes their object keys.
Query parameters must contain valid UTF-8 and percent escapes.

Explicit signing headers, URL credentials, fragments, and presigned URL parameters cannot combine with this authentication.
Signed requests never follow redirects, including same-origin redirects, regardless of `--max-redirects`.
File and multipart bodies are rejected before file or network access.
AWS profiles, ambient credentials, credential discovery, presigned URLs, SigV4a, and streaming signatures remain unsupported.
Native Forms do not yet expose AWS fields. Use Source to edit these requests.
Use HTTPS for real credentials, especially when a session token is configured.

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
Quinn caches tokens in the current Engine until `expires_in` seconds after acquisition starts.
`expires_in`, when present, must be a nonnegative JSON integer within the supported clock range.
Missing expiry or zero expiry makes the access token single-use. Quinn then refreshes or reacquires on the next send.
Cache entries are isolated by expanded endpoint, client ID and secret, scope, credential placement,
refresh configuration, authorization URL, and callback URL. Concurrent acquisitions are serialized.
Tokens and client secrets stay in memory only; no credentials are saved to disk.

Set `auto_refresh_token: true` to use the `refresh_token` grant for expired tokens with a refresh token.
The default is `false`, as in Bruno. Quinn acquires a new token instead.
An absent or empty `refresh_token_url` defaults to `access_token_url`. It follows the same URL restrictions.
Rotated refresh tokens replace the previous token; an omitted replacement retains the previous token.
An empty refresh token is rejected. Refresh uses the configured body or Basic credentials.

Refresh failure clears that cache entry and fails the send before any API request.
It never retries or replays an API request. A later explicit send acquires a new token.
API HTTP 401 responses do not trigger automatic refresh or replay.
`Engine::clear_oauth_tokens()` clears all cached credentials. Restarting the application also clears them.
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

Quinn generates fresh random state and a PKCE verifier for each browser acquisition.
It ignores the stored Bruno `state` value and rejects `pkce: false`.
The browser URL does not include the client secret.
Public clients can omit `client_secret` with `credentials_placement: body`.
Confidential clients can supply `client_secret` and use `body` or `header`.

The local listener checks the callback path and state. It rejects duplicate state or code parameters.
The browser page does not display the code or token.
Provider denial cancels authorization. Other invalid callbacks are rejected while Quinn waits for a valid one.
The browser step times out after two minutes. Closing the browser alone does not cancel the listener.
Ctrl+C stops the CLI. The desktop has no separate authorization-cancel button.

Tokens use the in-memory cache and refresh flow described above.
Quinn does not support custom authorization parameters or headless device authorization.

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
The `expect` subset includes equality, JSON deep equality, string/array/object inclusion,
numeric comparisons (`above`, `below`, `least`, `most`, `within`), `lengthOf`,
RegExp `match`, type checks, properties, `not`, and boolean/existence predicates.
Assertions support fluent chains and common comparison aliases.
Deep equality compares object fields without regard to insertion order. Array order remains significant.
Deep inclusion and property values also use structural equality.
Property checks include inherited fields unless the chain uses `own`.
`property(key, undefined)` checks the value and requires that the field exists.
`throw` supports error constructors, error instances, message strings, and RegExp patterns.
Non-JSON objects in deep comparisons, collection inclusion, nested property paths,
and other Chai extensions remain unsupported. Unsupported assertion methods fail explicitly.
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
With local descriptors, Quinn rejects unknown fields, missing methods, and incorrect `methodType` values before connecting.
The canonical request field `protoPath` can select a `.proto` file relative to the collection root.
Without enabled local files or an explicit descriptor, Quinn uses server reflection.
It requests the selected service and missing dependencies through the [standard reflection service](https://github.com/grpc/grpc-proto/blob/master/grpc/reflection/v1/reflection.proto).
It uses `v1alpha` only when the server reports `UNIMPLEMENTED`. Authentication failures do not trigger a version fallback.
Reflection uses the same TLS verification, authentication, metadata, and total request timeout as the RPC.
Reflected descriptors have limits of 1024 files and 16 MiB. An incomplete dependency graph fails the request.

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
### Finite gRPC streams

Set `methodType` to `server-streaming`, `client-streaming`, or `bidi-streaming` to match the protobuf method.
Unary and server-streaming requests require exactly one `body:grpc` block.
Client-streaming and bidirectional requests require 1 to 1024 `body:grpc` blocks.
Quinn sends those messages in file order, then closes the outgoing stream.
There is no interactive message entry after the request starts.

```bru
grpc {
  url: grpc://127.0.0.1:50051
  method: /hello.HelloService/Chat
  methodType: bidi-streaming
  body: grpc
}

body:grpc {
  name: first
  content: { "greeting": "hello" }
}

body:grpc {
  name: second
  content: { "greeting": "goodbye" }
}
```

Server-streaming and bidirectional response bodies contain a JSON array, including an empty array when no messages arrive.
Client-streaming responses contain one JSON object, like unary responses.
Assertions and response variables can select array entries, for example `res.body[0].greeting`.
Response headers include initial metadata and final trailers.
A failed stream keeps messages received before the error and exposes the nonzero `grpc-status`.
The failure prevents response-variable publication.
Request and response streams each have limits of 1024 messages and 16 MiB total protobuf and JSON data.
An exceeded limit fails the request instead of returning a truncated successful response.
The total request timeout includes reflection and the complete stream, not a separate timeout for each message.
Compression, gRPC script hooks, Unix sockets, and an interactive message history are not implemented.

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

## Offline imports

Use `quinn import FORMAT SOURCE DESTINATION` with `postman`, `openapi`, `insomnia`, or `curl`.
The source is a local UTF-8 file. The input limit is 16 MiB.
An import contains at most 10,000 requests. Postman folder nesting has a 32-level limit.
The library exposes `importers::parse` and `ImportedCollection::write_to`.

Import parses and validates all requests before creating the destination.
The destination must not exist, including an existing symlink.
Request names never become paths. Numbered, sanitized filenames prevent collisions.
Collection variables become `collection.bru` defaults. Folder variables become request variables.
Folders become name prefixes, not directories.
On a disk write error, the new destination can contain a partial collection.
Remove or rename that directory before retrying. Existing collections are never replaced.
Credentials and variable values remain plaintext.

Postman collection v2.1 supports HTTP requests, raw URLs, query/path parameters, disabled entries, and collection/folder/request variables.
Authentication supports inherited basic, Digest, bearer, API key, explicit AWS SigV4 credentials, and explicit `noauth`.
Postman AWS `accessKey` and `secretKey` map to Bruno `accessKeyId` and `secretAccessKey`.
AWS imports require explicit region and service values. Session tokens are optional. Variable placeholders remain unchanged.
Digest imports use username and password. Custom challenge parameters and disabled or duplicate credential entries are rejected.
AWS profiles, signature variants, query-auth placement, and other unsupported auth options are rejected before files are created.
Bodies support raw JSON/text/XML, form-urlencoded, text-only multipart, and GraphQL with JSON variables.
Scripts/tests, other authentication, file bodies, multipart files/content types, and protocol profile behavior are rejected.
Object/array dictionary values, string shorthand requests/headers, and other body modes are rejected.
Response examples and descriptions are not imported. Postman environments are not imported.

OpenAPI 3 JSON and YAML support operations, primitive path/query/header parameters, examples/defaults, and local JSON-pointer references.
The importer uses the first server at the operation, path, or document level.
Server variables use their defaults. Relative server URLs are rejected.
Required parameters without values become unresolved Bruno variables.
Optional parameters without values remain disabled.
Path parameters must fill a whole URL segment.
Authentication supports one basic, bearer, or header/query API-key requirement.
Alternative/combined security requirements, OAuth, cookie parameters, and structured parameter serialization are rejected.
Bodies require explicit examples or defaults. JSON content takes priority; otherwise the first content type is selected.
JSON, text, and XML examples are supported.
External references/examples, callback operations, and request bodies without examples are rejected.
Response schemas, webhooks, tags, and descriptions are not converted into request behavior.

cURL imports parse one POSIX-quoted command without a shell.
Supported options are `-X/--request`, `-H/--header`, `-d/--data`, `--data-raw`, `--data-binary`, `-u/--user`, `--url`, and `-I/--head`.
Long options accept `--option=value`. Short options need a separate value.
Literal data uses a text body and keeps cURL's default form content type unless explicitly overridden.
Repeated data values join with `&`. Basic credentials require an explicit password.
Output-only silent/error flags, `--compressed`, and `-L/--location` are accepted.
Other options, multiple URLs, interactive credentials, and `@file` input are rejected.
Shell substitutions and environment variables are not expanded.
Imported requests use Quinn's networking defaults, including cookies, redirects, and timeouts, rather than cURL's runtime defaults.
Insomnia native JSON export v4 supports exactly one workspace and one optional base environment.
Folder ancestry becomes request-name prefixes. Scalar environment variables become collection defaults.
HTTP methods, headers, query/path parameters, disabled entries, basic/bearer auth, and JSON/text/XML bodies are supported.
Form-urlencoded and text-only multipart bodies are supported.
Simple `{{ _.name }}` variables become `{{name}}`. Nested variables and template tags are rejected.
Parent cycles, missing parents, duplicate IDs, and folder nesting beyond 32 levels are rejected.
Scripts, tests, other resource types, multiple/child environments, folder variables/auth, uploads, and non-default networking settings are rejected.
Insomnia v5 YAML, GraphQL MIME bodies, cookie jars, and request descriptions are not converted.
Request sequence follows the exported resource order.
Desktop import controls remain unfinished.

## Offline exports

Use `quinn export FORMAT PATH DESTINATION [--env NAME]` with `postman` or `openapi`.
The library exposes `exporters::export` and `exporters::write_new`.
The input can be a collection, folder, or single HTTP request.
Exports contain between 1 and 10,000 requests. All requests are validated before the output file is created.
Existing files and symlinks are never overwritten.
Collection/folder headers, static variables, and inherited authentication become request-level values.
Environment values override static variables. Export files can contain plaintext secrets.
Scripts/tests, assertions, response variables, settings, protocol requests, and unknown nonempty blocks are rejected.
Embedded URL query strings must first move into `params:query`.
List-valued dictionaries, binary bodies, uploads, and multipart MIME annotations are rejected.
Documentation and response examples are not exported.

Postman collection v2.1 exports preserve variable placeholders, disabled entries, and basic/bearer/header-or-query API-key authentication.
Bodies support raw JSON/text/XML, GraphQL, form-urlencoded, and text-only multipart.
Folder hierarchy becomes flat request names. OAuth and SPARQL bodies are rejected.

OpenAPI 3.0.3 exports materialize all variables and produce primitive parameter examples.
Operations contain absolute per-operation server URLs and a generic response description.
Raw JSON, XML, and text bodies become explicit examples. JSON body formatting can change on reimport.
Authentication credentials are rejected; use Postman export for authenticated requests.
Explicit Accept/Authorization headers and bodyless Content-Type headers are rejected because OpenAPI ignores these parameter definitions.
Form, multipart, GraphQL, duplicate parameters, and duplicate path/method operations are rejected.
Path parameters must fill a whole URL segment. Disabled entries are omitted from OpenAPI examples.
Response schemas and API contracts are not inferred from request samples.

## Remaining port work

HTTP and OAuth token transports accept explicit session-level proxy, CA-bundle, client-certificate, and redirect configuration.
Use the CLI flags documented in the README, including when launching the desktop app.
Explicit proxies replace system proxies. `--no-proxy` disables system and environment proxies.
CA bundles supplement system trust. TLS verification remains enabled.
Certificate chains and unencrypted client keys use PEM files, with a 1 MiB limit per file.
The API redirect limit defaults to ten. Zero disables redirects. OAuth token endpoints never redirect.
Custom configuration for gRPC and WebSockets, per-host certificates, and desktop configuration controls remain unfinished.

| Area | Current status |
| --- | --- |
| Desktop request forms, tabs, syntax highlighting | HTTP forms and Source tabs. Syntax highlighting and protocol-specific forms remain unfinished. |
| JavaScript scripts and tests | Embedded synchronous subset; Node APIs, async jobs, full Chai, and runner control remain unfinished |
| OAuth | Client credentials and browser authorization code with PKCE S256 and loopback redirects. In-memory expiry-aware token caching and refresh-token rotation. No persistent token store or automatic API replay. |
| HTTP Digest | MD5/SHA-256 auth or no-qop challenges, one buffered-body retry, no redirects. File/multipart replay and extended algorithms remain unsupported. |
| AWS SigV4 | Explicit-credential HTTP signing with buffered bodies; no profiles, presigned URLs, streaming signatures, or native forms. |
| OAuth 1, NTLM, WSSE | Not implemented |
| Multipart requests and binary uploads | Streamed file uploads. Custom boundaries remain unfinished. |
| gRPC and WebSockets | Unary and finite streaming RPCs with local protobuf files or server reflection, plus one-shot WebSocket exchange. Interactive sessions remain unfinished. |
| OpenAPI, Postman, Insomnia, and cURL import/export | Offline Postman v2.1, OpenAPI 3 JSON/YAML, Insomnia v4 JSON, and cURL imports. Supported HTTP subsets export to Postman v2.1 and OpenAPI 3 JSON. |
| Bruno YAML collections | OpenCollection 1.0.0 HTTP, GraphQL, finite gRPC, and one-shot WebSocket subsets. OAuth2 and explicit AWS v4 map to existing engines. Secret storage and typed variables remain unfinished. |
| Proxy configuration, client certificates, custom CAs | HTTP/OAuth session configuration through CLI or library. Protocol configuration and desktop controls remain unfinished. |
| Bruno secret storage and integrations | Not implemented |
| Response-variable extraction and runner scripting | JSON selectors, JavaScript runtime variables, and sequential chaining; runner control remains unfinished |
| Collection/folder tests and full ordering semantics | Inherited synchronous tests and assertions; full ordering remains unfinished |
| Large downloads, streaming, binary response preview | 16 MiB text preview limit |
| Installers, signing, auto-update | CI executable artifacts only |
