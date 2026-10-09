# Bruno compatibility

Quinn 0.2 implements the core HTTP workflow in Rust.
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
Other grants, token sources, token placement, and OAuth additional-parameter blocks are rejected.

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

## Remaining port work

| Area | Current status |
| --- | --- |
| Desktop request forms, tabs, syntax highlighting | `.bru` source editor only |
| JavaScript scripts and tests | Rejected before sending |
| OAuth | Client credentials only. Interactive authorization, token caching, and refresh flows remain unfinished. |
| OAuth 1, AWS SigV4, digest, NTLM, WSSE | Not implemented |
| Multipart requests and binary uploads | Streamed file uploads. Custom boundaries remain unfinished. |
| gRPC and WebSockets | Not implemented |
| OpenAPI, Postman, Insomnia, and cURL import/export | Not implemented |
| Bruno YAML collections | Not implemented |
| Proxy configuration, client certificates, custom CAs | No desktop configuration. reqwest handles its default networking. |
| Bruno secret storage and integrations | Not implemented |
| Response-variable extraction and runner scripting | JSON selectors and request chaining are supported. JavaScript remains unfinished. |
| Collection/folder tests and full ordering semantics | Static defaults and supported assertions only |
| Large downloads, streaming, binary response preview | 16 MiB text preview limit |
| Installers, signing, auto-update | CI executable artifacts only |
