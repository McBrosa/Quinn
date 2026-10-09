# Bruno compatibility

Quinn 0.1 implements the core HTTP workflow in Rust.
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
Dictionary annotations are not supported.

## Variables and inheritance

`vars:pre-request` supplies static variables from the collection, folders, and request.
Inner documents override outer documents.
The selected environment overrides these static variables.
CLI `--var KEY=VALUE` and desktop overrides take highest precedence.
This precedence is Quinn's initial contract, not a claim of exact Bruno runtime parity.

Nested `{{variable}}` placeholders are supported.
Missing variables and cycles produce errors.
Runtime variables, dynamic variables, JavaScript expressions, and post-response variables are not supported.
Environment secret blocks require explicit overrides instead of Bruno's secret storage.

Headers inherit from the collection and enclosing folders.
A request header overrides the inherited header with the same case-insensitive name.
A disabled header removes the inherited value.
Other disabled dictionary pairs are ignored.
Query parameters do not inherit.

Requests inherit authentication only with `auth: inherit`.
The nearest `auth { mode: ... }` block supplies the mode and credentials.
Supported modes are `none`, `basic`, `bearer`, and `apikey`.
API keys support `header` and `queryparams` placement.

## Assertions

The `assert` block supports these expressions:

| Expression | Value |
| --- | --- |
| `res.status` | HTTP status code |
| `res.responseTime` | Elapsed milliseconds, including the response body |
| `res.body` | Response text |
| `res.body.FIELD` | A JSON field, with dot-separated nested fields |
| `res.body.items.0.id` | A JSON array element |
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
JavaScript selectors, bracket selectors, regex assertions, and legacy `$res` expressions are not supported.
Failed assertions and HTTP status codes of 400 or greater fail the CLI run.

## Remaining port work

| Area | Current status |
| --- | --- |
| Desktop request forms, tabs, syntax highlighting | `.bru` source editor only |
| JavaScript scripts and tests | Rejected before sending |
| OAuth 1/2, AWS SigV4, digest, NTLM, WSSE | Not implemented |
| Multipart requests and binary uploads | Not implemented |
| gRPC and WebSockets | Not implemented |
| OpenAPI, Postman, Insomnia, and cURL import/export | Not implemented |
| Bruno YAML collections | Not implemented |
| Proxy configuration, client certificates, custom CAs | No desktop configuration. reqwest handles its default networking. |
| Bruno secret storage and integrations | Not implemented |
| Response-variable extraction and runner scripting | Not implemented |
| Collection/folder tests and full ordering semantics | Static defaults and supported assertions only |
| Large downloads, streaming, binary response preview | 16 MiB text preview limit |
| Installers, signing, auto-update | CI executable artifacts only |
