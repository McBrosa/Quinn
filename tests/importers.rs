#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use quinn_api::{
    bru::Document,
    collection,
    engine::Engine,
    importers::{Format, parse},
    network::NetworkOptions,
    variables::Variables,
};
use reqwest::Url;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::Sha256;

fn postman(item: Value) -> String {
    json!({
        "info": { "name": "Test", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
        "item": [item]
    }).to_string()
}

#[test]
fn postman_inherits_auth_and_variables_and_keeps_disabled_entries() {
    let input = json!({
        "info": {"name":"API", "schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "variable":[{"key":"baseUrl","value":"https://example.test"}],
        "auth":{"type":"bearer","bearer":[{"key":"token","value":"{{token}}"}]},
        "item":[{
            "name":"Folder", "variable":[{"key":"token","value":"secret"}],
            "item":[{"name":"Get", "request":{
                "method":"GET", "url":{"raw":"{{baseUrl}}/users/:id?old=value",
                    "query":[{"key":"a","value":"one"},{"key":"a","value":"two"},{"key":"skip","value":"bad","disabled":true}],
                    "variable":[{"key":"id","value":42}]},
                "header":[{"key":"X-Custom","value":"yes"},{"key":"X-Off","value":"no","disabled":true}]
            }}]
        }]
    });
    let imported = parse(Format::Postman, &input.to_string()).unwrap();
    assert_eq!(imported.variables["baseUrl"], "https://example.test");
    let document = Document::parse(&imported.requests[0].source).unwrap();
    assert_eq!(
        document.value("get", "url").unwrap().unwrap(),
        "{{baseUrl}}/users/:id"
    );
    assert_eq!(document.value("get", "auth").unwrap().unwrap(), "bearer");
    assert_eq!(
        document
            .value("vars:pre-request", "token")
            .unwrap()
            .unwrap(),
        "secret"
    );
    assert_eq!(document.pairs("params:query").unwrap().len(), 3);
    assert!(!document.pairs("headers").unwrap()[1].enabled);
    assert_eq!(document.value("params:path", "id").unwrap().unwrap(), "42");
}

#[test]
fn postman_noauth_overrides_collection_auth() {
    let input = json!({
        "info":{"name":"API","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "auth":{"type":"basic","basic":[{"key":"username","value":"u"},{"key":"password","value":"p"}]},
        "item":[{"name":"Get","request":{"method":"GET","url":"https://example.test","auth":{"type":"noauth"}}}]
    });
    let imported = parse(Format::Postman, &input.to_string()).unwrap();
    let document = Document::parse(&imported.requests[0].source).unwrap();
    assert_eq!(document.value("get", "auth").unwrap().unwrap(), "none");
    assert!(document.block("auth:basic").is_none());
}

fn oauth1() -> Value {
    json!({"type":"oauth1","oauth1":[
        {"key":"consumerKey","value":"{{consumer}}","type":"string"},
        {"key":"consumerSecret","value":"consumer/+ é","type":"string"},
        {"key":"token","value":"access/token","type":"string"},
        {"key":"tokenSecret","value":"token&secret","type":"string"}
    ]})
}

#[test]
fn postman_oauth1_maps_canonical_fields_preserving_placeholders_and_defaults() {
    let mut auth = oauth1();
    auth["oauth1"].as_array_mut().unwrap().extend([
        json!({"key":"signatureMethod","value":"HMAC-SHA256"}),
        json!({"key":"version","value":"1.0"}),
        json!({"key":"realm","value":"Example"}),
        json!({"key":"addParamsToHeader","value":true,"type":"boolean"}),
        json!({"key":"includeBodyHash","value":false,"type":"boolean"}),
        json!({"key":"disableHeaderEncoding","value":false,"type":"boolean"}),
    ]);
    for field in ["callback", "verifier", "nonce", "timestamp", "privateKey"] {
        auth["oauth1"]
            .as_array_mut()
            .unwrap()
            .push(json!({"key":field,"value":""}));
    }
    for (auth, expected) in [
        (auth, Some("HMAC-SHA256")),
        (oauth1(), None),
        (
            json!({"type":"oauth1","oauth1":[
                {"key":"consumerKey","value":"{{consumer}}"},
                {"key":"consumerSecret","value":"consumer/+ é"}
            ]}),
            None,
        ),
    ] {
        let input = postman(json!({"name":"Auth","request":{
            "method":"GET","url":"https://example.test","auth":auth
        }}));
        let imported = parse(Format::Postman, &input).unwrap();
        let document = Document::parse(&imported.requests[0].source).unwrap();
        assert_eq!(
            document.value("get", "auth").unwrap().as_deref(),
            Some("oauth1")
        );
        assert_eq!(
            document
                .value("auth:oauth1", "consumer_key")
                .unwrap()
                .as_deref(),
            Some("{{consumer}}")
        );
        assert_eq!(
            document
                .value("auth:oauth1", "consumer_secret")
                .unwrap()
                .as_deref(),
            Some("consumer/+ é")
        );
        assert_eq!(
            document
                .value("auth:oauth1", "signature_method")
                .unwrap()
                .as_deref(),
            expected
        );
        assert!(
            document
                .value("auth:oauth1", "consumerKey")
                .unwrap()
                .is_none()
        );
        if expected.is_some() {
            for (key, value) in [
                ("access_token", "access/token"),
                ("token_secret", "token&secret"),
                ("realm", "Example"),
                ("version", "1.0"),
                ("callback_url", ""),
            ] {
                assert_eq!(
                    document.value("auth:oauth1", key).unwrap().as_deref(),
                    Some(value)
                );
            }
        }
    }
}

#[test]
fn postman_oauth1_preserves_collection_folder_and_request_auth_inheritance() {
    let mut folder_auth = oauth1();
    folder_auth["oauth1"][0]["value"] = json!("folder-key");
    let mut own_auth = oauth1();
    own_auth["oauth1"][0]["value"] = json!("request-key");
    let input = json!({
        "info":{"name":"API","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "auth":oauth1(), "variable":[{"key":"consumer","value":"collection-key"}],
        "item":[
            {"name":"Inherited","request":{"method":"GET","url":"https://example.test"}},
            {"name":"Folder","auth":folder_auth,"item":[
                {"name":"Inherited","request":{"method":"GET","url":"https://example.test","auth":null}},
                {"name":"None","request":{"method":"GET","url":"https://example.test","auth":{"type":"noauth"}}},
                {"name":"Own","request":{"method":"GET","url":"https://example.test","auth":own_auth}}
            ]}
        ]
    });
    let imported = parse(Format::Postman, &input.to_string()).unwrap();
    assert_eq!(imported.variables["consumer"], "collection-key");
    for (request, expected) in imported.requests.iter().zip([
        Some("{{consumer}}"),
        Some("folder-key"),
        None,
        Some("request-key"),
    ]) {
        let document = Document::parse(&request.source).unwrap();
        assert_eq!(
            document
                .value("auth:oauth1", "consumer_key")
                .unwrap()
                .as_deref(),
            expected
        );
        assert_eq!(
            document.value("get", "auth").unwrap().as_deref(),
            Some(if expected.is_some() { "oauth1" } else { "none" })
        );
    }
}

#[test]
fn postman_oauth1_rejects_unsupported_or_malformed_settings_before_cli_writes_or_network() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut malformed = Vec::new();
    for entry in [
        json!({"key":"addParamsToHeader","value":false}),
        json!({"key":"includeBodyHash","value":true}),
        json!({"key":"disableHeaderEncoding","value":true}),
        json!({"key":"addEmptyParamsToSign","value":false}),
        json!({"key":"addEmptyParamsToSign","value":true}),
        json!({"key":"signatureMethod","value":"RSA-SHA256"}),
        json!({"key":"version","value":"2.0"}),
        json!({"key":"realm","value":"secret-marker\n"}),
        json!({"key":"unknown","value":"secret-marker"}),
        json!({"key":"addParamsToHeader","value":"true","type":"boolean"}),
        json!({"key":"includeBodyHash","value":false,"type":"string"}),
        json!({"key":"disableHeaderEncoding","value":null}),
        json!({"key":"addParamsToHeader","value":true,"disabled":true}),
        json!({"key":"addParamsToHeader","value":true,"unexpected":"secret-marker"}),
    ] {
        let mut auth = oauth1();
        auth["oauth1"].as_array_mut().unwrap().push(entry);
        malformed.push(auth);
    }
    for key in ["callback", "verifier", "nonce", "timestamp", "privateKey"] {
        let mut auth = oauth1();
        auth["oauth1"]
            .as_array_mut()
            .unwrap()
            .push(json!({"key":key,"value":"secret-marker"}));
        malformed.push(auth);
    }
    for field in ["value", "type", "disabled", "extra"] {
        let mut auth = oauth1();
        auth["oauth1"][0][field] = json!({"secret":"secret-marker"});
        malformed.push(auth);
    }
    for key in ["consumerKey", "consumerSecret", "token"] {
        let mut auth = oauth1();
        auth["oauth1"]
            .as_array_mut()
            .unwrap()
            .retain(|entry| entry["key"] != key);
        malformed.push(auth);
    }
    let mut auth = oauth1();
    auth["oauth1"][0]["value"] = json!("");
    malformed.push(auth);
    let mut auth = oauth1();
    let duplicate = auth["oauth1"][0].clone();
    auth["oauth1"].as_array_mut().unwrap().push(duplicate);
    malformed.push(auth);
    let mut auth = oauth1();
    auth["oauth1"].as_array_mut().unwrap().extend([
        json!({"key":"includeBodyHash","value":false}),
        json!({"key":"includeBodyHash","value":false}),
    ]);
    malformed.push(auth);
    let mut auth = oauth1();
    auth["extra"] = json!("secret-marker");
    malformed.push(auth);
    let mut auth = oauth1();
    auth["oauth1"] = json!({"consumerKey":"secret-marker"});
    malformed.push(auth);
    for auth in malformed {
        let input = json!({
            "info":{"name":"API","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item":[
                {"name":"Valid","request":{"method":"GET","url":url}},
                {"name":"Invalid","request":{"method":"GET","url":url,"auth":auth}}
            ]
        }).to_string();
        let error = parse(Format::Postman, &input).unwrap_err().to_string();
        assert!(!error.contains("secret-marker"), "{error}");
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source.json");
        let destination = temporary.path().join("new-collection");
        fs::write(&source, input).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
            .args(["import", "postman"])
            .arg(&source)
            .arg(&destination)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!destination.exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-marker"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn postman_digest_and_aws_credentials_map_without_expanding_variables() {
    for (kind, pairs, expected) in [
        (
            "digest",
            json!([
                {"key":"username","value":"{{user}}","type":"string"},
                {"key":"password","value":"","type":"string"}
            ]),
            vec![("username", "{{user}}"), ("password", "")],
        ),
        (
            "awsv4",
            json!([
                {"key":"accessKey","value":"{{access}}","type":"string"},
                {"key":"secretKey","value":"{{secret}}","type":"string"},
                {"key":"region","value":"{{region}}","type":"string"},
                {"key":"service","value":"execute-api","type":"string"},
                {"key":"sessionToken","value":"","type":"string"}
            ]),
            vec![
                ("accessKeyId", "{{access}}"),
                ("secretAccessKey", "{{secret}}"),
                ("region", "{{region}}"),
                ("service", "execute-api"),
                ("sessionToken", ""),
            ],
        ),
    ] {
        let input = postman(json!({"name":"Auth","request":{
            "method":"GET","url":"https://example.test","auth":{"type":kind,kind:pairs}
        }}));
        let imported = parse(Format::Postman, &input).unwrap();
        let document = Document::parse(&imported.requests[0].source).unwrap();
        assert_eq!(
            document.value("get", "auth").unwrap().as_deref(),
            Some(kind)
        );
        let block = format!("auth:{kind}");
        for (key, value) in expected {
            assert_eq!(document.value(&block, key).unwrap().as_deref(), Some(value));
        }
    }
}

#[test]
fn postman_credential_auth_preserves_nearest_inheritance_and_noauth() {
    let input = json!({
        "info":{"name":"API","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "auth":{"type":"digest","digest":[{"key":"username","value":"{{user}}"},{"key":"password","value":"{{password}}"}]},
        "variable":[{"key":"user","value":"collection-user"},{"key":"password","value":"secret"}],
        "item":[
            {"name":"Inherited","request":{"method":"GET","url":"https://example.test"}},
            {"name":"AWS Folder","auth":{"type":"awsv4","awsv4":[
                {"key":"accessKey","value":"{{access}}"},{"key":"secretKey","value":"{{secret}}"},
                {"key":"region","value":"us-east-1"},{"key":"service","value":"s3"}
            ]},"variable":[{"key":"access","value":"folder-key"},{"key":"secret","value":"folder-secret"}],"item":[
                {"name":"Inherited AWS","request":{"method":"GET","url":"https://example.test","auth":null}},
                {"name":"No auth","request":{"method":"GET","url":"https://example.test","auth":{"type":"noauth"}}},
                {"name":"Own Digest","request":{"method":"GET","url":"https://example.test","auth":{"type":"digest","digest":[{"key":"username","value":"request-user"},{"key":"password","value":"request-secret"}]}}}
            ]}
        ]
    });
    let imported = parse(Format::Postman, &input.to_string()).unwrap();
    assert_eq!(imported.variables["user"], "collection-user");
    let documents = imported
        .requests
        .iter()
        .map(|request| Document::parse(&request.source).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        documents[0]
            .value("auth:digest", "username")
            .unwrap()
            .as_deref(),
        Some("{{user}}")
    );
    assert_eq!(
        documents[1].value("get", "auth").unwrap().as_deref(),
        Some("awsv4")
    );
    assert_eq!(
        documents[1]
            .value("vars:pre-request", "access")
            .unwrap()
            .as_deref(),
        Some("folder-key")
    );
    assert!(
        documents[1]
            .value("auth:awsv4", "sessionToken")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        documents[2].value("get", "auth").unwrap().as_deref(),
        Some("none")
    );
    assert!(documents[2].block("auth:awsv4").is_none());
    assert_eq!(
        documents[3]
            .value("auth:digest", "username")
            .unwrap()
            .as_deref(),
        Some("request-user")
    );
    assert!(documents[3].block("auth:awsv4").is_none());
}

#[test]
fn postman_credential_auth_rejects_malformed_and_unmapped_options_without_disclosing_secrets() {
    let digest = json!({"type":"digest","digest":[{"key":"username","value":"u"},{"key":"password","value":"secret-marker"}]});
    let aws = json!({"type":"awsv4","awsv4":[{"key":"accessKey","value":"a"},{"key":"secretKey","value":"secret-marker"},{"key":"region","value":"us-east-1"},{"key":"service","value":"s3"}]});
    let mut malformed = Vec::new();
    for base in [&digest, &aws] {
        let kind = base["type"].as_str().unwrap();
        for change in [
            json!({"key":"profileName","value":"secret-marker"}),
            json!({"key":"algorithm","value":"secret-marker"}),
            json!({"key":"addAuthDataToQuery","value":false}),
            json!({"key":"realm","value":"secret-marker"}),
        ] {
            let mut auth = base.clone();
            auth[kind].as_array_mut().unwrap().push(change);
            malformed.push(auth);
        }
        for field in ["value", "type", "disabled", "customOption"] {
            let mut auth = base.clone();
            auth[kind][0][field] = if field == "disabled" {
                json!(true)
            } else {
                json!({"secret":"secret-marker"})
            };
            malformed.push(auth);
        }
        let mut auth = base.clone();
        auth[kind].as_array_mut().unwrap().remove(0);
        malformed.push(auth);
        let mut auth = base.clone();
        let duplicate = auth[kind][0].clone();
        auth[kind].as_array_mut().unwrap().push(duplicate);
        malformed.push(auth);
        let mut auth = base.clone();
        auth["unexpectedAuthOption"] = json!("secret-marker");
        malformed.push(auth);
        let mut auth = base.clone();
        auth[kind] = json!({"username":"secret-marker"});
        malformed.push(auth);
    }
    for field in ["accessKey", "secretKey", "region", "service"] {
        let mut auth = aws.clone();
        for entry in auth["awsv4"].as_array_mut().unwrap() {
            if entry["key"] == field {
                entry["value"] = json!("");
            }
        }
        malformed.push(auth);
    }
    for value in ["US-EAST-1", "*", "us east 1"] {
        let mut auth = aws.clone();
        auth["awsv4"][2]["value"] = json!(value);
        malformed.push(auth);
    }
    for auth in malformed {
        let input = postman(
            json!({"name":"Unsafe","request":{"method":"GET","url":"https://example.test","auth":auth}}),
        );
        let error = parse(Format::Postman, &input).unwrap_err().to_string();
        assert!(!error.contains("secret-marker"), "{error}");
    }
}

#[test]
fn postman_unsupported_credential_option_fails_cli_before_partial_import_or_network() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let input = json!({
        "info":{"name":"API","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item":[
            {"name":"Valid","request":{"method":"GET","url":url}},
            {"name":"Invalid","request":{"method":"GET","url":url,"auth":{"type":"awsv4","awsv4":[{"key":"profileName","value":"secret-marker"}]}}}
        ]
    });
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source.json");
    let destination = temporary.path().join("new-collection");
    fs::write(&source, input.to_string()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["import", "postman"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!destination.exists());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-marker"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn postman_raw_and_graphql_bodies_round_trip() {
    let input = postman(json!({"name":"Body","request":{
        "method":"POST","url":"https://example.test",
        "header":[{"key":"X-Space","value":"  first\nsecond  "}],
        "body":{"mode":"raw","raw":"{\n  \"nested\": {}\n}\n","options":{"raw":{"language":"json"}}}
    }}));
    let imported = parse(Format::Postman, &input).unwrap();
    let document = Document::parse(&imported.requests[0].source).unwrap();
    assert_eq!(
        document.block("body:json").unwrap().content,
        "{\n  \"nested\": {}\n}\n"
    );
    assert_eq!(
        document.value("headers", "X-Space").unwrap().unwrap(),
        "  first\nsecond  "
    );
    let input = postman(json!({"name":"GraphQL","request":{
        "method":"POST","url":"https://example.test",
        "body":{"mode":"graphql","graphql":{"query":"query($id: ID!) { user(id: $id) { id } }","variables":"{\"id\":42}"}}
    }}));
    let imported = parse(Format::Postman, &input).unwrap();
    let document = Document::parse(&imported.requests[0].source).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&document.block("body:graphql:vars").unwrap().content)
            .unwrap(),
        json!({"id":42})
    );
}

#[test]
fn unsupported_postman_scripts_auth_and_files_fail() {
    for item in [
        json!({"name":"Unsafe","event":[{"listen":"test","script":{"exec":["pm.test('x',()=>{})"]}}],"request":{"method":"GET","url":"https://example.test"}}),
        json!({"name":"Unsafe","request":{"method":"GET","url":"https://example.test","auth":{"type":"digest"}}}),
        json!({"name":"Unsafe","request":{"method":"POST","url":"https://example.test","body":{"mode":"file","file":{"src":"/etc/passwd"}}}}),
        json!({"name":"Unsafe","request":{"method":"POST","url":"https://example.test","body":{"mode":"formdata","formdata":[{"key":"file","value":"@file(/etc/passwd)","type":"text"}]}}}),
    ] {
        assert!(parse(Format::Postman, &postman(item)).is_err());
    }
}

#[test]
fn openapi_yaml_local_refs_server_defaults_and_security() {
    let input = r#"
openapi: 3.1.0
info:
  title: Example
servers:
  - url: https://{host}/v1
    variables:
      host:
        default: example.test
security:
  - bearerAuth: []
paths:
  /users/{id}:
    parameters:
      - $ref: '#/components/parameters/id'
    get:
      operationId: readUser
      parameters:
        - in: query
          name: verbose
          schema: {type: boolean, default: true}
        - in: header
          name: X-Optional
          schema: {type: string}
        - in: query
          name: optionalWithExample
          example: '{{provided}}'
          schema: {type: string}
components:
  parameters:
    id:
      in: path
      name: id
      required: true
      example: 42
      schema: {type: integer}
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
"#;
    let imported = parse(Format::OpenApi, input).unwrap();
    let document = Document::parse(&imported.requests[0].source).unwrap();
    assert_eq!(
        document.value("get", "url").unwrap().unwrap(),
        "https://example.test/v1/users/:id"
    );
    assert_eq!(document.value("params:path", "id").unwrap().unwrap(), "42");
    assert_eq!(
        document.value("params:query", "verbose").unwrap().unwrap(),
        "true"
    );
    assert!(!document.pairs("headers").unwrap()[0].enabled);
    assert_eq!(
        document
            .value("params:query", "optionalWithExample")
            .unwrap()
            .unwrap(),
        "{{provided}}"
    );
    assert_eq!(
        document.value("auth:bearer", "token").unwrap().unwrap(),
        "{{token}}"
    );
}

#[test]
fn openapi_json_body_uses_local_example_and_operation_auth_override() {
    let input = json!({
        "openapi":"3.0.3","info":{"title":"Body"},"servers":[{"url":"https://example.test"}],
        "security":[{"unknown":[]}],
        "paths":{"/user":{"post":{"security":[],"requestBody":{"content":{"application/json":{
            "examples":{"first":{"$ref":"#/components/examples/user"}}
        }}}}}},
        "components":{"examples":{"user":{"value":{"name":"Quinn"}}}}
    });
    let imported = parse(Format::OpenApi, &input.to_string()).unwrap();
    let document = Document::parse(&imported.requests[0].source).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&document.block("body:json").unwrap().content).unwrap(),
        json!({"name":"Quinn"})
    );
    assert_eq!(document.value("post", "auth").unwrap().unwrap(), "none");
}

#[test]
fn openapi_rejects_external_refs_cycles_missing_examples_and_structured_parameters() {
    for operation in [
        json!({"parameters":[{"$ref":"https://example.test/parameter.json"}]}),
        json!({"parameters":[{"$ref":"#/components/parameters/cycle"}]}),
        json!({"requestBody":{"content":{"application/json":{"schema":{"type":"object"}}}}}),
        json!({"parameters":[{"in":"query","name":"items","schema":{"type":"array"}}]}),
    ] {
        let input = json!({
            "openapi":"3.0.0","info":{"title":"Unsafe"},"servers":[{"url":"https://example.test"}],
            "paths":{"/":{"post":operation}},
            "components":{"parameters":{"cycle":{"$ref":"#/components/parameters/cycle"}}}
        });
        assert!(parse(Format::OpenApi, &input.to_string()).is_err());
    }
}

#[test]
fn curl_keeps_quotes_headers_literal_data_and_basic_auth() {
    let imported = parse(Format::Curl, r#"curl --url=https://example.test/api -X PATCH -H 'X-Test: quoted value' --data-raw '{"value":"$(do-not-run)"}' -u 'user:pass:word'"#).unwrap();
    let document = Document::parse(&imported.requests[0].source).unwrap();
    assert_eq!(document.value("patch", "auth").unwrap().unwrap(), "basic");
    assert_eq!(
        document.value("auth:basic", "password").unwrap().unwrap(),
        "pass:word"
    );
    assert_eq!(
        document.block("body:text").unwrap().content,
        r#"{"value":"$(do-not-run)"}"#
    );
    assert_eq!(
        document.value("headers", "X-Test").unwrap().unwrap(),
        "quoted value"
    );
    assert_eq!(
        document.value("headers", "Content-Type").unwrap().unwrap(),
        "application/x-www-form-urlencoded"
    );
}

#[test]
fn curl_rejects_files_unsafe_flags_multiple_urls_and_bad_quotes() {
    for input in [
        "curl https://example.test --data @/etc/passwd",
        "curl https://example.test -H @headers.txt",
        "curl https://example.test -k",
        "curl https://example.test https://other.test",
        "curl https://example.test ; touch /tmp/no",
        "curl 'unterminated",
        "curl https://example.test --head=true",
        "curl https://example.test -I -d 'body'",
    ] {
        assert!(parse(Format::Curl, input).is_err(), "{input}");
    }
}

#[test]
fn curl_custom_method_overrides_head_in_either_order() {
    for input in [
        "curl https://example.test -X GET -I",
        "curl https://example.test -I -X GET",
    ] {
        let imported = parse(Format::Curl, input).unwrap();
        let document = Document::parse(&imported.requests[0].source).unwrap();
        assert!(document.block("get").is_some());
    }
}

#[test]
fn rejects_duplicate_headers_and_partial_openapi_path_parameters() {
    assert!(
        parse(
            Format::Curl,
            "curl https://example.test -H 'X-Test: one' -H 'x-test: two'"
        )
        .is_err()
    );
    let input = json!({
        "openapi":"3.0.0","info":{"title":"Path"},"servers":[{"url":"https://example.test"}],
        "paths":{"/prefix{id}":{"get":{"parameters":[{"in":"path","name":"id","required":true,"example":42}]}}}
    });
    assert!(parse(Format::OpenApi, &input.to_string()).is_err());
}

#[test]
fn imports_number_filenames_and_never_overwrite_paths() {
    let imported = parse(Format::Postman, &json!({
        "info":{"name":"Test","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item":[
            {"name":"../../outside","request":{"method":"GET","url":"https://example.test"}},
            {"name":"../../outside","request":{"method":"GET","url":"https://example.test"}}
        ]
    }).to_string()).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("collection");
    imported.write_to(&destination).unwrap();
    let entries = collection::discover(&destination).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .all(|entry| entry.path.parent() == Some(destination.as_path()))
    );
    fs::write(destination.join("sentinel"), "preserve").unwrap();
    assert!(imported.write_to(&destination).is_err());
    assert_eq!(
        fs::read_to_string(destination.join("sentinel")).unwrap(),
        "preserve"
    );
}

#[cfg(unix)]
#[test]
fn imports_refuse_symlink_destinations() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("link");
    std::os::unix::fs::symlink(temporary.path(), &destination).unwrap();
    let imported = parse(Format::Curl, "curl https://example.test").unwrap();
    assert!(imported.write_to(&destination).is_err());
    assert!(!temporary.path().join("bruno.json").exists());
}

#[test]
fn rejects_oversized_or_empty_imports() {
    assert!(parse(Format::Curl, &"x".repeat(16 * 1024 * 1024 + 1)).is_err());
    assert!(parse(Format::Postman, &json!({
        "info":{"name":"Empty","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":[]
    }).to_string()).is_err());
}

fn server() -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut stream: TcpStream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "request never arrived"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}").unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (url, handle)
}

#[test]
fn imported_postman_and_openapi_requests_execute_in_the_engine() {
    for format in [Format::Postman, Format::OpenApi] {
        let (url, handle) = server();
        let input = match format {
            Format::Postman => postman(json!({"name":"Send","request":{
                "method":"POST","url":format!("{url}/body"),
                "body":{"mode":"raw","raw":"{\"name\":\"Quinn\"}","options":{"raw":{"language":"json"}}}
            }})),
            Format::OpenApi => json!({
                "openapi":"3.0.3","info":{"title":"Send"},"servers":[{"url":url}],
                "paths":{"/body":{"post":{"requestBody":{"content":{"application/json":{"example":{"name":"Quinn"}}}}}}}
            }).to_string(),
            Format::Curl | Format::Insomnia => unreachable!(),
        };
        let imported = parse(format, &input).unwrap();
        let document = Document::parse(&imported.requests[0].source).unwrap();
        let engine = Engine::new(Duration::from_secs(5)).unwrap();
        assert!(
            engine
                .send(&document, &[], &Variables::new())
                .unwrap()
                .passed()
        );
        let request = handle.join().unwrap();
        assert!(request.starts_with("POST /body HTTP/1.1"));
        assert_eq!(
            serde_json::from_str::<Value>(request.split_once("\r\n\r\n").unwrap().1).unwrap(),
            json!({"name":"Quinn"})
        );
    }
}

#[test]
fn imported_postman_oauth1_signs_actual_form_and_duplicate_query_parameters() {
    const ENCODING: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    let encode = |value: &str| utf8_percent_encode(value, ENCODING).to_string();
    for algorithm in ["HMAC-SHA1", "HMAC-SHA256"] {
        let (url, handle) = server();
        let mut auth = oauth1();
        auth["oauth1"]
            .as_array_mut()
            .unwrap()
            .push(json!({"key":"signatureMethod","value":algorithm}));
        let input = postman(json!({"name":"Signed","request":{
            "method":"POST","url":format!("{url}/resource?repeat=z&repeat=a&space=a+b&literal=%2B"),
            "auth":auth,"body":{"mode":"urlencoded","urlencoded":[
                {"key":"repeat","value":"form"}, {"key":"empty","value":""},
                {"key":"value","value":"one + two"}
            ]}
        }}));
        let imported = parse(Format::Postman, &input).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("collection");
        imported.write_to(&destination).unwrap();
        let request = collection::discover(&destination).unwrap().remove(0);
        let source = fs::read_to_string(&request.path).unwrap();
        let document = Document::parse(&source).unwrap();
        let variables = Variables::from([("consumer".into(), "consumer/key".into())]);
        let engine = Engine::with_network(
            Duration::from_secs(5),
            &NetworkOptions {
                no_proxy: true,
                ..NetworkOptions::default()
            },
        )
        .unwrap();
        assert!(engine.send(&document, &[], &variables).unwrap().passed());
        assert_eq!(fs::read_to_string(&request.path).unwrap(), source);
        let wire = handle.join().unwrap();
        assert!(
            wire.starts_with("POST /resource?repeat=z&repeat=a&space=a+b&literal=%2B HTTP/1.1")
        );
        assert!(wire.ends_with("repeat=form&empty=&value=one+%2B+two"));
        let (head, body) = wire.split_once("\r\n\r\n").unwrap();
        let headers: BTreeMap<_, _> = head
            .lines()
            .skip(1)
            .map(|line| {
                let (key, value) = line.split_once(':').unwrap();
                (key.to_ascii_lowercase(), value.trim())
            })
            .collect();
        let oauth: BTreeMap<_, _> = headers["authorization"]
            .strip_prefix("OAuth ")
            .unwrap()
            .split(", ")
            .map(|field| {
                let (key, value) = field.split_once('=').unwrap();
                let value = value.strip_prefix('"').unwrap().strip_suffix('"').unwrap();
                (
                    key.to_owned(),
                    percent_encoding::percent_decode_str(value)
                        .decode_utf8()
                        .unwrap()
                        .into_owned(),
                )
            })
            .collect();
        assert_eq!(oauth["oauth_consumer_key"], "consumer/key");
        assert_eq!(oauth["oauth_token"], "access/token");
        assert_eq!(oauth["oauth_signature_method"], algorithm);
        assert_eq!(oauth["oauth_version"], "1.0");
        assert_eq!(oauth["oauth_nonce"].len(), 48);
        assert!(oauth["oauth_timestamp"].parse::<u64>().unwrap() > 1_700_000_000);
        let mut parameters = Url::parse(&format!("{url}/?repeat=z&repeat=a&space=a+b&literal=%2B"))
            .unwrap()
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        parameters.extend(
            Url::parse(&format!("http://parse.invalid/?{body}"))
                .unwrap()
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned())),
        );
        parameters.extend(
            oauth
                .iter()
                .filter(|(key, _)| key.as_str() != "oauth_signature")
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        let mut parameters = parameters
            .iter()
            .map(|(key, value)| (encode(key), encode(value)))
            .collect::<Vec<_>>();
        parameters.sort();
        let normalized = parameters
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        let base = format!(
            "POST&{}&{}",
            encode(&format!("{url}/resource")),
            encode(&normalized)
        );
        let key = format!("{}&{}", encode("consumer/+ é"), encode("token&secret"));
        let expected = if algorithm == "HMAC-SHA256" {
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
            mac.update(base.as_bytes());
            STANDARD.encode(mac.finalize().into_bytes())
        } else {
            let mut mac = Hmac::<Sha1>::new_from_slice(key.as_bytes()).unwrap();
            mac.update(base.as_bytes());
            STANDARD.encode(mac.finalize().into_bytes())
        };
        assert_eq!(oauth["oauth_signature"], expected);
        assert!(!wire.contains("consumer/+ é"));
        assert!(!wire.contains("token&secret"));
    }
}

#[test]
fn cli_import_then_run_sends_the_translated_curl_request() {
    let (url, handle) = server();
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("request.txt");
    let destination = temporary.path().join("collection");
    fs::write(
        &source,
        format!("curl '{url}/submit' --data-raw 'a=hello+world' -H 'X-Imported: yes'"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["import", "curl"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .arg("run")
        .arg(&destination)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = handle.join().unwrap();
    assert!(request.starts_with("POST /submit HTTP/1.1"));
    assert!(request.to_lowercase().contains("x-imported: yes"));
    assert!(request.ends_with("a=hello+world"));
    let output = Command::new(env!("CARGO_BIN_EXE_quinn"))
        .args(["import", "curl"])
        .arg(&source)
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
}
