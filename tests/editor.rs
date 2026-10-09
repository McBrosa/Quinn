use quinn_api::{
    Result,
    bru::{Document, Pair},
    editor,
};

#[test]
fn edits_preserve_unrelated_bytes_and_entries() -> Result<()> {
    let source = "\u{feff}# comment\r\nmeta {\r\n  name: untouched\r\n}\r\n\r\nget {\r\n  url: https://old.example\r\n  auth: none\r\n  future: keep this\r\n}\r\n\r\nheaders {\r\n  # keep header note\r\n  X-Test: old\r\n  ~X-Disabled: '''disabled'''\r\n}\r\n\r\nscript:pre-request {\r\n  let a = { hello: 'world' };\r\n}\r\nunknown {\r\n  preserve: true\r\n}\r\n";
    let updated = editor::set_value(source, "get", "url", "https://new.example")?;
    assert!(updated.starts_with("\u{feff}# comment\r\nmeta {\r\n"));
    assert!(updated.contains("  auth: none\r\n  future: keep this\r\n"));
    assert!(updated.ends_with("script:pre-request {\r\n  let a = { hello: 'world' };\r\n}\r\nunknown {\r\n  preserve: true\r\n}\r\n"));
    let mut pairs = Document::parse(&updated)?.pairs("headers")?;
    pairs[0].value = "new".into();
    let updated = editor::replace_pairs(&updated, "headers", &pairs)?;
    assert!(updated.contains("  # keep header note\r\n"));
    assert!(updated.contains("  ~X-Disabled: '''disabled'''\r\n"));
    Ok(())
}

#[test]
fn disabled_lists_multiline_and_quoted_keys_roundtrip() -> Result<()> {
    let source = "headers {\n  first: yes\n  values: [\n    one\n    two\n  ]\n}\n";
    let pairs = vec![
        Pair {
            key: "first".into(),
            value: "no".into(),
            enabled: false,
            is_list: false,
        },
        Pair {
            key: "values".into(),
            value: "three\nfour".into(),
            enabled: true,
            is_list: true,
        },
        Pair {
            key: "key:with:colon".into(),
            value: "first\nsecond".into(),
            enabled: true,
            is_list: false,
        },
    ];
    let updated = editor::replace_pairs(source, "headers", &pairs)?;
    assert_eq!(Document::parse(&updated)?.pairs("headers")?, pairs);
    let updated = editor::replace_pairs(&updated, "headers", &pairs[1..])?;
    assert_eq!(Document::parse(&updated)?.pairs("headers")?, pairs[1..]);
    Ok(())
}

#[test]
fn json_body_and_method_auth_updates_keep_other_blocks() -> Result<()> {
    let source = "get {\n  url: {{baseUrl}}\n  auth: none\n  body: none\n}\n\ndocs {\n  Keep me exactly.\n}\n";
    let updated = editor::rename_block(source, "get", "post")?;
    let updated = editor::set_value(&updated, "post", "auth", "bearer")?;
    let updated = editor::set_value(&updated, "post", "body", "json")?;
    let updated = editor::set_value(&updated, "auth:bearer", "token", "{{token}}")?;
    let body = "{\n  \"nested\": {\n    \"enabled\": true\n  }\n}";
    let updated = editor::replace_block(&updated, "body:json", Some(body))?;
    let document = Document::parse(&updated)?;
    assert_eq!(document.value("post", "auth")?.as_deref(), Some("bearer"));
    assert_eq!(
        document.value("auth:bearer", "token")?.as_deref(),
        Some("{{token}}")
    );
    assert_eq!(
        document
            .block("body:json")
            .map(|block| block.content.as_str()),
        Some(body)
    );
    assert!(updated.contains("docs {\n  Keep me exactly.\n}\n"));
    Ok(())
}

#[test]
fn malformed_source_and_unrepresentable_values_fail_without_writes() {
    assert!(editor::set_value("get {\n  url: missing\n", "get", "url", "other").is_err());
    assert!(editor::replace_block("broken", "body:json", Some("{}")).is_err());
    let pair = Pair {
        key: "k".into(),
        value: "\na'''b".into(),
        enabled: true,
        is_list: false,
    };
    assert!(editor::replace_pairs("headers {\n}\n", "headers", &[pair]).is_err());
}

#[test]
fn unchanged_edit_is_byte_identical_and_empty_body_can_be_removed() -> Result<()> {
    let source = "get {\n  url: x\n}\n\nheaders {\n  # keep\n  X: '''unchanged'''\n}\n\nbody:text {\n  hello\n}\n";
    let pairs = Document::parse(source)?.pairs("headers")?;
    assert_eq!(editor::replace_pairs(source, "headers", &pairs)?, source);
    let updated = editor::replace_block(source, "body:text", None)?;
    assert!(Document::parse(&updated)?.block("body:text").is_none());
    assert!(
        updated.starts_with("get {\n  url: x\n}\n\nheaders {\n  # keep\n  X: '''unchanged'''\n}\n")
    );
    Ok(())
}

#[test]
fn bom_survives_renaming_or_replacing_the_first_block() -> Result<()> {
    let source = "\u{feff}get {\n  url: x\n}\n";
    assert!(editor::rename_block(source, "get", "post")?.starts_with('\u{feff}'));
    assert!(editor::replace_block(source, "get", Some("url: y"))?.starts_with('\u{feff}'));
    Ok(())
}
