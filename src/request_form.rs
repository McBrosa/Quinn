use std::collections::BTreeMap;

use eframe::egui::{self, TextEdit};
use quinn_api::{
    Error, Result,
    bru::{Document, Pair},
    editor,
};

const METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "connect", "trace", "http",
];
const AUTH: &[&str] = &["none", "inherit", "basic", "bearer", "apikey", "oauth2"];
const BODIES: &[(&str, &str)] = &[
    ("none", ""),
    ("json", "body:json"),
    ("text", "body:text"),
    ("xml", "body:xml"),
    ("sparql", "body:sparql"),
    ("formUrlEncoded", "body:form-urlencoded"),
    ("graphql", "body:graphql"),
    ("multipartForm", "body:multipart-form"),
    ("file", "body:file"),
];

pub struct RequestForm {
    pub source: String,
    method: String,
    url: String,
    custom_method: String,
    auth: String,
    body: String,
    pairs: BTreeMap<String, Vec<Pair>>,
    contents: BTreeMap<String, String>,
    tab: String,
    pub error: String,
}

impl RequestForm {
    pub fn parse(source: &str) -> Result<Self> {
        let document = Document::parse(source)?;
        let methods = document
            .blocks
            .iter()
            .filter(|block| METHODS.contains(&block.name.as_str()))
            .collect::<Vec<_>>();
        if methods.len() != 1 {
            return Err(invalid(
                "Forms require one HTTP request block. Use Source for this request.",
            ));
        }
        let method = methods[0].name.clone();
        let url = document.value(&method, "url")?.unwrap_or_default();
        let custom_method = document
            .value(&method, "method")?
            .unwrap_or_else(|| "GET".into());
        let auth = document
            .value(&method, "auth")?
            .unwrap_or_else(|| "none".into());
        let body = document
            .value(&method, "body")?
            .unwrap_or_else(|| "none".into());
        let mut pairs = BTreeMap::new();
        for name in [
            "headers",
            "params:query",
            "params:path",
            "auth:basic",
            "auth:bearer",
            "auth:apikey",
            "auth:oauth2",
            "body:form-urlencoded",
            "body:multipart-form",
            "body:file",
        ] {
            pairs.insert(name.into(), document.pairs(name)?);
        }
        let mut contents: BTreeMap<String, String> = BODIES
            .iter()
            .filter(|(_, name)| !name.is_empty())
            .map(|(_, name)| {
                (
                    (*name).into(),
                    document
                        .block(name)
                        .map(|block| block.content.clone())
                        .unwrap_or_default(),
                )
            })
            .collect();
        contents.insert(
            "body:graphql:vars".into(),
            document
                .block("body:graphql:vars")
                .map(|block| block.content.clone())
                .unwrap_or_default(),
        );
        Ok(Self {
            source: source.to_owned(),
            method,
            url,
            custom_method,
            auth,
            body,
            pairs,
            contents,
            tab: "Headers".into(),
            error: String::new(),
        })
    }

    pub fn apply(&self) -> Result<String> {
        let original = Document::parse(&self.source)?;
        let old_method = original
            .blocks
            .iter()
            .find(|block| METHODS.contains(&block.name.as_str()))
            .ok_or_else(|| invalid("cannot locate request"))?
            .name
            .clone();
        let mut result = self.source.clone();
        if self.method != old_method {
            result = editor::rename_block(&result, &old_method, &self.method)?;
        }
        for (key, value) in [
            ("url", self.url.as_str()),
            ("auth", self.auth.as_str()),
            ("body", self.body.as_str()),
        ] {
            let old = original.value(&old_method, key)?.unwrap_or_else(|| {
                if key == "url" {
                    String::new()
                } else {
                    "none".into()
                }
            });
            if old != value {
                result = editor::set_value(&result, &self.method, key, value)?;
            }
        }
        if self.method == "http"
            && original.value(&old_method, "method")?.as_deref() != Some(&self.custom_method)
        {
            result = editor::set_value(&result, &self.method, "method", &self.custom_method)?;
        }
        for (name, pairs) in &self.pairs {
            if original.pairs(name)? != *pairs {
                result = editor::replace_pairs(&result, name, pairs)?;
            }
        }
        for (name, content) in &self.contents {
            if original
                .block(name)
                .map(|block| block.content.as_str())
                .unwrap_or_default()
                != content
            {
                result = editor::replace_block(&result, name, Some(content))?;
            }
        }
        let old_body = original
            .value(&old_method, "body")?
            .unwrap_or_else(|| "none".into());
        if self.body != old_body {
            let mode = match self.body.as_str() {
                "form-urlencoded" => "formUrlEncoded",
                "multipart-form" => "multipartForm",
                mode => mode,
            };
            if let Some((_, name)) = BODIES.iter().find(|(body, _)| *body == mode)
                && !name.is_empty()
                && Document::parse(&result)?.block(name).is_none()
            {
                result = editor::replace_block(&result, name, Some(""))?;
            }
        }
        Ok(result)
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> bool {
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("method")
                .selected_text(self.method.to_uppercase())
                .show_ui(ui, |ui| {
                    for method in METHODS {
                        ui.selectable_value(
                            &mut self.method,
                            (*method).into(),
                            method.to_uppercase(),
                        );
                    }
                });
            ui.add(
                TextEdit::singleline(&mut self.url)
                    .hint_text("URL (supports {{variables}})")
                    .desired_width(f32::INFINITY),
            );
        });
        if self.method == "http" {
            ui.horizontal(|ui| {
                ui.label("Custom method");
                ui.text_edit_singleline(&mut self.custom_method);
            });
        }
        ui.horizontal_wrapped(|ui| {
            for tab in ["Headers", "Query", "Path", "Auth", "Body"] {
                ui.selectable_value(&mut self.tab, tab.into(), tab);
            }
        });
        match self.tab.as_str() {
            "Headers" => self.pairs_ui(ui, "headers"),
            "Query" => self.pairs_ui(ui, "params:query"),
            "Path" => self.pairs_ui(ui, "params:path"),
            "Auth" => {
                let previous_auth = self.auth.clone();
                ui.horizontal(|ui| {
                    ui.label("Authentication");
                    combo(ui, "auth_mode", &mut self.auth, AUTH);
                });
                if self.auth != previous_auth {
                    let name = format!("auth:{}", self.auth);
                    let fields: &[(&str, &str)] = match self.auth.as_str() {
                        "basic" => &[("username", ""), ("password", "")],
                        "bearer" => &[("token", "")],
                        "apikey" => &[("key", ""), ("value", ""), ("placement", "header")],
                        "oauth2" => &[
                            ("grant_type", "client_credentials"),
                            ("access_token_url", ""),
                            ("client_id", ""),
                            ("client_secret", ""),
                        ],
                        _ => &[],
                    };
                    let pairs = self.pairs.entry(name).or_default();
                    if pairs.is_empty() {
                        pairs.extend(fields.iter().map(|(key, value)| Pair {
                            key: (*key).into(),
                            value: (*value).into(),
                            enabled: true,
                            is_list: false,
                        }));
                    }
                }
                if matches!(self.auth.as_str(), "basic" | "bearer" | "apikey" | "oauth2") {
                    let name = format!("auth:{}", self.auth);
                    ui.label(match self.auth.as_str() {
                        "basic" => "Fields: username, password. Use {{variables}} for secrets.",
                        "bearer" => "Field: token. Use {{variables}} for secrets.",
                        "apikey" => "Fields: key, value, placement (header or queryparams).",
                        _ => "Use Bruno OAuth field names. Configure supported grants in COMPATIBILITY.md.",
                    });
                    self.pairs_ui(ui, &name);
                } else if self.auth == "inherit" {
                    ui.label("Uses the nearest collection or folder authentication.");
                }
            }
            "Body" => {
                ui.horizontal(|ui| {
                    ui.label("Body type");
                    let options = BODIES.iter().map(|(mode, _)| *mode).collect::<Vec<_>>();
                    combo(ui, "body_mode", &mut self.body, &options);
                });
                let normalized = match self.body.as_str() {
                    "form-urlencoded" => "formUrlEncoded",
                    "multipart-form" => "multipartForm",
                    other => other,
                };
                if let Some((_, name)) = BODIES.iter().find(|(mode, _)| *mode == normalized) {
                    if matches!(
                        *name,
                        "body:form-urlencoded" | "body:multipart-form" | "body:file"
                    ) {
                        let name = *name;
                        if name != "body:form-urlencoded" {
                            ui.label("Uploads: @file(path) @contentType(type). Paths resolve from the collection root.");
                        }
                        self.pairs_ui(ui, name);
                    } else if !name.is_empty() {
                        let content = self.contents.entry((*name).into()).or_default();
                        ui.add(
                            TextEdit::multiline(content)
                                .code_editor()
                                .desired_rows(8)
                                .desired_width(f32::INFINITY),
                        );
                        if *name == "body:graphql" {
                            ui.label("GraphQL variables (JSON object)");
                            let variables =
                                self.contents.entry("body:graphql:vars".into()).or_default();
                            ui.add(
                                TextEdit::multiline(variables)
                                    .code_editor()
                                    .desired_rows(3)
                                    .desired_width(f32::INFINITY),
                            );
                        }
                    }
                } else {
                    ui.label("This body type is not editable in Forms. Use Source.");
                }
            }
            _ => {}
        }
        if !self.error.is_empty() {
            ui.colored_label(ui.visuals().error_fg_color, &self.error);
        }
        ui.horizontal(|ui| {
            let apply = ui.button("Apply form changes").clicked();
            ui.label("Apply updates Source; Save writes the file.");
            apply
        })
        .inner
    }

    fn pairs_ui(&mut self, ui: &mut egui::Ui, name: &str) {
        let pairs = self.pairs.entry(name.into()).or_default();
        ui.label("Enabled / Name / Value. List values use one item per line.");
        let mut remove = None;
        for (index, pair) in pairs.iter_mut().enumerate() {
            ui.push_id((name, index), |ui| {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut pair.enabled, "")
                        .on_hover_text("Enable this field");
                    ui.add(
                        TextEdit::singleline(&mut pair.key)
                            .hint_text("Name")
                            .desired_width(150.0),
                    );
                    ui.checkbox(&mut pair.is_list, "List");
                    if ui.button("Remove").clicked() {
                        remove = Some(index);
                    }
                });
                let rows = if pair.value.contains('\n') { 3 } else { 1 };
                ui.add(
                    TextEdit::multiline(&mut pair.value)
                        .hint_text("Value")
                        .desired_rows(rows)
                        .desired_width(f32::INFINITY),
                );
            });
        }
        if let Some(index) = remove {
            pairs.remove(index);
        }
        if ui.button("Add field").clicked() {
            pairs.push(Pair {
                key: String::new(),
                value: String::new(),
                enabled: true,
                is_list: false,
            });
        }
    }
}

fn combo(ui: &mut egui::Ui, id: &str, value: &mut String, options: &[&str]) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(value.as_str())
        .show_ui(ui, |ui| {
            for option in options {
                ui.selectable_value(value, (*option).into(), *option);
            }
        });
}

fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::RequestForm;
    use quinn_api::{Result, bru::Document};

    #[test]
    fn form_noop_and_edits_preserve_scripts_unknown_fields_and_uploads() -> Result<()> {
        let source = "post {\n  url: {{baseUrl}}/old\n  auth: basic\n  body: multipartForm\n  future: yes\n}\n\nauth:basic {\n  username: user\n  password: {{secret}}\n  future: keep\n}\n\nbody:multipart-form {\n  attachments: [\n    @file(one.txt)\n    @file(two.txt)\n  ]\n}\n\nscript:pre-request {\n  bru.setVar('x', 'y');\n}\n";
        let mut form = RequestForm::parse(source)?;
        assert_eq!(form.apply()?, source);
        form.method = "put".into();
        form.url = "{{baseUrl}}/new".into();
        form.auth = "bearer".into();
        let updated = form.apply()?;
        let document = Document::parse(&updated)?;
        assert_eq!(
            document.value("put", "url")?.as_deref(),
            Some("{{baseUrl}}/new")
        );
        assert_eq!(document.value("put", "auth")?.as_deref(), Some("bearer"));
        assert!(updated.contains(
            "auth:basic {\n  username: user\n  password: {{secret}}\n  future: keep\n}\n"
        ));
        assert!(updated.ends_with("script:pre-request {\n  bru.setVar('x', 'y');\n}\n"));
        assert_eq!(
            document.pairs("body:multipart-form")?,
            Document::parse(source)?.pairs("body:multipart-form")?
        );
        Ok(())
    }

    #[test]
    fn graph_ql_variables_and_nested_json_roundtrip() -> Result<()> {
        let mut form = RequestForm::parse(
            "post {\n  url: http://localhost\n  body: graphql\n}\n\nbody:graphql {\n  query { user { id } }\n}\n",
        )?;
        form.contents.insert(
            "body:graphql:vars".into(),
            "{\n  \"nested\": {\n    \"value\": 1\n  }\n}".into(),
        );
        let updated = form.apply()?;
        assert_eq!(
            Document::parse(&updated)?
                .block("body:graphql:vars")
                .map(|block| block.content.as_str()),
            form.contents.get("body:graphql:vars").map(String::as_str)
        );
        Ok(())
    }

    #[test]
    fn invalid_and_non_http_requests_are_not_replaced() {
        assert!(RequestForm::parse("get {\n").is_err());
        assert!(RequestForm::parse("ws {\n  url: ws://localhost\n}\n").is_err());
        assert!(RequestForm::parse("get {\n}\npost {\n}\n").is_err());
    }
}
