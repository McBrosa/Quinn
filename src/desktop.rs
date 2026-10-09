use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, Receiver},
    },
    thread,
};

use eframe::egui::{
    self, Color32, FontId, Key, KeyboardShortcut, Modifiers, RichText, ScrollArea, TextEdit,
};
use quinn_api::{
    Result,
    collection::{self, Entry},
    engine::{Engine, Response},
    variables::Variables,
};

use crate::request_form::RequestForm;

pub fn open(path: Option<PathBuf>, engine: Engine) -> std::result::Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1220.0, 800.0])
            .with_min_inner_size([820.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Quinn",
        options,
        Box::new(move |context| {
            context.egui_ctx.set_visuals(egui::Visuals::dark());
            let mut app = Quinn::new(engine);
            if let Some(path) = path {
                app.load_collection(path);
            }
            Ok(Box::new(app))
        }),
    )
    .map_err(|error| error.to_string())
}

struct Quinn {
    engine: Arc<Engine>,
    root: Option<PathBuf>,
    entries: Vec<Entry>,
    environments: Vec<String>,
    environment: String,
    overrides: String,
    runtime_variables: Variables,
    filter: String,
    selected: Option<PathBuf>,
    source: String,
    original: String,
    form: Option<RequestForm>,
    forms_tab: bool,
    response: Option<Response>,
    response_text: String,
    receiver: Option<Receiver<Result<Response>>>,
    error: String,
    response_tab: ResponseTab,
    pending: Option<Action>,
    new_request: bool,
    new_name: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseTab {
    Body,
    Headers,
    Assertions,
}

enum Action {
    Collection(PathBuf),
    Request(PathBuf),
    Close,
}

impl Quinn {
    fn new(engine: Engine) -> Self {
        Self {
            engine: Arc::new(engine),
            root: None,
            entries: Vec::new(),
            environments: Vec::new(),
            environment: String::new(),
            overrides: String::new(),
            runtime_variables: Variables::new(),
            filter: String::new(),
            selected: None,
            source: String::new(),
            original: String::new(),
            form: None,
            forms_tab: true,
            response: None,
            response_text: String::new(),
            receiver: None,
            error: String::new(),
            response_tab: ResponseTab::Body,
            pending: None,
            new_request: false,
            new_name: String::new(),
        }
    }

    fn dirty(&self) -> bool {
        self.source != self.original
            || self
                .form
                .as_ref()
                .is_some_and(|form| form.apply().map_or(true, |source| source != self.source))
    }

    fn apply_form(&mut self) -> bool {
        let Some(form) = &mut self.form else {
            return true;
        };
        match form.apply() {
            Ok(source) => {
                self.source = source;
                self.form = None;
                true
            }
            Err(error) => {
                form.error = error.to_string();
                self.error = error.to_string();
                false
            }
        }
    }

    fn request_action(&mut self, action: Action, context: &egui::Context) {
        if self.dirty() {
            self.pending = Some(action);
        } else {
            self.apply_action(action, context);
        }
    }

    fn apply_action(&mut self, action: Action, context: &egui::Context) {
        match action {
            Action::Collection(path) => self.load_collection(path),
            Action::Request(path) => self.load_request(path),
            Action::Close => context.send_viewport_cmd(egui::ViewportCommand::Close),
        }
    }

    fn load_collection(&mut self, path: PathBuf) {
        let loaded = (|| {
            let root = collection::root(&path)?;
            let target = std::fs::canonicalize(&path).map_err(|source| quinn_api::Error::Io {
                path: path.clone(),
                source,
            })?;
            let entries = collection::discover(&target)?;
            let environments = collection::environment_names(&root)?;
            Ok::<_, quinn_api::Error>((root, entries, environments))
        })();
        match loaded {
            Ok((root, entries, environments)) => {
                self.root = Some(root);
                self.entries = entries;
                self.environments = environments;
                self.environment.clear();
                self.overrides.clear();
                self.runtime_variables.clear();
                self.selected = None;
                self.source.clear();
                self.original.clear();
                self.form = None;
                self.response = None;
                self.response_text.clear();
                self.error.clear();
                if let Some(path) = self.entries.first().map(|entry| entry.path.clone()) {
                    self.load_request(path);
                }
            }
            Err(error) => self.error = error.to_string(),
        }
    }

    fn load_request(&mut self, path: PathBuf) {
        match collection::read(&path) {
            Ok(source) => {
                if path.extension().is_some_and(|extension| extension == "yml") {
                    self.forms_tab = false;
                }
                self.original = source.clone();
                self.source = source;
                self.form = None;
                self.selected = Some(path);
                self.response = None;
                self.response_text.clear();
                self.error.clear();
            }
            Err(error) => self.error = error.to_string(),
        }
    }

    fn save_request(&mut self) -> bool {
        if !self.apply_form() {
            return false;
        }
        let Some(path) = &self.selected else {
            return false;
        };
        match collection::save(path, &self.original, &self.source) {
            Ok(()) => {
                self.original = self.source.clone();
                self.error.clear();
                true
            }
            Err(error) => {
                self.error = error.to_string();
                false
            }
        }
    }

    fn send(&mut self, context: &egui::Context) {
        if self.receiver.is_some() || self.selected.is_none() {
            return;
        }
        if !self.apply_form() {
            return;
        }
        let prepared = (|| {
            let root = self
                .root
                .as_ref()
                .ok_or_else(|| quinn_api::Error::Invalid {
                    reason: "open a collection first".into(),
                })?;
            let path = self
                .selected
                .as_ref()
                .ok_or_else(|| quinn_api::Error::Invalid {
                    reason: "select a request first".into(),
                })?;
            let request = collection::parse(path, &self.source)?;
            let defaults = collection::defaults(root, path)?;
            let mut variables = if self.environment.is_empty() {
                Variables::new()
            } else {
                collection::environment(root, &self.environment)?
            };
            variables.extend(self.runtime_variables.clone());
            for line in self
                .overrides
                .lines()
                .filter(|line| !line.trim().is_empty())
            {
                let (key, value) =
                    line.split_once('=')
                        .ok_or_else(|| quinn_api::Error::Invalid {
                            reason: "variables must use KEY=VALUE, one per line".into(),
                        })?;
                if key.trim().is_empty() {
                    return Err(quinn_api::Error::Invalid {
                        reason: "variable name is empty".into(),
                    });
                }
                variables.insert(key.trim().to_owned(), value.to_owned());
            }
            Ok::<_, quinn_api::Error>((request, defaults, variables, root.clone()))
        })();
        match prepared {
            Ok((request, defaults, variables, root)) => {
                let engine = Arc::clone(&self.engine);
                let (sender, receiver) = mpsc::channel();
                self.receiver = Some(receiver);
                self.error.clear();
                self.response = None;
                self.response_text.clear();
                let context = context.clone();
                thread::spawn(move || {
                    let _ = sender.send(engine.send_in(&request, &defaults, &variables, &root));
                    context.request_repaint();
                });
            }
            Err(error) => self.error = error.to_string(),
        }
    }

    fn refresh(&mut self) {
        if let Some(root) = &self.root {
            match collection::discover(root) {
                Ok(entries) => self.entries = entries,
                Err(error) => self.error = error.to_string(),
            }
            match collection::environment_names(root) {
                Ok(environments) => self.environments = environments,
                Err(error) => self.error = error.to_string(),
            }
        }
    }

    fn create_request(&mut self, context: &egui::Context) {
        let name = self.new_name.trim();
        if name.is_empty()
            || name.contains(['/', '\\', '\n', '\r', ':'])
            || name.starts_with('.')
            || name == "collection"
            || name == "folder"
        {
            self.error = "Use a request name without slashes, colons, or line breaks.".into();
            return;
        }
        let Some(root) = &self.root else {
            return;
        };
        let yaml = collection::is_yaml(root);
        let path = root.join(format!("{name}.{}", if yaml { "yml" } else { "bru" }));
        let source = if yaml {
            let value = serde_json::json!({"info":{"name":name,"type":"http","seq":self.entries.len()+1},"http":{"method":"GET","url":"https://httpbin.org/get"}});
            match serde_yaml_ng::to_string(&value) {
                Ok(source) => source,
                Err(error) => {
                    self.error = error.to_string();
                    return;
                }
            }
        } else {
            format!(
                "meta {{\n  name: {name}\n  type: http\n  seq: {}\n}}\n\nget {{\n  url: https://httpbin.org/get\n  body: none\n  auth: none\n}}\n",
                self.entries.len() + 1
            )
        };
        let result = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| file.write_all(source.as_bytes()));
        match result {
            Ok(()) => {
                self.new_request = false;
                self.new_name.clear();
                self.refresh();
                self.request_action(Action::Request(path), context);
            }
            Err(error) => self.error = format!("Cannot create request: {error}"),
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        ui.horizontal(|ui| {
            ui.heading("Quinn");
            ui.separator();
            if ui
                .add_enabled(
                    self.receiver.is_none(),
                    egui::Button::new("Open collection…"),
                )
                .clicked()
                && let Some(path) = rfd::FileDialog::new().pick_folder()
            {
                self.request_action(Action::Collection(path), &context);
            }
            if ui
                .add_enabled(
                    self.root.is_some() && self.receiver.is_none(),
                    egui::Button::new("New request"),
                )
                .clicked()
            {
                self.new_request = true;
            }
            if ui
                .add_enabled(
                    self.root.is_some() && self.receiver.is_none(),
                    egui::Button::new("Refresh"),
                )
                .clicked()
            {
                self.refresh();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(
                        self.root.is_some() && self.receiver.is_none(),
                        egui::Button::new("Clear OAuth tokens"),
                    )
                    .on_hover_text(
                        "Clear tokens kept in memory. The next Send acquires a fresh token.",
                    )
                    .clicked()
                {
                    match self.engine.clear_oauth_tokens() {
                        Ok(()) => self.error.clear(),
                        Err(error) => self.error = error.to_string(),
                    }
                }
                egui::widgets::global_theme_preference_switch(ui);
            });
        });
        ui.add_space(6.0);
        let previous_environment = self.environment.clone();
        ui.add_enabled_ui(self.receiver.is_none(), |ui| {
            ui.horizontal(|ui| {
                ui.label("Environment");
                egui::ComboBox::from_id_salt("environment")
                    .selected_text(if self.environment.is_empty() {
                        "No environment"
                    } else {
                        &self.environment
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.environment, String::new(), "No environment");
                        for name in &self.environments {
                            ui.selectable_value(&mut self.environment, name.clone(), name);
                        }
                    });
                if ui
                    .add_enabled(
                        !self.runtime_variables.is_empty(),
                        egui::Button::new("Reset variables"),
                    )
                    .clicked()
                {
                    self.runtime_variables.clear();
                }
                if let Some(root) = &self.root {
                    ui.label(RichText::new(root.display().to_string()).small().weak());
                }
            });
        });
        if self.environment != previous_environment {
            self.runtime_variables.clear();
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.heading("Collection");
        ui.add_space(8.0);
        ui.add(
            TextEdit::singleline(&mut self.filter)
                .hint_text("Filter requests")
                .desired_width(f32::INFINITY),
        );
        ui.add_space(8.0);
        let mut clicked = None;
        ScrollArea::vertical().id_salt("requests").show(ui, |ui| {
            let mut folder = None;
            for entry in &self.entries {
                let relative = self
                    .root
                    .as_ref()
                    .and_then(|root| entry.path.strip_prefix(root).ok())
                    .unwrap_or(&entry.path);
                let current = relative
                    .parent()
                    .map(|parent| parent.display().to_string())
                    .unwrap_or_default();
                if !self.filter.is_empty()
                    && !entry
                        .name
                        .to_lowercase()
                        .contains(&self.filter.to_lowercase())
                    && !relative
                        .to_string_lossy()
                        .to_lowercase()
                        .contains(&self.filter.to_lowercase())
                {
                    continue;
                }
                if folder.as_ref() != Some(&current) {
                    if !current.is_empty() {
                        ui.add_space(8.0);
                        ui.label(RichText::new(&current).small().weak());
                    }
                    folder = Some(current);
                }
                let selected = self.selected.as_ref() == Some(&entry.path);
                if ui
                    .add_enabled(
                        self.receiver.is_none(),
                        egui::Button::selectable(selected, &entry.name),
                    )
                    .on_hover_text(relative.display().to_string())
                    .clicked()
                {
                    clicked = Some(entry.path.clone());
                }
            }
            if self.root.is_some() && self.entries.is_empty() {
                ui.label("No requests yet. Create a request to start.");
            }
        });
        if let Some(path) = clicked {
            self.request_action(Action::Request(path), ui.ctx());
        }
    }

    fn editor(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        if self.selected.is_none() {
            ui.vertical_centered(|ui| {
                ui.add_space(70.0);
                ui.heading("Your APIs, on your filesystem");
                ui.add_space(12.0);
                ui.label("Open a Bruno collection folder to browse, edit, and send requests.");
                ui.label("Try the included examples/starter collection.");
            });
            return;
        }
        ui.horizontal(|ui| {
            let name = self
                .selected
                .as_ref()
                .and_then(|path| path.file_name())
                .unwrap_or_default()
                .to_string_lossy();
            ui.heading(format!("{name}{}", if self.dirty() { " *" } else { "" }));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(
                        self.receiver.is_none(),
                        egui::Button::new(if self.receiver.is_some() {
                            "Sending…"
                        } else {
                            "Send  ⌘/Ctrl+Enter"
                        })
                        .fill(Color32::from_rgb(40, 115, 85)),
                    )
                    .clicked()
                {
                    self.send(&context);
                }
                if ui
                    .add_enabled(self.dirty(), egui::Button::new("Save  ⌘/Ctrl+S"))
                    .clicked()
                {
                    self.save_request();
                }
            });
        });
        ui.horizontal(|ui| {
            let yaml = self
                .selected
                .as_ref()
                .is_some_and(|path| path.extension().is_some_and(|extension| extension == "yml"));
            if yaml {
                self.forms_tab = false;
                ui.label("YAML requests use the Source editor.");
            } else {
                ui.selectable_value(&mut self.forms_tab, true, "Forms");
            }
            ui.selectable_value(&mut self.forms_tab, false, "Source");
            if !yaml {
                ui.label(
                    RichText::new("Send and Save apply form changes.")
                        .small()
                        .weak(),
                );
            }
        });
        ui.add_space(8.0);
        ScrollArea::vertical()
            .id_salt("request_editor")
            .max_height((ui.available_height() * 0.48).max(130.0))
            .show(ui, |ui| {
                if self.forms_tab {
                    if self.form.is_none() {
                        match RequestForm::parse(&self.source) {
                            Ok(form) => self.form = Some(form),
                            Err(error) => {
                                ui.colored_label(ui.visuals().error_fg_color, error.to_string());
                                ui.label("Open Source to edit this request. Its contents have not changed.");
                            }
                        }
                    }
                    if let Some(form) = &mut self.form && form.show(ui) {
                        self.apply_form();
                    }
                } else {
                    if self.form.as_ref().is_some_and(|form| form.apply().map_or(true, |source| source != self.source)) {
                        ui.label("Apply or discard form changes before editing Source.");
                        if ui.button("Apply form changes").clicked() { self.apply_form(); }
                        if ui.button("Discard form changes").clicked() { self.form = None; }
                    }
                    let form_changed = self.form.as_ref().is_some_and(|form| form.apply().map_or(true, |source| source != self.source));
                    if ui.add_enabled(!form_changed, TextEdit::multiline(&mut self.source)
                        .code_editor()
                        .font(FontId::monospace(13.0))
                        .desired_width(f32::INFINITY)
                        .desired_rows(14),
                    ).changed() { self.form = None; }
                }
            });
        egui::CollapsingHeader::new("Variable overrides (kept in memory)").show(ui, |ui| {
            ui.add(
                TextEdit::multiline(&mut self.overrides)
                    .code_editor()
                    .hint_text("baseUrl=https://api.example.com\ntoken=YOUR_TOKEN")
                    .desired_width(f32::INFINITY)
                    .desired_rows(2),
            );
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.heading("Response");
            if let Some(response) = &self.response {
                let color = if response.passed() {
                    Color32::from_rgb(100, 195, 140)
                } else {
                    Color32::from_rgb(240, 130, 115)
                };
                ui.label(
                    RichText::new(response.status.to_string())
                        .color(color)
                        .strong(),
                );
                ui.label(format!(
                    "{} ms   {} bytes",
                    response.elapsed_ms, response.bytes
                ));
                if ui.button("Copy body").clicked() {
                    context.copy_text(response.body.clone());
                }
            }
            if self.receiver.is_some() {
                ui.spinner();
            }
        });
        if self.response.is_some() {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.response_tab, ResponseTab::Body, "Body");
                ui.selectable_value(&mut self.response_tab, ResponseTab::Headers, "Headers");
                ui.selectable_value(
                    &mut self.response_tab,
                    ResponseTab::Assertions,
                    "Assertions",
                );
            });
            ScrollArea::both().id_salt("response").show(ui, |ui| {
                if let Some(response) = &self.response {
                    match self.response_tab {
                        ResponseTab::Body => {
                            let mut body = self.response_text.as_str();
                            ui.add(
                                TextEdit::multiline(&mut body)
                                    .code_editor()
                                    .desired_width(f32::INFINITY),
                            );
                        }
                        ResponseTab::Headers => {
                            for (key, value) in &response.headers {
                                ui.monospace(format!("{key}: {value}"));
                            }
                        }
                        ResponseTab::Assertions => {
                            if response.assertions.is_empty() {
                                ui.label("This request has no assertions.");
                            }
                            for assertion in &response.assertions {
                                ui.label(format!(
                                    "{}  {}: {}  (actual: {})",
                                    if assertion.passed { "PASS" } else { "FAIL" },
                                    assertion.expression,
                                    assertion.expected,
                                    assertion.actual
                                ));
                            }
                        }
                    }
                }
            });
        } else if self.receiver.is_none() {
            ui.label(RichText::new("Send a request to inspect its response.").weak());
        }
    }

    fn dialogs(&mut self, context: &egui::Context) {
        if self.pending.is_some() {
            let mut save = false;
            let mut discard = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("unsaved")).show(context, |ui| {
                ui.heading("Save your changes?");
                ui.label("This request contains unsaved edits.");
                ui.horizontal(|ui| {
                    save = ui.button("Save and continue").clicked();
                    discard = ui.button("Discard edits").clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
            if cancel {
                self.pending = None;
            }
            if (discard || (save && self.save_request()))
                && let Some(action) = self.pending.take()
            {
                if discard {
                    self.source = self.original.clone();
                    self.form = None;
                }
                self.apply_action(action, context);
            }
        }
        if self.new_request {
            let mut create = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("new_request")).show(context, |ui| {
                ui.heading("New request");
                ui.label("Request name");
                ui.add(TextEdit::singleline(&mut self.new_name).hint_text("Get users"));
                ui.horizontal(|ui| {
                    create = ui.button("Create").clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
            if cancel {
                self.new_request = false;
            }
            if create {
                self.create_request(context);
            }
        }
    }
}

impl eframe::App for Quinn {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        if let Some(receiver) = &self.receiver {
            match receiver.try_recv() {
                Ok(Ok(response)) => {
                    self.runtime_variables.extend(response.variables.clone());
                    self.error = response.variable_errors.join("; ");
                    self.response_text = response.pretty_body();
                    self.response = Some(response);
                    self.receiver = None;
                }
                Ok(Err(error)) => {
                    self.error = error.to_string();
                    self.receiver = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.error = "Request worker stopped unexpectedly.".into();
                    self.receiver = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if context.input(|input| input.viewport().close_requested()) && self.dirty() {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.pending = Some(Action::Close);
        }
        if context.input_mut(|input| {
            input.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::S))
        }) {
            self.save_request();
        }
        if context.input_mut(|input| {
            input.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::Enter))
        }) {
            self.send(&context);
        }
        egui::Panel::top("toolbar").exact_size(64.0).show(ui, |ui| {
            self.toolbar(ui);
        });
        egui::Panel::bottom("status")
            .exact_size(28.0)
            .show(ui, |ui| {
                if self.error.is_empty() {
                    ui.label(
                        RichText::new("Local collections · Rust request engine")
                            .small()
                            .weak(),
                    );
                } else {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(Color32::from_rgb(240, 130, 115), &self.error);
                        if ui.small_button("Dismiss").clicked() {
                            self.error.clear();
                        }
                    });
                }
            });
        egui::Panel::left("collection")
            .resizable(true)
            .default_size(245.0)
            .size_range(180.0..=440.0)
            .show(ui, |ui| {
                self.sidebar(ui);
            });
        egui::CentralPanel::default().show(ui, |ui| {
            self.editor(ui);
        });
        self.dialogs(&context);
    }
}
