use std::sync::{Arc, Mutex};

use crate::{
    ca::PkiConfigurationEnum,
    egui_multiwin_dynamic::{
        multi_window::NewWindowRequest,
        tracked_window::{RedrawResponse, TrackedWindow},
    },
    main_config::MainConfigurationAnswers,
};
use egui_multiwin::egui_glow::EguiGlow;

use crate::AppCommon;

/// Defines messages that can some from other threads
enum Message {
    ///The schematic is being loaded
    HttpsCertificateName(std::path::PathBuf),
    /// A path is selected for the certificate authority
    CaPathSelected(crate::ca::CaCertificateStorageBuilder),
}

enum GeneratingMode {
    Idle,
    Generating,
    Error(i32),
    Done,
}

pub struct RootWindow {
    answers: MainConfigurationAnswers,
    service_name: String,
    username: String,
    generating: Arc<Mutex<GeneratingMode>>,
    message_channel: (
        std::sync::mpsc::Sender<Message>,
        std::sync::mpsc::Receiver<Message>,
    ),
}

impl RootWindow {
    pub fn request() -> NewWindowRequest {
        NewWindowRequest {
            window_state: super::MyWindows::Root(RootWindow {
                answers: MainConfigurationAnswers::default(),
                service_name: "default".into(),
                username: whoami::username(),
                generating: Arc::new(Mutex::new(GeneratingMode::Idle)),
                message_channel: std::sync::mpsc::channel(),
            }),
            builder: egui_multiwin::winit::window::WindowBuilder::new()
                .with_resizable(true)
                .with_inner_size(egui_multiwin::winit::dpi::LogicalSize {
                    width: 800.0,
                    height: 600.0,
                })
                .with_title("egui-multiwin root window"),
            options: egui_multiwin::tracked_window::TrackedWindowOptions {
                vsync: false,
                shader: None,
            },
            id: egui_multiwin::multi_window::new_id(),
        }
    }
}

impl TrackedWindow for RootWindow {
    fn is_root(&self) -> bool {
        true
    }

    fn set_root(&mut self, _root: bool) {}

    fn redraw(
        &mut self,
        _c: &mut AppCommon,
        egui: &mut EguiGlow,
        _window: &egui_multiwin::winit::window::Window,
        _clipboard: &mut egui_multiwin::arboard::Clipboard,
    ) -> RedrawResponse {
        egui.egui_ctx.request_repaint();

        let quit = false;

        let windows_to_create = vec![];

        while let Ok(message) = self.message_channel.1.try_recv() {
            match message {
                Message::HttpsCertificateName(n) => {
                    self.answers.https.certificate = n;
                }
                Message::CaPathSelected(p) => {
                    if let PkiConfigurationEnum::Ca(ca) = &mut self.answers.pki {
                        ca.path = p;
                    }
                }
            }
        }

        egui_multiwin::egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {
            let mut m = self.generating.lock().unwrap();
            egui_multiwin::egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                match *m {
                    GeneratingMode::Idle => {
                        ui.label("User to run service as");
                        ui.text_edit_singleline(&mut self.username);
                        ui.label("Name of the service");
                        ui.text_edit_singleline(&mut self.service_name);
                        ui.label("Cookie name");
                        ui.text_edit_singleline(&mut self.answers.general.cookie);
                        let mut proxy = self.answers.general.proxy.is_some();
                        ui.checkbox(&mut proxy, "Use proxy");
                        if proxy && self.answers.general.proxy.is_none() {
                            self.answers.general.proxy = Some(String::new());
                        }
                        if !proxy && self.answers.general.proxy.is_some() {
                            self.answers.general.proxy = None;
                        }
                        if let Some(proxy) = &mut self.answers.general.proxy {
                            ui.text_edit_singleline(proxy);
                        }
                        ui.label("Static content");
                        ui.text_edit_singleline(&mut self.answers.general.static_content);
                        {
                            ui.label("Administrator password");
                            let p: &mut String = &mut self.answers.admin.pass;
                            let pe = egui_multiwin::egui::TextEdit::singleline(p).password(true);
                            ui.add(pe);
                            let p2: &mut String = self.answers.admin.pass.second();
                            let pe = egui_multiwin::egui::TextEdit::singleline(p2).password(true);
                            ui.add(pe);
                        }
                        ui.heading("HTTP SERVER SETTINGS");
                        ui.checkbox(&mut self.answers.http.enabled, "Enabled");
                        if self.answers.http.enabled {
                            ui.label("Port");
                            let mut s = format!("{}", self.answers.http.port);
                            if ui.text_edit_singleline(&mut s).changed() {
                                let v = s.parse();
                                if let Ok(v) = v {
                                    self.answers.http.port = v;
                                }
                            }
                        }
                        ui.heading("HTTPS SERVER SETTINGS");
                        ui.checkbox(&mut self.answers.https.enabled, "Enabled");
                        if self.answers.https.enabled {
                            ui.label("Port");
                            let mut s = format!("{}", self.answers.https.port);
                            if ui.text_edit_singleline(&mut s).changed() {
                                let v = s.parse();
                                if let Ok(v) = v {
                                    self.answers.https.port = v;
                                }
                            }
                            ui.label(format!(
                                "Certificate file: {}",
                                self.answers.https.certificate.display()
                            ));
                            if ui.button("Select certificate file").clicked() {
                                let f = rfd::AsyncFileDialog::new()
                                    .add_filter("Pkcs12 Certificate", &["p12"])
                                    .set_title("Load Certificate file")
                                    .pick_file();
                                let message_sender = self.message_channel.0.clone();
                                crate::execute(async move {
                                    let file = f.await;
                                    if let Some(file) = file {
                                        let fname = file.path().to_path_buf();
                                        message_sender
                                            .send(Message::HttpsCertificateName(fname))
                                            .ok();
                                    }
                                });
                            }
                            ui.label("Certificate password");
                            let p: &mut String = &mut self.answers.https.certpass;
                            let pe = egui_multiwin::egui::TextEdit::singleline(p).password(true);
                            ui.add(pe);
                            let p2: &mut String = self.answers.https.certpass.second();
                            let pe = egui_multiwin::egui::TextEdit::singleline(p2).password(true);
                            ui.add(pe);
                        }
                        use strum::IntoEnumIterator;
                        egui_multiwin::egui::ComboBox::from_label("Select a type!")
                            .selected_text(self.answers.pki.display())
                            .show_ui(ui, |ui| {
                                for option in PkiConfigurationEnum::iter() {
                                    if ui.selectable_label(false, option.display()).clicked() {
                                        self.answers.pki = option;
                                    }
                                }
                            });
                        match &mut self.answers.pki {
                            PkiConfigurationEnum::Pki(pki) => {
                                ui.label("Not implemented yet");
                            }
                            PkiConfigurationEnum::Ca(ca) => {
                                egui_multiwin::egui::ComboBox::from_label("Select a storage medium!")
                                    .selected_text(ca.path.display())
                                    .show_ui(ui, |ui| {
                                        for option in crate::ca::CaCertificateStorageBuilder::iter() {
                                            if ui.selectable_label(false, option.display()).clicked() {
                                                ca.path = option;
                                            }
                                        }
                                    });
                                match &mut ca.path {
                                    crate::ca::CaCertificateStorageBuilder::Nowhere => {
                                        ui.label("No configurable options");
                                    }
                                    crate::ca::CaCertificateStorageBuilder::Sqlite(p) => {
                                        if ui.button("Select database location").clicked() {
                                            let f = rfd::AsyncFileDialog::new()
                                                .add_filter("Sqlite database", &["sqlite"])
                                                .set_title("Save Sqlite database")
                                                .save_file();
                                            let message_sender = self.message_channel.0.clone();
                                            crate::execute(async move {
                                                let file = f.await;
                                                if let Some(file) = file {
                                                    let fname = file.path().to_path_buf();
                                                    let path = crate::ca::CaCertificateStorageBuilder::Sqlite(fname);
                                                    message_sender
                                                        .send(Message::CaPathSelected(path))
                                                        .ok();
                                                }
                                            });
                                        }
                                    }
                                }
                                ui.checkbox(&mut ca.root, "Root authority");
                                ui.label("Subject alternate names, one per line");
                                let mut s = ca.san.join("\n");
                                if ui.text_edit_multiline(&mut s).changed() {
                                    let names = s.split("\n");
                                    let names: Vec<&str> = names.collect();
                                    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
                                    ca.san = names;
                                }
                                ui.label("Common name of the authority");
                                ui.text_edit_singleline(&mut ca.common_name);
                                {
                                    ui.label("Number of days the authority should last");
                                    let mut s = format!("{}", ca.days);
                                    if ui.text_edit_singleline(&mut s).changed() {
                                        let v = s.parse();
                                        if let Ok(v) = v {
                                            ca.days = v;
                                        }
                                    }
                                }
                                {
                                    ui.label("Maximum chain length for authorities");
                                    let mut s = format!("{}", ca.chain_length);
                                    if ui.text_edit_singleline(&mut s).changed() {
                                        let v = s.parse();
                                        if let Ok(v) = v {
                                            ca.chain_length = v;
                                        }
                                    }
                                }
                                {
                                    ui.label("Administrator access password");
                                    let p: &mut String = &mut ca.admin_access_password;
                                    let pe = egui_multiwin::egui::TextEdit::singleline(p).password(true);
                                    ui.add(pe);
                                    let p2: &mut String = ca.admin_access_password.second();
                                    let pe = egui_multiwin::egui::TextEdit::singleline(p2).password(true);
                                    ui.add(pe);
                                }
                                {
                                    ui.label("Administrator certificate password");
                                    let p: &mut String = &mut ca.admin_password;
                                    let pe = egui_multiwin::egui::TextEdit::singleline(p).password(true);
                                    ui.add(pe);
                                    let p2: &mut String = ca.admin_password.second();
                                    let pe = egui_multiwin::egui::TextEdit::singleline(p2).password(true);
                                    ui.add(pe);
                                }
                                {
                                    ui.label("Ocsp certificate password");
                                    let p: &mut String = &mut ca.ocsp_password;
                                    let pe = egui_multiwin::egui::TextEdit::singleline(p).password(true);
                                    ui.add(pe);
                                    let p2: &mut String = ca.ocsp_password.second();
                                    let pe = egui_multiwin::egui::TextEdit::singleline(p2).password(true);
                                    ui.add(pe);
                                }
                                {
                                    ui.label("Root certificate password");
                                    let p: &mut String = &mut ca.root_password;
                                    let pe = egui_multiwin::egui::TextEdit::singleline(p).password(true);
                                    ui.add(pe);
                                    let p2: &mut String = ca.root_password.second();
                                    let pe = egui_multiwin::egui::TextEdit::singleline(p2).password(true);
                                    ui.add(pe);
                                }
                                ui.checkbox(&mut ca.ocsp_signature, "Ocsp request requires signature");
                            }
                        }

                        let mut reason_no_generate = None;
                        if self.answers.admin.pass.is_empty() {
                            reason_no_generate = Some("Admin password is empty");
                        }
                        if reason_no_generate.is_none() && !self.answers.admin.pass.matches() {
                            reason_no_generate = Some("Admin passwords do not match");
                        }
                        if reason_no_generate.is_none()
                            && self.answers.https.enabled
                            && !self.answers.https.certpass.matches()
                        {
                            reason_no_generate = Some("HTTPS Certificate passwords do not match");
                        }
                        if reason_no_generate.is_none() {
                            match &self.answers.pki {
                                PkiConfigurationEnum::Pki(pki) => { }
                                PkiConfigurationEnum::Ca(ca) => {
                                    if !ca.admin_access_password.matches() {
                                        reason_no_generate = Some("Admin access password does not match");
                                    } else if !ca.admin_password.matches() {
                                        reason_no_generate = Some("Admin password does not match");
                                    } else if !ca.ocsp_password.matches() {
                                        reason_no_generate = Some("Ocsp password does not match");
                                    } else if !ca.root_password.matches() {
                                        reason_no_generate = Some("Root password does not match");
                                    }
                                }
                            }
                        }
                        if let Some(reason) = reason_no_generate {
                            ui.label("Not ready to generate service");
                            ui.label(format!("{}", reason));
                        } else {
                            if ui.button("Build config").clicked() {
                                let tfile = tempfile::NamedTempFile::new().unwrap();
                                let ipc_name = tfile.path().to_owned();
                                drop(tfile);
                                println!("Name for ipc is {}", ipc_name.display());
                                let local_socket =
                                    interprocess::local_socket::LocalSocketListener::bind(
                                        ipc_name.clone(),
                                    )
                                    .unwrap();
                                println!("Launching process");
                                let username = self.username.clone();
                                let mode = self.generating.clone();
                                let sname = self.service_name.clone();
                                std::thread::spawn(move || {
                                    {
                                        let mut m = mode.lock().unwrap();
                                        *m = GeneratingMode::Generating;
                                    }
                                    let mut exe = std::env::current_exe().unwrap();
                                    exe.pop();
                                    let asdf = runas::Command::new(exe.join("rust-iot-construct"))
                                        .show(true)
                                        .gui(true)
                                        .arg(format!("--ipc={}", ipc_name.display()))
                                        .arg(format!("--name={}", sname))
                                        .arg(format!("--user={}", username))
                                        .status()
                                        .unwrap();
                                    println!("{:?}", asdf.code());
                                    if asdf.success() {
                                        {
                                            let mut m = mode.lock().unwrap();
                                            *m = GeneratingMode::Done;
                                        }
                                    } else {
                                        {
                                            let mut m = mode.lock().unwrap();
                                            *m = GeneratingMode::Error(asdf.code().unwrap());
                                        }
                                    }
                                });
                                let answers = self.answers.clone();
                                std::thread::spawn(move || {
                                    println!("Waiting for connection from process");
                                    let mut stream = local_socket.accept().unwrap();
                                    println!("Sending answers");
                                    std::io::Write::write_all(
                                        &mut stream,
                                        &bincode::serialize(&answers).unwrap(),
                                    )
                                    .expect("Failed to send answers to build service");
                                    println!("Done sending answers");
                                });
                            }
                        }
                    }
                    GeneratingMode::Generating => {
                        ui.label("Generating service configuration");
                    }
                    GeneratingMode::Error(code) => {
                        ui.label(format!("There was an error generating the config {}", code));
                        if ui.button("Try again").clicked() {
                            *m = GeneratingMode::Idle;
                        }
                    }
                    GeneratingMode::Done => {
                        ui.label("Finished generating service configuration");
                        if ui.button("Generate another").clicked() {
                            self.answers = MainConfigurationAnswers::default();
                            *m = GeneratingMode::Idle;
                        }
                    }
                }
            });
        });
        RedrawResponse {
            quit,
            new_windows: windows_to_create,
        }
    }
}