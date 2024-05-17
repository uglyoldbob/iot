use std::sync::{Arc, Mutex};

use crate::{
    egui_multiwin_dynamic::{
        multi_window::NewWindowRequest,
        tracked_window::{RedrawResponse, TrackedWindow},
    },
    main_config::MainConfigurationAnswers,
};
use egui_multiwin::egui_glow::EguiGlow;
use interprocess::local_socket::ToFsName;
use userprompt::EguiPrompting;

use crate::AppCommon;

/// Specifies how the system should process input and provide feedback to the user
enum GeneratingMode {
    /// The system is ready to accept input from the user
    Idle,
    /// The generation binary is currently running
    Generating,
    /// There was an error in the generation program
    Error(i32),
    /// Done generating an iot instance
    Done,
}

/// The struct for the root window
pub struct RootWindow {
    /// The answers to construct and pass to the construction binary
    answers: MainConfigurationAnswers,
    /// The name of the service
    service_name: String,
    /// The mode for showing when the instance is being generated
    generating: Arc<Mutex<GeneratingMode>>,
}

impl RootWindow {
    /// Create a request for a new window
    pub fn request() -> NewWindowRequest {
        let mut answers = MainConfigurationAnswers::default();
        answers.username = whoami::username();
        NewWindowRequest::new(
            super::MyWindows::Root(RootWindow {
                answers,
                service_name: "default".into(),
                generating: Arc::new(Mutex::new(GeneratingMode::Idle)),
            }),
            egui_multiwin::winit::window::WindowBuilder::new()
                .with_resizable(true)
                .with_inner_size(egui_multiwin::winit::dpi::LogicalSize {
                    width: 800.0,
                    height: 600.0,
                })
                .with_title("Certificate Authority Service Builder"),
            egui_multiwin::tracked_window::TrackedWindowOptions {
                vsync: false,
                shader: None,
            },
            egui_multiwin::multi_window::new_id(),
        )
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
        let quit = false;

        let windows_to_create = vec![];

        egui_multiwin::egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {
            let mut m = self.generating.lock().unwrap();
            egui_multiwin::egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| match *m {
                    GeneratingMode::Idle => {
                        ui.label("Name of the service");
                        ui.text_edit_singleline(&mut self.service_name);
                        let reason_no_generate = self.answers.build_gui(ui, None);
                        if reason_no_generate.is_ok() {
                            let mut config = crate::main_config::MainConfiguration::new();
                            config.provide_answers(&self.answers);
                        }
                        if let Err(reason) = reason_no_generate {
                            ui.label("Not ready to generate service");
                            ui.label(reason.to_string());
                        } else if ui.button("Build config").clicked() {
                            let tfile = tempfile::NamedTempFile::new().unwrap();
                            let ipc_name = tfile.path().to_owned();
                            drop(tfile);
                            println!("Name for ipc is {}", ipc_name.display());
                            let lipc_name = ipc_name
                                .clone()
                                .to_fs_name::<interprocess::local_socket::GenericFilePath>()
                                .unwrap();
                            let opts =
                                interprocess::local_socket::ListenerOptions::new().name(lipc_name);
                            let local_socket = opts.create_sync().unwrap();
                            println!("Launching process");
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
                                use interprocess::local_socket::traits::Listener;
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
                });
        });
        RedrawResponse {
            quit,
            new_windows: windows_to_create,
        }
    }
}
