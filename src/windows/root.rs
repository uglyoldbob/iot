use crate::{
    egui_multiwin_dynamic::{
        multi_window::NewWindowRequest,
        tracked_window::{RedrawResponse, TrackedWindow},
    },
    main_config::MainConfigurationAnswers,
};
use egui_multiwin::egui_glow::EguiGlow;
use serde::Serialize;

use crate::AppCommon;

pub struct RootWindow {
    answers: MainConfigurationAnswers,
    username: String,
}

impl RootWindow {
    pub fn request() -> NewWindowRequest {
        NewWindowRequest {
            window_state: super::MyWindows::Root(RootWindow {
                answers: MainConfigurationAnswers::default(),
                username: "pki".to_string(),
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
        c: &mut AppCommon,
        egui: &mut EguiGlow,
        _window: &egui_multiwin::winit::window::Window,
        _clipboard: &mut egui_multiwin::arboard::Clipboard,
    ) -> RedrawResponse {
        let mut quit = false;

        let mut windows_to_create = vec![];

        egui_multiwin::egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {
            ui.label("User to run service as");
            ui.text_edit_singleline(&mut self.username);
            ui.label("Cookie name");
            ui.text_edit_singleline(&mut self.answers.general.cookie);
            {
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
                ui.label("password test");
                let p: &mut String = &mut self.answers.admin.pass;
                let pe = egui_multiwin::egui::TextEdit::singleline(p).password(true);
                ui.add(pe);
                if ui.button("Build config").clicked() {
                    let asdf = runas::Command::new("./target/debug/rust-iot-construct")
                        .show(true)
                        .gui(true)
                        .arg(format!("--user={}", self.username))
                        .status()
                        .unwrap();
                }
            }
        });
        RedrawResponse {
            quit,
            new_windows: windows_to_create,
        }
    }
}
