use std::{
    io::Read,
    sync::{Arc, Mutex},
};

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

/// A message sent to the async code
pub enum Message {
    /// The async code should send a reply then exit
    Exit,
    /// Erase the piv card
    ErasePivCard,
    /// Generate a keypair
    GenerateKeypair,
}

enum EraseStatus {
    Idle,
    Confirming,
    Erasing,
    Success,
    Failed,
}

/// A response from the async code
pub enum Response {
    /// The async code is about to exit
    Done,
    /// The card was erased with the given status, true if successful
    Erased(bool),
    /// A keypair generated
    KeypairGenerated(Option<card::KeyPair>),
}

/// The struct for the root window
pub struct RootWindow {
    /// We are expecting a response from the async
    expecting_response: bool,
    /// The erase status of the smartcard
    erase_status: EraseStatus,
    /// The keypair of the smartcard
    keypair: Option<card::KeyPair>,
    /// Notes to present to the user
    notes: Vec<String>,
    /// The optional smartcard simulator
    simulator: Option<crate::utility::DroppingProcess>,
}

impl RootWindow {
    /// Create a request for a new window
    pub fn request() -> NewWindowRequest {
        let answers = MainConfigurationAnswers {
            username: whoami::username(),
            ..Default::default()
        };
        NewWindowRequest::new(
            super::MyWindows::SmartcardRoot(RootWindow {
                expecting_response: false,
                erase_status: EraseStatus::Idle,
                keypair: None,
                notes: Vec::new(),
                simulator: None,
            }),
            egui_multiwin::winit::window::WindowBuilder::new()
                .with_resizable(true)
                .with_inner_size(egui_multiwin::winit::dpi::LogicalSize {
                    width: 800.0,
                    height: 600.0,
                })
                .with_title("Certificate Authority Smartcard Manager"),
            egui_multiwin::tracked_window::TrackedWindowOptions {
                vsync: false,
                shader: None,
            },
            egui_multiwin::multi_window::new_id(),
        )
    }
}

/// Receive a string from a local socket stream, sent length first, 4 bytes, le, then bytes of utf8
fn receive_string(
    stream: &mut interprocess::local_socket::prelude::LocalSocketStream,
) -> Option<String> {
    let mut asdf = [0, 0, 0, 0];
    if stream.read_exact(&mut asdf).is_ok() {
        let total_len = u32::from_le_bytes(asdf);
        if total_len != 0 {
            let mut m: Vec<u8> = vec![0; total_len as usize];
            stream.read_exact(&mut m).unwrap();
            Some(String::from_utf8(m).unwrap())
        } else {
            None
        }
    } else {
        None
    }
}

impl TrackedWindow for RootWindow {
    fn is_root(&self) -> bool {
        true
    }

    fn can_quit(&mut self, c: &mut crate::AppCommon) -> bool {
        let _ = c.send.blocking_send(Message::Exit);
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

        let windows_to_create = vec![];

        if self.expecting_response {
            egui.egui_ctx.request_repaint();
            match c.recv.try_recv() {
                Ok(response) => {
                    self.expecting_response = false;
                    match response {
                        Response::Erased(s) => {
                            if s {
                                self.erase_status = EraseStatus::Success;
                            } else {
                                self.erase_status = EraseStatus::Failed;
                            }
                        }
                        Response::KeypairGenerated(_s) => {
                            self.notes.push("Keypair generated".to_string());
                        }
                        Response::Done => {
                            quit = true;
                        }
                    }
                }
                Err(_) => {}
            }
        }

        egui_multiwin::egui::CentralPanel::default().show(&egui.egui_ctx, |ui| {
            egui_multiwin::egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.label("I am groot");
                    match &self.simulator {
                        Some(sim) => {
                            if ui.button("End simulator").clicked() {
                                self.simulator.take();
                            }
                        }
                        None => {
                            if ui.button("Start simulator").clicked() {
                                self.simulator = crate::utility::run_smartcard_sim();
                            }
                        }
                    }
                    if card::is_card_present().is_some() {
                        ui.label("Card is present");
                        match self.erase_status {
                            EraseStatus::Idle => {
                                if ui.button("Erase card").clicked() {
                                    self.erase_status = EraseStatus::Confirming;
                                }
                            }
                            EraseStatus::Confirming => {
                                ui.label("Are you sure you want to erase the smartcard?");
                                if ui.button("No").clicked() {
                                    self.erase_status = EraseStatus::Idle;
                                }
                                if ui.button("Yes").clicked() {
                                    if c.send.blocking_send(Message::ErasePivCard).is_ok() {
                                        self.erase_status = EraseStatus::Erasing;
                                    }
                                }
                            }
                            EraseStatus::Erasing => {
                                ui.label("Erasing smartcard");
                            }
                            EraseStatus::Success => {
                                ui.label("Successfully erased smartcard");
                            }
                            EraseStatus::Failed => {
                                ui.label("Failed to erase smartcard");
                            }
                        }
                        if ui.button("Generate a keypair").clicked() {
                            c.send.blocking_send(Message::GenerateKeypair);
                        }
                    } else {
                        ui.label("Card is not present");
                        self.keypair = None;
                        self.notes.clear();
                    }
                    if ui.button("Clear notes").clicked() {
                        self.notes.clear();
                    }
                    ui.label("NOTES:");
                    for m in &self.notes {
                        ui.label(m);
                    }
                });
        });
        RedrawResponse {
            quit,
            new_windows: windows_to_create,
        }
    }
}
