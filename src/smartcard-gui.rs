#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]
#![allow(unused)]

//! This binary is a gui app used to work with smartcards.

mod main_config;

pub use main_config::MainConfiguration;

#[path = "ca/ca_common.rs"]
/// The ca module, with code used to construct a ca
mod ca;
mod hsm2;
mod tpm2;
mod utility;

use egui_multiwin_dynamic::multi_window::{MultiWindow, NewWindowRequest};

/// The gui library code
pub mod egui_multiwin_dynamic {
    egui_multiwin::tracked_window!(
        crate::AppCommon,
        egui_multiwin::NoEvent,
        crate::smartcard_windows::MyWindows
    );
    egui_multiwin::multi_window!(
        crate::AppCommon,
        egui_multiwin::NoEvent,
        crate::smartcard_windows::MyWindows
    );
}

mod smartcard_windows;

use smartcard_windows::smartcard_root;

/// The common data for the gui
pub struct AppCommon {
    /// object to send messages to the async code
    pub send: tokio::sync::mpsc::Sender<smartcard_root::Message>,
    /// object to receive messages from the async code
    pub recv: tokio::sync::mpsc::Receiver<smartcard_root::Response>,
}

impl AppCommon {
    /// Process events sent to the gui
    fn process_event(&mut self, _event: egui_multiwin::NoEvent) -> Vec<NewWindowRequest> {
        Vec::new()
    }
}

async fn handle_card_stuff(
    mut recv: tokio::sync::mpsc::Receiver<smartcard_root::Message>,
    send: tokio::sync::mpsc::Sender<smartcard_root::Response>,
) {
    while let Some(m) = recv.recv().await {
        match m {
            smartcard_root::Message::Exit => {
                send.send(smartcard_root::Response::Done).await.unwrap();
                break;
            }
            smartcard_root::Message::ErasePivCard => {
                let erased = ::card::with_current_valid_piv_card(|card| {
                    let mut cw = card.to_writer();
                    cw.erase_card().is_ok()
                }).await;
                send.send(smartcard_root::Response::Erased(erased))
                    .await
                    .unwrap();
            }
            smartcard_root::Message::GenerateKeypair => {
                let keypair = card::KeyPair::generate_with_smartcard(::card::PIV_PIN_KEY_DEFAULT.to_vec(), "TEST KEYPAIR", false).await;
                let _ = send.send(smartcard_root::Response::KeypairGenerated(keypair)).await;
            }
            _ => {}
        }
    }
}

fn main() {
    let mut event_loop = egui_multiwin::winit::event_loop::EventLoopBuilder::with_user_event();
    let event_loop = event_loop.build().unwrap();
    let mut multi_window: MultiWindow = MultiWindow::new();
    let root_window = smartcard_root::RootWindow::request();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let ch = tokio::sync::mpsc::channel(10);
    let ch2 = tokio::sync::mpsc::channel(10);
    let asdf = runtime.spawn(handle_card_stuff(ch.1, ch2.0));

    let mut ac = AppCommon {
        send: ch.0,
        recv: ch2.1,
    };

    let _e = multi_window.add(root_window, &mut ac, &event_loop);
    multi_window.run(event_loop, ac).unwrap();
}
