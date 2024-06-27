#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(unused_extern_crates)]

//! This binary is a gui app used to construct the elements necessary to operate an iot instance.

mod main_config;

pub use main_config::MainConfiguration;

#[path = "ca/ca_usage.rs"]
/// The ca module, with code used to construct a ca
mod ca;
mod card;
mod hsm2;
mod tpm2;

use egui_multiwin_dynamic::multi_window::{MultiWindow, NewWindowRequest};

/// The gui library code
pub mod egui_multiwin_dynamic {
    egui_multiwin::tracked_window!(
        crate::AppCommon,
        egui_multiwin::NoEvent,
        crate::windows::MyWindows
    );
    egui_multiwin::multi_window!(
        crate::AppCommon,
        egui_multiwin::NoEvent,
        crate::windows::MyWindows
    );
}

mod windows;

use windows::root;

/// The common data for the gui
pub struct AppCommon {}

impl AppCommon {
    /// Process events sent to the gui
    fn process_event(&mut self, _event: egui_multiwin::NoEvent) -> Vec<NewWindowRequest> {
        Vec::new()
    }
}

fn main() {
    let mut event_loop = egui_multiwin::winit::event_loop::EventLoopBuilder::with_user_event();
    let event_loop = event_loop.build().unwrap();
    let mut multi_window: MultiWindow = MultiWindow::new();
    let root_window = root::RootWindow::request();

    let mut ac = AppCommon {};

    let _e = multi_window.add(root_window, &mut ac, &event_loop);
    multi_window.run(event_loop, ac).unwrap();
}
