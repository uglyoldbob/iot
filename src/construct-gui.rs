mod main_config;

pub use main_config::MainConfiguration;

#[path = "ca_construct.rs"]
mod ca;
pub mod oid;
pub mod pkcs12;
mod tpm2;

use egui_multiwin_dynamic::multi_window::{MultiWindow, NewWindowRequest};

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

pub struct AppCommon {}

impl AppCommon {
    fn process_event(&mut self, _event: egui_multiwin::NoEvent) -> Vec<NewWindowRequest> {
        Vec::new()
    }
}

fn main() {
    let mut event_loop = egui_multiwin::winit::event_loop::EventLoopBuilder::with_user_event();
    let event_loop = event_loop.build();
    let mut multi_window: MultiWindow = MultiWindow::new();
    let root_window = root::RootWindow::request();

    let mut ac = AppCommon {};

    let _e = multi_window.add(root_window, &mut ac, &event_loop);
    multi_window.run(event_loop, ac);
}

#[cfg(not(target_arch = "wasm32"))]
///Run an asynchronous object on a new thread. Maybe not the best way of accomplishing this, but it does work.
fn execute<F: std::future::Future<Output = ()> + Send + 'static>(f: F) {
    std::thread::spawn(move || futures::executor::block_on(f));
}
/// This code will likely not be used, as it makes no sense to try to run this program in wasm
#[cfg(target_arch = "wasm32")]
///Run an asynchronous object on a new thread. Maybe not the best way of accomplishing this, but it does work.
fn execute<F: std::future::Future<Output = ()> + 'static>(f: F) {
    wasm_bindgen_futures::spawn_local(f);
}