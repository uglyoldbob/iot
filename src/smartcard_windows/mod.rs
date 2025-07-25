//! Contains all of the window code for the gui.

use egui_multiwin::enum_dispatch::enum_dispatch;

use crate::egui_multiwin_dynamic::tracked_window::{RedrawResponse, TrackedWindow};
use egui_multiwin::egui_glow::EguiGlow;
use std::sync::Arc;

/// The smartcard root window module
pub mod smartcard_root;

#[enum_dispatch(TrackedWindow)]
/// The list of all possible application windows
pub enum MyWindows {
    /// The smartcard application window
    SmartcardRoot(smartcard_root::RootWindow),
}
