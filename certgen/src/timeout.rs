//! Convenience code for handling closures and timeouts on web pages.
//! This is because generics and wasm_bindgen don't work together.

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
/// A handle that takes no arguments for its closure
pub struct TimeoutHandle {
    /// The closure that gets called
    _closure: wasm_bindgen::closure::Closure<dyn FnMut()>,
}

impl TimeoutHandle {
    /// Build a new self
    pub fn new(a: wasm_bindgen::closure::Closure<dyn FnMut()>) -> Self {
        Self { _closure: a }
    }
}

#[wasm_bindgen]
/// This takes a single string as an argument
pub struct TimeoutHandle1 {
    /// The closure that gets called
    _closure: wasm_bindgen::closure::Closure<dyn FnMut(String)>,
}

impl TimeoutHandle1 {
    /// Build a new self
    pub fn new(a: wasm_bindgen::closure::Closure<dyn FnMut(String)>) -> Self {
        Self { _closure: a }
    }
}

#[wasm_bindgen]
/// This takes a CsrWork object as an argument
pub struct TimeoutHandleCsrWork {
    /// The closure that gets called
    _closure: wasm_bindgen::closure::Closure<dyn FnMut(super::CsrWork)>,
}

impl TimeoutHandleCsrWork {
    /// Build a new self
    pub fn new(a: wasm_bindgen::closure::Closure<dyn FnMut(super::CsrWork)>) -> Self {
        Self { _closure: a }
    }
}

#[wasm_bindgen]
/// This takes an SshWork object as an argument
pub struct TimeoutHandleSshWork {
    /// The closure that gets called
    _closure: wasm_bindgen::closure::Closure<dyn FnMut(crate::SshWork)>,
}

impl TimeoutHandleSshWork {
    /// Build a new self
    pub fn new(a: wasm_bindgen::closure::Closure<dyn FnMut(crate::SshWork)>) -> Self {
        Self { _closure: a }
    }
}
