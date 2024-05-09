use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct TimeoutHandle {
    _closure: wasm_bindgen::closure::Closure<dyn FnMut()>,
}

impl TimeoutHandle {
    pub fn new(a: wasm_bindgen::closure::Closure<dyn FnMut()>) -> Self {
        Self { _closure: a }
    }
}

#[wasm_bindgen]
pub struct TimeoutHandle1 {
    _closure: wasm_bindgen::closure::Closure<dyn FnMut(String)>,
}

impl TimeoutHandle1 {
    pub fn new(a: wasm_bindgen::closure::Closure<dyn FnMut(String)>) -> Self {
        Self { _closure: a }
    }
}

#[wasm_bindgen]
pub struct TimeoutHandleCsrWork {
    _closure: wasm_bindgen::closure::Closure<dyn FnMut(super::CsrWork)>,
}

impl TimeoutHandleCsrWork {
    pub fn new(a: wasm_bindgen::closure::Closure<dyn FnMut(super::CsrWork)>) -> Self {
        Self { _closure: a }
    }
}
