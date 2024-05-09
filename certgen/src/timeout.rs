use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct TimeoutHandle {
    _closure: wasm_bindgen::closure::Closure<dyn FnMut()>,
}

impl TimeoutHandle {
    pub fn new(a: wasm_bindgen::closure::Closure<dyn FnMut()>) -> Self {
        Self {
            _closure: a,
        }
    }
}