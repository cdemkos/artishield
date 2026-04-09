use wasm_bindgen::prelude::*;
#[wasm_bindgen(module = "/static/fullscreen.js")]
extern "C" {
    #[wasm_bindgen(js_name = requestFullScreenCanvas)]
    pub fn request_fullscreen_canvas();
    #[wasm_bindgen(js_name = exitFullScreen)]
    pub fn exit_fullscreen();
}
