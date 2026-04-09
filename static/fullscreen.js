export function requestFullScreenCanvas() {
  const canvas = document.querySelector("canvas");
  if (!canvas) return;
  const isFull = document.fullscreenElement !== null;
  if (!isFull) {
    canvas.requestFullscreen().catch(e => console.warn("FS failed", e));
  } else {
    document.exitFullscreen().catch(e => console.warn("Exit FS failed", e));
  }
}

// For wasm-bindgen, export under expected names:
window.requestFullScreenCanvas = requestFullScreenCanvas;
window.exitFullScreen = () => { if (document.fullscreenElement) document.exitFullscreen(); };
