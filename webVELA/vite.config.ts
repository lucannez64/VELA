import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

// The VELA core runs as WebAssembly in the browser. `vite-plugin-wasm` lets us
// import the wasm-bindgen glue, and the top-level-await plugin supports the
// async wasm init in older browsers.
export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  server: { port: 5273 },
  build: { target: 'es2022', outDir: 'dist' },
});
