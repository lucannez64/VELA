import { defineConfig } from 'vite';

// wasm-pack `--target web` glue loads the .wasm itself via
// `new URL('..._bg.wasm', import.meta.url)`, which Vite handles natively (it
// emits the wasm as an asset and rewrites the URL) — no wasm plugin needed.
export default defineConfig({
  server: { port: 5273 },
  build: { target: 'es2022', outDir: 'dist' },
});
