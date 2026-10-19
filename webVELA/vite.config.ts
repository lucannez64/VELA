import { defineConfig } from 'vite';
import { resolve } from 'node:path';

// wasm-pack `--target web` glue loads the .wasm itself via
// `new URL('..._bg.wasm', import.meta.url)`, which Vite handles natively (it
// emits the wasm as an asset and rewrites the URL) — no wasm plugin needed.
//
// Two entry points: the ephemeral vault SPA (`index.html`) and the one-off
// share-link recipient page (`send.html`).
export default defineConfig({
  server: { port: 5273 },
  build: {
    target: 'es2022',
    outDir: 'dist',
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        send: resolve(__dirname, 'send.html'),
      },
    },
  },
});
