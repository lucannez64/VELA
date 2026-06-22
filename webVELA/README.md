# vela-web

The **ephemeral web vault** SPA — temporary, revocable, no-install browser access
to a VELA vault ([`EPHEMERAL_WEB_ACCESS_DESIGN.md`](../EPHEMERAL_WEB_ACCESS_DESIGN.md)).

It runs the VELA core as WebAssembly ([`vela-wasm-bridge`](../libVELA/vela-wasm-bridge)),
so the server never sees plaintext. It is meant to be served **same-origin as the
API** (e.g. `vault.klyt.eu`) under a strict CSP.

## Status — phase 4b (read-only)

- Generates an ephemeral KEM keypair in-browser, `POST /web-session/start`, shows a
  QR + paste code for the approver, polls `GET /web-session/:id`.
- On a **read-only** grant: decapsulates the one-shot snapshot capsule
  (`open_share`) and renders the vault read-only (reveal / copy fields).
- Read-write (RMS in memory + live sync + Argon2id reload survival) is **phase 4c**;
  this build sends no signing key, so the server can only grant read-only.

## Develop / build

```sh
bun install
bun run build:wasm     # wasm-pack → src/wasm/ (gitignored)
bun run dev            # vite dev server (set VITE_API_BASE for a remote API)
bun run build:all      # build:wasm + tsc + vite build → dist/
```

`build:wasm` requires the Rust toolchain + `wasm-pack`. The generated `src/wasm/`
is not committed; CI / local builds regenerate it.
