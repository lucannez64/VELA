# vela-wasm-bridge

WebAssembly (wasm-bindgen) bridge over the shared VELA Rust core
([`vela-crypto`](../vela-crypto), [`vela-core`](../vela-core)), for the
**ephemeral web vault client** described in
[`EPHEMERAL_WEB_ACCESS_DESIGN.md`](../../EPHEMERAL_WEB_ACCESS_DESIGN.md).

This is **Phase 1** of that design: it proves the core runs in the browser. No UI.

## Exported functions

Each takes a JSON request string and returns a JSON response string
(`{"error": "..."}` on failure):

| Function | Request → Response |
| :--- | :--- |
| `vela_wasm_version()` | → version string |
| `generate_ephemeral_keypair()` | → `{ share_ek_b64, share_dk_b64 }` |
| `open_share_json` | `{ share_dk_b64, capsule_b64 }` → `{ item_json }` |
| `encrypt_vault_chunk_json` | `{ rms_b64, chunk_id, vault_json }` → `{ ciphertext_b64 }` |
| `decrypt_vault_chunk_json` | `{ rms_b64, chunk_id, ciphertext_b64 }` → `{ vault_json }` |
| `password_strength_json` | `{ password }` → `{ entropy, score, crack_time }` |
| `argon2_wrap_json` | `{ pin, plaintext_b64 }` → `{ blob_b64 }` |
| `argon2_unwrap_json` | `{ pin, blob_b64 }` → `{ plaintext_b64 }` |

Chunk crypto is **byte-identical** to the Apple/Android/desktop bridges
(`derive("vela chunk key v1" || {:?}(chunk_id_bytes), rms)`), so chunks written by
any client decrypt here. `argon2_*` implements the RW reload-survival wrap from the
design (§8.1): Argon2id (3 iterations, 64 MiB, 4 lanes) → XChaCha20-Poly1305, blob =
`salt(16) ‖ ciphertext`.

TOTP is intentionally **not** in this crate (computed client-side, as on native).

## Build

```sh
# native tests (exercise all the *_impl logic)
cargo test

# wasm artifact
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
# → target/wasm32-unknown-unknown/release/vela_wasm_bridge.wasm
```

Then run `wasm-bindgen` (or `wasm-pack`) to emit the JS glue for the web SPA.

### Note on randomness backends

`crypto-common` (via `ml-kem`/`blake3`) pulls **getrandom 0.4**, which needs an
explicit browser backend. This crate enables the `wasm_js` cargo feature
(`Cargo.toml`) **and** sets `--cfg getrandom_backend="wasm_js"`
(`.cargo/config.toml`). `uuid` likewise needs its `js` feature on wasm. These are
already configured; they are only the reason the build "just works" for wasm.
