# C16 — Secret erasure in VELA's Rust core

Status: implemented and checked. The check is a reviewed allowlist plus a
regression test; it is **not** a proof that the compiler, allocator, OS, or a
foreign runtime erased every copy.

Scope read for this inventory:

- `libVELA/vela-crypto/src/**`
- `libVELA/vela-core/src/**`
- key handling in `desktopVELA/vela-desktop-core/src/store.rs` (and the
  `IdentityKeysStore` users in `sync.rs` / `sharing.rs`)
- the mobile Rust bridges: `libVELA/vela-android-bridge/src/lib.rs`,
  `libVELA/vela-apple-bridge/src/lib.rs`, and the key paths they expose

## Type inventory

“Status” is the state after this step. `ZeroizeOnDrop` means a derive or a
reviewed marker/`Drop` impl wipes the secret fields when the value is dropped.
`Zeroizing<T>` means the buffer itself is wrapped. “Plain” means the value is
still an ordinary `String`/`Vec<u8>`/`[u8; N]` and is listed as a follow-up.

| Type | File:line | Holds | Status | Clone/Copy/Debug notes |
|---|---|---|---|---|
| `kdf::DerivedKey` | `libVELA/vela-crypto/src/kdf.rs:11` | 32-byte KDF output | `#[derive(Clone, ZeroizeOnDrop)]`; custom redacting `Debug` | Clone OK (each clone wipes); no Copy; no derived Debug |
| `kem::HybridSecretKey` | `libVELA/vela-crypto/src/kem.rs:76` | ML-KEM-1024 DK seed + X25519 static secret | fields zeroize on drop; `impl ZeroizeOnDrop` marker at `:83`; `ml-kem` `zeroize` feature enabled | no Clone/Copy/Debug derived |
| `kem::SharedSecret` | `libVELA/vela-crypto/src/kem.rs:92` | 32-byte KEM shared secret | manual `Drop` with volatile writes (`:94`); redacting `Debug` | no Clone/Copy; no derived Debug |
| `signing::HybridSigningKey` | `libVELA/vela-crypto/src/signing.rs:141` | ML-DSA-87 + Ed25519 private key | `#[derive(ZeroizeOnDrop)]` | no Clone/Copy/Debug derived |
| `identity::DeviceIdentity` | `libVELA/vela-crypto/src/identity.rs:47` | signing key, share DK, optional identity DK | key fields zeroize on drop; `impl ZeroizeOnDrop` marker at `:64` | custom redacting `Debug`; no Clone/Copy |
| `shamir::Share` | `libVELA/vela-crypto/src/shamir.rs:88` | share y-values + MAC (two reconstruct the RMS) | `#[derive(Clone, Zeroize, ZeroizeOnDrop)]` | Clone OK; no Copy; custom redacting `Debug` |
| `recovery::ReconstructedRms` | `libVELA/vela-crypto/src/recovery.rs:57` | recovered 32-byte RMS | `#[derive(Clone, Zeroize, ZeroizeOnDrop, ...)]` | Clone OK; no Copy; custom redacting `Debug` |
| `recovery::KdfStreamRng` | `libVELA/vela-crypto/src/recovery.rs:332` | RMS-derived seed and keystream block | `#[derive(Zeroize, ZeroizeOnDrop)]` | private, no Clone/Copy/Debug |
| `share_envelope::OpenedShare` | `libVELA/vela-crypto/src/share_envelope.rs:83` | decrypted shared item | manual `Drop` wipes `item` (`:97`); custom redacting `Debug` | Clone OK; no Copy; no derived Debug |
| `oram::OramBlock` | `libVELA/vela-crypto/src/oram.rs:61` | decrypted vault-chunk bytes | manual `Drop` wipes `data` (`:79`); custom redacting `Debug` | Clone OK; no Copy; no derived Debug |
| `oram::TrivialOram` | `libVELA/vela-crypto/src/oram.rs:458` | map of decrypted chunks | manual `Drop` wipes every value | contains `OramBlock`s / plain buffers; no Debug |
| `vault::VaultItem` | `libVELA/vela-core/src/vault.rs:53` | passwords, TOTP seeds, PAN/CVV/PIN, notes, SSN, passkey scalar | manual `Drop` via `zeroize_secrets`; custom redacting `Debug` | Clone OK; no Copy; no derived Debug |
| `rich_items::SensitiveValue` | `libVELA/vela-core/src/rich_items.rs:44` | arbitrary JSON credential value | manual `Drop` recursively wipes strings (`:52`); redacting `Debug` | Clone OK; no Copy; no derived Debug |
| `rich_items::AdditionalUrl` | `libVELA/vela-core/src/rich_items.rs:267` | URL (may embed credentials) | manual `Drop` zeroizes `url` | Clone OK; no Copy; custom redacting `Debug` |
| `rich_items::IdentityDetails` | `libVELA/vela-core/src/rich_items.rs:343` | contact/identity fields | manual `Drop` zeroizes strings | Clone OK; no Copy; `redact_debug!` |
| `rich_items::PostalAddress` | `libVELA/vela-core/src/rich_items.rs:358` | address fields | manual `Drop` zeroizes strings | Clone OK; no Copy; `redact_debug!` |
| `store::IdentityKeysStore` | `desktopVELA/vela-desktop-core/src/store.rs:29` | `hybrid_sk`, `share_dk`, `hybrid_dk` (+ public halves) | manual `Drop` zeroizes the three private keys (`:69`); custom `Debug` redacts them | Clone OK; no Copy; no derived Debug |
| `SecretBytes` (Android JNI) | `libVELA/vela-android-bridge/src/lib.rs:1613` | byte array copied out of the JVM | manual `Drop` zeroizes (`:1622`) | no Clone/Copy/Debug |

### Function-local secret buffers fixed or confirmed

| Buffer | File:line | Before / after |
|---|---|---|
| Shamir polynomial coefficients | `libVELA/vela-crypto/src/shamir.rs` (`split`) | `Vec<Vec<u8>>` → `Zeroizing<Vec<Vec<u8>>>`; per-polynomial `Zeroizing` |
| Shamir MAC key | `libVELA/vela-crypto/src/shamir.rs` (`split`, `reconstruct`) | plain `[u8; 32]` → `Zeroizing<[u8; 32]>` |
| Shamir reconstructed secret | `libVELA/vela-crypto/src/shamir.rs` (`reconstruct`) | plain `Vec<u8>` → `Zeroizing<Vec<u8>>`; the returned `Vec` is the API copy (follow-up) |
| Recovery reconstructed secret | `libVELA/vela-crypto/src/recovery.rs` (`reconstruct_account_recovery`) | plain `Vec<u8>` → `Zeroizing<Vec<u8>>` before the 32-byte copy |
| Possession-key seeds | `libVELA/vela-crypto/src/recovery.rs` (`possession_keys`) | plain `[u8; 32]` → `Zeroizing<[u8; 32]>` |
| Re-key share check | `libVELA/vela-crypto/src/rekey.rs` (`shares_reconstruct_to`) | plain reconstructed `Vec<u8>` → `Zeroizing<Vec<u8>>` |
| AEAD plaintext | `libVELA/vela-crypto/src/aead.rs` | already `Zeroizing<Vec<u8>>` on `open`/`decrypt` |
| KEM combiner IKM | `libVELA/vela-crypto/src/kem.rs` | already `Zeroizing<Vec<u8>>` |
| Link KDF material | `libVELA/vela-crypto/src/link.rs` | already `Zeroizing<Vec<u8>>` |
| Re-key payload / old RMS / new RMS | `libVELA/vela-crypto/src/rekey.rs` | already `Zeroizing<...>` |
| Identity seal plaintext and field buffers | `libVELA/vela-crypto/src/identity.rs` (`seal`, `open`) | already `Zeroizing<...>` |
| Shared-envelope plaintext | `libVELA/vela-crypto/src/share_envelope.rs` | already `Zeroizing<Vec<u8>>` |
| Password generator RNG block | `libVELA/vela-core/src/password.rs` (`RandomDraws`) | manual `Drop` zeroizes the 64-byte block |
| Desktop retired/current RMS | `desktopVELA/vela-desktop-core/src/store.rs` (`rekey_secret_files_inner`) | already `Zeroizing<[u8; 32]>` |

## Fixes in this step

- Enabled `ml-kem`'s `zeroize` feature so `DecapsulationKey` really wipes its
  expanded key, seed, and implicit-rejection string on drop
  (`libVELA/vela-crypto/Cargo.toml`), and marked `HybridSecretKey` /
  `DeviceIdentity` as `ZeroizeOnDrop` containers.
- `shamir::Share` now derives `Zeroize, ZeroizeOnDrop`; its split coefficients
  and MAC key are `Zeroizing`; `reconstruct` wipes its working secret.
- `recovery::ReconstructedRms` no longer derives `Debug` (it printed the RMS);
  it zeroizes on drop. `KdfStreamRng` and the possession-key seeds zeroize.
- `share_envelope::OpenedShare` wipes the decrypted item on drop and redacts it
  in `Debug`.
- `oram::OramBlock` wipes decrypted chunk bytes on drop and redacts them in
  `Debug`; `TrivialOram` wipes its stored chunks.
- `desktopVELA/.../store.rs::IdentityKeysStore` no longer derives `Debug` (it
  printed all three private keys) and wipes `hybrid_sk`, `share_dk`, and
  `hybrid_dk` on drop. Two struct-update sites that moved fields out of a
  `Drop` type were rewritten (`store.rs`, `sync.rs`).
- Added `security/formal/check-secret-erasure.py` and
  `security/formal/tests/test_secret_erasure.py`, wired into
  `.github/workflows/security.yml` next to the proof-escape check.

Unit tests were added only where behavior is observable: the existing
`debug_redacts_share_material`, `zeroizing_an_item_clears_every_secret_field`,
and `debug_never_prints_a_secret` tests continue to pin the redaction/wipe
behavior; the new guard test pins the erasure declarations themselves.

## What the guard does

`security/formal/check-secret-erasure.py` holds a reviewed `(path, kind, name)`
allowlist (17 entries in 12 files). For each entry it requires:

1. a `Zeroize`/`ZeroizeOnDrop` derive or impl, **or**
2. a manual `Drop` impl whose body calls `zeroize`/`write_volatile`, **or**
3. a `Zeroizing<_>` field in the declaration; and
4. no `Copy` derive; and
5. no derived `Debug`; a hand-written `Debug` is allowed only when its body
   contains the inventory's `REDACTED` marker (or the reviewed
   `redact_debug!` macro names the type).

A renamed/removed allowlisted type, a deleted derive or wiping `Drop`, an added
`Copy`, or a new non-redacting `Debug` fails. The companion test mutates the
real source in memory (removes `Zeroize` from `Share`, adds `Copy`/`Debug` to
`DerivedKey`, removes `OramBlock`'s `Drop`, renames `DerivedKey`, un-redacts
`Share`'s `Debug`) and asserts each mutant fails.

## Verification run

All cargo commands went through
`~/.local/opt/vela-tools/bin/vela-heavy` with
`VELA_STEP_TIMEOUT=3600` and `CARGO_TARGET_DIR=<worktree>/target-c16`:

- `python3 -I security/formal/check-secret-erasure.py` — 17 types in 12 files,
  exit 0.
- `python3 -I -m unittest discover -s security/formal/tests -p
  'test_secret_erasure.py'` — 7 tests passed, including all mutants.
- `cargo test --manifest-path libVELA/vela-crypto/Cargo.toml` — 134 unit tests
  + 4 ORAM integration tests + 2 doc-tests passed.
- `cargo test --manifest-path libVELA/vela-core/Cargo.toml` — 21 unit tests +
  20 integration tests passed.
- `cargo test --manifest-path desktopVELA/vela-desktop-core/Cargo.toml --lib
  store::tests` — 19 passed; `--lib sync::` — 31 passed (the two struct-update
  call sites changed for the new `Drop` impl).

## What the check does **not** catch

This is the important limitation list; do not read a green check as more than a
source-level declaration audit.

- **Copies the compiler makes.** Moves, closures, `Clone`, `serde` decoding,
  `to_vec()`/`String::from_utf8`, argument passing, and register/stack spills
  are invisible to a source scanner. Zeroizing a variable does not zero copies
  already made from it. A copy made by the compiler into a temporary or an
  ABI buffer can outlive the original.
- **The allocator and OS.** `Vec::clear`/`String::clear` and `Zeroize` wipe
  the current allocation, not freed/reallocated pages, the page cache, swap,
  hibernation images, core dumps, crash reporters, or a JVM/Swift runtime's
  heap. `Vec` growth can leave an old buffer behind even when the final buffer
  is wiped.
- **Foreign-language strings.** The Android/iOS bridges receive secrets as
  base64 in Kotlin/Swift `String` values in many request/response structs.
  Rust can wipe its decoded copy, but an immutable JVM/Swift string cannot be
  wiped. `SecretBytes` only covers the JNI `ByteArray` paths.
- **Plain API returns.** Several functions still return ordinary
  `Vec<u8>`/`[u8; 32]`/`String` plaintext (next section); the check can see
  the type name in the allowlist only if it is added, and cannot force callers
  to wrap the result.
- **Field-level semantics.** For container types marked `ZeroizeOnDrop`
  (`HybridSecretKey`, `DeviceIdentity`), the marker asserts that the current
  field types wipe themselves. The check does not recursively verify every
  dependency's destructor. `HybridSecretKey`'s ML-KEM field is covered by the
  upstream `zeroize` feature, not by local code.
- **Types not on the allowlist.** A new secret-bearing type, a secret added to
  a non-secret type, a secret in a local variable, or a secret in a test/helper
  type is not detected. Review must add it to the allowlist.
- **Concurrency/lifetime bugs.** Nothing here proves a secret is not observable
  through a stale reference, a `Mutex` guard, a panic payload, a `Debug`
  implementation elsewhere, or a `format!`/logging call.
- **Performance/ABI constraints.** The check is textual (regex + brace
  matching), not a Rust type checker; formatting or macro changes can require
  updating it.

## Unverified / follow-ups (API redesigns, not changed here)

1. **Plaintext-returning public APIs.** Consider returning `Zeroizing<Vec<u8>>`
   (or a secret wrapper) from `kem::open_share`
   (`libVELA/vela-crypto/src/kem.rs:339`), `password_kdf::open_with_password`
   (`:147`), `shamir::reconstruct` (`:274`),
   `identity::DeviceIdentity::{open_share, open_identity_capsule}`
   (`libVELA/vela-crypto/src/identity.rs:196`), `share_envelope::OpenedShare::
   into_item` (`libVELA/vela-crypto/src/share_envelope.rs`), and
   `signing::HybridSigningKey::to_bytes`
   (`libVELA/vela-crypto/src/signing.rs:309`). Each call site (including the
   Android/Apple bridges) must then be updated.
2. **`link::generate_link_key`** (`libVELA/vela-crypto/src/link.rs:33`)
   returns a bare `[u8; LINK_KEY_LEN]`; callers own the wipe contract.
3. **Desktop `Store::load_rms`** (`desktopVELA/vela-desktop-core/src/store.rs:508`)
   returns `[u8; 32]`; `derive_device_key` also returns a plain `[u8; 32]`.
   These are public/cross-crate APIs.
4. **Desktop saved/loaded plaintext.** `save_vault`/`load_vault` and
   `save_identity_keys_full`/`load_identity_keys` serialize/deserialize into
   plain `Vec<u8>` before/after encryption; wrap those locals in `Zeroizing`.
   The RMS migration journal returns bare `[u8; 32]` pairs.
   `IdentityKeysStore` now wipes its own fields, but the caller's copies and
   serde's intermediate buffers are still plain.
5. **Android bridge request/response structs** hold `rms_b64`, `hybrid_sk_b64`,
   `share_dk_b64`, passwords, and vault JSON as `String`
   (`libVELA/vela-android-bridge/src/lib.rs` request structs). Moving them to a
   zeroizing wrapper / raw byte arrays is an ABI change. `decode_rms` returns
   `[u8; 32]`.
6. **Apple bridge** has no equivalent of Android's `SecretBytes`; its request
   structs and `decode_key32` return plain buffers. This needs an ABI-level
   change with Swift.
7. **WASM/web bridge** (`libVELA/vela-wasm-bridge`) passes vault plaintext and
   keys through JavaScript `Uint8Array`/`String`; JavaScript cannot guarantee
   wiping either. Out of scope for a Rust-only check.
8. **`HybridSigningKey::to_bytes`/`into_bytes`** produce secret `Vec<u8>`s for
   persistence; the caller must wrap them. The zero-copy `into_bytes` path
   uses `ManuallyDrop` + explicit wipes and is reviewed in place.
9. **`password::generate_password`** returns the generated password as a
   `String` (`libVELA/vela-core/src/password.rs:177`); the API has to hand it
   to the caller/UI. The RNG block is wiped.

## How to extend

Add a `(path, kind, name)` row to `ALLOWLIST` in
`security/formal/check-secret-erasure.py`, then make the type pass the five
rules above. If a dependency type cannot implement `Zeroize` locally, either
enable its upstream `zeroize` feature or add a reviewed marker plus a comment
explaining which field destructor does the wipe (as for `HybridSecretKey`).
