# VELA fuzzing harness

Coverage-guided fuzzing (libFuzzer + ASAN) for `libVELA`'s untrusted-input
surfaces. Run from this directory (`libVELA/vela-core/fuzz`); requires a
nightly toolchain and `cargo install cargo-fuzz --locked`.

## Targets

| Target | Surface | Oracle |
|---|---|---|
| `vault_json` | `VaultStore`/`VaultItem` deserialization — vault file + sync wire | no panic/OOM/hang; parse → serialize → parse round-trip stability |
| `url_domain_match` | `search_by_domain`, i.e. the autofill URL matcher (fast host splitter vs `url` crate) | reference model of the match rule rebuilt from `url` + `psl`; any divergence fires |
| `shamir_shares` | `Share::from_bytes` / `reconstruct` — recovery flow (paper/cloud/server shares) | no panic on arbitrary share bytes; honest split/reconstruct must always round-trip |
| `crypto_parsers` | `HybridPublicKey`/`HybridCapsule::from_bytes`, `open_share`, AEAD `decrypt`/`open`/`open_vault_chunk` | no panic/OOB on hostile blobs; sealed/legacy AEAD round-trip |
| `password_options` | `generate_password(options)` as reached from the Tauri command (options come straight from the webview) | no panic at any length up to 1e6 incl. empty charsets; strength score consistent with entropy |
| `totp_otpauth` | hand-rolled `otpauth://` parser + HOTP pipeline (vault-stored TOTP fields) | no panic on arbitrary strings; generated codes are 6–8 digits and self-verify |
| `ipc_message` | `IpcMessage` JSON parsing — the native-messaging frame body | no panic; parsed messages round-trip type-identically |
| `pwkdf_blob` | versioned password-sealed blob reader incl. unauthenticated Argon2 cost fields | no panic; hostile recorded costs must fail the implausible-cost refusal |
| `oram_state` | `PathOram` against a tree-modelled server (register/read/write/unregister sequences) | every registered chunk reads back its last write byte-exact |
| `enrollment_codes` | verification-code rendering + fingerprint decoy-choice sets | fixed 18-digit grouped shape; answer appears exactly once; no decoy collisions |
| `credential_key_verify` | ES256 COSE_Key parser + DER signature verify (`verify_der`) | no panic; hand parser accepts only canonical-shape keys; honest sigs verify, bit-flips don't |
| `nm_host_protocol` | native-messaging framing (`read_browser_message`/`write_browser_message`, `framed_exchange`) + projection helpers | no panic, no unbounded alloc; structured messages survive their own reframe |

## Known finding: `PathOram` loses blocks (latently)

`fuzz_targets/oram_state.rs` drives the client through the documented
protocol against a faithful tree-backed server
(`artifacts/oram_state/crash-*` reproduce). `access()` absorbs blocks from
the path to the **old** leaf but evicts the stash onto a write-back path for
the **reassigned** leaf. When the two routes diverge below the root, the
upload overwrites tree nodes that were never downloaded — destroying blocks
parked there by earlier evictions, without them ever having entered a stash.

Classic Path ORAM reads and writes back the *same* path; the reassigned leaf
only steers the next access. Suggested direction when this module ships:
evict along the downloaded path (or return the old path for upload).

Not reachable today — every client runs `TrivialOram`
(`desktopVELA/vela-desktop-core/src/sync.rs` "chunked trivial ORAM payload")
and no non-test caller touches `PathOram` — but the server's `oram_buckets`
storage is already live, so this must be fixed before the >4-chunk switch.

## Run

```sh
cd libVELA/vela-core/fuzz
cargo fuzz run vault_json            # corpus in corpus/<target>/, artifacts in artifacts/
cargo fuzz run url_domain_match -max_total_time=600
```

Targets that pull in `vela-desktop-core` (`totp_otpauth`, `ipc_message`)
need the desktop crate's unstable-http3 cfg:

```sh
RUSTFLAGS="--cfg reqwest_unstable" cargo fuzz run totp_otpauth
```

Seeds live in `corpus/<target>/`. Crashes land in
`artifacts/<target>/crash-<sha>` and reproduce with
`cargo fuzz run <target> artifacts/<target>/crash-<sha>`.
Minimize with `cargo fuzz tmin`.

## Conventions

- Targets cap input size so a found "hang" is algorithmic, not payload bulk.
- Oracles assert only what is provably sound; where the reference parser cannot
  interpret an input, the check is skipped rather than guessed.
- The Shamir and password targets embed a known-good round-trip check each
  iteration so a regression in the happy path fails loudly too.

## Scope notes

- `vela-crypto` primitives themselves are third-party audited crates; the fuzz
  surface is VELA's own byte-layout parsers and glue around them.
- The desktop IPC/native-messaging layer is a separate workstream (see
  `security/exploits/`); these targets cover the shared core both clients call.
