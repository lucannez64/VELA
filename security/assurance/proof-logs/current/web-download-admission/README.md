# Web download admission (U-27, plan step N0c)

Worktree: `/home/hirew/.t3/worktrees/VELA/t3-1ab9758d`
Baseline: `1e8f6ba` (fast-forwarded as the step instructs, replacing the plan's
usual `94696ed`).

## The gap

`webVELA` decrypted every chunk with the epoch and revision the server reported
in `GET /vault/sync` (baseline: `webVELA/src/api.ts:148`,
`webVELA/src/main.ts:478-483`) through the wasm export
`decrypt_vault_chunk_json`, which made no admission decision (and defaulted a
missing epoch to 1). The proved gates
`plan_sync_epoch_match` and `plan_chunk_download` ran only on Android and iOS.
A malicious server could therefore claim epoch 1, where a pre-C-2 **unsealed**
blob opens without any chunk or revision binding, or replay an older admitted
revision. Found by the [FFI inventory](../ffi-inventory/README.md) (N1, F1).

## Can the browser authenticate the epoch?

**No.** The evidence:

- The read-write grant envelope is `{ "v": 2, "mode": "rw", "chunk_keys": … }`:
  keys only, no epoch (`EPHEMERAL_WEB_ACCESS_DESIGN.md:438-452`;
  `androidVELA/.../core/FeatureRepositories.kt:282,295`;
  `iosVELA/Sources/AccountViewModel.swift:303`).
- The approving device does check its own epoch against the server's before
  granting, but it sends `key_epoch` **to the server**
  (`serverVELA/vela-server/src/web_session/mod.rs:652`, stored at `:760,:777`).
  The token response (`mod.rs:902-906`) and the poll response (`mod.rs:288-300`)
  carry no epoch, and anything the server relayed would be server-asserted.
- The capsule is sealed to the browser's ephemeral public key (KEM-DEM). That
  proves confidentiality and integrity *against third parties*, not sender
  authenticity: the browser sends `ephemeral_pk` at `POST /web-session/start`
  and the server serves it back at `/web-session/:id/keys` (`mod.rs:553-640`),
  so the server knows the public key and can mint a capsule of its own. The QR
  fingerprint check stops the *approver* from sealing to a substituted key; it
  does not authenticate the capsule the browser later receives. Adding an epoch
  field to this envelope would therefore not authenticate it either.

**Conclusion:** the only epoch fact a tab can establish for itself is the first
epoch it admits. That is the floor implemented here. U-27 therefore stays
**partly** closed; see the residual section below.

## Change

### `libVELA/vela-wasm-bridge` (new dependency `vela-sync-policy`)

- New export `decrypt_admitted_vault_chunk_json`
  (`src/lib.rs:499`, implementation `:339`), mirroring the Android
  `nativeDecryptAdmittedVaultChunkJson` and Apple
  `vela_ffi_decrypt_admitted_vault_chunk_json` shape:
  request `{ chunk_key_b64, ciphertext_b64, chunk_id, lamport_clock, key_epoch }`
  → `{ vault_json, lamport_clock }`.
- Admission order:
  1. `aead::is_sealed` refusal for unsealed pre-C-2 blobs (`:350`), before any
     policy or crypto work: that shape binds neither chunk nor revision.
  2. Epoch floor. The first admitted epoch is pinned in a `thread_local`
     `AdmissionState` (`:147`); later downloads call the verified
     `plan_sync_epoch_match` with the pinned epoch and the manifest integer
     (`:364`). A lower epoch is a downgrade, a different one an unadopted
     rotation; both refuse. No caller-supplied boolean can skip this.
  3. The real `rekey::open_fleet_chunk` open. Epoch 1 verifies
     `chunk_id ‖ lamport_clock`; epoch 2+ also verifies the epoch. Only a
     successful open sets `aad_binding_verified: true` (`:403`).
  4. `plan_chunk_download` against the highest revision this tab already
     admitted for that chunk; the state is updated only after the plaintext was
     produced and decoded (`record_admission`, `:171`). A lower revision is
     refused; an equal one (redelivery) is admitted, as the policy specifies.
- The unguarded `decrypt_vault_chunk_json` export and its request type were
  **removed**. `grep` over the tree showed its only download caller was
  `webVELA/src/main.ts` (the Apple bridge has its own, unrelated C export), so
  no caller needs it. Download code now has one entry point.
- The floor and the per-chunk baselines live in WASM memory only. The web client
  has no durable store (RW resume was removed), so a reload is a new first
  contact; this is recorded as the residual risk.

### `webVELA`

- `src/vela.ts:88` replaces `decryptVaultChunk` with `admitVaultChunk`, which
  calls the new export and returns the admitted clock.
- `src/main.ts:483` is the only download call site; failures are wrapped as
  `Could not safely open "<id>" from the server: …` so the bridge's specific
  refusal (unsealed / downgrade / rotation / rollback) reaches the user.
- `src/api.ts:158-166` pins the first manifest epoch in `AuthedSession` and
  refuses any later different value. This also covers the upload path
  (`putChunk`/`deleteChunk`/`encryptVaultChunk` use `authed.epoch`), so a
  downgraded manifest cannot make the browser seal new chunks at epoch 1. A
  mid-session rotation fails closed with a "reload and approve again" message.

## Test evidence

All heavy commands ran through
`~/.local/opt/vela-tools/bin/vela-heavy` with
`CARGO_TARGET_DIR=/home/hirew/.t3/worktrees/VELA/t3-1ab9758d/target-vela-n0c-web`
and `VELA_STEP_TIMEOUT=3600`. `wasm-pack` is not part of the repo toolchain; the
0.15.1 binary was installed under `/tmp/opencode/wasm-pack-tool` and invoked
through `vela-heavy` (the wrapper runs non-cargo/non-fstar commands locally
under its 3 GiB / one-job cap). `bun` is not installed on this host, so the
web package was installed with `npm install --no-package-lock` and the build
ran through the same `tsc && vite build` script (`npm run build`); no
`package-lock.json` was added.

| Log | Command | Result |
|---|---|---|
| [`cargo-test.log`](cargo-test.log) | `cargo test` in `libVELA/vela-wasm-bridge` | **16 passed, 0 failed** (plus 0 doc-tests) |
| [`wasm-pack-build.log`](wasm-pack-build.log) | `wasm-pack build ../libVELA/vela-wasm-bridge --target web --release --out-dir ../../webVELA/src/wasm` from `webVELA` | **Done**; `vela_wasm_bridge_bg.wasm` 487,048 bytes |
| [`web-build.log`](web-build.log) | `npm run build` (`tsc && vite build`) in `webVELA` | **success**, 39 modules transformed |

The Rust tests include the three refusals the step asks for and their
positive controls:

- `admitted_download_refuses_unsealed_legacy_blobs` — `aead::encrypt` blob at
  epoch 1 is refused, no plaintext returned.
- `admitted_download_refuses_epoch_below_the_tab_floor` — after admitting
  epoch 3, an epoch-1 blob that *does* open is refused and the floor stays 3.
- `admitted_download_refuses_an_epoch_change_after_the_pin` — a higher epoch is
  refused as an unadopted rotation.
- `admitted_download_refuses_rollback_and_allows_equal_redelivery` — revision 3
  after revision 7 is refused; revision 7 again is admitted.
- `admitted_download_does_not_pin_a_failed_first_attempt` — a first attempt that
  fails the AAD check leaves no floor behind.
- `admitted_download_refuses_nonpositive_epochs`,
  `admitted_download_binds_the_chunk_id`, `chunk_key_from_another_chunk_fails`,
  `epoch_chunk_roundtrip_rejects_wrong_or_legacy_epoch`,
  `epoch_one_uses_the_fleet_legacy_chunk_format` — epoch and chunk binding.
- `admitted_download_roundtrips_and_returns_the_admitted_clock` — the response
  carries the policy's clock, not the caller's.

`webVELA/package.json` has **no test script and no test runner** (only
`dev`/`build`/`typecheck`/`build:wasm`), so there is no web unit-test suite to
extend; `tsc` + `vite build` are the web checks that ran.

## Residual risk (why U-27 is "partly closed")

1. **First contact is unauthenticated.** A fresh tab has no epoch floor, so it
   pins the first manifest epoch. A malicious server can still answer epoch 1
   and serve a pre-rotation **epoch-1 sealed** blob for a chunk/revision the tab
   has not read yet. That shape binds the chunk id and revision (so it cannot be
   relabelled or clock-shifted), but not the epoch. Unsealed blobs no longer
   open at all.
2. **No durable state.** The epoch pin and per-chunk Lamport floors die with
   the page; every reload is another first contact. Making the floor durable
   needs a grant channel that authenticates the epoch end-to-end (an
   approver-signed epoch over a channel the server cannot substitute), which is
   a protocol change, not a client change.
3. **A mid-session rotation is refused, not adopted.** The browser has no way to
   authenticate the new epoch, so the session ends and must be re-approved.
4. The server can always deny service or serve stale-but-valid revisions of
   chunks the tab has never read; the gate bounds what a *successful* read
   proves, not availability.

## What was not verified

- No browser/end-to-end session was run against a live server. The wasm package
  and the SPA were built, and the Rust admission logic is unit-tested natively.
- The F* proofs of `plan_sync_epoch_match` / `plan_chunk_download`
  ([17](../../../17-universal-chunk-admission.md),
  [18](../../../18-mobile-sync-admission.md)) were not re-run: the policy crate
  is unchanged and only reused. This increment adds no new policy decision, so
  it makes no new formal claim; the bridge-side fact construction (sealed
  header, real open, tab floor) is the part that remains unproved.
- The mobile bridges, JNI/C/Swift and the desktop paths are untouched.
