# Desktop download admission (plan steps N0a, N0b)

Closes two client gaps recorded from the FFI inventory
([F2 and F3](../ffi-inventory/README.md)):

- **U-28** — the desktop download path opened pre-C-2 **unsealed** chunks at
  epoch 1, although that shape authenticates neither the chunk id nor the
  revision.
- **U-29** — the desktop rollback gate (`plan_chunk_download`) ran on the
  literals `aad_binding_verified: true` and `key_epoch_positive: true`, before
  any decryption.

Base commit: `1e8f6ba` (fast-forward of the delegate rule's `94696ed`). The
worktree is `t3-0e516d4a`; no other branch or worktree was used.

## Files changed

| File | Change |
|---|---|
| `libVELA/vela-crypto/src/rekey.rs` | Adds `open_sealed_fleet_chunk` (the one download-admission open) and the shared `LEGACY_UNSEALED_REFUSAL` text; documents which readers keep the legacy shape; adds `admission_open_refuses_the_unsealed_legacy_shape`. |
| `libVELA/vela-android-bridge/src/lib.rs` | Deletes the bridge-local `open_admitted_fleet_chunk` copy; the admitted path calls `rekey::open_sealed_fleet_chunk`. |
| `libVELA/vela-apple-bridge/src/lib.rs` | Same deletion/replacement for the Apple bridge. |
| `desktopVELA/vela-desktop-core/src/sync.rs` | Download path opens sealed-only first, builds `ChunkDownloadFacts` from the open result and the real epoch, runs `plan_chunk_download` before returning plaintext, and keeps the rollback error text. New unit and wiremock tests. |
| `security/assurance/05-known-limitations.md` | Rows U-28 and U-29 move to Closed with test names. |

## Step 1: can a desktop client still legitimately meet a legacy unsealed chunk?

Read from the tree; every claim cites a symbol or file line.

1. **Every current chunk writer seals.** The only production chunk writers are
   `vela_crypto::rekey::seal_fleet_chunk` callers:
   - desktop `seal_sync_chunk` (`desktopVELA/vela-desktop-core/src/sync.rs:574`,
     called for vault chunks and the audit chunk);
   - Android `nativeEncryptVaultChunkJson`
     (`libVELA/vela-android-bridge/src/lib.rs:950`);
   - Apple `vela_ffi_encrypt_vault_chunk_json`
     (`libVELA/vela-apple-bridge/src/lib.rs:1108`);
   - web `encrypt_vault_chunk_json`
     (`libVELA/vela-wasm-bridge/src/lib.rs:253`).

   No production chunk writer calls `aead::encrypt` or `aead::seal`
   directly. The remaining `aead::encrypt` call sites are whole-vault blobs,
   identity, KEM capsules, password KDF, server migration bundles
   (`serverVELA/vela-server/src/migration.rs:302`) and test vectors, not sync
   chunks.

2. **A migration re-seals legacy chunks.** The desktop re-key rotation reads
   each chunk with `open_epoch_chunk` (which still accepts the unsealed shape
   at epoch 1) and writes a fresh `seal_epoch_chunk` shadow row under the new
   epoch (`desktopVELA/vela-desktop-core/src/commands/rekey.rs:213` and
   `:235`). It refuses an unbound blob at epoch 2+ (`:225-230`).

3. **Other legitimate legacy readers exist and are retained explicitly:**
   - enrollment bootstrap `download_vault_after_enrollment` →
     `try_download_chunk` (`desktopVELA/vela-desktop-core/src/commands/devices.rs:397`,
     `:407`, `:468-496`) reads both shapes at epoch 1 while a joining device
     seeds its vault;
   - the desktop-only audit chunk read (`desktopVELA/vela-desktop-core/src/sync.rs:1343`)
     keeps `open_fleet_chunk` and is commented in place as a pre-C-2 read.

   None of these is the sync download path, and none claims admission.

**Conclusion:** no production sync download needs the unsealed shape, so the
desktop can refuse it exactly as the mobile bridges do. The shared gate is
`vela_crypto::rekey::open_sealed_fleet_chunk`; all three clients call it, so
there is no third copy. `open_fleet_chunk`/`open_epoch_chunk` remain the
documented reads for the migration/bootstrap paths above.

## What changed in the desktop download path

Before (`sync.rs:1086-1103` at the base commit):

1. `reject_rollback` ran `plan_chunk_download` with `aad_binding_verified: true`
   and `key_epoch_positive: true` (constants);
2. `open_fleet_chunk` then opened any shape, including unsealed epoch-1 blobs.

After:

1. `open_sealed_fleet_chunk` refuses a blob without the `VAE1` header before the
   AEAD open and otherwise opens with the epoch/chunk-id/revision AAD
   (`sync.rs:1115`);
2. `established_chunk_download_facts` (`sync.rs:519`) sets
   `aad_binding_verified` to `opened.is_ok()` and `key_epoch_positive` to
   `key_epoch >= INITIAL_EPOCH`;
3. `reject_rollback` (`sync.rs:548`) runs `plan_chunk_download` on those facts
   before any plaintext is returned, so before the merge and before any
   baseline write. It still runs when the open failed (a false AAD fact); the
   open error is reported in that case because it names the failure more
   precisely. On a successful open, the only way to reach the refusal is a
   clock below the recorded baseline (or below 1), so the existing message is
   unchanged.

`key_epoch as u64` was also replaced by `u64::try_from`, so a negative epoch is
reported as a corrupt chunk instead of wrapping.

## Commands and results

All heavy commands ran one at a time through `vela-heavy` from the worktree
root with `VELA_STEP_TIMEOUT=3600` and `CARGO_TARGET_DIR=$PWD/target-vela-n0-desktop`.
No gpui or Tauri application was built (per the task's disk constraint).

| # | Command | Exit | Result | Log |
|---|---|---|---|---|
| 1 | `vela-heavy cargo test --locked --manifest-path libVELA/vela-crypto/Cargo.toml --lib` | 0 | 131 passed, 0 failed (includes `rekey::tests::admission_open_refuses_the_unsealed_legacy_shape`) | `crypto-tests.log` |
| 2 | `vela-heavy cargo test --manifest-path desktopVELA/Cargo.toml -p vela-desktop-core --locked --lib` | 0 | 459 passed, 0 failed, 8 ignored (includes the three new sync tests and the new facts test) | `desktop-core-tests.log` |
| 3 | `vela-heavy cargo test --locked --manifest-path libVELA/vela-android-bridge/Cargo.toml --lib` | 0 | 28 passed, 0 failed (existing legacy-refusal test unchanged) | `android-bridge-tests.log` |
| 4 | `vela-heavy cargo test --locked --manifest-path libVELA/vela-apple-bridge/Cargo.toml --lib` | 0 | 18 passed, 0 failed (existing legacy-refusal test unchanged) | `apple-bridge-tests.log` |

New tests:

- `vela_crypto::rekey::tests::admission_open_refuses_the_unsealed_legacy_shape`
- `vela_desktop_core::sync::tests::a_legacy_unsealed_chunk_is_refused_on_download`
- `vela_desktop_core::sync::tests::a_legacy_chunk_relabelled_to_a_newer_revision_is_refused`
- `vela_desktop_core::sync::tests::a_sealed_chunk_relabelled_to_another_revision_is_refused`
- `vela_desktop_core::sync::tests::download_gate_receives_false_facts_when_the_open_fails_or_the_epoch_is_zero`
- `vela_desktop_core::sync::tests::a_server_serving_an_older_revision_is_refused` (adapted to the facts API; same assertions and message)

## Before-fix regression evidence

Both changes were temporarily reverted in place, the focused tests rerun, and
the tree restored byte-identically (`cmp` against the saved fixed file). The
mutation diffs are against the fixed file.

1. **Sealed gate removed** (`open_sealed_fleet_chunk` → `open_fleet_chunk` at the
   download call only; diff in `before-fix-unsealed-gate.diff`). Command:
   `vela-heavy cargo test --manifest-path desktopVELA/Cargo.toml -p vela-desktop-core --locked --lib sync::tests::a_legacy`
   → exit 101, **2 failed**, 0 passed (`before-fix-unsealed-gate.log`):

   ```
   test sync::tests::a_legacy_chunk_relabelled_to_a_newer_revision_is_refused ... FAILED
   test sync::tests::a_legacy_unsealed_chunk_is_refused_on_download ... FAILED
   test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 465 filtered out
   ```

   The failure text records what the pre-fix path returned in both cases:
   `Available(VaultStore { … }, 9)` — i.e. each blob was decrypted and admitted
   at the server's inflated clock 9.

2. **Facts reverted to the old literals** (`aad_binding_verified: true`,
   `key_epoch_positive: true`; diff in `before-fix-asserted-facts.diff`).
   Command:
   `vela-heavy cargo test --manifest-path desktopVELA/Cargo.toml -p vela-desktop-core --locked --lib download_gate_receives_false_facts`
   → exit 101, **1 failed** (`before-fix-asserted-facts.log`):

   ```
   test sync::tests::download_gate_receives_false_facts_when_the_open_fails_or_the_epoch_is_zero ... FAILED
   test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 466 filtered out
   ```

The third new test (`a_sealed_chunk_relabelled_to_another_revision_is_refused`)
passes with and without the gate: it pins the binding the sealed shape already
had, so the legacy-shape gap is what the other two regressions isolate.

## What the tests establish and what they do not

Established by these tests:

- an unsealed blob encrypted under **this device's own chunk key** is refused on
  the desktop download path even with an inflated clock and no recorded
  baseline (before the fix it was admitted);
- an unsealed blob relabelled above a recorded baseline is refused (before the
  fix it was admitted);
- a sealed blob relabelled to another revision does not open;
- a failed open and a zero/negative epoch produce false facts, and the verified
  kernel rejects them;
- the rollback message and the rollback refusal point (before merge/baseline)
  are unchanged for a chunk that opens. If the open itself also fails, the
  authentication error is reported instead (still before any merge); that is
  the open-first ordering the step asked for, and it is strictly more specific
  than the old shape-blind rollback message.

Not established here:

- no refinement proof. Docs 17 and 18 still bound the kernel: they prove the
  decision over the facts they are given, not that a particular byte path
  produced them. This change makes the desktop's facts source observations
  rather than constants, but there is no machine-checked link from AEAD success
  to the flag.
- the mobile bridges were compiled and unit-tested only. JNI, Swift, Kotlin and
  native device execution were not run on this Linux host; the Kotlin/Swift
  substring match on `LEGACY_UNSEALED_REFUSAL` is textual (the added
  `Invalid parameter: ` Display prefix keeps the matched substring intact).
- the gpui and Tauri front ends were not built (disk constraint); only the
  `vela-desktop-core` library tests ran.
- the web client (U-27) is untouched and still has no admission export.
- two pre-existing legacy readers remain: enrollment bootstrap
  (`commands/devices.rs:397-496`) and the desktop audit chunk
  (`sync.rs:1343`). Both are outside the sync download path and documented in
  place; the audit reader still accepts an unsealed blob at epoch 1, so a
  malicious server can inject audit events into the local log until that path
  is tightened. That was true before this change and is not claimed fixed.
- the chunk id also enters the per-chunk key derivation
  (`Crypto::chunk_key`, `desktopVELA/vela-desktop-core/src/crypto.rs:299`), so
  the practically exploitable relabel for an unsealed blob is the revision
  (Lamport clock), which the regression tests exercise. The shared gate refuses
  any unsealed blob regardless of which label was changed.

## Follow-ups

1. U-27: add an admitted-download export to the WASM bridge (or move web onto
   the admitted path) so `plan_sync_epoch_match` and `plan_chunk_download` run
   there too.
2. Decide whether the enrollment bootstrap and audit-chunk readers should also
   require sealed ciphertext; both are legacy-compat reads, not sync admission.
3. Replace the English substring match for the unsealed refusal with an error
   code in all three ABI surfaces (FFI inventory F9).
4. The desktop still does not call `plan_sync_epoch_match` on the download path
   (F3's second half). It compares/adopts epochs through
   `plan_epoch_adoption`; whether an explicit exact-agreement gate should be
   added to the desktop manifest path is a separate design decision.
