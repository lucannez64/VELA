# F-5: mobile sync download admission (review-corrected)

Baseline parent: `0b4ef27`. This increment cherry-picks `d8a6962` (mobile
admission, not yet in the parent) and corrects the read-only review findings
before integration. It is committed as one isolated change; no push/PR.

Selected trust boundary: OS/compiler and primitive security, per
`security/assurance/09-target-contract.md`. This is a selected-component
increment, not full-system formalization. Global assurance,
`proof-boundary.json`, correspondence/`MANIFEST.sha256` and CI wiring remain
parent-owned and are untouched here.

## Change

- Android and Apple production sync downloads route every chunk through the
  narrow Rust bridge entry points that compare the raw manifest/local epoch
  integers (`plan_sync_epoch_match`), perform the real AEAD open, and only then
  run the verified `plan_chunk_download` rollback decision. `aad_binding_verified`
  is derived from the successful Rust open, never from caller JSON.
- **Legacy-unsealed gate (review 1).** `open_fleet_chunk` keeps the pre-C-2
  wire shape readable at epoch 1 during migration, and that shape includes
  unsealed `aead::encrypt` blobs that bind neither chunk nor clock. Both
  production bridges now require `aead::is_sealed` first and refuse unsealed
  legacy ciphertext ("migrate it through the explicit pre-C-2 path"). Sealed
  epoch-1 blobs bind `chunk_id ‖ lamport_clock`; sealed epoch-2+ blobs also bind
  the epoch. The lower-level `decrypt_vault_chunk_*` helpers keep reading
  legacy blobs for migration and make no admission claim. Regression tests in
  both Rust bridges seal with `aead::encrypt` and request admission at epoch 1
  and 2 with an inflated clock/baseline; both are refused, while the low-level
  reader still opens the same bytes.
- **Per-context baselines (review 2).** Android `EncryptedSharedPreferences`
  and iOS App Group `UserDefaults` baselines are namespaced by
  `(normalized server, authenticated account, key epoch)`:
  - a missing entry is explicit first contact (`None`, never clock 0);
  - switching servers/accounts does not inherit another context's counters;
  - switching back preserves that context's own baseline;
  - adopting a rotated epoch starts a fresh context, so restarted server
    counters are not rejected against the old epoch's record;
  - the whole-manifest floor is namespaced the same way;
  - only a deliberate sign-out (iOS) / local-security reset (both) clears
    baselines. Routine `updateServer` for the same context does not.
- **Concurrency (review 5).** Android now funnels every settings mutation
  through one synchronized read-modify-write and commits synchronously
  (`commit`, not `apply`) before publishing, so a concurrent token refresh and
  baseline advance cannot lose each other. iOS wraps its baseline
  read-modify-write in a process-wide `NSLock`. Cross-process app/extension
  writes remain unsynchronized in `UserDefaults`; that is documented as a
  residual (a missed advance, never a lowered baseline).
- **Baseline ordering and corruption (review 6).** Baselines are recorded only
  after the admitted plaintext was decoded, merged and durably persisted
  locally (`vault.replaceAll` / `repo.save`), and uploads only after every write
  succeeded. A failed/partial batch records nothing. Unreadable baseline JSON
  now fails closed and the original bytes are preserved on unrelated writes, so
  corruption cannot be laundered into an empty baseline; only an explicit reset
  clears it.
- **Permit clock used (review 9).** Both bridges return the Lamport clock the
  verified policy admitted (`AdmittedChunk`), and Kotlin/Swift baselines record
  that value rather than the manifest entry they asked for. The dead
  `rms_b64` field on the Android admitted request was removed (the JNI path
  passes the RMS as bytes).
- **F\* kernel strengthened (review 8).** A hand-written module
  `proofs/fstar/epoch-lemmas/Vela_sync_policy_epoch_lemmas.fst` states the F-5
  property parametrically: accepted ⇒ positive+equal; positive+equal ⇒
  accepted; decision = an *independently written* predicate; explicit refusal
  direction; plus the two parametric forms over bare epochs. It is checked in
  the same `fstar.exe` invocation as the extracted kernel.
- `verify-fstar-epoch.sh` is now staged mode `100755` (review 3) and checks both
  the extracted module and the lemma module.

## Checked artifacts and exact counts (for the parent's census)

| Artifact | Content | Count |
|---|---|---|
| `proofs/fstar/extraction/Vela_sync_policy.fst` | historical selected set, byte-identical after regeneration | 11 postconditions |
| `proofs/fstar/extraction-epoch/Vela_sync_policy.fst` | new F-5 kernel: `plan_sync_epoch_match` + 3 concrete witness functions | 4 postconditions |
| `proofs/fstar/epoch-lemmas/Vela_sync_policy_epoch_lemmas.fst` | new universal/parametric lemmas | 6 lemmas |
| `verify-fstar-epoch.sh` | extracts with hax, then checks extraction + lemmas | mode `100755` |

Neither module contains `admit`, `assume val`, or lax flags. `epoch-kernel.log`
ends with `Verified module: Vela_sync_policy`,
`Verified module: Vela_sync_policy_epoch_lemmas` and
`All verification conditions discharged successfully`.

## Test evidence

All heavy commands ran through
`~/.local/opt/vela-tools/bin/vela-heavy` (3 GiB / no swap / one worker or one
Gradle worker). Cargo reused the parent worktree's cache via
`CARGO_TARGET_DIR=/home/hirew/.t3/worktrees/VELA/t3-700776df/target`.

| Log | Command | Result |
|---|---|---|
| `policy-tests.log` | `cargo test --locked --offline` in `libVELA/vela-sync-policy` | **5 passed, 0 failed** |
| `epoch-kernel.log` | `./verify-fstar-epoch.sh` | extraction + **4 postconditions + 6 lemmas** verified |
| `existing-policy-proof.log` | `./verify-fstar.sh` (also runs the focused script) | **11 postconditions** unchanged, then 4 + 6 verified |
| `android-bridge-tests.log` | `cargo test --locked --offline` in `libVELA/vela-android-bridge` | **28 passed, 0 failed** |
| `apple-bridge-tests.log` | `cargo test --locked --offline` in `libVELA/vela-apple-bridge` | **18 passed, 0 failed** |
| `android-kotlin-tests.log` | `sh ./gradlew --no-daemon --offline -Dorg.gradle.jvmargs=-Xmx1536m --max-workers=1 :app:testDebugUnitTest --tests 'com.vela.android.sync.*'` | **BUILD SUCCESSFUL; 26 tests, 0 failures** (`EpochSyncContractTest`: 7) |

The Android count is from
`app/build/test-results/testDebugUnitTest/*.xml` (`tests=26`,
`failures=0`, `errors=0`), not from the bare `BUILD SUCCESSFUL` line.

New production-path tests cover: valid forward download and equal-clock
redelivery; rollback against a recorded per-chunk clock; relabelled-clock and
corrupted-ciphertext authentication failure (including an attempted
`aad_binding_verified: true` in JSON); nonpositive clocks/epochs and mismatched
positive epochs; cross-client wire reads at epochs 1–3; **legacy-unsealed
blobs refused at epochs 1 and 2 with an inflated clock/baseline** (both
bridges, with the low-level reader still opening them for migration); sealed
epoch-1 chunk/clock binding; baseline namespacing, first-contact, epoch
adoption restart, malformed-JSON fail-closed, and concurrent token/baseline
writers in the Android JVM tests.

## Open (not claimed)

- **Swift could not be compiled or executed on this Linux host** (neither
  `swift` nor `swiftc` is installed). Caller-level Swift tests were updated and
  added (admitted-chunk policy, per-context namespacing/switching back,
  concurrent baseline writers, failed-decode-before-persist ordering) but are
  unrun here. Only the Apple Rust C-ABI bridge was executed.
- Rust JSON envelope parsing, JNI/C buffer handling, Kotlin/Swift language
  semantics and the exact FFI glue remain implementation-correspondence gaps.
- Crash atomicity between local vault persistence and baseline commit is not
  proved: a crash in the window re-admits one revision, it cannot lower a
  baseline. Android `EncryptedSharedPreferences` durability beyond a successful
  `commit()` is an OS guarantee taken as trusted.
- iOS cross-process (app vs. share extension) baseline writes are not
  serialized; App Group `UserDefaults` has no cross-process transaction. The
  failure direction is a missed advance, documented in `SyncEngine`.
- Pre-C-2 **unsealed/clock-0** blobs must be re-sealed through an explicit
  migration path (trusted client, current epoch); they cannot be admitted
  as-is. That migration path is **not implemented in this increment**: the
  low-level readers remain for it, but a legacy unsealed server blob now fails
  the mobile sync closed (visible error, no automatic downgrade of the gate).
  No rollback-protection claim is made for such data.
- Legacy un-namespaced baseline keys are deliberately not migrated (they cannot
  be attributed to a context after the fact): the first sync after upgrading is
  an explicit first contact, and reset removes the old keys. On Android this
  means the *previous global* `lamportClock` floor is not reused as a
  namespaced floor, so rollback protection for the pre-upgrade history begins
  at that first post-upgrade sync (one possible replay window) instead of
  mis-attributing a foreign context's clock. On iOS the old per-chunk keys are
  likewise ignored. This trade is deliberate; server-side whole-vault
  enforcement is unaffected.
- The caller-supplied `EpochAdoptionFacts::server_epoch_is_next` transition flag
  on the existing adoption path is unchanged and remains outside the verified
  decision for clients that adopt rotations.
- Global proof-boundary/correspondence/manifest/CI census of the new F-5
  artifacts is parent-owned and intentionally not modified here.
