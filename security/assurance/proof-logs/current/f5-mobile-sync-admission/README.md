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
- **Account pin (review 1).** Android validates the server-verified `user_id`
  against the id already stored on the device before persisting the identity or
  storing/returning a token, on both `/account/register` and `/auth/verify`.
  First registration/enrollment/recovery may pin a previously unknown id;
  automatic re-authentication (including the recoverable-401 retry path) may
  only confirm the existing pin. A hostile server that answers 401 and then
  returns a different id is refused with the stored identity, token and
  baseline namespace unchanged. `IdentityBinding.kt` holds the shared,
  unit-tested decision used by production.
- **Concurrency (review 5).** Android funnels every settings mutation through
  one synchronized read-modify-write, commits synchronously (`commit`, not
  `apply`), and publishes the new `StateFlow` value **inside the same lock**
  after the commit. A slow older writer therefore cannot publish its stale
  snapshot over a newer one. iOS wraps its baseline read-modify-write in a
  process-wide `NSLock`. That is a single-syncing-writer-process guarantee
  only (today the app's `AccountViewModel`; the AutoFill extension does not
  sync). App Group `UserDefaults` has no cross-process transaction: a second
  writer process could interleave whole-map get/set and **lower** a clock or
  **erase other chunks/contexts**. No "never lower" or "re-admit once"
  guarantee is claimed for that unsupported configuration.
- **Baseline ordering and corruption (review 6).** Baselines are recorded only
  after the admitted plaintext was decoded, merged and explicitly persisted
  locally (`vault.replaceAllAdmitted` / `repo.save`), and uploads only after
  every write succeeded. `replaceAllAdmitted` requires an unlocked RMS and a
  successful write before it publishes or runs the baseline recorder; a lock
  race (AutoLock during a background sync) or storage failure therefore leaves
  the floors unchanged instead of advancing without a persistent vault.
  `EncryptedVaultStore.save` now writes a temp file, syncs its data, and
  atomically renames it over `vault.enc`. The parent-directory entry is not
  fsynced (the Java/Android File API cannot), so power-loss durability of the
  rename itself is an OS/filesystem guarantee we rely on, not one this change
  proves. A failed/partial batch records nothing. Unreadable baseline JSON
  fails closed and the original bytes are preserved on unrelated writes, so
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
| `android-kotlin-tests.log` | `sh ./gradlew --no-daemon --offline -Dorg.gradle.jvmargs=-Xmx1536m --max-workers=1 :app:testDebugUnitTest` (full JVM unit suite) | **BUILD SUCCESSFUL; 139 tests, 0 failures** (`android-kotlin-tests.log` lists every class) |

The Android count is from
`app/build/test-results/testDebugUnitTest/*.xml` (`tests=139`,
`failures=0`, `errors=0`), not from the bare `BUILD SUCCESSFUL` line. The
focused sync/security/core subset alone is 69 tests; the earlier increment's
sync-only count was 26. The Rust bridge and F* logs above are unchanged from
`57d8bf6`: this correction does not edit `libVELA/vela-sync-policy`,
`vela-android-bridge`, `vela-apple-bridge`, or the proof kernels, and they were
not re-run here.

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

The review-correction tests added here are:
`IdentityBindingTest` (hostile `/auth/verify` returns a different user id after
a 401: automatic re-auth is refused, first pin only for registration/recovery,
stored pin and baseline unchanged on failure); `SyncSettingsPublicationTest`
(controlled T1/T2 interleaving through the real `StateFlow` publication path,
failed commit publishes nothing, 8 concurrent token/baseline writers);
`LocalVaultAdmissionTest` (locked RMS and storage failure leave the baseline
recorder uncalled); `EncryptedVaultStoreTest.saveReplacesThroughATemporaryFile…`
(atomic replacement leaves no temp copy); and `AdmittedChunkFailureTest`
(legacy-unsealed refusal maps to an actionable migration error, rollback
refusals are not relabelled).

## Open (not claimed)

- **Swift could not be compiled or executed on this Linux host** (neither
  `swift` nor `swiftc` is installed). Caller-level Swift tests were updated and
  added (admitted-chunk policy, per-context namespacing/switching back,
  concurrent baseline writers, failed-decode-before-persist ordering) but are
  unrun here. The new iOS `legacyChunkNeedsMigration` error path and the
  throwing FFI wrapper are also unrun. Only the Apple Rust C-ABI bridge was
  executed.
- Rust JSON envelope parsing, JNI/C buffer handling, Kotlin/Swift language
  semantics and the exact FFI glue remain implementation-correspondence gaps.
  Nothing in this increment proves what the Swift compiler, JNI marshalling,
  Keystore/Keychain, or the filesystem actually do; those remain trusted
  OS/compiler/primitives boundaries.
- Local vault persistence is now temp-file + fd sync + same-directory atomic
  rename, with a check that refuses a filesystem that cannot rename atomically.
  The parent directory is not fsynced, so the rename's survival across sudden
  power loss is an OS/filesystem guarantee taken as trusted. The Android
  `EncryptedSharedPreferences.commit()` durability boundary is likewise an OS
  guarantee, and vault persistence plus baseline commit are not atomic. A crash can lose
  an unrecorded baseline advance and leave a replay window; no once-only or
  one-revision bound is established.
- iOS cross-process baseline writes are **not** serialized: the `NSLock` only
  covers one writer process. If a second process ever synced, its whole-map
  `UserDefaults` read-modify-write could lower a clock and erase other
  chunks/contexts. The code and this evidence make no "never lower" or
  "re-admit once" claim under that configuration; an App Group file lock or a
  transactional store would be required.
- Pre-C-2 **unsealed/clock-0** blobs must be re-sealed through an explicit
  migration path (trusted client, current epoch); they cannot be admitted
  as-is. The bridge still refuses them, and the Android and iOS production
  callers now surface a distinct "legacy unsealed chunk needs explicit
  migration" error instead of a generic unreadable/rollback failure. That
  migration path is **not implemented in this increment**; no
  rollback-protection claim is made for such data, and the gate was not
  weakened.
- Legacy un-namespaced baseline keys are deliberately not migrated (they cannot
  be attributed to a context after the fact): the first sync after upgrading is
  an explicit first contact, and reset removes the old keys. On Android this
  means the *previous global* `lamportClock` floor is not reused as a
  namespaced floor, so rollback protection for the pre-upgrade history begins
  at that first post-upgrade sync (one possible replay window) instead of
  mis-attributing a foreign context's clock. On iOS the old per-chunk keys are
  likewise ignored. This trade is deliberate; server-side whole-vault
  enforcement is unaffected.
- Sign-out (iOS) / local-security reset (Android) currently clear **all**
  baseline contexts because an install holds one account. If multi-account
  support lands, clearing must become account-scoped; otherwise signing out
  one account would erase another account's rollback floors.
- The caller-supplied `EpochAdoptionFacts::server_epoch_is_next` transition flag
  on the existing adoption path is unchanged and remains outside the verified
  decision for clients that adopt rotations.
- Global proof-boundary/correspondence/manifest/CI census of the new F-5
  artifacts is parent-owned and intentionally not modified here.

## Parent integration candidate (not published)

The parent integrates 57d8bf6 and 889b03c as 714aeb2/5086395 with the separate
chunk proof from 25bf944. `parent-fstar.log` checks six unique Rust tests,
15 sync Rust contracts (11 historical +4 epoch), 6 epoch lemmas and 20 chunk
lemmas in separate invocations. All verification conditions discharge. The
focused epoch module and both lemma modules have reviewed hash pins; the
source guard rejects local proof escapes/options, with only the exact generated
hax fuel/budget header allowlisted. Nine final guard tests pass separately.
The global local-candidate census is 249 Rust postconditions /256 selections;
26 handwritten lemmas are counted separately. Imported-library warnings remain.

`parent-android-bridge.log` records 28 passing tests; `parent-apple-bridge.log`
records 18. `parent-android-jvm.log` records a native-library rebuild followed by
139 passing tests (counts read from 20 JUnit XML reports, no failures/errors).
`parent-jni-symbols.log` lists the admitted-open export in the packaged arm64
and x86_64 libraries respectively; it is not a live JNI execution test.
`parent-gradle-config.log` is a dry-run configuration check after adding policy
sources/manifests to native-library task inputs, so policy changes cannot leave
the packaged JNI library stale. No new hax/toolchain cache key was introduced.

The parent noticed that abrupt-power-loss directory durability is not ensured
by data sync plus rename alone, and removed the once-only/one-revision bound
on a lost baseline advance. Static review R5 found further token-header-finally,
missing-pin fallback/durability and RMS-copy race gaps. Those are being fixed
separately; neither the 139-test result nor the pure IdentityBinding tests
establish those production failure paths. This candidate must not be published
as closing them. Swift remains uncompiled/unrun locally and will need hosted
macOS validation. See the current candidate scope note in the assurance package.
