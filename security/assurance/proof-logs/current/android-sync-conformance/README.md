# Android sync download/admission conformance

Baseline parent: `7e4dba6` (`Bind each challenge to one purpose and make account
deletion atomic`), branch `t3/android-sync-admission-conformance`. This is a
selected-component test increment. It does not change production code: the
`androidVELA/app/src/main` diff is empty (verified with `git diff`).

## What was checked

The Android sync download path composes four decisions:

1. `requireSyncBaselineAccount` — a durable token without a readable account pin
   refuses before any request (no empty baseline namespace).
2. `requireMatchingSyncEpoch` — the Rust `plan_sync_epoch_match` mobile gate:
   manifest and local epochs must be equal and positive. This device does not
   adopt a rotation during a download.
3. `syncBaselineScope` — floors are namespaced by normalized server,
   authenticated account and key epoch; a missing namespace entry is first
   contact, never clock 0.
4. `rejectRollback`, the native `plan_chunk_download` decision, and
   `recordAdmittedBaselines` — the whole-manifest floor and per-chunk floors may
   only rise; an admitted clock is recorded only after every chunk in the batch
   was admitted and persisted.

`SyncAdmissionModelTest` (new,
`androidVELA/app/src/test/java/com/vela/android/core/SyncAdmissionModelTest.kt`)
contains an independent Kotlin reference model (`RefState`) written from the
Rust semantics. It does not call the Android code under test. The Android side
is a harness around the production Kotlin functions above plus a fake of the
JNI chunk policy (sealed header, positive clock, per-chunk floor). The fake
deliberately omits the Rust bridge's *redundant* epoch-equality check so the
Kotlin epoch gate is observable; see "Not covered".

Universe: one server (`https://vault.example`), accounts `alice`/`bob`, chunk
ids `vault-data-000000`/`vault-data-000001`, clocks `0..3`, epochs `1..3`.

Commands model what a malicious or stale server can return:

- a chunk at `(chunk, clock, epoch)` sealed with the expected AAD, sealed with
  the wrong AAD, or legacy unsealed (72 commands);
- a manifest-only response at clock `0..3` (4);
- an epoch-adoption offer `1..3` with a bound, absent or foreign capsule (9);
- a replay of the last, first or last-accepted earlier chunk response (3);
- an account switch to `alice`/`bob` (2);
- a lost account pin (1);
- a deliberate local-security reset (2); and
- a delayed stale baseline write for a chunk at clock `1..3` (6).

The alphabet is therefore 99 commands. Five initial states are explored:
`alice` at epoch 1/2/3, a durable token with no pin at epoch 1, and `alice` at
epoch 1 with a recorded per-chunk floor of 2 (so the per-chunk gate is
exercised independently of the whole-manifest gate).

After every step the test compares:

- accepted / refused (and applied for state-only commands);
- the adopted epoch (must never change on the download path);
- every namespaced per-chunk floor and manifest floor;
- the admitted vault content (chunk → admitted clock);
- that floors never decrease (the one documented exception is a deliberate
  local reset, which clears all contexts);
- that a refused response leaves the entire state unchanged; and
- that branch/clock/epoch/account refusals were actually exercised
  (non-vacuity assertions below).

## Trace counts

Every command sequence up to depth 3 over the full 99-command alphabet is
explored from all five initial states:

| Run | Alphabet | Depth | Initial states | Traces | Steps |
|---|---|---:|---:|---:|---:|
| full | 99 | 3 | 5 | 4,851,495 | 4,900,995 |
| deep | 30 | 4 | 3 | 2,430,000 | 2,513,790 |

The depth-4 run uses a documented reduced alphabet (one chunk id, epochs
`local`/`local+1`, sealed/unsealed plus one wrong-AAD case, one account switch,
two replay kinds, reset, pin loss, stale write) because the full alphabet at
depth 4 is about 96M traces per initial state. It runs in the same JVM run as
the full depth-3 exploration when `VELA_ANDROID_SYNC_DEPTH=4`; without the
variable it is skipped (JUnit assume).

Non-vacuity assertions require, for the full run: every command kind both
accepted and refused (where applicable), `LosePin`/`Reset`/`StaleRecord`
applied, sealed chunks accepted, wrong-AAD/unsealed/clock-0 refused, equal
epoch accepted, older and skipped epochs refused, per-chunk and manifest
rollback refused, equal-clock redelivery accepted, replay both accepted and
refused, account switch both accepted and refused, cross-account switch and
missing-pin refused, and an accepted chunk at every local epoch 1/2/3. The
counts in `full.txt` and `deep.txt` show each of these is non-zero.

## Properties asserted explicitly

- A server response with an older clock than the recorded floor for that
  `(server, account, epoch, chunk)` is never admitted; equal-clock redelivery
  is admitted (the Rust `server_lamport >= seen` rule).
- A server response with an older epoch, or a jumped epoch, is never admitted.
  The mobile download path never adopts an epoch at all.
- The adoption ladder `plan_epoch_adoption` (separately enumerated over local
  1..3 × offered 1..3 × bound/absent/foreign capsule) adopts only
  `offered == local + 1` with a bound capsule; rollback, skipped transitions,
  absent capsules and foreign capsules are refused, and a refused/fetch
  decision changes no epoch. An adopted epoch starts a fresh
  `(server, account, epoch)` floor namespace without erasing the old epoch's
  recorded floors.
- One account's floors never affect another's: namespaces differ; recording
  `bob`'s floor leaves `alice`'s floor and manifest floor unchanged; a stale
  write inside `bob`'s namespace cannot lower it. The exhaustive run also
  shows a cross-account switch is refused and leaves both pins/floors intact.
- A refused response leaves every floor, the pinned account, the local epoch
  and the admitted vault unchanged (`refusedUnchanged` counts all refusals).
- Refused ciphertext never reaches the vault store.
- Manifest rollback: a first-contact chunk behind the recorded whole-manifest
  floor is refused even though its per-chunk floor is absent.
- A missing pin refuses before the epoch/floor path and before any state read
  or write.

## Mutation check

`requireMatchingSyncEpoch`'s `manifestEpoch == localEpoch` check was
temporarily weakened to `manifestEpoch >= localEpoch` (a real production file,
`VaultSyncManager.kt`). The new tests failed as required:

```
everyBoundedSyncTraceMatchesTheReferenceModel:
  full: verdict mismatch ... command=Chunk(clock=1, epoch=2, seal=SEALED)
  expected=REFUSED actual=ACCEPTED
refusedCiphertextsNeverReachTheVault:
  expected refusal for Chunk(... clock=2, epoch=2 ...) expected:<REFUSED> but was:<ACCEPTED>
adoptionLadderNeverAdoptsRollbackOrJump:
  mobile epoch gate must be exact equality expected:<false> but was:<true>
epochOffersNeverChangeTheDownloadEpoch:
  offer 1->2/BOUND expected:<REFUSED> but was:<ACCEPTED>
```

Full output: `mutation.log`; assertion messages: `mutation-failures.txt`. The
file was restored with `git checkout --`; `git diff -- androidVELA/app/src/main`
is empty in the final commit.

## Focused residual-coverage tests

- `IdentityRotationFieldIsolationTest` — changing `userId`, `deviceId`,
  `hybridEkB64`, `hybridVkB64` or `sealedB64` in isolation is refused by
  `requireUnchangedAuthenticationIdentity`; a share-key rotation or its
  metadata update is not an identity replacement.
- `IdentityRegistrationSuccessTest` — first identity registration pins the
  server-verified account/device, updates the key epoch to 1 and returns the
  token without a challenge; existing re-authentication confirms the same pin
  without resetting the epoch; share-key registration reaches the real HTTP
  client with the device-signed binding and accepts the rotated token.
- `BlankTokenRefusalTest` — a blank re-authentication token is refused before
  the retry and is never committed; a blank `X-New-Token` header is not
  collected or committed and leaves the durable token/floors untouched.

## Results

All heavy commands ran through
`~/.local/opt/vela-tools/bin/vela-heavy` (3 GiB cap, one heavy job at a time).
The full JVM unit suite passes **179 tests, 0 failures, 1 skipped** (the
skipped test is the depth-4 run, gated by `VELA_ANDROID_SYNC_DEPTH`). Before
this increment the parent reported 162 tests; the new files add 17 (10 model
tests + 2 + 3 + 2 focused tests).

| Log | Command | Result |
|---|---|---|
| `depth3.log` | `VELA_ANDROID_SYNC_DEPTH=3 … :app:testDebugUnitTest --tests 'com.vela.android.core.SyncAdmissionModelTest'` | BUILD SUCCESSFUL |
| `full.txt` | depth-3 exploration summary written by the test | 4,851,495 traces / 4,900,995 steps |
| `depth4.log` | `VELA_ANDROID_SYNC_DEPTH=4 … --rerun-tasks` | BUILD SUCCESSFUL |
| `deep.txt` | depth-4 reduced-alphabet summary | 2,430,000 traces / 2,513,790 steps |
| `focused-tests.log` | the three focused classes | BUILD SUCCESSFUL |
| `full-suite.log` | `:app:testDebugUnitTest` | BUILD SUCCESSFUL |
| `test-results.txt` | per-class JUnit XML summary | 179 tests, 0 failures, 1 skipped |
| `mutation.log` | weakened epoch check | BUILD FAILED (as required) |
| `mutation-failures.txt` | exact assertion messages | four tests failed |
| `environment.txt` | host/toolchain/parent commit | — |

## Not covered

- Real JNI/native crypto: `decryptAdmittedVaultChunkJson` is faked down to the
  chunk policy; the Rust bridge's own epoch check, AEAD open, sealed-header
  parsing and AAD derivation are not executed by these JVM tests.
- The Rust policy itself is covered by its own tests/proofs, not here.
- Keystore/`EncryptedSharedPreferences` (`SyncSettingsStore`,
  `ServerIdentityStore`), real filesystem atomic replace/power-loss behaviour,
  real HTTPS/Cronet, multi-process writers, and crash ordering between the
  vault write and floor commit.
- Multi-chunk manifests: each modeled chunk response's clock is also its
  manifest maximum. Production takes the maximum over all manifest entries;
  mixed-clock multi-chunk manifests are not enumerated.
- Android manager-level ordering (`syncNow`, auth retry, publication guards),
  the real account-switch/enrollment/recovery HTTP flows, and
  `adoptRmsAtCurrentEpoch` are outside this model.
- No Swift/iOS, no hosted macOS run, no external audit.

## Observations, not fixes

- The Android download path intentionally does **not** adopt a rotation: a
  legitimate `local+1` offer with a bound capsule is refused for downloading
  (matching `plan_sync_epoch_match`). Adoption lives in the separate
  enrollment/recovery flow, so the Rust adoption ladder is modeled separately
  and is not expected to match download verdicts.
- `adoptRmsAtCurrentEpoch` (enrollment/recovery, not the download path) reads
  the server's epoch and checks `state == "active"` / an optional
  `expectedEpoch`; it does not apply `server_epoch_is_next`. The assurance
  document already records that the adoption flag is caller-supplied. This
  model does not claim to cover it.
- `AccountAuthenticator` returns the `/auth/verify` token without a blank
  check; `registerAccount` filters a blank registration token, and the retry
  controller refuses a blank re-authentication token. A blank verify token
  does not create a new floor namespace (the account pin check still runs
  first), but it can leave an unusable durable token. This is a hardening gap
  outside the download-admission scope; no production change was made.
- No divergence was found in the modeled download path: no rollback was
  admitted, no floor was lowered, no epoch jump was adopted, and no
  cross-account floor was read.
