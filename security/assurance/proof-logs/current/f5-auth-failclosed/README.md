# F-5 review R5 corrections: fail-closed auth, identity and RMS handling

Baseline parent: `5086395` (includes `57d8bf6` + `889b03c` + independent chunk
proof `25bf944`). This is an isolated correction commit on top of that parent;
no cherry-picks, no push/PR.

Scope is the Android Kotlin auth/identity/security/runtime/test surface plus this
new evidence directory (`security/assurance/proof-logs/current/f5-auth-failclosed`).
`libVELA`, Gradle build scripts, the existing
`security/assurance/proof-logs/current/f5-mobile-sync-admission/README.md`,
global assurance, correspondence, `MANIFEST.sha256` and CI were **not** edited.

## Findings and fixes

### F1 (MEDIUM): a failed auth operation could persist an unaccepted token

Previous `VaultSyncManager.withAuthenticatedClient` had:

```kotlin
finally { acceptRefreshedToken(client.latestSessionToken()) }
```

and `AndroidVelaApiClient.request` recorded `X-New-Token` from **any** response,
including a 401. A hostile server could answer 401, then return a different
`user_id` plus an `X-New-Token` on `/auth/verify`; the pin check threw, but the
`finally` still wrote that token.

Fixes:

- `AndroidVelaApiClient` now collects `X-New-Token` only from 2xx responses, so a
  401 header is never even recorded. `VaultEventStream` likewise accepts its
  `X-New-Token` only from a 2xx stream response, not from a refused connection.
- The `finally` acceptance is gone. The retry/token-acceptance decision is now
  the production `SyncAuthController` used by both `withAuthenticatedClient` and
  `getManifestWithTokenRetry`.
- Tokens collected by `SyncAuthController` from operation/retry responses are
  committed only after that controller operation succeeds. Bootstrap authentication
  and explicit intermediate rotations are separate and may be persisted earlier.
  A fresh re-authentication token is committed only if the retry succeeds.
- `AccountAuthenticator` (extracted production auth state machine) validates the
  verified `user_id` before the identity write and before returning a token.
  `EXISTING` re-authentication refuses a missing/empty pin before any request.

Tests (`SyncAuthControllerTest`) exercise the real production controller,
`AccountAuthenticator`, and `AndroidVelaApiClient` parsing/header collection via
a fake `VelaHttpTransport`:

1. 401 → `/auth/verify` returns `mallory` + `X-New-Token`: pin mismatch throws,
   stored token/identity/baselines unchanged, no commit, collector cleared.
2. Successful 401 → retry accepts the final successful response token only.
3. Failure after a successful re-auth commits neither the fresh token nor a
   failed response's header token.
4. The real client ignores a 401's `X-New-Token` and still records a 2xx one.
5. `VaultEventStreamParserTest` checks the event stream accepts `X-New-Token`
   only from a 2xx response.

Tested boundary: Kotlin controller/authenticator logic, HTTP response handling
and pin ordering. **Not** tested: the JNI signing bridge, Android Keystore
`SharedPreferences`, a real HTTPS/Cronet stack, or a real hostile server.

### F3 (MEDIUM): async identity write could outlive the token; empty account fallback

`ServerIdentityStore.save` used `apply()` while the bearer token was committed
synchronously. A crash after the token commit but before the pin write could
leave a durable token with no account id. `baselineScope()` then mapped the
missing pin to `account=""`, which is a fresh namespace and silently bypasses
every previously recorded floor.

Fixes:

- Identity writes run through `SerializedIdentityRecord` and use synchronous
  `SharedPreferences.commit()` with a checked result. The seal key is committed
  synchronously too, so a sealed identity cannot outlive the key that opens it.
- `syncBaselineScope` calls `requireBaselineAccountId` and throws on a
  missing/blank account. It never produces the empty-account namespace.
- `requireSyncBaselineAccount(hasDurableToken, pinnedUserId)` rejects a sync
  **before its first request** when a durable token exists with no readable pin.
  A blank token remains the explicit fresh-install registration path; it is not
  an automatic re-auth.
- `AccountAuthenticator` `EXISTING` refuses a missing identity or empty pin
  before `/auth/challenge` or `/auth/verify`, so automatic re-auth cannot create
  a pin.
- Registration/verification persist the pin synchronously before the caller can
  commit the returned token.

Tests (`IdentityFailClosedTest`) cover: null/blank account scope throws; durable
token without a pin is rejected; corrupt/truncated JSON decodes as no pin (not an
empty account) and leaves the durable token/baselines untouched; concurrent
whole-record updates do not lose a rotation; a failed identity write throws
before a token can be returned; `EXISTING` with an empty pin makes zero
requests.

Tested boundary: serialization/pin ordering and fail-closed decisions on the
JVM. **Not** tested: an actual process crash between two Android
`EncryptedSharedPreferences.commit()` calls, or the Keystore implementation.

### F4 (LOW): RMS copy raced lock zeroization

`SecureVaultManager.rms` was a plain field; `lock()` zeroized it in place while
`currentRmsCopy()` could copy it, producing a torn or all-zero 32-byte key that
would be used to persist a vault and advance floors under the wrong cipher.

Fixes:

- New `RmsHolder` owns the bytes behind one small monitor for lock state,
  copies, replacement and zeroization. No asynchronous I/O is performed while
  the monitor is held.
- `SecureVaultManager` uses the holder for unlock/adopt/lock/session/RMS copy.
- Exact semantics are documented in `RmsHolder`: a snapshot already returned is
  a coherent detached key and **may finish after `lock()`**. Lock does not
  cancel in-flight vault/chunk I/O; it prevents new snapshots. A lock before
  the snapshot prevents persistence and floor advancement; a captured coherent
  snapshot may finish persistence and advance floors after lock. There is no
  additional session check or cancellation lease.

Tests (`RmsHolderTest`) verify a pre-lock snapshot survives and is not a view
into the zeroized key, and run a concurrent replace/clear vs copy race asserting
every snapshot is one coherent pattern, never torn or zeroized.

Tested boundary: the production `RmsHolder` helper and its concurrency
semantics. **Not** tested: `SecureVaultManager` itself because it needs an
Android `Context`/filesystem (no Robolectric in this suite), nor Android
Keystore/native crypto.

### F5: recovery replaced a pin before verifying it

`recoverAccount` did `getOrCreate()` then saved
`userId = callerUserId, deviceId = ...` before `/auth/verify` re-checked the
pin. A recovery attempt for another account could replace the stored pin and
only then fail, leaving changed local state.

Fixes:

- New `RecoveryAccountBinder` is the production ordering used by
  `recoverAccount`: validate the caller account against the existing pin
  (`INITIAL`, which may establish a first pin but refuses a different one)
  **before** the device-enrollment request and before any local write.
  `recoverAccount` also performs the same preflight before its existing
  `updateServer(..., "")` clears the token, so a wrong-account attempt does not
  discard the current session token either.
- A genuinely different existing account therefore requires an explicit local
  reset first; it is not silently re-pinned. The final identity update is a
  targeted `ServerIdentityStore.update` under the record monitor, so it cannot
  clobber a concurrent share-key rotation with a stale whole-record save.
- `finishV3Join`, `rotateShareKey` and `markShareKeyRegistered` also use targeted
  updates instead of whole-record stale saves.

Tests (`RecoveryAccountBindingTest`) verify a mismatched existing pin fails with
zero enrollments, zero identity writes and unchanged identity/token/baseline
scope; first recovery may establish a pin; same-account recovery only updates
the device id; an empty caller id is rejected before enrollment. The atomic
whole-record update is tested through `SerializedIdentityRecord` in
`IdentityFailClosedTest`.

Tested boundary: the production local ordering helper. **Not** tested: the real
WebAuthn assertion, native RMS combine, `/recovery/*` requests, or native key
material.

### F6: filesystem/native claims narrowed (no code behavior change)

- `Files.move(..., ATOMIC_MOVE, REPLACE_EXISTING)` requires API 26, which is
  this app's `minSdk`. The behavior was already in the parent; no Rust change.
- The parent directory entry is **not** fsynced. The `EncryptedVaultStore`
  comment now states precisely that survival of the rename across sudden power
  loss is **not ensured** by this code. Only reader atomicity (no partial vault)
  is claimed. This is not an invented OS durability guarantee.
- The vault-persist → baseline-commit crash window is not "one revision once":
  losing the baseline advance can allow a range of unrecorded clocks on a later
  sync. The code comment/evidence now say that instead of overclaiming.
- The legacy-unsealed gate is unchanged. Its migration path remains
  unimplemented and no rollback-protection claim is made for that data.
- Unit tests run on the Linux JVM. They do not prove Android filesystem rename
  behavior, power-loss behavior, or native crypto on a device.

## Test evidence

All heavy work ran through `~/.local/opt/vela-tools/bin/vela-heavy` (global
3 GiB / no swap / one worker). Working directory: `androidVELA`.

| Log | Command | Result |
|---|---|---|
| `android-kotlin-tests.log` | `sh ./gradlew --no-daemon --offline -Dorg.gradle.jvmargs=-Xmx1536m --max-workers=1 :app:testDebugUnitTest` | **BUILD SUCCESSFUL; 159 tests, 0 failures, 0 errors, 24 classes** |
| `junit-counts.txt` | parsed `app/build/test-results/testDebugUnitTest/TEST-*.xml` | confirms 159 / 0 / 0 / 0 |
| `commands.log` | environment and exact commands | — |
| `diff-stat.txt` | `git diff --stat` at evidence capture | — |

New tests: 20 (6 `SyncAuthControllerTest`, 7 `IdentityFailClosedTest`,
4 `RecoveryAccountBindingTest`, 2 `RmsHolderTest`, and 1 added
`VaultEventStreamParserTest`). Parent suite was 139.

No `cargo`, F*, Swift, Gradle build-script, `libVELA` bridge, global assurance,
correspondence, `MANIFEST.sha256` or CI commands were run; this correction is
Android Kotlin + JVM unit tests only.

## Open (not claimed)

- No Android instrumentation/emulator run. Android `EncryptedSharedPreferences`,
  Keystore, `Files.move` on a real filesystem, process kill/power loss and native
  JNI crypto remain trusted implementation boundaries.
- No real-network hostile-server test. The fake transport exercises the real
  request/response parsing and controller path, not TLS/Cronet.
- Recovery's WebAuthn/native-combine ceremony is unrun here; only the local
  pin-before-write ordering helper is tested.
- Parent-owned global proof census, correspondence, `MANIFEST.sha256` and CI
  wiring are intentionally untouched.

## Parent integration

Integrated as92c6c92. The parent full JVM run passes159 tests across24 JUnit
reports, with no failures/errors/skips; see parent-jvm.log and parent-counts.txt.
No Rust/F★/Swift changed in this auth correction, so the earlier bridge and
kernel checks remain separate evidence. Parent comment-only corrections make
key-snapshot timing precise: a lock before snapshot prevents a write; a coherent
snapshot already captured may finish. UI StateFlow is not a cancellation lease.

The first delegated final review failed because the Go subscription was not
active. The user renewed it, and an independent review was restarted. It is
pending. Parent self-review confirms retry-controller failures clear collected
headers before token commit and that auth/store callbacks are used in the
production manager. Bootstrap authentication/share-key setup can persist a
validated token before entering that controller; the controller's whole-
operation guarantee does not describe that earlier setup. Concurrent explicit
account reset/replacement during network requests remains a review question,
particularly validation against the current identity inside targeted writes.
The159-test result does not establish full auth/reset trace refinement.


### Renewed review corrections

The renewed review inspected production manager wiring but did not execute the
manager itself. Controller/client tests use fake HTTP; recovery binder tests
cannot exercise the manager's earlier token clearing. Assertions about untouched
token/baseline fixtures in those binder tests are helper-level evidence only.

Authentication and recovery now validate the current identity inside the atomic
record update against the identity used for the request (pin, device, long-term
public keys and sealed identity). Replacement or disappearance refuses the result;
registration no longer recreates a vanished record. Metadata-only updates remain
preserved. A changed sealed record also requires a retry, including when a rotation
changed it. The publication epoch check now runs the missing-pin guard before
network access. SSE still accepts a cached token without this account guard; it
does not read or advance rollback floors, and its headers require a 2xx response.
Blank re-authentication tokens are refused before retry.

`AuthenticationReplacementTest` drives both real authenticator branches with a
replacement or disappearance during HTTP, recovery replacement during enrollment,
and metadata-only changes. Full manager lifecycle, SSE transport, Android storage,
and native instrumentation remain outside these JVM tests.

Parent correction run: 162 JVM tests, 25 classes, zero failures/errors/skips; see `review-corrections-jvm.log` and `review-corrections-counts.txt`. This supersedes the 159-test snapshot for current runtime validation.
