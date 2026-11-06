# Mobile sync admission candidate

This local candidate routes Android and Apple downloads through a Rust bridge
that compares the supplied integer epochs, requires sealed ciphertext, opens
it with the expected AAD, then applies the sync chunk policy. The admitted
clock is returned to the caller for its baseline update. Epoch-1 seals bind
chunk id and clock; later epochs additionally bind epoch.

The focused epoch extraction adds four Rust postconditions. Six handwritten
lemmas characterize acceptance as positive/equal integer inputs. Twenty
separate handwritten chunk lemmas characterize the existing chunk planner.
The two extractions have the same F★ module name and are checked in separate
invocations with disjoint include directories. The Rust corpus is 249
postconditions / 256 selections over fourteen inventoried artifacts. The 26
handwritten lemmas are counted separately. There is no composed byte-to-client
or whole-system theorem.

The candidate uses server/account/epoch namespaces for per-chunk and manifest
floors. Missing entries are first contact. Android's synchronous settings
commit and StateFlow publication share one lock. Admitted vault writes require
a consistent usable key and a successful persistence path before recording
floors; the ongoing key-snapshot review is described below. iOS uses an NSLock
within one writer process. A second process could overwrite whole maps,
lowering floors and erasing other contexts; that configuration is not supported
by the current guarantee.

## Runtime review status

The fail-closed correction implements the token-header, missing-pin and RMS-
snapshot fixes found by prior review. The production retry controller accepts
collected headers only after its operation/retry succeeds and clears them on
failure; API/SSE collectors ignore non-2xx headers. Identity records commit
synchronously; missing account pins refuse sync before requests and cannot
become an empty namespace. A shared RMS monitor makes copy/replace/zeroize
coherent. Recovery preflights a different existing pin before enrollment/writes.

The latest parent JVM run passes 162 tests, including production retry/auth components
with a fake HTTP transport. It does not execute real HTTPS, JNI, Keystore or
physical filesystem failure. Focused internal review found no code blockers.
Bootstrap authentication/share-key setup may save a validated token before the
retry controller; its guarantee is scoped to the controller's operation.
Concurrent identity replacement during a request is checked again inside the
atomic record update; a changed or vanished snapshot refuses the result. No end-to-end auth/storage trace theorem is claimed.

## Persistence and compatibility limits

Android writes a temporary file, flushes/syncs its data, and requests atomic
same-directory replacement. It does not sync the parent directory, so survival
of that rename across abrupt power loss is not ensured here. Vault and
baseline writes are separate: a crash can lose an unrecorded floor advance
and leave a replay window, without a one-revision/once-only bound. Shared
preferences and filesystem effects remain unproved interfaces.

Legacy unsealed or clock-zero ciphertext fails mobile admission closed.
Distinct migration errors are exposed, but a trusted migration/re-sealing
workflow is not implemented. Old un-namespaced floors are not migrated; the
first post-upgrade sync is an explicit first-contact replay window. Sign-out/
reset clears all contexts under the one-account-per-install assumption.

The Rust bridge tests and JVM tests exercise selected implementation paths.
They do not prove JNI/C/JSON handling, Swift/Kotlin semantics, Keystore/Keychain,
storage concurrency or crash behavior. Swift cannot be compiled/run on this
Linux host; hosted macOS validation remains necessary. Actual Android libcore
atomic replacement and native JNI execution are separate from Linux JVM tests.
The existing adoption flag server_epoch_is_next remains caller-supplied.

[Evidence](proof-logs/current/f5-mobile-sync-admission/README.md) retains the
delegated snapshot separately from parent integration checks. Auth
corrections have their own evidence rather than retroactively relabelling tests.


The renewed internal review confirmed the core controller fixes and requested
claim corrections and a missing publication guard. The follow-up checks identity
snapshot consistency inside authentication/recovery writes, refuses vanished
registration records and blank re-auth tokens, and guards publication epoch HTTP
requests. The controller's token guarantee excludes bootstrap and explicit
intermediate rotations. A captured RMS may finish persistence after lock; there
is no session cancellation lease. SSE has no missing-pin guard and does not touch
rollback floors. Helper tests do not execute full manager/recovery lifecycles.
The focused internal review found no code blockers; hosted validation passed on fdee2bc for this increment. It was a static review, not an external audit.


Residual coverage: JVM tests do not execute manager-level auth/recovery ordering,
publication HTTP guards or the actual SSE transport. The metadata-only test
checks the snapshot helper, not write-path preservation. Field-isolated rotation
refusal, successful registration and blank-token refusal lack dedicated tests.
A refusal after server enrollment can leave a server-side record requiring retry;
retry idempotency is unproved. Recovery may already have cleared its old token
before a concurrent replacement is detected. The pre-existing recovery RMS
cleanup on exceptional exits is also outside this increment. SSE itself does not
advance floors; sync triggered by SSE uses the regular guarded sync path.

## Bounded client conformance (after 7e4dba6)

**Android** ([evidence](proof-logs/current/android-sync-conformance/README.md)):
an independent Kotlin model of the shared Rust floor/epoch rules is compared
with the production Kotlin gates (`requireSyncBaselineAccount`,
`requireMatchingSyncEpoch`, `syncBaselineScope`, `bindVerifiedUserId` and the
admitted-baseline merge) over every sequence of up to three server responses
(4,851,495 traces across five initial states; a reduced 30-command alphabet
to depth four, 2,430,000 traces). No rollback, floor decrease, epoch jump or
cross-account floor effect was admitted; weakening the epoch check fails the
test. The native AEAD/AAD path is faked down to the chunk policy, and the
gates are exercised as functions, not through the full manager. The focused
tests listed as missing above (field-isolated rotation refusal, successful
registration, blank-token refusal) now exist, and `/auth/verify` now refuses
a blank token before the identity record is touched.

**iOS** ([evidence](proof-logs/current/ios-sync-conformance/README.md)): the
same style of model drives the real `SyncEngine.sync`, the Rust admission
bridge and `VaultRepository` over all 1,110 sequences of up to three
responses, plus a 360-call kernel grid. It runs only in macOS CI, where it
passed on d3ccba6; its mutation check has not been run. iOS never
adopts an epoch on the download path and keeps a stricter manifest-wide
floor; both are recorded as deliberate, fail-closed differences.

Neither is a proof; Keystore, real HTTPS, multi-process writers and
manager-level ordering remain outside both tests.
