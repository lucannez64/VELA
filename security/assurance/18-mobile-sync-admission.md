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

## Pending runtime review corrections

This candidate is not published with the independent chunk-proof increment.
Static review confirmed namespace pinning on the ordinary recoverable-401 path
but found that a rejected auth result's token header can still be saved by a
finally block. It also found asynchronous identity-pin persistence and an empty-
account fallback when a pin is missing, plus an unsynchronized RMS copy/zeroize
race. Those paths require corrections and tests before runtime publication.
Pure IdentityBinding tests alone do not establish production auth ordering.
Recovery's prior-pin replacement and platform atomic-move behavior are further
review obligations. Do not infer that the policy lemmas close these gaps.

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
delegated snapshot separately from parent integration checks. Pending auth
corrections have their own evidence rather than retroactively relabelling tests.
