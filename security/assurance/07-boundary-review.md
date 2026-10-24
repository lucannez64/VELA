# 7. Implementation-boundary review, 2026-10-23

**Three sharing-boundary failures were reproduced at the implementation baseline.
All three now have implementation fixes and regression coverage.**
The eight pure-policy proofs still hold under their stated input facts; they
must not be read as an end-to-end guarantee for these workflows.

This was a focused maintainer-side code review and executable check against
implementation HEAD `148ff32` plus this assurance working tree. It was not an
independent audit or a proof of the whole Rust system. Review concentrated on
M19c sharing, M13b enrollment key binding, M27 challenge login, hybrid signature
verification, KEM v2 and recovery reconstruction. Other handler families, full
SQL transaction semantics, native platform persistence, side channels, unsafe
FFI and dependency internals were not comprehensively reviewed.

## Current remediation

- **BR-1:** acceptance now rejects an already accepted/declined record or any
  existing pin, and requires a capsule. Decline also rejects accepted records.
  Acceptance commits the item ID and pin before attempting network deletion,
  so cancellation/failure of that request cannot discard local admission state.
- **BR-2:** every share-store read/modify/write workflow holds one AppState
  sharing mutex across its network awaits. Each encrypted snapshot has a
  generation; saving a stale generation fails instead of overwriting newer pins.
  Legacy snapshots default to generation zero and preserve their existing pins.
- **BR-3:** `shares.enc` now carries the new pin and pending item changes as one
  encrypted write-ahead record. It is durably replaced before vault mutation.
  After saving the vault, the pending changes are cleared durably. Opening the
  vault replays unfinished changes before exposing it, with the same stable
  item IDs. Recovery preserves intervening local edits and tombstones. Pins
  never regress during recovery, even if an operation returned an I/O error.

`write_secret_file` now uses unique private temporary files, syncs their
contents before rename and, on Unix, syncs the parent directory afterward.
Both vault and share records use it. Errors before rename preserve the old
file; errors after rename are uncertain commits, handled by idempotent recovery.
Existing unreadable/decryption-invalid stores produce errors rather than an
empty share history. This also makes vault opening fail closed if its share
metadata cannot be authenticated. Cached shares remain available offline when
only network refresh fails.

The [full desktop-core test log](proof-logs/current/sharing-fixes/desktop-core-tests.log)
and [reproduction instructions](proof-logs/current/sharing-fixes/README.md)
cover the fixes. The new CI `sharing-boundaries` job gates this suite; a new
successful CI run is still pending. Pure-policy sources/models were unchanged,
so the earlier hax/F* results retain their original scope.

These fixes are tested implementation correspondence, not a formal storage
proof. Serialization covers one shared AppState; multiple independent desktop
processes writing the same profile are not supported by this mutex. Restoring
an old disk image, filesystem/device violations of sync/rename semantics,
Windows power-loss behavior, old binaries rewriting the new journal format,
and malicious same-UID modification remain outside this evidence. Mobile pin
persistence remains outside the desktop fix.

The following findings and witness observations describe the **pre-fix** source
at `148ff32`; their line numbers refer to that baseline.

## BR-1: repeated acceptance discards the existing sender pin

Location: `desktopVELA/vela-desktop-core/src/sharing.rs`, `accept_share`,
particularly its call to `admit_received(..., None)` at line 609.

The command loads an existing share but never rejects `accepted == Some(true)`
and never supplies its stored pin. A second invocation therefore treats it as
first contact. A capsule signed by a different key, claiming the same sender
account and addressed to this recipient, can replace the original pin even
at a lower revision. It adds another vault item and repoints the share record
to that new item; it does not overwrite the old item's contents in this path.

The witness seeds a legitimately pinned share at revision 2, supplies a
revision-1 capsule signed by a different key, checks that admission with the
old pin rejects it, and calls the actual `accept_share` command. The command
succeeds, stores the other key at revision 1 and leaves two vault items.

Reachability: Tauri and GPUI expose the core command. Normal UI hides acceptance
for already accepted records. This is a command-level precondition failure;
no silent remote invocation or UI exploit was demonstrated. A malicious server
can supply candidate payloads during linked refresh, but the repeated command
invocation remains an additional prerequisite.

Required fix: reject already accepted records, validate required payloads, and
serialize acceptance with other operations on the same share. Passing a pin
alone is insufficient if the command continues to add duplicate vault items.

## BR-2: stale share-store snapshots can roll back newer pins

Location: `sharing.rs`, `load_share_store`, `save_share_store`,
`refresh_linked_shares_inner`, `get_shares`, and other read/modify/write callers.

The share store is read into a private snapshot and later rewritten in full.
There is no common transaction lock or generation compare at this boundary.
Background sync holds `sync_mutex`, but `get_shares` and acceptance do not
consistently participate in that lock. File encryption authenticates bytes;
it does not reject a stale but valid snapshot written by this process.

The witness obtains an old snapshot, saves a newer revision, then saves the
old snapshot. Reading the real encrypted file returns the old revision. This
reproduces the storage overwrite primitive and a possible interleaving; it
is not a full concurrent remote rollback exploit. Operations that modify
unrelated share records can also overwrite pins in another record because
all records share the same file.

Required fix: serialize all store mutations or use transactional compare/update,
with revision validation inside the serialized operation. Atomic file rename
alone does not prevent stale-snapshot overwrites.

## BR-3: vault updates and revision pins are separate durable writes

Location: `sharing.rs`, `sync_received_linked_items` (vault persistence around
line 353), followed by `refresh_linked_shares_inner` (share-store save around
line 209). Acceptance has the same two-store pattern.

The linked-update function persists new vault content before its caller saves
the new pin. Stopping at that boundary leaves the new content on disk with an
old persisted pin. A later replay above that old pin can pass the revision
gate. Separately, `save_share_store` directly uses `std::fs::write` without a
temporary file/rename or explicit fsync, so interrupted writes can damage it.
Several callers convert load/decryption/parse failure into an empty store;
that can discard the history needed for pinned admission.

The witness applies a correctly signed revision 3 to a revision-2 fixture,
stops before the caller's pin save, and reads the persisted vault with a new
Store object. It observes revision-3 item content and the revision-2 pin file.
This is an interruption-window simulation, not an OS power-loss test or a
full crash/restart attack. It does not establish filesystem durability.

Required fix: commit content and admission metadata together, or introduce a
recoverable journal with safe replay rules. Distinguish a missing store from
an unreadable/corrupt one, fail closed for pinned operations, and use durable
atomic replacement. A lock addresses BR-2 but does not close this crash window.

## Additional BR-4: recovery after an uncertain journal write

The selected-boundary review found that a failed atomic replacement can leave
a visible journal without an acknowledged durable directory entry. Merely
reading that journal is insufficient to authorize a later vault write under the
OS failure contract. The previous recovery path could mutate/persist the vault
before its next share-store write reported an error.

`finish_pending_items` now re-writes and syncs the pending journal successfully
before touching the vault on every recovery/retry. An error stops application.
The additional write is conservative on the normal path, where the initial
journal was already acknowledged; identical prepare writes are logical stutters.

The new `uncertain_journal_write_is_rearmed_before_recovery_changes_vault` test
injects a visible-write error, then a second error on recovery's share-store
write. It failed before the fix because the vault had already changed; it now
passes and verifies subsequent successful recovery. The failed-before log is
explicitly marked as such in `proof-logs/current/trusted-boundary/`.
The [counterexample patch](uncertain-write-counterexample.patch) removes only
that re-arm from the fixed source, retaining the test, so the previous failure
can be reproduced in a separate test checkout. Reversing the patch restores
the fix. This is an ordering/failure-injection test, not a physical power-loss proof.
OS durability semantics and concrete trace refinement remain obligations.

## Reviewed mappings that did not reveal a new mismatch in this pass

- Share envelope bytes bind sender account/device/key, recipient account/key
  digest, lineage, revision and item into the signature. Parsing rejects
  truncation, invalid key/signature lengths and trailing bytes. `admit` calls
  authenticated opening before constructing policy facts. Its mapping to the
  pure predicates was consistent on inspection; callers/storage above were not.
- Enrollment's primary fingerprints both inspected keys, compares the local
  choice, and seals to the copied inspected KEM key. The joining screen uses
  its own generated keys. This supports the manual M13b mapping, conditional
  on genuine human comparison. Primary-to-joiner authentication remains outside
  that focused model, as already documented.
- Login consumes the actual sled challenge with `get_del`; `Tree::remove` is
  its atomic one-shot step. Active-device SQL lookup and token issuance are
  separate, matching M27's documented revocation race. This inspection does
  not prove challenge durability over process/power loss or token correctness.
- Hybrid verification requires successful ML-DSA and Ed25519 verification.
  KEM v2 rejects noncontributory X25519 results and binds both public-key
  components and ciphertext context into its derivation. These are code
  observations, not a computational security reduction or constant-time audit.
- Recovery adoption sets its authentication fact only after `shamir::reconstruct`
  succeeds; the reconstruction checks authenticated shares. No independent
  Shamir/primitive correctness proof was performed.
- Android/iOS inbox callers use first-contact admission and do not retain the
  returned sender/revision pin in the inspected workflows. They do not implement
  desktop linked-update admission. Do not extend desktop pin persistence or
  exactly-once acceptance claims to these platforms.

## Reproduce and interpret the evidence

The historical diagnostic patch is
[`sharing-review-witness.patch`](sharing-review-witness.patch). To reproduce
the old failures, use a separate checkout at `148ff32` and copy this patch
there; it deliberately does not apply to the fixed source. At that baseline:

```bash
git apply --check security/assurance/sharing-review-witness.patch
git apply security/assurance/sharing-review-witness.patch
security/assurance/bounded.sh env CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm \
  cargo +nightly test --manifest-path desktopVELA/Cargo.toml \
  -p vela-desktop-core --lib assurance_boundary_review -- --nocapture
git apply -R security/assurance/sharing-review-witness.patch
```

All three tests passed because they assert the **unsafe current behavior**.
They are attack/interruption witnesses, not security regression passes. The
patch was removed after running; production source was restored byte for byte.
The tests use temporary directories and fabricated keys/accounts, no live server,
3 GiB process-tree memory, zero swap and one test/build worker. See
[`sharing-witnesses.log`](proof-logs/current/boundary-review/sharing-witnesses.log).
The checked policy/model sources did not change. Existing crypto unit tests
were separately rerun; their log is in the same evidence directory.

The findings above are remediated in the current desktop implementation and
covered by the regression suite. No whole-system confidentiality, integrity,
concurrency, crash recovery or outside-model attack guarantee follows from it.
