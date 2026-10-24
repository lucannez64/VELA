# M29: composed signed sharing and durable commit

M29 is a single transition system joining signature checking, first-contact
pinning, updates and journal/vault/cleanup. All eleven named lemmas pass. It is
not a machine-checked trace refinement of all Rust, native callers and OS calls.

## Primitive and attacker boundary

ML-DSA and Ed25519 are separate ideal signatures with independently generated
keys and independent reveal rules. A fresh-message provenance exception requires
both component secrets to have been revealed before admission/application; a
single revealed component is insufficient in the model. Actual key generation
uses independent OS randomness. Primitive unforgeability is trusted under the
maintainer-selected boundary; a quantitative computational reduction is not
claimed by these symbolic results.

The attacker chooses sender payloads (including repetitions) and sees the complete signed plaintext and both signatures. This is a
conservative authentication abstraction of encrypted transport, and intentionally
does not assume/prove security of VELA's hybrid KEM combiner. It can replay,
reorder, reattribute, generate its own keys and use selected cross-domain signing
oracles. No first-contact account-to-key authenticity claim follows: provenance
is conditional on an honestly generated pinned key pair.

## Production mapping

| Concrete code | Model or checked contract | Unproved seam |
|---|---|---|
| `signing::verify` checks ML-DSA first, then Ed25519; success uses `hybrid_components_verify` | Three checked AND-gate postconditions; both `Verified` actions in FirstJournal/UpdateJournal | Primitive API contract and wrapper control-flow refinement; encoding of ML-DSA context plus transcript |
| `Reader::take` uses `split_envelope_prefix` | Checked exact-prefix/suffix or rejection postcondition, plus reader-state regression | Full length-prefix/u64/UTF-8 parser round trip and transcript injectivity |
| `admit` calls `plan_observed_share` | Checked decoded-fields -> facts -> policy composition and actual permit revision getter | Correct authenticated-open observation and independent account/attribution/pin context |
| `plan_observed_share` authorizes an update only for matching account/key/lineage and higher revision | UpdateJournal matches the stored sender frame and applies RevisionIncreases | Concrete pin copying/persistence and model trace relation |
| First acceptance saves a stable item ID, pin and pending contents | FirstJournal, one linear DiskEmpty consumed; first-pin uniqueness | Actual acceptance/store-load/control-flow refinement |
| Journal -> vault -> cleanup; recovery before opening | Separate DiskPending / DiskApplied / DiskClean transitions | Durable atomic single-file I/O contracts and recovery implementation refinement |
| `sharing_mutex` and generation checks | One linear product state and retained stale snapshot observations | Scheduler/lock contracts and participation of every concrete caller; independent processes excluded |

The immutable sender frame is a tuple of account, both verification keys and
lineage. Regrouping these fields adds no guard. `PinObserved` is instrumentation
on transitions consuming existing pinned state; it does not constrain traces.
Its origin lemma gives induction hypotheses through read/recovery loops.
Every reused lemma is proved. Helper lemmas are hidden where unnecessary to
control proof-search growth, not to add assumptions. See the
[Tamarin lemma-reuse documentation](https://tamarin-prover.com/manual/master/book/007_property-specification.html).

The witness includes honest signing-key generation, two actual sender sends,
no signing-key reveals, a crash between journal and application, and a later
update. It therefore does not establish reachability solely with attacker keys.

The vault revision is a provenance label, not an extra serialized VaultItem
field. Identical retry writes stutter at the logical state level. Local edits,
tombstones and RMS migration are not in M29; concrete recovery choices have
separate F* proofs and tests. M29 is not a full joint enrollment/recovery/sync/
session composition or a computational confidentiality theorem.

Recovery now explicitly re-arms a read pending journal with a successful durable
write before changing the vault. A visible journal from an earlier failed write
is not treated as a durability acknowledgment. An injected-error regression
failed before this safeguard and passes after it. This strengthens the concrete
mapping to journal-before-vault ordering; a full I/O trace proof is still open.
