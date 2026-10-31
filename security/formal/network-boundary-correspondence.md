# Network boundary models and Rust correspondence

Reviewed against implementation commit `148ff32` and the model changes in
this package. `check-correspondence.py` checks `correspondence.json` so that
changes to these reviewed artifacts require another correspondence review.
A matching hash detects absence of drift; it does not prove the mapping correct.
It covers the listed files, not the whole repository or every mobile caller.
The subsequent [boundary review](../assurance/07-boundary-review.md) reproduced
three caller/storage failures in desktop sharing at the baseline. The current
fix uses strict initial acceptance, serialized generation-checked snapshots and
a recoverable encrypted pin/content journal. Regression tests support that
mapping; no formal filesystem/atomic-implementation refinement is established.

## Share envelope v2 — M19c

The server is the network adversary, rather than an enforcing party. It can
seal its own envelopes, change delivery attribution, and replay signed ones.
Device signing and recipient decryption keys have explicit reveal rules.

| Rust observation or effect | Tamarin rule/term | Remaining obligation |
|---|---|---|
| `share_envelope::push_header` serializes sender account, device ID, verifying key, recipient account, recipient-key digest, lineage, revision in order | `header = <S, dev, vk, B, h(pk(dk)), lineage, rev>` | Length-prefixed bytes, UTF-8 parsing, key validation and integer encodings are abstracted by tuples |
| `signing_transcript` signs context + header + length-prefixed item | `sign(<'vela share item v2', header, item>, sk)` | Both hybrid signature components must verify in Rust; represented by one perfect signature |
| `seal_signed_item` / `open_signed_item` use `kem::seal_share` / `open_share` | `aenc(<'VSE2', header, item, sig>, pk(dk))` | KEM v2 and AEAD idealized; no proof of the concrete combiner |
| `admit` computes signature, recipient, attribution, pin, lineage and revision facts | `Recipient_FirstContact`, `Recipient_Update`, `SignatureVerifies`, `PositiveRevision`, `RevisionIncreases` | Facts are computed outside the pure policy proof; actual signature checks and persisted pins need review |
| `first_contact_is_admissible` requires no pin and a bound positive revision | Fresh `slot`, matching recipient/key digest and server-attributed S | No account-to-key authentication at first contact: attacker can supply its own key; honest-key premise on the authentication lemma is essential |
| `update_is_admissible` requires same pinned account/key/lineage and higher revision | Consumed/replaced `Pin(slot, B, dk, S, vk, lineage, rev)` | Each model update is atomic; the implementation journals new pins and pending items before vault writes and replays on open. Tests cover interrupted commits and serialized local writes; formal storage refinement remains unproved |
| Desktop `accept_share` records pin; `sync_received_linked_items` applies under it | `Accepted` and `Applied` | Android/iOS inbox admission uses the shared Rust bridge, but their native persistence and lack of desktop linked-update polling are not modelled |

The sender-update rule deliberately **overapproximates** the implementation:
it may sign any positive natural revision in its lineage, including repeats
and decreases. Production uses checked u64 increments. Receiver monotonicity
and authentication therefore do not rely on a well-behaved sender counter.
Rust u64 revisions embed into natural-number terms, where `<<` represents
strict increase. The model's public `rev` variable is message-sorted and the
`PositiveRevision` restriction uses equality/subterm ordering; additional
term shapes may satisfy that ordering. This is another overapproximation,
not a proof of the parser's integer type validation.
The model does not prove exact increments, u64 overflow handling, or global
single-accept behavior. Secrecy assumes the sender has the intended recipient
public key; a malicious initial key directory is outside that lemma.

Five lemmas: honest-key sender provenance (with signing-key reveal exception),
pin/lineage preservation, every applied revision exceeding all earlier
admitted revisions in the same slot, secrecy until
reveal of the exact recipient key before attacker knowledge, and a non-vacuous first-contact-plus-update witness.
The v1 baseline has one verified attack witness: a forged update is admitted
without revealing a key. Baseline verification means the attack exists.

## Enrollment fingerprint v4 — M13b

The server may replace the claim's `hybrid_ek` and `hybrid_vk`. The authentic
human comparison is represented by `JoinScreen(c, FP(vk, ek))` consumed in
`Primary_Confirm`. `verification::enrollment_fingerprint` hashes the domain
`vela enrollment device fingerprint v4` and both length-prefixed keys;
`commands/enrollment_v3.rs` computes the inspected pair's fingerprint and
compares the human choice before sealing the RMS.

`Primary_Confirm` seals only to a pair matching that screen. The v3 baseline
hashes the signing key alone, allowing substitution of the KEM key and RMS
disclosure. The fixed model proves RMS secrecy, confirmed-pair provenance,
seal-target provenance, and an honest adoption witness (four lemmas).

This is a focused key-binding model. It does not replace M13's server grant
lifecycle model, authenticate the primary to the joining device, or prove
that an adopted RMS originated at that primary. `Join_Adopt` only decrypts:
its reachability witness is not an authentication claim. No key reveal rules
are included. The 18-digit fingerprint is idealized as collision-free; human
comparison errors, online attempts and ~60-bit search resistance need separate
analysis. A ceremony fact binds the two screens as a trusted local channel.

## Challenge login — M27

The network adversary sees challenges and signatures and has signing oracles
for the listed alternate domains. The server remains an honest authenticator.

| Rust operation | Model | Limit |
|---|---|---|
| `auth/challenge.rs` stores a random challenge for 60 s | `Server_Challenge`, linear `Challenge` | Expiry omitted; deleting expired challenges can only remove successful traces |
| `auth/verify.rs` calls `store.get_del` | A successful `Server_Verify` consumes `Challenge` | Actual consumption precedes lookup/signature check, and invalid attempts can burn a challenge (availability outside model) |
| SQL lookup `WHERE id = ? AND revoked = 0` | `Server_Lookup` consumes/restores `DeviceActive`, creates linear `LookupResult` | Lookup and issuance are separate steps; in-flight issuance can race revocation |
| `signing::auth_message` binds domain, device ID and challenge | `sign(<'vela auth challenge v1', dev, ch>, sk)` | Tuples stand for the unambiguous length-prefixed bytes |
| Hybrid signature validation and `TokenService::issue` | `Verified`, `SessionIssued`; idealized signed token | Token parser, TTL, PASETO encoding, JTI revocation and renewal are not proved |

Six lemmas: signature provenance or key reveal, challenge single use, challenge
origin, no active lookup after revocation, correct registered user, honest
login reachability. **No claim that a token cannot be minted after concurrent
revocation.** Other-protocol signing oracles are selected abstractions, not a
complete composition proof. Registration is trusted setup.

## Additional checked sharing contracts

The actual `admission_facts` constructor now has a checked F* postcondition
for all its outputs, conditional on authenticated opening and the supplied
context. The desktop acceptance/generation/recovery decisions use checked
policy functions. See [M28 correspondence](share-journal-correspondence.md)
and the [formalization ledger](../assurance/08-formalization-status.md).
No composite Rust-to-protocol refinement theorem follows from these results.

## Reproduction

Install Tamarin 1.12.0 and Maude 3.5.1, then run:

```bash
python3 security/formal/check-correspondence.py
VELA_PROOF_OUT=/tmp/vela-network-logs security/formal/run-network-boundary-proofs.sh
```

The runner caps each proof at 180 seconds, one GHC worker and a 1500 MiB GHC
heap, with a 3 GiB process-tree cgroup and no swap. It fails on timeouts,
warnings, incomplete analysis, unexpected verdicts, or missing named lemmas.
Full logs from this package's local run are in
[`../assurance/proof-logs/current/`](../assurance/proof-logs/current/).
