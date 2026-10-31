# 9. Selected whole-system proof boundary

The maintainer selected: **trust OS/compiler and primitive security; prove VELA's
constructions and application behavior**. This replaces the earlier undecided
scope. It does not make existing VELA constructions trusted primitives.

## Trusted interfaces

- OS entropy returns independent unpredictable bytes or reports failure.
- Standard synchronization, isolation, time and filesystem interfaces obey
  explicitly stated contracts. For the journal, successful file sync followed
  by atomic replacement and directory sync has the advertised durability;
  failures may leave either the before or after state. A failed write may be
  visible without confirmed durability; reading it does not upgrade that status. Disk-image restoration,
  malicious same-UID access, device/OS compromise and independent writers that
  bypass the profile lock are outside this application theorem.
- Rust/LLVM and native language compilers correctly implement their languages;
  proof extraction and proof checkers remain an explicit trusted toolchain.
  Standard-library semantics and the String/Vec compatibility models must still
  correspond to those language contracts; the local models are not new axioms
  granting application correctness.
- The pinned signature, KEM/DH, AEAD, hash, KDF and password-hashing primitives
  meet the precise security notions used by a proof. Their implementation,
  compiler assembly, CPU behavior and leakage resistance are excluded from
  this project. Primitive assumptions must be named per theorem; one primitive's
  assumption cannot silently stand in for a hybrid-combiner reduction.

The protocol adversary controls the network and can operate a malicious server
where the particular claim allows it. Compromise events, trusted human comparison
and initial key-directory/pin assumptions must be stated per claim. First-contact
TOFU does not establish person/account-to-key authenticity against that server.

## Application and construction obligations retained

| Target | Intended statement | Current boundary |
|---|---|---|
| TC-1 signed admission | A persisted remote item comes from the pinned sender under the complete signed recipient/account/key/lineage/revision context, unless the required signing secrets were already compromised | M19c and composed M29, plus checked decoded-field/policy composition; concrete I/O/crypto-wrapper trace refinement is still required |
| TC-2 recoverable state | A stale snapshot cannot regress pins; journal/vault recovery preserves safety under every allowed failure/retry/interleaving; accepted records cannot re-enter first contact | Production decision proofs, M28 and interruption regressions; actual I/O/collection/lock refinement remains open |
| TC-3 construction security | AND signatures preserve content authenticity while either independently generated component remains secure; hybrid KEM/AEAD and recovery/KDF constructions satisfy stated games under primitive assumptions | Pointwise AND-gate and ideal-signature proofs, plus scoped CryptoVerif construction games; concrete group/scalar, KDF/encoding, Rust and game-composition correspondence remain obligations |
| TC-4 server behavior | Concrete authentication, enrollment, recovery, sharing, revocation and vault handlers refine their specified state machines, with real database and token transitions | Selected policies/model tests; handler and database refinements remain open |
| TC-5 all clients | Desktop, Android, Apple and web callers enforce the same authenticated context and durable admission decisions; FFI preserves these contracts | Shared Rust proofs and bridge tests cover selected paths; native callers/storage and whole-client composition remain open |
| TC-6 protocol composition | Joint enrollment/recovery/sync/sharing/session execution preserves the scoped confidentiality, authenticity, integrity and compromise-resilience claims | Existing scoped models and composition abstractions; a full joint-system theorem is not established |

No current result proves all six targets. A model that assumes encryption ideal
has not proved the VELA KEM combiner merely because primitive implementations
are trusted. Likewise a boolean decision proof does not establish its caller's
observations or side effects. CI runs and independent review supply assurance
evidence, not substitutes for a missing theorem.
