# Research-Paper Potential — Honest Assessment

Which parts of VELA are genuinely novel research contributions versus solid
engineering that would be rejected as "an application of known techniques"?
Written 2026-08-28 to decide whether a paper is worth writing and where.

---

## 1. What is *not* novel (don't lead with these)

| Mechanism | Prior art |
| :--- | :--- |
| Hybrid PQC (ML-KEM-1024 + X25519 via HKDF; ML-DSA-87 + Ed25519) | Standard practice: TLS hybrid key agreement, Signal PQXDH, Apple iMessage PQ3. GL20-style hybrid composition arguments are published. |
| Shamir 2-of-3 recovery with cloud/server/contact shares | Social + cloud recovery is well explored (e.g., "Social Recovery" literature, Stellar's account recovery, Apple's recovery contacts). |
| Zero-knowledge vault, chunked encrypted blobs | Bitwarden/Vaultwarden, encrypted sync engines (CryFS, Cryptomator). |
| BLAKE3 domain-separated KDF from one seed | Deterministic key derivation is textbook; the registry is hygiene, not research. |
| Path ORAM itself | Stefanov et al. 2013; oblivious storage line (Recurphire, ObliviStore, Panda). |

A paper framed as "we built a post-quantum password manager" dies in review
at a security venue for exactly this reason.

## 2. Genuine candidates, ranked

### 2.1 Formally verified ORAM-mode equivalence in a deployed sync protocol (strongest)
VELA runs **two ORAM modes** — trivial ORAM (whole-vault sweep) below a
threshold, Path ORAM above — and the *selection function* is hax-extracted
from the Rust source into ProVerif, with both modes **proven observationally
equivalent for access-pattern hiding**, plus finite-workload stash
regression tests (`security/formal/oram-access-hiding-proverif-results.md`, m22b/m22c/m24).

Why this is a real contribution: mode-switching between an exact scheme and
an approximate/cheap one is exactly where implementations leak in practice,
and nobody (to our knowledge) has published a proof that the cheap mode
*never reveals more* than the expensive one — derived from implementation
code rather than a paper spec. The threshold (N=4) is an engineering choice
but the *method* (extract → model → equivalence proof → deploy) is the
paper.

**Venues:** POST, CSF, or PETS (systems track). Best paired with measured
overheads (sync bytes, latency, server-side timing distributions).

### 2.2 Single-seed, server-blind epoch rekeying (strong, systems-flavored)
`docs/VAULT_REKEYING_DESIGN.md` + `vela-crypto/src/rekey.rs` +
`vela-rekey-policy/`: because every key derives from one RMS via BLAKE3
domain separation, one rotation retires chunk keys, audit keys, ORAM state,
cloud recovery shares, *and outstanding ephemeral web-session keys
simultaneously* — with a server that only ever sees blob re-uploads, an
epoch in AEAD associated data, replay-safe idempotent commits, and rollback
via lazy timeouts instead of cron. ProVerif-proven.

Why novel: key rotation in E2EE systems is usually per-key and
partially-leaking (old shares survive); "rotate the seed, everything dies,
and the server can't even tell a rekey from a sync" is a clean property with
a proof. The interaction with distributed state (cloud shares held by
third parties, live browser sessions) is the hard part and is handled.

**Venues:** USENIX Security / CCS (systems sec), or EuroS&P.

### 2.3 Credential-less, process-ancestry IPC for browser extensions
The desktop IPC gate checks same-user identity, host executable basename,
and a recognized browser basename in a bounded process-ancestry walk. It does
**not** attest binary contents: attacker-controlled executables can use those
names. A provider-name branch also bypasses ancestry. This is an admission
filter, not proof of authentic browser provenance or credential authorization.

M6 models the higher-level handshake with a browser-channel assumption.
[M27](../security/formal/local-ipc-gate-assurance.md) now models local admission
and an explicit basename-impostor counterexample; its solver run is pending.
The original exact-binary and competitor-superiority claims are withdrawn.

### 2.4 Possession-proof recovery (M18) without releasing the server share
Recovery where the requester proves possession of two Shamir shares via a
challenge-bound keyed hash (verified against a staged commitment) and the
server **never releases Share 2** — plus two-phase, journaled, idempotent
share publication that makes same-epoch share mixing impossible. The
"recover without the server ever handing over its share" inversion is
genuinely different from published recovery designs, which all release
shares to the requester.

**Venue:** fits as a section of 2.2's paper, or EuroS&P/PETS.

### 2.5 The composite system ("a hardware-bound, metadata-private, PQ password manager, end to end")
Individually the ingredients are known; the *composition* — hardware-bound
identity, ORAM metadata hiding, PQ hybrid auth, ephemeral web sessions, and
verified recovery in one deployed product with red-team + formal assurance
— is a strong **engineering/experience paper**: USENIX Security practice
track, ACSAC, or IEEE S&P's "systemization/experience" tracks. Needs real
evaluation: sync latency/byte overhead vs. Bitwarden-class baselines,
ORAM bandwidth blowup at realistic vault sizes, unlock latency across 4
platforms.

## 3. Recommended strategy

1. **One flagship systems paper** = 2.1 + 2.2 + 2.4 ("verified,
   metadata-private sync and key rotation for zero-knowledge vaults"),
   with 2.3 as a subsection. This is publishable; the pieces reinforce
   each other and component evidence exists, but the IPC provenance boundary remains unproved.
2. **Measure first.** No venue will accept any of this without numbers:
   ORAM overhead vs. vault size (the trivial/Path crossover), rekey cost,
   unlock latency, sync payload inflation vs. a plaintext-manifest
   baseline. `security/exploits/` + the e2e suite give the harness a
   head start.
3. **Separately**, an SoK of browser-extension ↔ companion-app channels
   (2.3) is cheap to write and useful to the community.
4. **Do not** pitch the hybrid PQC choices as a contribution — present them
   as correct application of standards and cite PQXDH/PQ3.

## 4. Gaps to close before submitting

- Related-work pass against the oblivious-storage and password-manager
  literature (Stefanov et al., ObliviStore, Recurphire; "The Emperor's New
  Password Manager" 2022 SoK; PQXDH/PQ3 specs) to confirm no one has done
  verified dual-mode ORAM or seed-rotation-in-ORAM before.
- The ORAM stash claim is now explicitly **regression-backed**, not a
  small-stash theorem or quantified overflow probability. See the revised
  M24 claim boundary for its fixed-universe argument and malformed-path limit.
- Formal models cover enrollment/recovery/rekey/web-session/ORAM; the
  native-messaging gate (2.3) now has a separate local-adversary model
  (M27), pending solver validation; it exposes a basename-spoofing limit.
- Side-channel claims in SPEC §9 ("out of scope") will be probed by
  reviewers — timing of IPC approvals and ORAM path sizes deserve at least
  a measurement.

## 5. Next-step assurance artifacts

- [Measurement harness and run matrix](../security/measurements/README.md):
  production ORAM/rekey CPU samples plus paired external-operation runner.
  Installed competitor, cross-platform unlock, IPC approval and wire timing
  measurements remain pending; proxies are not product benchmarks.
- [Stash claim boundary](../security/formal/oram-stash-bounds-statistical-results.md):
  regression evidence only, no small-stash tail guarantee or universal proof.
- [Local IPC model](../security/formal/local-ipc-gate-assurance.md): explicit
  attacker capabilities and implementation mapping, separate from M6.
