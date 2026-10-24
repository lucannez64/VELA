# 5. Known limitations

This document lists what is **not** established. We would rather over-list
here than have a researcher find an unstated gap. IDs are stable so you can
cite them.

## Unproved properties

| ID | Property | Status |
|---|---|---|
| **U-1** | **End-to-end secrecy of the RMS and vault plaintext against a malicious server** (CONF-1, CONF-2) | No theory models the whole system with the server as attacker. Secrecy is argued from the architecture. Individual theories either model the server as an honest enforcer (M11–M21, M26) or make capsule contents opaque by assumption (M19b, M21) |
| **U-2** | **Device authentication beyond the challenge proof** | M27 locally proves signature provenance, challenge single use and registered-user binding. PASETO parsing, TTL, JTI revocation, device-revocation cascade and concurrent issuance remain unproved. An in-flight request can pass lookup before revocation and mint later. |
| **U-3** | **Computational security of the complete constructions**, including AEAD AAD encodings, BLAKE3 contexts, Shamir share tags, link-key/passphrase mixing and possession proofs | Scoped exceptions: CryptoVerif models cover the v2 KEM combiner, modular KEM-DEM, AND signatures, v2 RMS possession proofs and authenticated Shamir reconstruction under the [listed assumptions](../formal/cryptoverif/README.md), including ideal KDF/tag abstractions. Concrete hash/context/encoding correspondence, other constructions and full composition remain unproved. See [Q-1](06-engaging-researchers.md#priority-questions) |
| **U-4** | **Enrollment beyond both-key fingerprint binding** | M13b locally proves secrecy against key substitution under an ideal authentic human comparison. It does not prove primary-to-joiner authentication, correct adoption, human behavior, finite fingerprint collision resistance, or full composition with M13. |
| **U-5** | **Recovery with a network adversary** | M14 is ordering-only. M15 and M18 add adversarial cloud storage and contact responses, but WebAuthn is an idealised honest rule |
| **U-6** | **Long-term key compromise and post-compromise security** | M8/M10 model local client-key corruption; new M19c/M27 model device-key reveals and M19c models recipient decryption-key reveal. RMS compromise followed by rotation and cross-protocol compromise composition remain unproved. |
| **U-7** | **Sync rollback with advancing clocks** | M23 models only the bootstrap clock. Monotonic advancement from admitted revisions is future work (stated in the model) |
| **U-8** | **Mobile sync admission** | Android and iOS downloads now call admitted Rust bridge paths using the shared chunk policy and integer epoch kernel. These pure kernels are checked; Kotlin/Swift/JNI/C/JSON wiring, authenticated-open composition, baseline storage and complete native traces remain unproved. The runtime fixes have JVM/bridge tests and hosted build validation, not native-client refinement |
| **U-9** | **The 25-domain-per-unlock cap, audit entries, and toasts** (CONF-7) | Quantitative. Tamarin cannot count, so these are argued and tested, not proved |
| **U-10** | **ORAM beyond the abstract transcript** | M22 covers one tree, two rounds, and read/write-agnostic accesses. Stash overflow, timing, and the `/vault/events` side channel are outside it. Stash bounds are statistical (M24). Leaf uniformity is assumed |
| **U-11** | **Composition** | M26 is an abstract re-statement of three subsystems around one epoch token, bounded by fuel. It is not a composition of the actual M18, M19, and M20 theories. There is no general composition theorem |
| **U-12** | **One-off share links, audit log, breach monitoring, importers, autofill, passkey provider integration** | Tests and audit only |
| **U-14** | **First-contact sender authenticity and persistent share state** | Signed v2 envelopes and M19c establish provenance relative to an honest pinned key, with key-reveal exceptions. A malicious server can supply its own key at first contact (TOFU); account-to-key authenticity needs independent confirmation. Recipient key-directory substitution, crash/concurrent pin persistence and mobile native glue remain unproved. Legacy unsigned item capsules are rejected. |
| **U-15** | **Mixed-version deployment and migration** | Current signed item envelopes and KEM blobs use explicit v2 formats. Old unsigned item capsules are rejected; no seamless migration or mixed-client interoperability theorem is provided. Legacy trusted-contact handling is a separate scoped path in `recovery.rs`. |
| **U-16** | **Challenge purpose binding** | `/auth/challenge` nonces share one store namespace and are not tagged with a purpose: `/auth/verify`, `/device/enroll` and `/web-session/:id/token` each accept any live nonce. Each nonce is single-use across all three (bounded model + 16-way race test, [evidence](proof-logs/current/challenge-single-use/README.md)), and each endpoint also checks its own proof (enrollment adds a device-key signature over the new keys; web tokens use the session key), so no escalation was found. `/device/enroll` reuses the login message format for its first signature; separation therefore rests on the second signature and on single use, not on domain tags. |
| **U-17** | **Non-transactional account deletion** | `DELETE /account` runs separate SQL statements. A crash or database error midway can leave a partly deleted account. The bounded test checks the complete-success path only; backups, replicas and in-flight requests are not covered. |
| **U-18** | **Closed: revocation cascades to approved web sessions** | Revoking a device now revokes the web sessions it approved, and a grant requires the approving device to be unrevoked, so a stolen device's browser session ends with the device (regression test `revoking_a_device_revokes_the_web_sessions_it_approved`). Still open: revoking the account's last device is allowed, and the cascade is tested, not proved. |
| **U-13** | **Availability and liveness** | Only `exists-trace` reachability witnesses. No progress guarantees under an adversarial scheduler or a malicious server |

The [formalization obligation ledger](08-formalization-status.md) records the
remaining work across all six requested areas. New sharing contracts and M28
reduce selected gaps; the computational model proofs above do not establish a
full-system theorem.

The M28 all-pairs pin/generation results are checked for rules instrumented
with linear `Chain` ghost state. F★ now checks lifting/projection between two
typed single-slot encodings and now directly proves their all-pairs goals,
with a checked concrete order/two-commit witness. Their [source bridge](../formal/share-journal-correspondence.md#ghost-state-correspondence-manual-source-bridge)
to actual Tamarin traces remains a manual argument with two unproved embedding
obligations; the direct encoded safety proofs do not discharge those source
obligations or instantiate the full Tamarin term algebra.
Neither source equivalence nor Rust/filesystem refinement is machine-checked.

## Trusted components

| ID | Component | What we assume |
|---|---|---|
| **T-1** | Cryptographic primitives and crates: `ml-kem`, `fips204`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `blake3`, `hkdf`, `argon2`, `pasetors`, `webauthn-rs` | Correct and secure as specified. This package supplies no machine-checked implementation proof for these pinned dependencies; upstream assurance has not been established by this review |
| **T-2** | **Server state enforcement** | Lifecycle properties (single grant, epoch guards, revocation) hold only if the server runs the shipped code. A malicious server can break authorization and availability properties by design. The goal is that it still cannot break confidentiality (U-1) |
| **T-3** | Storage atomicity: Turso/SQLite transactions and sled atomic operations | Linear facts in the models assume these really are atomic. Race tests give evidence, not proof |
| **T-4** | Hardware keystores and OS user-presence APIs (TPM, Secure Enclave, StrongBox, Windows Hello, LocalAuthentication) | Keys do not leave, and presence checks are real (see audit D-3 and D-5, where both assumptions were initially false) |
| **T-5** | OS process isolation and kernel peer credentials for IPC | `ipc_peer`/`ipc_gate` answers are truthful. Same-UID code other than a browser-spawned host cannot impersonate one |
| **T-6** | Client RNG (`OsRng`, `getrandom`) | Fresh values are uniform. M22 and every `Fr(…)` depend on this |
| **T-7** | TLS 1.3 and Web PKI | Needed for availability and metadata protection. Confidentiality claims are designed not to depend on it |
| **T-8** | Cloud providers (iCloud, Google Drive) | Durable (M16, M17). Not trusted for secrecy |
| **T-9** | Verification toolchain: Tamarin, Maude, ProVerif, CryptoVerif/default.ocvl, hax, F\*, Z3, and hax's `core_models` | Sound. hax is research-grade. The prior 18 local PartialEq assumptions are removed; imported models and the defined String/Vec models remain trusted ([§3.2](03-implementation-correspondence.md#trusted-in-the-f-layer)) |
| **T-10** | Specification predicates in the policy crates | They express the intended property. F\* proves code = spec, not spec = intent |
| **T-11** | Build and distribution pipeline: GitHub Actions, release signing, app stores, extension stores | Out of the assurance scope. No reproducible-build attestation |

## Attacks outside the models

| ID | Attack class | Notes |
|---|---|---|
| **O-1** | Malware, keyloggers, memory scraping, or debuggers on an unlocked client | SPEC §9 non-goal. The audit D-4 residual (same-UID theft of named domains during an unlock) is accepted and bounded |
| **O-2** | Side channels: timing, cache, power, EM on client crypto; the server observing timing and volume | Non-goal. No timing audit yet. The `ml-dsa` crate was avoided because of RUSTSEC-2025-0144 |
| **O-3** | Coercion; social engineering of the trusted contact or of a fingerprint comparison | Non-goal |
| **O-4** | A malicious server denying service, dropping writes, or forking views between devices | Rollback is partly covered (INT-1). Fork consistency across devices is **not** claimed |
| **O-5** | Supply-chain compromise of dependencies, toolchains, or vendored `gpui-ce` | `cargo audit` and `cargo deny` only |
| **O-6** | Implementation bugs outside the policy crates: parsing, serialization, FFI memory safety (see C-4), UI confusion, autofill origin mapping (see A-2) | The share byte-frame parser has scoped refinement evidence; other parsing, serialization, UI and FFI paths remain unproved. Fuzzing exists for some parsers (`.github/workflows/fuzz.yml`) |
| **O-7** | Compromise of a browser that has been granted a web session | Bounded by AUTH-6 and COMP-6, but chunk keys already copied stay valid until rotation (audit D-2 residual) |
| **O-8** | Quantum-adversary and quantum-random-oracle composition | The computational games model ordinary oracle queries and the stated leaked-key cases. No QROM or complete quantum-adversary theorem for the concrete hybrid is supplied (COMP-5) |
| **O-9** | The WASM fallback with a PIN when no desktop app is present | Explicitly weaker (SPEC §7.4) |

## Gaps in the assurance itself

These are problems with the evidence, not with the protocol. We are fixing
them. Each is an easy place for a reviewer to find an over-claim.

| ID | Gap | Impact | Planned fix |
|---|---|---|---|
| **G-1** | **Hosted baseline passed on fdee2bc:** 249 Rust postconditions /256 selections, twenty chunk lemmas, six epoch lemmas and encoded journal proofs; all fifteen PR checks passed | Conditional policy proofs and green CI do not establish whole-handler/client correctness; later lifecycle changes need their own evidence | Exact metadata, uploaded proof logs and scope: [hosted-fdee2bc](proof-logs/current/hosted-fdee2bc/README.md); older snapshots keep their original provenance |
| **G-2** | **Closed: credential-release theories run in CI** | CONF-6/7/8, AUTH-9 and COMP-7 are now CI-witnessed | `run-all.sh` passed in the [368bcc0 hosted workflow](proof-logs/current/hosted-368bcc0/README.md): 83 verified plus exactly the five named intended falsifications |
| **G-3** | **Partly pinned environment** | Historical CI used unsupported Maude 3.2 and unpinned ProVerif | Current proof gates pin Tamarin 1.12.0, Maude 3.5.1, ProVerif 2.05 and Rust 1.99.1; hax/F*/Z3 versions are pinned. OS packages, action tags, transitive opam resolution and static scanners remain non-hermetic |
| **G-4** | **Historical documentation drift** | The original package predated the new protocols | This update removes the unsupported GL20 citation and the claimed reduction, records current counts and preserves old CI results as historical evidence |
| **G-5** | **Model ↔ policy correspondence remains manual** | Matching hashes do not establish semantic equivalence | A per-rule table and source/model drift gate now cover the new enrollment/share/login boundaries; other families and mobile call sites remain manual |
| **G-6** | **No independent review.** `SECURITY_AUDIT.md` and `SECURITY_REDTEAM.md` were done by the project on its own code. iOS was outside the audit scope. No third party has reviewed the models or proofs | Self-assessment bias | This package and [§6](06-engaging-researchers.md) |
| **G-7** | **Private reporting enabled as checked 2026-10-23** | GitHub is the only published private contact; no independent email/PGP fallback is supplied | GitHub API returned `enabled: true`; maintainers should provide a fallback address they control |

## Remediated implementation findings

The [boundary review](07-boundary-review.md) reproduced three sharing
caller/storage failures at the baseline. The desktop now rejects repeated
acceptance, serializes store changes with generation checks, and journals pins
with pending content before vault writes. Regression tests cover the fixes;
filesystem correctness and concurrent independent processes are not proved.
These implementation tests do not turn the pure-policy proofs into an
end-to-end sharing theorem.

## Accepted residual risks (from the audits)

- **D-2:** chunk keys granted to an RW web session stay valid until the next
  rotation.
- **D-4:** same-UID code during an unlock can obtain credentials for domains
  it names. This is bounded by the 25-domain cap, an audit entry, and a toast.
- **C-1/P-1:** key material briefly exists as a string during enrollment-code
  import (superseded by enrollment v3, which uses device-generated keys).
- **RT lower-severity items:** device-ID existence oracle via distinct 401
  messages, web-session metadata in `/devices`, `MAX_ACCOUNTS` and quota
  TOCTOU, and unvalidated `TRUSTED_PROXY_CIDRS` breadth (SECURITY_REDTEAM.md
  summary). Check the current code for their status before you report them
  again.
