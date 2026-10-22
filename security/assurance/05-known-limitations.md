# 5. Known limitations

This document lists what is **not** established. We would rather over-list
here than have a researcher find an unstated gap. IDs are stable so you can
cite them.

## Unproved properties

| ID | Property | Status |
|---|---|---|
| **U-1** | **End-to-end secrecy of the RMS and vault plaintext against a malicious server** (CONF-1, CONF-2) | No theory models the whole system with the server as attacker. Secrecy is argued from the architecture. Individual theories either model the server as an honest enforcer (M11–M21, M26) or make capsule contents opaque by assumption (M19b, M21) |
| **U-2** | **Device authentication** (`/auth/challenge`, `/auth/verify`, PASETO issuance and validation, JTI revocation, device-revocation cascade) | Not modelled symbolically and not hax-verified. Covered by unit, integration, and exploit tests |
| **U-3** | **Computational security of every construction**: the hybrid KEM combiner, the hybrid signature AND-composition, AEAD AAD encodings, BLAKE3 context separation, the Shamir share-tag MAC, link-key and passphrase mixing, the possession-proof keyed hash | Symbolic models treat all of these as perfect. No CryptoVerif or EasyCrypt proof exists. See [Q-1](06-engaging-researchers.md#priority-questions) |
| **U-4** | **Enrollment secrecy and MITM resistance** (fingerprint comparison, KEM capsule to the joining device) | M13 is ordering-only by its own header. The human fingerprint comparison is modelled only for IPC pairing (M6) |
| **U-5** | **Recovery with a network adversary** | M14 is ordering-only. M15 and M18 add adversarial cloud storage and contact responses, but WebAuthn is an idealised honest rule |
| **U-6** | **Long-term key compromise and post-compromise security** | Not modelled except `Corrupt_Client` in M8/M10. No theory covers "RMS leaked, then rotation" as an attacker game. COMP-2 rests on stranding lemmas (M11c, M26) |
| **U-7** | **Sync rollback with advancing clocks** | M23 models only the bootstrap clock. Monotonic advancement from admitted revisions is future work (stated in the model) |
| **U-8** | **Mobile sync admission** | Android and iOS do not call `vela-sync-policy`. Their rules are hand-written in Kotlin and Swift, so INT-1 and INT-9 are **[REF]** for desktop only |
| **U-9** | **The 25-domain-per-unlock cap, audit entries, and toasts** (CONF-7) | Quantitative. Tamarin cannot count, so these are argued and tested, not proved |
| **U-10** | **ORAM beyond the abstract transcript** | M22 covers one tree, two rounds, and read/write-agnostic accesses. Stash overflow, timing, and the `/vault/events` side channel are outside it. Stash bounds are statistical (M24). Leaf uniformity is assumed |
| **U-11** | **Composition** | M26 is an abstract re-statement of three subsystems around one epoch token, bounded by fuel. It is not a composition of the actual M18, M19, and M20 theories. There is no general composition theorem |
| **U-12** | **One-off share links, audit log, breach monitoring, importers, autofill, passkey provider integration** | Tests and audit only |
| **U-14** | **Sender authenticity of shared items** | `seal_share` is anonymous public-key encryption with no sender signature, and recipient share keys are public. No claim of sender authenticity against a malicious server or another user is made or proved. INT-2 only stops replay of *older* capsules. Open question [Q-2](06-engaging-researchers.md#priority-questions) |
| **U-13** | **Availability and liveness** | Only `exists-trace` reachability witnesses. No progress guarantees under an adversarial scheduler or a malicious server |

## Trusted components

| ID | Component | What we assume |
|---|---|---|
| **T-1** | Cryptographic primitives and crates: `ml-kem`, `fips204`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `blake3`, `hkdf`, `argon2`, `pasetors`, `webauthn-rs` | Correct and secure as specified. None of these is formally verified in the versions used. Formally verified alternatives exist (for example `libcrux` ML-KEM) but are not used |
| **T-2** | **Server state enforcement** | Lifecycle properties (single grant, epoch guards, revocation) hold only if the server runs the shipped code. A malicious server can break authorization and availability properties by design. The goal is that it still cannot break confidentiality (U-1) |
| **T-3** | Storage atomicity: Turso/SQLite transactions and sled atomic operations | Linear facts in the models assume these really are atomic. Race tests give evidence, not proof |
| **T-4** | Hardware keystores and OS user-presence APIs (TPM, Secure Enclave, StrongBox, Windows Hello, LocalAuthentication) | Keys do not leave, and presence checks are real (see audit D-3 and D-5, where both assumptions were initially false) |
| **T-5** | OS process isolation and kernel peer credentials for IPC | `ipc_peer`/`ipc_gate` answers are truthful. Same-UID code other than a browser-spawned host cannot impersonate one |
| **T-6** | Client RNG (`OsRng`, `getrandom`) | Fresh values are uniform. M22 and every `Fr(…)` depend on this |
| **T-7** | TLS 1.3 and Web PKI | Needed for availability and metadata protection. Confidentiality claims are designed not to depend on it |
| **T-8** | Cloud providers (iCloud, Google Drive) | Durable (M16, M17). Not trusted for secrecy |
| **T-9** | Verification toolchain: Tamarin, Maude, ProVerif, hax, F\*, Z3, and hax's `core_models` | Sound. hax is research-grade. 15 `assume val` `PartialEq` instances are axioms ([§3.2](03-implementation-correspondence.md#trusted-in-the-f-layer)) |
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
| **O-6** | Implementation bugs outside the policy crates: parsing, serialization, FFI memory safety (see C-4), UI confusion, autofill origin mapping (see A-2) | Fuzzing exists for some parsers (`.github/workflows/fuzz.yml`). No proofs |
| **O-7** | Compromise of a browser that has been granted a web session | Bounded by AUTH-6 and COMP-6, but chunk keys already copied stay valid until rotation (audit D-2 residual) |
| **O-8** | Quantum adversaries against the classical half alone, or classical attacks against the lattice half alone | Hybrid design intent (COMP-5). No proof |
| **O-9** | The WASM fallback with a PIN when no desktop app is present | Explicitly weaker (SPEC §7.4) |

## Gaps in the assurance itself

These are problems with the evidence, not with the protocol. We are fixing
them. Each is an easy place for a reviewer to find an over-claim.

| ID | Gap | Impact | Planned fix |
|---|---|---|---|
| **G-1** | **hax/F\* is not run in CI.** `vela-rekey-policy` does not commit its extraction. The other six crates commit `.fst` files that CI never regenerates or checks | **[REF]** results can silently go stale when a policy crate changes | Add a CI job that installs the pinned hax, F\*, and Z3 toolchain and runs every `verify-fstar.sh` |
| **G-2** | **M1–M10 credential-release theories (88 lemmas) are not run in CI** | CONF-6, CONF-7, CONF-8, AUTH-9, and COMP-7 are **[SYM-local]** | Add a runner gated on 83 verified plus the 5 named falsifications (the logic already exists in `run-all.sh`) |
| **G-3** | **Toolchain drift.** CI uses Maude 3.2 ("unsupported" according to Tamarin) while the docs cite 3.5.1. ProVerif, Rust stable, semgrep, cargo-audit, and cargo-deny are unpinned | Results can change without a code change | Pin versions explicitly and print every version in CI |
| **G-4** | **Documentation drift.** `security/formal/README.md` per-model counts predate later lemmas (M13 16 vs 15, M19b 6 vs 5, M21 3 vs 2, M23 11 vs 8, M26 4 + 6). `vela-crypto/SECURITY.md` lists `ml-kem 0.3.0` but the lockfile has 0.3.2. SPEC §3 cites "GL20 (Gong et al., 2020)" for the KEM combiner, and we have not been able to match that citation to a paper | Reviewers may distrust correct results, or trust an unsupported citation | Counts corrected in this change. The citation will be replaced or removed |
| **G-5** | **Model ↔ policy correspondence is manual** | A policy can diverge from its model's guard without any tool noticing | Write a per-rule correspondence table for each crate. Consider generating guards from one source |
| **G-6** | **No independent review.** `SECURITY_AUDIT.md` and `SECURITY_REDTEAM.md` were done by the project on its own code. iOS was outside the audit scope. No third party has reviewed the models or proofs | Self-assessment bias | This package and [§6](06-engaging-researchers.md) |
| **G-7** | **Private vulnerability reporting is disabled on GitHub,** yet it is the only channel listed in `SECURITY.md` and `security.txt`. There is no email address or PGP key | Researchers cannot report privately | Enable it before any outreach ([§6](06-engaging-researchers.md#before-outreach-checklist)) |

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
