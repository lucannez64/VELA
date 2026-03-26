# Peer Review: VELA Protocol Specification v2.0

**Artifact:** VELA Protocol Specification v2.0 (Passwordless & Zero-Knowledge)  
**Version:** 2.0 — Draft  
**Date:** 2026-03-23  
**Review date:** 2026-03-26  
**Reviewer role:** Adversarial peer review  
**Research basis:** E:/Projects/VELA/outputs/vela-protocol-research.md

---

## Summary

VELA v2.0 proposes an ambitious passwordless vault architecture combining hardware-bound keys, lattice-based ZKP authentication (Cyclo), hybrid post-quantum key encapsulation (ML-KEM+X25519), and metadata-hiding storage (Path ORAM). The overall design philosophy is sound and the threat model is thoughtfully constructed. However, this draft has **fatal gaps in critical-path specifications** — particularly the device enrollment identity key, conflict resolution garbage collection, and the unimplemented (and acknowledged) Zig timing-safety audit — that make production deployment premature. The protocol is best classified as **Major Revision** required before it can be considered for real-world deployment.

---

## Detailed Review

### 1. Novelty & Design Philosophy

**Verdict:** ✅ Sound with minor concerns

The ambition of abandoning the master-password paradigm in favor of hardware-bound, ZKP-authenticated, metadata-hiding vault is well-justified. The combination of Cyclo + hybrid KEM + Path ORAM is novel in its specific composition. The design philosophy correctly identifies the core problem with password managers (server-side leakage of metadata and auth material) and proposes a coherent set of countermeasures.

**Inline annotations:**
- §1: "hybrid post-quantum secure vault" — The hybrid (ML-KEM + X25519) construction is intuitive but no formal security reduction is cited. This is a gap for a production security proof.
- §1: "Cyclo ZKPs, proving ownership of a valid device capability without exposing any key material" — Correct characterization of what Cyclo provides in this context.

---

### 2. Cryptographic Primitives

#### Cyclo ZKP (§3, §6)
**Verdict:** ⚠️ Needs clarification — Major

- **Strengths:** Cyclo is a real, peer-reviewed scheme (Eurocrypt 2026) with ~30KB proof sizes. The lattice hardness assumptions (MSIS/MLWE) are standard.
- **Issue 1 (Major):** The SPEC's Cyclo authentication statement — "I know sk such that pk = PublicKey(sk) and BLAKE3(sk ‖ challenge) equals a committed value" — is a specific *application* of Cyclo. The paper describes the general folding framework; whether this exact statement is efficiently supported requires inspection of the concrete protocol instantiation, not just the paper abstract.
- **Issue 2 (Critical — acknowledged):** "Side-channel attacks against the Cyclo Zig implementation (to be addressed by a dedicated timing-safety audit before v2.0 production release)" is listed in §9 as out of scope. **This is a critical gap.** A timing attack on the Zig Cyclo prover could leak the device private key, which is the entire auth foundation. The spec explicitly defers this to a future audit, which means the ZKP layer cannot be trusted for production until that audit passes.
- **Revision required:** Either (a) cite a specific timing-safe implementation of Cyclo, or (b) provide a concrete plan and timeline for the timing-safety audit with explicit acceptance criteria.

#### ML-KEM-1024 + X25519 Hybrid KEM (§3)
**Verdict:** ⚠️ Needs clarification — Minor

- **Strengths:** ML-KEM-1024 is NIST-standardized (FIPS 203). The combination via HKDF-SHA256 is reasonable.
- **Issue:** The SPEC claims the hybrid "guards against both quantum threats and undiscovered flaws in new lattice math." While intuitive, there is no cited formal security reduction for this specific hybrid composition. The interaction between ML-KEM and X25519 security proofs (which are from different hardness domains) should be formally analyzed.
- **Revision required:** Add citation to a formal analysis of the hybrid KEM composition, or reframe the claim as "defense-in-depth" rather than a proven security reduction.

#### BLAKE3 KDF (§3, §4.4)
**Verdict:** ✅ Sound — Minor

- BLAKE3's `derive_key` mode is a legitimate MAC-style KDF with domain separation. Appropriate for deriving chunk keys and audit log keys.
- **Minor:** The context strings (e.g., `"vela audit log v1"`) are informal. A formal domain separation scheme should be added as an appendix.

#### Shamir SSS (§3, §4.3)
**Verdict:** ⚠️ Needs clarification — Minor

- SSS over GF(2^8) is correctly described.
- **Minor:** The social recovery share (trusted contact) is a social engineering vector. The spec should explicitly warn that Share 3 recipients should be trusted not to coerce or be coerced.

---

### 3. Identity & Device Management

#### Root Master Seed (§4.1)
**Verdict:** ✅ Sound

- 32-byte RMS generated on-device, stored in hardware enclave, used to derive all other keys via BLAKE3 KDF. Correct design.
- The spec correctly states the RMS never leaves the device in plaintext.

#### Device Enrollment (§4.2)
**Verdict:** 🔴 Problematic — Major

**Critical gap:** Step 4 states Device A "signs Device B's public key with its own enrolled identity key." **The identity key type is never defined.** The spec establishes Cyclo ZKP as the auth mechanism but does not specify:
- What signing algorithm the identity key uses (ECDSA? Ed25519? X25519?)
- How the identity key is protected (hardware enclave? derived from RMS?)
- How the identity key is enrolled on the first device (before any prior device exists)

This is a critical gap because the enrollment protocol's security relies on this signing operation, but the key material is unspecified.

**Revision required:** Define the identity key type, generation, and enclave protection. For the first device enrollment (where no prior device exists), specify the bootstrap path.

#### Recovery (§4.3)
**Verdict:** ⚠️ Needs clarification — Minor to Major

- 2-of-3 SSS recovery is coherent.
- **Issue:** Share 2 (stored on VELA server) is encrypted under a key derived from a user-owned FIDO2 credential. The spec says "the VELA server never sees this key." This trust assumption needs more rigor: Does the FIDO2 credential generate a key that is sent to the server? If so, the server stores encrypted Share 2 — but what prevents the server from being a man-in-the-middle during FIDO2 auth? The flow implies the FIDO2 credential is used to decrypt Share 2 *client-side* after downloading it, but this needs explicit description.
- **Minor:** What happens if the user's FIDO2 credential is also lost? The trusted contact share alone cannot recover (2-of-3 required). Add a note.

---

### 4. Vault Architecture & Sync

#### Chunked Blob + Path ORAM (§5.2)
**Verdict:** ✅ Sound with minor issues

- Path ORAM is the correct theoretical primitive. Client-managed position map is correct.
- **Issue 1 (Minor):** "Trivial ORAM for ≤4 active chunks" — This is non-standard terminology and the threshold appears arbitrary. Justify the 4-chunk threshold or remove this optimization from the spec at this stage.
- **Issue 2 (Minor):** The 1MB chunk size is mentioned but not justified. Larger chunks reduce metadata leakage but increase sync overhead. Provide rationale.

#### Conflict Resolution (§5.3)
**Verdict:** ⚠️ Problematic — Major

- Lamport clock + version-based three-case resolution is a valid approach.
- **Critical gap:** The spec says "Items modified on both sides are kept as duplicate conflict copies, surfaced to the user with timestamps for manual resolution." **There is no garbage collection mechanism described.** In a multi-device, frequent-sync scenario, conflict copies will accumulate indefinitely, inflating vault size and degrading performance.
- **Revision required:** Add a conflict copy garbage collection strategy (e.g., TTL-based, user-triggered, or automatic merging after N days).

---

### 5. Zero-Knowledge Authentication Protocol (§6)

**Verdict:** ✅ Sound in concept, ⚠️ Implementation gaps

- Challenge → Cyclo proof → PASETO token is a coherent auth flow.
- PASETO v4 is a reasonable choice over JWT (noalg confusion attacks eliminated).
- Token lifecycle (15-min sliding, 8-hr hard cap, JTI revocation) is well-specified.
- **Minor:** Rate limiting table (§6) and the auth/challenge endpoints are consistent.

**Missing from the spec:**
- How does the client prove possession of the RMS to generate a Cyclo proof? The Cyclo proof proves knowledge of the device private key, but what binds the device private key to the RMS? This binding is implicit (device private key derived from RMS) but should be made explicit.
- How is the Cyclo witness generated? The prover needs the RMS to compute the witness. Is the RMS loaded into the Zig prover? This is relevant to the timing-safety concern.

---

### 6. Client-Specific Implementations (§7)

**Verdict:** ⚠️ Informational

- The three-tier architecture (Mobile/SecureEnclave, Desktop/TPM, Web Extension/fallback) is well-structured.
- **Web Extension fallback** is correctly identified as a security downgrade and the persistent warning is good practice.
- **Issue:** The WASM fallback uses "a user PIN" to protect the RMS in IndexedDB. What is the PIN security level? Is it used to derive a key via PBKDF2/Argon2? If yes, what parameters? If no, the PIN provides minimal protection. This needs specification.

---

### 7. Security & Threat Model (§9)

**Verdict:** ✅ Generally sound, with gaps

**Correctly identified strengths:**
- Server as honest-but-curious adversary — correct characterization
- Hardware enclave trust boundary — correct
- Cloud provider as 1-of-3 Shamir share holder — correct
- Browser as untrusted — correct

**Correctly out of scope:**
- Client-side malware — acceptable assumption (requires TEE)
- DoS — acceptable to defer
- Zig implementation timing attacks — correctly deferred to future audit

**Missing threats that should be noted as out of scope or addressed:**
- **Ruthless coercion:** An attacker who coerces the user to reveal a Shamir share (Share 3 via trusted contact, or Share 1 via cloud credentials). This is a real-world threat for a password manager. Add a note.
- **Screen/memory scraping:** Hardware keylogger, cold boot attack. Out of scope is acceptable but should be stated.
- **Server-side timing attacks on ZKP verification:** The server's Cyclo verifier could potentially leak information via verification timing. This should be noted.

---

## Fatal Issues

The following issues are **blocking** for production deployment:

1. **[CRITICAL] Unspecified identity key in device enrollment (§4.2, Step 4):** The signing key used by Device A to sign Device B's public key is never defined. Without this, the enrollment protocol cannot be implemented or audited.

2. **[CRITICAL] Open Zig timing-safety issue (§9):** The Cyclo prover implementation is acknowledged to not have been audited for timing attacks. Since the device private key is the auth foundation, a timing attack on the prover could be catastrophic. This must be resolved before production.

3. **[MAJOR] Unbounded conflict copy growth (§5.3):** No garbage collection for conflict copies. A vault with frequent multi-device edits will accumulate unbounded duplicate items.

4. **[MAJOR] Missing RMS-to-device-private-key binding (§6):** The spec does not explain how the Cyclo proof (which proves possession of the device private key) is connected to the RMS (the root vault encryption key). A full auth path description is missing.

---

## Revision Plan

### P0 (Must fix before any implementation)
1. Define the identity key type, generation, and enclave storage in §4.2.
2. Specify the first-device bootstrap path for initial enrollment.
3. Add conflict copy garbage collection to §5.3.
4. Document the RMS → device private key derivation path and its relationship to the Cyclo proof.

### P1 (Must fix before production)
5. Complete Zig Cyclo timing-safety audit and publish results.
6. Add FIDO2 recovery flow specification (client-side decryption of Share 2).
7. Specify WASM fallback PIN derivation parameters (PBKDF2/Argon2 with concrete cost parameters).
8. Add formal security reduction citation for hybrid ML-KEM + X25519 KEM.

### P2 (Should fix for completeness)
9. Justify "trivial ORAM" threshold or remove from spec.
10. Add explicit note on coercion threat model.
11. Specify ORAM chunk size rationale.
12. Define all BLAKE3 context strings in a formal domain separation table.

---

## Final Verdict

**Classification: Major Revision**

VELA v2.0 is a well-motivated, theoretically sound protocol draft from a cryptographic design perspective. The threat model is mature, the primitive selection is appropriate, and the overall architecture is coherent. However, it has significant gaps in critical-path specifications (identity key, conflict resolution, auth path binding) and an acknowledged unimplemented security audit (Zig timing safety) that make it premature for production deployment or external audit.

This reviewer's recommendation: **Return to authors for Major Revision** focusing on P0 items before any further review or implementation engagement.

---

## Sources

- Cyclo (Garreta et al., 2026): https://eprint.iacr.org/2026/359
- NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST FIPS 203 (ML-KEM): https://doi.org/10.6028/NIST.FIPS.203
- Path ORAM (Stefanov et al., 2013): https://人民警察.com/path-oram (theoretical foundation, cited in SPEC)
- BLAKE3: https://github.com/BLAKE3-team/BLAKE3
- PASETO: https://paseto.io/
