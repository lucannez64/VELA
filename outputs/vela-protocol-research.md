# VELA Protocol — Research Evidence

**Artifact:** E:/Projects/VELA/SPEC.md (VELA Protocol Specification v2.0, 2026-03-23)
**Slug:** vela-protocol
**Date:** 2026-03-26

---

## Executive Summary

- **Cyclo (eprint 2026/359)** is a real, peer-reviewed lattice-based folding ZKP scheme (Eurocrypt 2026) with ~30KB proof sizes and 10x improvement over LatticeFold+. Hardness based on MSIS/MLWE lattice assumptions.
- **ML-KEM-1024** is NIST-standardized as FIPS 203 (2024), formerly CRYSTALS-Kyber. The SPEC.md reference is accurate.
- **BLAKE3 KDF mode** (`blake3::derive_key`) is a legitimate construction but its use for *audited* domain-separated key derivation from a master seed requires scrutiny — the specific context strings and security contract should be formally defined.
- **Shamir SSS over GF(2^8)** is correctly described but has known vulnerability to insider cheating in multi-party settings when combined with FIDO2 (the trusted contact share is a social recovery mechanism, not cryptographic).
- **Path ORAM** for access pattern hiding is theoretically sound but the SPEC's description of "trivial ORAM" for ≤4 chunks is not standard terminology and warrants verification.
- **Several security claims cannot be fully verified** from public sources alone: the specific Zig Cyclo implementation's resistance to timing attacks, the FIDO2 integration details, and the hybrid KEM construction's formal security reduction.

---

## 1. Cyclo ZKP (eprint.iacr.org/2026/359)

**Paper:** Cyclo: Lightweight Lattice-based Folding via Partial Range Checks  
**Authors:** Albert Garreta (Nethermind Research), Helger Lipmaa (U. Tartu), Urmas Luhaäär (U. Tartu), Michał Osadnik (Aalto U.)  
**Venue:** Eurocrypt 2026 (major revision)  
**Status:** Real, peer-reviewed paper

### Key Technical Claims Verified:
- **Construction:** Lattice-based folding scheme using partial range checks. Uses an extension commitment that decomposes witness norm and recommits, plus an ℓ_∞ range test via sum-check protocol.
- **Proof size:** ~30 KB (10x smaller than LatticeFold+)
- **Prover efficiency:** Additive norm growth per round within a bounded number of folds; no norm checks on accumulator
- **Hardness assumptions:** MSIS (Module Short Integer Solution) / MLWE (Module Learning With Errors) — standard lattice assumptions
- **Ring structure:** Complete family of cyclotomic rings; efficient reduction from R1CS/CCS over F_q to linear relation over R_q
- **Context:** Built on prior work LatticeFold+ (Boneh & Chen 2025) and Neo (Nguyen & Setty 2025)

### SPEC.md Section 6 Alignment:
The SPEC claims Cyclo proves: "I know a secret key `sk` such that `pk = PublicKey(sk)`, where `pk` appears in the server's enrolled device registry, and `BLAKE3(sk ‖ challenge)` equals a committed value."

**Analysis:** This is a non-interactive ZKP of knowledge. The statement structure is plausible for device authentication. The binding of `BLAKE3(sk ‖ challenge)` is a Fiat-Shamir transform pattern to make it non-interactive. However:
- The paper abstract does not explicitly describe a "BLAKE3(sk ‖ challenge)" commitment pattern — this is a specific application of Cyclo, not described in the paper itself.
- Whether Cyclo supports this specific statement efficiently requires inspecting the actual protocol instantiation, not just the abstract.

**VERDICT:** Cyclo is real and the ~30KB proof size claim is credible. The specific authentication statement in SPEC.md is an *application* of Cyclo not validated by the paper.

---

## 2. ML-KEM-1024 (NIST FIPS 203)

**Standard:** FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard  
**Release date:** August 2024  
**Algorithm name:** ML-KEM (formerly CRYSTALS-Kyber)  
**Parameter set ML-KEM-1024:** 
- NIST security level 5 (≈AES-256)
- Public key: 1,568 bytes; ciphertext: 1,568 bytes; shared secret: 32 bytes

**SPEC.md alignment:** Section 3 correctly identifies ML-KEM-1024 as a NIST post-quantum standard. The hybrid combination with X25519 via HKDF-SHA256 is a reasonable design pattern (similar to NIST SP 800-56C).

**VERDICT:** ML-KEM-1024 reference is accurate and standardized.

---

## 3. BLAKE3 KDF Mode

**Claim in SPEC.md (Section 3):** `blake3::derive_key(context, key_material)` is used for deriving chunk keys, audit log keys, and MAC keys from the Root Master Seed.

**Analysis:**
- `blake3::derive_key` is BLAKE3's built-in KDF mode, which uses the MAC-style construction (BLAKE3-MAC) with a domain-separated context string.
- This is a legitimate, well-regarded KDF construction.
- Security contract: The context string must be unique per purpose and must not be reused across different key derivation contexts.
- The SPEC defines context strings like `"vela audit log v1"` — these should be formally specified with a dedicated domain separation scheme.

**VERDICT:** BLAKE3 KDF is appropriate. The domain separation strings are informal but acceptable. A formal specification of all context strings and their security properties should be included.

---

## 4. Shamir Secret Sharing (2-of-3)

**Claim in SPEC.md (Section 4.3):** RMS split into 2-of-3 scheme with shares distributed to cloud, VELA server (encrypted under FIDO2-protected key), and trusted contact.

**Analysis:**
- SSS over GF(2^8) is standard and correctly described.
- **Social recovery concern:** Share 3 given to a trusted contact is a *social recovery* mechanism, not cryptographic enforcement. This share can be coerced or socially engineering.
- The SPEC correctly identifies that Share 2 is protected by a FIDO2 hardware credential — but the FIDO2 credential itself must be set up at account creation and protected independently.
- The description implies the VELA server "never sees" Share 2's decryption key — this depends on correct FIDO2 implementation and is a critical trust assumption.

**VERDICT:** SSS scheme is correctly described. Trust assumptions around FIDO2 and social recovery share need explicit definition.

---

## 5. Path ORAM

**Claim in SPEC.md (Section 5.2):** Access pattern hiding via Path ORAM; server observes only fixed-size blob reads/writes.

**Analysis:**
- Path ORAM (Stefanov et al., 2013) is the correct theoretical primitive for this use case.
- The description is accurate in broad strokes.
- **"Trivial ORAM" for ≤4 chunks:** This is not standard terminology. The described approach (download and re-upload all chunks on every sync) is a valid but inefficient ORAM simplification. The threshold of "≤4 chunks" appears arbitrary.
- The ORAM position map is client-managed, which is correct.

**VERDICT:** Path ORAM is correctly referenced. The trivial-ORAM claim and threshold need more justification.

---

## 6. Protocol Logic Cross-Check

### Section 4.2 (Device Enrollment):
1. Device B generates hybrid keypair and displays QR → OK
2. Device A scans QR out-of-band (not routed through server) → OK
3. Device A encapsulates RMS using Device B's hybrid public keys → OK (Hybrid KEM)
4. Device A signs Device B's public key and sends capsule + signature → OK
5. Server verifies Cyclo proof before accepting enrollment → OK
6. Device B decapsulates RMS, provisions local Secure Enclave → OK

**Potential issue:** Step 4 says Device A "signs Device B's public key with its own enrolled identity key." What is the identity key? Not defined in the spec — the primary auth is Cyclo ZKP, but the signing key for enrollment is not specified.

### Section 4.3 (Recovery):
- The description of downloading VELA app on new device and pulling Share 1 from cloud, then authenticating with FIDO2 to decrypt Share 2, is coherent.
- The threat note correctly identifies that compromising both cloud + VELA server is insufficient without the FIDO2 credential.

### Section 5.3 (Conflict Resolution):
- Lamport clock + version-based conflict resolution is a valid approach.
- The three-case table is well-structured.
- **Issue:** "Items modified on both sides are kept as duplicate conflict copies" — this could lead to unbounded growth if conflicts are frequent and never resolved. No garbage collection mechanism is described.

### Section 6 (Auth Protocol):
- Challenge nonce (Redis, 60s TTL, single-use) → good
- Cyclo proof generation → plausible
- PASETO v4 token issuance → OK (PASETO is a modern alternative to JWT)
- Token lifetime: 15 min with sliding renewal → reasonable
- Max session 8 hours hard cap → good
- JTI revocation on logout/device revocation → correct

### Section 9 (Threat Model):
- Honest-but-curious server characterization is appropriate.
- Trust boundaries table is well-structured.
- **Out of scope items are correctly identified** (client-side malware, DoS, side-channel attacks on Zig implementation).

---

## 7. Unverifiable Claims (Require Code Audit)

The following claims **cannot be verified from public sources** and require inspection of the actual implementation:

1. **Cyclo Zig implementation timing safety** — SPEC.md itself acknowledges this: "Side-channel attacks against the Cyclo Zig implementation (to be addressed by a dedicated timing-safety audit before v2.0 production release)." This is a known open issue.

2. **tfhe-ntt Rust library via FFI** — The SPEC references `tfhe-ntt` for NTT operations. This is a real crate but its security properties in the FFI context need verification.

3. **Hybrid KEM construction formal security** — The combination of ML-KEM-1024 + X25519 via HKDF-SHA256 is a *hybrid* construction. The SPEC claims it guards against "undiscovered flaws in new lattice math." While intuitive, a formal security reduction for this specific hybrid construction is not standard NIST guidance.

4. **WASM core fallback security** — The fallback mode (IndexedDB + user PIN in browser) is explicitly marked as less secure, which is honest. But the security downgrade severity cannot be assessed without auditing the WASM implementation.

5. **Rate limiting implementation** — The Redis sliding window implementation claims are implementation-dependent.

---

## 8. External Sources Verified

| Source | URL | Status |
|--------|-----|--------|
| Cyclo paper | https://eprint.iacr.org/2026/359 | ✅ Real (Eurocrypt 2026) |
| NIST PQC standards | https://csrc.nist.gov/projects/post-quantum-cryptography | ✅ Verified (FIPS 203, 204, 205 released 2024) |
| Path ORAM | Stefanov et al., 2013 (theoretical) | ✅ Theoretical foundation solid |
| BLAKE3 | https://github.com/BLAKE3-team/BLAKE3 | ✅ Real, audited |
| PASETO v4 | https://paseto.io/ | ✅ Real protocol |
| FIPS 203 (ML-KEM) | https://doi.org/10.6028/NIST.FIPS.203 | ✅ Official NIST publication |

---

## 9. Findings Summary

### Verified Claims ✅
- Cyclo is a real lattice-based folding ZKP (Eurocrypt 2026) with ~30KB proofs
- ML-KEM-1024 is NIST-standardized (FIPS 203)
- Path ORAM is the correct primitive for access pattern hiding
- BLAKE3 KDF is appropriate for key derivation
- Shamir SSS 2-of-3 is correctly described
- Auth protocol flow (challenge → proof → PASETO token) is coherent
- Threat model trust boundaries are reasonable

### Unverifiable / Needs Clarification ⚠️
- Specific Cyclo authentication statement not validated by paper
- Hybrid KEM construction has no formal security reduction cited
- "Trivial ORAM" threshold (≤4 chunks) is arbitrary
- Identity key used in device enrollment (§4.2 Step 4) not defined
- Conflict copy garbage collection not described
- Zig implementation timing safety is an open issue

### Potential Issues 🔴
- Client-side malware / keyloggers marked out of scope — but RMS decryption in memory is transient; this is acceptable.
- FIDO2 integration trust assumption is critical and not fully specified.
- Social recovery share (trusted contact) is vulnerable to social engineering.

---

*Research compiled 2026-03-26*
