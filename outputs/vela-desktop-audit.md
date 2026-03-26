# VELA Desktop Implementation Audit Report

**Target:** VELA Protocol Specification v2.0 vs `desktopVELA/` implementation  
**Date:** 2026-03-26  
**Scope:** Local implementation only (server-side not wired)  
**Slug:** `vela-desktop-audit`

---

## Executive Summary

The desktopVELA implementation covers a subset of the v2.0 spec's cryptographic and vault functionality. Most core primitives (BLAKE3 KDF, XChaCha20-Poly1305, Hybrid KEM, Shamir SSS, Path ORAM, Hybrid Signing, Cyclo ZKP FFI) are implemented correctly in the `libVELA/vela-crypto` crate. However, significant discrepancies exist in the vault data model, missing context strings, incomplete TPM/hardware enclave integration, and an RMS storage mechanism that uses Windows Credential Manager instead of hardware-protected storage.

---

## 1. Cryptographic Primitives

### 1.1 BLAKE3 KDF

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| BLAKE3 native KDF mode | `blake3::derive_key` in `libVELA/vela-crypto/src/kdf.rs` | ✅ MATCH |
| `"vela vault encryption v1"` | `crypto.rs:13` and `kdf.rs:28` | ✅ MATCH |
| `"vela audit log v1"` | `crypto.rs:15` and `kdf.rs:29` | ✅ MATCH |
| `"vela device identity v1"` | `crypto.rs:14` and `kdf.rs:32` | ✅ MATCH |
| `"vela chunk key v1"` | NOT FOUND | ❌ MISSING |
| `"vela identity signing v1"` | NOT FOUND | ❌ MISSING |
| `"vela mac key v1"` | `kdf.rs:30` has `"vela chunk mac v1"` | ⚠️ MISMATCH |

**Finding:** The spec defines 6 domain-separated context strings for BLAKE3 KDF. The implementation provides 6 constants in `kdf.rs:27-33` but uses different names for two of them. The spec's `"vela identity signing v1"` is absent entirely; the spec's `"vela mac key v1"` is named `"vela chunk mac v1"` in code.

**Spec Reference:** `SPEC.md:97-104` (Table in §3.1)

### 1.2 Hybrid KEM (ML-KEM-1024 + X25519)

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| ML-KEM-1024 | `ml_kem::ml_kem_1024` in `kem.rs:17-22` | ✅ MATCH |
| X25519 | `x25519_dalek::StaticSecret/PublicKey` in `kem.rs:25` | ✅ MATCH |
| HKDF-SHA256 combination | `Hkdf::<Sha256>` in `kem.rs:121` | ✅ MATCH |
| Salt: `b"vela hybrid kem v1"` | `kem.rs:30` | ✅ MATCH |

**Finding:** The Hybrid KEM implementation in `libVELA/vela-crypto/src/kem.rs` correctly combines ML-KEM-1024 and X25519 via HKDF-SHA256, matching the spec's security rationale in `SPEC.md:89`.

### 1.3 XChaCha20-Poly1305 AEAD

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| XChaCha20-Poly1305 AEAD | `chacha20poly1305::XChaCha20Poly1305` in `aead.rs:8` | ✅ MATCH |
| 24-byte nonce prepended | `aead.rs:32-34` | ✅ MATCH |
| 16-byte Poly1305 tag | `aead.rs:16` (OVERHEAD = 24+16=40) | ✅ MATCH |

**Finding:** The AEAD implementation in `libVELA/vela-crypto/src/aead.rs` correctly implements XChaCha20-Poly1305 with the nonce prepended to ciphertext for storage.

### 1.4 Shamir Secret Sharing

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| 2-of-3 scheme | `shamir.rs:96` threshold parameter | ✅ MATCH |
| GF(2^8) with irreducible polynomial 0x11b | `shamir.rs:17` | ✅ MATCH |
| Lagrange interpolation | `shamir.rs:186-206` | ✅ MATCH |

**Finding:** The Shamir SSS implementation in `libVELA/vela-crypto/src/shamir.rs` correctly implements GF(2^8) with the AES irreducible polynomial and 2-of-n threshold support.

### 1.5 Hybrid Signing (ML-DSA-87 + Ed25519)

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| ML-DSA-87 | `fips204::ml_dsa_87` in `signing.rs:39` | ✅ MATCH |
| Ed25519 | `ed25519_dalek` in `signing.rs:35-37` | ✅ MATCH |
| Both signatures required for verification | `signing.rs:129-138` | ✅ MATCH |

**Finding:** The signing implementation in `libVELA/vela-crypto/src/signing.rs` correctly implements a hybrid scheme where both ML-DSA-87 and Ed25519 signatures are required. Note: the spec (`SPEC.md:103-104`) references Ed25519 for identity signing; the implementation uses a hybrid scheme going beyond the spec's minimum requirement.

### 1.6 Cyclo ZKP (FFI to Zig)

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| Cyclo ZKP via FFI | `cyclo.rs` with `extern "C"` FFI calls | ✅ MATCH |
| Zig implementation | `libVELA/cyclo/src/cyclo_ffi.zig` | ✅ PRESENT |
| tfhe-ntt via Rust shim | `ntt_shim/src/lib.rs` wrapping `tfhe_ntt` | ✅ MATCH |

**Finding:** The Cyclo ZKP is implemented via FFI, with Zig code in `libVELA/cyclo/` and a Rust NTT shim (`ntt_shim`) wrapping `tfhe-ntt` via C ABI. Build infrastructure in `vela-crypto/build.rs` invokes `zig build`.

---

## 2. Vault Architecture

### 2.1 VaultItem Data Model

**Spec Claim** (`SPEC.md:178-185`):
```rust
enum VaultItem {
    Login { url: String, user: String, pass: String, totp: Option<String> },
    CreditCard { number: String, exp: String, cvv: String, pin: Option<String> },
    SecureNote { title: String, content: String },
    Identity { first_name: String, last_name: String, ssn: String },
    FileBlob { filename: String, mime: String, chunks: Vec<Uuid> },
}
```

**Implementation** (`vault.rs:5-27`):
```rust
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub item_type: ItemType,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub totp_secret: Option<String>,
    pub notes: Option<String>,
    pub card_number: Option<String>,
    pub card_exp: Option<String>,
    pub card_cvv: Option<String>,
    pub card_pin: Option<String>,
    pub cardholder_name: Option<String>,
    pub secure_note_content: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_modified_device: Option<String>,
    pub favorite: bool,
    pub shared: bool,
    pub share_recipient: Option<String>,
}
```

**Status:** ❌ MISMATCH — The spec defines a typed enum with structured variants; the implementation uses a flat "kitchen sink" struct with all possible fields nullable.

**Impact:** This is a significant design divergence. The spec's enum approach provides type safety and makes it explicit which fields apply to which item type. The flat struct approach risks storing inconsistent state (e.g., both `username` and `card_number` populated for a Login item).

### 2.2 ItemType Enum

**Spec Claim:** 5 variants: Login, CreditCard, SecureNote, Identity, FileBlob  
**Implementation** (`vault.rs:29-37`):
```rust
pub enum ItemType {
    Login,
    CreditCard,
    SecureNote,
    Identity,
    File,
}
```

**Status:** ⚠️ PARTIAL — `FileBlob` in spec is named `File` in code. Otherwise matches.

### 2.3 Serialization

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| Bincode serialization | `store.rs:54,73` using `bincode::serialize/deserialize` | ✅ MATCH |

### 2.4 Chunk Size and ORAM

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| 1MB chunk size | NOT FOUND as constant | ❌ MISSING |
| Path ORAM | `libVELA/vela-crypto/src/oram.rs` | ✅ MATCH |
| Trivial ORAM threshold (≤4 chunks) | `oram.rs:27` `TRIVIAL_ORAM_THRESHOLD = 4` | ✅ MATCH |

**Finding:** The 1MB chunk size constant is referenced in the spec (`SPEC.md:200`) but not defined as a named constant in the codebase. The Path ORAM and trivial ORAM threshold logic are correctly implemented.

---

## 3. Identity & Device Management

### 3.1 Root Master Seed (RMS)

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| 32-byte RMS generated on-device | `crypto.rs:29-33` using `OsRng` | ✅ MATCH |
| RMS stored in Hardware Secure Enclave | `biometric.rs:54-186` stores in Windows Credential Manager | ⚠️ DEVIATION |

**Finding:** The spec (`SPEC.md:116-119`) mandates the RMS be stored in a hardware secure enclave. The implementation stores the RMS in Windows Credential Manager (`CRED_PERSIST_LOCAL_MACHINE`), which provides software-level protection, not hardware-bound enclave protection. The `device.rs:134-163` TPM module is stubbed with fallbacks.

### 3.2 Device Identity Key Derivation

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| `device_identity_key = blake3::derive_key("vela device identity v1", RMS)` | `crypto.rs:39-41` using `IDENTITY_KEY_CONTEXT` | ✅ MATCH |

### 3.3 Identity Signing Key Derivation

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| `identity_signing_key = blake3::derive_key("vela identity signing v1", RMS)` | NOT FOUND | ❌ MISSING |

**Finding:** The `identity_signing_key` derivation with context `"vela identity signing v1"` is specified in `SPEC.md:126-127` but not implemented. The `crypto.rs` module provides `identity_key()` (device identity), `share_key()`, and `oram_key()`, but no `identity_signing_key()` function.

### 3.4 Device Audit Log

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| Audit log encrypted with XChaCha20-Poly1305 | `crypto.rs:43-45` `audit_key()` exists | ✅ MATCH |
| Logged: device enrolled/revoked, sync events, share events | NOT IMPLEMENTED | ❌ MISSING |

**Finding:** While the `audit_key()` derivation exists, the actual device audit log recording (enrollment events, revocation events, sync timestamps) is not implemented in `device.rs` or elsewhere.

### 3.5 DeviceKeys

**Implementation** (`device.rs:107-131`):
```rust
pub struct DeviceKeys {
    pub signing_secret: [u8; 32],
    pub signing_public: [u8; 32],
}
```

**Finding:** The `DeviceKeys` struct uses raw 32-byte keys derived from `OsRng`, not from the RMS as the spec requires. The spec (`SPEC.md:124-128`) specifies that the identity signing key should be derived from the RMS via BLAKE3 KDF, not randomly generated.

---

## 4. Client-Specific Implementation (Desktop)

### 4.1 Tauri/Rust Application

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| Rust/Tauri application | `src-tauri/Cargo.toml:10` `tauri = "2.0"` | ✅ MATCH |

### 4.2 TPM / Secure Enclave

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| TPM 2.0 integration | `device.rs:134-163` stub with fallback | ⚠️ INCOMPLETE |
| `is_tpm_available()` | `device.rs:135-153` checks via PowerShell | ✅ PRESENT |
| `store_in_tpm()` | `device.rs:155-158` logs "not yet implemented" | ❌ STUB |

**Finding:** TPM storage is stubbed. `store_in_tpm` logs a warning and returns `Ok(())`, and `retrieve_from_tpm` returns an error. The RMS is stored in Windows Credential Manager instead.

### 4.3 Biometric Authentication

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| Windows Hello / Touch ID | `biometric.rs:46-201` Windows Credential Manager API | ✅ PRESENT |
| RMS encryption with biometrics | `biometric.rs:161-186` `store_rms()` | ✅ PRESENT |

**Finding:** Biometric authentication uses Windows Credential Manager via the Win32 API (`CredReadW`, `CredWriteW`). This is functional but provides software-level security, not hardware enclave protection as the spec requires.

### 4.4 IPC for Web Extension

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| Local IPC socket (TCP on port 14597) | `ipc.rs:68` `const PORT: u16 = 14597` | ✅ MATCH |
| Autofill request/response | `ipc.rs:233-265` | ✅ PRESENT |

**Finding:** The IPC server is correctly implemented using TCP sockets, with message types for `AutofillRequest`, `AutofillResponse`, `Ping`, `Pong`, etc. This matches the spec's description of the desktop daemon exposing a local IPC socket for the web extension.

### 4.5 Session Tokens

| Spec Claim | Implementation | Status |
|------------|---------------|--------|
| 15-minute token lifetime | `session.rs:5` `SESSION_DURATION_SECS = 15 * 60` | ✅ MATCH |
| 8-hour max session | `session.rs:6` `MAX_SESSION_DURATION_SECS = 8 * 60 * 60` | ✅ MATCH |
| Sliding renewal (within 5 min of expiry) | `session.rs:69-87` checks `-300` seconds | ✅ MATCH |
| PASETO v4 tokens | NOT IMPLEMENTED — uses custom base64 tokens | ❌ MISMATCH |

**Finding:** The session management logic matches the spec's timing parameters, but session tokens are generated as random 32-byte values encoded in base64url (`session.rs:111-116`), not as PASETO v4 public tokens as specified in `SPEC.md:246`.

---

## 5. Missing / Not Wired

The following spec features are not yet implemented in the desktop client:

| Feature | Spec Section | Status |
|---------|-------------|--------|
| Server-side sync (vault/sync, vault/chunk endpoints) | §8 API Reference | ❌ NOT WIRED |
| Device enrollment flow (QR code, capsule transfer) | §4.2 | ❌ NOT IMPLEMENTED |
| Device revocation | §4.4, §8 | ❌ NOT IMPLEMENTED |
| RMS capsule encapsulation for new devices | §4.2 | ❌ NOT IMPLEMENTED |
| FIDO2 recovery flow | §4.3 | ❌ NOT IMPLEMENTED |
| Shamir share 2-of-3 recovery (cloud + FIDO2) | §4.3 | ❌ NOT IMPLEMENTED |
| Item sharing (`/share/send`) | §8 | ❌ NOT IMPLEMENTED |
| Conflict resolution (item-level merge) | §5.3 | ❌ NOT IMPLEMENTED |
| Rate limiting (Redis-backed) | §6 | ❌ N/A (server-side) |
| Cyclo ZKP authentication flow | §6 | ⚠️ FFI present, not integrated with auth |

---

## 6. Summary of Discrepancies

| Severity | Item | Location |
|----------|------|----------|
| **High** | VaultItem is flat struct, not typed enum | `vault.rs:5-27` |
| **High** | `"vela identity signing v1"` context string missing | `crypto.rs` |
| **High** | RMS not stored in hardware enclave (TPM stubbed) | `device.rs:155-162` |
| **Medium** | `"vela chunk key v1"` context string missing | `kdf.rs` |
| **Medium** | `"vela mac key v1"` named `"vela chunk mac v1"` | `kdf.rs:30` |
| **Medium** | PASETO tokens not used (custom base64 tokens) | `session.rs:111-116` |
| **Medium** | 1MB chunk size constant not defined | N/A |
| **Medium** | Device audit log not recorded | `device.rs` |
| **Low** | `FileBlob` variant named `File` | `vault.rs:36` |
| **Low** | `DeviceKeys` random generation not RMS-derived | `device.rs:114-130` |

---

## 7. Security Considerations

1. **RMS Protection:** Storing RMS in Windows Credential Manager instead of TPM provides weaker protection than the spec's hardware enclave requirement. An attacker with code execution on the machine can potentially retrieve the RMS.

2. **Missing Identity Signing Key:** Without the `"vela identity signing v1"` derived key, the enrollment flow's device-to-device authentication cannot be performed as specified.

3. **Session Tokens:** Custom base64 tokens lack the tamper-evidence properties of PASETO v4.

---

## Sources

- **Spec:** `E:\Projects\VELA\SPEC.md` (VELA Protocol Specification v2.0)
- **Desktop Client:** `E:\Projects\VELA\desktopVELA\src-tauri\`
- **Crypto Library:** `E:\Projects\VELA\libVELA\vela-crypto\`
- **Cyclo Zig Implementation:** `E:\Projects\VELA\libVELA\cyclo\`
- **NTT Shim:** `E:\Projects\VELA\libVELA\cyclo\ntt_shim\`
