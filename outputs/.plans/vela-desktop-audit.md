# Audit Plan: VELA Desktop Implementation vs Protocol Specification

## Audit Target
- **Spec:** VELA Protocol Specification v2.0 (Passwordless & Zero-Knowledge)
- **Codebase:** `desktopVELA/` - Rust/Tauri desktop application
- **Scope:** Local implementation only (server-side not yet wired)

## Claims to Check

### 1. Cryptographic Primitives
| Spec Claim | What to Verify |
|------------|----------------|
| BLAKE3 native KDF mode for key derivation | Check if `blake3::derive_key()` is used with correct context strings |
| Context strings: `"vela vault encryption v1"`, `"vela chunk key v1"`, `"vela audit log v1"`, `"vela device identity v1"`, `"vela identity signing v1"`, `"vela mac key v1"` | Verify all 6 context strings are present |
| Hybrid ML-KEM-1024 + X25519 for KEM | Check for `ml-kem` crate usage and X25519 implementation |
| XChaCha20-Poly1305 for symmetric vault encryption | Verify `chacha20poly1305` AEAD usage |
| Shamir's Secret Sharing for RMS recovery | Verify SSS implementation (2-of-3 scheme) |

### 2. Vault Architecture
| Spec Claim | What to Verify |
|------------|----------------|
| `VaultItem` enum with Login, CreditCard, SecureNote, Identity, FileBlob variants | Check enum definition and field names |
| Bincode serialization | Verify `bincode` crate usage |
| 1MB chunk size | Verify chunk size constant |
| Path ORAM for access pattern hiding | Check ORAM implementation |
| Trivial ORAM for vaults with ≤4 chunks | Verify threshold logic |

### 3. Identity & Device Management
| Spec Claim | What to Verify |
|------------|----------------|
| Root Master Seed (RMS) generation | Check RMS generation code |
| Device identity key derivation via BLAKE3 KDF | Verify `device_identity_key = blake3::derive_key("vela device identity v1", RMS)` |
| Identity signing key derivation via BLAKE3 KDF | Verify `identity_signing_key = blake3::derive_key("vela identity signing v1", RMS)` |
| Ed25519 for enrollment signatures | Check for Ed25519 signature implementation |
| Device audit log with XChaCha20-Poly1305 encryption | Verify audit log encryption |
| Audit key derivation: `blake3::derive_key("vela audit log v1", RMS)` | Verify correct context string |

### 4. Client-Specific Implementation (Desktop)
| Spec Claim | What to Verify |
|------------|----------------|
| Rust/Tauri application | Confirm `src-tauri/` exists with Tauri configuration |
| TPM 2.0 or Secure Enclave integration | Check for enclave-related code |
| Biometric authentication | Verify biometric prompt integration |
| Local IPC socket for Web Extension | Check for Unix Domain Socket / Named Pipe implementation |
| Background daemon architecture | Verify daemon/service structure |

### 5. ZKP Authentication (Cyclo)
| Spec Claim | What to Verify |
|------------|----------------|
| Cyclo ZKP scheme implementation | Check for Cyclo prover/verifier |
| Zig implementation with Rust FFI | Verify Zig code presence and FFI bindings |
| tfhe-ntt Rust library via FFI | Check for `tfhe-ntt` crate and FFI |

## Audit Approach
1. **Researcher agent:** Explore `desktopVELA/src-tauri/` and `desktopVELA/src/` directories
2. **Verifier agent:** Verify cryptographic implementations match spec exactly
3. **Focus:** Local implementation only - no server-side verification needed

## Output
- Audit artifact saved to: `outputs/vela-desktop-audit.md`
