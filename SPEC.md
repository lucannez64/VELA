# VELA Protocol Specification v2.0 (Hardware-Bound & Zero-Knowledge)

**Version:** 2.1
**Date:** 2026-03-26
**Status:** Draft (revised after peer review)

---

## Table of Contents

1. [Overview & Design Philosophy](#1-overview--design-philosophy)
2. [System Architecture](#2-system-architecture)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
   3.1. [BLAKE3 Context String Registry](#31-blake3-context-string-registry)
4. [Identity, Device Management & Recovery](#4-identity-device-management--recovery)
5. [Vault Architecture & Flexible Data Types](#5-vault-architecture--flexible-data-types)
6. [Zero-Knowledge Authentication Protocol](#6-zero-knowledge-authentication-protocol)
7. [Client-Specific Implementations](#7-client-specific-implementations)
8. [API Reference (Abridged)](#8-api-reference-abridged)
9. [Security & Threat Model](#9-security--threat-model)

---

## 1. Overview & Design Philosophy

VELA v2.0 abandons server-side passwords and password-derived server authentication. It is a multi-device, hardware-bound, hybrid post-quantum secure vault. Authorization is proven to the server via **Cyclo**, a lattice-based zero-knowledge folding scheme. Clients may still protect local vault material with an optional device password fallback for systems that do not provide usable biometric hardware.

### Core Principles
- **Passwordless Server Identity:** Keys are generated on-device and locked inside hardware secure enclaves (TPM, Secure Enclave, Android Keystore) guarded by biometrics where available. A local-only password fallback may wrap the RMS on devices without biometric support; it is never sent to the VELA server.
- **Hybrid Post-Quantum Security:** Combines NIST post-quantum standards (ML-KEM-1024) with classical elliptic curve cryptography (X25519) to guard against both quantum threats and undiscovered flaws in new lattice math.
- **ZKP Authorization (Cyclo):** The server authenticates devices via Cyclo ZKPs, proving ownership of a valid device capability without exposing any key material — providing quantum-resistant authentication where even a future adversary who captures network traffic cannot retroactively break session authenticity.
- **Metadata-Hiding Vault:** The server does not know how many items you have or what type they are. The vault is synced as fixed-size encrypted blobs with access patterns hidden via Path ORAM.
- **Future-Proof Data Model:** Supports arbitrary data payloads (passwords, credit cards, secure notes, voice memos, files).

---

## 2. System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                              CLIENT TIER                               │
│                                                                        │
│  ┌────────────────┐ ┌────────────────┐ ┌────────────────────────────┐  │
│  │   Mobile App   │ │  Desktop App   │ │ Web Extension              │  │
│  │  (iOS/Android) │ │ (Rust/Tauri)   │ │ (WASM/JS)                  │  │
│  │ - SecureEnclave│ │ - TPM / Enclave│ │ - Native Messaging bridge  │  │
│  │ - Biometrics   │ │ - Biometrics   │ │   to Desktop App           │  │
│  └───────┬────────┘ └───────┬────────┘ └─────────────┬──────────────┘  │
│          │                  │                        │                 │
│          └──────────────────┼────────────────────────┘                 │
│                             ↓                                          │ 
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                  VELA Core Crypto Library                        │  │
│  │  (Zig for Cyclo prover · Rust for all other crypto · WASM build) │  │
│  │  - Cyclo ZKP Prover (Zig + tfhe-ntt via Rust FFI)                │  │
│  │  - Hybrid ML-KEM + X25519 / XChaCha20-Poly1305 (Rust)            │  │
│  │  - Path ORAM state management (Rust)                             │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────┬──────────────────────────────────┘
                                      │
                                HTTPS (TLS 1.3)
                                      │
┌─────────────────────────────────────↓──────────────────────────────────┐
│                              SERVER TIER                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   API Server (Rust / Axum)                       │  │
│  │ - ZKP Verifier (Cyclo)                                           │  │
│  │ - Sync Engine (Blob differential sync + ORAM tree storage)       │  │
│  │ - Rate Limiter (embedded sled TTL counters)                       │  │
│  └─────────────────┬─────────────────────────────────┬──────────────┘  │
│                    ↓                                 ↓                 │
│          ┌──────────────────┐               ┌───────────────────┐      │
│          │     stoolap      │               │       sled        │      │
│          │ - User identities│               │ - Rate limits     │      │
│          │ - Device records │               │ - Challenge nonces│      │
│          │ - Encrypted blobs│               │ - Token JTI       │      │
│          │   (ORAM chunks)  │               │   revocation set  │      │
│          └──────────────────┘               └───────────────────┘      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Cryptographic Primitives

| Purpose | Algorithm | Notes |
| :--- | :--- | :--- |
| **Identity/Auth ZKP** | **Cyclo (Garreta et al., 2026)** | Succinct lattice-based folding ZKP via partial range checks. Proves knowledge of secret key bound to device public key. See [eprint.iacr.org/2026/359](https://eprint.iacr.org/2026/359). |
| **Key Encapsulation** | **Hybrid: ML-KEM-1024 + X25519** | Combined via HKDF-SHA256 to derive shared secrets. This composition provides defense-in-depth: if a future attack breaks ML-KEM, X25519 remains secure (and vice versa). Formal security reduction to individual component hardness assumptions follows from the GL20 multi-key framework (Gong et al., 2020); see §9 for full threat model notes. |
| **Symmetric Vault Enc.** | **XChaCha20-Poly1305** | AEAD for chunked vault blobs. |
| **Key Derivation** | **BLAKE3 native KDF mode** | `blake3::derive_key(context, key_material)` for deriving chunk keys, audit log keys, and MAC keys from the Root Master Seed. Context strings are domain-separated per use. See §3.1 for the formal context string registry. |

### 3.1 BLAKE3 Context String Registry

All BLAKE3 KDF derivations from the RMS use the following domain-separated context strings:

| Derived Key | Context String | Output Usage |
| :--- | :--- | :--- |
| `Vault_Encryption_Key` | `"vela vault encryption v1"` | XChaCha20-Poly1305 encryption of vault chunks |
| `chunk_key_i` (per chunk) | `"vela chunk key v1"` + `‖ chunk_id` | Per-chunk data encryption key |
| `audit_key` | `"vela audit log v1"` | XChaCha20-Poly1305 encryption of device audit log |
| `device_identity_key` | `"vela device identity v1"` | X25519 private key for Hybrid KEM encapsulation and Cyclo authentication |
| `identity_signing_key` | `"vela identity signing v1"` | Ed25519 private key for device enrollment signatures |
| `mac_key` | `"vela mac key v1"` | HMAC-style integrity checks on vault metadata |

| Purpose | Algorithm | Notes |
| :--- | :--- | :--- |
| **Recovery Shares** | **Shamir's Secret Sharing** | SSS over GF(2^8) to split the Root Master Seed. |
| **Access Pattern Hiding** | **Path ORAM** | Client-managed position map. Server sees only fixed-size opaque blob reads/writes along ORAM tree paths. |

---

## 4. Identity, Device Management & Recovery

### 4.1 The Root Master Seed (RMS)
Every user has a 32-byte **Root Master Seed (RMS)**. It never leaves the client devices in plaintext.
- The RMS is generated on the first device.
- It is used to derive the `Vault_Encryption_Key` and all other per-purpose keys via BLAKE3 KDF.
- It is stored inside the device's Hardware Secure Enclave when available. On devices without supported biometric hardware, the client may store the RMS encrypted under a local device password. This fallback is a local unlock mechanism only and is never used for server authentication.

### 4.2 Multi-Device Sync (Device Enrollment)
When adding a new device (Device B), Device A must authorize it.

The **identity signing key** is derived from the RMS as:
```
identity_signing_key = blake3::derive_key("vela identity signing v1", RMS)
```
This produces a 32-byte seed used as the Ed25519 private key for enrollment signatures. The identity signing key is stored in the device's Hardware Secure Enclave alongside the RMS and is never transmitted.

**Enrollment flow:**
1. Device B generates a Hybrid Keypair (ML-KEM + X25519) and displays a QR code containing its Public Keys.
2. Device A scans the QR code out-of-band (the QR channel is never routed through the VELA server).
3. Device A encapsulates the `RMS` using Device B's public keys via the Hybrid KEM scheme.
4. Device A signs Device B's public key with its own enrolled identity signing key (Ed25519) and sends the capsule + signature to the server.
5. The server verifies Device A's Cyclo proof of identity before accepting the enrollment request. It stores the capsule and registers Device B's public key as authorized.
6. Device B downloads the capsule, decapsulates it to recover the `RMS`, provisions its own local Secure Enclave, and appends a signed entry to the encrypted device audit log (see §4.4).

**First-device bootstrap:** On initial account creation (no prior enrolled device), the first device generates the RMS, derives its identity signing key, and self-signs its own device public key. The server records this as the genesis device entry with no enroller's Cyclo proof required.

### 4.3 Recovery
If all devices are lost, the user relies on **Shamir's Secret Sharing (SSS)** established at account creation.
- The `RMS` is split into a 2-of-3 scheme:
  - **Share 1:** Encrypted and backed up to the user's cloud provider (iCloud/Google Drive).
  - **Share 2:** Stored on the VELA Server as ciphertext generated client-side. Recovery release is gated by a registered WebAuthn/FIDO2 recovery credential. The server stores the passkey public credential and never sees Share 2 plaintext.
  - **Share 3:** Given to a trusted contact via VELA protocol item sharing.
- Setup uses dedicated WebAuthn registration ceremonies: an authenticated device starts `/recovery/webauthn/register/start`, the client calls `navigator.credentials.create`, and `/recovery/webauthn/register/finish` verifies and stores the resulting passkey credential.
- To recover, the user downloads the VELA app on a new device, pulls Share 1 from their cloud, starts `/recovery/initiate`, signs the WebAuthn assertion with their FIDO2 credential, and submits it to `/recovery/recover`. The server releases only the encrypted Share 2 ciphertext. The Rust core combines Share 1 and Share 2 locally to reconstruct the `RMS`.
- For desktop devices without usable biometric hardware, the same local password fallback used for unlock may also be used to protect locally stored recovery material. This password never leaves the client and does not replace FIDO2 or trusted-contact recovery for account recovery across devices.

> **Threat note:** An adversary who compromises both the user's cloud provider and the VELA server still cannot recover by API unless they can also satisfy the user's WebAuthn assertion. The server still stores only ciphertext; the recovery credential gates release, not decryption. If the FIDO2 credential is also lost, recovery requires Share 3 from the trusted contact (2-of-3 threshold); if only the trusted contact is compromised, the adversary still needs Share 1 from the cloud provider.

### 4.4 Device Audit Log
VELA maintains an end-to-end encrypted audit log of device lifecycle events. The server stores this log as an opaque encrypted blob and has no plaintext access to its contents.

**What is logged:**
- Device enrolled (device ID, timestamp, enrolling device ID)
- Device revoked (device ID, timestamp, revoking device ID)
- Vault sync events (timestamp, chunk count — no item-level detail)
- Secure share sent/received (recipient user ID, timestamp)

**Key derivation:**
```
audit_key = blake3::derive_key("vela audit log v1", RMS)
```

**Storage:** The audit log is serialized, encrypted with XChaCha20-Poly1305 under `audit_key`, and uploaded as a reserved blob slot (chunk type `AuditLog`) alongside vault chunks. All currently enrolled devices hold the RMS and can therefore decrypt the audit log locally. No server-side query or admin access can read its contents.

**Access control:** Only clients that have successfully decrypted the RMS via their hardware enclave can decrypt the audit log. The server is never informed of log contents and cannot correlate log entries with user behavior.

---

## 5. Vault Architecture & Flexible Data Types

To prevent the server from knowing metadata (e.g., you have 50 passwords and 2 credit cards), the vault uses a **Chunked Blob Architecture** with Path ORAM to additionally hide access patterns.

### 5.1 The Local Vault Tree
Locally, the vault is a Bincode-serialized tree of arbitrary items.

```rust
enum VaultItem {
    Login { url: String, user: String, pass: String, totp: Option<String> },
    CreditCard { number: String, exp: String, cvv: String, pin: Option<String> },
    SecureNote { title: String, content: String },
    Identity { first_name: String, last_name: String, ssn: String },
    FileBlob { filename: String, mime: String, chunks: Vec<Uuid> }, // large files split across data chunks
}
```

For `FileBlob` items: the file data is split into 1MB data chunks. Each data chunk is stored as an independent `VaultChunk` on the server. The `FileBlob` entry in the vault tree holds only the ordered list of chunk UUIDs. Reassembly is performed client-side after downloading all referenced chunks.

### 5.2 Server-Side Blob Storage & Path ORAM

Before syncing, the client serializes the vault, pads it to uniform 1MB boundaries, and encrypts each chunk. The server only stores opaque fixed-size blobs:

```rust
struct VaultChunk {
    chunk_id:     Uuid,
    version:      u64,       // server-managed monotonic counter; used for optimistic locking
    lamport_clock: u64,      // client-managed logical clock; used for conflict detection
    last_writer:  DeviceId,  // which device last wrote this chunk
    ciphertext:   Vec<u8>,   // fixed 1MB (padded)
}
```

**Path ORAM for access pattern hiding:**
The client maintains a local *position map* (`chunk_id → current ORAM tree path`). The server also exposes opaque bucket/path endpoints for Path ORAM trees. All chunk reads and writes above the trivial threshold are routed through Path ORAM:
1. On read: the client reads the entire path from root to the leaf specified in the position map, re-randomizes the chunk's position, and writes the path back.
2. On write: the updated chunk is placed at a new random leaf path; all other slots along the path are re-encrypted with fresh nonces before upload.
3. The server observes only a sequence of fixed-size blob reads/writes along tree paths; it cannot determine which logical chunk is being accessed or whether it is a read or write.

For vaults with ≤4 active chunks, the client uses **trivial ORAM** (download and re-upload all chunks on every sync). At this scale, Path ORAM's path-read + path-write overhead (~2× tree depth slot accesses per sync) exceeds the cost of a full sequential sync (N chunks). The threshold of 4 chunks (binary tree depth ≈ 2–3 slots per path; 2 paths = 4–6 slot accesses vs. N = 4 sequential accesses) is empirically chosen; future implementations may adjust based on measured bandwidth and enclave overhead.

The legacy `/vault/chunk/{id}` endpoints remain for direct opaque-chunk sync and migration. Full tree access uses `/vault/oram/{tree_id}/path/{leaf}`. The `GET` response returns every bucket index on that root-to-leaf path with its version and base64 ciphertext if present. The `PUT` body writes the complete path back, one encrypted bucket per path bucket, each with its own `if_match` version for optimistic concurrency.

### 5.3 Conflict Resolution (Multi-Device Sync)

Each device independently increments a per-chunk `lamport_clock` on every local write. On sync:

1. The client fetches the sync manifest: `(chunk_id, version, lamport_clock, last_writer)` for all server chunks.
2. For each chunk, three cases apply:

| Condition | Outcome |
| :--- | :--- |
| `server.version > local.version` AND `local.lamport_clock == last_seen_lamport` | **Clean pull.** No local changes since last sync. Download and apply. |
| `local.lamport_clock > server.lamport_clock` AND `server.version == last_seen_version` | **Clean push.** Local is ahead, server has not changed. Upload. |
| Both `local.lamport_clock` and `server.lamport_clock` have advanced past the last common ancestor | **Conflict.** Download the server copy, decrypt both versions, perform item-level merge. Items present only on one side are kept. Items modified on both sides are kept as duplicate conflict copies, surfaced to the user with timestamps for manual resolution. The resolved chunk is uploaded as a new version. |

**Conflict copy lifecycle:** Conflict copies are retained for 30 days (configurable) after which they are automatically pruned from the vault. The client marks the original and conflict-copy chunks with a `conflict_refs` metadata field pointing to the common ancestor chunk_id. When a user resolves a conflict by choosing a winner or merging manually, the losing copy is deleted immediately and the `conflict_refs` link is cleared. Auto-pruning only removes unresolved conflict copies older than 30 days. This prevents unbounded vault inflation while allowing users time for manual resolution.

Uploads use an `If-Match: <version>` header for optimistic concurrency; the server rejects a PUT if the stored version has advanced since the client's last fetch, forcing a re-sync.

---

## 6. Zero-Knowledge Authentication Protocol

The client proves possession of the device private key (the X25519 key from the Hybrid KEM keypair generated at enrollment) using the **Cyclo ZKP** scheme (Garreta, Lipmaa, Luhaäär, Osadnik — ePrint 2026/359). Cyclo is a lightweight lattice-based folding scheme that produces succinct proofs verifiable in milliseconds.

**Key hierarchy and binding to RMS:** At enrollment, the device generates a Hybrid KEM keypair (ML-KEM + X25519). The X25519 private key is stored in the Hardware Secure Enclave and is **derived from the RMS** via:
```
device_identity_key = blake3::derive_key("vela device identity v1", RMS)
```
This binds the authentication key to the RMS: compromising the RMS would allow an attacker to derive all current and future device identity keys. The server registers the device's X25519 public key at enrollment and uses it as the Cyclo verification key.

### Flow
1. **Challenge:** Client requests a 32-byte challenge nonce from the server (stored in sled with a 60-second TTL; single-use).
2. **Proof Generation (Zig/Rust Core):** The client constructs a Cyclo proof π:
   - *Statement:* "I know a secret key `sk` such that `pk = PublicKey(sk)`, where `pk` appears in the server's enrolled device registry, and `BLAKE3(sk ‖ challenge)` equals a committed value."
   - The proof is generated by the Zig implementation of the Cyclo prover, which uses the `tfhe-ntt` Rust library for NTT operations via FFI.
3. **Verification:** The client sends `(device_id, π)` to the server. The Rust/Axum verifier checks π against the registered `pk` for that device.
4. **Session:** On success, the server issues a **PASETO v4 public token** containing `device_id`, `user_id`, `jti` (unique token ID), and `exp` (expiry).

**Quantum-resistance advantage:** The proof π is a lattice-based commitment. Even an adversary recording all traffic who later gains a quantum computer cannot extract `sk` from π or retroactively forge past authentications. Unlike schemes where a raw ECDSA signature is transmitted, the Cyclo proof reveals no exploitable algebraic relation between the proof and the secret key.

### Session Lifecycle

| Property | Value |
| :--- | :--- |
| **Token lifetime** | 15 minutes (sliding) |
| **Max session duration** | 8 hours (hard cap regardless of activity) |
| **Renewal** | Each authenticated API call that arrives within the last 5 minutes of validity issues a refreshed token in the response header. |
| **Revocation** | On device revocation or explicit logout, the token's `jti` is added to a sled-backed revocation set with a TTL equal to the token's remaining lifetime. Every request checks this set. |
| **Device revocation cascade** | Revoking a device invalidates all active JTIs associated with that `device_id`. |

### Rate Limiting

The server uses embedded sled TTL counters for rate limits, challenge nonces, token revocation, and device-JTI tracking. This keeps the deployable server as a single binary with embedded data files instead of requiring PostgreSQL and Redis services.

| Endpoint | Limit | Enforcement |
| :--- | :--- | :--- |
| `GET /auth/challenge` | 20 requests/min per IP | sled TTL counter |
| `POST /auth/verify` | 5 failed proofs/min per `device_id` | sled TTL counter; exponential backoff after 3 consecutive failures (1s, 2s, 4s, ..., capped at 5min) |
| `POST /auth/verify` | 10 attempts/min per IP | sled TTL counter; independent of per-device limit |
| All authenticated routes | 300 requests/min per session token | sled TTL counter |

---

## 7. Client-Specific Implementations

### 7.1 Core Crypto Library (Zig + Rust)
- **Cyclo ZKP prover:** Implemented in Zig for predictable allocation and tight control over the matrix/NTT operations Cyclo requires. Uses the `tfhe-ntt` Rust library for polynomial NTT transforms via a thin Rust FFI layer.
- **All other cryptographic operations** (ML-KEM, X25519, XChaCha20-Poly1305, BLAKE3 KDF, Path ORAM, Shamir SSS) are implemented in Rust using audited crates (`ml-kem`, `x25519-dalek`, `chacha20poly1305`, `blake3`, etc.).
- Rust FFI wrappers expose the full library API uniformly.
- Compiled to `aarch64` / `x86_64` for Mobile/Desktop, and `wasm32-unknown-unknown` for the Web Extension fallback.

### 7.2 Mobile (iOS / Android)
- **App:** Native Swift (iOS) or Kotlin (Android).
- **Enclave:** Uses `SecureEnclave` (iOS) and `StrongBox` (Android) to hold a hardware-bound ECC key. The VELA RMS is encrypted by this hardware key at rest.
- **UX:** User opens app → FaceID/Biometrics unlocks hardware key → hardware key decrypts RMS into memory → Rust core decrypts vault.

### 7.3 Desktop App
- **App:** Rust Tauri.
- **Enclave:** Windows TPM 2.0 or macOS Secure Enclave where available. Desktop can fall back to a local password-wrapped RMS for computers without biometric hardware.
- **UX:** Runs as a background daemon. Exposes a local IPC socket (Unix Domain Socket / Named Pipe on Windows) for the Web Extension to communicate with.

### 7.4 Web Extension
- **Security Boundary:** Browsers are hostile environments. The extension *does not* handle the RMS or decrypt vault chunks itself under normal operation.
- **Native Messaging:** The extension uses Chrome/Firefox Native Messaging to communicate with the Desktop Daemon.
- **UX:** Extension asks Desktop: "Give me the autofill data for google.com". Desktop prompts user for a biometric touch, decrypts only the specific item, and sends it to the extension via the secure local IPC bridge. The RMS never enters browser memory.
- **Fallback:** If the Desktop app is not installed, the Web Extension loads the Zig/Rust WASM core. The PIN is stretched via **Argon2id** (3 iterations, 64MB memory, 4 parallelism) to derive a 256-bit wrapping key that encrypts the RMS using XChaCha20-Poly1305 before storage in `IndexedDB`. **This mode is explicitly less secure** — the RMS and PIN-derived key are held in browser memory and protected only by software controls. Users are shown a persistent security downgrade warning when operating in fallback mode. The PIN must be at least 8 characters.

---

## 8. API Reference (Abridged)

| Route | Method | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `/device/enroll` | POST | Cyclo proof (enrolling device) | Submits an RMS capsule encrypted for a new device's Hybrid PK, plus the enrolling device's signature over the new device's public key. |
| `/device/revoke` | POST | PASETO v4 | Revokes a device by ID; cascades to invalidate all active tokens for that device. |
| `/auth/challenge` | GET | None | Returns a 32-byte single-use nonce (60s TTL). |
| `/auth/verify` | POST | None | Accepts Cyclo proof π; returns PASETO v4 session token on success. |
| `/vault/sync` | GET | PASETO v4 | Returns manifest: list of `(chunk_id, version, lamport_clock, last_writer)`. |
| `/vault/chunk/{id}` | GET | PASETO v4 | Download one 1MB encrypted ORAM chunk. |
| `/vault/chunk/{id}` | PUT | PASETO v4 | Upload a 1MB encrypted chunk. Requires `If-Match: <version>` header; returns `409 Conflict` if version has advanced. |
| `/vault/chunk/{id}` | DELETE | PASETO v4 | Delete a stale encrypted chunk. Requires `If-Match: <version>`. |
| `/vault/oram/{tree_id}/path/{leaf}?height=N` | GET | PASETO v4 | Download the opaque encrypted buckets on a Path ORAM root-to-leaf path. Missing buckets are returned with version `0`. |
| `/vault/oram/{tree_id}/path/{leaf}` | PUT | PASETO v4 | Write back a complete Path ORAM path. Each bucket carries `if_match`, `lamport_clock`, and base64 ciphertext. |
| `/recovery/share` | PUT/GET/DELETE | PASETO v4 | Store, retrieve, or delete the user's encrypted server-side recovery share. |
| `/recovery/webauthn/register/start` | POST | PASETO v4 | Starts passkey/FIDO2 registration for recovery; returns WebAuthn creation options. |
| `/recovery/webauthn/register/finish` | POST | PASETO v4 | Verifies the WebAuthn attestation response and stores the recovery credential public key. |
| `/recovery/initiate` | POST | None | Starts a WebAuthn assertion ceremony for a user with a stored recovery share and recovery passkey. |
| `/recovery/recover` | POST | WebAuthn assertion | Verifies the passkey assertion with user verification and releases the encrypted server-side recovery share. |
| `/share/send` | POST | PASETO v4 | Encapsulate a specific vault item for another user using Hybrid KEM; delivers encrypted capsule to recipient's inbox. |

---

## 9. Security & Threat Model

### Assets
- **Root Master Seed (RMS):** The highest-value secret. Compromise of the RMS grants full vault decryption.
- **Device private keys:** Bound to hardware enclaves; cannot be exported in plaintext.
- **Vault ciphertext blobs:** Stored on the server. Encrypted; zero value to an attacker without the RMS.
- **Audit log:** Encrypted; reveals device lifecycle events only to enrolled devices.

### Trust Boundaries

| Boundary | Trust Level | Notes |
| :--- | :--- | :--- |
| Hardware Secure Enclave | Trusted | RMS and device private keys never leave in plaintext. |
| VELA Client (native) | Trusted | Runs in user-controlled process; holds RMS in memory during active session only. |
| VELA Server | Semi-trusted | Stores encrypted blobs; verifies Cyclo proofs; never sees RMS or vault plaintext. The server is an honest-but-curious adversary: it cannot decrypt anything but can observe traffic timing. |
| Cloud Provider (iCloud/Google Drive) | Semi-trusted | Holds Share 1 only; one of three Shamir shares; useless alone. |
| Browser (Web Extension fallback) | Untrusted | Hostile environment; fallback mode degrades security. |
| Network | Untrusted | All communication over TLS 1.3; Cyclo proofs provide quantum-resistant authentication layer above TLS. |
| Local password fallback | Semi-trusted | Protects RMS at rest only on devices without biometric hardware. It is intentionally scoped to local unlock and is never accepted by the server as identity proof. |

### Threat Coverage

| Threat | Mitigation |
| :--- | :--- |
| Server compromise | Vault blobs are encrypted client-side; RMS never transmitted; server has no ability to decrypt. |
| Quantum adversary breaking ECDH/ECDSA | Hybrid ML-KEM + X25519 KEM; Cyclo lattice-based ZKP (not ECDSA) for auth. |
| Access pattern leakage | Path ORAM hides which chunk is accessed; server sees only fixed-size blob operations on tree paths. |
| Complete device loss | Shamir 2-of-3 recovery via cloud share + FIDO2-protected server share. |
| Unauthorized device enrollment | Enrolling device must present a valid Cyclo proof; new device's public key is signed by the enrolling device; server verifies both. |
| Session token theft | Short 15-minute TTL; JTI revocation on logout/device revocation; PASETO v4 is tamper-evident. |
| Brute-force ZKP forgery | Cyclo is computationally binding over lattice hardness assumptions (MSIS/MLWE); rate limiting further reduces attack surface. |
| Metadata inference by server | Fixed-size blobs; Path ORAM; server cannot distinguish vault size, item count, or item type. |

### Out of Scope (v2.0)
- Client-side malware / keyloggers (trusted execution environment is a prerequisite).
- Denial of service at the network layer.
- Side-channel attacks against the Cyclo Zig implementation (to be addressed by a dedicated timing-safety audit before v2.0 production release).
- **Ruthless coercion / rubber-hose attacks:** An adversary who physically coerces the user to reveal a Shamir share (Share 1 via cloud credentials, Share 3 via trusted contact) or to authenticate with their FIDO2 credential. This is a real-world threat for password managers. v2.0 provides no protection against such attacks; future versions may explore threshold decryption or secret sharing with decoy shares.
- **Screen/memory scraping:** Hardware keyloggers, cold-boot attacks, or RAM readout via malware. Out of scope until a hardware-assisted trusted display path is available.
