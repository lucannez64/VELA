# VELA Crypto Review Status

This crate is security-sensitive and must not depend on release-candidate
cryptographic primitives for production vault encryption.

Current production primitives:

- Vault and chunk AEAD: `chacha20poly1305` `0.10.1` using XChaCha20-Poly1305.
- Hybrid KEM: `ml-kem` `0.3.0` plus X25519, combined with HKDF-SHA256.
- Signing: `fips204` ML-DSA-87 plus Ed25519.
- KDF: BLAKE3 derive-key mode with domain-separated context strings.

Review requirements before release:

- Run `cargo audit` for every Rust lockfile in this repo.
- Re-run interoperability tests for desktop, Android bridge, and server after
  changing any crypto crate version.
- Treat any migration of vault ciphertext format as a protocol change requiring
  explicit backwards-compatibility tests.
