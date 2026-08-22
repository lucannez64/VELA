//! Fuzz the binary crypto parsers + AEAD open paths.
//!
//! Byte-layout parsers (`HybridPublicKey::from_bytes`,
//! `HybridCapsule::from_bytes`, `open_share`) and the two AEAD readers
//! (`decrypt`, `open`) all take attacker-influenced bytes off the wire or off
//! disk. None may panic, read out of bounds, or wrap lengths.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_crypto::{aead, kem};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let key = [0x5au8; 32];

    // AEAD: both formats, arbitrary blobs.
    let _ = aead::decrypt(&key, data);
    let _ = aead::open(&key, data, b"fuzz-aad");
    let _ = aead::open_vault_chunk(&key, data, "vault-data-000001", 7);

    // Hybrid KEM parsers: split input into pk / capsule / share-ciphertext
    // thirds so every parser gets mutated bytes each run.
    let third = data.len() / 3;
    let (pk_blob, rest) = data.split_at(third);
    let (cap_blob, ct) = rest.split_at(third);

    if let Ok(pk) = kem::HybridPublicKey::from_bytes(pk_blob) {
        // A parsed public key must be usable for encapsulation.
        let _ = kem::encapsulate(&pk);
    }
    if let Ok(capsule) = kem::HybridCapsule::from_bytes(cap_blob) {
        let sk_pair = kem::generate_keypair();
        let _ = kem::decapsulate(&sk_pair.1, &capsule);
    }
    // seal_share/open_share round trip with a fresh keypair; ct is fuzzed.
    let (pk, sk) = kem::generate_keypair();
    if let Ok(sealed) = kem::seal_share(&pk, b"fuzz plaintext") {
        assert_eq!(kem::open_share(&sk, &sealed).unwrap(), b"fuzz plaintext");
    }
    let _ = kem::open_share(&sk, ct);
});
