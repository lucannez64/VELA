//! Fuzz vault JSON deserialization — the sync-wire / storage-file surface.
//!
//! `VaultStore` and `VaultItem` are read back from the encrypted local file
//! and from sync payloads; a malicious or corrupted document must never panic,
//! loop, or allocate unboundedly. Also exercises the index rebuild path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_core::vault::VaultStore;

fuzz_target!(|data: &[u8]| {
    // Cap input so a fuzzer-found "hang" is algorithmic, not payload size.
    if data.len() > 256 * 1024 {
        return;
    }
    let Ok(store) = serde_json::from_slice::<VaultStore>(data) else {
        return;
    };

    // Successful parse: derived state must be consistent.
    let _ = store.search("a");
    let _ = store.get_item("1");
    let json = serde_json::to_vec(&store).expect("re-serialize parsed store");

    // Round-trip stability: what parses must re-parse identically.
    let reparsed: VaultStore =
        serde_json::from_slice(&json).expect("own serialization must re-parse");
    assert_eq!(reparsed.items.len(), store.items.len());
    assert_eq!(reparsed.tombstones.len(), store.tombstones.len());
});
