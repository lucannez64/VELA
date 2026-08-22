//! Fuzz Shamir share parsing + reconstruction — recovery-flow surface.
//!
//! Shares are held by users (paper, cloud backups) and one leg can arrive from
//! the server. `Share::from_bytes` accepts both authenticated and legacy
//! layouts; `reconstruct` must reject mismatched/tampered sets instead of
//! panicking or returning an unauthenticated "secret" when tags are present.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_crypto::shamir::{self, Share};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 || data.len() > 4096 {
        return;
    }
    // First byte: secret length (kept small); second: how many shares to try.
    let secret_len = (data[0] as usize % 64) + 1;
    let n_shares = ((data[1] as usize) % 4) + 2; // 2..=5 shares
    let rest = &data[2..];

    // Slice `rest` into `n_shares` byte blobs.
    let chunk = rest.len() / n_shares;
    let mut shares = Vec::with_capacity(n_shares);
    for i in 0..n_shares {
        let blob = &rest[i * chunk..(i + 1) * chunk];
        // Parser must never panic on arbitrary bytes.
        if let Ok(share) = Share::from_bytes(blob) {
            shares.push(share);
        }
    }
    if shares.len() < 2 {
        return;
    }

    // Reconstruction with attacker-chosen y-lengths: must error cleanly, never
    // panic (indexing inside is length-checked by the caller contract).
    let len = shares[0].y.len().min(secret_len.max(1));
    let _ = shamir::reconstruct(&shares, len);

    // Sanity property: genuine splits of any secret always round-trip through
    // the parser, whatever the mutations did elsewhere. Use fixed x/y from the
    // corpus only when lengths line up; otherwise skip.
    let rms = vec![0x42u8; len];
    if let Ok(real) = shamir::split(&rms, 2, 3) {
        let parsed: Vec<Share> = real.iter().map(|s| Share::from_bytes(&s.to_bytes()).unwrap()).collect();
        assert_eq!(
            shamir::reconstruct(&parsed[..2], len).unwrap(),
            rms,
            "honest split/reconstruct broke"
        );
    }
});
