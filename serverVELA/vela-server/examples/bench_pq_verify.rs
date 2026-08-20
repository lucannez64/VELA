//! Microbenchmark: isolate the cost of one hybrid auth-signature verify
//! (ML-DSA-87 + Ed25519) — the dominant compute in POST /auth/verify — plus a
//! hybrid sign, so the HTTP benchmark's per-request cost can be attributed
//! precisely. No server, no DB.

use vela_crypto::signing::{self, HybridSigningKey, HybridVerifyingKey};

fn main() {
    let (vk, sk) = signing::generate_keypair().unwrap();
    let vk_bytes = vk.to_bytes();
    let sk_bytes = sk.to_bytes();

    let device_id = "645f47dd-53bb-46ef-9c96-000000000000";
    let challenge = vec![0x42u8; 32];
    let msg = signing::auth_message(device_id, &challenge);

    let sk_rebuilt = HybridSigningKey::from_bytes(&sk_bytes).unwrap();
    let sig = signing::sign(&sk_rebuilt, &msg).unwrap();
    let sig_bytes = sig.to_bytes();
    let vk_rebuilt = HybridVerifyingKey::from_bytes(&vk_bytes).unwrap();

    let ok = signing::verify(
        &vk_rebuilt,
        &msg,
        &signing::HybridSignature::from_bytes(&sig_bytes).unwrap(),
    )
    .unwrap();
    assert!(ok, "self-check signature must verify");

    let iters = 3000;

    let t0 = std::time::Instant::now();
    for _ in 0..iters {
        let s = signing::sign(&sk_rebuilt, &msg).unwrap();
        std::hint::black_box(s);
    }
    let sign_ms = t0.elapsed().as_secs_f64() * 1000.0 / iters as f64;

    let t0 = std::time::Instant::now();
    for _ in 0..iters {
        let h = signing::HybridSignature::from_bytes(&sig_bytes).unwrap();
        let ok = signing::verify(&vk_rebuilt, &msg, &h).unwrap();
        std::hint::black_box(ok);
    }
    let verify_ms = t0.elapsed().as_secs_f64() * 1000.0 / iters as f64;

    println!("sig bytes: {}  vk bytes: {}", sig_bytes.len(), vk_bytes.len());
    println!("--- per-operation (mean over {iters}) ---");
    println!("hybrid SIGN:   {sign_ms:8.3} ms");
    println!("hybrid VERIFY: {verify_ms:8.3} ms   (ML-DSA-87 + Ed25519; ML-DSA dominates)");
    println!(
        "=> at 12 cores full util, theoretical max verify/s ≈ {:.0}",
        12.0 * 1000.0 / verify_ms
    );
}
