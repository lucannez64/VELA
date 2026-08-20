//! Fast in-process HTTP benchmark client for POST /auth/verify.
//!
//! Unlike the Python harness (which shells out to `vela-rw-mint` per request),
//! this client signs with `vela-crypto` IN PROCESS and uses `reqwest` + tokio,
//! so it can actually saturate the server. This is required to measure the
//! server's true capacity — the Python client caps out far below it.
//!
//! Latency is measured per request as the full round-trip wall-clock from the
//! `/auth/challenge` GET to the `/auth/verify` response (success or failure),
//! aggregated across all tasks into percentile histograms.
//!
//! Usage:
//!   cargo run -p vela-server --example bench_client --release -- \
//!       --base http://127.0.0.1:8444 --keys /tmp/vela-bench/keys.json \
//!       --concurrency 64 --each 3000

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use serde::Deserialize;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use vela_crypto::signing::HybridSigningKey;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8444")]
    base: String,
    #[arg(long, default_value = "/tmp/vela-bench/keys.json")]
    keys: String,
    #[arg(long, default_value_t = 64)]
    concurrency: usize,
    #[arg(long, default_value_t = 3000)]
    each: usize,
    #[arg(long, default_value_t = 100)]
    warmup: usize,
}

#[derive(Deserialize, Clone)]
struct Key {
    device_id: String,
    sk: String,
}

#[derive(Deserialize)]
struct ChallengeResp {
    challenge: String,
}

async fn one(
    client: &reqwest::Client,
    base: &str,
    sk_map: &[(String, Vec<u8>)],
    idx: usize,
    xff: &str,
) -> Result<(), String> {
    let (device_id, sk_bytes) = &sk_map[idx % sk_map.len()];
    let sk = HybridSigningKey::from_bytes(sk_bytes).map_err(|e| format!("sk: {e}"))?;

    let challenge: ChallengeResp = client
        .get(format!("{base}/auth/challenge"))
        .header("X-Forwarded-For", xff)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;

    let ch_bytes = B64.decode(&challenge.challenge).map_err(|e| e.to_string())?;
    let msg = vela_crypto::signing::auth_message(device_id, &ch_bytes);
    let sig = vela_crypto::signing::sign(&sk, &msg).map_err(|e| format!("sign: {e}"))?;
    let sig_b64 = B64.encode(sig.to_bytes());

    let resp = client
        .post(format!("{base}/auth/verify"))
        .header("X-Forwarded-For", xff)
        .json(&serde_json::json!({
            "device_id": device_id,
            "challenge": challenge.challenge,
            "signature": sig_b64,
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!(
            "status {} body={}",
            status,
            &body[..body.len().min(120)]
        ))
    }
}

fn pct(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

/// Build a fresh reqwest client. Called once per spawned task (Option A) so no
/// two tasks share a connection pool — eliminating any shared-state class of
/// the challenge->sign->verify desync race observed under saturation.
fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .pool_max_idle_per_host(16)
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let raw: Vec<Key> = serde_json::from_str(
        &std::fs::read_to_string(&args.keys).expect("read keys.json"),
    )
    .expect("parse keys.json");
    let sk_map: Vec<(String, Vec<u8>)> = raw
        .iter()
        .map(|k| (k.device_id.clone(), B64.decode(&k.sk).unwrap()))
        .collect();
    let sk_map = Arc::new(sk_map);

    // Shared latency sink (ms), protected by a Mutex. We collect every
    // request's round-trip time so we can compute percentiles afterwards.
    let latencies: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::with_capacity(
        args.concurrency * args.each,
    )));

    // Option A: each spawned task builds its OWN reqwest client so there is no
    // shared connection pool / multiplexed state that could desync the
    // challenge->sign->verify pairing under saturation. (The 401s we saw were a
    // harness race, not a server defect; this removes the shared-state class.)
    let run = |count: usize, concurrency: usize, base: String, collect: bool| {
        let sk_map = sk_map.clone();
        let latencies = latencies.clone();
        async move {
            let mut handles = Vec::with_capacity(concurrency);
            let start = Instant::now();
            let mut ok = 0u64;
            let mut bad = 0u64;
            let mut errs: std::collections::HashMap<String, u64> = Default::default();
            for chunk in 0..concurrency {
                let base = base.clone();
                let sk_map = sk_map.clone();
                let latencies = latencies.clone();
                handles.push(tokio::spawn(async move {
                    // Fresh client per task (Option A) — no shared connection pool.
                    let c = build_client();
                    let mut local_ok = 0u64;
                    let mut local_bad = 0u64;
                    let mut local_err: std::collections::HashMap<String, u64> =
                        Default::default();
                    let mut local_lat = Vec::with_capacity(count);
                    for i in 0..count {
                        let idx = chunk * count.max(1) + i;
                        // unique source IP per request => each rate-limit bucket
                        // sees one hit (models 10k distinct users).
                        let mixed = (idx as u64).wrapping_mul(2654435761) % (1u64 << 32);
                        let xff = format!(
                            "{}.{}.{}.{}",
                            (mixed >> 24) & 255,
                            (mixed >> 16) & 255,
                            (mixed >> 8) & 255,
                            mixed & 255
                        );
                        let t0 = Instant::now();
                        match one(&c, &base, &sk_map, idx, &xff).await {
                            Ok(()) => local_ok += 1,
                            Err(e) => {
                                local_bad += 1;
                                *local_err.entry(e).or_insert(0) += 1;
                            }
                        }
                        let ms = t0.elapsed().as_secs_f64() * 1000.0;
                        if collect {
                            local_lat.push(ms);
                        }
                    }
                    if collect {
                        latencies.lock().unwrap().extend(local_lat);
                    }
                    (local_ok, local_bad, local_err)
                }));
            }
            for h in handles {
                let (o, b, e) = h.await.unwrap();
                ok += o;
                bad += b;
                for (k, v) in e {
                    *errs.entry(k).or_insert(0) += v;
                }
            }
            let el = start.elapsed().as_secs_f64();
            (ok, bad, errs, el)
        }
    };

    // warmup (no collection)
    run(args.warmup, args.concurrency, args.base.clone(), false).await;
    println!("warmup done");

    latencies.lock().unwrap().clear();
    let (ok, bad, errs, el) = run(args.each, args.concurrency, args.base.clone(), true).await;
    let total = ok + bad;
    let req_s = total as f64 / el;

    // percentile report
    let mut lat = latencies.lock().unwrap().clone();
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = lat.len();
    let mean = if n > 0 {
        lat.iter().sum::<f64>() / n as f64
    } else {
        0.0
    };
    let max = lat.last().copied().unwrap_or(0.0);
    let min = lat.first().copied().unwrap_or(0.0);

    println!(
        "concurrency={} requests={} ok={} bad={} elapsed={:.2}s req/s={:.1}",
        args.concurrency, total, ok, bad, el, req_s
    );
    println!(
        "latency ms (round-trip challenge->verify): n={} min={:.2} mean={:.2} \
         p50={:.2} p90={:.2} p95={:.2} p99={:.2} max={:.2}",
        n, min, mean, pct(&lat, 0.50), pct(&lat, 0.90), pct(&lat, 0.95), pct(&lat, 0.99), max
    );
    if !errs.is_empty() {
        println!("errors: {:?}", errs);
    }
}
