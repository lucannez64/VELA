//! Benchmark seeder: create N genuine device identities in a fresh stoolap DB
//! and emit a `keys.json` the Python benchmark can drive.
//!
//! Each device gets a real hybrid ML-DSA-87 + Ed25519 keypair. `hybrid_vk` is
//! stored in the DB (base64) exactly as the running server expects, and the
//! signing key is written to `keys.json` so the benchmark can produce genuine
//! per-request authentication signatures via `vela-rw-mint`'s `sign` path.
//!
//! Run:
//!   cargo run -p vela-server --example seed_devices -- \
//!       --db /tmp/vela-bench/data/vela.db \
//!       --count 10000 --out /tmp/vela-bench/keys.json
//!
//! The DB path must match what the benchmark server is started with (DB_PATH /
//! SLED_PATH). The same `data` dir also needs to exist for sled; pass
//! `--sled` to control it (defaults to `<db dir>/../sled`).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use serde::Serialize;
use uuid::Uuid;
use vela_crypto::signing::{self, HybridSigningKey, HybridVerifyingKey};

#[derive(Parser)]
#[command(about = "Seed N device identities for the /auth/verify benchmark")]
struct Args {
    /// stoolap DB path the benchmark server will open.
    #[arg(long, default_value = "/tmp/vela-bench/data/vela.db")]
    db: String,
    /// Number of device rows to create.
    #[arg(long, default_value_t = 10_000)]
    count: usize,
    /// Output path for keys.json (device_id -> {vk, sk}).
    #[arg(long, default_value = "/tmp/vela-bench/keys.json")]
    out: String,
}

#[derive(Serialize)]
struct DeviceKey {
    device_id: String,
    user_id: String,
    vk: String,
    sk: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Parent dir so sled (sibling of the db file) and the db file both exist.
    if let Some(parent) = std::path::Path::new(&args.db).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let db = vela_server::db::open_and_init(&args.db)?;
    let now = chrono::Utc::now().to_rfc3339();

    let mut keys: Vec<DeviceKey> = Vec::with_capacity(args.count);
    let total = args.count;

    // ML-DSA-87 keygen is the expensive part; do it inline and insert per row.
    // stoolap is a single embedded file, so inserts are serialized anyway.
    for n in 1..=total {
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let (vk, sk): (HybridVerifyingKey, HybridSigningKey) = signing::generate_keypair()?;
        let vk_bytes = vk.to_bytes().to_vec();
        let sk_bytes = sk.to_bytes();

        db.execute(
            "INSERT INTO devices (id, user_id, device_name, device_type, last_active, \
             hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, revoked, created_at) \
             VALUES ($1, $2, $3, $4, NULL, $5, $6, NULL, NULL, FALSE, $7)",
            stoolap::params![
                device_id.to_string(),
                user_id.to_string(),
                "Benchmark Device".to_string(),
                "desktop".to_string(),
                B64.encode(vec![0u8; 32]), // dummy hybrid_ek (NOT NULL in schema)
                B64.encode(&vk_bytes),
                now.clone(),
            ],
        )
        .map_err(|e| anyhow::anyhow!("insert failed for {device_id}: {e}"))?;

        keys.push(DeviceKey {
            device_id: device_id.to_string(),
            user_id: user_id.to_string(),
            vk: B64.encode(&vk_bytes),
            sk: B64.encode(&sk_bytes),
        });

        if n % 1000 == 0 || n == total {
            eprintln!("seeded {n}/{total}");
        }
    }

    let json = serde_json::to_string_pretty(&keys)?;
    std::fs::write(&args.out, json)?;
    eprintln!(
        "done: {} devices written to {}",
        keys.len(),
        args.out
    );
    Ok(())
}
