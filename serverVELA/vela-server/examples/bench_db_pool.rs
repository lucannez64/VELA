//! Probe lever (2): does cloning the stoolap `Database` handle into a pool of
//! executors remove the global `Mutex<Executor>` serialization that caps
//! /auth/verify throughput?
//!
//! Opens the SEEDED 10k-device DB, builds a pool of N cloned handles (each with
//! its own executor mutex, sharing the same MVCCEngine), and hammers the exact
//! verify SELECT (`WHERE id = $1 AND revoked = FALSE`) concurrently across the
//! pool. Reports achieved queries/s and compares against the single-handle
//! baseline.
//!
//! This isolates the executor-lock ceiling WITHOUT the PQ verify, the HTTP
//! layer, or the sled rate-limit — pure SQL-path parallelism.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Instant;

use stoolap::Database;

fn main() {
    let db_path = std::env::var("BENCH_DB").unwrap_or_else(|_| "/tmp/vela-bench/data/vela.db".into());
    let base = Database::open(&format!("file://{db_path}")).expect("open seeded db");

    // Collect 10k real device ids to query (PK lookups like the real server).
    let ids: Vec<String> = {
        let rows = base
            .query("SELECT id FROM devices LIMIT 10000", ())
            .expect("select ids");
        rows.filter_map(|r| r.ok().and_then(|row| row.get::<String>(0).ok()))
            .collect()
    };
    println!("queried {} device ids from seeded DB", ids.len());
    let ids = Arc::new(ids);

    let run = |pool_size: usize, threads: usize, iters: u64| {
        // Build a pool of cloned handles. Clone() creates a fresh Executor with
        // its own Mutex<Executor> but shares the same MVCCEngine.
        let pool: Vec<Database> = (0..pool_size).map(|_| base.clone()).collect();
        let pool = Arc::new(pool);
        let done = Arc::new(AtomicU64::new(0));
        let t0 = Instant::now();

        let handlers: Vec<_> = (0..threads)
            .map(|ti| {
                let pool = Arc::clone(&pool);
                let ids = Arc::clone(&ids);
                let done = Arc::clone(&done);
                thread::spawn(move || {
                    let mut local = 0u64;
                    for i in 0..iters {
                        let h = &pool[(ti + i as usize) % pool.len()];
                        let _ = h.query(
                            "SELECT id, user_id, device_name, device_type, last_active, \
                             hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, revoked, \
                             revoked_at, revoked_by, created_at \
                             FROM devices WHERE id = $1 AND revoked = FALSE",
                            stoolap::params![ids[(i as usize) % ids.len()].clone()],
                        );
                        local += 1;
                    }
                    done.fetch_add(local, Ordering::Relaxed);
                })
            })
            .collect();
        for h in handlers {
            h.join().unwrap();
        }
        let el = t0.elapsed().as_secs_f64();
        let total = done.load(Ordering::Relaxed);
        (total as f64 / el, el)
    };

    println!("\n=== concurrent SELECT (verify query) vs executor-pool size ===");
    println!("{:>4} {:>4} {:>10} {:>8}", "pool", "thr", "q/s", "sec");
    for &pool in &[1usize, 2, 4, 8, 12, 16, 24] {
        let (qs, el) = run(pool, pool, 20_000);
        println!("{:>4} {:>4} {:>10.0} {:>8.2}", pool, pool, qs, el);
    }
}
