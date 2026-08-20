//! Spike: validate the `turso` crate can handle VELA's schema + query patterns
//! before committing to the runtime migration. Loads the lossless export
//! (schema.sql + data.sql) into a local Turso DB and runs the server's exact
//! SQL patterns (SELECT-by-PK w/ param, UPDATE last_active, aggregate).

use clap::Parser;
use turso::Builder;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "/tmp/opencode/vela-export/schema.sql")]
    schema: String,
    #[arg(long, default_value = "/tmp/opencode/vela-export/data.sql")]
    data: String,
    #[arg(long, default_value = "/tmp/opencode/vela-spike/sample.db")]
    db: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let _ = std::fs::remove_file(&args.db);
    std::fs::create_dir_all(
        std::path::Path::new(&args.db)
            .parent()
            .unwrap_or(std::path::Path::new(".")),
    )
    .ok();

    let db = Builder::new_local(&args.db).build().await?;
    let conn = db.connect()?;

    // Load schema + data via turso's native execute_batch.
    let schema_sql = std::fs::read_to_string(&args.schema)?;
    let data_sql = std::fs::read_to_string(&args.data)?;
    conn.execute_batch(&schema_sql).await?;
    println!("schema loaded");
    conn.execute_batch(&data_sql).await?;
    println!("data loaded");

    for t in ["users", "devices", "vault_chunks"] {
        let n: i64 = conn
            .query(&format!("SELECT COUNT(*) FROM {t}"), ())
            .await?
            .next()
            .await?
            .expect("row")
            .get(0)?;
        println!("table {t:>14}: rows={n}");
    }

    // SELECT-by-PK with param (verify path), revoked=0.
    let row = conn
        .query("SELECT id FROM devices LIMIT 1", ())
        .await?
        .next()
        .await?
        .expect("a device");
    let dev_id: String = row.get(0)?;
    let n: i64 = conn
        .query(
            "SELECT COUNT(*) FROM devices WHERE id = ? AND revoked = 0",
            turso::params![dev_id.clone()],
        )
        .await?
        .next()
        .await?
        .expect("count")
        .get(0)?;
    println!("PK lookup device: count={n} (expect 1)");

    // UPDATE last_active (write path).
    let now = chrono::Utc::now().to_rfc3339();
    let upd = conn
        .execute(
            "UPDATE devices SET last_active = ? WHERE id = ?",
            turso::params![now.clone(), dev_id.clone()],
        )
        .await?;
    println!("UPDATE last_active affected: {upd}");

    // Aggregate pattern (share inbox): COALESCE(SUM(LENGTH(capsule))).
    let s: i64 = conn
        .query(
            "SELECT COALESCE(SUM(LENGTH(capsule)),0) FROM share_inbox \
             WHERE recipient_user_id = ?",
            turso::params!["00000000-0000-0000-0000-000000000000"],
        )
        .await?
        .next()
        .await?
        .expect("agg")
        .get(0)?;
    println!("share_inbox SUM(LENGTH) (empty -> 0): {s}");

    println!("SPIKE OK");
    Ok(())
}
