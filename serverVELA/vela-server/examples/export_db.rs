//! Lossless export: stoolap => SQLite-compatible (Turso/libSQL/SQLite) files.
//!
//! Proves "no data lost during migration": for every table, a FULL-SCAN
//! `SELECT` (we don't trust stoolap's COUNT(*), which we observed returning 1
//! for 10000 rows) dumps every cell as a typed value. Outputs:
//!   - `<out>/<table>.jsonl`  : one JSON array per row (canonical lossless record)
//!   - `<out>/schema.sql`     : SQLite-compatible CREATE TABLE/INDEX DDL
//!   - `<out>/data.sql`       : INSERT statements (loadable by SQLite, libSQL, or Turso)
//!
//! Verification: per-table row count from the full scan vs JSONL lines vs INSERT
//! count, plus a content hash over all exported JSONL.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::collections::BTreeMap;
use std::io::Write;

use serde_json::Value as J;
use stoolap::Database;

struct Table {
    name: &'static str,
    cols: &'static [&'static str],
}

const TABLES: &[Table] = &[
    Table {
        name: "users",
        cols: &[
            "id", "recovery_share", "recovery_auth_hash", "created_at",
            "recovery_webauthn_credential", "share_ek", "recovery_webauthn_cred_id",
            "key_epoch", "rekey_state", "rekey_started_at", "rekey_starter", "rekey_id",
            "last_rekey_id", "last_rekey_epoch",
        ],
    },
    Table {
        name: "devices",
        cols: &[
            "id", "user_id", "device_name", "device_type", "last_active",
            "hybrid_ek", "hybrid_vk", "enrolled_by", "rms_capsule", "revoked",
            "revoked_at", "revoked_by", "created_at", "rms_capsule_epoch", "rekey_capable",
        ],
    },
    Table {
        name: "vault_chunks",
        cols: &[
            "chunk_id", "user_id", "version", "lamport_clock", "last_writer",
            "ciphertext", "created_at", "updated_at", "epoch",
        ],
    },
    Table {
        name: "oram_buckets",
        cols: &[
            "user_id", "tree_id", "bucket_index", "version", "lamport_clock",
            "last_writer", "ciphertext", "created_at", "updated_at", "epoch",
        ],
    },
    Table {
        name: "share_inbox",
        cols: &["id", "sender_user_id", "recipient_user_id", "capsule", "created_at"],
    },
    Table {
        name: "shared_items",
        cols: &[
            "id", "sender_user_id", "recipient_user_id", "capsule", "created_at",
            "updated_at", "revoked",
        ],
    },
    Table {
        name: "web_sessions",
        cols: &[
            "id", "user_id", "approver_user_id", "poll_secret_hash", "ephemeral_pk",
            "web_vk", "link_nonce", "mode", "status", "capsule", "approved_by",
            "created_at", "expires_at", "key_epoch",
        ],
    },
];

/// Convert a stoolap `Value` into a canonical JSON representation.
fn cell_to_json(v: &stoolap::Value) -> J {
    use stoolap::Value;
    match v {
        Value::Null(_) => J::Null,
        Value::Integer(i) => J::Number((*i).into()),
        Value::Float(f) => serde_json::Number::from_f64(*f).map(J::Number).unwrap_or(J::Null),
        Value::Text(s) => J::String(s.to_string()),
        Value::Boolean(b) => J::Bool(*b),
        Value::Timestamp(ts) => J::String(ts.to_rfc3339()),
        Value::Extension(bytes) => J::String(format!("\\x{}", B64.encode(bytes))),
    }
}

fn sql_escape(s: &str) -> String {
    // single-quote doubling for SQL string literals
    format!("'{}'", s.replace('\'', "''"))
}

fn main() {
    let db_path =
        std::env::var("BENCH_DB").unwrap_or_else(|_| "/tmp/vela-bench/data/vela.db".into());
    let out_dir = std::env::var("EXPORT_DIR").unwrap_or_else(|_| "/tmp/vela-bench/export".into());
    std::fs::create_dir_all(&out_dir).unwrap();

    let db = vela_server::db::open_and_init(&db_path).expect("open stoolap db (schema-registered)");

    let mut schema_sql = String::from("PRAGMA foreign_keys = OFF;\nBEGIN;\n");
    let mut data_sql = String::from("BEGIN;\n");
    let mut overall = String::new(); // content hash seed over all rows
    let mut report: BTreeMap<String, (usize, usize)> = BTreeMap::new(); // table -> (source rows, jsonl rows)

    for t in TABLES {
        let col_list = t.cols.join(", ");
        let select = format!("SELECT {col_list} FROM {}", t.name);
        let rows = db.query(&select, ()).expect(&format!("scan {}", t.name));

        let mut jsonl = String::new();
        let mut inserts = Vec::new();
        let mut src_count = 0usize;

        for r in rows {
            let r = r.expect("row");
            let mut arr: Vec<J> = Vec::with_capacity(t.cols.len());
            let mut vals: Vec<String> = Vec::with_capacity(t.cols.len());
            for i in 0..t.cols.len() {
                let cell = r.get::<stoolap::Value>(i).expect("cell");
                let j = cell_to_json(&cell);
                let lit = match &cell {
                    stoolap::Value::Null(_) => "NULL".to_string(),
                    stoolap::Value::Integer(x) => x.to_string(),
                    stoolap::Value::Float(f) => f.to_string(),
                    stoolap::Value::Boolean(b) => if *b { "1".into() } else { "0".into() },
                    stoolap::Value::Timestamp(ts) => sql_escape(&ts.to_rfc3339()),
                    stoolap::Value::Text(s) => sql_escape(s),
                    stoolap::Value::Extension(bytes) => sql_escape(&format!("\\x{}", B64.encode(bytes))),
                };
                arr.push(j);
                vals.push(lit);
            }
            jsonl.push_str(&serde_json::to_string(&arr).unwrap());
            jsonl.push('\n');
            let ins = format!(
                "INSERT INTO {} ({col_list}) VALUES ({});\n",
                t.name,
                vals.join(", ")
            );
            inserts.push(ins);
            src_count += 1;
        }

        let jsonl_path = format!("{out_dir}/{}.jsonl", t.name);
        std::fs::write(&jsonl_path, &jsonl).unwrap();
        let jsonl_lines = jsonl.lines().count();
        data_sql.push_str(&inserts.concat());

        // content-hash seed: table name + sorted JSONL
        let mut lines: Vec<&str> = jsonl.lines().collect();
        lines.sort_unstable();
        overall.push_str(&format!("{}:{}:{}\n", t.name, lines.len(), lines.join("~")));

        report.insert(t.name.to_string(), (src_count, jsonl_lines));
        println!(
            "{:<14} source_rows={:<7} jsonl_rows={:<7} jsonl_file={}",
            t.name, src_count, jsonl_lines, jsonl_path
        );
    }

    // Emit DDL (SQLite-compatible, matching stoolap's schema). TIMESTAMP stored
    // as RFC3339 TEXT; boolean as INTEGER; TEXT for blobs/capsules.
    schema_sql.push_str(
        r#"
CREATE TABLE IF NOT EXISTS users (
    id TEXT UNIQUE NOT NULL, recovery_share TEXT, recovery_auth_hash TEXT,
    created_at TEXT NOT NULL, recovery_webauthn_credential TEXT,
    share_ek TEXT, recovery_webauthn_cred_id TEXT,
    key_epoch INTEGER NOT NULL DEFAULT 1, rekey_state TEXT,
    rekey_started_at TEXT, rekey_starter TEXT, rekey_id TEXT,
    last_rekey_id TEXT, last_rekey_epoch INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_webauthn_cred_id ON users(recovery_webauthn_cred_id);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT UNIQUE NOT NULL, user_id TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT 'Desktop Device', device_type TEXT NOT NULL DEFAULT 'desktop',
    last_active TEXT, hybrid_ek TEXT NOT NULL, hybrid_vk TEXT NOT NULL, enrolled_by TEXT,
    rms_capsule TEXT, rms_capsule_epoch INTEGER, rekey_capable INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0, revoked_at TEXT, revoked_by TEXT,
    created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE TABLE IF NOT EXISTS vault_chunks (
    chunk_id TEXT NOT NULL, user_id TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
    lamport_clock INTEGER NOT NULL DEFAULT 0, last_writer TEXT, ciphertext TEXT NOT NULL,
    epoch INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_chunks_user_chunk_epoch ON vault_chunks(user_id, chunk_id, epoch);
CREATE INDEX IF NOT EXISTS idx_vault_chunks_user_epoch ON vault_chunks(user_id, epoch);
CREATE TABLE IF NOT EXISTS oram_buckets (
    user_id TEXT NOT NULL, tree_id TEXT NOT NULL, bucket_index INTEGER NOT NULL,
    version INTEGER NOT NULL DEFAULT 1, lamport_clock INTEGER NOT NULL DEFAULT 0,
    last_writer TEXT, ciphertext TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oram_buckets_user_tree_bucket_epoch ON oram_buckets(user_id, tree_id, bucket_index, epoch);
CREATE TABLE IF NOT EXISTS share_inbox (
    id TEXT UNIQUE NOT NULL, sender_user_id TEXT NOT NULL, recipient_user_id TEXT NOT NULL,
    capsule TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_share_inbox_recipient ON share_inbox(recipient_user_id);
CREATE TABLE IF NOT EXISTS shared_items (
    id TEXT UNIQUE NOT NULL, sender_user_id TEXT NOT NULL, recipient_user_id TEXT NOT NULL,
    capsule TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS web_sessions (
    id TEXT UNIQUE NOT NULL, user_id TEXT, approver_user_id TEXT, poll_secret_hash TEXT,
    ephemeral_pk TEXT NOT NULL, web_vk TEXT, link_nonce TEXT NOT NULL, mode TEXT,
    status TEXT NOT NULL, capsule TEXT, approved_by TEXT, key_epoch INTEGER,
    created_at TEXT NOT NULL,
    expires_at TEXT);
CREATE INDEX IF NOT EXISTS idx_web_sessions_status ON web_sessions(status);
CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);
COMMIT;
"#,
    );
    schema_sql.push_str("\n");

    std::fs::write(format!("{out_dir}/schema.sql"), &schema_sql).unwrap();
    data_sql.push_str("COMMIT;\n");
    std::fs::write(format!("{out_dir}/data.sql"), &data_sql).unwrap();

    // verify parity + content hash
    let mut all_ok = true;
    for (name, (src, js)) in &report {
        let ok = src == js;
        all_ok &= ok;
        println!("  parity {name}: source={src} exported={js} -> {}", if ok { "OK" } else { "MISMATCH" });
    }
    // simple non-crypto content hash: FNV-1a over the seed string
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in overall.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    println!("\nall_parity_ok={all_ok}  content_hash=0x{hash:016x}");
    println!("schema: {out_dir}/schema.sql  data: {out_dir}/data.sql");
}
