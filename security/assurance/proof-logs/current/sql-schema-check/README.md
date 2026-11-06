# Schema check for every rendered SQL statement (plan step O2)

## Claim

Every SQL statement the server can send is checked against the schema it runs
on. `security/formal/check-sql-schema.py` parses the schema definitions and
every pinned SQL literal, then fails on a missing table or column, on an
INSERT whose column list and value expressions disagree, or on an UPDATE/DELETE
without a WHERE clause. It also pins the sharing store model's columns and
declarations, replacing the F-1 pilot's Rust column test, and compares the two
schema definitions the server carries.

The real repository passes. The checker found no statement/schema mismatch in
the current code.

## Where the schema actually comes from

- **Served schema:** `serverVELA/vela-server/src/sqldb.rs` (`SCHEMA`,
  `backfill_rekey_columns`, `REKEY_INDEXES`). `main.rs:199-215` opens the
  legacy stoolap database only for the one-time bootstrap; handlers run on
  `TursoDb`, which executes `SCHEMA` then the backfill `ALTER`s then
  `REKEY_INDEXES` (`sqldb.rs:109-135`). This is the schema every conformance
  test uses (`TursoDb::open_temp`).
- **Legacy schema:** `serverVELA/vela-server/src/db.rs` plus
  `migration.rs`. `db.rs` still holds the stoolap `CREATE TABLE`/`ALTER
  TABLE`/`CREATE INDEX` statements and the `vault_chunks_v2`/`devices_v2`
  rebuilds; `migration.rs` has no DDL.

The task brief named `db.rs`/`migration.rs` as the real schema. That is stale:
the served schema is `sqldb.rs`. The checker parses **both**, checks every
rendered statement against the turso schema, and compares the two definitions
column by column.

## Schema model

Both definitions produce the same 8 tables and 95 columns:

`users` 21, `devices` 17, `vault_chunks` 9, `oram_buckets` 10, `share_inbox` 5,
`shared_items` 7, `web_sessions` 14, `sends` 12.

The parser keeps each column's declared type, NOT NULL, UNIQUE, PRIMARY KEY and
DEFAULT, applies `ALTER TABLE ... ADD COLUMN` and `ALTER TABLE ... RENAME TO`,
and follows the `*_v2` rebuilds. Declarations are compared after the engine
affinity normalisation the pilot test relied on: `BOOLEAN` → `INTEGER`,
`TIMESTAMP` → `TEXT`, `FALSE`/`TRUE` → `0`/`1`.

The turso definition yields 12 final indexes; the stoolap parser sees 18 index
statements because `db.rs` also contains legacy indexes that the startup
migrations drop (`idx_vault_chunks_user_chunk`, the pre-epoch ORAM index, and
their rebuild duplicates). The 18-vs-12 difference is index history, not a
schema mismatch; every index statement is checked against its own definition.

## Coverage

243 SQL literals, 123 unique after whitespace normalisation. Literals outnumber
unique statements because each renderer is pinned again by unit tests.

| Source | Literals | Unique | Kinds |
|---|---:|---:|---|
| `vela-enrollment-policy` | 12 | 6 | INSERT 4, SELECT 8 |
| `vela-recovery-policy` | 42 | 21 | INSERT 4, SELECT 25, UPDATE 13 |
| `vela-rekey-policy` | 73 | 37 | DELETE 8, INSERT 6, SELECT 38, UPDATE 21 |
| `vela-session-policy` | 61 | 30 | DELETE 22, INSERT 6, SELECT 18, UPDATE 15 |
| `vela-share-policy` | 52 | 26 | DELETE 12, INSERT 6, SELECT 26, UPDATE 8 |
| `vela-server` raw handler SQL | 3 | 3 | SELECT 3 |
| **Total** | **243** | **123** | |

The three raw handler statements are exactly the ones H1 lists outside plans
(`handler-inventory/README.md`, findings 2 and 6): `middleware.rs:137`
(`SELECT key_epoch FROM users WHERE id = ?`), `middleware.rs:173`
(`SELECT id FROM devices WHERE id = ? AND user_id = ? AND revoked = 0`) and
`routes.rs:395` (`SELECT 1`, the `/health` probe).

## What is checked

- Every table and column named by every pinned statement exists in the turso
  schema.
- Table aliases (`FROM devices d`, `FROM vault_chunks t`), qualified columns
  (`d.hybrid_vk`, `u.share_ek_since`) and SQLite's `excluded` upsert pseudo-table
  resolve to the right table.
- Each `INSERT` column list matches the number of `VALUES` expressions, and
  every INSERT column exists.
- Every `UPDATE` and every `DELETE` has a WHERE clause.
- Index targets and indexed columns exist in both schema definitions.
- The sharing model's columns and declarations match `PILOT_COLUMNS`, the same
  declarations the removed Rust test asserted; `id` is UNIQUE/PRIMARY KEY.
- The stoolap and turso definitions agree on every table, column and normalised
  declaration.

## What is not checked

This is a light static tokenizer, not a SQL parser or a soundness proof.

- SQL semantics, result shapes, row decoding, parameter types or order, the
  Rust `params` vector's length, transactions and concurrency.
- Value types, NULLability of bound values, constraints beyond column
  existence, foreign keys, index selectivity, or whether an inserted key is
  fresh. The runtime duplicate-key assertion stays in Rust
  (`share/conformance.rs::model_tables_reject_duplicate_ids`).
- Correlated-subquery scoping: a column is accepted if it exists in any table
  the statement mentions, and a qualifier is accepted if it names any mentioned
  table/alias. A column that exists on the wrong one of two joined tables would
  not be flagged.
- Whether a WHERE clause is the *right* guard, only that one exists.
- Dynamic SQL (`format!`) such as the stoolap→turso bootstrap in
  `db.rs:889-930`, the legacy stoolap CRUD helpers in `db.rs`/`sqldb.rs`, test
  helpers, migration `INSERT ... SELECT` copying, and the engine's exact stored
  DDL (the pilot test queried `sqlite_master`; this check parses source DDL).

## Sharing pilot replacement

`schema_has_the_modelled_columns` in
`serverVELA/vela-server/src/share/conformance.rs` asserted the sharing model's
columns against `sqlite_master` at runtime. Its column and declaration
assertions now live here as `PILOT_COLUMNS`, so there is one schema check for
SQL. The Rust test became
`model_tables_reject_duplicate_ids`, which keeps the runtime half the static
check cannot perform: `share_inbox` must reject a duplicate id.

## Tests

`security/formal/tests/test_sql_schema.py`:

| Test | Expectation |
|---|---|
| real repository | no findings |
| coverage | all five policy crates and the raw handler source are present; all 8 tables parsed |
| migrations | ALTER columns and both `*_v2` rebuilds are applied |
| renamed column | a real `shared_items` statement with `sender_user_id` → `sender_user` fails |
| dropped table | deleting `sends` from the schema makes a real `DELETE FROM sends` fail |
| missing placeholder | a real `share_inbox` INSERT with one `?` removed fails the value count |
| unguarded UPDATE | a real `users` UPDATE with its WHERE removed fails |
| comments/labels | SQL in comments and the bare label `"update"` are not statements |

## Findings

1. **No SQL/schema mismatch.** Every statement matches the turso schema. No
   code was changed to make the check pass.
2. **The brief's schema location is stale (documentation finding).** The served
   schema is `sqldb.rs`, not `db.rs`; `main.rs:199-215` labels `db.rs` the
   legacy stoolap database. Both definitions were parsed; after the engine's
   type-affinity normalisation they agree on all 8 tables and 95 columns. No
   drift was found, but future edits must keep both in step, and the check now
   enforces that.
3. **Raw SQL is limited to the three H1-listed statements.** They match. The
   bootstrap/legacy dynamic SQL is outside plans and outside this check; H1
   already records that the only raw *handler* SQL is the auth extractor and
   `/health`.

## Reproduction

```bash
python3 -I security/formal/check-sql-schema.py
python3 -I -m unittest discover -s security/formal/tests -p 'test_sql_schema.py' -v
```

CI runs both in the existing `formal-rekey` job, immediately after "Check no
tracked F* file contains a proof escape".

## Verification run

```text
python3 -I security/formal/check-sql-schema.py            -> OK, 243 literals / 123 unique
python3 -I -m unittest ... -p 'test_sql_schema.py' -v      -> 8 tests, OK
python3 -I -m unittest discover -s security/formal/tests    -> 73 tests, OK
vela-heavy cargo test -p vela-server --lib \
  share::conformance::model_tables_reject_duplicate_ids    -> 1 passed
```

## Unverified

- The parser's treatment of a future migration it has not seen (for example a
  new rebuild table or a different baseline) is unverified beyond the current
  files.
- Only the renamed sharing test was run under cargo; the rest of the sharing
  conformance suite was not re-run (it is unchanged apart from the removed
  column assertions).
