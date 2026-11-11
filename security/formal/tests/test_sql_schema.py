"""Regression tests for the rendered-SQL/schema guard.

The first test is the real repository: every pinned statement must match the
schema parsed from db.rs.  The rest are mutants: a renamed column, a dropped
table, an INSERT missing a placeholder, and an UPDATE with its guard removed
must each be rejected.
"""
import copy
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
GUARD_PATH = HERE.parents[1] / "check-sql-schema.py"
spec = importlib.util.spec_from_file_location("sql_schema_guard", GUARD_PATH)
guard = importlib.util.module_from_spec(spec)
# Python 3.14's dataclasses looks the module up by name while the module body
# executes, so register it first.
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


class SqlSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = guard.parse_schema()
        cls.policy, cls.raw = guard.collect_statements()
        cls.statements = cls.policy + cls.raw

    def statement(self, needle):
        return next(s for s in self.statements if needle in s.sql)

    def test_real_repository_matches_the_schema(self):
        _, _, findings = guard.check_repo()
        self.assertEqual(findings, [])

    def test_real_repository_is_actually_covered(self):
        self.assertTrue(self.policy)
        self.assertTrue(self.raw)
        groups = {guard.group_of(s.path) for s in self.statements}
        for crate in (
            "vela-enrollment-policy",
            "vela-recovery-policy",
            "vela-rekey-policy",
            "vela-session-policy",
            "vela-share-policy",
        ):
            self.assertIn(crate, groups)
        self.assertIn("vela-server (raw handler SQL)", groups)
        for table in ("users", "devices", "vault_chunks", "oram_buckets",
                      "share_inbox", "shared_items", "web_sessions", "sends"):
            self.assertIn(table, self.schema.tables)

    def test_alter_and_rebuild_migrations_are_applied(self):
        # Columns added by ALTER, and the rebuilt *_v2 tables, must be present.
        self.assertIn("share_ek", self.schema.tables["users"].columns)
        self.assertIn("rekey_state", self.schema.tables["users"].columns)
        self.assertIn("enrollment_grant_id", self.schema.tables["devices"].columns)
        self.assertIn("recovery_grant_id", self.schema.tables["devices"].columns)
        self.assertIn("epoch", self.schema.tables["vault_chunks"].columns)
        self.assertNotIn("vault_chunks_v2", self.schema.tables)
        self.assertNotIn("devices_v2", self.schema.tables)

    def test_renamed_column_fails(self):
        original = self.statement("SELECT sender_user_id, revoked FROM shared_items")
        mutated = guard.Statement(
            original.path,
            original.line,
            original.sql.replace("sender_user_id", "sender_user", 1),
        )
        findings = guard.check_statement(self.schema, mutated)
        self.assertTrue(
            any("no column" in finding.message for finding in findings),
            findings,
        )

    def test_dropped_table_fails(self):
        schema = copy.deepcopy(self.schema)
        del schema.tables["sends"]
        original = self.statement("DELETE FROM sends WHERE id = ?")
        findings = guard.check_statement(schema, original)
        self.assertTrue(
            any("no table sends" in finding.message for finding in findings),
            findings,
        )

    def test_insert_with_a_missing_placeholder_fails(self):
        original = self.statement("INSERT INTO share_inbox")
        head, values = original.sql.split("VALUES", 1)
        mutated = guard.Statement(
            original.path,
            original.line,
            head + "VALUES" + values.replace("?, ", "", 1),
        )
        findings = guard.check_statement(self.schema, mutated)
        self.assertTrue(
            any("value expressions" in finding.message for finding in findings),
            findings,
        )

    def test_unguarded_update_fails(self):
        original = next(
            s
            for s in self.statements
            if s.sql.startswith("UPDATE users")
            and "recovery_pending_share" in s.sql
            and "WHERE" in s.sql
        )
        head, _ = original.sql.split("WHERE", 1)
        mutated = guard.Statement(original.path, original.line, head)
        findings = guard.check_statement(self.schema, mutated)
        self.assertTrue(
            any("has no WHERE clause" in finding.message for finding in findings),
            findings,
        )

    def test_comment_sql_and_labels_are_not_statements(self):
        text = '''
// "SELECT nope FROM nowhere"
/* "DELETE FROM nowhere" */
/// "UPDATE nowhere SET x = 1"
let label = "update";
fn f() { let sql = "SELECT id FROM users WHERE id = ?"; }
'''
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.rs"
            path.write_text(text)
            statements = guard.sql_literals(path, keep_test_modules=True)
        self.assertEqual([s.sql for s in statements],
                         ["SELECT id FROM users WHERE id = ?"])


if __name__ == "__main__":
    unittest.main()
