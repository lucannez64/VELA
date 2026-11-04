#!/usr/bin/env python3
"""Check every pinned server SQL statement against the schema it runs on.

The server's executors render byte-pinned SQL from typed plans, and some
handlers still run raw SQL.  This guard statically:

  * parses the real schema from ``serverVELA/vela-server/src/db.rs`` (the
    ``CREATE TABLE``/``CREATE INDEX`` statements, ``ALTER TABLE ... ADD
    COLUMN`` migrations, and the two table-rebuild migrations), and
  * extracts every SQL string literal from the policy crates and from the two
    raw-SQL handler sites named by the H1 handler inventory
    (``middleware.rs`` and ``routes.rs``), and
  * checks that every referenced table and column exists, that each INSERT's
    column list matches its value expressions, and that every UPDATE/DELETE
    carries a WHERE clause.

It also pins the columns the sharing store model (the F-1 pilot) relies on,
with the declarations the pilot's Rust schema test used to assert.

This is a light static tokenizer, not a SQL parser or a soundness proof.  It
does not check:

  * SQL semantics, result shapes, row decoding, parameter types, parameter
    order, the length of the Rust ``params`` vector, or transaction handling;
  * constraints beyond column existence (types of expressions, NULLability of
    values, foreign keys, index selectivity, uniqueness of inserted rows);
  * correlated-subquery scoping: a column is accepted if it exists in *any*
    table the statement mentions, and a qualifier is accepted if it names any
    mentioned table or alias;
  * dynamic SQL built with ``format!``, the legacy stoolap bootstrap SQL in
    ``db.rs``/``sqldb.rs``, migration ``INSERT ... SELECT`` copying, or test
    helpers under ``#[cfg(test)]`` in ``vela-server``;
  * whether a WHERE clause is the *right* guard, only that one exists;
  * the runtime DDL the engine stores (the pilot test queried
    ``sqlite_master``; this check parses the source DDL instead).

Usage: python3 -I security/formal/check-sql-schema.py
Exit status 0 when every statement matches, 1 with findings otherwise.
"""

from __future__ import annotations

import re
import sys
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# `db.rs` is the legacy stoolap schema; `sqldb.rs` is the turso schema the
# running server and every conformance test actually use.  Both are parsed and
# compared, and every rendered statement is checked against the turso schema.
STOOLAP_SCHEMA_SOURCES = (
    ROOT / "serverVELA/vela-server/src/db.rs",
    ROOT / "serverVELA/vela-server/src/migration.rs",
)
TURSO_SCHEMA_SOURCES = (ROOT / "serverVELA/vela-server/src/sqldb.rs",)
POLICY_GLOB = "vela-*-policy"
RAW_SQL_SOURCES = (
    ROOT / "serverVELA/vela-server/src/middleware.rs",
    ROOT / "serverVELA/vela-server/src/routes.rs",
)

SQL_STARTS = {"SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "REPLACE"}
DDL_STARTS = {"CREATE", "ALTER", "DROP"}

KEYWORDS = {
    "ALL", "AND", "AS", "ASC", "BETWEEN", "BY", "CASE", "COLLATE", "CROSS",
    "CURRENT_DATE", "CURRENT_TIME", "CURRENT_TIMESTAMP", "DESC", "DISTINCT",
    "ELSE", "END", "ESCAPE", "EXCEPT", "EXISTS", "FALSE", "FROM", "FULL",
    "GLOB", "GROUP", "HAVING", "IN", "INNER", "INSERT", "INTERSECT", "INTO",
    "IS", "ISNULL", "JOIN", "LEFT", "LIKE", "LIMIT", "NATURAL", "NOT",
    "NOTNULL", "NULL", "OFFSET", "ON", "OR", "ORDER", "OUTER", "RIGHT",
    "SELECT", "SET", "THEN", "TRUE", "UNION", "UPDATE", "USING", "VALUES",
    "WHEN", "WHERE", "WITH", "DELETE", "DO", "CONFLICT", "RETURNING",
}

# Declarations the F-1 sharing store model uses.  These mirror
# `schema_has_the_modelled_columns` in vela-server/src/share/conformance.rs,
# whose column checks this script replaced (the Rust test keeps only its
# runtime duplicate-key assertion).
PILOT_COLUMNS = OrderedDict(
    (
        (
            "shared_items",
            (
                ("id", "TEXT UNIQUE NOT NULL"),
                ("sender_user_id", "TEXT NOT NULL"),
                ("recipient_user_id", "TEXT NOT NULL"),
                ("capsule", "TEXT NOT NULL"),
                ("created_at", "TEXT NOT NULL"),
                ("updated_at", "TEXT NOT NULL"),
                ("revoked", "INTEGER NOT NULL DEFAULT 0"),
            ),
        ),
        (
            "share_inbox",
            (
                ("id", "TEXT UNIQUE NOT NULL"),
                ("sender_user_id", "TEXT NOT NULL"),
                ("recipient_user_id", "TEXT NOT NULL"),
                ("capsule", "TEXT NOT NULL"),
                ("created_at", "TEXT NOT NULL"),
            ),
        ),
        (
            "users",
            (
                ("id", "TEXT UNIQUE NOT NULL"),
                ("share_ek", "TEXT"),
                ("share_ek_since", "TEXT"),
                ("share_ek_device_id", "TEXT"),
            ),
        ),
        (
            "devices",
            (
                ("id", "TEXT UNIQUE NOT NULL"),
                ("user_id", "TEXT NOT NULL"),
                ("hybrid_vk", "TEXT NOT NULL"),
                ("revoked", "INTEGER NOT NULL DEFAULT 0"),
            ),
        ),
    )
)


@dataclass
class Column:
    name: str
    type: str
    declaration: str
    not_null: bool = False
    unique: bool = False
    primary_key: bool = False


@dataclass
class Table:
    name: str
    columns: "OrderedDict[str, Column]" = field(default_factory=OrderedDict)
    source: str = ""


@dataclass
class Schema:
    tables: "OrderedDict[str, Table]" = field(default_factory=OrderedDict)
    indexes: list[tuple[str, str, tuple[str, ...], str]] = field(default_factory=list)
    renames: dict[str, str] = field(default_factory=dict)


@dataclass
class Statement:
    path: str
    line: int
    sql: str


@dataclass
class Finding:
    path: str
    line: int
    message: str


# ── Rust source scanning ──────────────────────────────────────────────────


def _skip_block_comment(text: str, i: int) -> int:
    """Skip a (nesting) Rust block comment starting at i."""
    depth = 1
    i += 2
    while i < len(text) and depth:
        if text.startswith("/*", i):
            depth += 1
            i += 2
        elif text.startswith("*/", i):
            depth -= 1
            i += 2
        else:
            i += 1
    return i


def _raw_literal_at(text: str, i: int) -> tuple[int, str] | None:
    """Return (end, contents) for a raw string at i, or None."""
    j = i
    if text.startswith("br", j):
        j += 2
    elif text[j] == "r":
        j += 1
    else:
        return None
    hashes = 0
    while j < len(text) and text[j] == "#":
        hashes += 1
        j += 1
    if j >= len(text) or text[j] != '"':
        return None
    marker = '"' + "#" * hashes
    end = text.find(marker, j + 1)
    if end < 0:
        raise ValueError("unterminated raw string literal")
    return end + len(marker), text[j + 1 : end]


def _quoted_literal_at(text: str, i: int) -> tuple[int, str]:
    """Return (end, contents) for a normal or byte string at i."""
    if text[i] == "b":
        i += 1
    out: list[str] = []
    i += 1
    while i < len(text):
        c = text[i]
        if c == "\\":
            if i + 1 >= len(text):
                raise ValueError("unterminated string escape")
            nxt = text[i + 1]
            if nxt == "\n":
                # Rust line continuation: drop the newline and following indent.
                i += 2
                while i < len(text) and text[i] in " \t":
                    i += 1
                continue
            mapping = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", '"': '"', "\\": "\\", "'": "'"}
            out.append(mapping.get(nxt, nxt))
            i += 2
            continue
        if c == '"':
            return i + 1, "".join(out)
        out.append(c)
        i += 1
    raise ValueError("unterminated string literal")


def rust_string_literals(text: str):
    """Yield (line, contents) for every Rust string literal, skipping comments."""
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = n if end < 0 else end + 1
            continue
        if text.startswith("/*", i):
            i = _skip_block_comment(text, i)
            continue
        c = text[i]
        if c == '"' or (c == "b" and i + 1 < n and text[i + 1] == '"'):
            start = i
            end, contents = _quoted_literal_at(text, i)
            yield text.count("\n", 0, start) + 1, contents
            i = end
            continue
        if c == "r" or (c == "b" and text.startswith("br", i)):
            raw = _raw_literal_at(text, i)
            if raw is not None:
                start = i
                end, contents = raw
                yield text.count("\n", 0, start) + 1, contents
                i = end
                continue
        if c == "'":
            # Char literal or lifetime.  Only a closed one-character/escape
            # literal is skipped; lifetimes are left alone.
            if i + 1 < n and text[i + 1] == "\\":
                j = i + 2
                while j < n and text[j] != "'":
                    j += 1
                if j < n:
                    i = j + 1
                    continue
            elif i + 2 < n and text[i + 2] == "'":
                i += 3
                continue
        i += 1


def _brace_block_end(text: str, open_at: int) -> int:
    """Index just past the matching '}' of the '{' at open_at."""
    depth = 0
    i = open_at
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = n if end < 0 else end + 1
            continue
        if text.startswith("/*", i):
            i = _skip_block_comment(text, i)
            continue
        c = text[i]
        if c == '"' or (c == "b" and i + 1 < n and text[i + 1] == '"'):
            i = _quoted_literal_at(text, i)[0]
            continue
        if c == "r" or (c == "b" and text.startswith("br", i)):
            raw = _raw_literal_at(text, i)
            if raw is not None:
                i = raw[0]
                continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced block")


def strip_cfg_test_modules(text: str) -> str:
    """Blank out `#[cfg(test)] mod ... { ... }` regions."""
    out = text
    marker = "#[cfg(test)]"
    while True:
        at = out.find(marker)
        if at < 0:
            return out
        module = out.find("mod ", at + len(marker))
        brace = out.find("{", at + len(marker))
        if module < 0 or brace < 0 or module > brace:
            out = out[:at] + " " * len(marker) + out[at + len(marker) :]
            continue
        end = _brace_block_end(out, brace)
        blank = "".join("\n" if ch == "\n" else " " for ch in out[at:end])
        out = out[:at] + blank + out[end:]


def sql_literals(path: Path, keep_test_modules: bool) -> list[Statement]:
    text = path.read_text(encoding="utf-8")
    if not keep_test_modules:
        text = strip_cfg_test_modules(text)
    found = []
    for line, literal in rust_string_literals(text):
        stripped = literal.strip()
        words = stripped.split()
        first = words[0].upper() if words else ""
        # A bare label such as "update" or "select" is not SQL.  Every real
        # statement here has at least a keyword and an operand/clause.
        if len(words) < 2:
            continue
        if first in SQL_STARTS or first in DDL_STARTS:
            try:
                display = str(path.relative_to(ROOT))
            except ValueError:
                display = str(path)
            found.append(Statement(display, line, stripped))
    return found


# ── SQL helpers ───────────────────────────────────────────────────────────


def strip_sql_comments(sql: str) -> str:
    out: list[str] = []
    i = 0
    n = len(sql)
    quote = False
    while i < n:
        c = sql[i]
        if quote:
            out.append(c)
            if c == "'":
                if i + 1 < n and sql[i + 1] == "'":
                    out.append(sql[i + 1])
                    i += 2
                    continue
                quote = False
            i += 1
            continue
        if c == "'":
            quote = True
            out.append(c)
            i += 1
            continue
        if sql.startswith("--", i):
            end = sql.find("\n", i + 2)
            i = n if end < 0 else end
            continue
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


@dataclass
class Token:
    value: str
    kind: str  # IDENT, STRING, NUMBER, PLACEHOLDER, PUNCT


TOKEN_RE = re.compile(
    r"""
      \s+
    | --[^\n]*
    | /\*.*?\*/
    | '(?:''|[^'])*'
    | "(?:[^"]|"")*"
    | \[[^\]]*\]
    | \$\d+
    | \?
    | [A-Za-z_][A-Za-z0-9_]*
    | \d+(?:\.\d+)?
    | <=|>=|<>|!=|==|\|\|
    | .
    """,
    re.VERBOSE | re.DOTALL,
)


def tokenize(sql: str) -> list[Token]:
    tokens: list[Token] = []
    for match in TOKEN_RE.finditer(sql):
        text = match.group(0)
        if text.isspace() or text.startswith("--") or text.startswith("/*"):
            continue
        if text[0] == "'":
            tokens.append(Token(text, "STRING"))
        elif text[0] in "\"[":
            tokens.append(Token(text.strip('"[]'), "IDENT"))
        elif text[0] == "?" or text[0] == "$":
            tokens.append(Token(text, "PLACEHOLDER"))
        elif text[0].isalpha() or text[0] == "_":
            tokens.append(Token(text, "IDENT"))
        elif text[0].isdigit():
            tokens.append(Token(text, "NUMBER"))
        else:
            tokens.append(Token(text, "PUNCT"))
    return tokens


def _up(tokens: list[Token], i: int) -> str:
    return tokens[i].value.upper() if 0 <= i < len(tokens) else ""


def split_sql_statements(sql: str) -> list[str]:
    """Split a batch literal on top-level semicolons."""
    parts: list[str] = []
    start = 0
    i = 0
    quote = False
    while i < len(sql):
        c = sql[i]
        if quote:
            if c == "'":
                if i + 1 < len(sql) and sql[i + 1] == "'":
                    i += 2
                    continue
                quote = False
        elif c == "'":
            quote = True
        elif c == ";":
            part = sql[start:i].strip()
            if part:
                parts.append(part)
            start = i + 1
        i += 1
    part = sql[start:].strip()
    if part:
        parts.append(part)
    return parts


def _matching_paren(tokens: list[Token], open_at: int) -> int:
    depth = 0
    for i in range(open_at, len(tokens)):
        if tokens[i].value == "(":
            depth += 1
        elif tokens[i].value == ")":
            depth -= 1
            if depth == 0:
                return i
    return len(tokens) - 1


def _split_top_level(tokens: list[Token], start: int, end: int) -> list[list[Token]]:
    parts: list[list[Token]] = []
    current: list[Token] = []
    depth = 0
    for token in tokens[start:end]:
        if token.value == "(":
            depth += 1
        elif token.value == ")":
            depth -= 1
        if token.value == "," and depth == 0:
            parts.append(current)
            current = []
        else:
            current.append(token)
    if current:
        parts.append(current)
    return parts


# ── Schema parsing ────────────────────────────────────────────────────────


def _parse_column(tokens: list[Token]) -> Column | None:
    if not tokens or tokens[0].kind != "IDENT":
        return None
    name = tokens[0].value
    rest = tokens[1:]
    if not rest:
        return Column(name=name, type="", declaration="")
    type_tokens = []
    for token in rest:
        if token.value.upper() in {"UNIQUE", "PRIMARY", "NOT", "NULL", "DEFAULT", "CHECK", "REFERENCES", "COLLATE", "GENERATED"}:
            break
        type_tokens.append(token.value)
    declared = tokens[1:]
    upper = [t.value.upper() for t in declared]
    declaration = " ".join(t.value for t in declared)
    not_null = "NOT NULL" in " ".join(upper)
    unique = "UNIQUE" in upper
    primary = "PRIMARY" in upper and "KEY" in upper
    # Keep the declaration readable but with the same token order.
    return Column(
        name=name,
        type=" ".join(type_tokens) or declared[0].value,
        declaration=declaration,
        not_null=not_null,
        unique=unique,
        primary_key=primary,
    )


def _parse_create_table(tokens: list[Token], source: str) -> Table | None:
    i = 2  # CREATE TABLE
    if _up(tokens, i) == "IF":
        i += 3  # IF NOT EXISTS
    if i >= len(tokens) or tokens[i].kind != "IDENT":
        return None
    name = tokens[i].value
    i += 1
    if i >= len(tokens) or tokens[i].value != "(":
        return None
    close = _matching_paren(tokens, i)
    table = Table(name=name, source=source)
    for part in _split_top_level(tokens, i + 1, close):
        if not part:
            continue
        first = _up(part, 0)
        if first in {"CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"}:
            # Table-level PRIMARY KEY/UNIQUE constraint: mark its columns.
            col_start = None
            for j, token in enumerate(part):
                if token.value == "(":
                    col_start = j + 1
                    break
            if col_start is not None:
                end = _matching_paren(part, col_start - 1)
                for col_tokens in _split_top_level(part, col_start, end):
                    if col_tokens and col_tokens[0].kind == "IDENT":
                        col = table.columns.get(col_tokens[0].value)
                        if col is None:
                            # Forward reference: remember via a placeholder.
                            col = Column(col_tokens[0].value, "", "")
                            table.columns[col.name] = col
                        if first == "PRIMARY":
                            col.primary_key = True
                        elif first == "UNIQUE":
                            col.unique = True
            continue
        column = _parse_column(part)
        if column is not None:
            table.columns[column.name] = column
    return table


def _parse_alter(tokens: list[Token]) -> tuple[str, str, object] | None:
    i = 2  # ALTER TABLE
    if i >= len(tokens) or tokens[i].kind != "IDENT":
        return None
    table = tokens[i].value
    i += 1
    action = _up(tokens, i)
    if action == "ADD":
        i += 1
        if _up(tokens, i) == "COLUMN":
            i += 1
        column = _parse_column(tokens[i:])
        if column is not None:
            return ("alter", table, column)
    if action == "RENAME":
        # ALTER TABLE old RENAME TO new
        j = i + 1
        if _up(tokens, j) == "TO":
            j += 1
        if j < len(tokens) and tokens[j].kind == "IDENT":
            return ("rename", table, tokens[j].value)
    return None


def _parse_index(tokens: list[Token], source: str):
    i = 1  # after CREATE
    unique = False
    if _up(tokens, i) == "UNIQUE":
        unique = True
        i += 1
    if _up(tokens, i) != "INDEX":
        return None
    i += 1
    if _up(tokens, i) == "IF":
        i += 3  # IF NOT EXISTS
    if i >= len(tokens) or tokens[i].kind != "IDENT":
        return None
    index_name = tokens[i].value
    i += 1
    if _up(tokens, i) != "ON":
        return None
    i += 1
    if i >= len(tokens) or tokens[i].kind != "IDENT":
        return None
    table = tokens[i].value
    i += 1
    if i >= len(tokens) or tokens[i].value != "(":
        return None
    close = _matching_paren(tokens, i)
    columns = []
    for part in _split_top_level(tokens, i + 1, close):
        if part and part[0].kind == "IDENT":
            columns.append(part[0].value)
    suffix = " UNIQUE" if unique else ""
    return (f"{index_name}{suffix}", table, tuple(columns), source)


def parse_schema_from(sources: tuple[Path, ...]) -> Schema:
    statements: list[Statement] = []
    for path in sources:
        statements.extend(sql_literals(path, keep_test_modules=False))
    creates: "OrderedDict[str, Table]" = OrderedDict()
    alters: list[tuple[str, Column]] = []
    renames: dict[str, str] = {}
    indexes: list[tuple[str, str, tuple[str, ...], str]] = []
    for statement in statements:
        for part in split_sql_statements(statement.sql):
            tokens = tokenize(strip_sql_comments(part))
            if not tokens:
                continue
            first = _up(tokens, 0)
            if first == "CREATE" and _up(tokens, 1) == "TABLE":
                table = _parse_create_table(tokens, statement.path)
                if table is not None:
                    creates[table.name] = table
            elif first == "CREATE" and _up(tokens, 1) in {"INDEX", "UNIQUE"}:
                index = _parse_index(tokens, statement.path)
                if index is not None:
                    indexes.append(index)
            elif first == "ALTER":
                action = _parse_alter(tokens)
                if action is None:
                    continue
                kind, table, value = action
                if kind == "alter":
                    alters.append((table, value))  # type: ignore[arg-type]
                elif kind == "rename":
                    renames[table] = value  # type: ignore[assignment]
    final: "OrderedDict[str, Table]" = OrderedDict()
    for name, table in creates.items():
        if name in renames:
            continue
        final[name] = table
    # A rebuilt table (vault_chunks_v2 -> vault_chunks) wins over the legacy
    # table of the same final name.
    for old, new in renames.items():
        if old in creates:
            rebuilt = creates[old]
            rebuilt.name = new
            final[new] = rebuilt
    # ALTER ... ADD COLUMN is additive and order-independent for this schema:
    # every startup migration runs, so union the columns regardless of where
    # the literal sits in the file.
    for table_name, column in alters:
        target = renames.get(table_name, table_name)
        table = final.get(target)
        if table is not None and column.name not in table.columns:
            table.columns[column.name] = column
    return Schema(tables=final, indexes=indexes, renames=renames)


def parse_schema() -> Schema:
    """The schema rendered statements actually run on (turso)."""
    return parse_schema_from(TURSO_SCHEMA_SOURCES)


def parse_stoolap_schema() -> Schema:
    """The legacy stoolap schema, kept in step with turso."""
    return parse_schema_from(STOOLAP_SCHEMA_SOURCES)


def normalized_declaration(column: Column) -> str:
    text = column.declaration.upper()
    # turso/sqlite affinity: BOOLEAN is stored as INTEGER, TIMESTAMP as TEXT,
    # and FALSE/TRUE as 0/1.  The pilot test compared the engine's DDL.
    text = re.sub(r"\bBOOLEAN\b", "INTEGER", text)
    text = re.sub(r"\bTIMESTAMP\b", "TEXT", text)
    text = re.sub(r"\bFALSE\b", "0", text)
    text = re.sub(r"\bTRUE\b", "1", text)
    return " ".join(text.split())


def check_schema(schema: Schema) -> list[Finding]:
    findings: list[Finding] = []
    # Index targets and columns.
    for name, table_name, columns, source in schema.indexes:
        table_name = schema.renames.get(table_name, table_name)
        table = schema.tables.get(table_name)
        if table is None:
            findings.append(Finding(source, 0, f"index {name}: no table {table_name}"))
            continue
        for column in columns:
            if column not in table.columns:
                findings.append(
                    Finding(source, 0, f"index {name}: no column {table_name}.{column}")
                )
    # The sharing pilot's model columns and declarations.
    for table_name, columns in PILOT_COLUMNS.items():
        table = schema.tables.get(table_name)
        if table is None:
            findings.append(Finding("pilot:sharing", 0, f"no table {table_name}"))
            continue
        for column_name, expected in columns:
            column = table.columns.get(column_name)
            if column is None:
                findings.append(
                    Finding("pilot:sharing", 0, f"no column {table_name}.{column_name}")
                )
                continue
            actual = normalized_declaration(column)
            if actual != expected:
                findings.append(
                    Finding(
                        "pilot:sharing",
                        0,
                        f"{table_name}.{column_name} is declared `{actual}`, expected `{expected}`",
                    )
                )
        if "id" in table.columns and not (
            table.columns["id"].unique or table.columns["id"].primary_key
        ):
            findings.append(
                Finding("pilot:sharing", 0, f"{table_name}.id is not UNIQUE/PRIMARY KEY")
            )
    return findings


def compare_schemas(stoolap: Schema, turso: Schema) -> list[Finding]:
    """Report tables/columns where the two schema definitions diverge."""
    findings: list[Finding] = []
    for name in sorted(set(stoolap.tables) | set(turso.tables)):
        left = stoolap.tables.get(name)
        right = turso.tables.get(name)
        if left is None:
            findings.append(Finding("schema:stoolap", 0, f"table {name} is missing"))
            continue
        if right is None:
            findings.append(Finding("schema:turso", 0, f"table {name} is missing"))
            continue
        for column in sorted(set(left.columns) | set(right.columns)):
            a = left.columns.get(column)
            b = right.columns.get(column)
            if a is None:
                findings.append(
                    Finding("schema:stoolap", 0, f"column {name}.{column} is missing")
                )
                continue
            if b is None:
                findings.append(
                    Finding("schema:turso", 0, f"column {name}.{column} is missing")
                )
                continue
            if normalized_declaration(a) != normalized_declaration(b):
                findings.append(
                    Finding(
                        "schema:compare",
                        0,
                        f"{name}.{column}: stoolap `{normalized_declaration(a)}`, "
                        f"turso `{normalized_declaration(b)}`",
                    )
                )
    return findings


# ── Statement checking ────────────────────────────────────────────────────


def _collect_refs(tokens: list[Token]) -> tuple[OrderedDict[str, str], dict[str, str]]:
    """Return (table -> first alias, alias -> table)."""
    tables: "OrderedDict[str, str]" = OrderedDict()
    alias: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        keyword = _up(tokens, i)
        if keyword in {"FROM", "JOIN", "UPDATE", "INTO"}:
            j = i + 1
            # `ON CONFLICT ... DO UPDATE SET` is not a table reference.
            if keyword == "UPDATE" and (
                (i > 0 and _up(tokens, i - 1) == "DO") or _up(tokens, j) == "SET"
            ):
                i += 1
                continue
            if keyword == "UPDATE" and _up(tokens, j) == "OR":
                i += 1
                continue
            if j < len(tokens) and tokens[j].value == "(":
                i += 1
                continue
            if j < len(tokens) and tokens[j].kind == "IDENT":
                table = tokens[j].value
                tables.setdefault(table, table)
                alias.setdefault(table, table)
                k = j + 1
                if _up(tokens, k) == "AS":
                    k += 1
                if (
                    k < len(tokens)
                    and tokens[k].kind == "IDENT"
                    and _up(tokens, k) not in KEYWORDS
                ):
                    alias[tokens[k].value] = table
                    tables[table] = tokens[k].value
                    i = k
        i += 1
    return tables, alias


def check_statement(schema: Schema, statement: Statement) -> list[Finding]:
    findings: list[Finding] = []
    sql = strip_sql_comments(statement.sql)
    tokens = tokenize(sql)
    if not tokens:
        return findings
    kind = _up(tokens, 0)
    if kind not in SQL_STARTS:
        return findings

    tables, alias = _collect_refs(tokens)
    if kind in {"INSERT", "REPLACE"}:
        # SQLite's `excluded` pseudo-table in an upsert names the row proposed
        # for the INSERT target.
        into = next((i for i, t in enumerate(tokens) if t.value.upper() == "INTO"), None)
        if into is not None and into + 1 < len(tokens) and tokens[into + 1].kind == "IDENT":
            target = tokens[into + 1].value
            tables.setdefault(target, target)
            alias["excluded"] = target
    for table in tables:
        if table not in schema.tables:
            findings.append(
                Finding(statement.path, statement.line, f"no table {table}")
            )

    # INSERT column list and value count.
    if kind in {"INSERT", "REPLACE"}:
        into = next((i for i, t in enumerate(tokens) if t.value.upper() == "INTO"), None)
        if into is None or into + 1 >= len(tokens):
            findings.append(Finding(statement.path, statement.line, "INSERT has no table"))
            return findings
        table_name = tokens[into + 1].value
        table = schema.tables.get(table_name)
        j = into + 2
        column_names: list[str] = []
        if j < len(tokens) and tokens[j].value == "(":
            close = _matching_paren(tokens, j)
            for part in _split_top_level(tokens, j + 1, close):
                if part and part[0].kind == "IDENT":
                    column_names.append(part[0].value)
            j = close + 1
        if table is not None:
            for column in column_names:
                if column not in table.columns:
                    findings.append(
                        Finding(
                            statement.path,
                            statement.line,
                            f"no column {table_name}.{column}",
                        )
                    )
            expected = len(column_names) if column_names else len(table.columns)
            while j < len(tokens) and _up(tokens, j) != "VALUES":
                if _up(tokens, j) == "SELECT":
                    break
                j += 1
            if j < len(tokens) and _up(tokens, j) == "VALUES":
                j += 1
                if j < len(tokens) and tokens[j].value == "(":
                    close = _matching_paren(tokens, j)
                    expressions = _split_top_level(tokens, j + 1, close)
                    if len(expressions) != expected:
                        findings.append(
                            Finding(
                                statement.path,
                                statement.line,
                                f"INSERT into {table_name} has {len(expressions)} value "
                                f"expressions for {expected} columns",
                            )
                        )
                    placeholders = sum(
                        1
                        for part in expressions
                        if part and part[0].kind == "PLACEHOLDER"
                    )
                    if placeholders > len(expressions):
                        findings.append(
                            Finding(
                                statement.path,
                                statement.line,
                                f"INSERT into {table_name} has more placeholders than values",
                            )
                        )

    # UPDATE/DELETE must be guarded.
    if kind in {"UPDATE", "DELETE"} and not any(
        token.value.upper() == "WHERE" for token in tokens
    ):
        findings.append(
            Finding(statement.path, statement.line, f"{kind} has no WHERE clause")
        )

    # Column references.  Every identifier that is not a table, alias, keyword,
    # select alias or function call must name a column of a mentioned table.
    all_columns: set[str] = set()
    for table_name in tables:
        table = schema.tables.get(table_name)
        if table is not None:
            all_columns.update(table.columns)
    select_aliases: set[str] = set()
    for i, token in enumerate(tokens):
        if _up(tokens, i) == "AS" and i + 1 < len(tokens) and tokens[i + 1].kind == "IDENT":
            select_aliases.add(tokens[i + 1].value)

    for i, token in enumerate(tokens):
        if token.kind != "IDENT":
            continue
        value = token.value
        upper = value.upper()
        if upper in KEYWORDS or value in select_aliases:
            continue
        if value in tables or value in alias:
            continue
        if i + 1 < len(tokens) and tokens[i + 1].value == "(":
            continue
        if i > 0 and tokens[i - 1].value == ".":
            qualifier = tokens[i - 2].value if i >= 2 and tokens[i - 2].kind == "IDENT" else ""
            table_name = alias.get(qualifier, qualifier if qualifier in tables else None)
            if table_name is None:
                findings.append(
                    Finding(
                        statement.path,
                        statement.line,
                        f"unknown table/alias qualifier {qualifier!r} for {value}",
                    )
                )
                continue
            table = schema.tables.get(table_name)
            if table is not None and value not in table.columns:
                findings.append(
                    Finding(
                        statement.path,
                        statement.line,
                        f"no column {table_name}.{value}",
                    )
                )
            continue
        if not tables:
            continue
        if value not in all_columns:
            findings.append(
                Finding(
                    statement.path,
                    statement.line,
                    f"no column {value} in any of {', '.join(tables)}",
                )
            )
    return findings


# ── Collection and main ───────────────────────────────────────────────────


def collect_statements() -> tuple[list[Statement], list[Statement]]:
    """Return (policy statements, raw handler statements)."""
    policy: list[Statement] = []
    for path in sorted((ROOT / "serverVELA").glob(f"{POLICY_GLOB}/src/*.rs")):
        policy.extend(sql_literals(path, keep_test_modules=True))
    raw: list[Statement] = []
    for path in RAW_SQL_SOURCES:
        raw.extend(sql_literals(path, keep_test_modules=False))
    return policy, raw


def group_of(path: str) -> str:
    parts = Path(path).parts
    if len(parts) >= 2 and parts[0] == "serverVELA":
        if parts[1].endswith("-policy"):
            return parts[1]
        return "vela-server (raw handler SQL)"
    return path


def check_repo() -> tuple[Schema, list[Statement], list[Finding]]:
    schema = parse_schema()
    stoolap = parse_stoolap_schema()
    policy, raw = collect_statements()
    findings = check_schema(schema) + check_schema(stoolap)
    findings.extend(compare_schemas(stoolap, schema))
    for statement in policy + raw:
        findings.extend(check_statement(schema, statement))
    return schema, policy + raw, findings


def main() -> int:
    schema, statements, findings = check_repo()
    stoolap = parse_stoolap_schema()

    print(
        f"schema (turso): {len(schema.tables)} tables, "
        f"{sum(len(t.columns) for t in schema.tables.values())} columns, "
        f"{len(schema.indexes)} indexes"
    )
    print(
        f"schema (stoolap): {len(stoolap.tables)} tables, "
        f"{sum(len(t.columns) for t in stoolap.tables.values())} columns, "
        f"{len(stoolap.indexes)} indexes"
    )
    for table in schema.tables.values():
        print(f"  {table.name}: {', '.join(table.columns)}")

    groups: "OrderedDict[str, list[Statement]]" = OrderedDict()
    for statement in statements:
        groups.setdefault(group_of(statement.path), []).append(statement)
    total_unique = 0
    print("statements:")
    for group, items in groups.items():
        kinds = Counter(s.sql.split(None, 1)[0].upper() for s in items)
        unique = len({" ".join(s.sql.split()) for s in items})
        total_unique += unique
        kind_text = " ".join(f"{kind}={count}" for kind, count in sorted(kinds.items()))
        print(f"  {group}: {len(items)} literals, {unique} unique ({kind_text})")
    print(f"total: {len(statements)} literals, {total_unique} unique")

    if findings:
        print(f"\n{len(findings)} finding(s):", file=sys.stderr)
        for finding in findings:
            print(f"  {finding.path}:{finding.line}: {finding.message}", file=sys.stderr)
        return 1
    print("\nOK: every pinned SQL statement matches the schema")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"check-sql-schema: {error}", file=sys.stderr)
        sys.exit(1)
