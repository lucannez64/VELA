#!/usr/bin/env python3
"""Turn proof-stability CI artifacts into the README's hosted-run table.

Each `.github/workflows/proof-stability.yml` job writes
`.stability-out/<gate>-seed<N>/result.json` next to its gate log and uploads
that directory. Download them with, for example:

    gh run download <run-id> -D /tmp/stability-artifacts
    python3 security/formal/collect-stability.py \
      --artifacts /tmp/stability-artifacts \
      --readme security/assurance/proof-logs/current/proof-stability/README.md \
      --require-all-pass

The script walks ``--artifacts`` recursively, so the `stability-logs-*`
directories produced by `gh run download` can be passed unchanged. Rows are
(gate, seed, result, seconds), sorted by gate then seed.

`--summary PATH` appends the same table to a GitHub step summary.
`--readme PATH` replaces the text between ``<!-- hosted-run:start -->`` and
``<!-- hosted-run:end -->`` in that file; the rest of the README is untouched.
`--require-all-pass` compares what the artifacts contain with the matrix in
proof-stability.yml and exits 1 when a (gate, seed) pair is missing, duplicated
or not PASS.
"""

import argparse
import collections
import datetime as dt
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/proof-stability.yml"
START = "<!-- hosted-run:start -->"
END = "<!-- hosted-run:end -->"

problems = []


def fail(message):
    problems.append(message)


def expected_pairs(workflow):
    """(gate, seed) pairs from the workflow's matrix (tiny line parser)."""
    lines = workflow.read_text().splitlines()
    include = next((i for i, line in enumerate(lines)
                    if line.strip() == "include:"), None)
    if include is None:
        fail(f"{workflow.name}: no matrix include list")
        return set()
    pairs = set()
    for line in lines[include + 1:]:
        stripped = line.strip()
        if stripped.startswith("- {"):
            body = stripped[stripped.index("{") + 1:stripped.rindex("}")]
            fields = {}
            for part in body.split(","):
                key, sep, value = part.partition(":")
                if sep:
                    fields[key.strip()] = value.strip()
            try:
                pairs.add((fields["name"], int(fields["seed"])))
            except (KeyError, ValueError):
                fail(f"cannot read a (name, seed) pair from {stripped}")
        elif stripped and not stripped.startswith("#"):
            break
    return pairs


def read_results(directory):
    rows = collections.OrderedDict()
    for path in sorted(directory.rglob("result.json")):
        try:
            record = json.loads(path.read_text())
            row = {
                "gate": str(record["gate"]),
                "seed": int(record["seed"]),
                "result": str(record["result"]).upper(),
                "seconds": int(record["seconds"]),
                "exit": int(record.get("exit", -1)),
                "commit": str(record.get("commit", "")),
                "path": str(path),
            }
        except (ValueError, KeyError) as error:
            fail(f"{path}: not a stability result ({error})")
            continue
        key = (row["gate"], row["seed"])
        if key in rows:
            fail(f"duplicate result for {key[0]} seed {key[1]}: "
                 f"{rows[key]['path']} and {path}")
            continue
        rows[key] = row
    return rows


def table(rows):
    out = ["| Gate | Seed | Result | Seconds |", "|---|---|---|---|"]
    for key in sorted(rows, key=lambda k: (k[0], k[1])):
        row = rows[key]
        out.append(f"| `{row['gate']}` | {row['seed']} | {row['result']} | {row['seconds']} |")
    return "\n".join(out)


def hosted_block(rows, expected):
    passed = sum(1 for row in rows.values() if row["result"] == "PASS")
    lines = [
        f"Collected {len(rows)} job results "
        f"({passed} PASS, {len(rows) - passed} not PASS)"
        f" on {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}.",
        "",
        table(rows) if rows else "_No result.json files found._",
    ]
    missing = expected - set(rows)
    if missing:
        lines += ["", f"Missing {len(missing)} expected (gate, seed) pairs."]
    return "\n".join(lines)


def update_readme(path, block):
    text = path.read_text()
    if START not in text or END not in text:
        fail(f"{path}: missing {START} / {END} markers")
        return
    head, _, rest = text.partition(START)
    _, _, tail = rest.partition(END)
    path.write_text(head + START + "\n" + block + "\n" + END + tail)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifacts", type=pathlib.Path, required=True,
                        help="directory of downloaded artifacts (searched recursively)")
    parser.add_argument("--workflow", type=pathlib.Path, default=WORKFLOW,
                        help="proof-stability workflow holding the expected matrix")
    parser.add_argument("--readme", type=pathlib.Path, default=None,
                        help="README whose hosted-run block is replaced")
    parser.add_argument("--summary", type=pathlib.Path, default=None,
                        help="GitHub step summary to append the table to")
    parser.add_argument("--require-all-pass", action="store_true",
                        help="fail unless every expected (gate, seed) pair is PASS")
    args = parser.parse_args()

    expected = expected_pairs(args.workflow)
    rows = read_results(args.artifacts)
    block = hosted_block(rows, expected)

    if args.require_all_pass:
        missing = expected - set(rows)
        extra = set(rows) - expected
        for gate, seed in sorted(missing):
            fail(f"missing result for {gate} seed {seed}")
        for gate, seed in sorted(extra):
            fail(f"unexpected result for {gate} seed {seed}")
        for (gate, seed), row in sorted(rows.items()):
            if row["result"] != "PASS":
                fail(f"{gate} seed {seed} is {row['result']} (exit {row['exit']})")

    print(block)
    if args.summary:
        with args.summary.open("a") as summary:
            summary.write("\n## Proof stability: every gate under Z3 seeds 1, 2, 3\n\n")
            summary.write(block + "\n")
    if args.readme:
        update_readme(args.readme, block)
        print(f"collect-stability: updated the hosted-run block in {args.readme}")
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
