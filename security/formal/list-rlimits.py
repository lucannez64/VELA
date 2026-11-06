#!/usr/bin/env python3
"""Inventory every Z3 resource limit in the VELA proof corpus (plan step T8).

Searches, in the repository at HEAD:

  * every tracked shell script for a command-line ``--z3rlimit`` (or
    ``--z3rlimit=``) setting; this covers the gate scripts of the refinement
    matrix and the helpers they call;
  * every tracked ``.fst``/``.fsti`` module (outside ``proof-logs``, whose
    copies are evidence, not sources) for ``#set-options``/``#push-options``/
    ``#reset-options`` settings, including ``--z3rlimit_factor``; and
  * ``--z3seed`` in those modules, which would override the T8 seed shim's
    flag for that module and is therefore reported rather than ignored.

With ``--queries-log`` it also parses F* ``--query_stats`` output (from
``security/assurance/z3-seed/verify-fstar-seeded.sh --query-stats``) and
records, per module, the largest configured limit and the largest limit each
query actually used.

Writes ``rlimits.json`` and ``rlimits.md`` into ``--out`` (default:
``security/assurance/proof-logs/current/proof-stability``). Every claim in the
markdown comes from the files it scanned; nothing here is a proof that a limit
is adequate, only a record of what is set.
"""

import argparse
import collections
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROOF_LOG_PREFIX = "security/assurance/proof-logs/"
DEFAULT_OUT = ROOT / "security/assurance/proof-logs/current/proof-stability"

RLIMIT = re.compile(r"--z3rlimit(?:=|\s+)(\d+)")
RLIMIT_FACTOR = re.compile(r"--z3rlimit_factor(?:=|\s+)(\d+)")
Z3SEED = re.compile(r"--z3seed(?:=|\s+)(\d+)")
DIRECTIVE = re.compile(r"^\s*#([a-z][a-z-]*)")
# Query-stats (Vela_sync_policy.fst(6,0-6,35))	Query-stats (Vela_sync_policy.v_INITIAL_EPOCH, 1)	succeeded in 59 milliseconds with fuel 0 and ifuel 1 and rlimit 500 (used rlimit 0.037)
QUERY_STATS = re.compile(
    r"^\((?P<file>[^()]+?)\(\d+,\d+-\d+,\d+\)\)\s+Query-stats \((?P<query>.+), \d+\)\s+"
    r".*?rlimit (?P<rlimit>\d+(?:\.\d+)?).*?\(used rlimit (?P<used>\d+(?:\.\d+)?)\)"
)


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                          text=True, check=True).stdout


def tracked(pattern):
    out = git("ls-files", "--", pattern)
    return [p for p in out.splitlines() if p]


def scan(path, patterns):
    """Yield (line_number, matched_value, line_text, extra) for each match."""
    text = (ROOT / path).read_text(encoding="utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), 1):
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                yield number, match.group(1), line.strip(), match


def collect():
    shell_rows, factor_rows, seed_rows = [], [], []
    fstar_rows = []

    shells = sorted(set(tracked("*.sh")))
    modules = [p for p in sorted(tracked("*.fst")) + sorted(tracked("*.fsti"))
               if not p.startswith(PROOF_LOG_PREFIX)]

    for path in shells:
        for number, value, text, _ in scan(path, [RLIMIT]):
            shell_rows.append({"kind": "command-line", "file": path, "line": number,
                               "value": int(value), "text": text})
        for number, value, text, _ in scan(path, [RLIMIT_FACTOR]):
            factor_rows.append({"kind": "command-line", "file": path, "line": number,
                                "value": int(value), "text": text})

    for path in modules:
        text_lines = (ROOT / path).read_text(encoding="utf-8", errors="replace").splitlines()
        for number, line in enumerate(text_lines, 1):
            match = RLIMIT.search(line)
            if match:
                directive = DIRECTIVE.match(line)
                fstar_rows.append({
                    "kind": "fstar-source", "file": path, "line": number,
                    "directive": f"#{directive.group(1)}" if directive else "(module argument)",
                    "value": int(match.group(1)), "text": line.strip()})
            if RLIMIT_FACTOR.search(line):
                factor_rows.append({"kind": "fstar-source", "file": path, "line": number,
                                    "value": int(RLIMIT_FACTOR.search(line).group(1)),
                                    "text": line.strip()})
            if Z3SEED.search(line):
                seed_rows.append({"file": path, "line": number, "text": line.strip()})

    return shells, modules, shell_rows, fstar_rows, factor_rows, seed_rows


def parse_query_stats(paths):
    modules = collections.OrderedDict()
    for path in paths:
        text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            match = QUERY_STATS.match(line)
            if not match:
                continue
            module = re.sub(r"\.(fst|fsti)$", "", match.group("file").strip())
            entry = modules.setdefault(module, {
                "module": module, "file": match.group("file").strip(),
                "queries": 0, "max_rlimit": 0.0, "max_used_rlimit": 0.0})
            entry["queries"] += 1
            entry["max_rlimit"] = max(entry["max_rlimit"], float(match.group("rlimit")))
            entry["max_used_rlimit"] = max(entry["max_used_rlimit"], float(match.group("used")))
    return list(modules.values())


def clip(text, limit=140):
    return text if len(text) <= limit else text[:limit - 3] + "..."


def markdown(report):
    rows = report["command_line"] + report["fstar_source"]
    out = [
        "# Z3 resource limits in the VELA proof corpus",
        "",
        "Generated by `security/formal/list-rlimits.py`; do not edit by hand.",
        f"Generated {report['generated_at']} from the repository tree.",
        "",
        "## Summary",
        "",
        f"- Scanned {report['scope']['shell_files']} tracked shell scripts and "
        f"{report['scope']['fstar_files']} tracked F* modules "
        f"(the {report['scope']['proof_log_modules_excluded']} module copies under "
        "`security/assurance/proof-logs/` are evidence, not sources).",
        f"- {len(report['command_line'])} command-line `--z3rlimit` settings, "
        f"{len(report['fstar_source'])} in F* source directives.",
        f"- Largest configured limit: **{report['max']['value']}** in "
        + ", ".join(f"`{row['file']}:{row['line']}`"
                    for row in report["max_locations"])
        + ".",
        f"- `--z3rlimit_factor` settings: {len(report['rlimit_factor'])}.",
        f"- Tracked F* modules that set `--z3seed`: {len(report['z3seed_in_fstar'])}"
        " (any here would override the T8 seed shim for that module).",
        "",
        "A limit is a per-query ceiling, not a proof claim: it only says how much"
        " solver work a query may spend. The per-module `--query_stats` section below"
        " shows how much the queries of the module that was run locally actually used.",
        "",
        "## Command-line settings (shell scripts)",
        "",
        "| Limit | File:line | Setting |",
        "|---|---|---|",
    ]
    for row in report["command_line"]:
        text = clip(row["text"]).replace("|", "\\|")
        out.append(f"| {row['value']} | `{row['file']}:{row['line']}` | `{text}` |")
    out += [
        "",
        "## F* source directives",
        "",
        "`#set-options`/`#push-options` lines are per-module; a directive's limit"
        " applies to the queries of that module only.",
        "",
        "| Limit | Directive | File:line | Setting |",
        "|---|---|---|---|",
    ]
    for row in report["fstar_source"]:
        text = clip(row["text"]).replace("|", "\\|")
        out.append(f"| {row['value']} | `{row['directive']}` | "
                   f"`{row['file']}:{row['line']}` | `{text}` |")
    out += [
        "",
        "## Limits actually used (`--query_stats`)",
        "",
    ]
    stats = report.get("query_stats", {})
    if stats.get("modules"):
        out += [
            f"Parsed from `{stats['source']}`.",
            "",
            "| Module | Queries | Largest configured rlimit | Largest used rlimit |",
            "|---|---|---|---|",
        ]
        for row in stats["modules"]:
            out.append(f"| `{row['module']}` | {row['queries']} | "
                       f"{row['max_rlimit']:g} | {row['max_used_rlimit']:g} |")
    else:
        out.append("No `--query_stats` log was supplied; run"
                   " `security/assurance/z3-seed/verify-fstar-seeded.sh --query-stats"
                   " SEED GATE` and pass its log with `--queries-log`.")
    out += [
        "",
        "## Method",
        "",
        "- Shell rows: every tracked `*.sh` file, one row per `--z3rlimit`/"
        "`--z3rlimit=` occurrence, with the whole line as the setting text.",
        "- F* rows: every tracked `*.fst`/`*.fsti` outside `proof-logs/`, one row"
        " per line that mentions `--z3rlimit`, tagged with its directive.",
        "- `--z3seed`: same F* scan; none is expected because the seed shim would"
        " not be able to override a module's own setting.",
        "- `--query_stats`: F* 2025.10.06 prints one line per query with the"
        " configured limit and the fraction it used; this script keeps the maximum"
        " per module.",
        "",
    ]
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT,
                        help=f"output directory (default: {DEFAULT_OUT})")
    parser.add_argument("--queries-log", type=pathlib.Path, action="append", default=[],
                        help="F* --query_stats log to parse (repeatable)")
    args = parser.parse_args()

    shells, modules, shell_rows, fstar_rows, factor_rows, seed_rows = collect()
    proof_log_modules = len([p for p in sorted(tracked("*.fst")) + sorted(tracked("*.fsti"))
                             if p.startswith(PROOF_LOG_PREFIX)])
    all_rows = shell_rows + fstar_rows
    maximum = max(all_rows, key=lambda r: r["value"])
    values = collections.Counter(str(r["value"]) for r in all_rows)

    stats_modules = parse_query_stats(args.queries_log)
    report = {
        "generated_by": "security/formal/list-rlimits.py",
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "shell_files": len(shells),
            "fstar_files": len(modules),
            "proof_log_modules_excluded": proof_log_modules,
        },
        "counts": {
            "command_line": len(shell_rows),
            "fstar_source": len(fstar_rows),
            "rlimit_factor": len(factor_rows),
            "z3seed_overrides": len(seed_rows),
        },
        "values": dict(sorted(values.items(), key=lambda kv: -int(kv[0]))),
        "max": {key: maximum[key] for key in ("value", "kind", "file", "line")},
        "max_locations": [{"kind": r["kind"], "file": r["file"], "line": r["line"]}
                          for r in all_rows if r["value"] == maximum["value"]],
        "command_line": shell_rows,
        "fstar_source": fstar_rows,
        "rlimit_factor": factor_rows,
        "z3seed_in_fstar": seed_rows,
        "query_stats": {
            "source": ", ".join(str(p) for p in args.queries_log) or None,
            "modules": stats_modules,
        },
    }

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "rlimits.json").write_text(json.dumps(report, indent=1) + "\n")
    (args.out / "rlimits.md").write_text(markdown(report))

    print(f"list-rlimits: {len(shell_rows)} command-line, {len(fstar_rows)} F* source, "
          f"{len(factor_rows)} rlimit_factor, {len(seed_rows)} --z3seed")
    print(f"list-rlimits: max {maximum['value']} at {maximum['file']}:{maximum['line']}")
    if stats_modules:
        print(f"list-rlimits: {len(stats_modules)} modules from --query_stats")
    print(f"list-rlimits: wrote {args.out / 'rlimits.md'} and rlimits.json")
    return 1 if seed_rows else 0


if __name__ == "__main__":
    sys.exit(main())
