#!/usr/bin/env python3
"""Reject proof escapes in every F* file of the repository (plan step T2).

The focused gates run check-driver-proof-sources.py on their own modules, but
17 of the 61 verify-fstar*.sh scripts do not, and nothing covered the corpus as
a whole. This check scans every .fst/.fsti outside build output and historical
proof logs and rejects:

  - assume, admit, admit1, axiom, Admitted, sorry, magic, unsafe_coerce,
    expect_failure and expect_lax_failure in code (comments and strings are
    masked with the driver checker's lexer, so `(* admit *)` passes and
    `(* *) admit` does not);
  - an interface (.fsti) val with no implementation module (.fst) next to it,
    which F* would treat as an assumption.

Solver options are allowed here; the focused gates keep their exact budget
policy. Library models from hax are outside this scan (see
security/assurance/list-model-contracts.py). Not a proof checker: F* is.
"""
import argparse
import importlib.util
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SKIP = ("/target/", "/proof-logs/", "/fstar-cache/", "/.cache/", "/node_modules/", "/tests/fixtures/")
ESCAPE = re.compile(r"\b(?:assume|admit|admit1|axiom|Admitted|sorry|magic|unsafe_coerce|expect_failure|expect_lax_failure)\b")

_spec = importlib.util.spec_from_file_location("driver_guard", pathlib.Path(__file__).with_name("check-driver-proof-sources.py"))
_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_guard)


def masked(source):
    code = _guard.uncomment(source)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', code, flags=re.S)


def problems(path, source):
    code = masked(source)
    out = []
    for n, line in enumerate(code.splitlines(), 1):
        m = ESCAPE.search(line)
        if m:
            out.append(f"{path}:{n}: proof escape `{m.group()}`")
    if path.suffix == ".fsti" and not path.with_suffix(".fst").exists():
        for n, line in enumerate(code.splitlines(), 1):
            if re.match(r"\s*val\s", line):
                out.append(f"{path}:{n}: interface val with no implementation module")
    return out


# hax extracts #[derive(PartialEq)] and friends as an assumed typeclass instance
# when it cannot generate the body. Such an instance is satisfiable (the class
# is an inhabited record) but its behavior is unspecified, so --all lists them
# separately for review instead of mixing them with hand-written escapes.
DERIVED = re.compile(r"assume\s+val\s+impl_[0-9]+'\s*:\s*Core_models\.(?:Cmp|Clone|Fmt|Hash|Marker)\.t_[A-Za-z]+")


def corpus(root=ROOT, everything=False):
    if everything:
        paths = sorted(root.rglob("*.fst*"))
    else:  # tracked files only: what CI sees before any extraction runs
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", "*.fst", "*.fsti"],
                             capture_output=True, check=True).stdout.decode()
        paths = [root / p for p in out.split("\0") if p]
    for p in paths:
        if p.suffix in (".fst", ".fsti") and not any(k in str(p) for k in SKIP) and p.exists():
            yield p


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=str(ROOT))
    ap.add_argument("--all", action="store_true",
                    help="also scan untracked generated extractions; derived-instance assumes are listed, not failed")
    a = ap.parse_args(argv)
    root = pathlib.Path(a.root).resolve()
    files = list(corpus(root, a.all))
    found, derived = [], []
    for p in files:
        src = p.read_text(encoding="utf-8")
        tracked = not a.all or subprocess.run(["git", "-C", str(root), "ls-files", "--error-unmatch", str(p)],
                                              capture_output=True).returncode == 0
        for msg in problems(p.relative_to(root), src):
            line = int(msg.split(":")[1])
            text = " ".join(masked(src).splitlines()[line - 1:line + 1])
            (derived if (not tracked and DERIVED.search(text)) else found).append(msg)
    for msg in found:
        print(msg)
    for msg in derived:
        print(msg + " (generated derive instance)")
    if found:
        print(f"{len(found)} proof escape(s) in {len(files)} F* files", file=sys.stderr)
        return 1
    extra = f"; {len(derived)} generated derive-instance assumption(s) listed above" if derived else ""
    print(f"{len(files)} F* files: no proof escapes, no unimplemented interfaces{extra}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
