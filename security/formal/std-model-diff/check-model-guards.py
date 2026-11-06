#!/usr/bin/env python3
"""Reject corpus uses of the two hax 0.3.7 bugs and of signed `/!` `%!`.

Plan step T7.  The differential test shows *why* these three things must not
appear in the VELA corpus; this guard is what stops them from appearing:

  ne            Rust_primitives.Integers.ne is `v b <> v b`, i.e. constant
                false (a hax 0.3.7 library bug), so any corpus use would break
                the proof it supports.  The review counted 5 matches, all a
                local variable named `ne`; those stay allowed.
  mul_overflow  Rust_primitives.Integers.mul_overflow returns the wrapped
                product but a flag that tests `< maxint` instead of `< minint`
                (true for every product except exactly maxint), so it is wrong
                whenever the multiplication does not overflow.
  /!  %!        F* integer division is Euclidean (`%` is never negative),
                while Rust truncates towards zero.  The quotient differs
                whenever the dividend is negative, and the extracted OCaml
                truncates like Rust, so a signed use would compare Rust with
                the OCaml runtime instead of the specification.  The corpus
                uses them on u64 alone (Vela_crypto.Wire); a new use outside
                the allowlist below must be reviewed by hand.

Scans every .fst/.fsti in the repository (tracked, plus untracked generated
extractions), skipping build output and historical proof logs, exactly like
security/formal/check-no-proof-escapes.py.

Exit 1 on a violation.  `--print-allowlist` shows the accepted uses.
"""
import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SKIP = ("/target/", "/proof-logs/", "/fstar-cache/", "/.cache/", "/node_modules/",
        "/tests/fixtures/")

# The only files allowed to contain `/!` or `%!`, with the reason.
DIVISION_ALLOWLIST = {
    "libVELA/vela-crypto/proofs/fstar/extraction/Vela_crypto.Wire.fst":
        "u64 byte encoding: value /! 256 and value %! 256",
}

# `ne` in a call position: `ne #...`, `ne (x)`, `ne a b`.  A binding
# (`let ne = ...`), a field (`a_epoch = ne`), a match variable
# (`Option_Some ne ->`) or a comment word do not match.
NE_CALL = re.compile(r"(?<![\w'.])ne(?=\s+(?:#|\(|[A-Za-z_0-9]))")
NE_QUALIFIED = re.compile(r"\b(?:Rust_primitives(?:\.Integers)?|Integers|Rust_primitives)\.ne\b")
MUL_OVERFLOW = re.compile(r"\bmul_overflow\b")


def mask(source):
    """Blank out F* comments and string literals, keeping line structure."""
    out, i, n, depth = [], 0, len(source), 0
    while i < n:
        c = source[i]
        if depth == 0 and c == '"':
            out.append('"')
            i += 1
            while i < n and source[i] != '"':
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append('"')
                i += 1
            continue
        if source.startswith("(*", i):
            depth += 1
            out.append("  ")
            i += 2
            continue
        if source.startswith("*)", i) and depth:
            depth -= 1
            out.append("  ")
            i += 2
            continue
        out.append("\n" if c == "\n" else (" " if depth else c))
        i += 1
    return "".join(out)


def corpus(root):
    files = {}
    # The build box mirrors the worktree without .git, so `git ls-files` may
    # fail there; the filesystem walk below still covers every F* file.
    try:
        tracked = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--",
                                  "*.fst", "*.fsti"], capture_output=True, check=True)
        for p in tracked.stdout.decode().split("\0"):
            if p:
                files[p] = True
    except (OSError, subprocess.CalledProcessError):
        pass
    for p in root.rglob("*.fst*"):
        if p.suffix in (".fst", ".fsti"):
            files[str(p.relative_to(root))] = False
    for rel, is_tracked in sorted(files.items()):
        if any(k in "/" + rel for k in SKIP):
            continue
        p = root / rel
        if p.exists():
            yield rel, is_tracked, p.read_text(encoding="utf-8", errors="replace")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=str(ROOT))
    ap.add_argument("--print-allowlist", action="store_true")
    a = ap.parse_args(argv)
    root = pathlib.Path(a.root).resolve()
    if a.print_allowlist:
        for f, why in DIVISION_ALLOWLIST.items():
            print(f"{f}: {why}")
        return 0

    found, allowed_ne = [], 0
    files = 0
    for rel, tracked, source in corpus(root):
        files += 1
        code = mask(source)
        for n, line in enumerate(code.splitlines(), 1):
            m = NE_QUALIFIED.search(line) or NE_CALL.search(line)
            if m:
                found.append(f"{rel}:{n}: uses `ne` ({'tracked' if tracked else 'untracked'}); "
                             f"it is constant false in hax 0.3.7")
            if MUL_OVERFLOW.search(line):
                found.append(f"{rel}:{n}: uses `mul_overflow`; its flag is wrong in hax 0.3.7")
            if "/!" in line or "%!" in line:
                if rel not in DIVISION_ALLOWLIST:
                    found.append(f"{rel}:{n}: `/!` or `%!` outside the reviewed allowlist; "
                                 f"F* and Rust disagree on signed division")
                elif "u64" not in line:
                    found.append(f"{rel}:{n}: allowlisted file but the line does not show a "
                                 f"u64 operand; signed division rounds differently")
        # Count the variable-name uses this scan deliberately allows, so the
        # log shows the guard saw them.
        for n, line in enumerate(code.splitlines(), 1):
            if re.search(r"(?<![\w'.])ne\b", line) and not (
                    NE_QUALIFIED.search(line) or NE_CALL.search(line)):
                allowed_ne += 1
    for msg in found:
        print(msg)
    if found:
        print(f"{len(found)} guard violation(s) in {files} F* files", file=sys.stderr)
        return 1
    print(f"{files} F* files: no `ne`, no `mul_overflow`, "
          f"and `/!` `%!` only in {len(DIVISION_ALLOWLIST)} reviewed file(s); "
          f"{allowed_ne} non-call occurrences of the identifier `ne` allowed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
