#!/usr/bin/env python3
"""Check that every proof named in docs/feature-map.md still exists.

`uitest:<shot>` must be a `shot <shot>` call in desktopVELA/scripts/uitest.sh
and `e2e:<test>` a `fn <test>` in desktopVELA/vela-e2e/tests/e2e.rs. It also
checks that feature IDs are unique and every row names a proof.

Usage: python3 -I scripts/check-feature-map.py [--root DIR]
"""
import argparse
import re
import sys
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
ROW_RE = re.compile(r"^\|\s*(D\d+)\s*\|[^|]*\|(.*)\|\s*$")
PROOF_RE = re.compile(r"`(uitest|e2e):([A-Za-z0-9_-]+)`")


def check(root: Path) -> list[str]:
    errors = []
    rows = [ROW_RE.match(line) for line in
            (root / "docs/feature-map.md").read_text(encoding="utf-8").splitlines()]
    rows = [m for m in rows if m]
    shots = set(re.findall(r"^\s*shot\s+([A-Za-z0-9_-]+)",
                           (root / "desktopVELA/scripts/uitest.sh").read_text(encoding="utf-8"), re.M))
    tests = set(re.findall(r"\bfn\s+([A-Za-z0-9_]+)\s*\(",
                           (root / "desktopVELA/vela-e2e/tests/e2e.rs").read_text(encoding="utf-8")))
    if not rows:
        errors.append("docs/feature-map.md: no feature rows found")
    seen = set()
    for m in rows:
        fid, proofs = m.group(1), m.group(2)
        if fid in seen:
            errors.append(f"{fid}: duplicate feature ID")
        seen.add(fid)
        found = PROOF_RE.findall(proofs)
        if not found and "`none`" not in proofs:
            errors.append(f"{fid}: name a proof, or `none`")
        for kind, name in found:
            if kind == "uitest" and name not in shots:
                errors.append(f"{fid}: uitest.sh takes no screenshot named {name}")
            if kind == "e2e" and name not in tests:
                errors.append(f"{fid}: e2e.rs has no test named {name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Check docs/feature-map.md proofs.")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    errors = check(parser.parse_args().root)
    if errors:
        print("\n".join(errors))
        return 1
    print("Every proof in docs/feature-map.md exists.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
