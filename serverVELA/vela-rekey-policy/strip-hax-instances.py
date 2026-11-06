#!/usr/bin/env python3
"""Remove hax's unused derived-trait instance assumptions.

Newer hax emits, for each focused Rust type that derives `Copy`, `Debug` or
`PartialEq`:

    [@@ FStar.Tactics.Typeclasses.tcinstance]
    assume
    val impl_7': Core_models.Marker.t_Copy t_RekeyOp

    unfold
    let impl_7 = impl_7'

The focused proofs never use these typeclass instances (they only `match` on
the constructors), and the checked-in vault-upload extraction predates the
emission. Leaving them in the generated module would make
`check-driver-proof-sources.py` reject the extraction as an unreviewed proof
escape. This script removes exactly those blocks from *generated* modules
before the source guard and F* run; it does not touch hand-written proofs.

Usage: strip-hax-instances.py FILE...
"""
import re
import sys
from pathlib import Path

PATTERN = re.compile(
    r"\[@@ FStar\.Tactics\.Typeclasses\.tcinstance\]\n"
    r"assume\n"
    r"val (?P<name>impl_\w+)': [^\n]+\n"
    r"\n"
    r"unfold\n"
    r"let (?P=name) = (?P=name)'\n"
    r"\n?"
)

def main(paths):
    removed = 0
    for path in map(Path, paths):
        text = path.read_text(encoding="utf-8")
        text, count = PATTERN.subn("", text)
        if count:
            path.write_text(text, encoding="utf-8")
        removed += count
    print(f"stripped {removed} unused hax derived-instance assumption(s)")

if __name__ == "__main__":
    main(sys.argv[1:])
