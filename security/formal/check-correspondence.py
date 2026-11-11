#!/usr/bin/env python3
"""Detect drift in reviewed source/model pairs. This is not a refinement proof.

After a change, review the mapping in network-boundary-correspondence.md and
update the corresponding SHA-256 in correspondence.json. Never refresh blindly.
"""
import hashlib
import json
from pathlib import Path
import sys


def check(root: Path, record: dict) -> list[str]:
    failures = []
    for pair in record['pairs']:
        for path, expected in pair['artifacts'].items():
            file = root / path
            if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
                failures.append(f"{pair['boundary']}: review correspondence after changing {path}")
    return failures


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[2]
    failures = check(root, json.loads((Path(__file__).with_name('correspondence.json')).read_text()))
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        sys.exit(1)
    print('Reviewed source/model hashes match; semantic correspondence remains a manual review obligation.')
