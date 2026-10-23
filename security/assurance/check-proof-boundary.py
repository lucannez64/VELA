#!/usr/bin/env python3
"""Reject extraction assumption drift; this is not a proof checker."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def check_artifact(path, expected):
    text = path.read_text()
    # Erase Rust doc comments before scanning for admitted proof bodies.
    code = re.sub(r'(?m)^\s*///.*$', '', text)
    assumptions = re.findall(r'^assume\s+val\s+([^\n]+)', code, re.M)
    if assumptions != expected['allowed_assume_val']:
        raise ValueError(f'{path}: unreviewed assume val declarations')
    if len(re.findall(r'^assume\b', code, re.M)) != len(assumptions):
        raise ValueError(f'{path}: unreviewed assumption syntax')
    if re.search(r'\b(?:admit|admit1|magic|unsafe_coerce)\b|--(?:lax|admit_smt_queries|unsafe_tactic_exec)\b', code):
        raise ValueError(f'{path}: admitted/unsafe proof body or lax checking')
    count = len(re.findall(r'\(ensures\b', code))
    if count != expected['selected_postconditions']:
        raise ValueError(f'{path}: expected {expected["selected_postconditions"]} postconditions, found {count}')
    effects = len(re.findall(r'\bPrims\.Pure\b', code))
    trivial = len(re.findall(r'\bPrims\.l_True\s*\(ensures\b', code))
    if effects != count or trivial != count:
        raise ValueError(f'{path}: nontrivial or unreviewed extraction precondition')
    return len(assumptions), count

def main():
    boundary = json.loads((ROOT/'security/assurance/proof-boundary.json').read_text())
    totals = [0, 0]
    for artifact in boundary['artifacts']:
        assumptions, count = check_artifact(ROOT/artifact['artifact'], artifact)
        totals[0] += assumptions
        totals[1] += count
    print(f'{len(boundary["artifacts"])} checked module artifacts: {totals[1]} selected postconditions, {totals[0]} explicitly reviewed assume val declarations.')
    print('Imported libraries, the String compatibility view, extraction, solvers and the OS remain trusted; this static gate is not a proof.')

if __name__ == '__main__':
    main()
