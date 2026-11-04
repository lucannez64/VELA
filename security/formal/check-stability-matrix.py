#!/usr/bin/env python3
"""Keep the proof-stability matrix in step with security.yml (plan step T8).

`security.yml`'s refinement matrix holds 18 entries that together run every
verify-fstar*.sh gate. `.github/workflows/proof-stability.yml` must contain
exactly the same 18 entries with seeds 1, 2 and 3, on GitHub-hosted runners,
cold, and with the seed shim first on PATH. This script compares the two
matrices and the workflow's required settings, and fails loudly when one drifts.

No third-party dependency is required; when PyYAML is importable the workflow
is also parsed as YAML and the two matrices are compared structurally.
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SECURITY = ROOT / ".github/workflows/security.yml"
STABILITY = ROOT / ".github/workflows/proof-stability.yml"
EXPECTED_GATES = 18
EXPECTED_SEEDS = {1, 2, 3}
REQUIRED_PUSH_PATHS = (
    ".github/workflows/proof-stability.yml",
    "security/assurance/z3-seed/**",
    "security/formal/list-rlimits.py",
)

problems = []


def fail(message):
    problems.append(message)


def flow_mapping(text):
    body = text[text.index("{") + 1:text.rindex("}")]
    fields = {}
    for part in body.split(","):
        key, sep, value = part.partition(":")
        if not sep:
            fail(f"cannot parse matrix field {part!r} in {text!r}")
            continue
        fields[key.strip()] = value.strip()
    return fields


def job_matrix(path, job):
    """Entries of `<job>`'s `matrix.include` list, parsed line by line."""
    lines = path.read_text().splitlines()
    job_line = next((i for i, line in enumerate(lines)
                     if line.rstrip() == f"  {job}:"), None)
    if job_line is None:
        fail(f"{path.name}: no job named {job!r}")
        return None
    include = next((i for i in range(job_line, len(lines))
                    if lines[i].strip() == "include:"), None)
    if include is None:
        fail(f"{path.name}: job {job!r} has no matrix include list")
        return None
    entries = []
    for line in lines[include + 1:]:
        stripped = line.strip()
        if stripped.startswith("- {"):
            entries.append(flow_mapping(stripped))
        elif stripped and not stripped.startswith("#"):
            break
    return entries


def gate_key(entry):
    return (entry.get("name", ""), entry.get("dir", ""),
            entry.get("script", ""), entry.get("args", ""))


def check_matrix():
    refinement = job_matrix(SECURITY, "refinement")
    stability = job_matrix(STABILITY, "stability")
    if refinement is None or stability is None:
        return
    if len(refinement) != EXPECTED_GATES:
        fail(f"security.yml refinement has {len(refinement)} entries, expected {EXPECTED_GATES};"
             " update proof-stability.yml and this script together")
    refinement_keys = {gate_key(entry) for entry in refinement}
    if len(refinement_keys) != len(refinement):
        fail("security.yml refinement has duplicate (name, dir, script, args) entries")

    by_gate = {}
    for entry in stability:
        try:
            seed = int(entry.get("seed", ""))
        except ValueError:
            fail(f"proof-stability.yml entry {entry.get('name')!r} has no integer seed")
            continue
        by_gate.setdefault(gate_key(entry), set()).add(seed)

    missing = refinement_keys - set(by_gate)
    extra = set(by_gate) - refinement_keys
    for key in sorted(missing):
        fail(f"proof-stability.yml is missing the refinement gate {key}")
    for key in sorted(extra):
        fail(f"proof-stability.yml has a gate absent from security.yml: {key}")
    for key, seeds in sorted(by_gate.items()):
        if seeds != EXPECTED_SEEDS:
            fail(f"gate {key[0]!r} has seeds {sorted(seeds)}, expected {sorted(EXPECTED_SEEDS)}")
    if len(stability) != EXPECTED_GATES * len(EXPECTED_SEEDS):
        fail(f"proof-stability.yml has {len(stability)} entries, expected"
             f" {EXPECTED_GATES * len(EXPECTED_SEEDS)}")


def check_workflow_text():
    text = STABILITY.read_text()
    runs_on = re.findall(r"^\s*runs-on:\s*(.+)$", text, re.MULTILINE)
    if not runs_on:
        fail("proof-stability.yml has no runs-on")
    for value in runs_on:
        if value.strip() != "ubuntu-24.04":
            fail(f"proof-stability.yml runs on {value.strip()!r}; only GitHub-hosted"
                 " ubuntu-24.04 is allowed (never vela-box)")
    if "fail-fast: false" not in text:
        fail("proof-stability.yml must set `fail-fast: false`")
    if 'VELA_FSTAR_CACHE: "0"' not in text:
        fail("proof-stability.yml must run cold with VELA_FSTAR_CACHE: \"0\"")
    # security.yml keys reused proofs with `proof-verdict-v1-...` and stores
    # them under .proof-out; this workflow must have neither.
    if "proof-verdict-v1-" in text or ".proof-out" in text:
        fail("proof-stability.yml must not reuse proof verdicts or cached outputs")
    if 'PATH="$GITHUB_WORKSPACE/security/assurance/z3-seed:$PATH"' not in text:
        fail("proof-stability.yml must put security/assurance/z3-seed first on PATH")
    if "VELA_Z3_SEED: ${{ matrix.seed }}" not in text:
        fail("proof-stability.yml must pass matrix.seed as VELA_Z3_SEED")
    for trigger in ("schedule:", "workflow_dispatch:", "push:"):
        if trigger not in text:
            fail(f"proof-stability.yml is missing the {trigger} trigger")
    for path in REQUIRED_PUSH_PATHS:
        if f'"{path}"' not in text:
            fail(f"proof-stability.yml push paths are missing {path}")

    try:
        import yaml
    except ImportError:
        print("check-stability-matrix: PyYAML not installed; skipped the YAML parse")
        return
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as error:
        fail(f"proof-stability.yml does not parse as YAML: {error}")
        return
    matrix = doc["jobs"]["stability"]["strategy"]["matrix"]["include"]
    loaded = {gate_key(entry) for entry in matrix}
    if len(loaded) != EXPECTED_GATES:
        fail(f"parsed YAML has {len(loaded)} distinct gates, expected {EXPECTED_GATES}")
    sections = doc.get("on", doc.get(True, {}))
    for trigger in ("schedule", "workflow_dispatch", "push"):
        if trigger not in sections:
            fail(f"parsed YAML is missing the {trigger} trigger")
    paths = sections.get("push", {}).get("paths", [])
    for path in REQUIRED_PUSH_PATHS:
        if path not in paths:
            fail(f"parsed YAML push paths are missing {path}")


def main():
    global SECURITY, STABILITY
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--security", type=pathlib.Path, default=None)
    parser.add_argument("--stability", type=pathlib.Path, default=None)
    args = parser.parse_args()
    SECURITY = args.security or SECURITY
    STABILITY = args.stability or STABILITY

    check_matrix()
    check_workflow_text()
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}")
        return 1
    print(f"PASS: {EXPECTED_GATES} refinement gates x seeds {sorted(EXPECTED_SEEDS)}"
          f" = {EXPECTED_GATES * len(EXPECTED_SEEDS)} stability entries match security.yml")
    print("PASS: GitHub-hosted ubuntu-24.04 only, cold, seed shim first on PATH,"
          " required triggers present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
