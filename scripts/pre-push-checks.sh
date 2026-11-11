#!/usr/bin/env bash
# The fast gates of .github/workflows/security.yml (job `formal-rekey`), run
# locally. They need only python3 with PyYAML and finish in a few seconds; in
# CI each failure costs a full push-and-wait cycle.
#
#   scripts/pre-push-checks.sh             run the checks
#   scripts/pre-push-checks.sh --install   run them on every `git push` from this clone
#   git push --no-verify                   skip them once
#
# Keep the list below in step with the workflow when a fast gate is added.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

if [[ ${1:-} == --install ]]; then
  git config core.hooksPath .githooks
  echo "pre-push checks enabled (git config core.hooksPath .githooks)"
  exit 0
fi

# Branches from before the assurance package have nothing to check.
[[ -d security/formal/tests ]] || exit 0

unit() { python3 "${@:2}" -m unittest discover -s security/formal/tests -p "$1"; }

failed=0
gate() {
  local name=$1 out
  shift
  if out=$("$@" 2>&1); then
    printf '  ok    %s\n' "$name"
  else
    printf '  FAIL  %s\n' "$name"
    printf '%s\n' "$out" | tail -n 25 | sed 's/^/        /'
    failed=1
  fi
}

echo "pre-push checks (fast gates of security.yml):"
gate "reviewed model correspondence"        python3 security/formal/check-correspondence.py
gate "driver proof source policy"           unit test_driver_proof_sources.py
gate "no proof escapes in tracked F*"       python3 security/formal/check-no-proof-escapes.py
gate "no proof escapes (tests)"             unit test_no_proof_escapes.py
gate "secret-bearing types erase on drop"   python3 -I security/formal/check-secret-erasure.py
gate "secret erasure (tests)"               unit test_secret_erasure.py -I
gate "rendered SQL matches the schema"      python3 security/formal/check-sql-schema.py
gate "SQL schema (tests)"                   unit test_sql_schema.py
gate "bridge exports are thin core calls"   python3 -I security/formal/check-bridge-thinness.py
gate "bridge thinness (tests)"              unit test_bridge_thinness.py -I
gate "proof reuse keys cover their inputs"  unit test_proof_inputs.py

# Not a CI gate, so only a reminder: the manifest lists reviewed artifacts.
if ! sha256sum -c --quiet security/assurance/MANIFEST.sha256 >/dev/null 2>&1; then
  echo "  note  security/assurance/MANIFEST.sha256 is stale;" \
       "refresh with: security/assurance/make-manifest.sh > security/assurance/MANIFEST.sha256"
fi

if (( failed )); then
  echo "pre-push checks failed; fix the above, or push with --no-verify to skip." >&2
  exit 1
fi
