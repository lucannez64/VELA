#!/usr/bin/env bash
# Full logs are retained; a timeout, warning, missing lemma, or attack fails.
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
out=${VELA_PROOF_OUT:-$(mktemp -d -t vela-share-journal.XXXXXX)}
mkdir -p "$out"

# Reject trace-formula fact atoms that no rule emits as an action.  A state
# fact cannot be observed by "Fact(...) @ #i"; such a lemma is unreachable and
# vacuous.  This is a source guard, not a soundness certificate.  The
# regression also checks that the historical DiskClean(...) @ #i shape fails.
bash "$root/tests/run-action-atom-guard.sh"
python3 -m unittest discover -s "$root/tests" -p test_m28_semantic_guard.py

# Check lifting/projection inside two typed single-slot F* encodings.
# Their source embeddings and the all-pairs safety goals are not checked here.
# The Tamarin rules are mapped explicitly in
# m28-trace-equivalence/README.md.
fstar_log="$out/m28-trace-equivalence.log"
"$root/m28-trace-equivalence/verify.sh" >"$fstar_log" 2>&1
if ! grep -q 'All verification conditions discharged successfully' "$fstar_log" \
   || grep -Eiq 'warning|assume|admit|axiom|sorry|magic|error' "$fstar_log"; then
  echo "m28-trace-equivalence: FAIL; inspect $fstar_log" >&2
  exit 1
fi
printf 'm28-trace-equivalence: F* verified, 0 warnings, 0 local assumptions\n'


for model in m28_share_journal m29_signed_share_commit; do
  log="$out/$model.log"
  VELA_PROOF_TIMEOUT=${VELA_PROOF_TIMEOUT:-600} "$root/../assurance/bounded.sh" "$root/tamarin-bounded.sh" --derivcheck-timeout=30 --prove "$root/$model.spthy" >"$log" 2>&1
  python3 - "$root/$model.spthy" "$log" <<'PY'
import re, sys
from pathlib import Path
model, log = map(Path, sys.argv[1:])
text = log.read_text()
expected = set(re.findall(r'^lemma\s+(\w+)', model.read_text(), re.M))
summary = text.split('summary of summaries:')[-1]
actual = re.findall(r'^\s+(\w+) \((?:all-traces|exists-trace)\): verified', summary, re.M)
if ('summary of summaries:' not in text or re.search(r'WARNING:|falsified|analysis incomplete', text)
    or set(actual) != expected or len(actual) != len(expected)):
    sys.exit(f'{model.stem}: FAIL; inspect {log}')
print(f'{model.stem}: {len(expected)} verified, 0 falsified, 0 warnings')
PY
done

printf 'Full proof logs: %s\n' "$out"
