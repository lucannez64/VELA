#!/usr/bin/env bash
# Full logs are retained; a timeout, warning, missing lemma, or attack fails.
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
out=${VELA_PROOF_OUT:-$(mktemp -d -t vela-share-journal.XXXXXX)}
mkdir -p "$out"
for model in m28_share_journal m29_signed_share_commit; do
  log="$out/$model.log"
  "$root/../assurance/bounded.sh" "$root/tamarin-bounded.sh" --derivcheck-timeout=30 --prove "$root/$model.spthy" >"$log" 2>&1
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
