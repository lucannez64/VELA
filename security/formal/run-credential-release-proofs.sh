#!/usr/bin/env bash
# Check all credential-release verdicts and preserve per-model output.
set -euo pipefail
formal=$(cd "$(dirname "$0")" && pwd)
if [[ ${VELA_BOUNDED:-0} != 1 ]]; then
  exec "$formal/../assurance/bounded.sh" "$0" "$@"
fi
out_dir=${VELA_PROOF_OUT:-$(mktemp -d -t vela-credential-proofs.XXXXXX)}
mkdir -p "$out_dir"
credential_release() {
  local models=(m1_indomain m2_se_alone m3_de_se m4_bool_naive m5_tr_originbound
                m6_ipc_handshake m7_oneshot_assertion m8_hybrid m9a_in_core_login
                m9b_engine_login m9c_inprocess_sandbox m9d_captcha_artifact
                m10_full_ladder)
  local expected_falsified="m1_indomain.secrecy
m2_se_alone.secrecy
m9b_engine_login.credential_never_leaks
m9c_inprocess_sandbox.credential_never_leaks
m9c_inprocess_sandbox.unused_credentials_stay_secret"
  local verified=0 falsified="" model output
  for model in "${models[@]}"; do
    output="$out_dir/credential-release.$model.out"
    # Tamarin's exit status is not a verdict; parse the summary instead.
    "$formal/tamarin-bounded.sh" --prove "$formal/$model.spthy" >"$output" 2>&1 || { echo "$model: prover failed or timed out; see $output" >&2; return 1; }
    grep -q 'summary of summaries' "$output" \
      || { echo "$model: Tamarin produced no summary" >&2; return 1; }
    if grep -qE 'WARNING:|analysis incomplete' "$output"; then
      echo "$model: tool warning or incomplete analysis" >&2; return 1
    fi
    python3 - "$formal/$model.spthy" "$output" <<'CHECK'
import re, sys
from pathlib import Path
model, log = map(Path, sys.argv[1:])
expected = set(re.findall(r'^lemma\s+(\w+)', model.read_text(), re.M))
summary = log.read_text().split('summary of summaries:')[-1]
actual = re.findall(r'^\s+(\w+) \((?:all-traces|exists-trace)\): (?:verified|falsified)', summary, re.M)
if set(actual) != expected or len(actual) != len(expected):
    sys.exit(f'{model.stem}: missing or unexpected named lemma verdicts')
CHECK
    local v
    v="$(grep -cE '^\s+[A-Za-z0-9_]+ \((all-traces|exists-trace)\): verified' "$output" || true)"
    verified=$((verified + v))
    while read -r lemma; do
      [[ -n "$lemma" ]] && falsified+="$model.$lemma"$'\n'
    done < <(sed -nE 's/^\s+([A-Za-z0-9_]+) \((all-traces|exists-trace)\): falsified.*/\1/p' "$output")
    echo "$model: $v verified"
  done
  falsified="$(printf '%s' "$falsified" | sort)"
  echo "total: $verified verified"
  echo "falsified:"; echo "$falsified"
  [[ "$verified" -eq 83 ]] || { echo "expected 83 verified" >&2; return 1; }
  [[ "$falsified" == "$(sort <<<"$expected_falsified")" ]] \
    || { echo "falsified set differs from the 5 intended impossibility results" >&2; return 1; }
}
credential_release
