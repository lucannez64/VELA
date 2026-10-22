#!/usr/bin/env bash
# Re-run every machine-checked VELA assurance artifact and keep the logs.
#
#   security/assurance/run-all.sh                 Tamarin + ProVerif + statistical ORAM
#   security/assurance/run-all.sh --with-fstar    also hax extraction + F* for all 7 policy crates
#   security/assurance/run-all.sh --out DIR       write logs to DIR (default: a new temp dir)
#
# Unlike CI, this also gates the M1-M10 credential-release theories: they must
# give exactly 83 verified lemmas and exactly the 5 intended falsifications.
#
# Toolchain: see 04-reproducibility.md. The script fails if any check fails,
# and prints a summary table at the end.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
formal="$repo_root/security/formal"
with_fstar=false
out_dir=""

while (($#)); do
  case "$1" in
    --with-fstar) with_fstar=true ;;
    --out) out_dir="$2"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

out_dir="${out_dir:-$(mktemp -d -t vela-assurance.XXXXXX)}"
mkdir -p "$out_dir"
export LC_ALL="${LC_ALL:-C.UTF-8}" LANG="${LANG:-C.UTF-8}"

declare -a names=() results=()
failed=0

record() { names+=("$1"); results+=("$2"); [[ "$2" == PASS* ]] || failed=1; }

run_step() {
  local name="$1"; shift
  local log="$out_dir/$name.log"
  echo "== $name"
  if "$@" >"$log" 2>&1; then
    record "$name" "PASS"
  else
    record "$name" "FAIL (see $log)"
    tail -20 "$log" >&2
  fi
}

# ── Tool versions ────────────────────────────────────────────────────────────
{
  echo "commit: $(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "dirty:  $(git -C "$repo_root" status --porcelain 2>/dev/null | wc -l) changed paths"
  echo "date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host:   $(uname -srm)"
  for cmd in "tamarin-prover --version" "maude --version" "proverif -help" \
             "rustc --version" "cargo --version" "cargo hax --version" \
             "fstar.exe --version" "z3-4.13.3 --version"; do
    printf '%-22s ' "${cmd% -*}:"
    (eval "$cmd" 2>/dev/null | head -1 | grep .) || echo "not installed"
  done
} | tee "$out_dir/versions.txt"

# ── Credential-release ladder M1-M10 (not in CI) ─────────────────────────────
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
    tamarin-prover --prove "$formal/$model.spthy" >"$output" 2>&1 || true
    grep -q 'summary of summaries' "$output" \
      || { echo "$model: Tamarin produced no summary" >&2; return 1; }
    if grep -qE 'WARNING:|analysis incomplete' "$output"; then
      echo "$model: tool warning or incomplete analysis" >&2; return 1
    fi
    local v
    v="$(grep -cE '^\s+[A-Za-z0-9_]+ \((all-traces|exists-trace)\): verified' "$output")"
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
run_step tamarin-m1-m10-credential-release credential_release

# ── CI-gated Tamarin families ────────────────────────────────────────────────
for runner in rekey session enrollment recovery client-recovery \
              recovery-publication recovery-publication-recovery pair-selection \
              share-channel web-session-pass-through link-revocation-finality \
              composition sync-admission; do
  run_step "tamarin-$runner" "$formal/run-$runner-proofs.sh"
done

# ── ProVerif and statistical ORAM ────────────────────────────────────────────
run_step proverif-m22-oram-access-hiding "$formal/run-oram-access-hiding-proofs.sh"
run_step statistical-m24-oram-stash-bounds "$formal/run-oram-stash-bounds-tests.sh"

# ── hax / F* (not in CI) ─────────────────────────────────────────────────────
if $with_fstar; then
  for crate in serverVELA/vela-rekey-policy serverVELA/vela-session-policy \
               serverVELA/vela-enrollment-policy serverVELA/vela-recovery-policy \
               serverVELA/vela-share-policy libVELA/vela-client-recovery-policy \
               libVELA/vela-sync-policy; do
    run_step "fstar-$(basename "$crate")" "$repo_root/$crate/verify-fstar.sh"
  done
fi

# ── Summary ──────────────────────────────────────────────────────────────────
{
  echo
  echo "VELA assurance run — logs in $out_dir"
  for i in "${!names[@]}"; do printf '  %-44s %s\n' "${names[$i]}" "${results[$i]}"; done
  $with_fstar || echo "  (hax/F* skipped; pass --with-fstar to include it)"
} | tee "$out_dir/summary.txt"

exit "$failed"
