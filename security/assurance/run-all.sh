#!/usr/bin/env bash
# Re-run every machine-checked VELA assurance artifact and keep the logs.
#
#   security/assurance/run-all.sh                 Tamarin + ProVerif + statistical ORAM
#   security/assurance/run-all.sh --with-fstar    also hax extraction + F* for all 8 policy crates
#   security/assurance/run-all.sh --out DIR       write logs to DIR (default: a new temp dir)
#
# CI and this runner both gate the M1-M10 credential-release theories: they must
# give exactly 83 verified lemmas and exactly the 5 intended falsifications.
#
# Toolchain: see 04-reproducibility.md. The script fails if any check fails,
# and prints a summary table at the end.
set -uo pipefail

if [[ ${VELA_BOUNDED:-0} != 1 ]]; then
  exec "$(dirname "$0")/bounded.sh" "$0" "$@"
fi
export CARGO_BUILD_JOBS="${VELA_CARGO_JOBS:-1}" OPAMJOBS=1 MAKEFLAGS=-j1

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
formal="$repo_root/security/formal"
with_fstar=false
out_dir=""

while (($#)); do
  case "$1" in
    --with-fstar) with_fstar=true ;;
    --out) [[ $# -ge 2 && -n "$2" ]] || { echo "--out requires a directory" >&2; exit 2; }; out_dir="$2"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

out_dir="${out_dir:-$(mktemp -d -t vela-assurance.XXXXXX)}"
mkdir -p "$out_dir"
export LC_ALL="${LC_ALL:-C.UTF-8}" LANG="${LANG:-C.UTF-8}"

# All existing family runners resolve tamarin-prover through this bounded shim.
export VELA_TAMARIN_BIN="$(command -v tamarin-prover || true)"
[[ -n "$VELA_TAMARIN_BIN" ]] || { echo "tamarin-prover is missing" >&2; exit 2; }
shim=$(mktemp -d -t vela-prover-shim.XXXXXX)
trap 'rm -rf -- "$shim"' EXIT
ln -s "$formal/tamarin-bounded.sh" "$shim/tamarin-prover"
export PATH="$shim:$PATH"

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

run_step correspondence python3 "$formal/check-correspondence.py"
run_step share-journal env VELA_PROOF_OUT="$out_dir/share-journal" "$formal/run-share-journal-proofs.sh"
run_step network-boundaries env VELA_PROOF_OUT="$out_dir/network" "$formal/run-network-boundary-proofs.sh"

# ── Credential-release ladder M1-M10 (not in CI) ─────────────────────────────
run_step tamarin-m1-m10-credential-release env VELA_PROOF_OUT="$out_dir/credential-release" "$formal/run-credential-release-proofs.sh"


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

# ── hax / F* ─────────────────────────────────────────────────────
if $with_fstar; then
  for crate in serverVELA/vela-rekey-policy serverVELA/vela-session-policy \
               serverVELA/vela-enrollment-policy serverVELA/vela-recovery-policy \
               serverVELA/vela-share-policy libVELA/vela-client-recovery-policy \
               libVELA/vela-sync-policy libVELA/vela-client-share-policy; do
    run_step "fstar-$(basename "$crate")" "$repo_root/$crate/verify-fstar.sh"
  done
  run_step share-facts-fstar "$repo_root/libVELA/vela-crypto/verify-share-facts-fstar.sh"
  run_step proof-boundary python3 "$repo_root/security/assurance/check-proof-boundary.py"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
{
  echo
  echo "VELA assurance run — logs in $out_dir"
  for i in "${!names[@]}"; do printf '  %-44s %s\n' "${names[$i]}" "${results[$i]}"; done
  $with_fstar || echo "  (Rust extraction/policy checks skipped; pass --with-fstar to include them; journal F* encoding check still runs)"
} | tee "$out_dir/summary.txt"

exit "$failed"
