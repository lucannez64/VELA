#!/usr/bin/env bash
set -euo pipefail

# Mutation checks for the F-1 sharing-executor proofs. Run after
# verify-fstar-share-executors.sh (it reuses that gate's extraction); that
# gate calls this script last.
#
# Each mutant is a copy of the extracted `Vela_share_policy.Store` under /tmp
# with one change, equal to a one-line change in `src/store.rs`; the
# checked-in extraction is never modified. The checked-in lemma module must
# FAIL against every mutant, and the named theorem must be among those that
# fail.
#
#   classify-error   classify_send maps a failed commit to Committed
#   classify-rows    classify_rows maps a failed statement to one row
#   plan-drop        plan_send_insert drops the share_inbox insert
#   plan-swap        plan_send_insert swaps sender and recipient in the inbox row
#   link-sender      classify_link compares the caller with nothing (always the sender)

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}

store=$proof_root/proofs/fstar/extraction-store/Vela_share_policy.Store.fst
model_dir=$proof_root/proofs/fstar/store-lemmas
lemmas=$model_dir/Vela_share_policy_store_lemmas.fst
mut=/tmp/vela-share-executor-mut
[[ -f $store && -f $lemmas ]] || { echo "run verify-fstar-share-executors.sh first" >&2; exit 1; }

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

mutants=(classify-error classify-rows plan-drop plan-swap link-sender)
declare -A expect=(
  [classify-error]=send_insert_is_honest
  [classify-rows]=link_update_is_honest
  [plan-drop]=send_insert_is_honest
  [plan-swap]=send_insert_is_honest
  [link-sender]=link_observation_is_honest
)

rm -rf "$mut"
failures=0
for name in "${mutants[@]}"; do
  [[ $want == all || $want == "$name" ]] || continue
  d=$mut/$name
  mkdir -p "$d/store" "$d/lemmas"
  cp "$store" "$d/store/"
  cp "$model_dir"/*.fst "$d/lemmas/"
  python3 - "$name" "$d/store/Vela_share_policy.Store.fst" <<'PY'
import sys, pathlib, re
name, path = sys.argv[1], pathlib.Path(sys.argv[2])
text = path.read_text()
def once(old, new):
    global text
    if text.count(old) != 1:
        sys.exit(f'{name}: expected exactly one match for {old!r}, found {text.count(old)}')
    text = text.replace(old, new)
if name == 'classify-error':
    once('| WriteOutcome_Applied _, WriteOutcome_Applied _, WriteOutcome_Failed  ->\n'
         '      Vela_share_policy.Driver.SendResultObservation_CommitConflict',
         '| WriteOutcome_Applied _, WriteOutcome_Applied _, WriteOutcome_Failed  ->\n'
         '      Vela_share_policy.Driver.SendResultObservation_Committed')
elif name == 'classify-rows':
    start = text.index('let classify_rows')
    end = text.index('let classify_cleanup')
    body = text[start:end]
    old = '| WriteOutcome_Failed  ->\n      { Vela_share_policy.Driver.f_rows = mk_u64 0 }'
    if body.count(old) != 1:
        sys.exit(f'{name}: classify_rows shape changed')
    text = text[:start] + body.replace(old, '| WriteOutcome_Failed  ->\n      { Vela_share_policy.Driver.f_rows = mk_u64 1 }') + text[end:]
elif name == 'plan-drop':
    start = text.index('let plan_send_insert')
    end = text.index('let plan_link_read')
    body = text[start:end]
    body2 = re.sub(r'\n\s*ShareStmt_InsertInboxItem\n\s*\(\{.*?\}\)\n\s*<:\n\s*t_ShareStmt;', '', body, count=1, flags=re.S)
    if body2 == body:
        sys.exit(f'{name}: inbox insert not found')
    body2 = body2.replace('(List.Tot.length list) 3', '(List.Tot.length list) 2').replace('array_of_list 3 list', 'array_of_list 2 list')
    text = text[:start] + body2 + text[end:]
elif name == 'plan-swap':
    start = text.index('ShareStmt_InsertInboxItem\n')
    end = text.index('ShareStmt_Commit', start)
    body = text[start:end]
    body2 = body.replace('f_sender = sender', 'f_sender = recipient').replace('f_recipient = recipient', 'f_recipient = sender')
    if body2 == body:
        sys.exit(f'{name}: inbox fields not found')
    text = text[:start] + body2 + text[end:]
elif name == 'link-sender':
    once('| Core_models.Option.Option_Some sender -> sender =. caller', '| Core_models.Option.Option_Some sender -> true')
path.write_text(text)
PY
  set +e
  out=$(fstar.exe --cmi --cache_off --warn_error -331 --z3rlimit 200 --z3version 4.13.3 \
    --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
    --include "$hax_lib_root/proof-libs/fstar/core" \
    --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
    --include "$hax_lib_root/proofs/fstar/extraction" \
    --include "$proof_root/proofs/fstar/extraction-driver" \
    --include "$proof_root/proofs/fstar/extraction-send-driver" \
    --include "$d/store" --include "$d/lemmas" \
    "$d/lemmas/Vela_share_policy_store_lemmas.fst" 2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo "mutant $name: VERIFIED (the proof does not depend on it)" >&2
    failures=$((failures + 1))
    continue
  fi
  # Every theorem with an error; the expected one must be among them.
  rejected=$(grep -oE 'Vela_share_policy_store_lemmas\.fst\(([0-9]+),' <<<"$out" | grep -oE '[0-9]+' | sort -un |
    while read -r line; do head -n "$line" "$lemmas" | grep -oE '^let [a-z_0-9]+' | tail -n1 | cut -d' ' -f2; done | sort -u | tr '\n' ' ')
  if [[ " $rejected " != *" ${expect[$name]} "* ]]; then
    echo "mutant $name: rejected at [${rejected% }], expected ${expect[$name]}:" >&2
    grep -m5 -E 'Error' <<<"$out" >&2 || true
    failures=$((failures + 1))
    continue
  fi
  echo "mutant $name: rejected at ${rejected% }"
done
(( failures == 0 )) || { echo "$failures mutation check(s) failed" >&2; exit 1; }
echo "share executor mutations: every mutant rejected at its theorem"
