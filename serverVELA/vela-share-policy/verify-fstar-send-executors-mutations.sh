#!/usr/bin/env bash
set -euo pipefail

# Mutation checks for the F-1 one-off share-link executor proofs. Run after
# verify-fstar-send-executors.sh (it reuses that gate's extraction); that gate
# calls this script last.
#
# Each mutant is a copy of the extracted `Vela_share_policy.Store` under /tmp
# with one change, equal to a one-line change in `src/store.rs`; the checked-in
# extraction is never modified. The lemma module must FAIL against every
# mutant, and the named theorem must be among those that fail.
#
#   create-plan-swap   the create plan stores the id as the owner
#   consume-classify   a zero-row consume is classified as Consumed
#   remove-plan-drop   the view-once cleanup plans no statement
#   delete-rows        the owner-scoped delete reports one row for any run
#   read-view-once     the fetched view_once is inverted

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}

store=$proof_root/proofs/fstar/extraction-store/Vela_share_policy.Store.fst
model_dir=$proof_root/proofs/fstar/store-lemmas
lemmas_dir=$proof_root/proofs/fstar/send-store-lemmas
lemmas=$lemmas_dir/Vela_share_policy_send_store_lemmas.fst
mut=$(mktemp -d "${TMPDIR:-/tmp}/vela-send-executor-mut.XXXXXX")
# A fresh directory per run: CI runners and local runs share the build box.
trap 'rm -rf "$mut"' EXIT
[[ -f $store && -f $lemmas ]] || { echo "run verify-fstar-send-executors.sh first" >&2; exit 1; }

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

mutants=(create-plan-swap consume-classify remove-plan-drop delete-rows read-view-once)
declare -A expect=(
  [create-plan-swap]=send_create_is_honest
  [consume-classify]=send_consume_is_honest
  [remove-plan-drop]=send_remove_is_honest
  [delete-rows]=send_delete_is_honest
  [read-view-once]=send_read_is_honest
)

failures=0
for name in "${mutants[@]}"; do
  [[ $want == all || $want == "$name" ]] || continue
  d=$mut/$name
  mkdir -p "$d/store" "$d/lemmas"
  cp "$store" "$d/store/"
  cp "$model_dir/Vela_share_policy_store_model.fst" "$d/lemmas/"
  cp "$lemmas" "$d/lemmas/"
  python3 - "$name" "$d/store/Vela_share_policy.Store.fst" <<'PY'
import sys, pathlib
name, path = sys.argv[1], pathlib.Path(sys.argv[2])
text = path.read_text()

def once(old, new):
    global text
    if text.count(old) != 1:
        sys.exit(f'{name}: expected exactly one match for {old!r}, found {text.count(old)}')
    text = text.replace(old, new)

def body(start_marker, end_marker):
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return start, end

if name == 'create-plan-swap':
    start, end = body('let plan_send_create', 'let plan_send_consume')
    plan = text[start:end]
    if plan.count('f_owner = owner;') != 1:
        sys.exit('create-plan-swap: owner field not found')
    text = text[:start] + plan.replace('f_owner = owner;', 'f_owner = id;') + text[end:]
elif name == 'consume-classify':
    start, end = body('let classify_send_consume', 'let classify_send_remove')
    body_ = text[start:end]
    old = ('| WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->\n'
           '      Vela_share_policy.Send_driver.ConsumeObservation_Unavailable')
    if body_.count(old) != 1:
        sys.exit('consume-classify: zero-row branch not found')
    text = (text[:start]
            + body_.replace(old, old.replace('_Unavailable', '_Consumed'))
            + text[end:])
elif name == 'remove-plan-drop':
    start, end = body('let plan_send_remove', 'let plan_send_delete')
    replacement = (
        'let plan_send_remove (id: Alloc.String.t_String)\n'
        '    : Alloc.Vec.t_Vec t_SendStmt Alloc.Alloc.t_Global =\n'
        '  Alloc.Slice.impl__into_vec #t_SendStmt\n'
        '    #Alloc.Alloc.t_Global\n'
        '    ((let list = [] in\n'
        '        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);\n'
        '        Rust_primitives.Hax.array_of_list 0 list)\n'
        '      <:\n'
        '      t_Slice t_SendStmt)\n\n')
    text = text[:start] + replacement + text[end:]
elif name == 'delete-rows':
    start, end = body('let classify_send_delete', 'let classify_send_read')
    body_ = text[start:end]
    if body_.count('f_rows = rows;') != 1:
        sys.exit('delete-rows: applied branch not found')
    text = text[:start] + body_.replace('f_rows = rows;', 'f_rows = mk_u64 1;') + text[end:]
elif name == 'read-view-once':
    # `classify_send_read` is the last definition in the extracted module.
    start = text.index('let classify_send_read')
    body_ = text[start:]
    old = 'Vela_share_policy.Send_driver.f_view_once = view_once }'
    if body_.count(old) != 1:
        sys.exit('read-view-once: payload verdict not found')
    text = text[:start] + body_.replace(old, 'Vela_share_policy.Send_driver.f_view_once = true }')
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
    "$d/lemmas/Vela_share_policy_send_store_lemmas.fst" 2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo "mutant $name: VERIFIED (the proof does not depend on it)" >&2
    failures=$((failures + 1))
    continue
  fi
  # Every theorem with an error; the expected one must be among them.
  rejected=$(grep -oE 'Vela_share_policy_send_store_lemmas\.fst\(([0-9]+),' <<<"$out" | grep -oE '[0-9]+' | sort -un |
    while read -r line; do head -n "$line" "$lemmas" | grep -oE '^let [a-z_0-9]+' | tail -n1 | cut -d' ' -f2; done | sort -u | tr '\n' ' ') || true
  if [[ -z ${rejected// /} ]]; then
    # No lemma error: F* was killed or failed elsewhere. Say so instead of exiting silently.
    echo "mutant $name: F* exited $status without an error in the lemma module; last output:" >&2
    tail -n 20 <<<"$out" >&2
    failures=$((failures + 1))
    continue
  fi
  if [[ " $rejected " != *" ${expect[$name]} "* ]]; then
    echo "mutant $name: rejected at [${rejected% }], expected ${expect[$name]}:" >&2
    grep -m5 -E 'Error' <<<"$out" >&2 || true
    failures=$((failures + 1))
    continue
  fi
  echo "mutant $name: rejected at ${rejected% }"
done
(( failures == 0 )) || { echo "$failures mutation check(s) failed" >&2; exit 1; }
echo "send executor mutations: every mutant rejected at its theorem"
