#!/usr/bin/env bash
set -euo pipefail

# Mutation checks for the F-1 executor proofs. Run after
# verify-fstar-vault-executors.sh has produced the extraction; that gate calls
# this script last.
#
# Each mutant is a copy of the extracted `Vela_rekey_policy.Executor` (or of the
# hand-written model) under /tmp with one change, equal to a one-line change in
# `src/executor.rs` (or in the model). The checked-in extraction and model are
# never modified. The checked-in lemma module must FAIL against every mutant,
# and the named theorem must be among those that fail.
#
#   classify-error   classify_delete reports a zero-row delete as Deleted
#   classify-rows    classify_chunk_update reports a zero-row CAS as Updated
#   classify-ack     classify_ack reports a zero-row ACK as Cleared
#   plan-swap        plan_write_capsule writes the caller's device capsule to
#                    the target device id
#   plan-drop        plan_commit_transaction drops the transaction commit
#   guard-drop       the model's chunk delete ignores the account-epoch guard

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}

store=$proof_root/proofs/fstar/extraction-executor/Vela_rekey_policy.Executor.fst
model_dir=$proof_root/proofs/fstar/executor-lemmas
model=$model_dir/Vela_rekey_policy_executor_model.fst
lemmas=$model_dir/Vela_rekey_policy_executor_lemmas.fst
mut=/tmp/vela-vault-executor-mut
[[ -f $store && -f $lemmas ]] || { echo "run verify-fstar-vault-executors.sh first" >&2; exit 1; }

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

mutants=(classify-error classify-rows classify-ack plan-swap plan-drop guard-drop)
declare -A expect=(
  [classify-error]=delete_chunk_is_honest
  [classify-rows]=chunk_update_is_honest
  [classify-ack]=ack_capsule_is_honest
  [plan-swap]=write_capsule_is_honest
  [plan-drop]=freeze_transaction_is_honest
  [guard-drop]=delete_chunk_is_honest
)

rm -rf "$mut"
failures=0
for name in "${mutants[@]}"; do
  [[ $want == all || $want == "$name" ]] || continue
  d=$mut/$name
  mkdir -p "$d/store" "$d/lemmas"
  cp "$store" "$d/store/"
  cp "$model_dir"/*.fst "$d/lemmas/"
  python3 - "$name" "$d/store/Vela_rekey_policy.Executor.fst" \
    "$d/lemmas/Vela_rekey_policy_executor_model.fst" <<'PY'
import sys, pathlib, re
name, store_path, model_path = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
text = store_path.read_text()

def once(old, new):
    global text
    if text.count(old) != 1:
        sys.exit(f'{name}: expected exactly one match for {old!r}, found {text.count(old)}')
    text = text.replace(old, new)

def section(start_marker, end_marker):
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return start, end, text[start:end]

if name == 'classify-error':
    start, end, body = section('let classify_delete', 'let classify_chunk_read')
    old = ('WriteOutcome_Applied _ ->\n'
           '      Vela_rekey_policy.Vault_mutation_driver.DeleteObservation_Skipped')
    if body.count(old) != 1:
        sys.exit(f'{name}: classify_delete shape changed')
    text = text[:start] + body.replace(
        old,
        'WriteOutcome_Applied _ ->\n'
        '      Vela_rekey_policy.Vault_mutation_driver.DeleteObservation_Deleted',
    ) + text[end:]
elif name == 'classify-rows':
    start, end, body = section('let classify_chunk_update', 'let classify_inventory')
    old = ('WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->\n'
           '      Vela_rekey_policy.Vault_upload_driver.WriteObservation_Skipped')
    if body.count(old) != 1:
        sys.exit(f'{name}: classify_chunk_update shape changed')
    text = text[:start] + body.replace(
        old,
        'WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->\n'
        '      Vela_rekey_policy.Vault_upload_driver.WriteObservation_Updated',
    ) + text[end:]
elif name == 'classify-ack':
    start, end, body = section('let classify_ack', 'let classify_attest')
    old = ('WriteOutcome_Applied _ ->\n'
           '      Vela_rekey_policy.Vault_mutation_driver.AckObservation_Missed')
    if body.count(old) != 1:
        sys.exit(f'{name}: classify_ack shape changed')
    text = text[:start] + body.replace(
        old,
        'WriteOutcome_Applied _ ->\n'
        '      Vela_rekey_policy.Vault_mutation_driver.AckObservation_Cleared',
    ) + text[end:]
elif name == 'plan-swap':
    start, end, body = section('let plan_write_capsule', 'let plan_ack_capsule')
    old = 'f_device = device;\n                f_user = user;'
    if body.count(old) != 1:
        sys.exit(f'{name}: capsule fields not found')
    text = text[:start] + body.replace(
        old, 'f_device = user;\n                f_user = device;') + text[end:]
elif name == 'plan-drop':
    start, end, body = section('let plan_commit_transaction', 'let plan_commit_cas')
    old = ('[VaultStmt_Commit <: t_VaultStmt]')
    if body.count(old) != 1:
        sys.exit(f'{name}: commit plan shape changed')
    body2 = body.replace(old, '[]')
    body2 = body2.replace('(List.Tot.length list) 1', '(List.Tot.length list) 0')
    body2 = body2.replace('array_of_list 1 list', 'array_of_list 0 list')
    text = text[:start] + body2 + text[end:]
else:
    # guard-drop mutates the hand-written model, not the store.
    mt = model_path.read_text()
    old = '''    let key = mk_ckey user id epoch in
    if Some? (d.chunks key) && active_at d user epoch
    then Some (mk_u64 1, { d with chunks = upd_chunks d.chunks key None })
    else Some (mk_u64 0, d)'''
    if mt.count(old) != 1:
        sys.exit(f'{name}: model delete shape changed')
    mt = mt.replace(old, '''    let key = mk_ckey user id epoch in
    if Some? (d.chunks key)
    then Some (mk_u64 1, { d with chunks = upd_chunks d.chunks key None })
    else Some (mk_u64 0, d)''')
    model_path.write_text(mt)

store_path.write_text(text)
PY
  set +e
  out=$(fstar.exe --cmi --cache_off --warn_error -331 --z3rlimit 100 --z3version 4.13.3 \
    --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
    --include "$hax_lib_root/proof-libs/fstar/core" \
    --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
    --include "$hax_lib_root/proofs/fstar/extraction" \
    --include "$proof_root/proofs/fstar/extraction-executor" \
    --include "$d/store" --include "$d/lemmas" \
    "$d/lemmas/Vela_rekey_policy_executor_lemmas.fst" 2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo "mutant $name: VERIFIED (the proof does not depend on it)" >&2
    failures=$((failures + 1))
    continue
  fi
  # Every theorem with an error; the expected one must be among them.
  rejected=$(grep -oE 'Vela_rekey_policy_executor_lemmas\.fst\(([0-9]+),' <<<"$out" | grep -oE '[0-9]+' | sort -un |
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
echo "vault executor mutations: every mutant rejected at its theorem"
