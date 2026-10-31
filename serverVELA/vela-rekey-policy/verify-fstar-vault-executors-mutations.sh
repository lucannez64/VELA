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
mut=$(mktemp -d "${TMPDIR:-/tmp}/vela-vault-executor-mut.XXXXXX")
# A fresh directory per run: CI runners and local runs share the build box.
trap 'rm -rf "$mut"' EXIT
[[ -f $store && -f $lemmas ]] || { echo "run verify-fstar-vault-executors.sh first" >&2; exit 1; }

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

mutants=(classify-error classify-rows classify-ack plan-swap plan-drop guard-drop
         freeze-oram commit-shadows commit-devices
         key-state-failed key-state-missing usage-error usage-swap projection-error
         oram-error oram-plan sync-error sync-plan schema-error schema-plan
         capsule-error capsule-clear-error devices-error devices-plan
         begin-drop begin-fault)
declare -A expect=(
  [classify-error]=delete_chunk_is_honest
  [classify-rows]=chunk_update_is_honest
  [classify-ack]=ack_capsule_is_honest
  [plan-swap]=write_capsule_is_honest
  [plan-drop]=freeze_transaction_is_honest
  [guard-drop]=delete_chunk_is_honest
  [freeze-oram]=freeze_requires_a_clean_account
  [commit-shadows]=commit_publishes_complete_chunks
  [commit-devices]=commit_publishes_complete_devices
  [key-state-failed]=key_state_is_honest
  [key-state-missing]=key_state_is_honest
  [usage-error]=usage_is_honest
  [usage-swap]=usage_is_honest
  [projection-error]=projection_is_honest
  [oram-error]=oram_read_is_honest
  [oram-plan]=oram_read_is_honest
  [sync-error]=sync_is_honest
  [sync-plan]=sync_is_honest
  [schema-error]=schema_floor_read_is_honest
  [schema-plan]=schema_floor_read_is_honest
  [capsule-error]=capsule_read_is_honest
  [capsule-clear-error]=capsule_clear_is_honest
  [devices-error]=device_list_is_honest
  [devices-plan]=device_list_is_honest
  [begin-drop]=begin_plan_is_one_statement
  [begin-fault]=begin_transaction_is_honest
)

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
elif name == 'key-state-failed':
    once('| ReadOutcome_Failed  -> KeyStateObservation_Storage <: t_KeyStateObservation',
         '| ReadOutcome_Failed  -> KeyStateObservation_NotFound <: t_KeyStateObservation')
elif name == 'key-state-missing':
    once('''    KeyStateObservation_NotFound <: t_KeyStateObservation''',
         '''    KeyStateObservation_Storage <: t_KeyStateObservation''')
elif name == 'usage-error':
    once('| _ -> UsageObservation_Storage <: t_UsageObservation',
         '| _ -> UsageObservation_Measured ({ f_chunks = mk_i64 0; f_oram = mk_i64 0 }) <: t_UsageObservation')
elif name == 'usage-swap':
    once('VaultStmt_SelectUsageChunks ({ f_user = user })',
         'VaultStmt_SelectUsageOram ({ f_user = user })')
elif name == 'projection-error':
    once('| ReadOutcome_Failed  -> ProjectedUsageObservation_Storage <: t_ProjectedUsageObservation',
         '| ReadOutcome_Failed  -> ProjectedUsageObservation_Measured (mk_i64 0) <: t_ProjectedUsageObservation')
elif name == 'oram-error':
    once('| ReadOutcome_Failed  -> OramReadObservation_Storage <: t_OramReadObservation',
         '| ReadOutcome_Failed  -> OramReadObservation_Missing <: t_OramReadObservation')
elif name == 'oram-plan':
    once('VaultStmt_SelectOramRow\n  ({ f_user = user; f_tree_id = tree_id; f_bucket_index = bucket_index; f_epoch = epoch })',
         'VaultStmt_SelectOramRow\n  ({ f_user = user; f_tree_id = tree_id; f_bucket_index = bucket_index; f_epoch = epoch +. mk_i64 1 })')
elif name == 'sync-error':
    once('| ReadOutcome_Failed  -> SyncObservation_Failed <: t_SyncObservation',
         '| ReadOutcome_Failed  -> SyncObservation_Read <: t_SyncObservation')
elif name == 'sync-plan':
    once('VaultStmt_SelectSyncManifest ({ f_user = user; f_epoch = epoch })',
         'VaultStmt_SelectSyncManifest ({ f_user = user; f_epoch = epoch +. mk_i64 1 })')
elif name == 'schema-error':
    once('| ReadOutcome_Failed  -> SchemaFloorObservation_Storage <: t_SchemaFloorObservation',
         '| ReadOutcome_Failed  -> SchemaFloorObservation_Stored Core_models.Option.Option_None <: t_SchemaFloorObservation')
elif name == 'schema-plan':
    once('VaultStmt_SchemaFloorGet ({ f_key = key })',
         'VaultStmt_SchemaFloorGet ({ f_key = Alloc.String.impl_String__new () })')
elif name == 'capsule-error':
    once('| ReadOutcome_Failed  -> CapsuleReadObservation_Storage <: t_CapsuleReadObservation',
         '| ReadOutcome_Failed  -> CapsuleReadObservation_Missing <: t_CapsuleReadObservation')
elif name == 'capsule-clear-error':
    once('| WriteOutcome_Failed  -> CapsuleClearObservation_Storage <: t_CapsuleClearObservation',
         '| WriteOutcome_Failed  -> CapsuleClearObservation_Cleared <: t_CapsuleClearObservation')
elif name == 'devices-error':
    once('| ReadOutcome_Failed  -> DeviceListObservation_Failed <: t_DeviceListObservation',
         '| ReadOutcome_Failed  -> DeviceListObservation_Read <: t_DeviceListObservation')
elif name == 'devices-plan':
    once('VaultStmt_SelectDeviceList ({ f_user = user })',
         'VaultStmt_SelectDeviceList ({ f_user = Alloc.String.impl_String__new () })')
elif name == 'begin-drop':
    start, end, body = section('let plan_begin_transaction', 'let plan_load_key_state')
    body2 = body.replace('[VaultStmt_BeginTransaction <: t_VaultStmt]', '[]')
    body2 = body2.replace('(List.Tot.length list) 1', '(List.Tot.length list) 0')
    body2 = body2.replace('array_of_list 1 list', 'array_of_list 0 list')
    text = text[:start] + body2 + text[end:]
else:
    # The remaining mutants edit the hand-written model, not the store.
    mt = model_path.read_text()

    def model_once(old, new):
        global mt
        if mt.count(old) != 1:
            sys.exit(f'{name}: expected exactly one model match for {old!r}, found {mt.count(old)}')
        mt = mt.replace(old, new)

    if name == 'guard-drop':
        model_once(
            '''    if Some? (find_chunk d.chunks key) && active_at d user epoch
    then Some (mk_u64 1, { d with chunks = remove_chunk d.chunks key })''',
            '''    if Some? (find_chunk d.chunks key)
    then Some (mk_u64 1, { d with chunks = remove_chunk d.chunks key })''')
    elif name == 'freeze-oram':
        model_once(
            '''    r.us_key_epoch = from_epoch && r.us_rekey_state = None &&
    not (any_oram d user) && not (any_incapable d user) &&
    not (any_pending_capsule d user)''',
            '''    r.us_key_epoch = from_epoch && r.us_rekey_state = None &&
    not (any_incapable d user) &&
    not (any_pending_capsule d user)''')
    elif name == 'commit-shadows':
        model_once(
            '''    r.us_rotation = Some rotation && not (any_missing_shadow d user from_epoch to_epoch) &&
    not (any_incomplete_device d user to_epoch)''',
            '''    r.us_rotation = Some rotation &&
    not (any_incomplete_device d user to_epoch)''')
    elif name == 'commit-devices':
        model_once(
            '''    r.us_rotation = Some rotation && not (any_missing_shadow d user from_epoch to_epoch) &&
    not (any_incomplete_device d user to_epoch)''',
            '''    r.us_rotation = Some rotation && not (any_missing_shadow d user from_epoch to_epoch)''')
    elif name == 'begin-fault':
        model_once(
            """      if faulted f k
      then [WriteOutcome_Failed]
      else WriteOutcome_Applied (mk_u64 0) :: run_begin d rest (k + 1) f""",
            """      WriteOutcome_Applied (mk_u64 0) :: run_begin d rest (k + 1) f""")
    else:
        sys.exit(f'{name}: unknown mutant')
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
echo "vault executor mutations: every mutant rejected at its theorem"
