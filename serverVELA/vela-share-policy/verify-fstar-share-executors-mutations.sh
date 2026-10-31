#!/usr/bin/env bash
set -euo pipefail

# Mutation checks for the F-1 sharing-executor proofs, including the wave-2
# handler reads, sweeps and rate limiters. Run after
# verify-fstar-share-executors.sh (it reuses that gate's extraction); that gate
# calls this script last.
#
# Each mutant is a copy of the extracted `Vela_share_policy.Store` under a
# scratch directory with one change, equal to a one-line change in
# `src/store.rs`; the checked-in extraction is never modified. The named lemma
# module must FAIL against every mutant, and the expected theorem must be among
# those that fail.
#
#   classify-error        classify_send maps a failed commit to Committed
#   classify-rows         classify_rows maps a failed statement to one row
#   plan-drop             plan_send_insert drops the share_inbox insert
#   plan-swap             plan_send_insert swaps sender and recipient
#   link-sender           classify_link compares the caller with nothing
#   admission-classify    a ready admission is reported as a failed begin
#   admission-swap        the pair quota read filters by the wrong party
#   probe-empty           the recipient gate accepts an empty share key
#   page-has-more         a page that fit reports that more rows exist
#   page-before           the inbox page drops the caller's cursor
#   sweep-classify        a failed sweep reports success
#   sweep-swap            the inbox sweep plans the one-off-link delete
#   linked-limit          the linked-items page is planned with size 0
#   rate-allow            a counter at the budget is refused (off by one)
#   rate-fail             a failed store operation is reported as allowed

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
want=${1:-all}

store=$proof_root/proofs/fstar/extraction-store/Vela_share_policy.Store.fst
model_dir=$proof_root/proofs/fstar/store-lemmas
handler_dir=$proof_root/proofs/fstar/handler-lemmas
mut=$(mktemp -d "${TMPDIR:-/tmp}/vela-share-executor-mut.XXXXXX")
# A fresh directory per run: CI runners and local runs share the build box.
trap 'rm -rf "$mut"' EXIT
[[ -f $store && -f $model_dir/Vela_share_policy_store_lemmas.fst \
   && -f $handler_dir/Vela_share_policy_handler_lemmas.fst ]] || {
  echo "run verify-fstar-share-executors.sh first" >&2
  exit 1
}

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

mutants=(
  classify-error classify-rows plan-drop plan-swap link-sender
  admission-classify admission-swap probe-empty page-has-more page-before
  sweep-classify sweep-swap linked-limit rate-allow rate-fail
)
declare -A expect=(
  [classify-error]=send_insert_is_honest
  [classify-rows]=link_update_is_honest
  [plan-drop]=send_insert_is_honest
  [plan-swap]=send_insert_is_honest
  [link-sender]=link_observation_is_honest
  [admission-classify]=send_admission_is_honest
  [admission-swap]=admission_plan
  [probe-empty]=recipient_probe_is_honest
  [page-has-more]=pagination_is_honest
  [page-before]=inbox_page_plan_facts
  [sweep-classify]=inbox_sweep_is_honest
  [sweep-swap]=inbox_sweep_is_honest
  [linked-limit]=linked_items_plan_facts
  [rate-allow]=rate_limit_is_honest
  [rate-fail]=rate_limit_is_honest
)
# Which lemma module each mutant must be rejected by.
declare -A target=(
  [classify-error]=store
  [classify-rows]=store
  [plan-drop]=store
  [plan-swap]=store
  [link-sender]=store
  [admission-classify]=handler
  [admission-swap]=handler
  [probe-empty]=handler
  [page-has-more]=handler
  [page-before]=handler
  [sweep-classify]=handler
  [sweep-swap]=handler
  [linked-limit]=handler
  [rate-allow]=handler
  [rate-fail]=handler
)

failures=0
for name in "${mutants[@]}"; do
  [[ $want == all || $want == "$name" ]] || continue
  d=$mut/$name
  mkdir -p "$d/store" "$d/lemmas"
  cp "$store" "$d/store/"
  cp "$model_dir"/*.fst "$d/lemmas/"
  if [[ ${target[$name]} == handler ]]; then
    cp "$handler_dir"/Vela_share_policy_handler_lemmas.fst "$d/lemmas/"
    module=$d/lemmas/Vela_share_policy_handler_lemmas.fst
    module_name=Vela_share_policy_handler_lemmas
  else
    module=$d/lemmas/Vela_share_policy_store_lemmas.fst
    module_name=Vela_share_policy_store_lemmas
  fi
  python3 - "$name" "$d/store/Vela_share_policy.Store.fst" <<'PY'
import sys, pathlib, re
name, path = sys.argv[1], pathlib.Path(sys.argv[2])
text = path.read_text()

def once(old, new):
    global text
    if text.count(old) != 1:
        sys.exit(f'{name}: expected exactly one match for {old!r}, found {text.count(old)}')
    text = text.replace(old, new)

def body_between(start_marker, end_marker):
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return start, end, text[start:end]

if name == 'classify-error':
    once('| WriteOutcome_Applied _, WriteOutcome_Applied _, WriteOutcome_Failed  ->\n'
         '      Vela_share_policy.Driver.SendResultObservation_CommitConflict',
         '| WriteOutcome_Applied _, WriteOutcome_Applied _, WriteOutcome_Failed  ->\n'
         '      Vela_share_policy.Driver.SendResultObservation_Committed')
elif name == 'classify-rows':
    start, end, body = body_between('let classify_rows', 'let classify_cleanup')
    old = '| WriteOutcome_Failed  ->\n      { Vela_share_policy.Driver.f_rows = mk_u64 0 }'
    if body.count(old) != 1:
        sys.exit(f'{name}: classify_rows shape changed')
    text = text[:start] + body.replace(old, '| WriteOutcome_Failed  ->\n      { Vela_share_policy.Driver.f_rows = mk_u64 1 }') + text[end:]
elif name == 'plan-drop':
    start, end, body = body_between('let plan_send_insert', 'let plan_link_read')
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
elif name == 'admission-classify':
    start, end, body = body_between('let classify_send_admission', 'let classify_recipient_ek')
    if body.count('AdmissionStage_Ready') != 1:
        sys.exit(f'{name}: ready branch not found')
    text = text[:start] + body.replace('AdmissionStage_Ready', 'AdmissionStage_Begin') + text[end:]
elif name == 'admission-swap':
    start, end, body = body_between('let plan_send_admission', 'let plan_recipient_ek')
    body2 = body.replace('f_sender = sender', 'f_sender = recipient')
    if body2 == body:
        sys.exit(f'{name}: pair quota fields not found')
    text = text[:start] + body2 + text[end:]
elif name == 'probe-empty':
    once('~.(ek =. (Alloc.String.impl_String__new () <: Alloc.String.t_String) <: bool)', 'true')
elif name == 'page-has-more':
    start, end, body = body_between('let classify_listing', 'let classify_sweep')
    old = 'else { f_keep = returned; f_has_more = false; f_failed = false }'
    if body.count(old) != 1:
        sys.exit(f'{name}: classify_listing shape changed')
    text = text[:start] + body.replace(old, 'else { f_keep = returned; f_has_more = true; f_failed = false }') + text[end:]
elif name == 'page-before':
    start, end, body = body_between('let plan_inbox_page', 'let plan_linked_items')
    body2 = body.replace('f_before = before', 'f_before = Core_models.Option.Option_None')
    if body2 == body:
        sys.exit(f'{name}: inbox page fields not found')
    text = text[:start] + body2 + text[end:]
elif name == 'sweep-classify':
    start, end, body = body_between('let classify_sweep', 'let classify_rate_limit')
    old = '| HandlerOutcome_Failed  -> { f_purged = mk_u64 0; f_failed = true }'
    if body.count(old) != 1:
        sys.exit(f'{name}: classify_sweep shape changed')
    text = text[:start] + body.replace(old, '| HandlerOutcome_Failed  -> { f_purged = mk_u64 0; f_failed = false }') + text[end:]
elif name == 'sweep-swap':
    once('let plan_expired_inbox_cleanup (cutoff: Alloc.String.t_String) : t_HandlerStmt =\n'
         '  HandlerStmt_DeleteExpiredInbox ({ f_cutoff = cutoff }) <: t_HandlerStmt',
         'let plan_expired_inbox_cleanup (cutoff: Alloc.String.t_String) : t_HandlerStmt =\n'
         '  HandlerStmt_DeleteExpiredSends ({ f_cutoff = cutoff }) <: t_HandlerStmt')
elif name == 'linked-limit':
    once('let plan_linked_items (user: Alloc.String.t_String) (limit: usize) : t_HandlerStmt =\n'
         '  HandlerStmt_SelectSharedItems ({ f_user = user; f_limit = limit }) <: t_HandlerStmt',
         'let plan_linked_items (user: Alloc.String.t_String) (limit: usize) : t_HandlerStmt =\n'
         '  HandlerStmt_SelectSharedItems ({ f_user = user; f_limit = mk_usize 0 }) <: t_HandlerStmt')
elif name == 'rate-allow':
    once('f_allowed = count <=. limit', 'f_allowed = count <. limit')
elif name == 'rate-fail':
    once('| RateOutcome_Failed  ->\n      { f_count = mk_u64 0; f_allowed = false; f_failed = true }',
         '| RateOutcome_Failed  ->\n      { f_count = mk_u64 0; f_allowed = true; f_failed = true }')
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
    "$module" 2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo "mutant $name: VERIFIED (the proof does not depend on it)" >&2
    failures=$((failures + 1))
    continue
  fi
  # Every theorem with an error; the expected one must be among them.
  rejected=$(grep -oE "${module_name}\.fst\(([0-9]+)," <<<"$out" | grep -oE '[0-9]+' | sort -un |
    while read -r line; do head -n "$line" "$d/lemmas/$module_name.fst" | grep -oE '^let [a-z_0-9]+' | tail -n1 | cut -d' ' -f2; done | sort -u | tr '\n' ' ') || true
  if [[ -z ${rejected// /} ]]; then
    # No lemma error: F* was killed or failed elsewhere. Say so instead of exiting silently.
    echo "mutant $name: F* exited $status without an error in $module_name.fst; last output:" >&2
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
echo "share executor mutations: every mutant rejected at its theorem"
