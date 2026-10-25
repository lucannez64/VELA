#!/usr/bin/env bash
set -euo pipefail

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow README.md" >&2
    exit 1
  }
done

cargo test

cargo hax into \
  -i '-** +vela_session_policy::parse_scope_claim +vela_session_policy::plan_grant +vela_session_policy::plan_device_token +vela_session_policy::plan_web_session_token +vela_session_policy::plan_renewal +vela_session_policy::authorize_route +vela_session_policy::clamp_web_ttl +vela_session_policy::ttl_clamp_can_be_violated +vela_session_policy::web_session_expired +vela_session_policy::renewal_escalates_authority +vela_session_policy::terminal_session_issues_token +vela_session_policy::grant_facts +vela_session_policy::web_token_facts +vela_session_policy::plan_observed_grant +vela_session_policy::plan_observed_web_token +vela_session_policy::missing_approver_observation_can_grant +vela_session_policy::wrong_nonce_length_observation_can_grant +vela_session_policy::cross_account_observation_can_issue +vela_session_policy::missing_accounts_observation_can_issue +vela_session_policy::unconsumed_challenge_observation_can_issue +vela_session_policy::invalid_signature_observation_can_issue' \
  fstar --z3rlimit 100

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
if [[ -z "$hax_lib_root" || ! -d "$hax_lib_root" ]]; then
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
fi

mapfile -t proof_files < <(
  find proofs/fstar/extraction -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no F* modules" >&2
  exit 1
fi

fstar.exe \
  --cmi \
  --warn_error -331 \
  --z3rlimit 100 \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --include "$hax_lib_root/proof-libs/fstar/core" \
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
  --include "$hax_lib_root/proofs/fstar/extraction" \
  --include proofs/fstar/extraction \
  "${proof_files[@]}"

# F-1/F-2 focused challenge-purpose and login-driver gate. It regenerates a
# partial extraction with the same root module name into
# proofs/fstar/extraction-login-driver, so it must run in its own fstar.exe
# invocation and never share an include directory with the historical artifact
# checked above.
"$proof_root/verify-fstar-login-driver.sh"
