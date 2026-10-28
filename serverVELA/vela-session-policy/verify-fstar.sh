#!/usr/bin/env bash
set -euo pipefail

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

# Optional part, so CI can check the crate's independent gate groups in
# parallel jobs: core (the historical extraction), login, revocation, deletion,
# account (registration and challenge issue plus the challenge composition).
# Each driver gate runs with its interpreter gate, which reads the driver
# extraction it just regenerated. No argument runs everything, in order.
part=${1:-all}
case $part in
  all|core|login|revocation|deletion|account|websession) ;;
  *) echo "usage: $0 [all|core|login|revocation|deletion|account|websession]" >&2; exit 2 ;;
esac
wants() { [[ $part == all || $part == "$1" ]]; }

if wants core; then
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
fi

# F-1/F-2 focused challenge-purpose and login-driver gate. It regenerates a
# partial extraction with the same root module name into
# proofs/fstar/extraction-login-driver, so it must run in its own fstar.exe
# invocation and never share an include directory with the historical artifact
# checked above.
if wants login; then "$proof_root/verify-fstar-login-driver.sh"; fi

# Handler-to-driver link for POST /auth/verify: the interpreter loop the
# handler expands, proved to perform exactly the driver's effects. Needs the
# login driver extraction above.
if wants login; then "$proof_root/verify-fstar-login-interpreter.sh"; fi

# F-3 focused device-revocation/logout/admission driver gate. It regenerates
# its own partial extraction into proofs/fstar/extraction-revocation-driver and
# is checked in its own fstar.exe invocation.
if wants revocation; then "$proof_root/verify-fstar-revocation-driver.sh"; fi

# Handler-to-driver link for POST /device/revoke and POST /auth/logout: the
# interpreter loops the handlers expand. Needs the revocation driver extraction
# above.
if wants revocation; then "$proof_root/verify-fstar-revocation-interpreter.sh"; fi

# F-2 account-registration and challenge-issue driver gates. Each regenerates
# its own partial extraction and is checked in its own fstar.exe invocation.
if wants account; then "$proof_root/verify-fstar-challenge-issue-driver.sh"; fi
if wants account; then "$proof_root/verify-fstar-registration-driver.sh"; fi

# Handler-to-driver links for GET /auth/challenge and POST /account/register:
# the interpreter loops the handlers expand. Need their driver extractions.
if wants account; then "$proof_root/verify-fstar-challenge-issue-interpreter.sh"; fi
if wants account; then "$proof_root/verify-fstar-registration-interpreter.sh"; fi

# Composition of the extracted issue driver with the shared take adapter:
# one issued nonce is consumed by at most one request, only for its purpose.
if wants account; then "$proof_root/verify-fstar-challenge-issue-composition.sh"; fi

# F-4 focused account-deletion driver gate. It regenerates its own partial
# extraction into proofs/fstar/extraction-deletion-driver (including the
# middleware admission decision it composes with) and is checked in its own
# fstar.exe invocation.
if wants deletion; then "$proof_root/verify-fstar-deletion-driver.sh"; fi

# Handler-to-driver link for DELETE /account: the interpreter loop the handler
# expands, proved to perform exactly the driver's effects. Needs the deletion
# driver extraction above.
if wants deletion; then "$proof_root/verify-fstar-deletion-interpreter.sh"; fi

# F-2 focused web-session start/grant/token/delete driver gate. It regenerates
# its own partial extraction into proofs/fstar/extraction-websession-driver and
# is checked in its own fstar.exe invocation.
if wants websession; then "$proof_root/verify-fstar-websession-driver.sh"; fi

# Handler-to-driver link for the four web-session transitions: the interpreter
# loops the handlers expand. Needs the web-session driver extraction above.
if wants websession; then "$proof_root/verify-fstar-websession-interpreter.sh"; fi
