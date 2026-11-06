#!/usr/bin/env bash
# Check the Kush port's proofs, then show that they are not vacuous: inject
# each listed bug into a temporary copy of the policy and require that the
# compiler rejects it with an unprovable obligation.
#
# Usage: libVELA/vela-client-share-policy-kush/check-proofs.sh [path/to/kush]
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kush=${1:-${KUSH:-kush}}
command -v "$kush" >/dev/null || { echo "kush is missing (pass its path)" >&2; exit 1; }

cd "$root"
"$kush" check

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cp -r Kush.toml src tests "$scratch/"
# The oracle is only linked by build/run/test, not by check.
sed -i 's/^cargo-manifests/# cargo-manifests/' "$scratch/Kush.toml"

failures=0
mutate() {
    local name=$1 from=$2 to=$3
    cp "$root/src/policy.kush" "$scratch/src/policy.kush"
    python3 - "$scratch/src/policy.kush" "$from" "$to" <<'EOF'
import sys
path, old, new = sys.argv[1:]
text = open(path).read()
if text.count(old) != 1:
    sys.exit(f"mutation anchor not found exactly once: {old!r}")
open(path, "w").write(text.replace(old, new))
EOF
    local output
    if output=$(cd "$scratch" && "$kush" check 2>&1); then
        echo "NOT REJECTED: $name" >&2
        failures=$((failures + 1))
    else
        printf '%-44s rejected: %s\n' "$name" \
            "$(grep -m1 -o "cannot prove '[^']*'" <<<"$output" || head -1 <<<"$output")"
    fi
}

# plan_share_admission
mutate "drop the lineage check" \
    "        && facts.lineage_matches_pin"$'\n'"        && facts.candidate_revision > facts.pinned_revision"$'\n'"    {" \
    "        && facts.candidate_revision > facts.pinned_revision"$'\n'"    {"
mutate "accept a replayed (equal) revision" \
    "        && facts.candidate_revision > facts.pinned_revision"$'\n'"    {" \
    "        && facts.candidate_revision >= facts.pinned_revision"$'\n'"    {"
mutate "drop the authentication check" \
    "    let bound = facts.envelope_authenticated"$'\n'"        && facts.addressed_to_recipient" \
    "    let bound = facts.addressed_to_recipient"
mutate "first contact even when pinned" \
    "    if !facts.has_pin && bound {" "    if bound {"
mutate "allow revision 0" \
    "        && facts.candidate_revision >= 1;" "        && facts.candidate_revision >= 0;"
mutate "apply an update from a foreign signer" \
    "        && bound"$'\n'"        && facts.signer_matches_pin"$'\n' "        && bound"$'\n'
mutate "pin the old revision on update" \
    "            revision: facts.candidate_revision,"$'\n'"        })"$'\n'"    } else {" \
    "            revision: facts.pinned_revision,"$'\n'"        })"$'\n'"    } else {"
mutate "reject a valid update" \
    "    } else if facts.has_pin" "    } else if false && facts.has_pin"
# the Rust-named predicates
mutate "predicate: drop the lineage check" \
    "        && facts.lineage_matches_pin"$'\n'"        && facts.candidate_revision > facts.pinned_revision"$'\n'"}" \
    "        && facts.candidate_revision > facts.pinned_revision"$'\n'"}"
mutate "predicate: first contact even when pinned" \
    "    !facts.has_pin && envelope_is_bound(facts)" "    envelope_is_bound(facts)"
mutate "predicate: allow revision 0" \
    "        && facts.candidate_revision >= 1"$'\n'"}" \
    "        && facts.candidate_revision >= 0"$'\n'"}"
mutate "count an update as not admitted" \
    "        ShareAdmissionDecision.ApplyUpdate(_) => true," \
    "        ShareAdmissionDecision.ApplyUpdate(_) => false,"
mutate "restore a deleted item" \
    "    matches_before && (current_present || !tombstoned)"$'\n'"}" \
    "    matches_before && (current_present || tombstoned)"$'\n'"}"
mutate "overwrite a pending commit" \
    "    if current != snapshot || pending || current" \
    "    if current != snapshot || current"
mutate "overflow the generation counter" \
    " || current == 18446744073709551615 {" " {"
mutate "re-accept a share that is already pinned" \
    "    !accepted && !has_pin && has_payload"$'\n'"}" \
    "    !accepted && has_payload"$'\n'"}"
mutate "false theorem: stale revision without clamp" \
    "            candidate_revision: facts.pinned_revision," \
    "            candidate_revision: facts.candidate_revision,"

# The permit field is private: code outside the policy module can neither
# mint a permit nor read its revision directly.
cp "$root/src/policy.kush" "$scratch/src/policy.kush"
for forged in \
    "policy.ShareAdmissionDecision.ApplyUpdate(policy.SharePinPermit { revision: 7 })" \
    "p.revision"; do
    printf '%s\n' "module share_policy.tests.main;" "use share_policy.policy;" \
        "fn forge(p: policy.SharePinPermit) -> Unit ! {} { let d = $forged; }" \
        >"$scratch/tests/main.kush"
    if output=$(cd "$scratch" && "$kush" check 2>&1); then
        echo "NOT REJECTED: permit access outside the module: $forged" >&2
        failures=$((failures + 1))
    else
        printf '%-44s rejected: %s\n' "outside: $forged" "$(head -1 <<<"$output")"
    fi
done

if ((failures)); then
    echo "$failures injected bug(s) were not rejected" >&2
    exit 1
fi
echo "all injected bugs rejected"
