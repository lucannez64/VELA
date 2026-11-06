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

mutate "drop the lineage check" \
    "    if lineage <= 0 { return reject_cross_lineage(has_pin, lineage, _); }"$'\n' ""
mutate "accept a replayed (equal) revision" \
    "if cand <= pinned { return" "if cand < pinned { return"
mutate "drop the authentication check" \
    "    if auth <= 0 { return reject_unauthenticated(auth, _); }"$'\n' ""
mutate "first contact even when pinned" \
    "    if has_pin <= 0 {" "    if has_pin <= 1 {"
mutate "allow revision 0" \
    "    if cand <= 0 { return reject_revision_zero(cand, _); }"$'\n' ""
mutate "apply an update from a foreign signer" \
    "if signer <= 0 { return reject_foreign_signer(has_pin, signer, _); }" \
    "if signer <= 0 { return apply_update(auth, addr, sender, has_pin, signer, lineage, pinned, cand, _, _); }"
mutate "skip the has_pin domain check" \
    "    if has_pin > 1 { return reject_malformed_high(has_pin, _); }"$'\n' ""
mutate "reject with the wrong reason" \
    "    if auth <= 0 { return reject_unauthenticated(auth, _); }" \
    "    if auth <= 0 { return reject_misaddressed(addr, _); }"
mutate "restore a deleted item" \
    "    if tombstoned >= 1 { return recovery_deleted(current_present, tombstoned, _); }"$'\n' ""
mutate "overwrite a pending commit" \
    "    if pending >= 1 { return generation_pending(pending, _); }"$'\n' ""
mutate "re-accept a share that is already pinned" \
    "    if has_pin >= 1 { return acceptance_pinned(has_pin, _); }"$'\n' ""
mutate "false lemma: next revision is stale" \
    "    erased reason: { has_pin == 1 && cand <= pinned },"$'\n'"    erased up:" \
    "    erased reason: { has_pin == 1 && cand <= pinned + 1 },"$'\n'"    erased up:"

if ((failures)); then
    echo "$failures injected bug(s) were not rejected" >&2
    exit 1
fi
echo "all injected bugs rejected"
