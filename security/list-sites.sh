#!/usr/bin/env bash
#
# Dump the login sites in the vault (names + URLs only, no passwords), to plan
# in-core login recipes.
#
# Run from the repo root:
#   ./security/list-sites.sh
#
# The master password is prompted for (read -s, never echoed, never written to
# disk). Output is `LOGIN<TAB>name<TAB>url` and `PASSKEY<TAB>rp_id`.

set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

read -r -s -p "VELA master password: " VELA_MASTER_PASSWORD
echo
if [ -z "$VELA_MASTER_PASSWORD" ]; then
  echo "No password given; aborting." >&2
  exit 1
fi
export VELA_MASTER_PASSWORD

( cd "$ROOT/desktopVELA" && cargo run --quiet --example list_sites )
