#!/usr/bin/env bash
# Remote-capable entry point for the F-2 cross-driver gate.
#
# `~/.local/opt/vela-tools/bin/vela-heavy` only offloads commands whose basename
# matches `verify-fstar*.sh`. This wrapper keeps the required
# `security/formal/cross-driver/verify.sh` gate usable directly while letting
# the heavy run use the build box under that name.
set -euo pipefail
proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$proof_root/verify.sh" "$@"
