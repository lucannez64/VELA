#!/usr/bin/env bash
# Standalone prebuilt F* for the symbolic job; leave the hax cache untouched.
set -euo pipefail
proof_root=${1:?usage: install-formal-fstar.sh DESTINATION}
if [[ ! -x "$proof_root/fstar/bin/fstar.exe" ]]; then
  mkdir -p "$proof_root"
  archive=$(mktemp -t vela-fstar.XXXXXX.tar.gz)
  trap 'rm -f "$archive"' EXIT
  curl -fL --retry 3 --connect-timeout 30 -o "$archive" \
    https://github.com/FStarLang/FStar/releases/download/v2025.10.06/fstar-v2025.10.06-Linux-x86_64.tar.gz
  echo "940c187d7a6dc3e95d17fd5159b5eaec17d62981c7f135a7e6c531ce3b59442d  $archive" | sha256sum -c
  tar -xzf "$archive" -C "$proof_root"
fi
test "$(cat "$proof_root/fstar/version.txt")" = 2025.10.06
"$proof_root/fstar/bin/fstar.exe" --version
"$proof_root/fstar/lib/fstar/z3-4.13.3/bin/z3" --version | grep -F 'Z3 version 4.13.3'
