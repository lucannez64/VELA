#!/usr/bin/env bash
# Print SHA-256 hashes of every assurance artifact, relative to the repo root.
# Usage: security/assurance/make-manifest.sh > security/assurance/MANIFEST.sha256
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
{
  git ls-files 'security/formal/*.spthy' 'security/formal/*.pv' 'security/formal/*.pvl' \
               'security/formal/run-*.sh'
  git ls-files '*/vela-*-policy/src/*.rs' '*/vela-*-policy/verify-fstar.sh' \
               '*/vela-*-policy/proofs/fstar/extraction/*.fst' \
               'libVELA/vela-crypto/proofs/proverif/extraction/*.pvl' \
               'libVELA/vela-crypto/src/oram.rs' 'libVELA/vela-crypto/tests/oram_stash_bounds.rs' \
               'serverVELA/vela-server/tests/*_model.rs' \
               'libVELA/vela-client-recovery-policy/tests/*.rs' \
               '.github/workflows/security.yml'
} | sort -u | xargs sha256sum
