#!/usr/bin/env bash
# Computational proofs of the hybrid KEM combiner (CryptoVerif 2.12).
#   kem_v2_x25519_gdh     must prove: IND-CCA2 from Gap-DH, ML-KEM broken
#   kem_v2_mlkem_cca      must prove: IND-CCA2 from ML-KEM IND-CCA2, X25519 broken
#   kem_v1_x25519_baseline must NOT prove: the legacy combiner lacks transcript binding
#   kem_dem_seal_share    must prove: seal_share (KEM + XChaCha20-Poly1305) is IND-CCA2 PKE
# Needs `cryptoverif` on PATH (or CRYPTOVERIF=/path/to/cryptoverif) and its
# library `default.ocvl` next to the binary (or CRYPTOVERIF_LIB=/path/to/default).
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
cv=${CRYPTOVERIF:-$(command -v cryptoverif || true)}
[[ -x "$cv" ]] || { echo "cryptoverif not found; see security/assurance/04-reproducibility.md" >&2; exit 2; }
lib=${CRYPTOVERIF_LIB:-$(dirname "$cv")/default}
out=${VELA_PROOF_OUT:-$(mktemp -d -t vela-cryptoverif.XXXXXX)}
mkdir -p "$out"

run() {
  local model=$1 expect=$2 log="$out/$1.log"
  "$root/../assurance/bounded.sh" timeout 600 "$cv" -lib "$lib" "$root/cryptoverif/$model.ocv" >"$log" 2>&1 || true
  if grep -q '^Error' "$log"; then echo "$model: CryptoVerif error; see $log" >&2; exit 1; fi
  if grep -q '^All queries proved\.' "$log"; then got=proved; else got=unproved; fi
  if [[ $got != "$expect" ]]; then echo "$model: expected $expect, got $got; see $log" >&2; exit 1; fi
  echo "$model: $got (as expected)"
  grep '^RESULT Proved' "$log" | sort -u | sed 's/^/  /' || true
}

run kem_v2_x25519_gdh proved
run kem_v2_mlkem_cca proved
run kem_v1_x25519_baseline unproved
run kem_dem_seal_share proved
printf 'Full CryptoVerif logs: %s\n' "$out"
