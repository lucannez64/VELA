#!/usr/bin/env bash
# Computational proofs of the hybrid KEM combiner (CryptoVerif 2.12).
#   kem_v2_x25519_gdh     must prove: uniform-group GDH, other KEM key disclosed
#   kem_v2_x25519_gdh_nonuniform must prove: nonuniform/clamped-style exponents,
#                         explicit collision + rerandomization loss
#   kem_v2_mlkem_cca      must prove: ML-KEM IND-CCA2/collision bounds, DH key disclosed
#   kem_v1_x25519_baseline must remain explicitly unproved (not an attack trace)
#   kem_dem_seal_share    must prove: seal_share (KEM + XChaCha20-Poly1305) is IND-CCA2 PKE
#   hybrid_sig_mldsa_euf  must prove: AND signature EUF-CMA from ML-DSA alone (Ed25519 key leaked)
#   hybrid_sig_ed25519_euf must prove: AND signature EUF-CMA from Ed25519 alone (ML-DSA key leaked)
# Needs `cryptoverif` on PATH (or CRYPTOVERIF=/path/to/cryptoverif) and its
# library `default.ocvl` next to the binary (or CRYPTOVERIF_LIB=/path/to/default).
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
cv=${CRYPTOVERIF:-$(command -v cryptoverif || true)}
[[ -x "$cv" ]] || { echo "cryptoverif not found; see security/assurance/04-reproducibility.md" >&2; exit 2; }
lib=${CRYPTOVERIF_LIB:-$(dirname "$cv")/default}
out=${VELA_PROOF_OUT:-$(mktemp -d -t vela-cryptoverif.XXXXXX)}
python3 "$root/check-cryptoverif-boundary.py"
mkdir -p "$out"

run() {
  local model=$1 expect=$2 query=$3 log="$out/$1.log"
  local status=0 got
  "$root/../assurance/bounded.sh" timeout 600 "$cv" -lib "$lib" "$root/cryptoverif/$model.ocv" >"$log" 2>&1 || status=$?
  if (( status != 0 )); then
    echo "$model: proof process failed (exit $status); see $log" >&2
    exit 1
  fi
  if grep -q '^Error' "$log"; then echo "$model: CryptoVerif error; see $log" >&2; exit 1; fi
  if grep -q '^All queries proved\.' "$log"; then
    got=proved
  elif grep -q '^RESULT Could not prove bit secrecy of b\.$' "$log"; then
    got=unproved
  else
    echo "$model: no recognized proof verdict; see $log" >&2
    exit 1
  fi
  if [[ $got == proved ]] && ! grep -Fq "RESULT Proved $query up to probability " "$log"; then
    echo "$model: missing expected query result ($query); see $log" >&2
    exit 1
  fi
  if [[ $got != "$expect" ]]; then echo "$model: expected $expect, got $got; see $log" >&2; exit 1; fi
  if [[ $model == kem_v2_x25519_gdh_nonuniform ]]; then
    python3 "$root/check-cryptoverif-bound.py" "$log"
  fi
  echo "$model: $got (as expected)"
  grep '^RESULT Proved' "$log" | sort -u | sed 's/^/  /' || true
}

run kem_v2_x25519_gdh proved 'bit secrecy of b'
run kem_v2_x25519_gdh_nonuniform proved 'bit secrecy of b'
run kem_v2_mlkem_cca proved 'bit secrecy of b'
run kem_v1_x25519_baseline unproved 'bit secrecy of b'
run kem_dem_seal_share proved 'bit secrecy of b'
run hybrid_sig_mldsa_euf proved 'event(forge) ==> false'
run hybrid_sig_ed25519_euf proved 'event(forge) ==> false'
printf 'Full CryptoVerif logs: %s\n' "$out"
