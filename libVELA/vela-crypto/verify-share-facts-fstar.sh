#!/usr/bin/env bash
set -euo pipefail
proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"
# Rebuild the checked dependency from Rust; never rely on a stale committed file.
../vela-client-share-policy/verify-fstar.sh
cargo test --locked --lib share_envelope::tests
cargo test --locked --doc share_envelope::OpenedShare
python3 -c 'from pathlib import Path; [Path(p).unlink(missing_ok=True) for p in ["proofs/fstar/extraction/Vela_crypto.Share_envelope.fst", "proofs/fstar/extraction/Vela_crypto.Signing.fst", "proofs/fstar/extraction/Vela_crypto.Wire.fst"]]'
cargo hax into -i '-** +vela_crypto::share_envelope::opened_share_header +vela_crypto::share_envelope::opened_share_item +vela_crypto::share_envelope::into_opened_share_item +vela_crypto::share_envelope::admission_facts +vela_crypto::share_envelope::plan_observed_share +vela_crypto::share_envelope::split_envelope_prefix +vela_crypto::share_envelope::take_frame_prefix +vela_crypto::share_envelope::share_frame_spec +vela_crypto::share_envelope::frame_results_equal +vela_crypto::share_envelope::parse_share_frame +vela_crypto::signing::hybrid_components_verify +vela_crypto::signing::invalid_ml_component_can_authenticate +vela_crypto::signing::invalid_ed_component_can_authenticate +vela_crypto::wire::split_lp_pair +vela_crypto::wire::take_lp_pair +vela_crypto::wire::split_lp_four +vela_crypto::wire::take_lp_four +vela_crypto::wire::split_u64_prefix +vela_crypto::wire::take_u64 +vela_crypto::wire::split_length_prefixed +vela_crypto::wire::take_length_prefixed +vela_crypto::wire::decode_u64_be +vela_crypto::wire::split_low_byte +vela_crypto::wire::encode_u64_be +vela_crypto::wire::u64_wire_round_trip +vela_crypto::wire::u64_wire_encoding_is_injective' fstar --z3rlimit 100
hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
if [[ -z "$hax_lib_root" || ! -d "$hax_lib_root" ]]; then
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
fi

fstar.exe \
  --cmi \
  --query_stats \
  --split_queries always \
  --warn_error -331 \
  --z3rlimit 100 \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --include "$hax_lib_root/proof-libs/fstar/core" \
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
  --include "$hax_lib_root/proofs/fstar/extraction" \
  --include ../vela-client-share-policy/proofs/fstar/extraction \
  --include proofs/fstar/extraction \
  --include proofs/fstar/models \
  ../vela-client-share-policy/proofs/fstar/extraction/Vela_client_share_policy.fst \
  proofs/fstar/extraction/Vela_crypto.Share_envelope.fst \
  proofs/fstar/extraction/Vela_crypto.Signing.fst \
  proofs/fstar/extraction/Vela_crypto.Wire.fst
