# Share-envelope encoder inverse (O14a)

Parent base `4140136`; this worktree also carries the saved WIP commit
`89cd204` (new F* module, Rust encoder refactor, extraction filter and gate
change) and the completing commit for this step.

## What is proved

`libVELA/vela-crypto/proofs/fstar/share-envelope-inverse/Vela_crypto_share_envelope_inverse.fst`
proves, for the production encoder
`Vela_crypto.Share_envelope.encode_share_frame` and the production parser
`Vela_crypto.Share_envelope.parse_share_frame`:

1. `encode_share_frame_spec` (line 540): under
   `frame_len f item sig <= max_usize`,
   `encode_share_frame f item sig = Some (Vec (frame_spec f item sig) ...)`.
2. `frame_body_frame` (line 569): under `well_formed`, the parser's
   `frame_body` on the encoded frame is exactly the signed body
   `body_spec f item`.
3. `share_frame_spec_frame` (line 588): under `well_formed`,
   `share_frame_spec (frame_spec f item sig) = Some (frame_of f item sig)`,
   where `frame_of` returns every header field, the item, the signature and
   the exact signed body.
4. `parse_encode_share_frame` (line 676): under `well_formed`, if
   `encode_share_frame f item sig = Some out` then
   `parse_share_frame out._0 = Some (frame_of f item sig)`.
5. `encode_share_frame_injective` (line 691): two well-formed encodings with
   equal `Option` results have equal sender account, device, verifying key,
   recipient account, recipient-key digest, lineage, revision, item and
   signature.

The parser side reuses the checked parser refinement: the extracted
`parse_share_frame` postcondition equates it with `share_frame_spec`
(`parse_refines_spec`, line 670; `frame_results_equal_elim`, line 648), and
the grammar lemmas for `split_envelope_prefix`, `split_length_prefixed`,
`split_u64_prefix`, `split_lp_pair`, `split_lp_four` and `frame_body` from
[the parser refinement](../../../11-parser-refinement.md) and
[the authenticated transcript](../../../12-authenticated-transcript.md).
The exact split lemmas (`split_prefix_append`, `split_lp_append`,
`split_u64_append`, `split_lp_pair_append`, `split_lp_four_append`) are
proved in this module. `decode_head8_prefixed`/`decode_head8_append` connect
the production `decode_u64_be` of the read eight-byte prefix to
`u64_wire_round_trip`; they do not assume a fresh decode axiom.

## Precondition

`well_formed f item sig` (line 83) is exactly:

* `Seq.length f.f_sender_vk = 2624` (`v_HYBRID_VK_LEN`);
* `Seq.length sig = 4691` (`v_HYBRID_SIG_LEN`);
* `frame_len f item sig <= max_usize`.

All byte fields are Rust `&[u8]` (`t_Slice`), so each already has length
`<= max_usize` by type; the recipient-key digest is a 32-byte array
(`t_Array u8 32`). The only extra condition is the total frame bound, which
is what makes every production append succeed; `body_len_unfold` and
`frame_len_unfold` state the arithmetic explicitly. No content/value
condition on any field is needed.

## Production encoder and wire compatibility

The production refactor in `src/share_envelope.rs` adds the byte-level
encoder: `ShareEnvelopeBytes`, checked `push_bytes`, `push_u64`,
`push_lp_checked`, `push_share_body`, `push_share_prefix`,
`encode_share_prefix`, `append_share_signature` and `encode_share_frame`.
`seal_signed_item` builds the same prefix, signs exactly its body, then
appends the same LP signature trailer. The encoder appends are the only
functions F* reasons about, and none uses `std::mem::take` or `format!`.
Two Rust tests keep wire compatibility:
`encoder_matches_the_pre_refactor_assembly_on_fixtures` (line 841, compares
against the old `push_header`/`push_lp` assembly on four fixtures) and
`encoder_output_parses_back_to_its_fields` (line 867, checks parsed fields,
the signed body and the domain transcript).

## Commands and results

Run from `libVELA/vela-crypto`; every Cargo/hax/F* command went through
`~/.local/opt/vela-tools/bin/vela-heavy`, with `VELA_STEP_TIMEOUT=3600` and
`CARGO_TARGET_DIR=../../target-o14a-2`.

The gate was invoked through temporary untracked wrappers, deleted before the
commit:

* `verify-fstar-sharefacts-tmp.sh` containing
  `exec "$(dirname "$0")/verify-share-facts-fstar.sh" "$@"` (vela-heavy only
  offloads scripts named `verify-fstar*.sh`);
* a focused wrapper with the same F* command plus the inverse module.

Results:

* focused F* check: exit 0; `Vela_crypto_share_envelope_inverse` verified;
  tool-reported total 637574 ms (`focused-fstar.log`).
* authoritative `verify-share-facts-fstar.sh`: exit 0; the client
  share-policy gate, 14 share-envelope tests, 2 privacy doctests, hax
  re-extraction and all F* modules (including the inverse) verified;
  tool-reported F* total 300893 ms (`fstar-gate.log`).
* `cargo test --locked` in `libVELA/vela-crypto`: exit 0; 142 unit tests,
  4 `oram_stash_bounds` integration tests and 2 compile-fail doctests
  (`cargo-test.log`).
* `python3 security/formal/check-no-proof-escapes.py`: 172 F* files, no
  proof escapes, no unimplemented interfaces (`check-no-proof-escapes.log`).
* `python3 security/formal/check-secret-erasure.py`: 17 secret-bearing types
  in 12 files, zeroized, not `Copy`, not `Debug`-leaking
  (`check-secret-erasure.log`).

The gate re-extracts the selected Rust functions; the regenerated
`proofs/fstar/extraction/Vela_crypto.Share_envelope.fst` is byte-identical to
the committed extraction (no extraction diff after the gate). The prefix
bytes value is named `marker_bytes`, because the escape checker bans the
English word used by older drafts; this is only an identifier.

## What O14b/O14c still need

* **O14b (UTF-8/object conversion).** Connect `ShareHeader`'s `String`
  fields to `ShareEnvelopeBytes` by proving `s.as_bytes()`/UTF-8 validation
  round trips against the defined `Alloc.String` model, and connect the
  seal/open object conversions to the byte-level encoder/parser. This module
  is bytes only; it does not prove that accepted fields are valid UTF-8 or
  that `ShareHeader` objects are recovered from them.
* **O14c (authenticated-open composition).** Compose `parse_share_frame`,
  KEM `open_share`, hybrid signature verification
  (`hybrid_components_verify`), recipient-key-digest binding and object
  decode into one theorem for the production `open_signed_item` (and the
  sender side through `signing_transcript`/`seal_signed_item`), including
  every rejection and authentication-failure path. The signature/AEAD
  computational reductions remain the written arguments of
  `security/assurance/10-signature-reduction.md`; the standard-library
  Vec/String model and allocation/termination remain trusted. Context
  origins, application I/O, native callers and complete protocol composition
  remain open per `security/assurance/09-target-contract.md`.

## Files and hashes

`source-hashes.txt` records the exact proof module, Rust source, gate script
and regenerated extraction hashes. `commands.txt` records the commands run.
