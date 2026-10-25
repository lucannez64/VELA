# Login challenge-tag producer closure (F-1 producer increment)

Base: `3aaac25` (`Run login proof gate with reviewed source policy`) on the
`login-driver` increment. This directory records local evidence; it is not a
hosted CI result.

## The gap this closes

`40129b6` proved the login challenge classifier only for the *bounded*
`StoredTag` value. The real production constructor
`vela_session_policy::challenge::stored_tag_from_bytes(&[u8])`, which
`vela-server/src/auth/challenge.rs::take_challenge` calls on the bytes returned
by `Store::get_del`, was Rust glue covered only by tests. The classifier proof
therefore started one conversion too late.

This increment extracts that actual constructor and proves its obligations in
F*. No second, duplicate constructor was introduced and no conversion is
assumed.

## Production change

`src/challenge.rs` replaces the bounded `while` copy with nine unrolled,
bounds-checked reads:

```rust
fn byte_or_zero(bytes: &[u8], index: usize) -> u8 {
    if index < bytes.len() { bytes[index] } else { 0 }
}

#[cfg_attr(hax, hax_lib::ensures(|tag| stored_tag_copies_prefix(tag, bytes)))]
pub fn stored_tag_from_bytes(bytes: &[u8]) -> StoredTag {
    StoredTag { len: bytes.len(), bytes: [
        byte_or_zero(bytes, 0), /* ... */ byte_or_zero(bytes, 8),
    ] }
}
```

`stored_tag_copies_prefix` is the explicit Rust contract: the real length is
preserved and each of the nine positions is the raw byte when the slice reaches
it, zero otherwise. It is written with explicit comparisons and index reads, not
by calling `byte_or_zero`, so the contract is independent of the implementation
helper. The extracted body contains no loop; hax emits one record literal whose
`f_len` is `Core_models.Slice.impl__len bytes` and whose `f_bytes` are the nine
`byte_or_zero` applications.

## New hand-written F* module

`proofs/fstar/challenge-lemmas/Vela_session_policy_tag_producer_lemmas.fst`
(23 lemmas) states the obligations over an arbitrary `t_Slice u8` and proves
them against the extracted body:

| Theorem | Statement |
|---|---|
| `producer_len` | `v (stored_tag_from_bytes b).f_len = Seq.length b` (length preserved, no truncation) |
| `copied_prefix_is_exact` | for `k < 9` and `k < Seq.length b`, `f_bytes[k] = Seq.index b k` |
| `copied_prefix_is_exact_forall` | range-wide form over `k < 9` via the total `producer_byte` reader |
| `copied_padding_is_zero` | positions past the raw length are zero |
| `classify_producer_matches_slice` | `classify_stored_tag (stored_tag_from_bytes b) = classify_slice b`, where `classify_slice` is built from the literal bytes `login`/`enroll`/`web_token` over the raw slice |
| `consumption_accepts_iff_slice` | `classify_consumption (Some (stored_tag_from_bytes b)) expected = Accepted` iff the raw slice is `expected`'s literal tag |
| `long_input_cannot_alias_short` | `Seq.length b > 9` implies a length `> 9` and `Unknown` classification |
| `issued_classified` | `classify_stored_tag (stored_tag_from_bytes (purpose_tag_bytes p)) = Recognized p` |
| `issued_path_accepts_only_its_purpose` | the issued bytes are accepted for their own purpose and `WrongPurpose` for the other two |
| `concrete_login_classified`, `concrete_long_is_unknown` | non-vacuity witnesses |

The slice predicates are independent of both the Rust contract
`stored_tag_copies_prefix` and the bounded predicates in
`Vela_session_policy_challenge_lemmas`; the bridge is proved from the extracted
producer body.

`purpose_tag_bytes` was added to the focused selection and extracts to literal
byte slices, so the issued path (issue → store → take → convert → classify) is
also checked, not just described.

## Results

- `cargo-test-session-policy.log`: 18 unit tests + 13 login-driver tests, 0
  failed. Four new producer tests cover every length 0..12, long-input
  non-aliasing, one-byte corruption and truncation.
- `cargo-test-server-producer-consumers.log`: the unchanged production
  consumers pass (`challenge_single_use_model` 3/3, `login_driver_handler`
  4/4).
- `fstar-full-verify.log`: historical extraction verifies; the focused gate
  verifies `Vela_session_policy.Challenge`, `Vela_session_policy.Login_driver`,
  both challenge lemma modules and the login-driver lemma module; the source
  policy gate passes. Exit 0. The historical artifact is byte identical.
- `mutation-truncation-length.log`: truncating the retained length to nine and
  weakening the contract makes the producer lemma fail (`producer_len`,
  `Error 19`) — the independent lemma, not the contract, catches the aliasing.
- `mutation-byte-corruption.log`: reading raw index 4 into position 0 while
  keeping the contract makes the extracted
  `stored_tag_from_bytes` postcondition itself fail (`Error 19`).

Mutant diffs are `mutant-truncation-length.diff` and
`mutant-byte-corruption.diff`. Only copies under `/tmp/opencode` were patched.

## Scope and residuals

- Changed: `serverVELA/vela-session-policy/src/challenge.rs`,
  `verify-fstar-login-driver.sh` (executable mode restored so
  `verify-fstar.sh` can invoke it), the focused extraction snapshot
  `proofs/fstar/extraction-login-driver/Vela_session_policy.Challenge.fst`, the
  new lemma module, and the crate `README.md`.
- Unchanged and byte identical: `proofs/fstar/extraction/Vela_session_policy.fst`
  (historical extraction) and
  `proofs/fstar/extraction-login-driver/Vela_session_policy.Login_driver.fst`.
- Out of scope by instruction and untouched: server handlers, `login_driver.rs`
  and its trace module, global docs/manifests/correspondence/CI.
- The proof covers the pure conversion and the pure classifier composition. It
  does not claim sled `get_del` atomicity, `&'static str` provenance beyond the
  literal match, or handler behavior.
- The concurrent one-challenge / concurrent nonce composition remains a
  separate open obligation; it is not closed here.
