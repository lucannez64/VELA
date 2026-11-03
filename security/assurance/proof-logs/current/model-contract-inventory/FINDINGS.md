# Findings from the imported model inventory (plan step T1)

Inventory: [README.md](README.md), produced by
`security/assurance/list-model-contracts.py` on 2026-11-03 against hax 0.3.7.

1. **No assumed library symbol is used.** None of the 114 library symbols the
   corpus references is declared with `assume val` or `assume type`.
2. **Eight abstract symbols are trusted** (an interface `val` with no
   definition in the library):
   - `Core_models.Fmt.Rt.impl__new_display`, `impl_1__new_v1` and
     `Core_models.Hint.must_use`, all from `format!` in
     `vela-session-policy`'s store extraction (`Vela_session_policy.Store`).
     `Alloc.Fmt.format` itself is defined over the abstract `format'`.
     So the store keys built with `format!` (`jti:revoked:{}`,
     `device:revoked:{}`, `challenge:{}`, `rl:streak:verify:{}:{}`, ...) are
     not just opaque: hax models `t_Arguments` as `Arguments : unit ->
     t_Arguments`, which has one value, so **F* proves every `format!` result
     equal** ([check](../std-model-review/format-collapse/Fmt_collapse.fst),
     verified 2026-11-03, [log](../std-model-review/format-collapse/fstar.log)).
     A session-store proof can therefore treat two different keys as the same
     key, which Rust does not. T4 found no lemma that asserts equality across
     different prefixes, but two key-shape lemmas are only meaningful because
     their prefixes happen to coincide. `format'` (an `assume val` reached
     through `Alloc.Fmt.format`) belongs in the trusted list: "no assumed
     symbol used" holds only for symbols the corpus names directly.
     **This blocks plan step O4** (store key builders are injective). O4 has
     to replace `format!` in those builders with an extracted byte or string
     concatenation that F* can see through, or model `format!` for the used
     `{}` cases.
   - `Rust_primitives.String.str_concat`, `str_index`, `str_of_char`,
     `str_sub` and `Core_models.Str.impl_str__len`, all used only by
     vela-crypto's local `Alloc.String` model. These are T4's review targets.
3. **One local model replaces hax's.** `libVELA/vela-crypto/proofs/fstar/models`
   holds `Alloc.String.fst` and `Alloc.Vec.fst`, loaded ahead of the hax
   models by `verify-share-facts-fstar.sh`. Neither file contains `assume`,
   `admit` or a bare `val`, but `Alloc.String` is built on the five abstract
   string symbols above. T3 (Vec) and T4 (String) must review these files, not
   only the hax ones.
4. **Seven defined symbols wrap an abstract one** in the same module:
   `maxint`, `minint`, `max_usize` and `add_sat` depend on the abstract
   `size_bits` (usize is 32 or 64 bits, left open), `&.` on `logand`, `<<!`
   on `shift_left` and `Alloc.Fmt.format` on `format'`. Proofs over `usize`
   bounds therefore hold for both widths, which is the intended reading; the
   bit operations are T5's review targets.
5. **The integer and option core is defined, not assumed.** The most used
   symbols (`t_Option`, the comparison and checked-arithmetic operators,
   `mk_*`, `v`, `fold_range`) have bodies in the library. Their trust is only
   that the definitions match Rust release-mode semantics, which T5 reviews.

Limits: names used through `open` are matched by token, so their counts are
upper bounds. Wrapping is followed only within a module, three levels deep.
