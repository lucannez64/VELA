# Review of the std models against Rust semantics (plan steps T3-T6)

Each section compares a hax 0.3.7 library model the F* corpus uses (see the
[model inventory](../model-contract-inventory/README.md)) with the Rust std
behavior it stands for. **Faithful** means every proof over the model also
holds for the Rust function in the cases the code can reach. **Over-approximate**
means the model allows more behaviors than Rust, which keeps proofs sound but
can make some true facts unprovable. **Gap** means a proof could hold for the
model and fail for Rust; each gap becomes a plan step or an explicit exclusion.

This is a manual review, not a machine-checked refinement. Differential
testing of these models against Rust is plan step T7.

## T6: Option, Result, slices, ranges, loops and Clone

Reviewed 2026-11-03. Sources: `proof-libs/fstar/core/Core_models.Bundle.fst`,
`Core_models.Slice.fst`, `Alloc.Slice.fst`, `Alloc.Vec.fst`,
`Core_models.Clone.fst`, `rust_primitives/Rust_primitives.Arrays.fsti`,
`Rust_primitives.Hax.fst`, `Rust_primitives.Hax.Folds.fsti`.

| Model (uses in corpus) | Definition | Rust semantics | Verdict |
|---|---|---|---|
| `t_Option`, `Option_Some`, `Option_None` (2,617) | Two-constructor datatype | `enum Option<T> { Some(T), None }` | Faithful |
| `impl__is_some` (15) | `match` returning `true` exactly for `Some`; the `ensures` states only `res ==> Some?`, but the body is total and transparent, so both directions are provable | `Option::is_some` | Faithful |
| `impl__is_none` (15) | `is_some self =. false` | `Option::is_none` | Faithful |
| `impl__is_some_and` (4) | `None -> false`, `Some x -> f x` | `Option::is_some_and` | Faithful |
| `impl__unwrap_or` (10) | `Some x -> x`, `None -> default` | `Option::unwrap_or` (default evaluated eagerly in both) | Faithful |
| `impl__as_ref` (5) | Identity on the value: `Option<&T>` becomes `Option<T>` | Borrow; references are erased because the extracted code is pure | Faithful for the pure subset hax accepts |
| `impl__map` (1), `impl__map_or` (4) | `match` applying `f` through `FnOnce.f_call_once` | `Option::map`, `Option::map_or` | Faithful |
| `t_Result`, `Result_Ok`, `Result_Err` (24) | Two-constructor datatype | `enum Result<T, E>` | Faithful |
| `Core_models.Slice.impl__len` (126) | `sz (Seq.length s)` on `t_Slice t = s:seq t{length s <= max_usize}` | `<[T]>::len` | Over-approximate: Rust also bounds a slice by `isize::MAX` bytes, the model only by `usize::MAX` elements. Proofs stay sound; no proof needs the tighter bound today |
| `Alloc.Slice.impl__into_vec` (81), `Alloc.Vec.impl_1__as_slice` (24) | Copy the sequence into or out of `Vec` | `<[T]>::to_vec` / `into_vec`, `Vec::as_slice` | Faithful (allocation failure aborts in Rust; outside the model, as for all allocation) |
| `Rust_primitives.Hax.array_of_list` (162) | `Seq.seq_of_list l` with `length l == n < 65535` | Array or slice literal | Faithful. The bound only limits literal size; extraction fails, it does not mis-model, beyond it |
| `Core_models.Ops.Range.f_start`, `f_end` (18) | Record fields | `Range { start, end }` fields | Faithful |
| `Rust_primitives.Hax.Folds.fold_range` (99), `fold_range_wf_index` (99), `range_empty` (33) | Applies `f` to `start, start+1, ..., end-1`; returns `init` when `start >= end` | `for i in start..end` | Faithful, including the empty range. The invariant argument is proof-only |
| `Core_models.Clone.f_clone` (22) | Class method typed `x:self -> r:self{x == r}`; extracted modules use the instance `fun x -> x` | Derived `Clone` on plain data returns an equal value | Faithful for derived `Clone`. A hand-written `Clone` that returned a different value would be a gap; the corpus has none (every instance is the identity) |

**Result: no gaps.** One over-approximation (slice length bound) is harmless
for soundness. Two conditions to keep: the extracted code stays in hax's pure
subset (no interior mutability behind `as_ref`), and every `Clone` used in
extracted code stays derived. T7's differential tests should cover
`is_some`/`is_none`/`unwrap_or`/`map_or` and `fold_range` on empty and
non-empty ranges.

## T5: integers and overflow

Reviewed 2026-11-03. Source: `rust_primitives/Rust_primitives.Integers.fsti`
and `Rust_primitives.Notations.fsti`. `serverVELA` builds release with the
default `overflow-checks = false`, so plain `+` wraps in release and panics in
debug.

| Model (uses) | Definition | Rust | Verdict |
|---|---|---|---|
| Types `i64`, `u8`, `u64`, `u128`, `usize`, `i128`, `isize`; `mk_*`, `v`, `MkInt` (~4,800) | `int_t t` holds an F* integer refined to `[minint t, maxint t]` | Fixed-width integers | Faithful |
| `usize`/`isize` width | Abstract `size_bits`, either 32 or 64 | Target-dependent | Faithful: proofs hold for both widths |
| `+!`, `-!`, `*!` (166) | `add`/`sub`/`mul` with a precondition that the exact result is in range | `+`, `-`, `*` | Faithful. hax emits these for plain arithmetic, so every proof discharges "no overflow"; release wrapping and debug panics then cannot differ from the model |
| `+.` (9, in hand-written models only) | `add_mod`, wrapping | `wrapping_add` | Faithful to `wrapping_add`. **Gap:** the send-store model uses it for `view_count + 1`, but the real statement is SQL `UPDATE sends SET view_count = view_count + 1`. SQLite does not wrap at `i64::MAX`. That needs 2^63 views of a link with no `max_views`, so it can't happen in practice. Fix in O3b: model the SQL increment as bounded (precondition) instead of wrapping |
| `/!`, `%!` (4, `Vela_crypto.Wire`, on `u64`) | F* integer `/` and `%` with nonzero divisor | `/`, `%` | Faithful for unsigned. F* rounds signed division differently from Rust (Rust truncates toward zero), but no signed use exists; T7 should add a guard test |
| `add_sat` (5) | Clamp to `[minint, maxint]` | `saturating_add` | Faithful |
| `cast` | `mk_int (v x)` with a precondition that `x` fits the target | `as` | Faithful: proofs must show the value fits, where `as` is the identity. `cast_mod` (truncating) is unused |
| `=.`, `<>.` (1,134) | F* `=` and `<>` | `==`, `!=` | Faithful |
| `<.`, `<=.`, `>.`, `>=.` (380) | Compare `v a` and `v b` | `<`, `<=`, `>`, `>=` | Faithful |
| `ne` | `v b <> v b`, **always false** (a hax 0.3.7 library bug) | `!=` | Not used: the 5 matches are a local variable named `ne`. T7 or the escape check should reject any future use |
| `mul_overflow` | Overflow flag tests `< maxint` instead of `< minint` (library bug) | `overflowing_mul` | Not used |
| `~.` (2,830) | Typeclass: `not` on `bool`, abstract `lognot` on integers | `!` | Faithful on `bool`, which is every use found |
| `&.`, `<<!` (1 each, vault-mutation driver `oram_bucket_is_create`) | Abstract `logand` and `shift_left`, specified only by trusted lemmas; the shift amount must be in `[0, bits)` | `&`, `1u64 << index` | Faithful. The Rust guard `index >= 0 && index < 64` matches the shift precondition, and the lemmas used (`logand_lemma`, `logor_lemma`, `lognot_lemma`, `shift_left_positive_lemma`) are true for two's-complement bit operations |

**Result: one modeling gap (send view-count increment, unreachable in
practice) and two hax library bugs (`ne`, `mul_overflow`) the corpus does not
use.** The trusted bit lemmas are the only unproved integer facts the proofs
can rely on. They are true statements, but they stay in the trusted base.
