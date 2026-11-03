## T3: Vec, sequences and indexing

Reviewed 2026-11-03. Sources: hax 0.3.7 `proof-libs/fstar/core/Alloc.Vec.fst`,
`Alloc.Slice.fst`, `Core_models.Slice.fst`, `Alloc.Alloc.fst`,
`rust_primitives/Rust_primitives.Sequence.fst`, `Rust_primitives.Arrays.fsti`,
`Rust_primitives.Slice.fsti`, `Rust_primitives.Notations.fsti`,
`Rust_primitives.Hax.fst`, `Rust_primitives.Hax.Monomorphized_update_at.fsti`,
and the repository model
`libVELA/vela-crypto/proofs/fstar/models/Alloc.Vec.fst`. Uses and file lists
come from [inventory.json](../model-contract-inventory/inventory.json); I
re-counted each pattern below with `git grep`/Python over the 168 tracked
`*.fst` files outside `security/assurance/proof-logs` and give the two numbers
where they differ. Verdict words are the README's: **Faithful**,
**Over-approximate**, **Gap**.

Limits of this review: the counts are textual, so a name used through `open`
can over-count (this is why the inventory's 34 "uses" of `split` and 10 of
`length` are really a comment word and `List.Tot.length`/a local `length`
variable, not `Rust_primitives.Arrays` calls). inventory.json scanned 172 files
and I counted 168 tracked ones at this commit; no Vec/slice symbol's file list
changes between the two. No F* or Rust was run for this note, so every claim
below is read from the sources cited.

Every `.[ ]` in F* is the hax notation
`let ( .[] ) #self #idx {| inst: t_Index self idx |} (s:self) (i:idx{f_index_pre s i})`
(`rust_primitives/Rust_primitives.Notations.fsti:18-20`). A Rust indexing panic
therefore becomes a *refinement obligation*: an extracted term typechecks only
if the corpus proves the index in range, so a modeled execution cannot panic.
Rows marked **Faithful** also inherit the length-bound over-approximation that
the `t_Slice` and `t_Vec` rows record once: the model bounds a slice/Vec by
`usize::MAX` elements, Rust bounds it by `isize::MAX` **bytes**. Proofs stay
sound; no proof needs the tighter bound.

| Model (uses in corpus) | Definition | Rust semantics | Verdict |
|---|---|---|---|
| `Alloc.Vec.t_Vec` and the `Vec` constructor (type: 167 uses / 25 files; constructor: 3 uses / 1 file) | `type t_Vec (v_T: Type0) (v_A: Type0) = \| Vec : Rust_primitives.Sequence.t_Seq v_T -> Core_models.Marker.t_PhantomData v_A -> t_Vec v_T v_A` (`core/Alloc.Vec.fst:6-8`); the allocator argument `v_A` is `Alloc.Alloc.t_Global` (`core/Alloc.Alloc.fst:6`), a one-constructor unit type carried in a `PhantomData` (`core/Core_models.Marker.fst:36`) | `Vec<T, A> { ptr, len, capacity }`: a heap buffer with a length, a capacity and an allocation; capacity, pointer identity and aliasing are observable through `capacity()`, `as_ptr()` and `ptr::eq` | Over-approximate: a Vec is identified with its element sequence, so capacity, allocation state and buffer identity are erased and every sequence of at most `usize::MAX` elements is admitted (Rust admits at most `isize::MAX` bytes). Sound: every Rust Vec maps to a model value, and no corpus proof observes capacity or identity |
| `Alloc.Vec.impl__new` (2 / 2) | `Vec (Rust_primitives.Sequence.seq_empty #v_T ()) PhantomData` (`core/Alloc.Vec.fst:21-25`) | `Vec::new()`: no allocation, `len == 0`, `capacity == 0`, cannot panic | Faithful |
| `Alloc.Vec.impl_1__len` (1 / 1) | `Rust_primitives.Sequence.seq_len #v_T self._0` (`core/Alloc.Vec.fst:30-31`), i.e. `mk_usize (Seq.length s)` (`rust_primitives/Rust_primitives.Sequence.fst:15`) | `Vec::len`: O(1) element count, cannot panic | Faithful (the `mk_usize` refinement is discharged by the `t_Slice` length bound) |
| `Alloc.Vec.impl_1__as_slice` (24 / 6) | `Rust_primitives.Sequence.seq_to_slice #v_T self._0` (`core/Alloc.Vec.fst:65-66`), and `seq_to_slice s = s` (`Rust_primitives.Sequence.fst:13`) | `Vec::as_slice` / `Deref`: borrows the same buffer as `&self[..]`, no copy, cannot panic | Faithful: references are erased because the extracted code is pure, and the element sequence is preserved unchanged |
| `Alloc.Vec.impl_2__extend_from_slice` (2 / 1; only in `Vela_crypto.Wire`) | hax: `Pure` with `requires len s + len other <= max_usize` and `ensures True`, body `seq_concat s._0 (seq_from_slice other)` (`core/Alloc.Vec.fst:185-210`). Local model: refined argument `Seq.length s._0 + Seq.length other <= max_usize` and refined result `result._0 == Seq.append s._0 other` plus the two slice identities and the length (`libVELA/vela-crypto/proofs/fstar/models/Alloc.Vec.fst:27-39`, proved from `FStar.Seq.Properties.append_slices` at line 37) | `Vec::extend_from_slice`: clones every element of `other` onto the end, growing capacity (reallocation) as needed; panics with "capacity overflow" when `len + other.len` exceeds `isize::MAX` bytes, aborts on allocation failure, and propagates a panic from `T::clone` | Faithful for the resulting value and length; allocation/abort is outside the model, as for all allocation in T6, and the length bound is the `t_Vec` over-approximation above |
| `Alloc.Slice.impl__into_vec` (81 / 8) and `Alloc.Slice.impl__to_vec` (1 / 1) | `Vec (seq_from_slice s) PhantomData`, `seq_from_slice s = s` (`core/Alloc.Slice.fst:6-16`; `Rust_primitives.Sequence.fst:9`) | `<[T]>::to_vec` / `Vec::from(&[T])`: allocates a fresh buffer and copies the elements; `<[T]>::into_vec` (on a `Box<[T]>`) reuses that allocation. Both abort on allocation failure and panic on capacity overflow (`len * size_of::<T>() > isize::MAX`) | Faithful (same verdict and same allocator caveat as T6): the produced element sequence and length are exactly the source slice's. Copying vs. reusing a `Box` allocation is not distinguishable in the pure model |
| `Core_models.Slice.impl__len` (126 / 14) | `Rust_primitives.Slice.slice_length #v_T s`, i.e. `sz (Seq.length s)` (`core/Core_models.Slice.fst:6`; `rust_primitives/Rust_primitives.Slice.fsti:7`) | `<[T]>::len`: element count as `usize`, cannot panic | Over-approximate, identical to the T6 row: the model allows up to `usize::MAX` elements, Rust up to `isize::MAX` bytes |
| `Core_models.Slice.impl__is_empty` (3 / 2) | `impl__len s =. mk_usize 0` (`core/Core_models.Slice.fst:19`) | `<[T]>::is_empty`: `len == 0`, cannot panic | Faithful |
| Element indexing `s.[ i ]` on `t_Slice` and `t_Array` (267 expressions / 13 files: 116 on slices, 151 on fixed byte arrays) | Slice instance `impl_11`: `f_index_pre = i <. impl__len self_`, `f_index = Rust_primitives.Slice.slice_index s i = Seq.index s (v i)` (`core/Core_models.Slice.fst:177-184`; `Rust_primitives.Slice.fsti:11`). Array instances `impl__index_refined` / `impl__index`: `f_index_pre = v i >= 0 && v i < v l`, `f_index = Seq.index s (v i)` (`rust_primitives/Rust_primitives.Hax.fst:26-45`). `Seq.index` itself requires `i < length s` (`FStar.Seq.Base.fsti:32`) | `v[i]`, `s[i]`, `a[i]`: panics when `i >= len` (for a fixed array the compiler can also reject a constant out-of-range index at compile time); no allocation | Faithful: the panic is exactly the model's `f_index_pre`, so a well-typed use carries a proof that Rust cannot panic. Every corpus use is either a constant index into a fixed `u8` array (`Vela_crypto.Wire.decode_u64_be` on `t_Array u8 8`, the session-policy tag comparisons on `t_Array u8 9`) or sits behind an explicit length test that yields `i < len` (`Vela_share_policy.Store.classify_send`/`classify_rows` test `len = k`, `Vela_crypto.Wire.split_u64_prefix` tests `len >= 8` before reading bytes 0-7) |
| Range indexing `s.[ a..b ]` (`Range`, `RangeTo`, `RangeFrom`, `RangeFull`) (13 expressions / 2 files) | `impl_7`/`impl_8`/`impl_9`/`impl_10`: preconditions `start <= end <= len`, `end <= len`, `start <= len`, `true`; bodies `slice_slice` = `Seq.slice s start end` (`core/Core_models.Slice.fst:97-175`; `rust_primitives/Rust_primitives.Slice.fsti:12-13`) | `&s[a..b]` panics if `a > b` or `b > len`; `&s[..b]` if `b > len`; `&s[a..]` if `a > len`; `&s[..]` cannot panic; no allocation | Faithful: the preconditions are exactly the panic conditions. Every corpus range use sits in the branch of the length test that makes it valid: `Vela_crypto.Share_envelope.split_envelope_prefix` (line 118), `Vela_crypto.Wire.split_u64_prefix` (`len < 8` guard at line 141), `split_length_prefixed` (`length > payload.len` at line 283), `frame_body` (`len < prefix_len \|\| len - prefix_len < trailer_len` at line 551), and `domain_message`'s postcondition over `as_slice message` (lines 590-605) |
| `Rust_primitives.Arrays.t_Slice` / `t_Array` (574 / 23 and 39 / 5) | `type t_Slice t = s:Seq.seq t{Seq.length s <= max_usize}`, `type t_Array t (l:usize) = s:Seq.seq t{Seq.length s == v l}` (`rust_primitives/Rust_primitives.Arrays.fsti:7-8`) | `&[T]` is (ptr, len) into a buffer of `len * size_of::<T>() <= isize::MAX` bytes; `[T; N]` has a compile-time length | Over-approximate for `t_Slice` (element-count bound, as in T6). Faithful for `t_Array`: the length is a type index, and all 162 `array_of_list` calls in the corpus pass a literal (1, 2, 4, 6, 8 or 9), so every array length is concrete |
| `Rust_primitives.Sequence.t_Seq`, `seq_empty`, `seq_from_slice`, `seq_to_slice`, `seq_len`, `seq_concat` (1 use each; all six inside `models/Alloc.Vec.fst`; no use in any extracted module) | `t_Seq t = t_Slice t`; `seq_empty = Seq.empty`; `seq_from_slice s = s`; `seq_to_slice s = s`; `seq_len = mk_usize (Seq.length s)`; `seq_concat = Seq.append` under `len1 + len2 <= max_usize` (`rust_primitives/Rust_primitives.Sequence.fst:5-25`) | No Rust call is modeled here: these are the F* sequence operations the Vec/Slice models are built from | Faithful: each is the identity or the corresponding total F* `Seq` operation. `seq_slice`, `seq_index`, `seq_one`, `seq_create` (`:17-29`) are reached only by unused Vec operations |

| Model (not reached by the 168-file corpus) | Definition | Rust semantics | Verdict |
|---|---|---|---|
| `Rust_primitives.Hax.Monomorphized_update_at.update_at_usize` (**0 uses**) | `Seq.upd s (v i) x` with `i: usize {v i < Seq.length s}` (`rust_primitives/Rust_primitives.Hax.Monomorphized_update_at.fsti:10-16`) | `s[i] = x`: panics if `i >= len`, cannot change the length | Faithful, unused |
| `Rust_primitives.Hax.Monomorphized_update_at.update_at_range`, `_range_to`, `_range_from`, `_range_full` and `Rust_primitives.Hax.update_at_array_range`, `_range_to`, `_range_from`, `_range_full` (**0 uses**) | Bare `val` with no body anywhere in the library (`.fsti:18-63`), and `assume val` (`Rust_primitives.Hax.fst:62-73`): the result is **unconstrained** apart from the `Pure` postcondition of the `Monomorphized_update_at` four | `s[a..b] = x` panics if the range is invalid or `x.len() != b - a`; cannot change the length | Gap, unreached: anything proved from these says nothing about Rust. `(.[]<-)` (`Rust_primitives.Hax.fst:93-94`) is the notation that would reach them |
| Assumed `Alloc.Vec` operations: `impl_1__truncate'`, `impl_1__swap_remove'`, `impl_1__remove'`, `impl_1__clear'`, `impl_1__drain'`, `impl_1__resize'`, `impl_5'` (FromIterator) (**0 uses**) | `assume val` with no specification (only `resize'` has the `ensures len = new_size`), wrapped by `unfold let` (`core/Alloc.Vec.fst:68-100`, `:147-162`, `:234-240`) | `truncate`/`clear`/`remove`/`swap_remove`/`drain`/`resize`/`collect`: each has a precise element-level result and its own panic conditions (`remove`/`swap_remove` panic when `index >= len`, `resize` panics on capacity overflow, `drain` panics on an invalid range) | Gap, unreached: the model returns an arbitrary Vec. T1's rule "no assumed library symbol is used" is what keeps the corpus sound |
| Defined but unused `Alloc.Vec` operations: `from_elem`, `impl__with_capacity`, `impl_1__pop`, `impl_1__is_empty`, `impl_1__push`, `impl_1__insert`, `impl_1__append`, and the `Index` (`impl_3`) and `Deref` (`impl_4`) instances (**0 uses**; `impl_3` would be the only Vec `.[]`) | `core/Alloc.Vec.fst:10-19`, `:27-28`, `:33-60`, `:62-63`, `:102-119`, `:121-145`, `:164-183`, `:212-223`, `:225-232` | `push`/`insert`/`append` may reallocate and panic on capacity overflow; `insert` panics when `index > len`; `pop` returns `Option<T>`; `with_capacity(c)` allocates capacity `c`; `as_slice` via `Deref`/`Index` panics when `i >= len` | Faithful or Over-approximate individually (`push`/`append` bound by `usize::MAX` elements; `impl__with_capacity c` returns the empty Vec and drops `c`, which is faithful for `len` and loses the capacity fact the model never has), all unreached |
| Hand-written `Seq` uses: `Seq.length` (26 / 3), `Seq.index` (21 / 10), `Seq.seq_of_list` (30 / 16), `Seq.seq_to_list` (20 / 9), `Seq.Properties.append_slices` (1 / 1), `Seq.empty` (1 / 1), `Seq.append` (1 / 1), `Seq.slice` (2 / 1) | `FStar.Seq.Base.fsti` / `FStar.Seq.Properties.fsti`; `Seq.index` requires `i < length s` | No Rust counterpart: these are F* library operations over `seq` | Faithful / not a Rust model. All 19 files are `models/` or `*-lemmas/` directories; **zero** `Seq.*` uses occur in any `extraction*` module, so extracted code only ever speaks through `Alloc.Vec`/`Alloc.Slice`/`Core_models.Slice` |

### Local model `libVELA/vela-crypto/proofs/fstar/models/Alloc.Vec.fst`

`verify-share-facts-fstar.sh` puts `--include "$hax_lib_root/proof-libs/fstar/core"`
(line 27) *before* `--include proofs/fstar/models` (line 32), but it also lists
`proofs/fstar/models/Alloc.Vec.fst` explicitly as the first checked module
(line 34). The explicit file is what the gate checks as `Alloc.Vec`, and the
gate's success on `domain_message`, whose `ensures` needs
`impl_1__len message = len domain + len body` (`Vela_crypto.Wire.fst:585-605`) —
a fact only the local `extend_from_slice` postcondition provides — shows the
local file is the one in force. I did not re-run the gate (no builds in this
step); this is an inference from the committed log
`proof-logs/current/extended-formalization/share-facts-fstar.log` and the
script.

| Aspect | hax `core/Alloc.Vec.fst` (240 lines) | local `models/Alloc.Vec.fst` (39 lines) |
|---|---|---|
| `t_Vec` / `Vec` constructor | `:6-8` | identical, `:6-8` |
| `impl__new`, `impl_1__len`, `impl_1__as_slice` | `:21-25`, `:30-31`, `:65-66` | identical bodies, `:12-16`, `:18-19`, `:21-22` |
| `impl_2__extend_from_slice` | `Pure` with an `Hax_lib.Int` `requires` on the two lengths and `ensures True` (`:185-210`); callers learn nothing about the result | refined argument (`Seq.length s._0 + Seq.length other <= max_usize`) and refined result (`result._0 == Seq.append s._0 other`, the two slice identities, the resulting length), `:27-39` |
| Everything else | `from_elem`, `impl__with_capacity`, `impl_1__pop`, `impl_1__push`, `impl_1__insert`, `impl_1__append`, the seven `assume val`s, the `Index`/`Deref`/`FromIterator` instances | absent |

Consequences worth keeping:

- The local file contains no `assume`, `admit` or bare `val` (0 matches for
  `assume`), so in the vela-crypto gate the Vec model contributes **no assumed
  symbol**. `Core_models.Slice`'s three `assume val`s (`impl__contains'`,
  `impl__copy_within'`, `impl__binary_search'`) are still loaded as a dependency
  of `impl__len`, but no vela-crypto module references them; `Alloc.Slice` is not
  referenced at all by the vela-crypto extraction.
- Dropping the rest means a future vela-crypto extraction that uses `Vec::push`,
  `truncate`, `vec[i]` or `&*vec` **fails to typecheck** in the gate instead of
  silently picking up an assumed or unconstrained model. That is the safe
  failure direction, and it is the main argument for keeping the reduced file.
- The strengthening in the local `extend_from_slice` is a *true* fact
  (`Seq.append` is `Vec::extend_from_slice`'s element-level result), not an
  extra assumption, but it is local and has no hax counterpart; it is the one
  Vec statement T7's differential test should check byte for byte.
- Compatibility condition: hax's `Alloc.Slice.impl__into_vec` constructs
  `Alloc.Vec.Vec` (`core/Alloc.Slice.fst:12-16`), so the constructor's name and
  type must stay identical between the two files. It currently is. vela-crypto
  does not reference `Alloc.Slice` today, so the coupling is latent.

### Gaps

No reached Vec, sequence or indexing operation is a gap. Specifically:

1. **`Monomorphized_update_at` range family and `update_at_array_range*`** are
   unconstrained (`val` with no body / `assume val`). Nothing in the corpus uses
   them, so no proof rests on them, but an extraction that emitted `s[a..b] = x`
   would get an arbitrary result. Owner: **T2** should extend the zero-assumption
   gate to reject *reachable* library `assume val`s (it currently scans the
   corpus only, so the T1 inventory is the only thing preventing this), and
   **T7** should cover `update_at` once it is modeled.
2. **The seven assumed `Alloc.Vec` operations** (`truncate`, `swap_remove`,
   `remove`, `clear`, `drain`, `resize`, `FromIterator`) are the same latent
   gap: an unspecified result for a real Rust function. Owner: **T2** (same
   reachability gate) and **T7**. The vela-crypto gate is already safe because
   the local model omits them.
3. **Not a gap, but a limit of the claims:** the model has no capacity, no
   allocation and no buffer identity, so no proof can state that a `Vec` is not
   reallocated, that two `Vec`s do not alias, or that `capacity()` has any
   value. The corpus never tries to (the only `Vec` values are built by
   `impl__new` + `extend_from_slice` in `Vela_crypto.Wire.domain_message`, by
   `into_vec` from `array_of_list` literals in the store/executor plans, and by
   three explicit `Alloc.Vec.Vec` constructions in
   `Vela_session_policy_challenge_take_adapter`). Keep any such statement out of
   the claim set; T7 tests behaviour, not allocation.
4. **Not a gap, but untested:** the element-count vs `isize::MAX`-byte bound.
   The one place where a large length could reach the model,
   `Vela_crypto.Wire.domain_message`, guards with `isize::MAX` itself
   (`wire.rs:239-242`, model lines 610-614), so the model's weaker precondition
   is discharged and the tighter Rust limit is enforced by the code. Owner:
   **T7** should include the boundary (`len = isize::MAX`, `len = isize::MAX + 1`)
   for `extend_from_slice` and `to_vec`.

**Result: no gap in any operation the corpus reaches.** The reached subset is
`t_Vec`, `Vec`, `impl__new`, `impl_1__len`, `impl_1__as_slice`,
`impl_2__extend_from_slice`, `Alloc.Slice.impl__into_vec`/`impl__to_vec`,
`Core_models.Slice.impl__len`/`impl__is_empty`, element and range indexing, and
the `Rust_primitives.Sequence` primitives; `Vec` is never indexed, pushed,
popped, inserted into, truncated or updated, and `Monomorphized_update_at` is
never referenced (0 uses). None of `Alloc.Vec`'s seven `assume val`s appears in
the corpus, which confirms T1 for Vec. Two over-approximations are harmless
(element-count length bounds; no capacity, allocation or identity), one local
model strengthens `extend_from_slice` with a true postcondition, and the two
latent gaps are the assumed `Alloc.Vec` operations and the unconstrained
update-at range family. Conditions to keep: the local `Alloc.Vec` keeps hax's
`Vec` constructor shape and stays the file the gate checks; no proof states a
capacity or aliasing fact; `Vec` stays unindexed and unmutated in extracted
code. T7 should differential-test `len`, `as_slice`, `extend_from_slice` (the
local postcondition), `into_vec`/`to_vec`, element and range indexing, and the
`isize::MAX` boundary.
