# Differential test of the std models against Rust (plan step T7)

Evidence run of `security/formal/std-model-diff`: the hax 0.3.7 F* definitions
the VELA corpus relies on, executed through F*'s OCaml extraction on the same
seeded inputs as the Rust standard library. Companion documents: the
[T3-T6 review](../std-model-review/README.md) (what each model means), the
[model inventory](../model-contract-inventory/README.md) (which symbols the
corpus uses), and the harness [README](../../../../formal/std-model-diff/README.md).

* Run: `security/formal/std-model-diff/run.sh --cases 1000000 --log <this file's path>`
* Seed: `0x5EED1234ABCD0001` (6840143426475589633), block size 1024. 119 of the
  127 operations get 10^6 cases; the seven `bounds` rows are a single case each
  and `phase.eq` is the four constructor pairs (119 x 10^6 + 7 + 4 =
  119 000 011). CI uses 10^4 cases with the same seed.
* Raw log: [evidence-run.log](evidence-run.log).

**Result: 127 operations, 119 000 011 cases, 0 mismatching blocks.** Every
runnable model operation produced the same value as Rust on every case; the two
documented hax-lib bugs reproduce exactly as the T5 review describes.

## Method

`make_shadow.py` copies the pinned model modules into a private `.fst` tree by
selecting declaration blocks verbatim (21 modules, one added line: the 64-bit
`size_bits` instantiation). `fstar.exe --lax --codegen OCaml` extracts them,
`ocaml/driver.ml` calls the extracted functions, `rust/src/main.rs` calls the
Rust standard library, and both implement the same case generator and canonical
encoding. Each run prints one FNV-1a hash per block of 1024 cases over
`inputs || '=' || result`, so mismatches cannot hide in a summary and a
generator divergence fails on the first block. `--lax` means F* typechecks but
does not re-prove the models; the preconditions are tested operationally (see
the harness README).

Method column: **extracted** = the F* definition was run and compared value by
value; **normalizer** = an F* proof obligation about a definition the extraction
cannot show (checked without `--lax`); **axiom** = the corpus value has no body,
so the harness pins the reading the proofs use.

## Operation table

| op ids | model definition | method | cases | mismatches |
|---|---|---|---|---|
| `<t>.add_checked` (`u8 u64 u128 i64 i128 usize isize`) | `Rust_primitives.Integers.add` (`+!`) `Rust_primitives.Integers.fsti:207`, precondition `range` `fsti:66` | extracted: model `range` vs `Some`/`None` of `checked_add`, value vs `checked_add` | 10^6 each | 0 |
| `<t>.sub_checked` | `sub` (`-!`) `fsti:228` | `checked_sub` | 10^6 each | 0 |
| `<t>.mul_checked` | `mul` (`*!`) `fsti:221` | `checked_mul` | 10^6 each | 0 |
| `<t>.add_mod` | `add_mod` (`+.`) `fsti:188` | `wrapping_add` | 10^6 each | 0 |
| `<t>.add_sat` | `add_sat` `fsti:191` | `saturating_add` | 10^6 each | 0 |
| `<t>.sub_sat` | `sub_sat` `fsti:199` | `saturating_sub` | 10^6 each | 0 |
| `<t>.eq` | `=.` `fsti:441` (`eq` `fsti:245`) | `==` | 10^6 each | 0 |
| `<t>.lt` | `<.` `fsti:447` (`lt` `fsti:247`) | `<` | 10^6 each | 0 |
| `<t>.lte` | `<=.` `fsti:450` | `<=` | 10^6 each | 0 |
| `<t>.gt` | `>.` `fsti:453` | `>` | 10^6 each | 0 |
| `<t>.gte` | `>=.` `fsti:456` | `>=` | 10^6 each | 0 |
| `<t>.bounds` | `minint` `fsti:56`, `maxint` `fsti:59` | 1 case per type vs `MIN`/`MAX` | 1 each | 0 |
| `u64.div_checked` | `div` (`/!`) `fsti:235` | `/`, and `None` on a zero divisor | 10^6 | 0 |
| `u64.mod_checked` | `mod` (`%!`) `fsti:239` | `%`, and `None` on a zero divisor | 10^6 | 0 |
| `cast.u8.u64` `cast.u8.u128` `cast.u8.i64` `cast.u64.u128` `cast.usize.u64` `cast.u64.usize` `cast.i64.i128` `cast.isize.i64` `cast.i64.isize` | `cast` `fsti:169` (in range by construction) | `as` | 10^6 each | 0 |
| `cast.u64.i64` `cast.i64.u64` `cast.u128.u64` `cast.i128.i64` | `cast` `fsti:169` with the `range (v u1) t'` precondition | `Some`/`None` of the precondition, then `as` | 10^6 each | 0 |
| `option.is_some` | `Core_models.Bundle.impl__is_some` `Core_models.Bundle.fst:149` | `Option::is_some` | 10^6 | 0 |
| `option.is_none` | `impl__is_none` `:160` | `Option::is_none` | 10^6 | 0 |
| `option.is_some_and` | `impl__is_some_and` `:10` | `Option::is_some_and` | 10^6 | 0 |
| `option.unwrap_or` | `impl__unwrap_or` `:39` | `Option::unwrap_or` | 10^6 | 0 |
| `option.map` | `impl__map` `:71` | `Option::map` | 10^6 | 0 |
| `option.map_or` | `impl__map_or` `:86` | `Option::map_or` | 10^6 | 0 |
| `option.as_ref` | `impl__as_ref` `:34` | `Option::as_ref` (borrow erased) | 10^6 | 0 |
| `slice.len` | `Core_models.Slice.impl__len` `Core_models.Slice.fst:6` | `[T]::len` | 10^6 | 0 |
| `slice.is_empty` | `impl__is_empty` `:19` | `[T]::is_empty` | 10^6 | 0 |
| `slice.index` | `impl_11` `:178` via `Rust_primitives.Slice.slice_index` `Rust_primitives.Slice.fsti:11` | `v[i]`, in range only (out of range is the model's `f_index_pre` = the Rust panic) | 10^6 | 0 |
| `vec.new` | local `Alloc.Vec.impl__new` `libVELA/vela-crypto/proofs/fstar/models/Alloc.Vec.fst:12` | `Vec::new` | 10^6 | 0 |
| `vec.len` | local `impl_1__len` `:18` | `Vec::len` | 10^6 | 0 |
| `vec.as_slice` | local `impl_1__as_slice` `:21` | `Vec::as_slice`, element by element | 10^6 | 0 |
| `vec.extend_from_slice` | local `impl_2__extend_from_slice` `:27` (the strengthened local postcondition) | `Vec::extend_from_slice` | 10^6 | 0 |
| `vec.into_vec` | `Alloc.Slice.impl__into_vec` `Alloc.Slice.fst:12` | `Box<[T]>::into_vec` | 10^6 | 0 |
| `vec.to_vec` | `Alloc.Slice.impl__to_vec` `:6` | `[T]::to_vec` | 10^6 | 0 |
| `array_of_list` | `Rust_primitives.Hax.array_of_list` `Rust_primitives.Hax.fst:96` | array/slice literal, elements read back | 10^6 | 0 |
| `fold_range.empty` | `Rust_primitives.Hax.Folds.fold_range` `Rust_primitives.Hax.Folds.fsti:128`, `range_empty` `:125` | `for i in start..end` with `start >= end` | 10^6 | 0 |
| `fold_range.start_eq_end` | same | `start == end` | 10^6 | 0 |
| `fold_range.nonempty` | same | `start < end`, up to 16 iterations | 10^6 | 0 |
| `string.new` | local `Alloc.String.impl_String__new` `libVELA/vela-crypto/proofs/fstar/models/Alloc.String.fst:8` | `String::new` | 10^6 | 0 |
| `string.as_str` | local `impl_String__as_str` `:49` | `String::as_str`, byte for byte | 10^6 | 0 |
| `string.eq` | F* `=` on `Alloc.String.t_String` `:6` | `String == String` | 10^6 | 0 |
| `string.length_chars` | `FStar.String.length` (character count) | `str::chars().count()`, non-ASCII inputs | 10^6 | 0 |
| `bool.not` | `Rust_primitives.Notations.negation_for_bool` `Rust_primitives.Notations.fsti:12` (`~.`) | `!` | 10^6 | 0 |
| `clone.identity` | `Core_models.Clone.impl` `Core_models.Clone.fst:13` (`f_clone = fun x -> x`) | `Clone::clone` on a `(Vec<u8>, String)`; the clone must equal the original | 10^6 | 0 |
| `partialeq.u64` | `Core_models.Cmp.impl_18` `Core_models.Cmp.fst:688` | `==` | 10^6 | 0 |
| `phase.eq` | `T7_phase.phase_eq` (`security/formal/std-model-diff/fstar/T7_phase.fst`), the reading of the assumed `impl_7' : t_PartialEq t_Phase` | axiom | Rust's derived `==`, all 4 constructor pairs | 4 | 0 |

`usize`/`isize` are the 64-bit instantiation of the abstract `size_bits`; the
model's `minint U64`/`maxint U64` etc. match `u64::MIN`/`u64::MAX` (`bounds`).

### Boundaries covered

Every operation also receives the boundary values of its type, cycled through
its first cases and re-drawn for one random case in sixteen: `min`, `min+1`,
`min/2`, `0`, `1`, `2`, `max/2`, `max`, plus `usize::MAX`/`isize::MAX` from the
`bounds` rows. `fold_range` is exercised with `start > end`, `start == end` and
non-empty ranges. The generator is in `ocaml/driver.ml` / `rust/src/main.rs`
(same code, checked by the hash of the inputs).

### Byte length vs character length

`string.length_chars` compares the model's `FStar.String.length` with
`chars().count()` on non-ASCII strings. The Rust run also prints the byte
length next to it, so the difference the T4 review records is in the log:

```
string.bytes.<empty>   chars=0 bytes=0
string.bytes.e         chars=1 bytes=1
string.bytes.é         chars=1 bytes=2
string.bytes.€         chars=1 bytes=3
string.bytes.😀        chars=1 bytes=4
```

The model counts characters, Rust's `String::len` counts bytes, and the
corpus only measures strings that are ASCII (base64) so the two agree where it
matters. The model has no executable byte-length function (`impl_str__len` is
an abstract `val`), which is why this row is the character count.

## The two documented hax-lib bugs

The guards (`check-model-guards.py`) reject any corpus use of `ne`,
`mul_overflow` or `/!`/`%!` outside the reviewed `u64` allowlist. The log shows
the guard biting on three injected uses, then shows *why*:

```
demo.ne.u64: 10000 cases, model `ne` always false, Rust `!=` true in 9982 cases, 0 unexpected
demo.mul_overflow.u64: 10000 cases (9191 overflow, 809 in range); model flag == (prod != MAX) in all cases, so it is wrong in 805 of the 809 in-range products; 0 unexpected
demo.mul_overflow.i64: 10000 cases (9575 overflow, 425 in range); model flag == (prod != MAX) in all cases, so it is wrong in 424 of the 425 in-range products; 0 unexpected
```

(`Rust_primitives.Integers.ne` `fsti:246` is `v b <> v b`; `mul_overflow`
`fsti:218` tests `< maxint t` where it should test `< minint t`, so its flag is
true for every product except exactly `maxint`.)

## Signed division

F* integer division is Euclidean (non-negative remainder); Rust truncates
towards zero. The extracted OCaml truncates like Rust, so this cannot be
checked by extraction. `semantics/T7_semantics.fst` asserts the six signed
cases against the F* specification without `--lax` (all verified), and the Rust
run prints its column in the log:

```
div.rounding  (-7)/2=-3 (-7)%2=-1 7/(-2)=-3 7%(-2)=1 (-7)/(-2)=3 (-7)%(-2)=-1
```

F* gives `-4, 1, -3, 1, 4, 1` for the same expressions. The corpus uses `/!`
and `%!` on `u64` only, where the two agree.

## Abstract symbols (not run)

`lognot`, `logand`, `logor`, `logxor`, `shift_left`, `rotate_left`,
`rotate_right` (`fsti:265-353`) have no body. `&.` and `<<!` are used once
each; the trusted lemmas they rely on are checked against Rust's operators on
10^6 samples (`N bit_lemma_samples 1000000 violations=0` in the log). Also not
runnable: `str_concat`, `str_of_char`, `str_sub`, `str_index`,
`impl_str__len` (used only by the unreachable `Alloc.String.push`/`pop`), and
`Alloc.Fmt.format` over the assumed `format'` (T4's `format!` gap) — see the
harness README for the full list and why each is unreachable.

## What remains trusted / unverified

* The F* definitions are *executed*, not re-proved, here (`--lax`). Their
  correctness as F* terms is the crate gates' job; this log only says the
  values agree with Rust.
* The abstract symbols above stay in the trusted base; the bit-lemma sample
  check shows the axioms are true of the real operators, which is a consistency
  check, not a refinement proof.
* `phase.eq` pins the meaning of an `assume val` (the derived `PartialEq` for
  `t_Phase`); the axiom itself is not executable and stays in the trusted base.
* CI (`std-model-diff.yml`) runs 10^4 cases per operation on a GitHub-hosted
  runner. Its tool-install step is the one thing this evidence run does not
  exercise: it installs the pinned F* release plus an OCaml 4.14 switch for
  F*'s shipped `fstar.lib`. The proof-container path (the parent's plan) will
  replace it.
* Versions of the evidence run: F* 2025.10.06, Z3 4.13.3, OCaml 5.1.1 with
  zarith 1.14 and batteries 3.11.0, rustc 1.101.0-nightly, hax-lib 0.3.7.
  The 21 pinned hax-lib files are verified by sha256 (`pins.sha256`); the two
  local models' hashes are printed in the log.
