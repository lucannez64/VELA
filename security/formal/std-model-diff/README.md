# std-model-diff: the F* std models against real Rust (plan step T7)

The VELA proofs trust the hax 0.3.7 model of Rust's standard library: integers,
`Option`, slices, `Vec`, `String`, `Clone` and `PartialEq`. Steps T3-T6 reviewed
those definitions by hand against the Rust semantics they stand for. This
directory is the machine check the review asked for: it **runs the reviewed F*
definitions** on seeded pseudo-random inputs and compares every value with the
Rust standard library function the model replaces.

Nothing here is a re-implementation of a model. `make_shadow.py` selects
declaration blocks out of the pinned model files; `ocaml/driver.ml` calls the
extracted F* functions; `rust/src/main.rs` calls `checked_add`,
`wrapping_mul`, `saturating_add`, `/`, `%`, `&`, `!`, `Vec::extend_from_slice`,
`String::len`, `str::chars().count()`, derived `Clone`/`PartialEq` and so on.

## Method

1. **Shadow tree.** F* only emits `.ml` for a *module* (`.fst`), and the pinned
   models live in interface files that mix definitions with abstract `val`s
   (no code to run). `make_shadow.py` writes a private `.fst` copy of each
   module it runs by selecting declaration blocks **by name, verbatim, in pin
   order**. The only added line in the whole tree is
   `let size_bits: n:nat{n == 32 \/ n == 64} = 64` in
   `Rust_primitives.Integers`: `size_bits` is abstract in the pin because the
   proofs hold for a 32- or 64-bit target, and the harness runs the 64-bit
   target the Rust side is built for. `--verbose` prints every kept block with
   its pin line number.
2. **`fstar.exe --lax --codegen OCaml`** on the shadow tree. `--lax` skips SMT
   obligations (the crate gates prove the models; this harness only *runs*
   them) while F* still typechecks every term. The checked-arithmetic protocol
   below evaluates the same `range` predicate at run time, so the preconditions
   are still exercised.
3. **Two independent runs on the same inputs.** Both drivers implement the same
   case generator (`splitmix64` draws keyed by the FNV-1a hash of the op name,
   so the input stream does not depend on list order), the same edge tables and
   the same canonical encoding. Each run prints one FNV-1a hash per block of
   1024 cases over `input-bytes || '=' || result`, so the *inputs* are part of
   the hash: a divergence in the generator fails on the first block instead of
   passing silently.
4. **`compare.py hash`** requires every `(op, block)` hash to be equal, and
   prints the case/block/mismatch table that goes into the evidence log.

Cases per op: 10^6 for the evidence run (`run.sh`), 10^4 in CI. Seed
`0x5EED1234ABCD0001`, block 1024, both recorded in the log. Two rows are
exhaustive instead of sampled: `bounds` has exactly one possible input per type
(the type's constants) and `phase.eq` is all four constructor pairs of a
two-constructor enum. Every operation
first sees the boundary cases of its type (min, min+1, min/2, 0, 1, 2, max/2,
max, per input slot, cycled over the first 8 cases), then a uniform draw, with
roughly one random case in sixteen replaced by another boundary value.

### Operation table

`<t>` is one of `u8 u64 u128 i64 i128 usize isize`; `usize`/`isize` are the
64-bit instantiation of `size_bits`.

| Test id | F* definition under test | Method |
|---|---|---|
| `<t>.add_checked` | `Rust_primitives.Integers.add` (`+!`) `fsti:207`; precondition `range (v a + v b) t` `fsti:66` | extracted: model value vs `checked_add`; model `range` vs `Some`/`None` |
| `<t>.sub_checked` | `sub` (`-!`) `fsti:228` | `checked_sub` |
| `<t>.mul_checked` | `mul` (`*!`) `fsti:221` | `checked_mul` |
| `<t>.add_mod` | `add_mod` (`+.`) `fsti:188` | `wrapping_add` |
| `<t>.add_sat` | `add_sat` `fsti:191` | `saturating_add` |
| `<t>.sub_sat` | `sub_sat` `fsti:199` | `saturating_sub` |
| `<t>.eq` `lt` `lte` `gt` `gte` | `=.` `fsti:441`, `<.` `fsti:447`, `<=.` `fsti:450`, `>.` `fsti:453`, `>=.` `fsti:456` | `==`, `<`, `<=`, `>`, `>=` |
| `<t>.bounds` | `minint` `fsti:56`, `maxint` `fsti:59` | `MIN`/`MAX` (one case per type) |
| `u64.div_checked`, `u64.mod_checked` | `div` (`/!`) `fsti:235`, `mod` (`%!`) `fsti:239` | `/`, `%`, `None` on a zero divisor. Unsigned only: see *not run* below |
| `phase.eq` | `T7_phase.phase_eq` (`fstar/T7_phase.fst`), the meaning of the assumed `t_PartialEq t_Phase` | Rust's derived `==` on all four constructor pairs |
| `cast.<from>.<to>` | `cast` `fsti:169` (9 in-range, 4 with the `range (v u1) t'` precondition) | `as`, and `Some`/`None` on the precondition |
| `option.is_some`, `is_none` | `Core_models.Bundle.impl__is_some` `:149`, `impl__is_none` `:160` | `Option::is_some`/`is_none` |
| `option.is_some_and` | `impl__is_some_and` `:10` | `Option::is_some_and` with a closure |
| `option.unwrap_or` | `impl__unwrap_or` `:39` | `Option::unwrap_or` |
| `option.map` | `impl__map` `:71` | `Option::map` |
| `option.map_or` | `impl__map_or` `:86` | `Option::map_or` |
| `option.as_ref` | `impl__as_ref` `:34` | `Option::as_ref` in the pure subset (references erased) |
| `slice.len`, `slice.is_empty` | `Core_models.Slice.impl__len` `:6`, `impl__is_empty` `:19` over `Rust_primitives.Arrays.t_Slice` `:7` | `[T]::len`, `[T]::is_empty` |
| `slice.index` | `Core_models.Slice.impl_11` `:178` through `Rust_primitives.Slice.slice_index` `:11` | `v[i]` (in-range only; out of range is the model's `f_index_pre`, i.e. the Rust panic) |
| `vec.new`, `vec.len`, `vec.as_slice` | local `Alloc.Vec.impl__new` `:12`, `impl_1__len` `:18`, `impl_1__as_slice` `:21` | `Vec::new`, `len`, `as_slice` |
| `vec.extend_from_slice` | local `Alloc.Vec.impl_2__extend_from_slice` `:27` (the strengthened local postcondition) | `Vec::extend_from_slice` |
| `vec.into_vec`, `vec.to_vec` | `Alloc.Slice.impl__into_vec` `:12`, `impl__to_vec` `:6` | `Box<[T]>::into_vec`, `[T]::to_vec` |
| `array_of_list` | `Rust_primitives.Hax.array_of_list` `:96` | array/slice literal: read back the elements |
| `fold_range.empty`, `start_eq_end`, `nonempty` | `Rust_primitives.Hax.Folds.fold_range` `:128`, `range_empty` `:125` | `for i in start..end`, including `start >= end` and `start == end` |
| `string.new` | local `Alloc.String.impl_String__new` `:8` | `String::new` |
| `string.as_str` | local `Alloc.String.impl_String__as_str` `:49` | `String::as_str` byte for byte |
| `string.eq` | F* `=` on `Alloc.String.t_String` `:6` | `String == String` |
| `string.length_chars` | `FStar.String.length` (char count) | `str::chars().count()`, on non-ASCII inputs |
| `bool.not` | `Rust_primitives.Notations.negation_for_bool` `:12` (`~.`) | `!` |
| `clone.identity` | `Core_models.Clone.impl` `:13` (`f_clone = fun x -> x`) | `Clone::clone` on a `(Vec<u8>, String)` value: the clone equals the original |
| `partialeq.u64` | `Core_models.Cmp.impl_18` `:688` (`t_PartialEq u64 u64`) | `==` |
| `demo.ne.u64` | `Rust_primitives.Integers.ne` `fsti:246` | the documented bug: model constant `false` vs `!=` |
| `demo.mul_overflow.u64`, `.i64` | `mul_overflow` `fsti:218` | the documented bug: model flag vs `overflowing_mul` |

`Core_models.Result.t_Result`/`Result_Ok`/`Result_Err`
(`Core_models.Bundle.fst:170` onward) are a two-constructor datatype; the
inventory lists only those constructors as used, so there is no reached helper
to run (T6 records the datatype as faithful). Option is where the helpers are.

`<from>.<to>` casts: `u8.u64`, `u8.u128`, `u8.i64`, `u64.u128`, `usize.u64`,
`u64.usize`, `i64.i128`, `isize.i64`, `i64.isize` (in range by construction),
and `u64.i64`, `i64.u64`, `u128.u64`, `i128.i64` (the model's `range`
precondition decides between `Some` and `None`).

### Not run: abstract definitions

These are `val` (or `assume val`) with no body in the pinned library, so there
is no code to extract. They are listed here so no reader mistakes the table
above for full coverage:

* `lognot`, `logand`, `logor`, `logxor`, `shift_left`, `rotate_left`,
  `rotate_right` and their lemmas (`fsti:265-353`). `&.` and `<<!` appear once
  each in the corpus. The trusted statements (`logand_lemma`,
  `logor_lemma`, `lognot_lemma`, `shift_left_positive_lemma`) are checked
  against Rust's `&`, `|`, `~`, `<<` on 10^6 samples in the Rust driver (`N
  bit_lemma_samples` line of the log): every conjunct holds, so the axioms are
  true of the real operators. That is a constraint check, not a model-vs-Rust
  equality, and the log says so.
* `Core_models.Str.impl_str__len`, `Rust_primitives.String.str_concat`,
  `str_of_char`, `str_sub`, `str_index` (`Str.fsti:4`, `String.fsti:5-11`): the
  local `Alloc.String` builds `push`/`push_str`/`pop` on them. They are
  unreachable from the corpus, and `pop` is the latent gap T4 recorded. The
  shadow keeps only `t_String`, `new` and `as_str`. The byte-length question is
  answered the other way round: `string.length_chars` shows the model's
  `FStar.String.length` equals `chars().count()`, and the log's
  `string.bytes.<s>` notes print Rust's byte length next to it for `""`, `e`,
  `é`, `€`, `😀`.
* `Alloc.Fmt.format` over the assumed `format'` (`Alloc.Fmt.fst:6-10`): every
  `format!` in the corpus denotes the same string (T4's gap). Nothing to run.
* The seven `assume val` `Alloc.Vec` operations and the
  `Monomorphized_update_at` range family: unreached by the corpus (T3), and the
  local `Alloc.Vec` deliberately omits them, so a future extraction that needs
  them fails to typecheck instead of picking up an unconstrained model.
* The derived `PartialEq` instance for `t_Phase` that
  `check-no-proof-escapes.py --all` lists (`assume val impl_7' :
  Core_models.Cmp.t_PartialEq t_Phase t_Phase`, seen in the rekey-policy
  extraction) is an axiom: it has no body to execute. The equality the proofs
  assume is structural equality on the two-constructor enum; the evidence log
  pins that reading exhaustively (`phase.eq` report: all four constructor
  pairs, model structural equality vs Rust's derived `==`).

### Not run: signed division

`div` (`/!`) and `mod` (`%!`) are tested on `u64` only, because that is the
only use in the corpus (`Vela_crypto.Wire`). F*'s integer division is Euclidean
(the remainder is never negative) while Rust truncates towards zero, so the
quotient differs whenever the dividend is negative. The extracted OCaml uses
`Z.div`/`Z.rem`, which truncate like Rust, so extraction cannot show the
difference; `semantics/T7_semantics.fst` asserts the six signed facts against
the F* specification (checked without `--lax`) and the Rust driver prints its
column in the log (`N div.rounding`). `check-model-guards.py` fails if `/!` or
`%!` appears outside the reviewed allowlist.

## Layout

```
make_shadow.py                  derive executable .fst modules from the pins
pins.sha256                     sha256 of every hax-lib 0.3.7 file read
ocaml/driver.ml                 model side: calls the extracted functions
rust/Cargo.toml, Cargo.lock     Rust reference (own workspace, no deps)
rust/src/main.rs                Rust side: generator, reference ops, hashing
compare.py                      per-op hash table + documented-bug classifier
check-model-guards.py           reject ne / mul_overflow / signed division
verify-fstar-std-model-diff.sh  the whole pipeline (heavy; vela-heavy offloads it)
run.sh                          entry point: vela-heavy when available
semantics/                      normalizer facts that need no extraction
```

## Running it

```sh
security/formal/std-model-diff/run.sh                     # 10^6 cases/op, evidence run
security/formal/std-model-diff/run.sh --cases 10000       # CI-sized
security/formal/std-model-diff/run.sh --log /tmp/t7.log   # keep the output
```

On a developer machine `run.sh` goes through
`~/.local/opt/vela-tools/bin/vela-heavy`, which offloads the whole pipeline to
the build box in one slot (the file is named `verify-fstar*.sh` for exactly
that). `VELA_HEAVY=0` runs it in place; CI calls the pipeline directly. Exit
status 0 is the pass condition: 0 mismatching blocks and the two documented
bugs reproducing exactly.

Required tools: the pinned F* release (2025.10.06, `install-formal-fstar.sh`),
`ocamlfind` with `zarith`, `batteries`, `pprint`, `stdint`, `yojson` and
`fstar.lib` (F*'s extracted ulib), `cargo`, `python3`. The script prints the
exact versions into the log.

## What this does and does not prove

* It proves the model **values** agree with Rust on 10^6 generated cases per
  operation, including every boundary value of every type it tests.
* It does not prove the F* definitions again (that is the crates' gates) and it
  does not cover the abstract symbols listed above.
* `phase.eq` is the one row whose F* side is not a pinned definition: the
  corpus value is an `assume val`, so the harness supplies the equality the
  proofs read it as (constructor equality) and checks it against Rust.
* `--lax` means F* does not discharge the refinement obligations of the shadow
  tree here. The preconditions are tested operationally instead: whenever Rust's
  `checked_*` returns `Some`, the model's precondition and value must agree;
  whenever it returns `None`, the model's `range` must be false.
* The `int_t` representation is constructed directly in OCaml, so a value
  outside the type's range could be built. Every generator is in range by
  construction and `bounds` checks the model's `minint`/`maxint` against Rust's
  `MIN`/`MAX`, but this is an execution harness, not a type checker.
