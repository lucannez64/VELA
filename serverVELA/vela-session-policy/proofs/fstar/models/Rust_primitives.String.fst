module Rust_primitives.String

// Local replacement for hax 0.3.7's `Rust_primitives.String`. hax declares
// `str_concat` as a bare `val`, so every `format!`/`push_str` result is opaque
// to F*. Here `str_concat` is the library's string concatenation `^`, which is
// exactly Rust's `push_str` / `&str + &str` on the character-sequence view
// (T4: UTF-8 is injective, so equality and concatenation are preserved).
//
// The other three declarations keep hax's types. `str_of_char` is
// `FStar.String.string_of_char`. `str_sub` and `str_index` are only reached by
// `Alloc.String.impl_String__pop`, which no proof in the corpus calls; they are
// defined for in-range inputs (character indices, the only index unit this
// model has) and return "" / 'a' out of range instead of Rust's panic. The
// existing model already left them total and unspecified; pinning the
// out-of-range value does not make any reachable proof stronger.

open Rust_primitives.Integers

let str_concat (s1 s2: string) : string = s1 ^ s2

let str_of_char (c: FStar.Char.char) : string = FStar.String.string_of_char c

let str_sub (s: string) (i l: usize) : string =
  if v i + v l <= FStar.String.length s
  then FStar.String.sub s (v i) (v l)
  else ""

let str_index (s: string) (i: usize) : FStar.Char.char =
  if v i < FStar.String.length s
  then FStar.String.index s (v i)
  else 'a'
