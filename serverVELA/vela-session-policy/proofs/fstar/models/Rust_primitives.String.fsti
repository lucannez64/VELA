module Rust_primitives.String

// Local replacement for hax 0.3.7's
// `proof-libs/fstar/rust_primitives/Rust_primitives.String.fsti`, with the
// same four declarations. The implementation (`Rust_primitives.String.fst`)
// defines the two operations the session store keys use; `str_sub` and
// `str_index` are only reached by the unreachable `String::pop` model and are
// defined conservatively there.

open Rust_primitives.Integers

/// `&str + &str` / `String::push_str`: byte concatenation, i.e. `^` on the
/// character-sequence view (UTF-8 is injective, T4).
val str_concat: string -> string -> string

/// `char::encode_utf8`: the one-character string.
val str_of_char: FStar.Char.char -> string

val str_sub: string -> usize -> usize -> string

val str_index: string -> usize -> FStar.Char.char
