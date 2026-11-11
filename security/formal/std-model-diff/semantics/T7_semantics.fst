(* Facts about F* integer division that the extracted code cannot show.

   The corpus uses `/!` and `%!` on u64 only (Vela_crypto.Wire), and every
   `/!`/`%!` use is allowlisted by check-model-guards.py.  The reason for the
   guard is here: F* integer division is *Euclidean* (the remainder is always
   non-negative), while Rust truncates towards zero.  The quotient therefore
   differs whenever the dividend is negative, and the remainder's sign follows
   the dividend in Rust:

       expression        F*    Rust
       (-7) / 2          -4    -3
       (-7) % 2           1    -1
       7 / (-2)          -3    -3      (agree)
       7 % (-2)           1     1      (agree)
       (-7) / (-2)        4     3
       (-7) % (-2)        1    -1

   The extracted OCaml implements `/` and `%` with `Z.div`/`Z.rem`, which
   truncate like Rust, so an extracted differential test of a *signed* use
   would compare Rust with the OCaml runtime, not with the F* specification.
   That is why signed `/!` `%!` are excluded from the differential run and
   rejected by the guard instead, and why these six facts are checked here as
   F* assertions, without --lax, against the specification.

   The Rust column is printed by the Rust driver in the evidence log
   (`N div.rounding`), so both sides of the table are machine produced. *)

module T7_semantics

let _ = assert ((-7) / 2 = -4)      (* Rust: -3 *)
let _ = assert ((-7) % 2 = 1)       (* Rust: -1 *)
let _ = assert (7 / (-2) = -3)      (* Rust: -3, agrees *)
let _ = assert (7 % (-2) = 1)       (* Rust: 1, agrees *)
let _ = assert ((-7) / (-2) = 4)    (* Rust: 3 *)
let _ = assert ((-7) % (-2) = 1)    (* Rust: -1 *)
(* Unsigned values, the only corpus use, agree with Rust. *)
let _ = assert (255 / 2 = 127)
let _ = assert (255 % 2 = 1)
