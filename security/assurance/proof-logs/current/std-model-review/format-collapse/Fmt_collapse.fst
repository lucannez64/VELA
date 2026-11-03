module Fmt_collapse
open Core_models

(* If this verifies, F* treats every format! result as the same string. *)
let all_formats_equal (a b: Core_models.Fmt.t_Arguments)
  : Lemma (Alloc.Fmt.format a == Alloc.Fmt.format b)
  = match a, b with
    | Core_models.Fmt.Arguments (), Core_models.Fmt.Arguments () -> ()
