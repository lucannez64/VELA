(* The `t_Phase` equality the rekey-policy proofs assume, defined.

   hax extracts `#[derive(PartialEq)] enum Phase { Active, Freezing }` as an
   assumed typeclass instance:

     [@@ FStar.Tactics.Typeclasses.tcinstance]
     assume
     val impl_7': Core_models.Cmp.t_PartialEq t_Phase t_Phase

   (seen in serverVELA/vela-rekey-policy/proofs/fstar/extraction/
   Vela_rekey_policy.fst, and listed by `check-no-proof-escapes.py --all` as a
   generated derive instance).  An `assume val` is an axiom: it has no body to
   execute, so the differential test cannot call it.  What the proofs actually
   use is the derived equality on a two-constructor enum, i.e. constructor
   equality, which is what `phase_eq` below is.  The harness compares that with
   Rust's derived `==` on all four constructor pairs, so the axiom's intended
   meaning is pinned even though the axiom itself stays in the trusted base. *)

module T7_phase

type t_Phase =
  | Phase_Active : t_Phase
  | Phase_Freezing : t_Phase

/// Constructor equality: the behaviour of `#[derive(PartialEq)]` here.
let phase_eq (a b : t_Phase) : bool =
  match a, b with
  | Phase_Active, Phase_Active -> true
  | Phase_Freezing, Phase_Freezing -> true
  | _ -> false

/// Truth table, in the order the case generator emits it.
let phase_of (i : int) : t_Phase =
  if i = 0 then Phase_Active else Phase_Freezing
