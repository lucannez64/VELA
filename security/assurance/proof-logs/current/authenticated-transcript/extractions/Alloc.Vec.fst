module Alloc.Vec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Rust_primitives

type t_Vec (v_T: Type0) (v_A: Type0) =
  | Vec : Rust_primitives.Sequence.t_Seq v_T -> Core_models.Marker.t_PhantomData v_A
    -> t_Vec v_T v_A

// Defined subset of the pinned Vec model; Rust/std correspondence is trusted.

let impl__new (#v_T: Type0) (_: Prims.unit) : t_Vec v_T Alloc.Alloc.t_Global =
  Vec (Rust_primitives.Sequence.seq_empty #v_T ())
    (Core_models.Marker.PhantomData <: Core_models.Marker.t_PhantomData Alloc.Alloc.t_Global)
  <:
  t_Vec v_T Alloc.Alloc.t_Global

let impl_1__len (#v_T #v_A: Type0) (self: t_Vec v_T v_A) : usize =
  Rust_primitives.Sequence.seq_len #v_T self._0

let impl_1__as_slice (#v_T #v_A: Type0) (self: t_Vec v_T v_A) : t_Slice v_T =
  Rust_primitives.Sequence.seq_to_slice #v_T self._0

// Same sequence-append body as pinned hax-lib 0.3.7. A refined argument
// expresses its existing capacity requirement; a refined result exposes the
// defined bytes instead of the upstream Pure postcondition True.
let impl_2__extend_from_slice (#v_T #v_A: Type0) (s: t_Vec v_T v_A)
    (other: t_Slice v_T {
      FStar.Seq.length s._0 + FStar.Seq.length other <= Rust_primitives.max_usize
    })
    : result:t_Vec v_T v_A {
      result._0 == FStar.Seq.append s._0 other /\ result._1 == s._1 /\
      FStar.Seq.length result._0 == FStar.Seq.length s._0 + FStar.Seq.length other /\
      FStar.Seq.slice result._0 0 (FStar.Seq.length s._0) == s._0 /\
      FStar.Seq.slice result._0 (FStar.Seq.length s._0) (FStar.Seq.length result._0) == other
    } =
  FStar.Seq.Properties.append_slices s._0 other;
  { s with _0 = Rust_primitives.Sequence.seq_concat #v_T
      s._0 (Rust_primitives.Sequence.seq_from_slice #v_T other) }
