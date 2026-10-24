module Vela_crypto.Wire
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

let decode_u64_be (bytes: t_Array u8 (mk_usize 8))
    : Prims.Pure u64
      Prims.l_True
      (ensures
        fun result ->
          let result:u64 = result in
          result =.
          (((((((((cast (bytes.[ mk_usize 0 ] <: u8) <: u64) *! mk_u64 72057594037927936 <: u64) +!
                        ((cast (bytes.[ mk_usize 1 ] <: u8) <: u64) *! mk_u64 281474976710656 <: u64
                        )
                        <:
                        u64) +!
                      ((cast (bytes.[ mk_usize 2 ] <: u8) <: u64) *! mk_u64 1099511627776 <: u64)
                      <:
                      u64) +!
                    ((cast (bytes.[ mk_usize 3 ] <: u8) <: u64) *! mk_u64 4294967296 <: u64)
                    <:
                    u64) +!
                  ((cast (bytes.[ mk_usize 4 ] <: u8) <: u64) *! mk_u64 16777216 <: u64)
                  <:
                  u64) +!
                ((cast (bytes.[ mk_usize 5 ] <: u8) <: u64) *! mk_u64 65536 <: u64)
                <:
                u64) +!
              ((cast (bytes.[ mk_usize 6 ] <: u8) <: u64) *! mk_u64 256 <: u64)
              <:
              u64) +!
            (cast (bytes.[ mk_usize 7 ] <: u8) <: u64)
            <:
            u64)) =
  let n:u64 = cast (bytes.[ mk_usize 0 ] <: u8) <: u64 in
  let n:u64 = (n *! mk_u64 256 <: u64) +! (cast (bytes.[ mk_usize 1 ] <: u8) <: u64) in
  let n:u64 = (n *! mk_u64 256 <: u64) +! (cast (bytes.[ mk_usize 2 ] <: u8) <: u64) in
  let n:u64 = (n *! mk_u64 256 <: u64) +! (cast (bytes.[ mk_usize 3 ] <: u8) <: u64) in
  let n:u64 = (n *! mk_u64 256 <: u64) +! (cast (bytes.[ mk_usize 4 ] <: u8) <: u64) in
  let n:u64 = (n *! mk_u64 256 <: u64) +! (cast (bytes.[ mk_usize 5 ] <: u8) <: u64) in
  let n:u64 = (n *! mk_u64 256 <: u64) +! (cast (bytes.[ mk_usize 6 ] <: u8) <: u64) in
  (n *! mk_u64 256 <: u64) +! (cast (bytes.[ mk_usize 7 ] <: u8) <: u64)

/// Quotient/remainder step used to build a byte encoding without overflow.
let split_low_byte (value: u64)
    : Prims.Pure (u64 & u8)
      Prims.l_True
      (ensures
        fun parts ->
          let parts:(u64 & u8) = parts in
          parts._1 =. (value /! mk_u64 256 <: u64) &&
          (cast (parts._2 <: u8) <: u64) =. (value %! mk_u64 256 <: u64) &&
          value =. ((parts._1 *! mk_u64 256 <: u64) +! (cast (parts._2 <: u8) <: u64) <: u64)) =
  value /! mk_u64 256, (cast (value %! mk_u64 256 <: u64) <: u8) <: (u64 & u8)

let encode_u64_be (value: u64)
    : Prims.Pure (t_Array u8 (mk_usize 8))
      Prims.l_True
      (ensures
        fun bytes ->
          let bytes:t_Array u8 (mk_usize 8) = bytes in
          (decode_u64_be (let list =
                  [
                    bytes.[ mk_usize 0 ] <: u8;
                    bytes.[ mk_usize 1 ] <: u8;
                    bytes.[ mk_usize 2 ] <: u8;
                    bytes.[ mk_usize 3 ] <: u8;
                    bytes.[ mk_usize 4 ] <: u8;
                    bytes.[ mk_usize 5 ] <: u8;
                    bytes.[ mk_usize 6 ] <: u8;
                    bytes.[ mk_usize 7 ] <: u8
                  ]
                in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 8);
                Rust_primitives.Hax.array_of_list 8 list)
            <:
            u64) =.
          value) =
  let (n: u64), (b7: u8) = split_low_byte value in
  let (n: u64), (b6: u8) = split_low_byte n in
  let (n: u64), (b5: u8) = split_low_byte n in
  let (n: u64), (b4: u8) = split_low_byte n in
  let (n: u64), (b3: u8) = split_low_byte n in
  let (n: u64), (b2: u8) = split_low_byte n in
  let (n: u64), (b1: u8) = split_low_byte n in
  let list = [cast (n <: u64) <: u8; b1; b2; b3; b4; b5; b6; b7] in
  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 8);
  Rust_primitives.Hax.array_of_list 8 list

let u64_wire_round_trip (value: u64) : Prims.Pure bool Prims.l_True (ensures fun result -> result) =
  (decode_u64_be (encode_u64_be value <: t_Array u8 (mk_usize 8)) <: u64) =. value

let u64_wire_encoding_is_injective (left right: u64)
    : Prims.Pure bool Prims.l_True (ensures fun result -> result) =
  let _:bool = u64_wire_round_trip left in
  let _:bool = u64_wire_round_trip right in
  (encode_u64_be left <: t_Array u8 (mk_usize 8)) <>.
  (encode_u64_be right <: t_Array u8 (mk_usize 8)) ||
  left =. right
