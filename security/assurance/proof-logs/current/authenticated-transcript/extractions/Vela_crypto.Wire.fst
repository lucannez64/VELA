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

/// Decode a fixed-width integer and its exact remaining input.
let split_u64_prefix (input: t_Slice u8)
    : Prims.Pure (Core_models.Option.t_Option (u64 & t_Slice u8))
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Option.t_Option (u64 & t_Slice u8) = result in
          if (Core_models.Slice.impl__len #u8 input <: usize) <. mk_usize 8
          then
            match result <: Core_models.Option.t_Option (u64 & t_Slice u8) with
            | Core_models.Option.Option_None  -> true
            | _ -> false
          else
            match result <: Core_models.Option.t_Option (u64 & t_Slice u8) with
            | Core_models.Option.Option_Some (value, rest) ->
              value =.
              (decode_u64_be (let list =
                      [
                        input.[ mk_usize 0 ] <: u8;
                        input.[ mk_usize 1 ] <: u8;
                        input.[ mk_usize 2 ] <: u8;
                        input.[ mk_usize 3 ] <: u8;
                        input.[ mk_usize 4 ] <: u8;
                        input.[ mk_usize 5 ] <: u8;
                        input.[ mk_usize 6 ] <: u8;
                        input.[ mk_usize 7 ] <: u8
                      ]
                    in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 8);
                    Rust_primitives.Hax.array_of_list 8 list)
                <:
                u64) &&
              rest =.
              (input.[ { Core_models.Ops.Range.f_start = mk_usize 8 }
                  <:
                  Core_models.Ops.Range.t_RangeFrom usize ]
                <:
                t_Slice u8)
            | Core_models.Option.Option_None  -> false) =
  if (Core_models.Slice.impl__len #u8 input <: usize) <. mk_usize 8
  then Core_models.Option.Option_None <: Core_models.Option.t_Option (u64 & t_Slice u8)
  else
    Core_models.Option.Option_Some
    (decode_u64_be (let list =
            [
              input.[ mk_usize 0 ] <: u8;
              input.[ mk_usize 1 ] <: u8;
              input.[ mk_usize 2 ] <: u8;
              input.[ mk_usize 3 ] <: u8;
              input.[ mk_usize 4 ] <: u8;
              input.[ mk_usize 5 ] <: u8;
              input.[ mk_usize 6 ] <: u8;
              input.[ mk_usize 7 ] <: u8
            ]
          in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 8);
          Rust_primitives.Hax.array_of_list 8 list),
      input.[ { Core_models.Ops.Range.f_start = mk_usize 8 }
        <:
        Core_models.Ops.Range.t_RangeFrom usize ]
      <:
      (u64 & t_Slice u8))
    <:
    Core_models.Option.t_Option (u64 & t_Slice u8)

let take_u64 (input: t_Slice u8)
    : Prims.Pure (t_Slice u8 & Core_models.Option.t_Option u64)
      Prims.l_True
      (ensures
        fun temp_0_ ->
          let (input_future: t_Slice u8), (result: Core_models.Option.t_Option u64) = temp_0_ in
          match split_u64_prefix input <: Core_models.Option.t_Option (u64 & t_Slice u8) with
          | Core_models.Option.Option_Some (value, rest) ->
            result =. (Core_models.Option.Option_Some value <: Core_models.Option.t_Option u64) &&
            input_future =. rest
          | Core_models.Option.Option_None  ->
            (match result <: Core_models.Option.t_Option u64 with
              | Core_models.Option.Option_None  -> true
              | _ -> false) &&
            input_future =. input) =
  let (input: t_Slice u8), (hax_temp_output: Core_models.Option.t_Option u64) =
    match split_u64_prefix input <: Core_models.Option.t_Option (u64 & t_Slice u8) with
    | Core_models.Option.Option_Some (value, rest) ->
      let input:t_Slice u8 = rest in
      input, (Core_models.Option.Option_Some value <: Core_models.Option.t_Option u64)
      <:
      (t_Slice u8 & Core_models.Option.t_Option u64)
    | Core_models.Option.Option_None  ->
      input, (Core_models.Option.Option_None <: Core_models.Option.t_Option u64)
      <:
      (t_Slice u8 & Core_models.Option.t_Option u64)
  in
  input, hax_temp_output <: (t_Slice u8 & Core_models.Option.t_Option u64)

/// Parse a u64-length-prefixed field, returning its exact payload and remainder.
/// The length is checked before narrowing it to usize or indexing the payload.
let split_length_prefixed (input: t_Slice u8)
    : Prims.Pure (Core_models.Option.t_Option (t_Slice u8 & t_Slice u8))
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) = result in
          if (Core_models.Slice.impl__len #u8 input <: usize) <. mk_usize 8
          then
            match result <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
            | Core_models.Option.Option_None  -> true
            | _ -> false
          else
            let length:u64 =
              decode_u64_be (let list =
                    [
                      input.[ mk_usize 0 ] <: u8;
                      input.[ mk_usize 1 ] <: u8;
                      input.[ mk_usize 2 ] <: u8;
                      input.[ mk_usize 3 ] <: u8;
                      input.[ mk_usize 4 ] <: u8;
                      input.[ mk_usize 5 ] <: u8;
                      input.[ mk_usize 6 ] <: u8;
                      input.[ mk_usize 7 ] <: u8
                    ]
                  in
                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 8);
                  Rust_primitives.Hax.array_of_list 8 list)
            in
            if
              length >.
              (cast ((Core_models.Slice.impl__len #u8 input <: usize) -! mk_usize 8 <: usize) <: u64
              )
            then
              match result <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
              | Core_models.Option.Option_None  -> true
              | _ -> false
            else
              match result <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
              | Core_models.Option.Option_Some (field, rest) ->
                field =.
                (input.[ {
                      Core_models.Ops.Range.f_start = mk_usize 8;
                      Core_models.Ops.Range.f_end
                      =
                      mk_usize 8 +! (cast (length <: u64) <: usize) <: usize
                    }
                    <:
                    Core_models.Ops.Range.t_Range usize ]
                  <:
                  t_Slice u8) &&
                rest =.
                (input.[ {
                      Core_models.Ops.Range.f_start
                      =
                      mk_usize 8 +! (cast (length <: u64) <: usize) <: usize
                    }
                    <:
                    Core_models.Ops.Range.t_RangeFrom usize ]
                  <:
                  t_Slice u8)
              | Core_models.Option.Option_None  -> false) =
  if (Core_models.Slice.impl__len #u8 input <: usize) <. mk_usize 8
  then Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)
  else
    let length:u64 =
      decode_u64_be (let list =
            [
              input.[ mk_usize 0 ] <: u8;
              input.[ mk_usize 1 ] <: u8;
              input.[ mk_usize 2 ] <: u8;
              input.[ mk_usize 3 ] <: u8;
              input.[ mk_usize 4 ] <: u8;
              input.[ mk_usize 5 ] <: u8;
              input.[ mk_usize 6 ] <: u8;
              input.[ mk_usize 7 ] <: u8
            ]
          in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 8);
          Rust_primitives.Hax.array_of_list 8 list)
    in
    let payload:t_Slice u8 =
      input.[ { Core_models.Ops.Range.f_start = mk_usize 8 }
        <:
        Core_models.Ops.Range.t_RangeFrom usize ]
    in
    if length >. (cast (Core_models.Slice.impl__len #u8 payload <: usize) <: u64)
    then Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)
    else
      let length:usize = cast (length <: u64) <: usize in
      Core_models.Option.Option_Some
      (payload.[ { Core_models.Ops.Range.f_end = length } <: Core_models.Ops.Range.t_RangeTo usize ],
        payload.[ { Core_models.Ops.Range.f_start = length }
          <:
          Core_models.Ops.Range.t_RangeFrom usize ]
        <:
        (t_Slice u8 & t_Slice u8))
      <:
      Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)

/// Stateful reader operation: successful reads consume exactly one field;
/// rejected reads preserve the cursor. Used directly by the envelope reader.
let take_length_prefixed (input: t_Slice u8)
    : Prims.Pure (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8))
      Prims.l_True
      (ensures
        fun temp_0_ ->
          let (input_future: t_Slice u8), (result: Core_models.Option.t_Option (t_Slice u8)) =
            temp_0_
          in
          match
            split_length_prefixed input <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)
          with
          | Core_models.Option.Option_Some (field, rest) ->
            result =.
            (Core_models.Option.Option_Some field <: Core_models.Option.t_Option (t_Slice u8)) &&
            input_future =. rest
          | Core_models.Option.Option_None  ->
            (match result <: Core_models.Option.t_Option (t_Slice u8) with
              | Core_models.Option.Option_None  -> true
              | _ -> false) &&
            input_future =. input) =
  let (input: t_Slice u8), (hax_temp_output: Core_models.Option.t_Option (t_Slice u8)) =
    match split_length_prefixed input <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
    | Core_models.Option.Option_Some (field, rest) ->
      let input:t_Slice u8 = rest in
      input, (Core_models.Option.Option_Some field <: Core_models.Option.t_Option (t_Slice u8))
      <:
      (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8))
    | Core_models.Option.Option_None  ->
      input, (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
      <:
      (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8))
  in
  input, hax_temp_output <: (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8))

/// Grammar combinators for two and four adjacent LP fields. The stateful
/// operations commit their cursor only after the complete group succeeds.
let split_lp_pair (input: t_Slice u8)
    : Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & t_Slice u8) =
  match split_length_prefixed input <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
  | Core_models.Option.Option_Some (first, rest) ->
    (match split_length_prefixed rest <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
      | Core_models.Option.Option_Some (second, rest) ->
        Core_models.Option.Option_Some
        ((first, second <: (t_Slice u8 & t_Slice u8)), rest
          <:
          ((t_Slice u8 & t_Slice u8) & t_Slice u8))
        <:
        Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & t_Slice u8)
      | Core_models.Option.Option_None  ->
        Core_models.Option.Option_None
        <:
        Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & t_Slice u8))
  | Core_models.Option.Option_None  ->
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & t_Slice u8)

let take_lp_pair (input: t_Slice u8)
    : Prims.Pure (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8 & t_Slice u8))
      Prims.l_True
      (ensures
        fun temp_0_ ->
          let
          (input_future: t_Slice u8),
          (result: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)) =
            temp_0_
          in
          match
            split_lp_pair input
            <:
            Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & t_Slice u8)
          with
          | Core_models.Option.Option_Some ((first, second), tail) ->
            (match result <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
              | Core_models.Option.Option_Some (a, b) ->
                a =. first && b =. second && input_future =. tail
              | Core_models.Option.Option_None  -> false)
          | Core_models.Option.Option_None  ->
            (match result <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
              | Core_models.Option.Option_None  -> true
              | _ -> false) &&
            input_future =. input) =
  let rest:t_Slice u8 = input in
  let (tmp0: t_Slice u8), (out: Core_models.Option.t_Option (t_Slice u8)) =
    take_length_prefixed rest
  in
  let rest:t_Slice u8 = tmp0 in
  match out <: Core_models.Option.t_Option (t_Slice u8) with
  | Core_models.Option.Option_Some first ->
    let (tmp0: t_Slice u8), (out: Core_models.Option.t_Option (t_Slice u8)) =
      take_length_prefixed rest
    in
    let rest:t_Slice u8 = tmp0 in
    (match out <: Core_models.Option.t_Option (t_Slice u8) with
      | Core_models.Option.Option_Some second ->
        let input:t_Slice u8 = rest in
        let hax_temp_output:Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) =
          Core_models.Option.Option_Some (first, second <: (t_Slice u8 & t_Slice u8))
          <:
          Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)
        in
        input, hax_temp_output
        <:
        (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8 & t_Slice u8))
      | Core_models.Option.Option_None  ->
        input,
        (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8))
        <:
        (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)))
  | Core_models.Option.Option_None  ->
    input, (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8))
    <:
    (t_Slice u8 & Core_models.Option.t_Option (t_Slice u8 & t_Slice u8))

let split_lp_four (input: t_Slice u8)
    : Core_models.Option.t_Option
    (((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)) & t_Slice u8) =
  match
    split_lp_pair input <: Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & t_Slice u8)
  with
  | Core_models.Option.Option_Some (first, rest) ->
    (match
        split_lp_pair rest <: Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & t_Slice u8)
      with
      | Core_models.Option.Option_Some (second, rest) ->
        Core_models.Option.Option_Some
        ((first, second <: ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8))), rest
          <:
          (((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)) & t_Slice u8))
        <:
        Core_models.Option.t_Option
        (((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)) & t_Slice u8)
      | Core_models.Option.Option_None  ->
        Core_models.Option.Option_None
        <:
        Core_models.Option.t_Option
        (((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)) & t_Slice u8))
  | Core_models.Option.Option_None  ->
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option
    (((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)) & t_Slice u8)

let take_lp_four (input: t_Slice u8)
    : Prims.Pure
      (t_Slice u8 &
        Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)))
      Prims.l_True
      (ensures
        fun temp_0_ ->
          let
          (input_future: t_Slice u8),
          (result:
            Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8))) =
            temp_0_
          in
          match
            split_lp_four input
            <:
            Core_models.Option.t_Option
            (((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)) & t_Slice u8)
          with
          | Core_models.Option.Option_Some (((a, b), (c, d)), tail) ->
            (match
                result
                <:
                Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8))
              with
              | Core_models.Option.Option_Some ((w, x), (y, z)) ->
                w =. a && x =. b && y =. c && z =. d && input_future =. tail
              | Core_models.Option.Option_None  -> false)
          | Core_models.Option.Option_None  ->
            (match
                result
                <:
                Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8))
              with
              | Core_models.Option.Option_None  -> true
              | _ -> false) &&
            input_future =. input) =
  let rest:t_Slice u8 = input in
  let (tmp0: t_Slice u8), (out: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)) =
    take_lp_pair rest
  in
  let rest:t_Slice u8 = tmp0 in
  match out <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
  | Core_models.Option.Option_Some first ->
    let (tmp0: t_Slice u8), (out: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8)) =
      take_lp_pair rest
    in
    let rest:t_Slice u8 = tmp0 in
    (match out <: Core_models.Option.t_Option (t_Slice u8 & t_Slice u8) with
      | Core_models.Option.Option_Some second ->
        let input:t_Slice u8 = rest in
        let hax_temp_output:Core_models.Option.t_Option
        ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)) =
          Core_models.Option.Option_Some
          (first, second <: ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)))
          <:
          Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8))
        in
        input, hax_temp_output
        <:
        (t_Slice u8 &
          Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)))
      | Core_models.Option.Option_None  ->
        input,
        (Core_models.Option.Option_None
          <:
          Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)))
        <:
        (t_Slice u8 &
          Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8))))
  | Core_models.Option.Option_None  ->
    input,
    (Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)))
    <:
    (t_Slice u8 &
      Core_models.Option.t_Option ((t_Slice u8 & t_Slice u8) & (t_Slice u8 & t_Slice u8)))

/// Exact body between a fixed prefix and fixed trailer, without allocation.
let frame_body (input: t_Slice u8) (prefix_len trailer_len: usize)
    : Prims.Pure (Core_models.Option.t_Option (t_Slice u8))
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Option.t_Option (t_Slice u8) = result in
          if
            (Core_models.Slice.impl__len #u8 input <: usize) <. prefix_len ||
            ((Core_models.Slice.impl__len #u8 input <: usize) -! prefix_len <: usize) <. trailer_len
          then
            match result <: Core_models.Option.t_Option (t_Slice u8) with
            | Core_models.Option.Option_None  -> true
            | _ -> false
          else
            match result <: Core_models.Option.t_Option (t_Slice u8) with
            | Core_models.Option.Option_Some body ->
              body =.
              (input.[ {
                    Core_models.Ops.Range.f_start = prefix_len;
                    Core_models.Ops.Range.f_end
                    =
                    (Core_models.Slice.impl__len #u8 input <: usize) -! trailer_len <: usize
                  }
                  <:
                  Core_models.Ops.Range.t_Range usize ]
                <:
                t_Slice u8)
            | Core_models.Option.Option_None  -> false) =
  if
    (Core_models.Slice.impl__len #u8 input <: usize) <. prefix_len ||
    ((Core_models.Slice.impl__len #u8 input <: usize) -! prefix_len <: usize) <. trailer_len
  then Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8)
  else
    Core_models.Option.Option_Some
    input.[ {
        Core_models.Ops.Range.f_start = prefix_len;
        Core_models.Ops.Range.f_end
        =
        (Core_models.Slice.impl__len #u8 input <: usize) -! trailer_len <: usize
      }
      <:
      Core_models.Ops.Range.t_Range usize ]
    <:
    Core_models.Option.t_Option (t_Slice u8)

#push-options "--fuel 2 --ifuel 2"

/// Domain prefix followed by the exact received body. Reject capacities above
/// Rust\'s byte-vector limit before doing length arithmetic or appending.
let domain_message (domain body: t_Slice u8)
    : Prims.Pure (Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
            result
          in
          let maximum:usize = cast (Core_models.Num.impl_isize__MAX <: isize) <: usize in
          match result <: Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) with
          | Core_models.Option.Option_Some message ->
            (Core_models.Slice.impl__len #u8 domain <: usize) <=. maximum &&
            (Core_models.Slice.impl__len #u8 body <: usize) <=.
            (maximum -! (Core_models.Slice.impl__len #u8 domain <: usize) <: usize) &&
            (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global message <: usize) =.
            ((Core_models.Slice.impl__len #u8 domain <: usize) +!
              (Core_models.Slice.impl__len #u8 body <: usize)
              <:
              usize) &&
            ((Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global message <: t_Slice u8).[ {
                  Core_models.Ops.Range.f_end = Core_models.Slice.impl__len #u8 domain <: usize
                }
                <:
                Core_models.Ops.Range.t_RangeTo usize ]
              <:
              t_Slice u8) =.
            domain &&
            ((Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global message <: t_Slice u8).[ {
                  Core_models.Ops.Range.f_start = Core_models.Slice.impl__len #u8 domain <: usize
                }
                <:
                Core_models.Ops.Range.t_RangeFrom usize ]
              <:
              t_Slice u8) =.
            body
          | Core_models.Option.Option_None  ->
            (Core_models.Slice.impl__len #u8 domain <: usize) >. maximum ||
            (Core_models.Slice.impl__len #u8 body <: usize) >.
            (maximum -! (Core_models.Slice.impl__len #u8 domain <: usize) <: usize)) =
  let maximum:usize = cast (Core_models.Num.impl_isize__MAX <: isize) <: usize in
  if
    (Core_models.Slice.impl__len #u8 domain <: usize) >. maximum ||
    (Core_models.Slice.impl__len #u8 body <: usize) >.
    (maximum -! (Core_models.Slice.impl__len #u8 domain <: usize) <: usize)
  then
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  else
    let message:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
    let message:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global message domain
    in
    let message:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global message body
    in
    Core_models.Option.Option_Some message
    <:
    Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)

#pop-options
