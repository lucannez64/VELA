(* Model side of the std-model differential test (plan step T7).

   Calls the F* definitions directly after `fstar.exe --codegen OCaml`, so the
   values compared with Rust are produced by the extracted model, not by a
   re-implementation.  Module names are the F* module names with dots replaced
   by underscores (F*'s OCaml backend); the comments name the F* definition.

   Prints `H` lines (per-block FNV-1a hash of inputs and result) and, in
   `--mode verbose`, `V` lines for the documented model bugs.  The case
   generator mirrors ../rust/src/main.rs exactly. *)

let ver = "t7-ocaml-driver/1"

(* ------------------------------------------------------------------ Z ----- *)

let two = Z.of_int 2
let z_two_64 = Z.shift_left Z.one 64

let u64_of_int64 (x : int64) : Z.t =
  if Int64.compare x 0L >= 0 then Z.of_int64 x else Z.add (Z.of_int64 x) z_two_64

let le_bytes_of_int64 (x : int64) : string =
  String.init 8 (fun i ->
      Char.chr
        (Int64.to_int
           (Int64.logand (Int64.shift_right_logical x (8 * i)) 0xFFL)))

let signed_of (z : Z.t) (w : int) : Z.t =
  let half = Z.pow two (w - 1) in
  if Z.compare z half >= 0 then Z.sub z (Z.pow two w) else z

(* ---------------------------------------------------------------- draws --- *)

let k1 = Int64.of_string "0x9E3779B97F4A7C15"
let k2 = Int64.of_string "0xD1B54A32D192ED03"

let mix64 (z : int64) : int64 =
  let z =
    Int64.mul (Int64.logxor z (Int64.shift_right_logical z 30))
      (Int64.of_string "0xBF58476D1CE4E5B9")
  in
  let z =
    Int64.mul (Int64.logxor z (Int64.shift_right_logical z 27))
      (Int64.of_string "0x94D049BB133111EB")
  in
  Int64.logxor z (Int64.shift_right_logical z 31)

let draw (seed : int64) (tag : int64) (i : int64) (slot : int64) : int64 =
  mix64
    (Int64.logxor seed
       (mix64
          (Int64.logxor tag
             (mix64 (Int64.add (Int64.mul i k1) (Int64.mul slot k2))))))

let draw_k seed tag i slot k =
  mix64 (Int64.add (draw seed tag i slot) (Int64.mul k k1))

type case = { seed : int64; tag : int64; i : int64 }

let r c slot = draw c.seed c.tag c.i slot
let rk c slot k = draw_k c.seed c.tag c.i slot k

(* The four draws, exactly as the Rust side feeds them. *)
let input_bytes (c : case) : string =
  let b = Buffer.create 32 in
  for s = 0 to 3 do
    Buffer.add_string b (le_bytes_of_int64 (r c (Int64.of_int s)))
  done;
  Buffer.contents b

(* Raw 128-bit pattern for an input slot, as Z. *)
let raw128 (c : case) (slot : int) : Z.t =
  let lo = u64_of_int64 (r c (Int64.of_int (slot * 2))) in
  let hi = u64_of_int64 (r c (Int64.of_int ((slot * 2) + 1))) in
  Z.add (Z.mul hi z_two_64) lo

(* ------------------------------------------------------------- integers --- *)

let u8_inttype = Rust_primitives_Integers.U8
let u64_inttype = Rust_primitives_Integers.U64
let u128_inttype = Rust_primitives_Integers.U128
let i64_inttype = Rust_primitives_Integers.I64
let usize_inttype = Rust_primitives_Integers.USIZE
let isize_inttype = Rust_primitives_Integers.ISIZE

let width = function
  | Rust_primitives_Integers.U8 | Rust_primitives_Integers.I8 -> 8
  | Rust_primitives_Integers.U16 | Rust_primitives_Integers.I16 -> 16
  | Rust_primitives_Integers.U32 | Rust_primitives_Integers.I32 -> 32
  | Rust_primitives_Integers.U64 | Rust_primitives_Integers.I64 -> 64
  | Rust_primitives_Integers.U128 | Rust_primitives_Integers.I128 -> 128
  | _ -> 64 (* the harness instantiates size_bits = 64 *)

let mk t z = Rust_primitives_Integers.MkInt z
let v t x = Rust_primitives_Integers.v t x

(* Edge table, same order and same values as edge_table! in main.rs.
   Memoised: the table depends only on the inttype. *)
let edges_cache : (Rust_primitives_Integers.inttype, Z.t array) Hashtbl.t =
  Hashtbl.create 16

let rec edges (t : Rust_primitives_Integers.inttype) : Z.t array =
  match Hashtbl.find_opt edges_cache t with
  | Some e -> e
  | None ->
  let e = edges_uncached t in
  Hashtbl.replace edges_cache t e;
  e

and edges_uncached (t : Rust_primitives_Integers.inttype) : Z.t array =
  let w = width t in
  let signed = not (Rust_primitives_Integers.unsigned t) in
  let maxv =
    if signed then Z.sub (Z.pow two (w - 1)) Z.one
    else Z.sub (Z.pow two w) Z.one
  in
  let minv = if signed then Z.neg (Z.pow two (w - 1)) else Z.zero in
  let half_max = Z.div maxv two in
  let half_min = Z.div minv two in
  Array.of_list
    [ minv; Z.add minv Z.one; half_min; Z.zero; Z.one; Z.of_int 2; half_max; maxv ]

let value_z (c : case) (slot : int) (t : Rust_primitives_Integers.inttype) : Z.t =
  let e = edges t in
  let lo = u64_of_int64 (r c (Int64.of_int (slot * 2))) in
  let pick =
    if Int64.compare c.i 8L < 0 then
      Some
        (Int64.to_int
           (Int64.rem
              (Int64.add (Int64.mul c.i 3L) (Int64.of_int (slot * 5)))
              8L))
    else if Z.equal (Z.erem lo (Z.of_int 16)) Z.zero then
      Some (Z.to_int (Z.erem (Z.shift_right lo 4) (Z.of_int 8)))
    else None
  in
  match pick with
  | Some k -> e.(k)
  | None ->
    let w = width t in
    let raw = Z.erem (raw128 c slot) (Z.pow two w) in
    let raw = if Z.sign raw < 0 then Z.add raw (Z.pow two w) else raw in
    if Rust_primitives_Integers.unsigned t then raw else signed_of raw w

(* ------------------------------------------------------------- encoding --- *)

let enc_u (z : Z.t) = Z.to_string z
let enc_b (b : bool) = if b then "b1" else "b0"
let enc_uopt = function None -> "n" | Some z -> "o" ^ enc_u z

let enc_list (xs : int list) =
  "l" ^ String.concat "," (List.map string_of_int xs)

let hex_of_string s =
  let b = Buffer.create (2 * String.length s) in
  String.iter
    (fun c -> Buffer.add_string b (Printf.sprintf "%02x" (Char.code c)))
    s;
  Buffer.contents b

let enc_str s = "s" ^ hex_of_string s

(* --------------------------------------------------------------- hasher --- *)

let fnv_offset = Int64.of_string "0xCBF29CE484222325"
let fnv_prime = Int64.of_string "0x100000001B3"

let feed (h : int64 ref) (s : string) =
  String.iter
    (fun c -> h := Int64.mul (Int64.logxor !h (Int64.of_int (Char.code c))) fnv_prime)
    s

let fnv1a (s : string) : int64 =
  let h = ref fnv_offset in
  feed h s;
  !h

(* --------------------------------------------------------------- models --- *)

let opt_some x = Core_models_Bundle.Option_Some x
let opt_none = Core_models_Bundle.Option_None

let model_add_checked t a b =
  if Rust_primitives_Integers.range (Z.add a b) t then
    Some (v t (Rust_primitives_Integers.add t (mk t a) (mk t b)))
  else None

let model_sub_checked t a b =
  if Rust_primitives_Integers.range (Z.sub a b) t then
    Some (v t (Rust_primitives_Integers.sub t (mk t a) (mk t b)))
  else None

let model_mul_checked t a b =
  if Rust_primitives_Integers.range (Z.mul a b) t then
    Some (v t (Rust_primitives_Integers.mul t (mk t a) (mk t b)))
  else None

let model_cast_checked t t' a =
  if Rust_primitives_Integers.range a t' then
    Some (v t' (Rust_primitives_Integers.cast t t' (mk t a)))
  else None

let model_div_checked t a b =
  if Z.equal b Z.zero then None
  else if
    Rust_primitives_Integers.unsigned t
    || Rust_primitives_Integers.range (Z.div a b) t
  then Some (v t (Rust_primitives_Integers.div t (mk t a) (mk t b)))
  else None

let model_mod_checked t a b =
  if Z.equal b Z.zero then None
  else Some (v t (Rust_primitives_Integers.mod1 t (mk t a) (mk t b)))

(* ------------------------------------------------------------ sequences --- *)

let seq_of_bytes (bs : int list) =
  FStar_Seq_Base.seq_of_list (List.map (fun b -> mk u8_inttype (Z.of_int b)) bs)

let seq_to_list (s : 'a FStar_Seq_Base.seq) : 'a list =
  let n = Z.to_int (FStar_Seq_Base.length s) in
  let rec go i acc =
    if i >= n then List.rev acc
    else go (i + 1) (FStar_Seq_Base.index s (Z.of_int i) :: acc)
  in
  go 0 []

let seq_bytes (s : Rust_primitives_Integers.u8 FStar_Seq_Base.seq) : int list =
  List.map (fun x -> Z.to_int (v u8_inttype x)) (seq_to_list s)

let bytes_of_list (bs : int list) : string =
  String.init (List.length bs) (fun i -> Char.chr (List.nth bs i))

let value_bytes (c : case) (n : int) : int list =
  let b = Buffer.create (n + 8) in
  let k = ref 0 in
  while Buffer.length b < n do
    Buffer.add_string b (le_bytes_of_int64 (rk c 0L (Int64.of_int !k)));
    incr k
  done;
  let s = Buffer.contents b in
  List.init n (fun i -> Char.code s.[i])

(* Unsigned remainder of a 64-bit draw, as an int. *)
let umod (x : int64) (m : int) : int =
  Z.to_int (Z.erem (u64_of_int64 x) (Z.of_int m))

let seq_len (c : case) = umod (r c 1L) 24
let str_len (c : case) = umod (r c 1L) 10

(* --------------------------------------------------------------- strings --- *)

let utf8_of_cp (cp : int) : string =
  let b = Buffer.create 4 in
  if cp < 0x80 then Buffer.add_char b (Char.chr cp)
  else if cp < 0x800 then begin
    Buffer.add_char b (Char.chr (0xC0 lor (cp lsr 6)));
    Buffer.add_char b (Char.chr (0x80 lor (cp land 0x3F)))
  end
  else if cp < 0x10000 then begin
    Buffer.add_char b (Char.chr (0xE0 lor (cp lsr 12)));
    Buffer.add_char b (Char.chr (0x80 lor ((cp lsr 6) land 0x3F)));
    Buffer.add_char b (Char.chr (0x80 lor (cp land 0x3F)))
  end
  else begin
    Buffer.add_char b (Char.chr (0xF0 lor (cp lsr 18)));
    Buffer.add_char b (Char.chr (0x80 lor ((cp lsr 12) land 0x3F)));
    Buffer.add_char b (Char.chr (0x80 lor ((cp lsr 6) land 0x3F)));
    Buffer.add_char b (Char.chr (0x80 lor (cp land 0x3F)))
  end;
  Buffer.contents b

let codepoint (x : int64) : int =
  let r = u64_of_int64 x in
  let sel = Z.to_int (Z.erem r (Z.of_int 100)) in
  let x = Z.div r (Z.of_int 100) in
  if sel <= 49 then 0x20 + Z.to_int (Z.erem x (Z.of_int 95))
  else if sel <= 69 then 0x80 + Z.to_int (Z.erem x (Z.of_int 0x700))
  else if sel <= 84 then 0x100 + Z.to_int (Z.erem x (Z.of_int 0xD000))
  else if sel <= 92 then 0xE000 + Z.to_int (Z.erem x (Z.of_int 0x1F00))
  else 0x10000 + Z.to_int (Z.erem x (Z.of_int 0xF0000))

let gen_string (c : case) : string =
  let n = str_len c in
  let b = Buffer.create 16 in
  for k = 0 to n - 1 do
    Buffer.add_string b (utf8_of_cp (codepoint (rk c 0L (Int64.of_int (1 + k)))))
  done;
  Buffer.contents b

let fixed_strings = [| ""; "e"; "é"; "😀" |]

let string_input (c : case) : string =
  if Int64.compare c.i 8L < 0 && Int64.rem c.i 2L = 0L then
    fixed_strings.(Int64.to_int (Int64.div c.i 2L))
  else gen_string c

(* ----------------------------------------------------------------- ops ----- *)

(* Rust_primitives.Hax.Folds.fold_range: applies f to start..end-1 and returns
   init when start >= end.  The accumulator counts iterations. *)
let count_range (start : Z.t) (end_ : Z.t) : int =
  Rust_primitives_Hax_Folds.fold_range u64_inttype (mk u64_inttype start)
    (mk u64_inttype end_) () 0
    (fun acc (_i : Obj.t Rust_primitives_Integers.int_t) -> acc + 1)

(* The 12 integer operations, parameterised by the F* inttype value. *)
let int_ops (t : Rust_primitives_Integers.inttype) (op : string) (c : case) :
    string * string =
  let a () = value_z c 0 t and b () = value_z c 1 t in
  match op with
  | "add_checked" -> (input_bytes c, enc_uopt (model_add_checked t (a ()) (b ())))
  | "sub_checked" -> (input_bytes c, enc_uopt (model_sub_checked t (a ()) (b ())))
  | "mul_checked" -> (input_bytes c, enc_uopt (model_mul_checked t (a ()) (b ())))
  | "add_mod" ->
    (input_bytes c, enc_u (v t (Rust_primitives_Integers.add_mod t (mk t (a ())) (mk t (b ())))))
  | "add_sat" ->
    (input_bytes c, enc_u (v t (Rust_primitives_Integers.add_sat t (mk t (a ())) (mk t (b ())))))
  | "sub_sat" ->
    (input_bytes c, enc_u (v t (Rust_primitives_Integers.sub_sat t (mk t (a ())) (mk t (b ())))))
  | "eq" ->
    (input_bytes c, enc_b (Rust_primitives_Integers.eq t (mk t (a ())) (mk t (b ()))))
  | "lt" ->
    (input_bytes c, enc_b (Rust_primitives_Integers.lt t (mk t (a ())) (mk t (b ()))))
  | "lte" ->
    (input_bytes c, enc_b (Rust_primitives_Integers.lte t (mk t (a ())) (mk t (b ()))))
  | "gt" ->
    (input_bytes c, enc_b (Rust_primitives_Integers.gt t (mk t (a ())) (mk t (b ()))))
  | "gte" ->
    (input_bytes c, enc_b (Rust_primitives_Integers.gte t (mk t (a ())) (mk t (b ()))))
  | "bounds" ->
    ("",
     Printf.sprintf "MIN=%s,MAX=%s"
       (Z.to_string (Rust_primitives_Integers.minint t))
       (Z.to_string (Rust_primitives_Integers.maxint t)))
  | _ -> assert false

let per_type_ops =
  [ "add_checked"; "sub_checked"; "mul_checked"; "add_mod"; "add_sat";
    "sub_sat"; "eq"; "lt"; "lte"; "gt"; "gte"; "bounds" ]

let itypes =
  [ ("u8", u8_inttype); ("u64", u64_inttype); ("u128", u128_inttype);
    ("i64", i64_inttype); ("i128", Rust_primitives_Integers.I128);
    ("usize", usize_inttype); ("isize", isize_inttype) ]

let run_op_other (name : string) (c : case) : string * string =
  if name = "u64.div_checked" then
    let a = value_z c 0 u64_inttype and b = value_z c 1 u64_inttype in
    (input_bytes c, enc_uopt (model_div_checked u64_inttype a b))
  else if name = "u64.mod_checked" then
    let a = value_z c 0 u64_inttype and b = value_z c 1 u64_inttype in
    (input_bytes c, enc_uopt (model_mod_checked u64_inttype a b))
  else if String.length name > 5 && String.sub name 0 5 = "cast." then begin
    let parts = String.split_on_char '.' name in
    let to_t = function
      | "u8" -> u8_inttype
      | "u64" -> u64_inttype
      | "u128" -> u128_inttype
      | "i64" -> i64_inttype
      | "i128" -> Rust_primitives_Integers.I128
      | "usize" -> usize_inttype
      | "isize" -> isize_inttype
      | _ -> assert false
    in
    let t = to_t (List.nth parts 1) in
    let t' = to_t (List.nth parts 2) in
    let a = value_z c 0 t in
    let checked =
      List.mem name
        [ "cast.u64.i64"; "cast.i64.u64"; "cast.u128.u64"; "cast.i128.i64" ]
    in
    if checked then (input_bytes c, enc_uopt (model_cast_checked t t' a))
    else (input_bytes c, enc_u (v t' (Rust_primitives_Integers.cast t t' (mk t a))))
  end
  else if String.length name > 5 && String.sub name 0 5 = "demo." then begin
    let t =
      if name = "demo.mul_overflow.i64" then i64_inttype else u64_inttype
    in
    let a = value_z c 0 t and b = value_z c 1 t in
    let fa = mk t a and fb = mk t b in
    if name = "demo.ne.u64" then
      (input_bytes c,
       Printf.sprintf "%s,%s,%b" (Z.to_string a) (Z.to_string b)
         (Rust_primitives_Integers.ne t fa fb))
    else
      let r, flag = Rust_primitives_Integers.mul_overflow t fa fb in
      (input_bytes c,
       Printf.sprintf "%s,%s,%s,%b" (Z.to_string a) (Z.to_string b)
         (Z.to_string (v t r)) flag)
  end
  else if String.length name > 7 && String.sub name 0 7 = "option." then begin
    let present = Int64.rem (r c 0L) 2L = 0L in
    let a = value_z c 1 u64_inttype and b = value_z c 2 u64_inttype in
    let o =
      if present then opt_some (mk u64_inttype a) else opt_none
    in
    let inst_fn () = Core_models_Ops_Function.impl_2 () in
    (* Rust's closures wrap: `x.wrapping_add(b)`, `x.wrapping_mul(b)`. *)
    let wrap_u64 z = Z.erem z z_two_64 in
    let ff_add : Obj.t Rust_primitives_Integers.int_t -> Obj.t Rust_primitives_Integers.int_t =
      fun x -> mk u64_inttype (wrap_u64 (Z.add (v u64_inttype x) b))
    in
    let ff_mul : Obj.t Rust_primitives_Integers.int_t -> Obj.t Rust_primitives_Integers.int_t =
      fun x -> mk u64_inttype (wrap_u64 (Z.mul (v u64_inttype x) b))
    in
    let ff_gt_a : Obj.t Rust_primitives_Integers.int_t -> bool =
      fun x -> Z.compare (wrap_u64 (Z.add (v u64_inttype x) b)) a > 0
    in
    let res =
      if name = "option.is_some" then enc_b (Core_models_Bundle.impl__is_some o)
      else if name = "option.is_none" then
        enc_b (Core_models_Bundle.impl__is_none o)
      else if name = "option.is_some_and" then
        enc_b
          (Obj.magic
             (Obj.repr
                (Core_models_Bundle.impl__is_some_and (inst_fn ()) () o ff_gt_a)))
      else if name = "option.unwrap_or" then
        enc_u
          (v u64_inttype
             (Core_models_Bundle.impl__unwrap_or o (mk u64_inttype b)))
      else if name = "option.map" then
        match Core_models_Bundle.impl__map (inst_fn ()) () o ff_mul with
        | Core_models_Bundle.Option_None -> "n"
        | Core_models_Bundle.Option_Some x ->
          "o" ^ Z.to_string (v u64_inttype (Obj.magic (Obj.repr x)))
      else if name = "option.map_or" then
        enc_u
          (v u64_inttype
             (Obj.magic
                (Obj.repr
                   (Core_models_Bundle.impl__map_or (inst_fn ()) () o
                      (mk u64_inttype a) ff_add))))
      else if name = "option.as_ref" then
        match Core_models_Bundle.impl__as_ref o with
        | Core_models_Bundle.Option_None -> "n"
        | Core_models_Bundle.Option_Some x -> "o" ^ Z.to_string (v u64_inttype x)
      else assert false
    in
    (input_bytes c, res)
  end
  else
    match name with
    | "slice.len" ->
      let bs = value_bytes c (seq_len c) in
      let sl = Rust_primitives_Slice.array_as_slice (mk usize_inttype (Z.of_int (List.length bs))) (seq_of_bytes bs) in
      (bytes_of_list bs, enc_u (v usize_inttype (Core_models_Slice.impl__len sl)))
    | "slice.is_empty" ->
      let bs = value_bytes c (seq_len c) in
      let sl = Rust_primitives_Slice.array_as_slice (mk usize_inttype (Z.of_int (List.length bs))) (seq_of_bytes bs) in
      (bytes_of_list bs, enc_b (Core_models_Slice.impl__is_empty sl))
    | "slice.index" ->
      let bs = value_bytes c (seq_len c) in
      let sl = Rust_primitives_Slice.array_as_slice (mk usize_inttype (Z.of_int (List.length bs))) (seq_of_bytes bs) in
      let n = List.length bs in
      if n = 0 then (bytes_of_list bs, "z")
      else begin
        let i = umod (r c 2L) n in
        let inst = Core_models_Slice.impl_11 () in
        let x =
          Rust_primitives_Notations.op_String_Access inst sl
            (mk usize_inttype (Z.of_int i))
        in
        (bytes_of_list bs, enc_u (v u8_inttype (Obj.magic (Obj.repr x))))
      end
    | "vec.new" ->
      let vec = Alloc_Vec.impl__new () in
      ("", enc_u (v usize_inttype (Alloc_Vec.impl_1__len vec)))
    | "vec.len" ->
      let bs = value_bytes c (seq_len c) in
      let vec = Alloc_Slice.impl__into_vec (seq_of_bytes bs) in
      (bytes_of_list bs, enc_u (v usize_inttype (Alloc_Vec.impl_1__len vec)))
    | "vec.as_slice" ->
      let bs = value_bytes c (seq_len c) in
      let vec = Alloc_Slice.impl__into_vec (seq_of_bytes bs) in
      let sl = Alloc_Vec.impl_1__as_slice vec in
      (bytes_of_list bs, enc_list (seq_bytes sl))
    | "vec.extend_from_slice" ->
      let bs = value_bytes c (seq_len c) in
      let other = value_bytes c (umod (r c 2L) 8) in
      let vec = Alloc_Slice.impl__into_vec (seq_of_bytes bs) in
      let vec = Alloc_Vec.impl_2__extend_from_slice vec (seq_of_bytes other) in
      (bytes_of_list (bs @ other),
       enc_list (seq_bytes (Alloc_Vec.impl_1__as_slice vec)))
    | "vec.into_vec" ->
      let bs = value_bytes c (seq_len c) in
      let vec = Alloc_Slice.impl__into_vec (seq_of_bytes bs) in
      (bytes_of_list bs, enc_list (seq_bytes (Alloc_Vec.impl_1__as_slice vec)))
    | "vec.to_vec" ->
      let bs = value_bytes c (seq_len c) in
      let vec = Alloc_Slice.impl__to_vec (seq_of_bytes bs) in
      (bytes_of_list bs, enc_list (seq_bytes (Alloc_Vec.impl_1__as_slice vec)))
    | "array_of_list" ->
      let bs = value_bytes c (seq_len c) in
      let arr =
        Rust_primitives_Hax.array_of_list
          (Z.of_int (List.length bs))
          (List.map (fun b -> mk u8_inttype (Z.of_int b)) bs)
      in
      let sl =
        Rust_primitives_Slice.array_as_slice
          (mk usize_inttype (Z.of_int (List.length bs)))
          arr
      in
      (bytes_of_list bs, enc_list (seq_bytes sl))
    | "fold_range.empty" ->
      let a = value_z c 0 u64_inttype and b = value_z c 1 u64_inttype in
      let start, end_ = if Z.compare a b >= 0 then (a, b) else (b, a) in
      (input_bytes c, enc_u (Z.of_int (count_range start end_)))
    | "fold_range.start_eq_end" ->
      let a = value_z c 0 u64_inttype in
      (input_bytes c, enc_u (Z.of_int (count_range a a)))
    | "fold_range.nonempty" ->
      let start = Z.erem (u64_of_int64 (r c 0L)) (Z.of_int 4096) in
      let len = Z.erem (u64_of_int64 (r c 1L)) (Z.of_int 17) in
      (input_bytes c, enc_u (Z.of_int (count_range start (Z.add start len))))
    | "string.new" ->
      let s = Alloc_String.impl_String__new () in
      ("", enc_u (Z.of_int (String.length (Alloc_String.impl_String__as_str s))))
    | "string.as_str" ->
      let bs = string_input c in
      let s = Alloc_String.String bs in
      (bs, enc_str (Alloc_String.impl_String__as_str s))
    | "string.eq" ->
      let a = string_input c in
      let b =
        if Int64.rem (r c 3L) 2L = 0L then a
        else string_input { c with i = Int64.add c.i 1L }
      in
      (a ^ "\000" ^ b, enc_b (Alloc_String.String a = Alloc_String.String b))
    | "string.length_chars" ->
      let bs = string_input c in
      let s = Alloc_String.impl_String__as_str (Alloc_String.String bs) in
      (bs, enc_u (FStar_String.length s))
    | "bool.not" ->
      let b = Int64.rem (r c 0L) 2L = 0L in
      let inst = Rust_primitives_Notations.negation_for_bool in
      ( String.make 1 (if b then '\001' else '\000'),
        enc_b (Rust_primitives_Notations.op_Tilde_Dot inst b) )
    | "clone.identity" ->
      let bs = value_bytes c (seq_len c) in
      let s = string_input c in
      let vec = Alloc_Slice.impl__into_vec (seq_of_bytes bs) in
      let payload = bytes_of_list bs ^ s in
      let pair = (vec, payload) in
      let inst = Core_models_Clone.impl () in
      let v', str' = Core_models_Clone.f_clone inst pair in
      ( input_bytes c ^ payload,
        enc_b
          (seq_bytes (Alloc_Vec.impl_1__as_slice v') = bs && str' = payload) )
    | "phase.eq" ->
      let i = Int64.to_int (Int64.rem c.i 4L) in
      let pick k = T7_phase.phase_of (Z.of_int k) in
      let a = pick (i / 2) and b = pick (i mod 2) in
      (String.make 1 (Char.chr i), enc_b (T7_phase.phase_eq a b))
    | "partialeq.u64" ->
      let a = value_z c 0 u64_inttype and b = value_z c 1 u64_inttype in
      let inst = Core_models_Cmp.impl_18 in
      ( input_bytes c,
        enc_b
          (Core_models_Cmp.f_eq () (Obj.magic (Obj.repr inst)) (mk u64_inttype a)
             (Obj.magic (Obj.repr (mk u64_inttype b)))) )
    | _ -> assert false

let run_op (name : string) (c : case) : string * string =
  let dot = try String.index name '.' with Not_found -> -1 in
  let prefix = if dot > 0 then String.sub name 0 dot else "" in
  let suffix =
    if dot > 0 then String.sub name (dot + 1) (String.length name - dot - 1)
    else ""
  in
  match List.assoc_opt prefix itypes with
  | Some t when List.mem suffix per_type_ops -> (int_ops t suffix) c
  | _ -> run_op_other name c

(* The op list, in the order of ../rust/src/main.rs. *)
let op_names : string list =
  let ints =
    [ "u8"; "u64"; "u128"; "i64"; "i128"; "usize"; "isize" ]
  in
  let int_ops =
    List.concat_map (fun nm -> List.map (fun op -> nm ^ "." ^ op) per_type_ops) ints
  in
  let casts =
    [ "cast.u8.u64"; "cast.u8.u128"; "cast.u8.i64"; "cast.u64.u128";
      "cast.usize.u64"; "cast.u64.usize"; "cast.i64.i128"; "cast.isize.i64";
      "cast.i64.isize"; "cast.u64.i64"; "cast.i64.u64"; "cast.u128.u64";
      "cast.i128.i64" ]
  in
  int_ops
  @ [ "u64.div_checked"; "u64.mod_checked" ]
  @ casts
  @ [ "option.is_some"; "option.is_none"; "option.is_some_and";
      "option.unwrap_or"; "option.map"; "option.map_or"; "option.as_ref" ]
  @ [ "slice.len"; "slice.is_empty"; "slice.index"; "vec.new"; "vec.len";
      "vec.as_slice"; "vec.extend_from_slice"; "vec.into_vec"; "vec.to_vec";
      "array_of_list"; "fold_range.empty"; "fold_range.start_eq_end";
      "fold_range.nonempty" ]
  @ [ "string.new"; "string.as_str"; "string.eq"; "string.length_chars";
      "bool.not"; "clone.identity"; "partialeq.u64"; "phase.eq" ]
  @ [ "demo.ne.u64"; "demo.mul_overflow.u64"; "demo.mul_overflow.i64" ]

let small_ops = [ "demo.ne.u64"; "demo.mul_overflow.u64"; "demo.mul_overflow.i64" ]

(* Op families with a fixed case count, as in main.rs. *)
let one_case_ops = List.map (fun nm -> nm ^ ".bounds")
    [ "u8"; "u64"; "u128"; "i64"; "i128"; "usize"; "isize" ]

(* `phase.eq` has exactly four cases (all constructor pairs). *)
let four_case_ops = [ "phase.eq" ]

(* ----------------------------------------------------------------- main ----- *)

let seed = ref (Int64.of_string "0x5EED1234ABCD0001")
let cases = ref 1_000_000
let block = ref 1024
let mode = ref "hash"
let only = ref None

let () =
  let args = Array.to_list Sys.argv in
  let rec go = function
    | [] -> ()
    | "--seed" :: x :: tl ->
      seed := Int64.of_string x;
      go tl
    | "--cases" :: x :: tl ->
      cases := int_of_string x;
      go tl
    | "--block" :: x :: tl ->
      block := int_of_string x;
      go tl
    | "--mode" :: x :: tl ->
      mode := x;
      go tl
    | "--op" :: x :: tl ->
      only := Some x;
      go tl
    | _ :: tl -> go tl
  in
  go (List.tl args)

let () =
  let out = Buffer.create 65536 in
  let dump () =
    print_string (Buffer.contents out);
    Buffer.clear out;
    flush stdout
  in
  List.iter
    (fun name ->
      match !only with
      | Some f when f <> name -> ()
      | _ ->
        let n =
          if List.mem name four_case_ops then 4
          else if List.mem name one_case_ops then 1
          else if List.mem name small_ops then min 10_000 !cases
          else !cases
        in
        let tag = fnv1a name in
        let is_demo = List.mem name small_ops in
        let verbose = !mode = "verbose" || (is_demo && !mode = "demo") in
        if (!mode = "demo" && not is_demo) || (is_demo && not verbose) then ()
        else begin
        let block_no = ref 0 and block_cases = ref 0 in
        let h = ref fnv_offset in
        for i = 0 to n - 1 do
          let c = { seed = !seed; tag; i = Int64.of_int i } in
          let inp, res = run_op name c in
          if verbose then
            Buffer.add_string out
              (Printf.sprintf "V\t%s\t%d\t%s\t%s\n" name i
                 (hex_of_string inp) res);
          feed h inp;
          feed h "=";
          feed h res;
          feed h "\n";
          incr block_cases;
          if !block_cases = !block then begin
            Buffer.add_string out
              (Printf.sprintf "H\t%s\t%d\t%d\t%016Lx\n" name !block_no
                 !block_cases !h);
            incr block_no;
            block_cases := 0;
            h := fnv_offset
          end;
          if i mod 65536 = 0 then dump ()
        done;
        if !block_cases > 0 then
          Buffer.add_string out
            (Printf.sprintf "H\t%s\t%d\t%d\t%016Lx\n" name !block_no
               !block_cases !h);
        if not verbose then
          Buffer.add_string out (Printf.sprintf "C\t%s\t%d\n" name n)
        end)
    op_names;
  dump ();
  Printf.printf "N\tdriver\t%s\n" ver
