//! Reference side of the std-model differential test (plan step T7).
//!
//! Reads nothing, writes one `H` line per (op, block) with a FNV-1a hash of
//! the inputs and of the Rust result, so the F* model run can be compared
//! without shipping 10^8 values through a file.  `--mode verbose` instead
//! prints `V` lines (inputs, result) for the documented bug demonstrations.
//!
//! The case generator (splitmix64 draws, boundary injection, string and
//! sequence construction) is mirrored exactly in `../ocaml/driver.ml`; the
//! input bytes are part of the hash, so any divergence fails on the first
//! block instead of passing silently.
//!
//! Rust std is the oracle: every operation here is the standard library
//! function the review notes name (`checked_add`, `wrapping_add`,
//! `saturating_add`, `checked_mul`, `/`, `%`, `&`, `!`, `Vec::extend_from_slice`,
//! `String::len`, `str::chars().count()`, derived `PartialEq`, ...).

use std::io::{BufWriter, Write};

// ---------------------------------------------------------------- hashing ---

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

struct Hasher(u64);

impl Hasher {
    fn new() -> Self {
        Hasher(FNV_OFFSET)
    }
    fn byte(&mut self, b: u8) {
        self.0 = (self.0 ^ b as u64).wrapping_mul(FNV_PRIME);
    }
    fn bytes(&mut self, bs: &[u8]) {
        for b in bs {
            self.byte(*b);
        }
    }
    fn word(&mut self, w: u64) {
        self.bytes(&w.to_le_bytes());
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = Hasher::new();
    h.bytes(bytes);
    h.finish()
}

// ----------------------------------------------------------------- draws ---

const K1: u64 = 0x9E37_79B9_7F4A_7C15;
const K2: u64 = 0xD1B5_4A32_D192_ED03;

fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn draw(seed: u64, tag: u64, i: u64, slot: u64) -> u64 {
    mix64(seed ^ mix64(tag ^ mix64(i.wrapping_mul(K1).wrapping_add(slot.wrapping_mul(K2)))))
}

/// Position `k` of an unbounded per-case draw stream.
fn draw_k(seed: u64, tag: u64, i: u64, slot: u64, k: u64) -> u64 {
    mix64(draw(seed, tag, i, slot).wrapping_add(k.wrapping_mul(K1)))
}

struct Case {
    seed: u64,
    tag: u64,
    i: u64,
}

impl Case {
    fn r(&self, slot: u64) -> u64 {
        draw(self.seed, self.tag, self.i, slot)
    }
    fn rk(&self, slot: u64, k: u64) -> u64 {
        draw_k(self.seed, self.tag, self.i, slot, k)
    }
    /// The four draws, fed into the hash so the inputs are part of it.
    fn input_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32);
        for s in 0..4u64 {
            v.extend_from_slice(&self.r(s).to_le_bytes());
        }
        v
    }
}

/// A 128-bit input word built from two draws (low, high).
fn bits128(lo: u64, hi: u64) -> u128 {
    ((hi as u128) << 64) | lo as u128
}

/// Edge table for a fixed-width integer type, in the same order as
/// `edges ()` in the OCaml driver.
macro_rules! edge_table {
    ($ty:ty) => {
        [
            <$ty>::MIN,
            <$ty>::MIN + 1,
            <$ty>::MIN / 2,
            0 as $ty,
            1 as $ty,
            2 as $ty,
            <$ty>::MAX / 2,
            <$ty>::MAX,
        ]
    };
}

/// Input value for `slot`: boundary-heavy for the first cases and for one in
/// sixteen draws, uniform inside the type otherwise.
macro_rules! value_of {
    ($c:expr, $slot:expr, $ty:ty, $signed:expr) => {{
        let c: &Case = $c;
        let slot: u64 = $slot;
        let e = edge_table!($ty);
        let lo = c.r(slot * 2);
        let hi = c.r(slot * 2 + 1);
        let bits = bits128(lo, hi);
        let pick = if c.i < 8 {
            Some(((c.i.wrapping_mul(3).wrapping_add(slot.wrapping_mul(5))) % 8) as usize)
        } else if lo % 16 == 0 {
            Some(((lo >> 4) % 8) as usize)
        } else {
            None
        };
        match pick {
            Some(k) => e[k],
            None => {
                let _ = $signed;
                bits as $ty
            }
        }
    }};
}

// ------------------------------------------------------------- encodings ---

fn enc_u(v: u128) -> String {
    v.to_string()
}
fn enc_i(v: i128) -> String {
    v.to_string()
}
fn enc_b(b: bool) -> String {
    if b { "b1".into() } else { "b0".into() }
}
fn enc_list(v: &[u8]) -> String {
    let mut s = String::from("l");
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&x.to_string());
    }
    s
}
fn enc_str(v: &[u8]) -> String {
    let mut s = String::from("s");
    for b in v {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
/// Signed types print the two's-complement value the way the F* model does
/// (`int_t` holds a mathematical integer, so `v` of -1 is -1, not 2^64-1).
fn enc_int(signed: bool, v: u128) -> String {
    if signed { enc_i(v as i128) } else { enc_u(v) }
}
fn enc_intopt(signed: bool, v: Option<u128>) -> String {
    match v {
        None => "n".into(),
        Some(x) => format!("o{}", enc_int(signed, x)),
    }
}

fn enc_uopt(v: Option<u128>) -> String {
    match v {
        None => "n".into(),
        Some(x) => format!("o{}", enc_u(x)),
    }
}
fn enc_iopt(v: Option<i128>) -> String {
    match v {
        None => "n".into(),
        Some(x) => format!("o{}", enc_i(x)),
    }
}

// ------------------------------------------------------------- op table ---

type RunFn = fn(&Case) -> (Vec<u8>, String);

struct Op {
    name: &'static str,
    cases: fn(u64) -> u64,
    run: RunFn,
}

fn cases_default(n: u64) -> u64 {
    n
}
fn cases_small(n: u64) -> u64 {
    if n < 10_000 { n } else { 10_000 }
}

macro_rules! int_family {
    ($ty:ty, $tag:literal, $signed:expr, $out:ident) => {{
        fn add_checked(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            let r = a.checked_add(b).map(|x| x as u128);
            (c.input_bytes(), enc_intopt($signed, r))
        }
        fn sub_checked(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            let r = a.checked_sub(b).map(|x| x as u128);
            (c.input_bytes(), enc_intopt($signed, r))
        }
        fn mul_checked(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            let r = a.checked_mul(b).map(|x| x as u128);
            (c.input_bytes(), enc_intopt($signed, r))
        }
        fn add_mod(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            (c.input_bytes(), enc_int($signed, a.wrapping_add(b) as u128))
        }
        fn add_sat(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            (c.input_bytes(), enc_int($signed, a.saturating_add(b) as u128))
        }
        fn sub_sat(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            (c.input_bytes(), enc_int($signed, a.saturating_sub(b) as u128))
        }
        fn eq(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            (c.input_bytes(), enc_b(a == b))
        }
        fn lt(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            (c.input_bytes(), enc_b(a < b))
        }
        fn lte(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            (c.input_bytes(), enc_b(a <= b))
        }
        fn gt(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            (c.input_bytes(), enc_b(a > b))
        }
        fn gte(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $ty, $signed);
            let b = value_of!(c, 1, $ty, $signed);
            (c.input_bytes(), enc_b(a >= b))
        }
        fn bounds(_c: &Case) -> (Vec<u8>, String) {
            (
                Vec::new(),
                format!("MIN={},MAX={}", <$ty>::MIN as i128, <$ty>::MAX as u128),
            )
        }
        $out.extend([
            Op { name: concat!($tag, ".add_checked"), cases: cases_default, run: add_checked },
            Op { name: concat!($tag, ".sub_checked"), cases: cases_default, run: sub_checked },
            Op { name: concat!($tag, ".mul_checked"), cases: cases_default, run: mul_checked },
            Op { name: concat!($tag, ".add_mod"), cases: cases_default, run: add_mod },
            Op { name: concat!($tag, ".add_sat"), cases: cases_default, run: add_sat },
            Op { name: concat!($tag, ".sub_sat"), cases: cases_default, run: sub_sat },
            Op { name: concat!($tag, ".eq"), cases: cases_default, run: eq },
            Op { name: concat!($tag, ".lt"), cases: cases_default, run: lt },
            Op { name: concat!($tag, ".lte"), cases: cases_default, run: lte },
            Op { name: concat!($tag, ".gt"), cases: cases_default, run: gt },
            Op { name: concat!($tag, ".gte"), cases: cases_default, run: gte },
            Op { name: concat!($tag, ".bounds"), cases: |_| 1, run: bounds },
        ]);
    }};
}

macro_rules! cast_op {
    ($from:ty, $to:ty, $from_signed:expr, $to_signed:expr, $name:literal, $checked:expr, $out:ident) => {{
        fn cast(c: &Case) -> (Vec<u8>, String) {
            let a = value_of!(c, 0, $from, $from_signed);
            if $checked {
                // `cast` only exists when the exact value fits the target
                // type; compare in a domain wide enough for both.
                let fits = if $from_signed {
                    (a as i128) >= (<$to>::MIN as i128) && (a as i128) <= (<$to>::MAX as i128)
                } else {
                    (a as u128) <= (<$to>::MAX as u128)
                };
                let r = if fits { Some(a as $to as u128) } else { None };
                (c.input_bytes(), enc_intopt($to_signed, r))
            } else {
                (c.input_bytes(), enc_int($to_signed, a as $to as u128))
            }
        }
        $out.push(Op { name: $name, cases: cases_default, run: cast });
    }};
}

fn value_bytes(c: &Case, n: usize) -> Vec<u8> {
    // n random bytes, from the per-case stream.
    let mut v = Vec::with_capacity(n);
    let mut k = 0u64;
    while v.len() < n {
        v.extend_from_slice(&c.rk(0, k).to_le_bytes());
        k += 1;
    }
    v.truncate(n);
    v
}

fn seq_len(c: &Case) -> usize {
    (c.r(1) % 24) as usize
}

fn str_len(c: &Case) -> usize {
    (c.r(1) % 10) as usize
}

fn codepoint(r: u64) -> u32 {
    let sel = r % 100;
    let x = r / 100;
    match sel {
        0..=49 => 0x20 + (x % 95) as u32,
        50..=69 => 0x80 + (x % 0x700) as u32,
        70..=84 => 0x100 + (x % 0xD000) as u32,
        85..=92 => 0xE000 + (x % 0x1F00) as u32,
        _ => 0x10000 + (x % 0xF0000) as u32,
    }
}

fn gen_string(c: &Case) -> String {
    let n = str_len(c);
    let mut s = String::new();
    for k in 0..n {
        let cp = codepoint(c.rk(0, 1 + k as u64));
        s.push(char::from_u32(cp).expect("valid scalar value"));
    }
    s
}

fn fixed_strings() -> [&'static str; 4] {
    ["", "e", "é", "😀"]
}

fn string_input(c: &Case) -> String {
    // One fixed case in eight (cycling), random otherwise, so every string op
    // sees the empty string and the non-ASCII cases.
    if c.i < 8 {
        let fs = fixed_strings();
        if c.i % 2 == 0 {
            return fs[(c.i / 2) as usize].to_string();
        }
    }
    gen_string(c)
}

fn ops() -> Vec<Op> {
    let mut v: Vec<Op> = Vec::new();
    // -- integers: the seven widths the corpus uses -----------------------
    int_family!(u8, "u8", false, v);
    int_family!(u64, "u64", false, v);
    int_family!(u128, "u128", false, v);
    int_family!(i64, "i64", true, v);
    int_family!(i128, "i128", true, v);
    int_family!(usize, "usize", false, v);
    int_family!(isize, "isize", true, v);
    // /! and %! are used on u64 only (Vela_crypto.Wire)
    v.push(Op { name: "u64.div_checked", cases: cases_default, run: u64_div });
    v.push(Op { name: "u64.mod_checked", cases: cases_default, run: u64_mod });
    // -- casts between the used types -------------------------------------
    cast_op!(u8, u64, false, false, "cast.u8.u64", false, v);
    cast_op!(u8, u128, false, false, "cast.u8.u128", false, v);
    cast_op!(u8, i64, false, true, "cast.u8.i64", false, v);
    cast_op!(u64, u128, false, false, "cast.u64.u128", false, v);
    cast_op!(usize, u64, false, false, "cast.usize.u64", false, v);
    cast_op!(u64, usize, false, false, "cast.u64.usize", false, v);
    cast_op!(i64, i128, true, true, "cast.i64.i128", false, v);
    cast_op!(isize, i64, true, true, "cast.isize.i64", false, v);
    cast_op!(i64, isize, true, true, "cast.i64.isize", false, v);
    cast_op!(u64, i64, false, true, "cast.u64.i64", true, v);
    cast_op!(i64, u64, true, false, "cast.i64.u64", true, v);
    cast_op!(u128, u64, false, false, "cast.u128.u64", true, v);
    cast_op!(i128, i64, true, true, "cast.i128.i64", true, v);
    // -- options on u64 ----------------------------------------------------
    v.push(Op { name: "option.is_some", cases: cases_default, run: option_is_some });
    v.push(Op { name: "option.is_none", cases: cases_default, run: option_is_none });
    v.push(Op { name: "option.is_some_and", cases: cases_default, run: option_is_some_and });
    v.push(Op { name: "option.unwrap_or", cases: cases_default, run: option_unwrap_or });
    v.push(Op { name: "option.map", cases: cases_default, run: option_map });
    v.push(Op { name: "option.map_or", cases: cases_default, run: option_map_or });
    v.push(Op { name: "option.as_ref", cases: cases_default, run: option_as_ref });
    // -- slices and Vec ----------------------------------------------------
    v.push(Op { name: "slice.len", cases: cases_default, run: slice_len });
    v.push(Op { name: "slice.is_empty", cases: cases_default, run: slice_is_empty });
    v.push(Op { name: "slice.index", cases: cases_default, run: slice_index });
    v.push(Op { name: "vec.new", cases: cases_default, run: vec_new });
    v.push(Op { name: "vec.len", cases: cases_default, run: vec_len });
    v.push(Op { name: "vec.as_slice", cases: cases_default, run: vec_as_slice });
    v.push(Op { name: "vec.extend_from_slice", cases: cases_default, run: vec_extend });
    v.push(Op { name: "vec.into_vec", cases: cases_default, run: vec_into_vec });
    v.push(Op { name: "vec.to_vec", cases: cases_default, run: vec_to_vec });
    v.push(Op { name: "array_of_list", cases: cases_default, run: array_of_list });
    v.push(Op { name: "fold_range.empty", cases: cases_default, run: fold_range_empty });
    v.push(Op { name: "fold_range.start_eq_end", cases: cases_default, run: fold_range_eq });
    v.push(Op { name: "fold_range.nonempty", cases: cases_default, run: fold_range_nonempty });
    // -- strings -----------------------------------------------------------
    v.push(Op { name: "string.new", cases: cases_default, run: string_new });
    v.push(Op { name: "string.as_str", cases: cases_default, run: string_as_str });
    v.push(Op { name: "string.eq", cases: cases_default, run: string_eq });
    v.push(Op { name: "string.length_chars", cases: cases_default, run: string_length });
    // -- bool negation (`~.` on bool) --------------------------------------
    v.push(Op { name: "bool.not", cases: cases_default, run: bool_not });
    // -- Clone and PartialEq ----------------------------------------------
    v.push(Op { name: "clone.identity", cases: cases_default, run: clone_identity });
    v.push(Op { name: "partialeq.u64", cases: cases_default, run: partialeq_u64 });
    v.push(Op { name: "phase.eq", cases: |_| 4, run: phase_eq });
    // -- documented model bugs (small, verbose) ----------------------------
    v.push(Op { name: "demo.ne.u64", cases: cases_small, run: demo_ne });
    v.push(Op { name: "demo.mul_overflow.u64", cases: cases_small, run: demo_mul_overflow });
    v.push(Op { name: "demo.mul_overflow.i64", cases: cases_small, run: demo_mul_overflow_i64 });
    v
}

fn u64_div(c: &Case) -> (Vec<u8>, String) {
    let a = value_of!(c, 0, u64, false);
    let b = value_of!(c, 1, u64, false);
    let r = if b == 0 { None } else { Some((a / b) as u128) };
    (c.input_bytes(), enc_uopt(r))
}

fn u64_mod(c: &Case) -> (Vec<u8>, String) {
    let a = value_of!(c, 0, u64, false);
    let b = value_of!(c, 1, u64, false);
    let r = if b == 0 { None } else { Some((a % b) as u128) };
    (c.input_bytes(), enc_uopt(r))
}

fn opt_input(c: &Case) -> (Option<u64>, u64, u64) {
    let present = c.r(0) % 2 == 0;
    let a = value_of!(c, 1, u64, false);
    let b = value_of!(c, 2, u64, false);
    (if present { Some(a) } else { None }, a, b)
}

fn option_is_some(c: &Case) -> (Vec<u8>, String) {
    let (o, _, _) = opt_input(c);
    (c.input_bytes(), enc_b(o.is_some()))
}
fn option_is_none(c: &Case) -> (Vec<u8>, String) {
    let (o, _, _) = opt_input(c);
    (c.input_bytes(), enc_b(o.is_none()))
}
fn option_is_some_and(c: &Case) -> (Vec<u8>, String) {
    let (o, a, b) = opt_input(c);
    (c.input_bytes(), enc_b(o.is_some_and(|x| x.wrapping_add(b) > a)))
}
fn option_unwrap_or(c: &Case) -> (Vec<u8>, String) {
    let (o, _, b) = opt_input(c);
    (c.input_bytes(), enc_u(o.unwrap_or(b) as u128))
}
fn option_map(c: &Case) -> (Vec<u8>, String) {
    let (o, _, b) = opt_input(c);
    (c.input_bytes(), enc_uopt(o.map(|x| x.wrapping_mul(b) as u128)))
}
fn option_map_or(c: &Case) -> (Vec<u8>, String) {
    let (o, a, b) = opt_input(c);
    (c.input_bytes(), enc_u(o.map_or(a, |x| x.wrapping_add(b)) as u128))
}
fn option_as_ref(c: &Case) -> (Vec<u8>, String) {
    let (o, _, _) = opt_input(c);
    let r = o.as_ref().copied();
    (c.input_bytes(), enc_uopt(r.map(|x| x as u128)))
}

fn vec_bytes(c: &Case) -> Vec<u8> {
    value_bytes(c, seq_len(c))
}

fn slice_len(c: &Case) -> (Vec<u8>, String) {
    let v = vec_bytes(c);
    (v.clone(), enc_u(v.len() as u128))
}
fn slice_is_empty(c: &Case) -> (Vec<u8>, String) {
    let v = vec_bytes(c);
    (v.clone(), enc_b(v.is_empty()))
}
fn slice_index(c: &Case) -> (Vec<u8>, String) {
    let v = vec_bytes(c);
    let n = v.len();
    if n == 0 {
        return (v, String::from("z"));
    }
    let i = (c.r(2) as usize) % n;
    (v.clone(), enc_u(v[i] as u128))
}
fn vec_new(_c: &Case) -> (Vec<u8>, String) {
    let v: Vec<u8> = Vec::new();
    (Vec::new(), enc_u(v.len() as u128))
}
fn vec_len(c: &Case) -> (Vec<u8>, String) {
    let v = vec_bytes(c);
    (v.clone(), enc_u(v.len() as u128))
}
fn vec_as_slice(c: &Case) -> (Vec<u8>, String) {
    let v = vec_bytes(c);
    (v.clone(), enc_list(v.as_slice()))
}
fn vec_extend(c: &Case) -> (Vec<u8>, String) {
    let mut v = vec_bytes(c);
    let other = value_bytes(c, (c.r(2) % 8) as usize);
    let mut inputs = v.clone();
    inputs.extend_from_slice(&other);
    v.extend_from_slice(&other);
    (inputs, enc_list(&v))
}
fn vec_into_vec(c: &Case) -> (Vec<u8>, String) {
    let v = vec_bytes(c);
    let boxed: Box<[u8]> = v.clone().into_boxed_slice();
    let back: Vec<u8> = boxed.into_vec();
    (v, enc_list(&back))
}
fn vec_to_vec(c: &Case) -> (Vec<u8>, String) {
    let v = vec_bytes(c);
    let copy: Vec<u8> = v.to_vec();
    (v, enc_list(&copy))
}
fn array_of_list(c: &Case) -> (Vec<u8>, String) {
    let v = vec_bytes(c);
    let a: [u8; 32] = {
        let mut a = [0u8; 32];
        a[..v.len()].copy_from_slice(&v);
        a
    };
    let sl = &a[..v.len()];
    (v, enc_list(sl))
}
fn fold_range_empty(c: &Case) -> (Vec<u8>, String) {
    let a = value_of!(c, 0, u64, false);
    let b = value_of!(c, 1, u64, false);
    let (start, end) = if a >= b { (a, b) } else { (b, a) };
    let n = (start..end).count();
    (c.input_bytes(), enc_u(n as u128))
}
fn fold_range_eq(c: &Case) -> (Vec<u8>, String) {
    let a = value_of!(c, 0, u64, false);
    let n = (a..a).count();
    (c.input_bytes(), enc_u(n as u128))
}
fn fold_range_nonempty(c: &Case) -> (Vec<u8>, String) {
    let start = c.r(0) % 4096;
    let len = c.r(1) % 17;
    let n = (start..start + len).count();
    (c.input_bytes(), enc_u(n as u128))
}

fn string_new(_c: &Case) -> (Vec<u8>, String) {
    let s = String::new();
    (Vec::new(), enc_u(s.chars().count() as u128))
}
fn string_as_str(c: &Case) -> (Vec<u8>, String) {
    let s = string_input(c);
    let t: &str = s.as_str();
    (s.as_bytes().to_vec(), enc_str(t.as_bytes()))
}
fn string_eq(c: &Case) -> (Vec<u8>, String) {
    let a = string_input(c);
    let b = if c.r(3) % 2 == 0 {
        a.clone()
    } else {
        string_input(&Case { seed: c.seed, tag: c.tag, i: c.i + 1 })
    };
    let mut inputs = a.as_bytes().to_vec();
    inputs.push(0);
    inputs.extend_from_slice(b.as_bytes());
    (inputs, enc_b(a == b))
}
fn string_length(c: &Case) -> (Vec<u8>, String) {
    let s = string_input(c);
    (s.as_bytes().to_vec(), enc_u(s.chars().count() as u128))
}

fn bool_not(c: &Case) -> (Vec<u8>, String) {
    let b = c.r(0) % 2 == 0;
    (vec![b as u8], enc_b(!b))
}

/// The Rust enum hax extracts as `t_Phase` (serverVELA/vela-rekey-policy/src/lib.rs).
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Active,
    Freezing,
}

#[derive(Clone, PartialEq)]
struct CloneSample {
    n: u64,
    v: Vec<u8>,
    s: String,
}

fn clone_sample(c: &Case) -> CloneSample {
    CloneSample {
        n: value_of!(c, 0, u64, false),
        v: vec_bytes(c),
        s: string_input(c),
    }
}

fn clone_identity(c: &Case) -> (Vec<u8>, String) {
    let x = clone_sample(c);
    let y = x.clone();
    let mut inputs = c.input_bytes();
    inputs.extend_from_slice(&x.v);
    inputs.extend_from_slice(x.s.as_bytes());
    (inputs, enc_b(y == x))
}

fn phase_eq(c: &Case) -> (Vec<u8>, String) {
    // Four pairs: (0,0) (0,1) (1,0) (1,1), as in T7_phase.phase_of.
    let i = c.i % 4;
    let pick = |k: u64| if k == 0 { Phase::Active } else { Phase::Freezing };
    let a = pick(i / 2);
    let b = pick(i % 2);
    (vec![i as u8], enc_b(a == b))
}

fn partialeq_u64(c: &Case) -> (Vec<u8>, String) {
    let a = value_of!(c, 0, u64, false);
    let b = value_of!(c, 1, u64, false);
    (c.input_bytes(), enc_b(a == b))
}

fn demo_ne(c: &Case) -> (Vec<u8>, String) {
    let a = value_of!(c, 0, u64, false);
    let b = value_of!(c, 1, u64, false);
    // Rust's `!=`; the F* side reports `Rust_primitives.Integers.ne`.
    (c.input_bytes(), format!("{},{},{}", a, b, a != b))
}
fn demo_mul_overflow(c: &Case) -> (Vec<u8>, String) {
    let a = value_of!(c, 0, u64, false);
    let b = value_of!(c, 1, u64, false);
    let (w, flag) = a.overflowing_mul(b);
    (c.input_bytes(), format!("{},{},{}", a, b, format!("{},{}", w, flag)))
}
fn demo_mul_overflow_i64(c: &Case) -> (Vec<u8>, String) {
    let a = value_of!(c, 0, i64, true);
    let b = value_of!(c, 1, i64, true);
    let (w, flag) = a.overflowing_mul(b);
    (c.input_bytes(), format!("{},{},{}", a, b, format!("{},{}", w, flag)))
}

// ---------------------------------------------------------------- driver ---

fn main() {
    let mut seed: u64 = 0x5EED_1234_ABCD_0001;
    let mut cases: u64 = 1_000_000;
    let mut block: u64 = 1024;
    let mut mode = String::from("hash");
    let mut only: Option<String> = None;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut k = 0;
    while k < args.len() {
        match args[k].as_str() {
            "--seed" => {
                seed = args[k + 1].parse().expect("seed");
                k += 2;
            }
            "--cases" => {
                cases = args[k + 1].parse().expect("cases");
                k += 2;
            }
            "--block" => {
                block = args[k + 1].parse().expect("block");
                k += 2;
            }
            "--mode" => {
                mode = args[k + 1].clone();
                k += 2;
            }
            "--op" => {
                only = Some(args[k + 1].clone());
                k += 2;
            }
            other => panic!("unknown argument {other}"),
        }
    }
    assert_eq!(usize::BITS, 64, "the harness models a 64-bit target");
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for op in ops() {
        if let Some(f) = &only {
            if f != op.name {
                continue;
            }
        }
        let n = (op.cases)(cases);
        let tag = fnv1a(op.name.as_bytes());
        let demo = op.cases as usize == cases_small as usize;
        let verbose = mode == "verbose" || (demo && mode == "demo");
        if mode == "demo" && !demo {
            continue;
        }
        if demo && mode != "demo" && mode != "verbose" {
            // documented-bug demonstrations: verbose only
            continue;
        }
        let mut block_no = 0u64;
        let mut block_cases = 0u64;
        let mut h = Hasher::new();
        for i in 0..n {
            let c = Case { seed, tag, i };
            let (inp, res) = (op.run)(&c);
            if verbose {
                let mut hex = String::new();
                for b in &inp {
                    hex.push_str(&format!("{:02x}", b));
                }
                writeln!(out, "V\t{}\t{}\t{}\t{}", op.name, i, hex, res).unwrap();
            }
            h.bytes(&inp);
            h.byte(b'=');
            h.bytes(res.as_bytes());
            h.byte(b'\n');
            block_cases += 1;
            if block_cases == block {
                writeln!(out, "H\t{}\t{}\t{}\t{:016x}", op.name, block_no, block_cases, h.finish())
                    .unwrap();
                block_no += 1;
                block_cases = 0;
                h = Hasher::new();
            }
        }
        if block_cases > 0 {
            writeln!(out, "H\t{}\t{}\t{}\t{:016x}", op.name, block_no, block_cases, h.finish())
                .unwrap();
        }
        if !verbose {
            writeln!(out, "C\t{}\t{}", op.name, n).unwrap();
        }
    }
    // Notes: byte lengths next to char counts, so the log shows the
    // byte-vs-char difference the T4 review records.
    for name in ["", "e", "é", "€", "😀"] {
        writeln!(
            out,
            "N\tstring.bytes.{}\tchars={} bytes={}",
            if name.is_empty() { "<empty>".to_string() } else { name.to_string() },
            name.chars().count(),
            name.len()
        )
        .unwrap();
    }
    // F*'s Euclidean division vs Rust's truncation (T7_semantics.fst).
    writeln!(
        out,
        "N\tdiv.rounding\t(-7)/2={} (-7)%2={} 7/(-2)={} 7%(-2)={} (-7)/(-2)={} (-7)%(-2)={}",
        -7i64 / 2,
        -7i64 % 2,
        7i64 / -2,
        7i64 % -2,
        -7i64 / -2,
        -7i64 % -2
    )
    .unwrap();
    // Bit-lemma constraints (`logand`/`logor`/`lognot`/`shift_left` are
    // abstract F* `val`s, so the trusted statements are checked against the
    // Rust operators instead of a model value).  10^6 samples.
    let mut bad = 0u64;
    for i in 0..1_000_000u64 {
        let a = mix64(seed ^ i.wrapping_mul(K1));
        let b = mix64(seed ^ i.wrapping_mul(K2));
        let ones = u64::MAX;
        let na = !a;
        let nz = 0u64;
        let and_ok = (a & nz == 0)
            && (a & ones == a)
            && (ones & a == a)
            && (a & a == a)
            && (a & na == 0)
            && (a & b) <= a
            && (a & b) <= b;
        let or_ok = (a | nz == a) && (a | ones == ones) && (a | b) >= a && (a | b) >= b;
        let not_ok = (na == !a) && (a ^ ones == na) && (!!a == a);
        let sh = (i % 63) as u32;
        let shl_ok = if a >= 0 {
            a.checked_shl(sh).map(|x| x == a.wrapping_mul(1u64 << sh)).unwrap_or(true)
        } else {
            true
        };
        if !(and_ok && or_ok && not_ok && shl_ok) {
            bad += 1;
        }
    }
    writeln!(out, "N\tbit_lemma_samples\t1000000 violations={}", bad).unwrap();
    out.flush().unwrap();
}
