//! Thin C-ABI wrapper around tfhe_ntt.
//!
//! Exposed functions:
//!
//!   ntt_plan_create  – allocate a Plan for (n, p), returns opaque handle
//!   ntt_plan_destroy – free the handle
//!   ntt_mul_poly     – negacyclic multiplication of two degree-N polynomials
//!   ntt_fwd          - forward transform
//!   ntt_inv          - inverse transform
//!   ntt_pointwise_mul_normalize - pointwise multiplication
//!
//!   ntt_native_plan_create
//!   ntt_native_plan_destroy
//!   ntt_native_mul_poly
//!   ntt_native_fwd
//!   ntt_native_inv
//!   ntt_native_pointwise_mul_normalize
//!

use std::ffi::c_void;
use tfhe_ntt::native64::Plan32 as NativePlan;
use tfhe_ntt::prime64::Plan;

// ---------------------------------------------------------------------------
// Prime64 Plan with Scratch
// ---------------------------------------------------------------------------

struct PlanWithScratch {
    plan: Plan,
    scratch_a: Vec<u64>,
    scratch_b: Vec<u64>,
}

#[unsafe(no_mangle)]
pub extern "C" fn ntt_plan_create(n: usize, p: u64) -> *mut c_void {
    match Plan::try_new(n, p) {
        Some(plan) => {
            let s = PlanWithScratch {
                plan,
                scratch_a: vec![0u64; n],
                scratch_b: vec![0u64; n],
            };
            Box::into_raw(Box::new(s)) as *mut c_void
        }
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_plan_destroy(handle: *mut c_void) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle as *mut PlanWithScratch) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_mul_poly(
    handle: *mut c_void,
    a: *const u64,
    b: *const u64,
    out: *mut u64,
    n: usize,
) {
    let s = unsafe { &mut *(handle as *mut PlanWithScratch) };

    s.scratch_a[..n].copy_from_slice(unsafe { std::slice::from_raw_parts(a, n) });
    s.scratch_b[..n].copy_from_slice(unsafe { std::slice::from_raw_parts(b, n) });

    s.plan.fwd(&mut s.scratch_a);
    s.plan.fwd(&mut s.scratch_b);
    s.plan.mul_assign_normalize(&mut s.scratch_a, &s.scratch_b);
    s.plan.inv(&mut s.scratch_a);

    unsafe { std::slice::from_raw_parts_mut(out, n) }.copy_from_slice(&s.scratch_a[..n]);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_fwd(handle: *const c_void, poly: *mut u64, n: usize) {
    let s = unsafe { &*(handle as *const PlanWithScratch) };
    let slice = unsafe { std::slice::from_raw_parts_mut(poly, n) };
    s.plan.fwd(slice);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_inv(handle: *const c_void, poly: *mut u64, n: usize) {
    let s = unsafe { &*(handle as *const PlanWithScratch) };
    let slice = unsafe { std::slice::from_raw_parts_mut(poly, n) };
    s.plan.inv(slice);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_pointwise_mul_normalize(
    handle: *const c_void,
    a: *mut u64,
    b: *const u64,
    n: usize,
) {
    let s = unsafe { &*(handle as *const PlanWithScratch) };
    let a_s = unsafe { std::slice::from_raw_parts_mut(a, n) };
    let b_s = unsafe { std::slice::from_raw_parts(b, n) };
    s.plan.mul_assign_normalize(a_s, b_s);
}

// ---------------------------------------------------------------------------
// Native64 Plan
// ---------------------------------------------------------------------------

struct NativePlanWithScratch {
    plan: NativePlan,
    lhs: Vec<u32>, // Size 5 * n
    rhs: Vec<u32>, // Size 5 * n
}

#[unsafe(no_mangle)]
pub extern "C" fn ntt_native_plan_create(n: usize) -> *mut c_void {
    match NativePlan::try_new(n) {
        Some(plan) => {
            let s = NativePlanWithScratch {
                plan,
                lhs: vec![0u32; 5 * n],
                rhs: vec![0u32; 5 * n],
            };
            Box::into_raw(Box::new(s)) as *mut c_void
        }
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_native_plan_destroy(handle: *mut c_void) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle as *mut NativePlanWithScratch) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_native_mul_poly(
    handle: *mut c_void,
    a: *const u64,
    b: *const u64,
    out: *mut u64,
    n: usize,
) {
    let s = unsafe { &mut *(handle as *mut NativePlanWithScratch) };

    // We can't easily avoid allocation for input/output copy if we want to be safe,
    // but here we just read A and B.
    // Wait, fwd takes `val: &[u64]`. It doesn't modify it.
    // So we can pass A and B directly.

    let a_slice = unsafe { std::slice::from_raw_parts(a, n) };
    let b_slice = unsafe { std::slice::from_raw_parts(b, n) };
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out, n) };

    // Fwd A -> s.lhs
    {
        let (p0, rest) = s.lhs.split_at_mut(n);
        let (p1, rest) = rest.split_at_mut(n);
        let (p2, rest) = rest.split_at_mut(n);
        let (p3, p4) = rest.split_at_mut(n);
        s.plan.fwd(a_slice, p0, p1, p2, p3, p4);
    }

    // Fwd B -> s.rhs
    {
        let (p0, rest) = s.rhs.split_at_mut(n);
        let (p1, rest) = rest.split_at_mut(n);
        let (p2, rest) = rest.split_at_mut(n);
        let (p3, p4) = rest.split_at_mut(n);
        s.plan.fwd(b_slice, p0, p1, p2, p3, p4);
    }

    // Pointwise mul: lhs *= rhs
    // We need to iterate over sub-plans
    {
        let (l0, rest_l) = s.lhs.split_at_mut(n);
        let (l1, rest_l) = rest_l.split_at_mut(n);
        let (l2, rest_l) = rest_l.split_at_mut(n);
        let (l3, l4) = rest_l.split_at_mut(n);

        let (r0, rest_r) = s.rhs.split_at(n);
        let (r1, rest_r) = rest_r.split_at(n);
        let (r2, rest_r) = rest_r.split_at(n);
        let (r3, r4) = rest_r.split_at(n);

        s.plan.ntt_0().mul_assign_normalize(l0, r0);
        s.plan.ntt_1().mul_assign_normalize(l1, r1);
        s.plan.ntt_2().mul_assign_normalize(l2, r2);
        s.plan.ntt_3().mul_assign_normalize(l3, r3);
        s.plan.ntt_4().mul_assign_normalize(l4, r4);
    }

    // Inv -> out
    // Note: inv reconstructs into the first argument!
    // pub fn inv(&self, val: &mut [u64], mod_p0: &mut [u32], ...)
    // Wait, inv signature from error: `inv(&mut a_buf, ...)`
    // So it writes result to `val`.
    {
        let (p0, rest) = s.lhs.split_at_mut(n);
        let (p1, rest) = rest.split_at_mut(n);
        let (p2, rest) = rest.split_at_mut(n);
        let (p3, p4) = rest.split_at_mut(n);
        s.plan.inv(out_slice, p0, p1, p2, p3, p4);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_native_fwd(
    handle: *const c_void,
    val: *const u64,
    out_ntt: *mut u64, // Treated as *mut u32, size 5*n
    n: usize,
) {
    let s = unsafe { &*(handle as *const NativePlanWithScratch) };
    let val_slice = unsafe { std::slice::from_raw_parts(val, n) };

    let out_u32 = out_ntt as *mut u32;
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_u32, 5 * n) };

    let (p0, rest) = out_slice.split_at_mut(n);
    let (p1, rest) = rest.split_at_mut(n);
    let (p2, rest) = rest.split_at_mut(n);
    let (p3, p4) = rest.split_at_mut(n);

    s.plan.fwd(val_slice, p0, p1, p2, p3, p4);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_native_inv(
    handle: *const c_void,
    val_ntt: *mut u64, // Treated as *mut u32, size 5*n (mutable because inv modifies residues?)
    out: *mut u64,
    n: usize,
) {
    let s = unsafe { &*(handle as *const NativePlanWithScratch) };
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out, n) };

    let in_u32 = val_ntt as *mut u32;
    let in_slice = unsafe { std::slice::from_raw_parts_mut(in_u32, 5 * n) };

    let (p0, rest) = in_slice.split_at_mut(n);
    let (p1, rest) = rest.split_at_mut(n);
    let (p2, rest) = rest.split_at_mut(n);
    let (p3, p4) = rest.split_at_mut(n);

    s.plan.inv(out_slice, p0, p1, p2, p3, p4);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_native_pointwise_mul_normalize(
    handle: *const c_void,
    a_ntt: *mut u64,   // in-out, treated as *mut u32
    b_ntt: *const u64, // read-only, treated as *const u32
    n: usize,
) {
    let s = unsafe { &*(handle as *const NativePlanWithScratch) };

    let a_u32 = a_ntt as *mut u32;
    let b_u32 = b_ntt as *const u32;

    let a_slice = unsafe { std::slice::from_raw_parts_mut(a_u32, 5 * n) };
    let b_slice = unsafe { std::slice::from_raw_parts(b_u32, 5 * n) };

    let (a0, rest_a) = a_slice.split_at_mut(n);
    let (a1, rest_a) = rest_a.split_at_mut(n);
    let (a2, rest_a) = rest_a.split_at_mut(n);
    let (a3, a4) = rest_a.split_at_mut(n);

    let (b0, rest_b) = b_slice.split_at(n);
    let (b1, rest_b) = rest_b.split_at(n);
    let (b2, rest_b) = rest_b.split_at(n);
    let (b3, b4) = rest_b.split_at(n);

    s.plan.ntt_0().mul_assign_normalize(a0, b0);
    s.plan.ntt_1().mul_assign_normalize(a1, b1);
    s.plan.ntt_2().mul_assign_normalize(a2, b2);
    s.plan.ntt_3().mul_assign_normalize(a3, b3);
    s.plan.ntt_4().mul_assign_normalize(a4, b4);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_native_add(
    handle: *const c_void,
    a_ntt: *mut u64,   // in-out
    b_ntt: *const u64, // read-only
    n: usize,
) {
    let s = unsafe { &*(handle as *const NativePlanWithScratch) };

    let a_u32 = a_ntt as *mut u32;
    let b_u32 = b_ntt as *const u32;

    let a_slice = unsafe { std::slice::from_raw_parts_mut(a_u32, 5 * n) };
    let b_slice = unsafe { std::slice::from_raw_parts(b_u32, 5 * n) };

    for i in 0..5 {
        let (sub_plan_p, start, end) = match i {
            0 => (s.plan.ntt_0().modulus(), 0, n),
            1 => (s.plan.ntt_1().modulus(), n, 2 * n),
            2 => (s.plan.ntt_2().modulus(), 2 * n, 3 * n),
            3 => (s.plan.ntt_3().modulus(), 3 * n, 4 * n),
            4 => (s.plan.ntt_4().modulus(), 4 * n, 5 * n),
            _ => unreachable!(),
        };

        let p = sub_plan_p as u64;

        let sub_a = &mut a_slice[start..end];
        let sub_b = &b_slice[start..end];

        for j in 0..n {
            let sum = sub_a[j] as u64 + sub_b[j] as u64;
            sub_a[j] = if sum >= p {
                (sum - p) as u32
            } else {
                sum as u32
            };
        }
    }
}

pub struct IncompleteNttPlan {
    phi: usize,
    half_plan: Plan,
    eval_points: Vec<u64>,
    q: u64,
    inv_phi: u64,
}

impl IncompleteNttPlan {
    pub fn try_new(phi: usize, q: u64) -> Option<Self> {
        if !phi.is_power_of_two() || phi < 4 {
            return None;
        }
        let half = phi / 2;
        let half_plan = Plan::try_new(half, q)?;
        let eval_points = compute_eval_points(half, q)?;
        let inv_phi = mod_inv(phi as u64, q)?;
        Some(Self {
            phi,
            half_plan,
            eval_points,
            q,
            inv_phi,
        })
    }

    pub fn fwd(&self, poly: &[u64], out: &mut [u64]) -> bool {
        if poly.len() != self.phi || out.len() != self.phi {
            return false;
        }
        let half = self.phi / 2;
        let (out_e, out_o) = out.split_at_mut(half);
        for i in 0..half {
            out_e[i] = poly[2 * i];
            out_o[i] = poly[2 * i + 1];
        }
        self.half_plan.fwd(out_e);
        self.half_plan.fwd(out_o);
        true
    }

    pub fn inv(&self, ntt: &[u64], out: &mut [u64]) -> bool {
        if ntt.len() != self.phi || out.len() != self.phi {
            return false;
        }
        let half = self.phi / 2;
        let (ntt_e, ntt_o) = ntt.split_at(half);
        let mut scratch_e = ntt_e.to_vec();
        let mut scratch_o = ntt_o.to_vec();
        self.half_plan.inv(&mut scratch_e);
        self.half_plan.inv(&mut scratch_o);
        let two = 2 % self.q;
        let q128 = self.q as u128;
        for i in 0..half {
            out[2 * i] = ((scratch_e[i] as u128 * two as u128) % q128) as u64;
            out[2 * i + 1] = ((scratch_o[i] as u128 * two as u128) % q128) as u64;
        }
        true
    }

    pub fn mul_assign(&self, a: &mut [u64], b: &[u64]) -> bool {
        if a.len() != self.phi || b.len() != self.phi {
            return false;
        }
        let half = self.phi / 2;
        let (ae, ao) = a.split_at_mut(half);
        let (be, bo) = b.split_at(half);
        let q128 = self.q as u128;
        let inv_phi = self.inv_phi as u128;
        for i in 0..half {
            let r = self.eval_points[i] as u128;
            let ae_i = ae[i] as u128;
            let ao_i = ao[i] as u128;
            let be_i = be[i] as u128;
            let bo_i = bo[i] as u128;
            let re = (ae_i * be_i + (r * ((ao_i * bo_i) % q128)) % q128) % q128;
            let ro = (ae_i * bo_i + ao_i * be_i) % q128;
            ae[i] = ((re * inv_phi) % q128) as u64;
            ao[i] = ((ro * inv_phi) % q128) as u64;
        }
        true
    }

    pub fn mul_poly(&self, a: &[u64], b: &[u64], out: &mut [u64]) -> bool {
        if a.len() != self.phi || b.len() != self.phi || out.len() != self.phi {
            return false;
        }
        let mut ntt_a = vec![0u64; self.phi];
        let mut ntt_b = vec![0u64; self.phi];
        if !self.fwd(a, &mut ntt_a) {
            return false;
        }
        if !self.fwd(b, &mut ntt_b) {
            return false;
        }
        if !self.mul_assign(&mut ntt_a, &ntt_b) {
            return false;
        }
        self.inv(&ntt_a, out)
    }
}

fn compute_eval_points(half: usize, q: u64) -> Option<Vec<u64>> {
    let order = 4 * half as u64;
    if (q - 1) % order != 0 {
        return None;
    }
    let g = find_primitive_root(q)?;
    let psi = pow_mod(g, (q - 1) / order, q);
    let mut eval_points = Vec::with_capacity(half);
    for i in 0..half {
        let exp = 2 * (2 * i as u64 + 1);
        eval_points.push(pow_mod(psi, exp, q));
    }
    Some(eval_points)
}

fn mod_inv(a: u64, q: u64) -> Option<u64> {
    if a % q == 0 {
        return None;
    }
    Some(pow_mod(a, q - 2, q))
}

fn pow_mod(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result as u128 * base as u128 % modulus as u128) as u64;
        }
        exp >>= 1;
        base = (base as u128 * base as u128 % modulus as u128) as u64;
    }
    result
}

fn find_primitive_root(q: u64) -> Option<u64> {
    let phi_q = q - 1;
    let factors = factorize(phi_q);
    'outer: for g in 2..q {
        for &p in &factors {
            if pow_mod(g, phi_q / p, q) == 1 {
                continue 'outer;
            }
        }
        return Some(g);
    }
    None
}

fn factorize(mut n: u64) -> Vec<u64> {
    let mut factors = Vec::new();
    let mut d = 2u64;
    while d * d <= n {
        if n % d == 0 {
            factors.push(d);
            while n % d == 0 {
                n /= d;
            }
        }
        d += 1;
    }
    if n > 1 {
        factors.push(n);
    }
    factors
}

#[unsafe(no_mangle)]
pub extern "C" fn ntt_incomplete_plan_create(phi: usize, q: u64) -> *mut c_void {
    match IncompleteNttPlan::try_new(phi, q) {
        Some(plan) => Box::into_raw(Box::new(plan)) as *mut c_void,
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_incomplete_plan_destroy(handle: *mut c_void) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle as *mut IncompleteNttPlan) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_incomplete_fwd(
    handle: *const c_void,
    poly: *const u64,
    out: *mut u64,
    phi: usize,
) {
    if handle.is_null() || poly.is_null() || out.is_null() || phi == 0 {
        return;
    }
    let plan = unsafe { &*(handle as *const IncompleteNttPlan) };
    let poly_s = unsafe { std::slice::from_raw_parts(poly, phi) };
    let out_s = unsafe { std::slice::from_raw_parts_mut(out, phi) };
    let _ = plan.fwd(poly_s, out_s);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_incomplete_inv(
    handle: *const c_void,
    ntt: *const u64,
    out: *mut u64,
    phi: usize,
) {
    if handle.is_null() || ntt.is_null() || out.is_null() || phi == 0 {
        return;
    }
    let plan = unsafe { &*(handle as *const IncompleteNttPlan) };
    let ntt_s = unsafe { std::slice::from_raw_parts(ntt, phi) };
    let out_s = unsafe { std::slice::from_raw_parts_mut(out, phi) };
    let _ = plan.inv(ntt_s, out_s);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_incomplete_mul_assign(
    handle: *const c_void,
    a: *mut u64,
    b: *const u64,
    phi: usize,
) {
    if handle.is_null() || a.is_null() || b.is_null() || phi == 0 {
        return;
    }
    let plan = unsafe { &*(handle as *const IncompleteNttPlan) };
    let a_s = unsafe { std::slice::from_raw_parts_mut(a, phi) };
    let b_s = unsafe { std::slice::from_raw_parts(b, phi) };
    let _ = plan.mul_assign(a_s, b_s);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_incomplete_mul_poly(
    handle: *const c_void,
    a: *const u64,
    b: *const u64,
    out: *mut u64,
    phi: usize,
) {
    if handle.is_null() || a.is_null() || b.is_null() || out.is_null() || phi == 0 {
        return;
    }
    let plan = unsafe { &*(handle as *const IncompleteNttPlan) };
    let a_s = unsafe { std::slice::from_raw_parts(a, phi) };
    let b_s = unsafe { std::slice::from_raw_parts(b, phi) };
    let out_s = unsafe { std::slice::from_raw_parts_mut(out, phi) };
    let _ = plan.mul_poly(a_s, b_s, out_s);
}
