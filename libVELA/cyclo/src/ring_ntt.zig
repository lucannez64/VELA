//! NTT-backed polynomial multiplication using the tfhe-ntt Rust shim.
//!
//! Usage:
//!   const NttMul = @import("ring_ntt.zig").NttMul;
//!   const plan = try NttMul(N, Q).init();      // once per (N, Q) pair
//!   defer plan.deinit();
//!   const c = plan.mul(a, b);                  // replaces a.mul(b)

const std = @import("std");
const c = @import("ntt_c");

fn nowNs() i96 {
    var threaded: std.Io.Threaded = .init_single_threaded;
    return std.Io.Clock.awake.now(threaded.io()).nanoseconds;
}

fn powMod(base_in: u64, exp_in: u64, modulus: u64) u64 {
    var base = base_in % modulus;
    var exp = exp_in;
    var acc: u64 = 1 % modulus;
    while (exp > 0) : (exp >>= 1) {
        if ((exp & 1) == 1) {
            acc = @intCast((@as(u128, acc) * @as(u128, base)) % modulus);
        }
        base = @intCast((@as(u128, base) * @as(u128, base)) % modulus);
    }
    return acc;
}

fn invMod(a: u64, modulus: u64) u64 {
    std.debug.assert(modulus > 1);
    std.debug.assert(a % modulus != 0);
    return powMod(a, modulus - 2, modulus);
}

/// Returns a Plan-wrapper for Ring(degree, modulus).
///
/// Returns the NTT plan for the ring Z_modulus[X]/(X^degree + 1).
///
/// For native modulus (modulus == 0), uses 2^64 arithmetic.
/// For prime modulus, requires modulus ≡ 1 (mod 2*degree).
///
/// # Errors
/// Returns `NoPlan` if:
/// - degree is not a power of two
/// - modulus doesn't meet requirements
/// - tfhe-ntt initialization fails
pub fn NttMul(
    comptime degree: usize,
    comptime modulus: u64,
) type {
    return struct {
        handle: *anyopaque,

        const Self = @This();
        const is_native = (modulus == 0);

        pub fn init() error{NoPlan}!Self {
            if (@popCount(degree) != 1) return error.NoPlan;
            if (!is_native and modulus % (2 * degree) != 1) return error.NoPlan;
            const h = if (is_native)
                c.ntt_native_plan_create(degree)
            else
                c.ntt_incomplete_plan_create(degree, modulus);

            if (h == null) return error.NoPlan;
            return .{ .handle = h.? };
        }

        pub fn deinit(self: *Self) void {
            if (is_native) {
                c.ntt_native_plan_destroy(self.handle);
            } else {
                c.ntt_incomplete_plan_destroy(self.handle);
            }
            self.handle = undefined;
        }

        /// Negacyclic product a * b in Z_modulus[X]/(X^degree + 1).
        pub fn mul(
            self: Self,
            a: *const [degree]u64,
            b: *const [degree]u64,
        ) [degree]u64 {
            var out: [degree]u64 = undefined;
            if (is_native) {
                c.ntt_native_mul_poly(
                    self.handle,
                    a,
                    b,
                    &out,
                    degree,
                );
            } else {
                c.ntt_incomplete_mul_poly(
                    self.handle,
                    a,
                    b,
                    &out,
                    degree,
                );
            }
            return out;
        }
    };
}

/// A polynomial already in NTT domain — cheap to multiply,
/// cannot be read back as ring coefficients without inv().
pub fn NttDomain(
    comptime degree: usize,
    comptime modulus: u64,
) type {
    const RingT = @import("root.zig").Ring(degree, modulus);
    const is_native = (modulus == 0);
    // Native64 requires 5 * degree * u32 (20 bytes per polynomial coefficient).
    // Prime64 requires degree * u64 (8 bytes per polynomial coefficient).
    // We use [3 * degree]u64 (24 bytes per polynomial coefficient) for Native64 storage.
    const CoeffsT = if (is_native) [3 * degree]u64 else [degree]u64;

    return struct {
        coeffs: CoeffsT,

        const Self = @This();

        /// Zero element in NTT domain.
        /// All-zero NTT representation — corresponds to the zero polynomial.
        /// Valid because NTT is linear: NTT(0⃗) = 0⃗.
        pub fn zero() Self {
            return .{
                .coeffs = std.mem.zeroes(CoeffsT),
            };
        }

        /// Forward-transform a ring element.
        pub fn init(
            plan: *const NttMul(degree, modulus),
            r: RingT,
        ) Self {
            if (is_native) {
                var buf: CoeffsT = undefined;
                c.ntt_native_fwd(plan.handle, &r.data, &buf, degree);
                return .{ .coeffs = buf };
            } else {
                var buf: CoeffsT = undefined;
                c.ntt_incomplete_fwd(plan.handle, &r.data, &buf, degree);
                return .{ .coeffs = buf };
            }
        }

        /// Pointwise add two NTT-domain elements.
        pub fn add(self: Self, other: Self, plan: *const NttMul(degree, modulus)) Self {
            var buf = self.coeffs;
            if (is_native) {
                c.ntt_native_add(
                    plan.handle,
                    &buf,
                    &other.coeffs,
                    degree,
                );
            } else {
                for (0..degree) |i| {
                    const sum = buf[i] + other.coeffs[i];
                    buf[i] = if (sum >= modulus) sum - modulus else sum;
                }
            }
            return .{ .coeffs = buf };
        }

        pub fn scalarMulConst(self: Self, scalar: u64) Self {
            var buf = self.coeffs;
            if (is_native) {
                for (0..buf.len) |i| {
                    buf[i] = buf[i] *% scalar;
                }
            } else {
                const s = scalar % modulus;
                for (0..degree) |i| {
                    buf[i] = @intCast((@as(u128, buf[i]) * @as(u128, s)) % modulus);
                }
            }
            return .{ .coeffs = buf };
        }

        /// Pointwise multiply two NTT-domain elements (normalised).
        pub fn mul(self: Self, other: Self, plan: *const NttMul(degree, modulus)) Self {
            var buf = self.coeffs;
            if (is_native) {
                c.ntt_native_pointwise_mul_normalize(
                    plan.handle,
                    &buf,
                    &other.coeffs,
                    degree,
                );
            } else {
                c.ntt_incomplete_mul_assign(
                    plan.handle,
                    &buf,
                    &other.coeffs,
                    degree,
                );
            }
            return .{ .coeffs = buf };
        }

        /// Multiply without allocating new buffer (reuses self's buffer)
        pub fn mulAssign(self: *Self, other: Self, plan: *const NttMul(degree, modulus)) void {
            if (is_native) {
                c.ntt_native_pointwise_mul_normalize(
                    plan.handle,
                    &self.coeffs,
                    &other.coeffs,
                    degree,
                );
            } else {
                c.ntt_incomplete_mul_assign(
                    plan.handle,
                    &self.coeffs,
                    &other.coeffs,
                    degree,
                );
            }
        }

        /// Inverse-transform back to ring element.
        pub fn toRing(self: Self, plan: *const NttMul(degree, modulus)) RingT {
            if (is_native) {
                var out: [degree]u64 = undefined;
                var buf = self.coeffs; // Copy because inv modifies residues
                c.ntt_native_inv(plan.handle, &buf, &out, degree);
                return .{ .data = out };
            } else {
                var out: [degree]u64 = undefined;
                c.ntt_incomplete_inv(plan.handle, &self.coeffs, &out, degree);
                return .{ .data = out };
            }
        }

        pub fn toRingBatch(
            items: []const Self,
            out: []RingT,
            plan: *const NttMul(degree, modulus),
        ) void {
            std.debug.assert(items.len == out.len);
            for (items, 0..) |item, i| {
                out[i] = item.toRing(plan);
            }
        }
    };
}

pub fn NttDomainFq2(
    comptime degree: usize,
    comptime modulus: u64,
    comptime beta: u64,
) type {
    const root = @import("root.zig");
    const E = root.Fq2(modulus, beta);
    const Re = root.RingWithOps(degree, E, E.Ops);
    const R = root.Ring(degree, modulus);
    const Dom = NttDomain(degree, modulus);

    return struct {
        c0: Dom,
        c1: Dom,

        const Self = @This();

        pub fn zero() Self {
            return .{ .c0 = Dom.zero(), .c1 = Dom.zero() };
        }

        pub fn init(plan: *const NttMul(degree, modulus), value: Re) Self {
            var c0_coeffs: [degree]u64 = undefined;
            var c1_coeffs: [degree]u64 = undefined;
            for (value.data, 0..) |coeff, i| {
                c0_coeffs[i] = coeff.c0;
                c1_coeffs[i] = coeff.c1;
            }
            return .{
                .c0 = Dom.init(plan, .{ .data = c0_coeffs }),
                .c1 = Dom.init(plan, .{ .data = c1_coeffs }),
            };
        }

        pub fn add(self: Self, other: Self, plan: *const NttMul(degree, modulus)) Self {
            return .{
                .c0 = self.c0.add(other.c0, plan),
                .c1 = self.c1.add(other.c1, plan),
            };
        }

        pub fn mul(self: Self, other: Self, plan: *const NttMul(degree, modulus)) Self {
            const left = self.toRing(plan);
            const right = other.toRing(plan);
            const inv_n = invMod(@intCast(degree % modulus), modulus);
            const inv_n_sq: u64 = @intCast((@as(u128, inv_n) * @as(u128, inv_n)) % modulus);
            const normalized = left.mul(right).scalarMul(E.fromU64(inv_n_sq));
            return init(plan, normalized);
        }

        pub fn toRing(self: Self, plan: *const NttMul(degree, modulus)) Re {
            const c0_ring: R = self.c0.toRing(plan);
            const c1_ring: R = self.c1.toRing(plan);
            var out = Re.zero();
            for (0..degree) |i| {
                out.data[i] = E.init(c0_ring.data[i], c1_ring.data[i]);
            }
            return out;
        }
    };
}

test "NTT round-trip" {
    const N = 64;
    const Q = 1062862849; // Prime ≡ 1 (mod 2*64)
    const Plan = NttMul(N, Q);
    var plan = try Plan.init();
    defer plan.deinit();

    // Create test polynomial
    var poly: [N]u64 = undefined;
    for (&poly, 0..) |*coeff, i| {
        coeff.* = i % Q;
    }

    // Forward then inverse
    const RingT = @import("root.zig").Ring(N, Q);
    const ring_poly = RingT{ .data = poly };
    const ntt = NttDomain(N, Q).init(&plan, ring_poly);
    const recovered = ntt.toRing(&plan);

    // Should recover scaled by N
    for (poly, recovered.data) |orig, rec| {
        try std.testing.expectEqual((orig * N) % Q, rec);
    }
}

test "NTT native round-trip" {
    const N = 64;
    const Q = 0; // Native
    const Plan = NttMul(N, Q);
    var plan = try Plan.init();
    defer plan.deinit();

    const RingT = @import("root.zig").Ring(N, Q);
    var poly: [N]u64 = undefined;
    for (&poly, 0..) |*coeff, i| {
        coeff.* = @as(u64, @intCast(i));
    }
    const ring_poly = RingT{ .data = poly };
    const ntt = NttDomain(N, Q).init(&plan, ring_poly);
    const recovered = ntt.toRing(&plan);

    // Native NTT also scales by N
    for (poly, recovered.data) |orig, rec| {
        const expected = orig *% N;
        try std.testing.expectEqual(expected, rec);
    }
}

test "mulAssign matches mul" {
    const N = 64;
    const Q = 1062862849;
    const Plan = NttMul(N, Q);
    var plan = try Plan.init();
    defer plan.deinit();

    const RingT = @import("root.zig").Ring(N, Q);
    const Dom = NttDomain(N, Q);

    var a_data: [N]u64 = undefined;
    var b_data: [N]u64 = undefined;
    for (&a_data, 0..) |*x, i| x.* = i % Q;
    for (&b_data, 0..) |*x, i| x.* = (i + 1) % Q;

    const a = RingT{ .data = a_data };
    const b = RingT{ .data = b_data };

    const a_ntt = Dom.init(&plan, a);
    const b_ntt = Dom.init(&plan, b);

    // mul
    const res_mul = a_ntt.mul(b_ntt, &plan);

    // mulAssign
    var res_assign = a_ntt; // copy
    res_assign.mulAssign(b_ntt, &plan);

    // Check equality of coeffs
    for (res_mul.coeffs, res_assign.coeffs) |c1, c2| {
        try std.testing.expectEqual(c1, c2);
    }
}

test "NTT zero polynomial" {
    const N = 64;
    const Q = 1062862849;
    const Plan = NttMul(N, Q);
    var plan = try Plan.init();
    defer plan.deinit();

    const RingT = @import("root.zig").Ring(N, Q);
    const zero = RingT.zero();
    const ntt_zero = NttDomain(N, Q).init(&plan, zero);
    const recovered = ntt_zero.toRing(&plan);

    for (recovered.data) |coeff| {
        try std.testing.expectEqual(@as(u64, 0), coeff);
    }
}

test "NttDomain pointwise add" {
    const N = 64;
    const Q = 1062862849;
    const Plan = NttMul(N, Q);
    var plan = try Plan.init();
    defer plan.deinit();

    const RingT = @import("root.zig").Ring(N, Q);
    const Dom = NttDomain(N, Q);

    var a_data = [_]u64{0} ** N;
    a_data[0] = 1;
    const a = RingT{ .data = a_data };

    var b_data = [_]u64{0} ** N;
    b_data[0] = 2;
    const b = RingT{ .data = b_data };

    const a_ntt = Dom.init(&plan, a);
    const b_ntt = Dom.init(&plan, b);

    const sum = a_ntt.add(b_ntt, &plan).toRing(&plan);
    const expected = a.add(b).scalarMul(N);
    try std.testing.expect(sum.eq(expected));
}

test "NttDomainFq2 multiplication matches schoolbook extension ring" {
    const root = @import("root.zig");
    const N = 64;
    const Q = 1062862849;
    const Beta = 3;
    const E = root.Fq2(Q, Beta);
    const Re = root.RingWithOps(N, E, E.Ops);
    const Plan = NttMul(N, Q);
    const DomE = NttDomainFq2(N, Q, Beta);
    var plan = try Plan.init();
    defer plan.deinit();

    var a = Re.zero();
    var b = Re.zero();
    for (0..N) |i| {
        a.data[i] = E.init(@intCast(i + 1), @intCast((2 * i + 3) % Q));
        b.data[i] = E.init(@intCast((3 * i + 5) % Q), @intCast((7 * i + 11) % Q));
    }

    const prod_ntt = DomE.init(&plan, a).mul(DomE.init(&plan, b), &plan).toRing(&plan);
    const prod_ref = a.mul(b).scalarMul(E.fromU64(N % Q));
    try std.testing.expect(prod_ntt.eq(prod_ref));
}

pub fn benchmarkNttMultiplication() !void {
    const degrees = [_]usize{ 64, 128, 256, 512, 1024 };

    // We use Q=0 (native) because it works for any power-of-two degree.
    const Q = 0;

    std.debug.print("\nBenchmark (Native64):\n", .{});

    inline for (degrees) |N| {
        const Plan = NttMul(N, Q);

        if (Plan.init()) |plan_val| {
            var plan = plan_val;
            defer plan.deinit();

            const RingT = @import("root.zig").Ring(N, Q);
            var a = RingT.zero();
            var b = RingT.zero();

            // Initialize with some data
            for (0..N) |i| {
                a.data[i] = @intCast(i);
                b.data[i] = @intCast(N - i);
            }

            const iterations = 1000;
            const start_ns = nowNs();

            for (0..iterations) |_| {
                const res = plan.mul(&a.data, &b.data);
                std.mem.doNotOptimizeAway(res);
            }

            const elapsed: u64 = @intCast(nowNs() - start_ns);
            const avg_ns = elapsed / iterations;

            std.debug.print("N={d: <4}: {d} ns/op\n", .{ N, avg_ns });
        } else |err| {
            std.debug.print("N={d}: Plan init failed ({any})\n", .{ N, err });
        }
    }
}
