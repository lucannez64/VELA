//! VELA Cyclo authentication benchmark.
//!
//! Benchmarks the exact prove/verify flow used by the desktop app and server
//! with VELA parameters: N=128, Q=1125899906839937, 132 public inputs, 128 private inputs.

const std = @import("std");
const zig_ring_arithmetic = @import("zig_ring_arithmetic");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag == .windows) {
        _ = @import("msvc_compat");
    }
}

const N = 128;
const Q: u64 = 1125899906839937;
const CYCLO_PK_LEN: usize = 128;
const TOTAL_PUBLIC: usize = 132; // 128 pk + 4 hash u64s
const TOTAL_PRIVATE: usize = 128; // cyclo_sk

const Protocol = zig_ring_arithmetic.CycloProtocol(N, Q);
const Term = zig_ring_arithmetic.CycloLinearTerm;
const Constraint = zig_ring_arithmetic.CycloR1csConstraint;
const Relation = zig_ring_arithmetic.CycloRelation;

const BENCH_ITERS = 5;
const WARMUP_ITERS = 2;

fn nowNs() i96 {
    var threaded: std.Io.Threaded = .init_single_threaded;
    return std.Io.Clock.awake.now(threaded.io()).nanoseconds;
}

/// Simulates the VELA auth flow public/private inputs.
/// cyclo_pk: 128 random u64 values in [0, Q)
/// committed_hash: 4 u64 values from SHA256(challenge || device_id)
/// cyclo_sk: 128 u64 values in [0, 2^20)
fn generateAuthAssignment(seed: u64) struct {
    public_inputs: [TOTAL_PUBLIC]u64,
    private_inputs: [TOTAL_PRIVATE]u64,
} {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var public_inputs: [TOTAL_PUBLIC]u64 = undefined;
    var private_inputs: [TOTAL_PRIVATE]u64 = undefined;

    // cyclo_pk: 128 random u64 values mod Q
    for (0..CYCLO_PK_LEN) |i| {
        public_inputs[i] = random.int(u64) % Q;
    }

    // committed_hash: 4 u64 values (SHA256 digest as 4×u64 LE)
    for (0..4) |i| {
        public_inputs[CYCLO_PK_LEN + i] = random.int(u64);
    }

    // cyclo_sk: 128 values in [0, B_SIS) = [0, 2^20)
    for (0..TOTAL_PRIVATE) |i| {
        private_inputs[i] = random.int(u64) & 0xFFFFF;
    }

    return .{ .public_inputs = public_inputs, .private_inputs = private_inputs };
}

fn buildAuthRelation() Relation {
    // The VELA auth relation has 132 public + 128 private = 260 total variables.
    // The only "constraint" is the empty constraint set (the cyclo protocol
    // handles the lattice relation internally — the R1CS here forms the
    // short-witness lattice commitment as an implicit relation).
    return Relation{
        .r1cs = .{
            .q = Q,
            .num_variables = TOTAL_PUBLIC + TOTAL_PRIVATE,
            .constraints = &.{},
        },
    };
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed: u64 = 0xCAFE_BABE_DEAD_BEEF;
    const assignment = generateAuthAssignment(seed);
    const relation = buildAuthRelation();

    var params = Protocol.PRESET_128;
    params.security_target_bits = 0.0; // standalone (non-IVC)

    // Sanity check protocol instantiation
    const ring_els = params.rank_a_prime;
    const ext_ell: usize = blk: {
        const b_sis: u64 = 1 << 20;
        const bound = @max(params.b, b_sis);
        const b_u32: u32 = @intCast(bound);
        const bits: usize = 64 - @as(usize, @clz(b_u32));
        break :blk (bits + params.b - 1) / params.b;
    };

    std.debug.print("\n=== VELA Cyclo Auth Benchmark ===\n", .{});
    std.debug.print("N           : {d}\n", .{N});
    std.debug.print("Q           : {d}\n", .{Q});
    std.debug.print("Public ins  : {d}\n", .{TOTAL_PUBLIC});
    std.debug.print("Private ins : {d}\n", .{TOTAL_PRIVATE});
    std.debug.print("rank_a      : {d}\n", .{params.rank_a});
    std.debug.print("rank_a_prime: {d}\n", .{ring_els});
    std.debug.print("B_sis       : {d}\n", .{params.B_sis});
    std.debug.print("extension_ell: {d}\n", .{ext_ell});
    std.debug.print("Iterations  : {d}\n\n", .{BENCH_ITERS});

    const statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = &assignment.public_inputs,
    };
    const witness = Protocol.Witness{
        .private_assignment = &assignment.private_inputs,
    };

    // ── Warmup ────────────────────────────────────────────────────────────
    std.debug.print("Warming up ({d} iterations)...\n", .{WARMUP_ITERS});
    for (0..WARMUP_ITERS) |_| {
        var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
        const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
        proof.deinit(allocator);
        if (!ok) {
            std.debug.print("WARMUP VERIFY FAILED!\n", .{});
            return error.TestFailed;
        }
    }
    std.debug.print("Warmup complete.\n\n", .{});

    // ── Benchmark ─────────────────────────────────────────────────────────
    var prove_times: [BENCH_ITERS]u64 = undefined;
    var verify_times: [BENCH_ITERS]u64 = undefined;
    var proof_sizes: [BENCH_ITERS]usize = undefined;

    for (0..BENCH_ITERS) |iter| {
        // Prove
        const prove_start = nowNs();
        var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
        const prove_ns: u64 = @intCast(nowNs() - prove_start);
        prove_times[iter] = prove_ns;

        // Measure proof size
        var size_buf: [512 * 1024]u8 = [_]u8{0} ** (512 * 1024);
        const ser_len = proof.serializeInto(size_buf[0..]) catch |err| {
            std.debug.print("Serialization failed on iter {d}: {s}\n", .{iter, @errorName(err)});
            return error.TestFailed;
        };
        proof_sizes[iter] = ser_len;

        // Verify
        const verify_start = nowNs();
        const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
        const verify_ns: u64 = @intCast(nowNs() - verify_start);
        verify_times[iter] = verify_ns;

        proof.deinit(allocator);

        if (!ok) {
            std.debug.print("VERIFY FAILED on iter {d}!\n", .{iter});
            return error.TestFailed;
        }
    }

    // ── Statistics ─────────────────────────────────────────────────────────
    var prove_min: u64 = std.math.maxInt(u64);
    var prove_max: u64 = 0;
    var prove_sum: u128 = 0;
    var verify_min: u64 = std.math.maxInt(u64);
    var verify_max: u64 = 0;
    var verify_sum: u128 = 0;
    var size_min: usize = std.math.maxInt(usize);
    var size_max: usize = 0;
    var size_sum: usize = 0;

    for (0..BENCH_ITERS) |i| {
        if (prove_times[i] < prove_min) prove_min = prove_times[i];
        if (prove_times[i] > prove_max) prove_max = prove_times[i];
        prove_sum += prove_times[i];

        if (verify_times[i] < verify_min) verify_min = verify_times[i];
        if (verify_times[i] > verify_max) verify_max = verify_times[i];
        verify_sum += verify_times[i];

        if (proof_sizes[i] < size_min) size_min = proof_sizes[i];
        if (proof_sizes[i] > size_max) size_max = proof_sizes[i];
        size_sum += proof_sizes[i];
    }

    const count = @as(f64, @floatFromInt(BENCH_ITERS));
    const prove_avg_ms = @as(f64, @floatFromInt(prove_sum)) / count / 1_000_000.0;
    const prove_min_ms = @as(f64, @floatFromInt(prove_min)) / 1_000_000.0;
    const prove_max_ms = @as(f64, @floatFromInt(prove_max)) / 1_000_000.0;
    const verify_avg_ms = @as(f64, @floatFromInt(verify_sum)) / count / 1_000_000.0;
    const verify_min_ms = @as(f64, @floatFromInt(verify_min)) / 1_000_000.0;
    const verify_max_ms = @as(f64, @floatFromInt(verify_max)) / 1_000_000.0;
    const size_avg = @as(f64, @floatFromInt(size_sum)) / count;

    std.debug.print("=== Results ===\n", .{});
    std.debug.print("Proof size      : min={d} B  max={d} B  avg={d:.0} B\n", .{ size_min, size_max, size_avg });
    std.debug.print("Proof size      : {d:.1} KB (base64: {d:.1} KB)\n", .{ size_avg / 1024.0, size_avg * 4.0 / 3.0 / 1024.0 });
    std.debug.print("\n", .{});
    std.debug.print("Prove time      : avg={d:.1} ms  min={d:.1} ms  max={d:.1} ms\n", .{ prove_avg_ms, prove_min_ms, prove_max_ms });
    std.debug.print("Verify time     : avg={d:.1} ms  min={d:.1} ms  max={d:.1} ms\n", .{ verify_avg_ms, verify_min_ms, verify_max_ms });
    std.debug.print("\n", .{});
    std.debug.print("Est. auth latency : {d:.1} ms (prove) + network RTT + {d:.1} ms (server verify)\n", .{ prove_avg_ms, verify_avg_ms });
    std.debug.print("Est. throughput   : {d:.1} authentications/second (prove side)\n", .{ 1000.0 / prove_avg_ms });
    std.debug.print("Est. server TPS   : {d:.1} verifications/second\n", .{ 1000.0 / verify_avg_ms });
}
