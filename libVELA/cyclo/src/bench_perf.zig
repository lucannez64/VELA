const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag == .windows) {
        _ = @import("msvc_compat");
    }
}

const N = 16;
const Q: u64 = 97;

fn nowNs() i96 {
    var threaded: std.Io.Threaded = .init_single_threaded;
    return std.Io.Clock.awake.now(threaded.io()).nanoseconds;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const Term = @import("zig_ring_arithmetic").CycloLinearTerm;
    const Constraint = @import("zig_ring_arithmetic").CycloR1csConstraint;
    const Relation = @import("zig_ring_arithmetic").CycloRelation;
    const Protocol = @import("zig_ring_arithmetic").CycloProtocol(N, Q);

    const x_term = [_]Term{.{ .index = 0, .coeff = 1 }};
    const y_term = [_]Term{.{ .index = 1, .coeff = 1 }};
    const constraint = Constraint{
        .a = .{ .terms = &x_term, .constant = 0 },
        .b = .{ .terms = &y_term, .constant = 0 },
        .c = .{ .terms = &.{}, .constant = 12 },
    };
    const relation = Relation{
        .r1cs = .{
            .q = Q,
            .num_variables = 2,
            .constraints = &.{constraint},
        },
    };
    const assignment = [_]u64{ 3, 4 };

    const params = Protocol.Params{
        .b = 2,
        .gamma = 1,
        .B_sis = 256,
        .rank_a = 4,
        .rank_a_prime = 4,
        .challenge_set_size_c = 1 << 20,
        .challenge_set_size_d = 1 << 16,
        .use_extension_commitment = false,
        .enable_zk_blinding = true,
        .theta_base_k = 2,
        .security_target_bits = 0.0,
    };

    const statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = &assignment,
    };
    const witness = Protocol.Witness{
        .private_assignment = &[_]u64{},
    };

    const WARMUP = 1;
    const ITERS = 5;

    for (0..WARMUP) |_| {
        var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
        _ = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
        proof.deinit(allocator);
    }

    var prove_total: u128 = 0;
    var verify_total: u128 = 0;

    std.debug.print("N={d} Q={d} rank_a={d}\n", .{ N, Q, params.rank_a });

    for (0..ITERS) |_| {
        const p_start = nowNs();
        var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
        const p_elapsed: u64 = @intCast(nowNs() - p_start);

        const v_start = nowNs();
        _ = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
        const v_elapsed: u64 = @intCast(nowNs() - v_start);

        prove_total += p_elapsed;
        verify_total += v_elapsed;
        proof.deinit(allocator);
    }

    const prove_avg_us = @as(f64, @floatFromInt(prove_total)) / @as(f64, @floatFromInt(ITERS)) / 1000.0;
    const verify_avg_us = @as(f64, @floatFromInt(verify_total)) / @as(f64, @floatFromInt(ITERS)) / 1000.0;

    std.debug.print("Prove avg:  {d:.1} us\n", .{prove_avg_us});
    std.debug.print("Verify avg: {d:.1} us\n", .{verify_avg_us});
    std.debug.print("Verify TPS: {d:.1} (theoretical)\n", .{1_000_000.0 / verify_avg_us});
}
