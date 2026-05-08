//! Minimal single-shot prove/verify test for VELA auth - debugging crash.
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
const Protocol = zig_ring_arithmetic.CycloProtocol(N, Q);
const Term = zig_ring_arithmetic.CycloLinearTerm;
const Constraint = zig_ring_arithmetic.CycloR1csConstraint;
const Relation = zig_ring_arithmetic.CycloRelation;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const relation = Relation{
        .r1cs = .{
            .q = Q,
            .num_variables = 260,
            .constraints = &.{},
        },
    };

    var assignment: [260]u64 = undefined;
    var prng = std.Random.DefaultPrng.init(0xBEEF);
    const random = prng.random();
    for (&assignment) |*v| v.* = random.int(u64) % Q;
    for (assignment[132..]) |*v| v.* = v.* & 0xFFFFF;

    var params = Protocol.PRESET_128;
    params.security_target_bits = 0.0;

    const statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = assignment[0..132],
    };
    const witness = Protocol.Witness{
        .private_assignment = assignment[132..],
    };

    var proof = Protocol.proveFromStatement(allocator, statement, witness, params) catch |err| {
        std.debug.print("prove failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer proof.deinit(allocator);

    const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
    std.debug.print("verify={}\n", .{ok});
}
