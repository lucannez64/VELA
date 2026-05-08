const std = @import("std");
const zig_ring_arithmetic = @import("zig_ring_arithmetic");
const builtin = @import("builtin");

comptime {
    _ = @import("msvc_compat");
}

const N = 128;
const Q: u64 = 1125899906839937;
const Protocol = zig_ring_arithmetic.CycloProtocol(N, Q);
const Relation = zig_ring_arithmetic.CycloRelation;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    var public_inputs: [132]u64 = undefined;
    var private_inputs: [128]u64 = undefined;
    for (&public_inputs) |*v| v.* = random.int(u64) % Q;
    for (&private_inputs) |*v| v.* = random.int(u64) & 0xFFFFF;

    const relation = Relation{
        .r1cs = .{
            .q = Q,
            .num_variables = 260,
            .constraints = &.{},
        },
    };

    var params = Protocol.PRESET_128;
    params.security_target_bits = 0.0;

    const statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = &public_inputs,
    };
    const witness = Protocol.Witness{
        .private_assignment = &private_inputs,
    };

    std.debug.print("Starting prove...\n", .{});
    var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
    std.debug.print("Prove done.\n", .{});
    defer proof.deinit(allocator);

    std.debug.print("Starting verify...\n", .{});
    const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
    std.debug.print("Verify done: {}\n", .{ok});
}
