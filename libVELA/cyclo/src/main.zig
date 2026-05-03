const std = @import("std");
const zig_ring_arithmetic = @import("zig_ring_arithmetic");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag == .windows and !builtin.is_test) {
        _ = @import("msvc_compat");
    }
}

pub fn main() !void {
    const N = 128;
    const Q: u64 = 1125899906839937;
    const Protocol = zig_ring_arithmetic.CycloProtocol(N, Q);
    const Term = zig_ring_arithmetic.CycloLinearTerm;
    const Constraint = zig_ring_arithmetic.CycloR1csConstraint;
    const Relation = zig_ring_arithmetic.CycloRelation;

    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const idx_x: usize = 0;
    const idx_z: usize = 1;
    const idx_a: usize = 2;
    const idx_b: usize = 3;
    const idx_y: usize = 4;

    const assignment = [_]u64{
        3,
        4,
        7,
        49,
        54,
    };

    const terms_x_plus_z = [_]Term{
        .{ .index = idx_x, .coeff = 1 },
        .{ .index = idx_z, .coeff = 1 },
    };
    const terms_a = [_]Term{
        .{ .index = idx_a, .coeff = 1 },
    };
    const terms_b = [_]Term{
        .{ .index = idx_b, .coeff = 1 },
    };
    const terms_b_plus_z = [_]Term{
        .{ .index = idx_b, .coeff = 1 },
        .{ .index = idx_z, .coeff = 1 },
    };
    const terms_y = [_]Term{
        .{ .index = idx_y, .coeff = 1 },
    };

    const constraints = [_]Constraint{
        .{
            .a = .{ .terms = &terms_x_plus_z, .constant = 0 },
            .b = .{ .terms = &[_]Term{}, .constant = 1 },
            .c = .{ .terms = &terms_a, .constant = 0 },
        },
        .{
            .a = .{ .terms = &terms_a, .constant = 0 },
            .b = .{ .terms = &terms_a, .constant = 0 },
            .c = .{ .terms = &terms_b, .constant = 0 },
        },
        .{
            .a = .{ .terms = &terms_b_plus_z, .constant = 1 },
            .b = .{ .terms = &[_]Term{}, .constant = 1 },
            .c = .{ .terms = &terms_y, .constant = 0 },
        },
    };

    const relation = Relation{
        .r1cs = .{
            .q = Q,
            .num_variables = assignment.len,
            .constraints = &constraints,
        },
    };

    const base_params = Protocol.PRESET_128;
    var params = Protocol.Params.autoParams(relation.r1cs.num_variables, 128.0, base_params);
    params.security_target_bits = 0.0;

    const statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = assignment[0..2],
    };
    const witness = Protocol.Witness{
        .private_assignment = assignment[2..],
    };

    var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
    defer proof.deinit(allocator);
    const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);

    std.debug.print("statement: y = (x+z)^2 + z + 1\n", .{});
    std.debug.print("witness: x={d} z={d} y={d}\n", .{ assignment[idx_x], assignment[idx_z], assignment[idx_y] });
    std.debug.print("verify={any}\n", .{ok});
    const tampered_public = [_]u64{
        assignment[idx_x] + 1,
        assignment[idx_z],
    };
    const tampered_statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = &tampered_public,
    };
    const tampered_ok = try Protocol.verifyFromStatement(allocator, tampered_statement, &proof, params);
    std.debug.print("verify_with_tampered_public={any}\n", .{tampered_ok});

    const bad_assignment = [_]u64{
        3,
        4,
        7,
        49,
        55,
    };
    const bad_statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = bad_assignment[0..2],
    };
    const bad_witness = Protocol.Witness{
        .private_assignment = bad_assignment[2..],
    };
    const bad_result = Protocol.proveFromStatement(allocator, bad_statement, bad_witness, params);
    if (bad_result) |bad_proof| {
        var leaked_proof = bad_proof;
        defer leaked_proof.deinit(allocator);
        std.debug.print("bad-witness path: unexpectedly produced a proof\n", .{});
    } else |err| {
        std.debug.print("bad-witness path: prove failed as expected with error={s}\n", .{@errorName(err)});
    }

    const ExtN = 128;
    const ExtQ: u64 = 1125899906856961;
    const ExtRows = base_params.rank_a_prime;
    const ExtWitnessLen = 2;
    const ExtB = base_params.b;
    const ExtEll = 11;
    const ExtRing = zig_ring_arithmetic.Ring(ExtN, ExtQ);
    const ExtDom = zig_ring_arithmetic.cyclo_ring_ntt.NttDomain(ExtN, ExtQ);
    const ExtPlan = zig_ring_arithmetic.cyclo_ring_ntt.NttMul(ExtN, ExtQ);
    const ExtCommit = zig_ring_arithmetic.ExtensionCommitment(ExtN, ExtQ, ExtRows, ExtWitnessLen, ExtB, ExtEll);
    var ext_plan = try ExtPlan.init();
    defer ext_plan.deinit();
    const ext_one = ExtRing.one();
    const ext_witness = [_]ExtRing{
        ext_one.scalarMul(733),
        ext_one.scalarMul(-511),
    };
    var ext_matrix_ring: [ExtRows][ExtWitnessLen * ExtEll]ExtRing = undefined;
    var ext_matrix_ntt: [ExtRows * ExtWitnessLen * ExtEll]ExtDom = undefined;
    for (0..ExtRows) |r| {
        for (0..ExtWitnessLen * ExtEll) |c| {
            const scalar: i128 = @as(i128, @intCast((r + 1) * (c + 3)));
            const entry = ext_one.scalarMul(scalar);
            ext_matrix_ring[r][c] = entry;
            ext_matrix_ntt[r * (ExtWitnessLen * ExtEll) + c] = ExtDom.init(&ext_plan, entry);
        }
    }
    const ext_result = try ExtCommit.commit(ext_witness, &ext_matrix_ntt, &ext_plan, allocator);
    const ext_bound_ok = ExtCommit.verifyBound(ext_result.v);
    var ext_expected: [ExtRows]ExtRing = undefined;
    for (0..ExtRows) |r| {
        ext_expected[r] = ExtRing.zero();
    }
    for (0..ExtRows) |r| {
        for (0..ExtWitnessLen * ExtEll) |c| {
            ext_expected[r] = ext_expected[r].add(ext_matrix_ring[r][c].mul(ext_result.v[c]));
        }
    }
    var ext_commit_ok = true;
    for (0..ExtRows) |r| {
        if (!ext_result.t[r].eq(ext_expected[r])) {
            ext_commit_ok = false;
            break;
        }
    }
    std.debug.print("extension_commitment_prod_demo_rows={d} b={d} ell={d} bound_ok={any} commit_ok={any}\n", .{ ExtRows, ExtB, ExtEll, ext_bound_ok, ext_commit_ok });
}
