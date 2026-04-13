const std = @import("std");
const zig_ring_arithmetic = @import("zig_ring_arithmetic");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag == .windows and !builtin.is_test) {
        _ = @import("msvc_compat");
    }
}

const N = 128;
const Q: u64 = 1125899906839937;
const NUM_VOTERS = 3;
const D_VOTE_NULLIFIER: u64 = 4242;
const NULLIFIER_CONSTANT: u64 = D_VOTE_NULLIFIER % Q;

const Protocol = zig_ring_arithmetic.CycloProtocol(N, Q);
const Term = zig_ring_arithmetic.CycloLinearTerm;
const Constraint = zig_ring_arithmetic.CycloR1csConstraint;
const Relation = zig_ring_arithmetic.CycloRelation;

const IDX_TALLY = 0;
const IDX_ELECTION_ID = 1;
fn idxCommitment(v: usize) usize {
    return 2 + v;
}
fn idxNullifier(v: usize) usize {
    return 2 + NUM_VOTERS + v;
}
const NUM_PUBLIC = 2 + 2 * NUM_VOTERS;

fn idxBallot(v: usize) usize {
    return NUM_PUBLIC + v;
}
fn idxSerial(v: usize) usize {
    return NUM_PUBLIC + NUM_VOTERS + v;
}
fn idxSecret(v: usize) usize {
    return NUM_PUBLIC + 2 * NUM_VOTERS + v;
}
const NUM_PRIVATE = 3 * NUM_VOTERS;
const NUM_VARIABLES = NUM_PUBLIC + NUM_PRIVATE;
const NUM_CONSTRAINTS = 3 * NUM_VOTERS + 1;
const MICRO_BENCH_ITERS = 20;

fn addMod(a: u64, b: u64) u64 {
    return @intCast((@as(u128, a % Q) + @as(u128, b % Q)) % Q);
}

fn deriveTaggedKey(seed: [32]u8, domain_tag: u64, index: u64) u64 {
    var msg: [48]u8 = undefined;
    @memcpy(msg[0..32], &seed);
    std.mem.writeInt(u64, msg[32..40], domain_tag, .little);
    std.mem.writeInt(u64, msg[40..48], index, .little);
    var digest: [32]u8 = undefined;
    var shake = std.crypto.hash.sha3.Shake256.init(.{});
    shake.update(&msg);
    shake.final(&digest);
    return std.mem.readInt(u64, digest[0..8], .little) % Q;
}

fn deriveCommitmentKey(seed: [32]u8) [4]u64 {
    var key: [4]u64 = undefined;
    for (0..4) |i| key[i] = deriveTaggedKey(seed, 0, @as(u64, i));
    return key;
}

fn deriveNullifierKey(seed: [32]u8) [3]u64 {
    var key: [3]u64 = undefined;
    for (0..3) |i| key[i] = deriveTaggedKey(seed, 1, @as(u64, i));
    return key;
}

fn computeCommitment(key: [4]u64, serial: u64, secret: u64, election_id: u64, voter_slot: u64) u64 {
    var acc: u128 = 0;
    acc += @as(u128, key[0]) * @as(u128, serial % Q);
    acc += @as(u128, key[1]) * @as(u128, secret % Q);
    acc += @as(u128, key[2]) * @as(u128, election_id % Q);
    acc += @as(u128, key[3]) * @as(u128, voter_slot % Q);
    return @intCast(acc % Q);
}

fn computeNullifier(key: [3]u64, serial: u64, secret: u64, election_id: u64) u64 {
    var acc: u128 = NULLIFIER_CONSTANT;
    acc += @as(u128, key[0]) * @as(u128, serial % Q);
    acc += @as(u128, key[1]) * @as(u128, secret % Q);
    acc += @as(u128, key[2]) * @as(u128, election_id % Q);
    return @intCast(acc % Q);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const election_id: u64 = 2026;
    const ballots = [NUM_VOTERS]u64{ 1, 0, 1 };
    const serials = [NUM_VOTERS]u64{ 1001, 1002, 1003 };
    const secrets = [NUM_VOTERS]u64{ 90001, 90002, 90003 };
    const tally: u64 = ballots[0] + ballots[1] + ballots[2];

    const issuer_seed = [_]u8{0xAB} ** 32;
    const commit_key = deriveCommitmentKey(issuer_seed);
    const nul_key = deriveNullifierKey(issuer_seed);

    var commitments: [NUM_VOTERS]u64 = undefined;
    var nullifiers: [NUM_VOTERS]u64 = undefined;
    for (0..NUM_VOTERS) |v| {
        commitments[v] = computeCommitment(commit_key, serials[v], secrets[v], election_id, @intCast(v));
        nullifiers[v] = computeNullifier(nul_key, serials[v], secrets[v], election_id);
    }

    var assignment: [NUM_VARIABLES]u64 = undefined;
    assignment[IDX_TALLY] = tally;
    assignment[IDX_ELECTION_ID] = election_id;
    for (0..NUM_VOTERS) |v| {
        assignment[idxCommitment(v)] = commitments[v];
        assignment[idxNullifier(v)] = nullifiers[v];
        assignment[idxBallot(v)] = ballots[v];
        assignment[idxSerial(v)] = serials[v];
        assignment[idxSecret(v)] = secrets[v];
    }

    var commitment_terms: [NUM_VOTERS][3]Term = undefined;
    var nullifier_terms: [NUM_VOTERS][3]Term = undefined;
    var ballot_sel: [NUM_VOTERS][1]Term = undefined;
    var commitment_out_sel: [NUM_VOTERS][1]Term = undefined;
    var nullifier_out_sel: [NUM_VOTERS][1]Term = undefined;
    var commitment_constants: [NUM_VOTERS]u64 = undefined;
    var tally_terms: [NUM_VOTERS]Term = undefined;
    for (0..NUM_VOTERS) |v| {
        commitment_terms[v][0] = .{ .index = idxSerial(v), .coeff = commit_key[0] };
        commitment_terms[v][1] = .{ .index = idxSecret(v), .coeff = commit_key[1] };
        commitment_terms[v][2] = .{ .index = IDX_ELECTION_ID, .coeff = commit_key[2] };
        commitment_constants[v] = @intCast((@as(u128, commit_key[3]) * @as(u128, @as(u64, @intCast(v)))) % Q);
        nullifier_terms[v][0] = .{ .index = idxSerial(v), .coeff = nul_key[0] };
        nullifier_terms[v][1] = .{ .index = idxSecret(v), .coeff = nul_key[1] };
        nullifier_terms[v][2] = .{ .index = IDX_ELECTION_ID, .coeff = nul_key[2] };
        ballot_sel[v][0] = .{ .index = idxBallot(v), .coeff = 1 };
        commitment_out_sel[v][0] = .{ .index = idxCommitment(v), .coeff = 1 };
        nullifier_out_sel[v][0] = .{ .index = idxNullifier(v), .coeff = 1 };
        tally_terms[v] = .{ .index = idxBallot(v), .coeff = 1 };
    }
    const tally_out_sel = [1]Term{.{ .index = IDX_TALLY, .coeff = 1 }};

    var constraints: [NUM_CONSTRAINTS]Constraint = undefined;
    for (0..NUM_VOTERS) |v| {
        const base = 3 * v;
        constraints[base] = .{
            .a = .{ .terms = &commitment_terms[v], .constant = commitment_constants[v] },
            .b = .{ .terms = &.{}, .constant = 1 },
            .c = .{ .terms = &commitment_out_sel[v] },
        };
        constraints[base + 1] = .{
            .a = .{ .terms = &nullifier_terms[v], .constant = NULLIFIER_CONSTANT },
            .b = .{ .terms = &.{}, .constant = 1 },
            .c = .{ .terms = &nullifier_out_sel[v] },
        };
        constraints[base + 2] = .{
            .a = .{ .terms = &ballot_sel[v] },
            .b = .{ .terms = &ballot_sel[v] },
            .c = .{ .terms = &ballot_sel[v] },
        };
    }
    constraints[NUM_CONSTRAINTS - 1] = .{
        .a = .{ .terms = &tally_terms },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &tally_out_sel },
    };

    const relation = Relation{ .r1cs = .{
        .q = Q,
        .num_variables = NUM_VARIABLES,
        .constraints = &constraints,
    } };

    var params = Protocol.PRESET_128;
    params.security_target_bits = 0.0;

    const statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = assignment[0..NUM_PUBLIC],
    };
    const witness = Protocol.Witness{
        .private_assignment = assignment[NUM_PUBLIC..],
    };

    std.debug.print("\n=== Electronic Vote (compact commitment + nullifier) ===\n", .{});
    std.debug.print("Voters         : {d}\n", .{NUM_VOTERS});
    std.debug.print("Variables      : {d}  ({d} public / {d} private)\n", .{ NUM_VARIABLES, NUM_PUBLIC, NUM_PRIVATE });
    std.debug.print("Constraints    : {d}\n\n", .{NUM_CONSTRAINTS});

    var prove_total_ns: u128 = 0;
    var verify_total_ns: u128 = 0;
    var prove_min_ns: u64 = std.math.maxInt(u64);
    var verify_min_ns: u64 = std.math.maxInt(u64);
    var prove_max_ns: u64 = 0;
    var verify_max_ns: u64 = 0;
    var bench_ok: bool = true;
    for (0..MICRO_BENCH_ITERS) |_| {
        var prove_timer = try std.time.Timer.start();
        var bench_proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
        const prove_ns = prove_timer.read();
        var verify_timer = try std.time.Timer.start();
        const verify_ok = try Protocol.verifyFromStatement(allocator, statement, &bench_proof, params);
        const verify_ns = verify_timer.read();
        bench_proof.deinit(allocator);
        bench_ok = bench_ok and verify_ok;
        prove_total_ns += prove_ns;
        verify_total_ns += verify_ns;
        if (prove_ns < prove_min_ns) prove_min_ns = prove_ns;
        if (verify_ns < verify_min_ns) verify_min_ns = verify_ns;
        if (prove_ns > prove_max_ns) prove_max_ns = prove_ns;
        if (verify_ns > verify_max_ns) verify_max_ns = verify_ns;
    }
    const bench_den = @as(f64, @floatFromInt(MICRO_BENCH_ITERS));
    const prove_avg_ms = @as(f64, @floatFromInt(prove_total_ns)) / bench_den / 1_000_000.0;
    const verify_avg_ms = @as(f64, @floatFromInt(verify_total_ns)) / bench_den / 1_000_000.0;
    const prove_min_ms = @as(f64, @floatFromInt(prove_min_ns)) / 1_000_000.0;
    const verify_min_ms = @as(f64, @floatFromInt(verify_min_ns)) / 1_000_000.0;
    const prove_max_ms = @as(f64, @floatFromInt(prove_max_ns)) / 1_000_000.0;
    const verify_max_ms = @as(f64, @floatFromInt(verify_max_ns)) / 1_000_000.0;
    std.debug.print("Micro-bench runs: {d}\n", .{MICRO_BENCH_ITERS});
    std.debug.print("Prove  ms       : avg={d:.3} min={d:.3} max={d:.3}\n", .{ prove_avg_ms, prove_min_ms, prove_max_ms });
    std.debug.print("Verify ms       : avg={d:.3} min={d:.3} max={d:.3}\n", .{ verify_avg_ms, verify_min_ms, verify_max_ms });
    std.debug.print("Bench verify all: {}\n\n", .{bench_ok});

    std.debug.print("Generating ZK proof...\n", .{});
    var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
    defer proof.deinit(allocator);
    std.debug.print("Proof generated.\n\n", .{});

    const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
    std.debug.print("Verify (correct)                    : {}\n", .{ok});

    var pub_bad_tally = assignment[0..NUM_PUBLIC].*;
    pub_bad_tally[IDX_TALLY] = addMod(tally, 1);
    const bad_tally_ok = try Protocol.verifyFromStatement(
        allocator,
        Protocol.Statement{ .relation = relation, .public_assignment = &pub_bad_tally },
        &proof,
        params,
    );
    std.debug.print("Verify (tampered tally +1)          : {}\n", .{bad_tally_ok});

    var pub_bad_nul = assignment[0..NUM_PUBLIC].*;
    pub_bad_nul[idxNullifier(0)] = addMod(nullifiers[0], 1);
    const bad_nul_ok = try Protocol.verifyFromStatement(
        allocator,
        Protocol.Statement{ .relation = relation, .public_assignment = &pub_bad_nul },
        &proof,
        params,
    );
    std.debug.print("Verify (tampered nullifier)         : {}\n", .{bad_nul_ok});

    const nul_repeat = computeNullifier(nul_key, serials[0], secrets[0], election_id);
    std.debug.print("Double-vote caught (same key→same nul): {}\n", .{nul_repeat == nullifiers[0]});

    var forged = assignment;
    forged[idxSerial(0)] = addMod(serials[0], 1);
    const forge_result = Protocol.proveFromStatement(
        allocator,
        statement,
        Protocol.Witness{ .private_assignment = forged[NUM_PUBLIC..] },
        params,
    );
    if (forge_result) |fp| {
        var leaked = fp;
        defer leaked.deinit(allocator);
        std.debug.print("Forged voter credential accepted    : true  (unexpected!)\n", .{});
    } else |_| {
        std.debug.print("Forged voter credential rejected    : true\n", .{});
    }
}
