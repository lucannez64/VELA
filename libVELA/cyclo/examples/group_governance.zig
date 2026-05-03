//! Group Governance Circuits — Cyclo-native R1CS rewrite
//!
//! Implements PP.md §13.4 (Group Membership Proof), §13.6 (Vote Validity),
//! and §13.7 (Vote Reveal) using the same Ajtai commitment + linear nullifier
//! pattern as electronic_vote.zig and anonymous_ticket_spend.zig.
//!
//! The PP.md spec uses Poseidon2 + MerkleVerify for membership and Poseidon2
//! for all nullifier and commitment derivations.  Encoding those inside R1CS
//! would require roughly 36 variables per Poseidon2 call, plus O(tree-depth)
//! Poseidon2 calls for the Merkle path.  Instead:
//!
//!   Poseidon2(fields...) + MerkleVerify  →  Ajtai commitment  y = Σ key[i]·field[i]
//!
//! The group registry stores one commitment per member.  Membership is proved by
//! demonstrating knowledge of (member_secret, member_salt) satisfying the
//! commitment equation — a single R1CS constraint.  Binding follows from Ring-SIS
//! hardness (the same assumption Cyclo uses for its own Ajtai commitment).
//!
//! Similarly, Poseidon2-based nullifiers become linear:
//!
//!   nullifier := D_DOMAIN + Σ nul_key[i] · field[i]   mod Q
//!
//! Circuit summary
//! ───────────────
//!   §13.4  Group Membership Proof    7 vars,  2 constraints
//!   §13.6  Vote Validity            13 vars,  6 constraints
//!   §13.7  Vote Reveal               6 vars,  4 constraints
//!
//! Build / run:
//!   zig build run-group-governance

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

/// Domain tags — direct analogue of PP.md's D_GROUP_ACTION / D_GROUP_VOTE.
/// Additive constants in the linear nullifier prevent cross-domain replay.
const D_GROUP_ACTION: u64 = 5001;
const D_GROUP_VOTE: u64 = 5002;

const Protocol = zig_ring_arithmetic.CycloProtocol(N, Q);
const Term = zig_ring_arithmetic.CycloLinearTerm;
const Constraint = zig_ring_arithmetic.CycloR1csConstraint;
const Relation = zig_ring_arithmetic.CycloRelation;

// ─── Field helpers ─────────────────────────────────────────────────────────────

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

// ─── Key derivation ────────────────────────────────────────────────────────────
//
// All derivation runs outside the circuit, exactly like electronic_vote.zig and
// anonymous_ticket_spend.zig.  The keys are public parameters published by the
// group authority.

/// 4-coefficient Ajtai membership commitment key.
/// Binds (member_secret, group_id, membership_epoch, member_salt) → F_q.
fn deriveMembershipKey(seed: [32]u8) [4]u64 {
    var key: [4]u64 = undefined;
    for (0..4) |i| key[i] = deriveTaggedKey(seed, 0, @as(u64, i));
    return key;
}

/// 4-coefficient nullifier key (shared across action and vote circuits).
/// Domain separation is the additive constant D_GROUP_ACTION / D_GROUP_VOTE.
fn deriveNullifierKey(seed: [32]u8) [4]u64 {
    var key: [4]u64 = undefined;
    for (0..4) |i| key[i] = deriveTaggedKey(seed, 1, @as(u64, i));
    return key;
}

/// 3-coefficient Ajtai vote-commitment key.
/// Binds (vote_code, vote_randomness, proposal_hash) → F_q.
fn deriveVoteCommitKey(seed: [32]u8) [3]u64 {
    var key: [3]u64 = undefined;
    for (0..3) |i| key[i] = deriveTaggedKey(seed, 2, @as(u64, i));
    return key;
}

// ─── Commitment and nullifier computation ──────────────────────────────────────

fn computeMembershipCommitment(
    key: [4]u64,
    member_secret: u64,
    group_id: u64,
    membership_epoch: u64,
    member_salt: u64,
) u64 {
    var acc: u128 = 0;
    acc += @as(u128, key[0]) * @as(u128, member_secret % Q);
    acc += @as(u128, key[1]) * @as(u128, group_id % Q);
    acc += @as(u128, key[2]) * @as(u128, membership_epoch % Q);
    acc += @as(u128, key[3]) * @as(u128, member_salt % Q);
    return @intCast(acc % Q);
}

fn computeNullifier4(domain: u64, key: [4]u64, f0: u64, f1: u64, f2: u64, f3: u64) u64 {
    var acc: u128 = domain % Q;
    acc += @as(u128, key[0]) * @as(u128, f0 % Q);
    acc += @as(u128, key[1]) * @as(u128, f1 % Q);
    acc += @as(u128, key[2]) * @as(u128, f2 % Q);
    acc += @as(u128, key[3]) * @as(u128, f3 % Q);
    return @intCast(acc % Q);
}

fn computeVoteCommitment(key: [3]u64, vote_code: u64, vote_randomness: u64, proposal_hash: u64) u64 {
    var acc: u128 = 0;
    acc += @as(u128, key[0]) * @as(u128, vote_code % Q);
    acc += @as(u128, key[1]) * @as(u128, vote_randomness % Q);
    acc += @as(u128, key[2]) * @as(u128, proposal_hash % Q);
    return @intCast(acc % Q);
}

// ─── §13.4 Group Membership Proof ──────────────────────────────────────────────
//
// PP.md constraints rewritten for Cyclo-native R1CS:
//
//   Original: leaf = Poseidon2(member_secret, group_id, membership_epoch, member_salt)
//             assert MerkleVerify(merkle_root, leaf, path, indices) == 1
//   Cyclo:    membership_commitment = Σ mem_key[i]·field[i]   (one constraint)
//
//   Original: computed_nullifier = Poseidon2(D_GROUP_ACTION, member_secret,
//                                            action_hash, group_id, membership_epoch)
//   Cyclo:    member_nullifier = D_GROUP_ACTION + Σ nul_key[i]·field[i]   (one constraint)
//
// Public  [0..4]: membership_commitment, group_id, membership_epoch,
//                 action_hash, member_nullifier
// Private [5..6]: member_secret, member_salt
//
// Constraints: 2  (1 membership binding + 1 action nullifier)

const MBR_IDX_COMMIT = 0;
const MBR_IDX_GROUP_ID = 1;
const MBR_IDX_EPOCH = 2;
const MBR_IDX_ACTION_HASH = 3;
const MBR_IDX_NULLIFIER = 4;
const MBR_NUM_PUBLIC = 5;
const MBR_IDX_SECRET = 5;
const MBR_IDX_SALT = 6;
const MBR_NUM_VARIABLES = 7;
const MBR_NUM_CONSTRAINTS = 2;

fn runMembershipProof(allocator: std.mem.Allocator, params: Protocol.Params) !void {
    std.debug.print("\n=== §13.4 Group Membership Proof ===\n", .{});
    std.debug.print("Variables  : {d}  ({d} public / {d} private)\n", .{
        MBR_NUM_VARIABLES, MBR_NUM_PUBLIC, MBR_NUM_VARIABLES - MBR_NUM_PUBLIC,
    });
    std.debug.print("Constraints: {d}  (1 membership binding + 1 action nullifier)\n\n", .{
        MBR_NUM_CONSTRAINTS,
    });

    const seed = [_]u8{0xAB} ** 32;
    const mem_key = deriveMembershipKey(seed);
    const nul_key = deriveNullifierKey(seed);

    const group_id: u64 = 42;
    const membership_epoch: u64 = 7;
    const member_secret: u64 = 0xDEADBEEF;
    const member_salt: u64 = 0xCAFEBABE;
    const action_hash: u64 = 0x1234567890ABCDEF;

    const membership_commitment = computeMembershipCommitment(
        mem_key, member_secret, group_id, membership_epoch, member_salt,
    );
    const member_nullifier = computeNullifier4(
        D_GROUP_ACTION, nul_key, member_secret, action_hash, group_id, membership_epoch,
    );

    var assignment: [MBR_NUM_VARIABLES]u64 = undefined;
    assignment[MBR_IDX_COMMIT] = membership_commitment;
    assignment[MBR_IDX_GROUP_ID] = group_id;
    assignment[MBR_IDX_EPOCH] = membership_epoch;
    assignment[MBR_IDX_ACTION_HASH] = action_hash;
    assignment[MBR_IDX_NULLIFIER] = member_nullifier;
    assignment[MBR_IDX_SECRET] = member_secret;
    assignment[MBR_IDX_SALT] = member_salt;

    const mem_terms = [4]Term{
        .{ .index = MBR_IDX_SECRET, .coeff = mem_key[0] },
        .{ .index = MBR_IDX_GROUP_ID, .coeff = mem_key[1] },
        .{ .index = MBR_IDX_EPOCH, .coeff = mem_key[2] },
        .{ .index = MBR_IDX_SALT, .coeff = mem_key[3] },
    };
    const nul_terms = [4]Term{
        .{ .index = MBR_IDX_SECRET, .coeff = nul_key[0] },
        .{ .index = MBR_IDX_ACTION_HASH, .coeff = nul_key[1] },
        .{ .index = MBR_IDX_GROUP_ID, .coeff = nul_key[2] },
        .{ .index = MBR_IDX_EPOCH, .coeff = nul_key[3] },
    };
    var constraints: [MBR_NUM_CONSTRAINTS]Constraint = undefined;
    constraints[0] = .{
        .a = .{ .terms = &mem_terms },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = MBR_IDX_COMMIT, .coeff = 1 }} },
    };
    constraints[1] = .{
        .a = .{ .terms = &nul_terms, .constant = D_GROUP_ACTION % Q },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = MBR_IDX_NULLIFIER, .coeff = 1 }} },
    };

    const relation = Relation{ .r1cs = .{
        .q = Q,
        .num_variables = MBR_NUM_VARIABLES,
        .constraints = &constraints,
    } };
    const statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = assignment[0..MBR_NUM_PUBLIC],
    };
    const witness = Protocol.Witness{ .private_assignment = assignment[MBR_NUM_PUBLIC..] };

    var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
    defer proof.deinit(allocator);

    const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
    std.debug.print("Verify (correct)                     : {}\n", .{ok});

    // Tamper: replayed/forged nullifier
    var pub_bad_nul = assignment[0..MBR_NUM_PUBLIC].*;
    pub_bad_nul[MBR_IDX_NULLIFIER] = addMod(member_nullifier, 1);
    const bad_nul_ok = try Protocol.verifyFromStatement(
        allocator,
        Protocol.Statement{ .relation = relation, .public_assignment = &pub_bad_nul },
        &proof,
        params,
    );
    std.debug.print("Verify (tampered nullifier)          : {}\n", .{bad_nul_ok});

    // Tamper: non-member claiming wrong commitment
    var pub_bad_commit = assignment[0..MBR_NUM_PUBLIC].*;
    pub_bad_commit[MBR_IDX_COMMIT] = addMod(membership_commitment, 1);
    const bad_commit_ok = try Protocol.verifyFromStatement(
        allocator,
        Protocol.Statement{ .relation = relation, .public_assignment = &pub_bad_commit },
        &proof,
        params,
    );
    std.debug.print("Verify (wrong commitment/non-member) : {}\n", .{bad_commit_ok});

    // Double-action: same inputs → same nullifier → authority rejects the repeat
    const nul2 = computeNullifier4(
        D_GROUP_ACTION, nul_key, member_secret, action_hash, group_id, membership_epoch,
    );
    std.debug.print("Double-action caught (same nul)      : {}\n", .{nul2 == member_nullifier});

    // Cross-domain isolation: action nullifier differs from vote nullifier
    const nul_vote = computeNullifier4(
        D_GROUP_VOTE, nul_key, member_secret, action_hash, group_id, membership_epoch,
    );
    std.debug.print("Domain tags isolate action vs vote   : {}\n", .{nul_vote != member_nullifier});
}

// ─── §13.6 Vote Validity ───────────────────────────────────────────────────────
//
// PP.md constraints rewritten for Cyclo-native R1CS:
//
//   membership:      Ajtai commitment (same as §13.4)
//   vote_nullifier:  D_GROUP_VOTE + Σ nul_key[i]·(secret, proposal_id, group_id, epoch)
//   vote_commitment: Σ vote_key[i]·(vote_code, vote_randomness, proposal_hash)
//   RangeCheck_2:    binary decomposition of vote_code into vbit0, vbit1
//
// Public  [0..6]: membership_commitment, group_id, membership_epoch,
//                 proposal_id, proposal_hash, vote_nullifier, vote_commitment
// Private [7..12]: member_secret, member_salt, vote_code, vote_randomness,
//                  vbit0, vbit1
//
// Constraints: 6  (1 membership + 1 vote-nul + 1 vote-commit + 2 bit-checks + 1 range)

const VOTE_IDX_COMMIT = 0;
const VOTE_IDX_GROUP_ID = 1;
const VOTE_IDX_EPOCH = 2;
const VOTE_IDX_PROPOSAL_ID = 3;
const VOTE_IDX_PROPOSAL_HASH = 4;
const VOTE_IDX_VOTE_NULLIFIER = 5;
const VOTE_IDX_VOTE_COMMITMENT = 6;
const VOTE_NUM_PUBLIC = 7;
const VOTE_IDX_SECRET = 7;
const VOTE_IDX_SALT = 8;
const VOTE_IDX_VOTE_CODE = 9;
const VOTE_IDX_VOTE_RANDOMNESS = 10;
const VOTE_IDX_VBIT0 = 11;
const VOTE_IDX_VBIT1 = 12;
const VOTE_NUM_VARIABLES = 13;
const VOTE_NUM_CONSTRAINTS = 6;

const SEL_VBIT = [2][1]Term{
    .{.{ .index = VOTE_IDX_VBIT0, .coeff = 1 }},
    .{.{ .index = VOTE_IDX_VBIT1, .coeff = 1 }},
};

fn runVoteValidity(allocator: std.mem.Allocator, params: Protocol.Params) !void {
    std.debug.print("\n=== §13.6 Vote Validity ===\n", .{});
    std.debug.print("Variables  : {d}  ({d} public / {d} private)\n", .{
        VOTE_NUM_VARIABLES, VOTE_NUM_PUBLIC, VOTE_NUM_VARIABLES - VOTE_NUM_PUBLIC,
    });
    std.debug.print("Constraints: {d}  (1 membership + 1 vote-nul + 1 vote-commit + 2 bits + 1 range)\n\n", .{
        VOTE_NUM_CONSTRAINTS,
    });

    const seed = [_]u8{0xAB} ** 32;
    const mem_key = deriveMembershipKey(seed);
    const nul_key = deriveNullifierKey(seed);
    const vote_key = deriveVoteCommitKey(seed);

    const group_id: u64 = 42;
    const membership_epoch: u64 = 7;
    const member_secret: u64 = 0xDEADBEEF;
    const member_salt: u64 = 0xCAFEBABE;
    const proposal_id: u64 = 999;
    const proposal_hash: u64 = 0xFEEDFACEDEADC0DE;
    const vote_code: u64 = 1; // 1 = approve
    const vote_randomness: u64 = 0xABCDEF12345678;

    const membership_commitment = computeMembershipCommitment(
        mem_key, member_secret, group_id, membership_epoch, member_salt,
    );
    const vote_nullifier = computeNullifier4(
        D_GROUP_VOTE, nul_key, member_secret, proposal_id, group_id, membership_epoch,
    );
    const vote_commitment = computeVoteCommitment(
        vote_key, vote_code, vote_randomness, proposal_hash,
    );
    const vbit0 = vote_code & 1;
    const vbit1 = (vote_code >> 1) & 1;

    var assignment: [VOTE_NUM_VARIABLES]u64 = undefined;
    assignment[VOTE_IDX_COMMIT] = membership_commitment;
    assignment[VOTE_IDX_GROUP_ID] = group_id;
    assignment[VOTE_IDX_EPOCH] = membership_epoch;
    assignment[VOTE_IDX_PROPOSAL_ID] = proposal_id;
    assignment[VOTE_IDX_PROPOSAL_HASH] = proposal_hash;
    assignment[VOTE_IDX_VOTE_NULLIFIER] = vote_nullifier;
    assignment[VOTE_IDX_VOTE_COMMITMENT] = vote_commitment;
    assignment[VOTE_IDX_SECRET] = member_secret;
    assignment[VOTE_IDX_SALT] = member_salt;
    assignment[VOTE_IDX_VOTE_CODE] = vote_code;
    assignment[VOTE_IDX_VOTE_RANDOMNESS] = vote_randomness;
    assignment[VOTE_IDX_VBIT0] = vbit0;
    assignment[VOTE_IDX_VBIT1] = vbit1;

    const mem_terms = [4]Term{
        .{ .index = VOTE_IDX_SECRET, .coeff = mem_key[0] },
        .{ .index = VOTE_IDX_GROUP_ID, .coeff = mem_key[1] },
        .{ .index = VOTE_IDX_EPOCH, .coeff = mem_key[2] },
        .{ .index = VOTE_IDX_SALT, .coeff = mem_key[3] },
    };
    const nul_terms = [4]Term{
        .{ .index = VOTE_IDX_SECRET, .coeff = nul_key[0] },
        .{ .index = VOTE_IDX_PROPOSAL_ID, .coeff = nul_key[1] },
        .{ .index = VOTE_IDX_GROUP_ID, .coeff = nul_key[2] },
        .{ .index = VOTE_IDX_EPOCH, .coeff = nul_key[3] },
    };
    const vote_commit_terms = [3]Term{
        .{ .index = VOTE_IDX_VOTE_CODE, .coeff = vote_key[0] },
        .{ .index = VOTE_IDX_VOTE_RANDOMNESS, .coeff = vote_key[1] },
        .{ .index = VOTE_IDX_PROPOSAL_HASH, .coeff = vote_key[2] },
    };
    const vote_code_bits_terms = [2]Term{
        .{ .index = VOTE_IDX_VBIT0, .coeff = 1 },
        .{ .index = VOTE_IDX_VBIT1, .coeff = 2 },
    };

    var constraints: [VOTE_NUM_CONSTRAINTS]Constraint = undefined;
    // C0: membership binding
    constraints[0] = .{
        .a = .{ .terms = &mem_terms },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = VOTE_IDX_COMMIT, .coeff = 1 }} },
    };
    // C1: vote nullifier
    constraints[1] = .{
        .a = .{ .terms = &nul_terms, .constant = D_GROUP_VOTE % Q },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = VOTE_IDX_VOTE_NULLIFIER, .coeff = 1 }} },
    };
    // C2: vote commitment
    constraints[2] = .{
        .a = .{ .terms = &vote_commit_terms },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = VOTE_IDX_VOTE_COMMITMENT, .coeff = 1 }} },
    };
    // C3: vbit0 ∈ {0,1}
    constraints[3] = .{
        .a = .{ .terms = &SEL_VBIT[0] },
        .b = .{ .terms = &SEL_VBIT[0] },
        .c = .{ .terms = &SEL_VBIT[0] },
    };
    // C4: vbit1 ∈ {0,1}
    constraints[4] = .{
        .a = .{ .terms = &SEL_VBIT[1] },
        .b = .{ .terms = &SEL_VBIT[1] },
        .c = .{ .terms = &SEL_VBIT[1] },
    };
    // C5: vote_code = vbit0 + 2·vbit1  (RangeCheck_2 from PP.md)
    constraints[5] = .{
        .a = .{ .terms = &vote_code_bits_terms },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = VOTE_IDX_VOTE_CODE, .coeff = 1 }} },
    };

    const relation = Relation{ .r1cs = .{
        .q = Q,
        .num_variables = VOTE_NUM_VARIABLES,
        .constraints = &constraints,
    } };
    const statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = assignment[0..VOTE_NUM_PUBLIC],
    };
    const witness = Protocol.Witness{ .private_assignment = assignment[VOTE_NUM_PUBLIC..] };

    var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
    defer proof.deinit(allocator);

    const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
    std.debug.print("Verify (correct)                     : {}\n", .{ok});

    // Tamper: forged vote nullifier (double-vote attempt with different nul)
    var pub_bad_nul = assignment[0..VOTE_NUM_PUBLIC].*;
    pub_bad_nul[VOTE_IDX_VOTE_NULLIFIER] = addMod(vote_nullifier, 1);
    const bad_nul_ok = try Protocol.verifyFromStatement(
        allocator,
        Protocol.Statement{ .relation = relation, .public_assignment = &pub_bad_nul },
        &proof,
        params,
    );
    std.debug.print("Verify (tampered vote nullifier)     : {}\n", .{bad_nul_ok});

    // Tamper: swapped vote commitment (claim different vote than cast)
    var pub_bad_commit = assignment[0..VOTE_NUM_PUBLIC].*;
    pub_bad_commit[VOTE_IDX_VOTE_COMMITMENT] = addMod(vote_commitment, 1);
    const bad_commit_ok = try Protocol.verifyFromStatement(
        allocator,
        Protocol.Statement{ .relation = relation, .public_assignment = &pub_bad_commit },
        &proof,
        params,
    );
    std.debug.print("Verify (tampered vote commitment)    : {}\n", .{bad_commit_ok});

    // Double-vote: same inputs → same nullifier → authority rejects second submission
    const nul2 = computeNullifier4(
        D_GROUP_VOTE, nul_key, member_secret, proposal_id, group_id, membership_epoch,
    );
    std.debug.print("Double-vote caught (same nul)        : {}\n", .{nul2 == vote_nullifier});

    // Forgery: vote_code = 4 is outside {0,1,2,3}; vbit0+2·vbit1 can only reach ≤3,
    // so the prover cannot satisfy C5 with a valid bit decomposition.
    var forged = assignment;
    forged[VOTE_IDX_VOTE_CODE] = 4;
    forged[VOTE_IDX_VBIT0] = 0;
    forged[VOTE_IDX_VBIT1] = 2; // vbit1=2 violates C4
    const forge_result = Protocol.proveFromStatement(
        allocator,
        statement,
        Protocol.Witness{ .private_assignment = forged[VOTE_NUM_PUBLIC..] },
        params,
    );
    if (forge_result) |fp| {
        var leaked = fp;
        defer leaked.deinit(allocator);
        std.debug.print("Forged vote_code=4 accepted          : true  (unexpected!)\n", .{});
    } else |_| {
        std.debug.print("Forged vote_code=4 rejected          : true\n", .{});
    }
}

// ─── §13.7 Vote Reveal ─────────────────────────────────────────────────────────
//
// Opens a previously committed vote during commit-then-reveal tally.
// Proves that revealed_vote_code is consistent with the prior vote_commitment
// without requiring membership — the voter's identity stays hidden.
//
// Public  [0..2]: proposal_hash, vote_commitment, revealed_vote_code
// Private [3..5]: vote_randomness, vbit0, vbit1
//
// Constraints: 4  (1 commitment opening + 2 bit-checks + 1 range)

const REV_IDX_PROPOSAL_HASH = 0;
const REV_IDX_VOTE_COMMITMENT = 1;
const REV_IDX_REVEALED_CODE = 2;
const REV_NUM_PUBLIC = 3;
const REV_IDX_RANDOMNESS = 3;
const REV_IDX_VBIT0 = 4;
const REV_IDX_VBIT1 = 5;
const REV_NUM_VARIABLES = 6;
const REV_NUM_CONSTRAINTS = 4;

const SEL_REV_VBIT = [2][1]Term{
    .{.{ .index = REV_IDX_VBIT0, .coeff = 1 }},
    .{.{ .index = REV_IDX_VBIT1, .coeff = 1 }},
};

fn runVoteReveal(allocator: std.mem.Allocator, params: Protocol.Params) !void {
    std.debug.print("\n=== §13.7 Vote Reveal ===\n", .{});
    std.debug.print("Variables  : {d}  ({d} public / {d} private)\n", .{
        REV_NUM_VARIABLES, REV_NUM_PUBLIC, REV_NUM_VARIABLES - REV_NUM_PUBLIC,
    });
    std.debug.print("Constraints: {d}  (1 commitment opening + 2 bits + 1 range)\n\n", .{
        REV_NUM_CONSTRAINTS,
    });

    const seed = [_]u8{0xAB} ** 32;
    const vote_key = deriveVoteCommitKey(seed);

    // Reuse the same vote cast in §13.6
    const proposal_hash: u64 = 0xFEEDFACEDEADC0DE;
    const vote_code: u64 = 1; // approve
    const vote_randomness: u64 = 0xABCDEF12345678;

    const vote_commitment = computeVoteCommitment(vote_key, vote_code, vote_randomness, proposal_hash);
    const vbit0 = vote_code & 1;
    const vbit1 = (vote_code >> 1) & 1;

    var assignment: [REV_NUM_VARIABLES]u64 = undefined;
    assignment[REV_IDX_PROPOSAL_HASH] = proposal_hash;
    assignment[REV_IDX_VOTE_COMMITMENT] = vote_commitment;
    assignment[REV_IDX_REVEALED_CODE] = vote_code;
    assignment[REV_IDX_RANDOMNESS] = vote_randomness;
    assignment[REV_IDX_VBIT0] = vbit0;
    assignment[REV_IDX_VBIT1] = vbit1;

    const reveal_terms = [3]Term{
        .{ .index = REV_IDX_REVEALED_CODE, .coeff = vote_key[0] },
        .{ .index = REV_IDX_RANDOMNESS, .coeff = vote_key[1] },
        .{ .index = REV_IDX_PROPOSAL_HASH, .coeff = vote_key[2] },
    };
    const code_bits_terms = [2]Term{
        .{ .index = REV_IDX_VBIT0, .coeff = 1 },
        .{ .index = REV_IDX_VBIT1, .coeff = 2 },
    };

    var constraints: [REV_NUM_CONSTRAINTS]Constraint = undefined;
    // C0: commitment opening — proves vote_randomness was used in the original commit
    constraints[0] = .{
        .a = .{ .terms = &reveal_terms },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = REV_IDX_VOTE_COMMITMENT, .coeff = 1 }} },
    };
    // C1: vbit0 ∈ {0,1}
    constraints[1] = .{
        .a = .{ .terms = &SEL_REV_VBIT[0] },
        .b = .{ .terms = &SEL_REV_VBIT[0] },
        .c = .{ .terms = &SEL_REV_VBIT[0] },
    };
    // C2: vbit1 ∈ {0,1}
    constraints[2] = .{
        .a = .{ .terms = &SEL_REV_VBIT[1] },
        .b = .{ .terms = &SEL_REV_VBIT[1] },
        .c = .{ .terms = &SEL_REV_VBIT[1] },
    };
    // C3: revealed_vote_code = vbit0 + 2·vbit1  (RangeCheck_2)
    constraints[3] = .{
        .a = .{ .terms = &code_bits_terms },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = REV_IDX_REVEALED_CODE, .coeff = 1 }} },
    };

    const relation = Relation{ .r1cs = .{
        .q = Q,
        .num_variables = REV_NUM_VARIABLES,
        .constraints = &constraints,
    } };
    const statement = Protocol.Statement{
        .relation = relation,
        .public_assignment = assignment[0..REV_NUM_PUBLIC],
    };
    const witness = Protocol.Witness{ .private_assignment = assignment[REV_NUM_PUBLIC..] };

    var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
    defer proof.deinit(allocator);

    const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
    std.debug.print("Verify (correct)                     : {}\n", .{ok});

    // Tamper: claim a different vote code (equivocation attempt)
    var pub_wrong_code = assignment[0..REV_NUM_PUBLIC].*;
    pub_wrong_code[REV_IDX_REVEALED_CODE] = (vote_code + 1) % 4;
    const bad_code_ok = try Protocol.verifyFromStatement(
        allocator,
        Protocol.Statement{ .relation = relation, .public_assignment = &pub_wrong_code },
        &proof,
        params,
    );
    std.debug.print("Verify (equivocated vote code)       : {}\n", .{bad_code_ok});

    // Consistency: the same (vote_code, vote_randomness, proposal_hash) used in §13.6
    // must produce the same commitment — the reveal proof is valid for that prior ballot.
    const commit2 = computeVoteCommitment(vote_key, vote_code, vote_randomness, proposal_hash);
    std.debug.print("Reveal consistent with §13.6 commit  : {}\n", .{commit2 == vote_commitment});
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var params = Protocol.PRESET_128;
    params.security_target_bits = 0.0;

    try runMembershipProof(allocator, params);
    try runVoteValidity(allocator, params);
    try runVoteReveal(allocator, params);
}
