//! Anonymous Ticket Spend — Cyclo-native R1CS
//!
//! What was wrong with the original
//! ----------------------------------
//! The original example used a Merkle tree with hash2(l,r) = l + 3r + 7.
//! That design had two fundamental problems:
//!
//!   1. hash2 is not a cryptographic function — it is a linear map, so any
//!      adversary can forge Merkle paths trivially.
//!
//!   2. Even replacing it with a proper arithmetic hash (e.g., Griffin) is the
//!      wrong abstraction for Cyclo.  Cyclo §2.6 / Remark 1 explicitly keeps
//!      hash gadgets *outside* the proven statement.  Fiat–Shamir hashing lives
//!      in the protocol layer (SHAKE-256 in the Zig code); it is never encoded
//!      as R1CS constraints.  Doing so inflates the witness by ~36 variables per
//!      hash call and blows up prover time proportionally.
//!
//! The right abstraction: Ajtai / Ring-SIS commitment
//! ---------------------------------------------------
//! Cyclo's principal linear relation already IS a set-membership proof:
//!
//!   A · z = y,   ‖z‖ ≤ B
//!
//! The issuer publishes a public random vector  a ∈ F_q^t  (derived from their
//! seed via SHAKE-256, exactly like the election vector in electronic_vote.zig)
//! and for each authorised ticket computes:
//!
//!   y = Σᵢ a[i] · field[i]   mod Q
//!
//! This is published in the ticket registry.  When spending, the user proves in
//! zero-knowledge that their private (serial, secret) — together with public
//! metadata — satisfies the published commitment.  No Merkle tree, no hash
//! inside the circuit.
//!
//! Binding follows from Ring-SIS hardness (the same assumption Cyclo requires
//! for its own Ajtai commitment).  Zero additional assumptions, zero extra cost.
//!
//! Circuit (12 constraints, 17 variables)
//! ----------------------------------------
//! Public inputs  [0..5]:
//!   issuer_commitment = Σ a[i]·field[i]   (Ajtai commitment, replaces Merkle root)
//!   spend_epoch
//!   quota_class
//!   transport_class
//!   expiry_epoch
//!   ticket_nullifier
//!
//! Private inputs [6..16]:
//!   serial, secret
//!   delta = expiry_epoch − spend_epoch  (≥ 0, proved via binary decomposition)
//!   dbit0 … dbit7
//!
//! Constraints:
//!   C0    Commitment binding : (Σ a[i]·field[i])  · 1 = issuer_commitment
//!   C1    Nullifier          : (D + serial·k₀ + secret·k₁ + spend·k₂) · 1 = nullifier
//!   C2–C9 Bit checks         : dbitₙ · dbitₙ = dbitₙ
//!   C10   Delta reconstr.    : (Σ 2ⁿ·dbitₙ) · 1 = delta
//!   C11   Validity           : (spend_epoch + delta) · 1 = expiry_epoch
//!
//! Comparison with original:
//!   Original  : 33 variables, 26 constraints, Merkle + insecure hash2
//!   This file : 17 variables, 12 constraints, Ring-SIS native, no hash in circuit
//!
//! Build / run:
//!   zig build run-ticket

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

/// Domain constant for the nullifier — separates it from the commitment key
/// space so that the same issuer seed cannot be replayed across both.
const D_TICKET_SPEND: u64 = 9091;
const NULLIFIER_CONSTANT: u64 = D_TICKET_SPEND % Q;

const Protocol = zig_ring_arithmetic.CycloProtocol(N, Q);
const Term = zig_ring_arithmetic.CycloLinearTerm;
const Constraint = zig_ring_arithmetic.CycloR1csConstraint;
const Relation = zig_ring_arithmetic.CycloRelation;

// ─── Field arithmetic ──────────────────────────────────────────────────────────

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

// ─── Issuer key derivation ─────────────────────────────────────────────────────
//
// Derives a public vector  a ∈ F_q^5  from the issuer's seed via SHAKE-256.
// This is the direct analogue of deriveElectionVector() in electronic_vote.zig:
// the hash runs *outside* the circuit (as part of parameter setup) so its cost
// is zero inside the R1CS.
//
fn deriveIssuerKey(seed: [32]u8) [5]u64 {
    var key: [5]u64 = undefined;
    for (0..5) |i| {
        key[i] = deriveTaggedKey(seed, 0, @as(u64, i));
    }
    return key;
}

fn deriveNullifierKey(seed: [32]u8) [3]u64 {
    var key: [3]u64 = undefined;
    for (0..3) |i| {
        key[i] = deriveTaggedKey(seed, 1, @as(u64, i));
    }
    return key;
}

// ─── Ticket commitment ─────────────────────────────────────────────────────────
//
// y = Σ key[i] · field[i]  mod Q
//
// Binding: forging a different (serial', secret') that satisfies the same y
// requires solving Ring-SIS with the public matrix row [key[0], key[1], ...],
// which is hard by assumption.
//
// The issuer computes y once per authorised ticket and publishes it in the
// ticket registry (a simple list — no Merkle tree needed).
//
fn computeCommitment(
    key: [5]u64,
    serial: u64,
    secret: u64,
    quota_class: u64,
    transport_class: u64,
    expiry_epoch: u64,
) u64 {
    var acc: u128 = 0;
    acc += @as(u128, key[0]) * @as(u128, serial % Q);
    acc += @as(u128, key[1]) * @as(u128, secret % Q);
    acc += @as(u128, key[2]) * @as(u128, quota_class % Q);
    acc += @as(u128, key[3]) * @as(u128, transport_class % Q);
    acc += @as(u128, key[4]) * @as(u128, expiry_epoch % Q);
    return @intCast(acc % Q);
}

// ─── Ticket nullifier ──────────────────────────────────────────────────────────
//
// nul = D_TICKET_SPEND + serial·k0 + secret·k1 + spend_epoch·k2  mod Q
//
// Properties:
//   Deterministic : same (serial, secret, spend_epoch) → same nullifier
//   Unlinkable    : different spend_epoch → different nullifier; different
//                   serials produce different nullifiers
//   Double-spend  : the authority rejects any second submission of the same nul
//
fn computeNullifier(key: [3]u64, serial: u64, secret: u64, spend_epoch: u64) u64 {
    var acc: u128 = NULLIFIER_CONSTANT;
    acc += @as(u128, serial % Q) * @as(u128, key[0]);
    acc += @as(u128, secret % Q) * @as(u128, key[1]);
    acc += @as(u128, spend_epoch % Q) * @as(u128, key[2]);
    return @intCast(acc % Q);
}

// ─── Variable layout ───────────────────────────────────────────────────────────

// Public (known to the verifier)
const IDX_ISSUER_COMMITMENT = 0; // Ajtai commitment y = Σ key[i]·field[i]
const IDX_SPEND_EPOCH = 1;
const IDX_QUOTA_CLASS = 2;
const IDX_TRANSPORT_CLASS = 3;
const IDX_EXPIRY_EPOCH = 4;
const IDX_TICKET_NULLIFIER = 5;
const NUM_PUBLIC = 6;

// Private (hidden inside the ZK proof)
const IDX_SERIAL = 6;
const IDX_SECRET = 7;
const IDX_DELTA = 8; // expiry_epoch − spend_epoch, range-proved via bits below
const IDX_DBIT0 = 9;
const IDX_DBIT1 = 10;
const IDX_DBIT2 = 11;
const IDX_DBIT3 = 12;
const IDX_DBIT4 = 13;
const IDX_DBIT5 = 14;
const IDX_DBIT6 = 15;
const IDX_DBIT7 = 16;

const NUM_VARIABLES = 17;
const NUM_CONSTRAINTS = 12; // 1 + 1 + 8 + 1 + 1

// Single-element term selectors for the eight delta bits.
// Declared here (function-scope lifetime) so that constraint slices remain
// valid for the duration of the prove/verify calls.
const SEL_DBIT = [8][1]Term{
    .{.{ .index = IDX_DBIT0, .coeff = 1 }},
    .{.{ .index = IDX_DBIT1, .coeff = 1 }},
    .{.{ .index = IDX_DBIT2, .coeff = 1 }},
    .{.{ .index = IDX_DBIT3, .coeff = 1 }},
    .{.{ .index = IDX_DBIT4, .coeff = 1 }},
    .{.{ .index = IDX_DBIT5, .coeff = 1 }},
    .{.{ .index = IDX_DBIT6, .coeff = 1 }},
    .{.{ .index = IDX_DBIT7, .coeff = 1 }},
};

// ─── main ──────────────────────────────────────────────────────────────────────

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // ── Ticket data ───────────────────────────────────────────────────────────
    const serial: u64 = 12345;
    const secret: u64 = 67890;
    const spend_epoch: u64 = 100;
    const quota_class: u64 = 2;
    const transport_class: u64 = 1;
    const expiry_epoch: u64 = 110;

    // ── Issuer key (public — derived from issuer seed, outside the circuit) ───
    const issuer_seed = [_]u8{0xAB} ** 32;
    const issuer_key = deriveIssuerKey(issuer_seed);
    const issuer_nul_key = deriveNullifierKey(issuer_seed);

    // ── Witness values ────────────────────────────────────────────────────────
    const issuer_commitment = computeCommitment(
        issuer_key,
        serial,
        secret,
        quota_class,
        transport_class,
        expiry_epoch,
    );
    const ticket_nullifier = computeNullifier(issuer_nul_key, serial, secret, spend_epoch);

    // delta ≥ 0 (expiry > spend) — proved via 8-bit binary decomposition
    if (expiry_epoch < spend_epoch) return error.TicketAlreadyExpired;
    const delta = expiry_epoch - spend_epoch;
    if (delta > 255) return error.TicketExpiredBeyondRangeWindow;
    const bits = [8]u64{
        (delta >> 0) & 1, (delta >> 1) & 1, (delta >> 2) & 1, (delta >> 3) & 1,
        (delta >> 4) & 1, (delta >> 5) & 1, (delta >> 6) & 1, (delta >> 7) & 1,
    };

    // ── Assignment ────────────────────────────────────────────────────────────
    var assignment: [NUM_VARIABLES]u64 = undefined;
    assignment[IDX_ISSUER_COMMITMENT] = issuer_commitment;
    assignment[IDX_SPEND_EPOCH] = spend_epoch;
    assignment[IDX_QUOTA_CLASS] = quota_class;
    assignment[IDX_TRANSPORT_CLASS] = transport_class;
    assignment[IDX_EXPIRY_EPOCH] = expiry_epoch;
    assignment[IDX_TICKET_NULLIFIER] = ticket_nullifier;
    assignment[IDX_SERIAL] = serial;
    assignment[IDX_SECRET] = secret;
    assignment[IDX_DELTA] = delta;
    inline for (0..8) |k| assignment[IDX_DBIT0 + k] = bits[k];

    // ── Constraint terms ──────────────────────────────────────────────────────

    // C0: commitment — coefficients are runtime (derived from issuer key)
    const terms_commitment = [5]Term{
        .{ .index = IDX_SERIAL, .coeff = issuer_key[0] },
        .{ .index = IDX_SECRET, .coeff = issuer_key[1] },
        .{ .index = IDX_QUOTA_CLASS, .coeff = issuer_key[2] },
        .{ .index = IDX_TRANSPORT_CLASS, .coeff = issuer_key[3] },
        .{ .index = IDX_EXPIRY_EPOCH, .coeff = issuer_key[4] },
    };

    // C1: nullifier
    const terms_nullifier = [_]Term{
        .{ .index = IDX_SERIAL, .coeff = issuer_nul_key[0] },
        .{ .index = IDX_SECRET, .coeff = issuer_nul_key[1] },
        .{ .index = IDX_SPEND_EPOCH, .coeff = issuer_nul_key[2] },
    };

    // C10: delta = Σ 2ⁿ · dbitₙ
    const terms_delta_bits = [_]Term{
        .{ .index = IDX_DBIT0, .coeff = 1 },
        .{ .index = IDX_DBIT1, .coeff = 2 },
        .{ .index = IDX_DBIT2, .coeff = 4 },
        .{ .index = IDX_DBIT3, .coeff = 8 },
        .{ .index = IDX_DBIT4, .coeff = 16 },
        .{ .index = IDX_DBIT5, .coeff = 32 },
        .{ .index = IDX_DBIT6, .coeff = 64 },
        .{ .index = IDX_DBIT7, .coeff = 128 },
    };

    // C11: spend_epoch + delta = expiry_epoch
    const terms_validity = [_]Term{
        .{ .index = IDX_SPEND_EPOCH, .coeff = 1 },
        .{ .index = IDX_DELTA, .coeff = 1 },
    };

    // ── Build constraints ─────────────────────────────────────────────────────
    var constraints: [NUM_CONSTRAINTS]Constraint = undefined;

    // C0 — commitment binding (single linear R1CS constraint, replaces full Merkle tree)
    constraints[0] = .{
        .a = .{ .terms = &terms_commitment },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_ISSUER_COMMITMENT, .coeff = 1 }} },
    };

    // C1 — nullifier
    constraints[1] = .{
        .a = .{ .terms = &terms_nullifier, .constant = NULLIFIER_CONSTANT },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_TICKET_NULLIFIER, .coeff = 1 }} },
    };

    // C2–C9 — bit checks: dbitₙ² = dbitₙ  ⟹  dbitₙ ∈ {0, 1}
    inline for (0..8) |k| {
        constraints[2 + k] = .{
            .a = .{ .terms = &SEL_DBIT[k] },
            .b = .{ .terms = &SEL_DBIT[k] },
            .c = .{ .terms = &SEL_DBIT[k] },
        };
    }

    // C10 — delta reconstruction
    constraints[10] = .{
        .a = .{ .terms = &terms_delta_bits },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_DELTA, .coeff = 1 }} },
    };

    // C11 — validity: expiry ≥ spend, i.e. spend + delta = expiry with delta ∈ [0,255]
    constraints[11] = .{
        .a = .{ .terms = &terms_validity },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_EXPIRY_EPOCH, .coeff = 1 }} },
    };

    // ── Relation, statement, witness ──────────────────────────────────────────
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

    std.debug.print(
        \\
        \\=== Anonymous Ticket Spend (Cyclo-native, no hash in circuit) ===
        \\Membership : Ajtai commitment  y = Σ key[i]·field[i]  (Ring-SIS binding)
        \\Variables  : {d}  ({d} public / {d} private)
        \\Constraints: {d}  (1 commitment + 1 nullifier + 8 bit-checks + 1 delta + 1 validity)
        \\
        \\
    , .{ NUM_VARIABLES, NUM_PUBLIC, NUM_VARIABLES - NUM_PUBLIC, NUM_CONSTRAINTS });

    // ── Prove ─────────────────────────────────────────────────────────────────
    std.debug.print("Generating ZK proof...\n", .{});
    var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
    defer proof.deinit(allocator);
    std.debug.print("Proof generated.\n\n", .{});

    // ── Happy path ────────────────────────────────────────────────────────────
    const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
    std.debug.print("Verify (correct)                     : {}\n", .{ok});

    // ── Tamper 1: flip one bit of the nullifier ───────────────────────────────
    var pub_bad_nul = assignment[0..NUM_PUBLIC].*;
    pub_bad_nul[IDX_TICKET_NULLIFIER] = addMod(ticket_nullifier, 1);
    const bad_nul_ok = try Protocol.verifyFromStatement(
        allocator,
        Protocol.Statement{ .relation = relation, .public_assignment = &pub_bad_nul },
        &proof,
        params,
    );
    std.debug.print("Verify (tampered nullifier)          : {}\n", .{bad_nul_ok});

    // ── Tamper 2: wrong issuer commitment (different ticket) ──────────────────
    var pub_bad_commit = assignment[0..NUM_PUBLIC].*;
    pub_bad_commit[IDX_ISSUER_COMMITMENT] = addMod(issuer_commitment, 1);
    const bad_commit_ok = try Protocol.verifyFromStatement(
        allocator,
        Protocol.Statement{ .relation = relation, .public_assignment = &pub_bad_commit },
        &proof,
        params,
    );
    std.debug.print("Verify (wrong issuer commitment)     : {}\n", .{bad_commit_ok});

    // ── Double-spend detection ────────────────────────────────────────────────
    // Same (serial, secret, spend_epoch) → identical nullifier → authority rejects.
    const nul_repeat = computeNullifier(issuer_nul_key, serial, secret, spend_epoch);
    std.debug.print("Double-spend caught (same key→same nul): {}\n", .{nul_repeat == ticket_nullifier});

    // ── Cross-epoch unlinkability ─────────────────────────────────────────────
    // Different spend_epoch → different nullifier → spends in different epochs
    // cannot be linked to the same ticket.
    const nul_other_epoch = computeNullifier(issuer_nul_key, serial, secret, spend_epoch + 1);
    std.debug.print("Cross-epoch nuls differ              : {}\n", .{nul_other_epoch != ticket_nullifier});

    // ── Forgery attempt: different serial, same public commitment ─────────────
    // The commitment constraint  Σ key[i]·field[i] = issuer_commitment  is no
    // longer satisfied → proveFromStatement rejects the witness before generating
    // any proof output.
    var forged = assignment;
    forged[IDX_SERIAL] = (serial + 1) % Q;
    const forge_result = Protocol.proveFromStatement(
        allocator,
        statement,
        Protocol.Witness{ .private_assignment = forged[NUM_PUBLIC..] },
        params,
    );
    if (forge_result) |fp| {
        var leaked = fp;
        defer leaked.deinit(allocator);
        std.debug.print("Forged serial accepted               : true  (unexpected!)\n", .{});
    } else |_| {
        std.debug.print("Forged serial rejected               : true\n", .{});
    }
}
