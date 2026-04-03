//! Griffin Hash in R1CS — Merkle-Tree Anonymous Ticket Spend
//!
//! Replaces the toy `hash2(l,r) = l + 3r + 7` in anonymous_ticket_spend.zig
//! with a proper arithmetic hash: a 3-state, 6-round Griffin permutation over
//! F_Q with S-box x→x³.
//!
//! Griffin permutation structure (each round):
//!   1. Non-linear layer : sᵢ ← sᵢ³  (S-box x³, 2 R1CS constraints per element)
//!   2. MDS layer        : s ← M·s   (circulant [[2,1,1],[1,2,1],[1,1,2]], free)
//!   3. Round constants  : s ← s + rc (free)
//!
//! Compression function: hash(l,r) = Permute(l,r,0)[0]
//!
//! R1CS constraint count per hash call:
//!   – 2 constraints per (round,element): sq=s², cu=sq·s  → 6·ROUNDS = 36
//!   – 1 output equality constraint
//!   Total: 37 per hash, 74 for the two Merkle levels.
//!
//! Build / run:
//!   zig build run-griffin

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
const D_TICKET_SPEND: u64 = 9091;

const Protocol = zig_ring_arithmetic.CycloProtocol(N, Q);
const Term = zig_ring_arithmetic.CycloLinearTerm;
const LC = zig_ring_arithmetic.CycloLinearCombination;
const Constraint = zig_ring_arithmetic.CycloR1csConstraint;
const Relation = zig_ring_arithmetic.CycloRelation;

// ─── Griffin parameters ────────────────────────────────────────────────────────

/// Number of permutation rounds.
const ROUNDS: usize = 6;

/// Circulant MDS matrix M = circ(2,1,1).
/// Chosen for simplicity; all 2×2 minors are non-zero over F_Q.
const MDS = [3][3]u64{
    .{ 2, 1, 1 },
    .{ 1, 2, 1 },
    .{ 1, 1, 2 },
};

/// Deterministic round constants: rc[r][i] = ((r*3 + i + 1) * 137) % Q + 1.
/// Non-zero by construction (the +1 guarantees > 0).
fn griffinRC(r: usize, i: usize) u64 {
    return (@as(u64, r * 3 + i + 1) *% 137) % Q + 1;
}

// ─── Field arithmetic ──────────────────────────────────────────────────────────

fn addMod(a: u64, b: u64) u64 {
    return @intCast((@as(u128, a % Q) + @as(u128, b % Q)) % Q);
}
fn subMod(a: u64, b: u64) u64 {
    const am = a % Q;
    const bm = b % Q;
    if (am >= bm) return am - bm;
    return Q - (bm - am);
}
fn mulMod(a: u64, b: u64) u64 {
    return @intCast((@as(u128, a % Q) * @as(u128, b % Q)) % Q);
}
fn lin5(a0: u64, c0: u64, a1: u64, c1: u64, a2: u64, c2: u64, a3: u64, c3: u64, a4: u64, c4: u64, k: u64) u64 {
    var acc = k % Q;
    acc = addMod(acc, mulMod(a0, c0));
    acc = addMod(acc, mulMod(a1, c1));
    acc = addMod(acc, mulMod(a2, c2));
    acc = addMod(acc, mulMod(a3, c3));
    acc = addMod(acc, mulMod(a4, c4));
    return acc;
}

// ─── Griffin permutation ───────────────────────────────────────────────────────

fn griffinPermute(state: *[3]u64) void {
    for (0..ROUNDS) |r| {
        // Non-linear: sᵢ ← sᵢ³
        for (0..3) |i| {
            const x = state[i];
            state[i] = mulMod(mulMod(x, x), x);
        }
        // MDS
        const prev = state.*;
        for (0..3) |i| {
            var acc: u64 = 0;
            for (0..3) |j| acc = addMod(acc, mulMod(MDS[i][j], prev[j]));
            state[i] = acc;
        }
        // Round constants
        for (0..3) |i| state[i] = addMod(state[i], griffinRC(r, i));
    }
}

fn griffinHash(left: u64, right: u64) u64 {
    var state = [3]u64{ left, right, 0 };
    griffinPermute(&state);
    return state[0];
}

// ─── Variable indices ──────────────────────────────────────────────────────────

const NUM_PUBLIC = 6;
const IDX_ISSUER_ROOT = 0;
const IDX_SPEND_EPOCH = 1;
const IDX_QUOTA_CLASS = 2;
const IDX_TRANSPORT_CLASS = 3;
const IDX_EXPIRY_EPOCH = 4;
const IDX_TICKET_NULLIFIER = 5;
const IDX_SERIAL = 6;
const IDX_SECRET = 7;
const IDX_SIB0 = 8;
const IDX_SIB1 = 9;
const IDX_IDX0 = 10;
const IDX_IDX1 = 11;
const IDX_COMMITMENT = 12;
const IDX_DIFF0 = 13;
const IDX_T0 = 14;
const IDX_LEFT0 = 15;
const IDX_RIGHT0 = 16;
const IDX_PARENT0 = 17;
const IDX_DIFF1 = 18;
const IDX_T1 = 19;
const IDX_LEFT1 = 20;
const IDX_RIGHT1 = 21;
const IDX_PARENT1 = 22;
const IDX_COMPUTED_NULLIFIER = 23;
const IDX_DELTA = 24;
const IDX_DBIT0 = 25;
const IDX_DBIT1 = 26;
const IDX_DBIT2 = 27;
const IDX_DBIT3 = 28;
const IDX_DBIT4 = 29;
const IDX_DBIT5 = 30;
const IDX_DBIT6 = 31;
const IDX_DBIT7 = 32;

// Griffin intermediates: 2 hashes × ROUNDS rounds × 3 elements × 2 vars (sq, cu).
//   gSq(h, r, i) = sq variable for hash h, round r, element i
//   gCu(h, r, i) = cu variable for hash h, round r, element i
const GRIFFIN_BASE: usize = 33;
const GRIFFIN_VARS_PER_HASH: usize = ROUNDS * 6; // 36

fn gSq(h: usize, r: usize, i: usize) usize {
    return GRIFFIN_BASE + h * GRIFFIN_VARS_PER_HASH + r * 6 + i * 2;
}
fn gCu(h: usize, r: usize, i: usize) usize {
    return GRIFFIN_BASE + h * GRIFFIN_VARS_PER_HASH + r * 6 + i * 2 + 1;
}

const NUM_VARIABLES: usize = GRIFFIN_BASE + 2 * GRIFFIN_VARS_PER_HASH; // 105

// ─── Griffin witness computation ───────────────────────────────────────────────

/// Fill assignment[gSq(h,r,i)] and assignment[gCu(h,r,i)] for all rounds.
fn griffinWitness(assignment: []u64, h: usize, left: u64, right: u64) void {
    var state = [3]u64{ left, right, 0 };
    for (0..ROUNDS) |r| {
        const before = state;
        for (0..3) |i| {
            const sq = mulMod(before[i], before[i]);
            assignment[gSq(h, r, i)] = sq;
            assignment[gCu(h, r, i)] = mulMod(sq, before[i]);
            state[i] = mulMod(sq, before[i]); // cube = state after non-linear
        }
        // MDS
        const prev = state;
        for (0..3) |i| {
            var acc: u64 = 0;
            for (0..3) |j| acc = addMod(acc, mulMod(MDS[i][j], prev[j]));
            state[i] = acc;
        }
        // Round constants
        for (0..3) |i| state[i] = addMod(state[i], griffinRC(r, i));
    }
}

// ─── Term buffer helper ────────────────────────────────────────────────────────

/// Copy `terms` into `buf[pos..]` and return the resulting slice.
fn copyTerms(buf: []Term, pos: *usize, terms: []const Term) []const Term {
    const start = pos.*;
    @memcpy(buf[start .. start + terms.len], terms);
    pos.* += terms.len;
    return buf[start .. start + terms.len];
}

// ─── Griffin R1CS constraint builder ──────────────────────────────────────────
//
// Emits 37 constraints into `cons[con_pos..]`:
//   – for each (round r, element i): sq = s²,  cu = sq·s   (6 per round)
//   – 1 output equality:  MDS(cu_last) + rc_last = output_var
//
// `term_buf` is a scratch buffer; call site must keep it alive for the
// duration of proveFromStatement / verifyFromStatement.
//
fn buildGriffinConstraints(
    h: usize,
    left_idx: usize,
    right_idx: usize,
    output_idx: usize,
    term_buf: []Term,
    term_pos: *usize,
    cons: []Constraint,
    con_pos: *usize,
) void {
    for (0..ROUNDS) |r| {
        for (0..3) |i| {
            // ── State linear combination at start of round r, element i ──────
            const state_lc: LC = blk: {
                if (r == 0) {
                    if (i == 0) {
                        const t = copyTerms(term_buf, term_pos, &.{.{ .index = left_idx, .coeff = 1 }});
                        break :blk .{ .terms = t };
                    } else if (i == 1) {
                        const t = copyTerms(term_buf, term_pos, &.{.{ .index = right_idx, .coeff = 1 }});
                        break :blk .{ .terms = t };
                    } else {
                        // element 2: constant zero
                        const t = copyTerms(term_buf, term_pos, &.{});
                        break :blk .{ .terms = t };
                    }
                } else {
                    // MDS output of previous round:
                    // sᵢ = Σⱼ MDS[i][j] · cu(h,r-1,j) + rc[r-1][i]
                    const t = copyTerms(term_buf, term_pos, &.{
                        .{ .index = gCu(h, r - 1, 0), .coeff = MDS[i][0] },
                        .{ .index = gCu(h, r - 1, 1), .coeff = MDS[i][1] },
                        .{ .index = gCu(h, r - 1, 2), .coeff = MDS[i][2] },
                    });
                    break :blk .{ .terms = t, .constant = griffinRC(r - 1, i) };
                }
            };

            // ── sq_r_i = state² ──────────────────────────────────────────────
            // A = state_lc, B = state_lc, C = sq(h,r,i)
            const sq_c = copyTerms(term_buf, term_pos, &.{.{ .index = gSq(h, r, i), .coeff = 1 }});
            cons[con_pos.*] = .{
                .a = state_lc,
                .b = state_lc,
                .c = .{ .terms = sq_c },
            };
            con_pos.* += 1;

            // ── cu_r_i = sq · state ──────────────────────────────────────────
            // A = sq(h,r,i), B = state_lc, C = cu(h,r,i)
            const sq_a = copyTerms(term_buf, term_pos, &.{.{ .index = gSq(h, r, i), .coeff = 1 }});
            const cu_c = copyTerms(term_buf, term_pos, &.{.{ .index = gCu(h, r, i), .coeff = 1 }});
            cons[con_pos.*] = .{
                .a = .{ .terms = sq_a },
                .b = state_lc,
                .c = .{ .terms = cu_c },
            };
            con_pos.* += 1;
        }
    }

    // ── Output: MDS(cu_last)[0] + rc_last[0] = output_var ───────────────────
    // A = Σⱼ MDS[0][j]·cu(h,R-1,j) + rc[R-1][0],  B = 1,  C = output_idx
    const out_a = copyTerms(term_buf, term_pos, &.{
        .{ .index = gCu(h, ROUNDS - 1, 0), .coeff = MDS[0][0] },
        .{ .index = gCu(h, ROUNDS - 1, 1), .coeff = MDS[0][1] },
        .{ .index = gCu(h, ROUNDS - 1, 2), .coeff = MDS[0][2] },
    });
    const out_c = copyTerms(term_buf, term_pos, &.{.{ .index = output_idx, .coeff = 1 }});
    cons[con_pos.*] = .{
        .a = .{ .terms = out_a, .constant = griffinRC(ROUNDS - 1, 0) },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = out_c },
    };
    con_pos.* += 1;
}

// ─── main ──────────────────────────────────────────────────────────────────────

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // ── Witness values (same as anonymous_ticket_spend) ──────────────────────
    const serial: u64 = 12345;
    const secret: u64 = 67890;
    const spend_epoch: u64 = 100;
    const quota_class: u64 = 2;
    const transport_class: u64 = 1;
    const expiry_epoch: u64 = 110;

    const sibling0: u64 = 2222;
    const sibling1: u64 = 3333;
    const path_idx0: u64 = 0;
    const path_idx1: u64 = 1;

    const commitment = lin5(
        serial, 1, secret, 5, quota_class, 7, transport_class, 11, expiry_epoch, 13, 17,
    );

    const diff0 = subMod(sibling0, commitment);
    const t0 = mulMod(path_idx0, diff0);
    const left0 = addMod(commitment, t0);
    const right0 = subMod(sibling0, t0);

    // Griffin hash instead of the toy hash2
    const parent0 = griffinHash(left0, right0);

    const diff1 = subMod(sibling1, parent0);
    const t1 = mulMod(path_idx1, diff1);
    const left1 = addMod(parent0, t1);
    const right1 = subMod(sibling1, t1);
    const issuer_root = griffinHash(left1, right1);

    const computed_nullifier = lin5(
        D_TICKET_SPEND, 1, serial, 19, secret, 23, spend_epoch, 29, 1, 31, 0,
    );
    const ticket_nullifier = computed_nullifier;

    const delta = expiry_epoch - spend_epoch;
    const bits = [_]u64{
        (delta >> 0) & 1, (delta >> 1) & 1, (delta >> 2) & 1, (delta >> 3) & 1,
        (delta >> 4) & 1, (delta >> 5) & 1, (delta >> 6) & 1, (delta >> 7) & 1,
    };

    // ── Assignment ───────────────────────────────────────────────────────────
    var assignment: [NUM_VARIABLES]u64 = undefined;
    assignment[IDX_ISSUER_ROOT] = issuer_root;
    assignment[IDX_SPEND_EPOCH] = spend_epoch;
    assignment[IDX_QUOTA_CLASS] = quota_class;
    assignment[IDX_TRANSPORT_CLASS] = transport_class;
    assignment[IDX_EXPIRY_EPOCH] = expiry_epoch;
    assignment[IDX_TICKET_NULLIFIER] = ticket_nullifier;
    assignment[IDX_SERIAL] = serial;
    assignment[IDX_SECRET] = secret;
    assignment[IDX_SIB0] = sibling0;
    assignment[IDX_SIB1] = sibling1;
    assignment[IDX_IDX0] = path_idx0;
    assignment[IDX_IDX1] = path_idx1;
    assignment[IDX_COMMITMENT] = commitment;
    assignment[IDX_DIFF0] = diff0;
    assignment[IDX_T0] = t0;
    assignment[IDX_LEFT0] = left0;
    assignment[IDX_RIGHT0] = right0;
    assignment[IDX_PARENT0] = parent0;
    assignment[IDX_DIFF1] = diff1;
    assignment[IDX_T1] = t1;
    assignment[IDX_LEFT1] = left1;
    assignment[IDX_RIGHT1] = right1;
    assignment[IDX_PARENT1] = issuer_root;
    assignment[IDX_COMPUTED_NULLIFIER] = computed_nullifier;
    assignment[IDX_DELTA] = delta;
    assignment[IDX_DBIT0] = bits[0];
    assignment[IDX_DBIT1] = bits[1];
    assignment[IDX_DBIT2] = bits[2];
    assignment[IDX_DBIT3] = bits[3];
    assignment[IDX_DBIT4] = bits[4];
    assignment[IDX_DBIT5] = bits[5];
    assignment[IDX_DBIT6] = bits[6];
    assignment[IDX_DBIT7] = bits[7];

    // Griffin intermediate witnesses
    griffinWitness(&assignment, 0, left0, right0);
    griffinWitness(&assignment, 1, left1, right1);

    // ── Term buffer (heap, must outlive the protocol calls) ──────────────────
    // Upper bound: 105 terms per hash × 2 + margin
    const MAX_GRIFFIN_TERMS = 256;
    const term_buf = try allocator.alloc(Term, MAX_GRIFFIN_TERMS);
    defer allocator.free(term_buf);
    var term_pos: usize = 0;

    // ── Constraint array ─────────────────────────────────────────────────────
    // 24 original (non-hash) + 2 × 37 Griffin = 98 constraints
    const NUM_CONSTRAINTS = 24 + 2 * (ROUNDS * 6 + 1);
    const all_cons = try allocator.alloc(Constraint, NUM_CONSTRAINTS);
    defer allocator.free(all_cons);
    var con_pos: usize = 0;

    // ── Original non-hash constraints (stack-allocated term slices) ──────────

    // Commitment = lin5(serial·1, secret·5, quota_class·7, transport_class·11, expiry·13) + 17
    const terms_commitment_hash = [_]Term{
        .{ .index = IDX_SERIAL, .coeff = 1 },
        .{ .index = IDX_SECRET, .coeff = 5 },
        .{ .index = IDX_QUOTA_CLASS, .coeff = 7 },
        .{ .index = IDX_TRANSPORT_CLASS, .coeff = 11 },
        .{ .index = IDX_EXPIRY_EPOCH, .coeff = 13 },
    };
    all_cons[con_pos] = .{
        .a = .{ .terms = &terms_commitment_hash, .constant = 17 },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_COMMITMENT, .coeff = 1 }} },
    };
    con_pos += 1;

    // idx0 ∈ {0,1}: idx0 * (idx0 - 1) = 0
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{.{ .index = IDX_IDX0, .coeff = 1 }} },
        .b = .{ .terms = &.{.{ .index = IDX_IDX0, .coeff = 1 }}, .constant = Q - 1 },
        .c = .{ .terms = &.{}, .constant = 0 },
    };
    con_pos += 1;

    // diff0 = sib0 - commitment
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{ .{ .index = IDX_SIB0, .coeff = 1 }, .{ .index = IDX_COMMITMENT, .coeff = Q - 1 } } },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_DIFF0, .coeff = 1 }} },
    };
    con_pos += 1;

    // t0 = idx0 * diff0
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{.{ .index = IDX_IDX0, .coeff = 1 }} },
        .b = .{ .terms = &.{.{ .index = IDX_DIFF0, .coeff = 1 }} },
        .c = .{ .terms = &.{.{ .index = IDX_T0, .coeff = 1 }} },
    };
    con_pos += 1;

    // left0 = commitment + t0
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{ .{ .index = IDX_COMMITMENT, .coeff = 1 }, .{ .index = IDX_T0, .coeff = 1 } } },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_LEFT0, .coeff = 1 }} },
    };
    con_pos += 1;

    // right0 = sib0 - t0
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{ .{ .index = IDX_SIB0, .coeff = 1 }, .{ .index = IDX_T0, .coeff = Q - 1 } } },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_RIGHT0, .coeff = 1 }} },
    };
    con_pos += 1;

    // ── Griffin hash 0: parent0 = griffinHash(left0, right0) ─────────────────
    buildGriffinConstraints(
        0, IDX_LEFT0, IDX_RIGHT0, IDX_PARENT0,
        term_buf, &term_pos, all_cons, &con_pos,
    );

    // idx1 ∈ {0,1}
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{.{ .index = IDX_IDX1, .coeff = 1 }} },
        .b = .{ .terms = &.{.{ .index = IDX_IDX1, .coeff = 1 }}, .constant = Q - 1 },
        .c = .{ .terms = &.{}, .constant = 0 },
    };
    con_pos += 1;

    // diff1 = sib1 - parent0
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{ .{ .index = IDX_SIB1, .coeff = 1 }, .{ .index = IDX_PARENT0, .coeff = Q - 1 } } },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_DIFF1, .coeff = 1 }} },
    };
    con_pos += 1;

    // t1 = idx1 * diff1
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{.{ .index = IDX_IDX1, .coeff = 1 }} },
        .b = .{ .terms = &.{.{ .index = IDX_DIFF1, .coeff = 1 }} },
        .c = .{ .terms = &.{.{ .index = IDX_T1, .coeff = 1 }} },
    };
    con_pos += 1;

    // left1 = parent0 + t1
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{ .{ .index = IDX_PARENT0, .coeff = 1 }, .{ .index = IDX_T1, .coeff = 1 } } },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_LEFT1, .coeff = 1 }} },
    };
    con_pos += 1;

    // right1 = sib1 - t1
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{ .{ .index = IDX_SIB1, .coeff = 1 }, .{ .index = IDX_T1, .coeff = Q - 1 } } },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_RIGHT1, .coeff = 1 }} },
    };
    con_pos += 1;

    // ── Griffin hash 1: issuer_root = griffinHash(left1, right1) ─────────────
    buildGriffinConstraints(
        1, IDX_LEFT1, IDX_RIGHT1, IDX_PARENT1,
        term_buf, &term_pos, all_cons, &con_pos,
    );

    // parent1 (= PARENT1) = issuer_root (= ISSUER_ROOT)
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{.{ .index = IDX_PARENT1, .coeff = 1 }} },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_ISSUER_ROOT, .coeff = 1 }} },
    };
    con_pos += 1;

    // Nullifier: D_TICKET_SPEND·1 + serial·19 + secret·23 + spend_epoch·29 + 1·31 = computed_nullifier
    const terms_nullifier_hash = [_]Term{
        .{ .index = IDX_SERIAL, .coeff = 19 },
        .{ .index = IDX_SECRET, .coeff = 23 },
        .{ .index = IDX_SPEND_EPOCH, .coeff = 29 },
    };
    all_cons[con_pos] = .{
        .a = .{ .terms = &terms_nullifier_hash, .constant = (D_TICKET_SPEND + 31) % Q },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_COMPUTED_NULLIFIER, .coeff = 1 }} },
    };
    con_pos += 1;

    // computed_nullifier = ticket_nullifier
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{.{ .index = IDX_COMPUTED_NULLIFIER, .coeff = 1 }} },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_TICKET_NULLIFIER, .coeff = 1 }} },
    };
    con_pos += 1;

    // dbit0..dbit7 binary checks: dbitₙ² = dbitₙ
    inline for ([_]usize{ IDX_DBIT0, IDX_DBIT1, IDX_DBIT2, IDX_DBIT3, IDX_DBIT4, IDX_DBIT5, IDX_DBIT6, IDX_DBIT7 }) |idx| {
        // We can't use a stack-allocated slice with runtime index inside inline for easily,
        // so build each constraint inline with a comptime-known index.
        const t = [1]Term{.{ .index = idx, .coeff = 1 }};
        all_cons[con_pos] = .{
            .a = .{ .terms = &t },
            .b = .{ .terms = &t },
            .c = .{ .terms = &t },
        };
        con_pos += 1;
    }

    // delta = Σ dbitₙ · 2ⁿ
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
    all_cons[con_pos] = .{
        .a = .{ .terms = &terms_delta_bits },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_DELTA, .coeff = 1 }} },
    };
    con_pos += 1;

    // spend_epoch + delta = expiry_epoch
    all_cons[con_pos] = .{
        .a = .{ .terms = &.{ .{ .index = IDX_SPEND_EPOCH, .coeff = 1 }, .{ .index = IDX_DELTA, .coeff = 1 } } },
        .b = .{ .terms = &.{}, .constant = 1 },
        .c = .{ .terms = &.{.{ .index = IDX_EXPIRY_EPOCH, .coeff = 1 }} },
    };
    con_pos += 1;

    std.debug.assert(con_pos == NUM_CONSTRAINTS);

    // ── Relation, statement, witness ─────────────────────────────────────────
    const relation = Relation{ .r1cs = .{
        .q = Q,
        .num_variables = NUM_VARIABLES,
        .constraints = all_cons,
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

    std.debug.print("\n=== Griffin Hash in R1CS — Merkle Anonymous Ticket Spend ===\n", .{});
    std.debug.print("Hash function    : Griffin(state=3, rounds={d}, S-box=x³)\n", .{ROUNDS});
    std.debug.print("Variables        : {d}  ({d} public / {d} private / {d} Griffin intermediates)\n", .{
        NUM_VARIABLES, NUM_PUBLIC, NUM_VARIABLES - NUM_PUBLIC - 2 * GRIFFIN_VARS_PER_HASH, 2 * GRIFFIN_VARS_PER_HASH,
    });
    std.debug.print("Constraints      : {d}  (24 circuit + 2×{d} Griffin)\n\n", .{ NUM_CONSTRAINTS, ROUNDS * 6 + 1 });

    std.debug.print("Generating ZK proof...\n", .{});
    var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
    defer proof.deinit(allocator);
    std.debug.print("Proof generated.\n\n", .{});

    const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
    std.debug.print("Verify (correct)                    : {}\n", .{ok});

    // Tamper: flip ticket nullifier
    const tampered_nullifier = [_]u64{
        assignment[IDX_ISSUER_ROOT], assignment[IDX_SPEND_EPOCH],
        assignment[IDX_QUOTA_CLASS], assignment[IDX_TRANSPORT_CLASS],
        assignment[IDX_EXPIRY_EPOCH], addMod(assignment[IDX_TICKET_NULLIFIER], 1),
    };
    const tampered_stmt = Protocol.Statement{
        .relation = relation,
        .public_assignment = &tampered_nullifier,
    };
    const tampered_ok = try Protocol.verifyFromStatement(allocator, tampered_stmt, &proof, params);
    std.debug.print("Verify (tampered nullifier)         : {}\n", .{tampered_ok});

    // Bad path: wrong path index should cause proveFromStatement to fail
    var bad_assignment = assignment;
    bad_assignment[IDX_IDX1] = 0; // wrong index breaks Merkle path
    // recompute Griffin witnesses for the new (wrong) path
    const bad_left1 = addMod(bad_assignment[IDX_PARENT0], mulMod(0, bad_assignment[IDX_DIFF1]));
    const bad_right1 = subMod(bad_assignment[IDX_SIB1], mulMod(0, bad_assignment[IDX_DIFF1]));
    griffinWitness(&bad_assignment, 1, bad_left1, bad_right1);
    const bad_stmt = Protocol.Statement{
        .relation = relation,
        .public_assignment = bad_assignment[0..NUM_PUBLIC],
    };
    const bad_witness = Protocol.Witness{
        .private_assignment = bad_assignment[NUM_PUBLIC..],
    };
    const bad_prove = Protocol.proveFromStatement(allocator, bad_stmt, bad_witness, params);
    if (bad_prove) |bad| {
        var leaked = bad;
        defer leaked.deinit(allocator);
        std.debug.print("Bad Merkle path produced proof      : true  (unexpected)\n", .{});
    } else |_| {
        std.debug.print("Bad Merkle path rejected            : true\n", .{});
    }
}
