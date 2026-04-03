//! C FFI bindings for the Cyclo prover
//!
//! This module exposes the Cyclo protocol via C-compatible FFI
//! so it can be called from Rust or other C-compatible languages.

const std = @import("std");
const zig_ring_arithmetic = @import("zig_ring_arithmetic");

comptime {
    if (@import("builtin").os.tag == .windows) {
        _ = @import("msvc_compat");
    }
}

// Protocol instantiation for VELA parameters (N=128, Q=1125899906839937)
const N = 128;
const Q: u64 = 1125899906839937;
const CycloProtocol = zig_ring_arithmetic.CycloProtocol(N, Q);
const ProofType = zig_ring_arithmetic.CycloProof(N, Q);

// Opaque pointers for handles
pub const CycloStatement = opaque {};
pub const CycloWitness = opaque {};
pub const CycloProof = opaque {};
pub const CycloParams = opaque {};
pub const CycloError = enum(i32) {
    success = 0,
    invalid_params = 1,
    invalid_witness = 2,
    proof_failed = 3,
    verification_failed = 4,
    allocation_failed = 5,
    serialization_failed = 6,
    _,
};

// ============================================================================
// Parameter Management
// ============================================================================

/// Get the PRESET_128 parameters
/// Returns a pointer to static params (not allocated)
export fn cyclo_preset_128() ?*const CycloParams {
    return @ptrCast(&CycloProtocol.PRESET_128);
}

/// Get default security target bits
export fn cyclo_security_bits() f64 {
    return 128.0;
}

// ============================================================================
// Memory Allocation
// ============================================================================

/// Allocate a proof buffer of maximum size
/// The caller is responsible for freeing with cyclo_proof_free
export fn cyclo_proof_allocate() ?*anyopaque {
    const allocator = std.heap.page_allocator;
    const size = 65536; // 64KB should be enough for most proofs
    const buf = allocator.alloc(u8, size) catch return null;
    return buf.ptr;
}

/// Free a proof buffer
export fn cyclo_proof_free(ptr: ?*anyopaque) void {
    if (ptr) |p| {
        const allocator = std.heap.page_allocator;
        const slice: [*]u8 = @ptrCast(p);
        allocator.free(slice[0..65536]);
    }
}

// ============================================================================
// High-Level Prove/Verify API
// ============================================================================

/// Prove a statement and return proof size
///
/// Args:
///   public_inputs: slice of public input u64 values
///   public_len: number of public inputs
///   private_inputs: slice of private input u64 values
///   private_len: number of private inputs
///   proof_out: buffer to write proof into
///   proof_out_size: size of the proof buffer
///
/// Returns: proof size on success, error code (1–6) on failure
export fn cyclo_prove(
    public_inputs: [*]const u64,
    public_len: usize,
    private_inputs: [*]const u64,
    private_len: usize,
    proof_out: [*]u8,
    proof_out_size: usize,
) CycloError {
    const allocator = std.heap.page_allocator;

    const public_assignment = public_inputs[0..public_len];
    const private_assignment = private_inputs[0..private_len];

    const statement = CycloProtocol.Statement{
        .relation = .{
            .r1cs = .{
                .q = Q,
                .num_variables = public_len + private_len,
                .constraints = &.{},
            },
        },
        .public_assignment = public_assignment,
    };

    const witness = CycloProtocol.Witness{
        .private_assignment = private_assignment,
    };

    var proof_result = CycloProtocol.proveFromStatement(allocator, statement, witness, CycloProtocol.PRESET_128) catch {
        return .proof_failed;
    };
    defer proof_result.deinit(allocator);

    // Serialize proof to the output buffer
    const serialized = proof_result.serialize(allocator) catch return .serialization_failed;
    defer allocator.free(serialized);

    if (serialized.len > proof_out_size) return .serialization_failed;

    @memcpy(proof_out[0..serialized.len], serialized);

    return @enumFromInt(@as(i32, @intCast(serialized.len)));
}

/// Verify a proof
///
/// Args:
///   public_inputs: slice of public input u64 values
///   public_len: number of public inputs
///   proof: proof bytes
///   proof_len: proof size
///
/// Returns: success(1) if valid, success(0) if invalid, error code on failure
export fn cyclo_verify(
    public_inputs: [*]const u64,
    public_len: usize,
    proof: [*]const u8,
    proof_len: usize,
) CycloError {
    const allocator = std.heap.page_allocator;

    const public_assignment = public_inputs[0..public_len];

    const statement = CycloProtocol.Statement{
        .relation = .{
            .r1cs = .{
                .q = Q,
                .num_variables = public_len,
                .constraints = &.{},
            },
        },
        .public_assignment = public_assignment,
    };

    const proof_bytes: []const u8 = proof[0..proof_len];
    var deserialized = ProofType.deserialize(allocator, proof_bytes) catch {
        return .serialization_failed;
    };
    defer deserialized.deinit(allocator);

    const ok = CycloProtocol.verifyFromStatement(allocator, statement, &deserialized, CycloProtocol.PRESET_128) catch {
        return .verification_failed;
    };

    return @enumFromInt(@as(i32, if (ok) 1 else 0));
}
