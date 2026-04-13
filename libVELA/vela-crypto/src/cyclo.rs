//! Cyclo ZKP integration via FFI.
//!
//! Wraps the Zig-implemented Cyclo lattice-based zero-knowledge proof system
//! using the C ABI exported by `cyclo_ffi.zig` (N=128, Q=1125899906839937,
//! targeting 128-bit post-quantum security).
//!
//! # Usage
//!
//! ```rust,no_run
//! use vela_crypto::cyclo;
//!
//! let public_inputs  = [42u64, 1337u64];
//! let private_inputs = [7u64, 13u64];
//!
//! let proof = cyclo::prove(&public_inputs, &private_inputs).unwrap();
//! let valid = cyclo::verify(&public_inputs, &proof).unwrap();
//! assert!(valid);
//! ```

use crate::{Result, VelaError};
use std::ffi::c_int;

// ── Raw FFI layer ────────────────────────────────────────────────────────────

#[allow(dead_code)]
mod ffi {
    use std::ffi::{c_double, c_int, c_void};

    extern "C" {
        /// Returns positive proof size on success; 1-6 on error (see `CycloErrCode`).
        pub fn cyclo_prove(
            public_inputs: *const u64,
            public_len: usize,
            private_inputs: *const u64,
            private_len: usize,
            proof_out: *mut u8,
            proof_out_size: usize,
        ) -> c_int;

        /// Returns 1 if valid, 0 if invalid, 1-6 on internal error.
        pub fn cyclo_verify(
            public_inputs: *const u64,
            public_len: usize,
            proof: *const u8,
            proof_len: usize,
        ) -> c_int;

        pub fn cyclo_proof_allocate() -> *mut c_void;
        pub fn cyclo_proof_free(ptr: *mut c_void);
        pub fn cyclo_security_bits() -> c_double;
    }
}

// ── Error mapping ─────────────────────────────────────────────────────────────

/// Error codes shared by `cyclo_prove` and `cyclo_verify`.
///
/// Values mirror `CycloError` in `cyclo_ffi.zig`.  A return value larger than
/// `MAX_ERROR_CODE` from `cyclo_prove` is interpreted as the proof byte-length.
const MAX_ERROR_CODE: c_int = 6;

fn map_error(code: c_int) -> VelaError {
    let msg = match code {
        1 => "invalid params",
        2 => "invalid witness",
        3 => "proof generation failed",
        4 => "verification failed internally",
        5 => "allocation failed",
        6 => "serialization failed",
        _ => "unknown error",
    };
    VelaError::CycloError(msg.into())
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Maximum proof buffer size — matches the Zig-side page allocator reservation.
const PROOF_BUF_SIZE: usize = 65536;

/// A serialized Cyclo ZK proof.
pub struct CycloProof(Vec<u8>);

impl CycloProof {
    /// Raw proof bytes suitable for transmission / storage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Reconstruct a `CycloProof` from raw bytes (e.g. after deserialization).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

// ── Safe wrappers ─────────────────────────────────────────────────────────────

/// Generate a Cyclo ZK proof for the given inputs.
///
/// `public_inputs` and `private_inputs` are field elements in Z_q (q = 1125899906839937).
///
/// # Errors
///
/// Returns [`VelaError::CycloError`] if the Zig prover reports a failure.
pub fn prove(public_inputs: &[u64], private_inputs: &[u64]) -> Result<CycloProof> {
    let mut buf = vec![0u8; PROOF_BUF_SIZE];

    let ret = unsafe {
        ffi::cyclo_prove(
            public_inputs.as_ptr(),
            public_inputs.len(),
            private_inputs.as_ptr(),
            private_inputs.len(),
            buf.as_mut_ptr(),
            buf.len(),
        )
    };

    // The Zig FFI contract: values > MAX_ERROR_CODE encode the proof byte-length.
    if ret > MAX_ERROR_CODE {
        buf.truncate(ret as usize);
        Ok(CycloProof(buf))
    } else {
        Err(map_error(ret))
    }
}

/// Verify a Cyclo ZK proof against public inputs.
///
/// Returns `Ok(true)` when the proof is valid, `Ok(false)` when it is structurally
/// valid but the statement does not hold, and `Err` on an internal protocol error.
pub fn verify(public_inputs: &[u64], proof: &CycloProof) -> Result<bool> {
    let ret = unsafe {
        ffi::cyclo_verify(
            public_inputs.as_ptr(),
            public_inputs.len(),
            proof.0.as_ptr(),
            proof.0.len(),
        )
    };

    match ret {
        1 => Ok(true),
        0 => Ok(false),
        code => Err(map_error(code)),
    }
}

/// Returns the nominal security level (in bits) of the embedded Cyclo parameters.
///
/// Always 128 for the VELA preset (N=128, Q=1125899906839937).
pub fn security_bits() -> f64 {
    unsafe { ffi::cyclo_security_bits() }
}
