//! Shamir's Secret Sharing over GF(2^8) with the AES irreducible polynomial.
//!
//! VELA uses a 2-of-3 scheme to split the 32-byte Root Master Seed:
//!   Share 1 → cloud provider backup
//!   Share 2 → VELA server (encrypted under FIDO2-bound key)
//!   Share 3 → trusted contact
//!
//! Each byte of the secret is shared independently using a degree-(threshold-1)
//! polynomial over GF(2^8).  Shares are represented as (x, y_0, y_1, …, y_31)
//! where x is a non-zero field element used as the evaluation point.

use crate::error::{Result, VelaError};

// ── GF(2^8) arithmetic ────────────────────────────────────────────────────────
// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1  (0x11b, AES field)

const POLY: u16 = 0x11b;

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= (POLY & 0xff) as u8;
        }
        b >>= 1;
    }
    result
}

fn gf_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut result: u8 = 1;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(2^8) via Fermat: a^(2^8 - 2) = a^254.
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "inverse of zero is undefined");
    gf_pow(a, 254)
}

fn gf_div(a: u8, b: u8) -> u8 {
    debug_assert!(b != 0, "division by zero");
    gf_mul(a, gf_inv(b))
}

// ── Share type ─────────────────────────────────────────────────────────────────

/// A single Shamir share: an x-coordinate and one y-value per secret byte.
#[derive(Clone, Debug)]
pub struct Share {
    /// Non-zero evaluation point (1..=255).
    pub x: u8,
    /// y-coordinates, one per byte of the secret.
    pub y: Vec<u8>,
}

impl Share {
    /// Serialize to `[x, y_0, y_1, …, y_{n-1}]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.y.len());
        out.push(self.x);
        out.extend_from_slice(&self.y);
        out
    }

    /// Deserialize from bytes produced by [`Share::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(VelaError::ShamirError("share too short".into()));
        }
        let x = bytes[0];
        if x == 0 {
            return Err(VelaError::ShamirError("x-coordinate must be non-zero".into()));
        }
        Ok(Self { x, y: bytes[1..].to_vec() })
    }
}

// ── Split ─────────────────────────────────────────────────────────────────────

/// Split `secret` into `n` shares requiring `threshold` to reconstruct.
///
/// `threshold` must be in `[2, n]` and `n` must be ≤ 255.
pub fn split(secret: &[u8], threshold: u8, n: u8) -> Result<Vec<Share>> {
    if threshold < 2 {
        return Err(VelaError::ShamirError("threshold must be ≥ 2".into()));
    }
    if n < threshold {
        return Err(VelaError::ShamirError("n must be ≥ threshold".into()));
    }
    if secret.is_empty() {
        return Err(VelaError::ShamirError("secret must not be empty".into()));
    }

    use rand_core::{OsRng, RngCore};

    let k = threshold as usize;
    let secret_len = secret.len();

    // For each secret byte, generate a random degree-(k-1) polynomial with
    // f(0) = secret[i].  Coefficients are [secret[i], a_1, …, a_{k-1}].
    let mut coefficients: Vec<Vec<u8>> = Vec::with_capacity(secret_len);
    for &s in secret {
        let mut poly = vec![0u8; k];
        poly[0] = s;
        OsRng.fill_bytes(&mut poly[1..]);
        coefficients.push(poly);
    }

    // Evaluate each polynomial at x = 1, 2, …, n.
    let shares: Vec<Share> = (1..=n)
        .map(|x| {
            let y: Vec<u8> = coefficients
                .iter()
                .map(|poly| eval_poly(poly, x))
                .collect();
            Share { x, y }
        })
        .collect();

    Ok(shares)
}

/// Evaluate polynomial (coefficients in ascending degree order) at `x` in GF(2^8).
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = gf_mul(result, x) ^ c;
    }
    result
}

// ── Reconstruct ───────────────────────────────────────────────────────────────

/// Reconstruct the secret from `threshold` or more shares via Lagrange interpolation.
pub fn reconstruct(shares: &[Share], secret_len: usize) -> Result<Vec<u8>> {
    if shares.len() < 2 {
        return Err(VelaError::InsufficientShares {
            need: 2,
            got: shares.len(),
        });
    }
    // Validate x-coordinates are distinct and y-lengths match.
    for s in shares {
        if s.y.len() != secret_len {
            return Err(VelaError::ShamirError(format!(
                "share y-length mismatch: expected {secret_len}, got {}",
                s.y.len()
            )));
        }
    }
    let xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    for i in 0..xs.len() {
        for j in (i + 1)..xs.len() {
            if xs[i] == xs[j] {
                return Err(VelaError::ShamirError(
                    "duplicate x-coordinates in shares".into(),
                ));
            }
        }
    }

    let mut secret = vec![0u8; secret_len];
    for byte_idx in 0..secret_len {
        secret[byte_idx] = lagrange_interpolate_at_zero(
            &shares.iter().map(|s| (s.x, s.y[byte_idx])).collect::<Vec<_>>(),
        );
    }
    Ok(secret)
}

/// Lagrange interpolation at x=0 for a set of (x, y) points in GF(2^8).
fn lagrange_interpolate_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut result = 0u8;
    let n = points.len();
    for i in 0..n {
        let (xi, yi) = points[i];
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..n {
            if i == j {
                continue;
            }
            let (xj, _) = points[j];
            // numerator *= (0 - xj) = xj  (since -a = a in GF(2^8))
            num = gf_mul(num, xj);
            // denominator *= (xi - xj) = xi ^ xj
            den = gf_mul(den, xi ^ xj);
        }
        result ^= gf_mul(yi, gf_div(num, den));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const RMS: &[u8] = b"super secret 32-byte rms seed!!!";

    #[test]
    fn split_and_reconstruct_2of3() {
        let shares = split(RMS, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 shares should reconstruct correctly.
        let recovered = reconstruct(&shares[0..2], RMS.len()).unwrap();
        assert_eq!(recovered, RMS);

        let recovered = reconstruct(&shares[1..3], RMS.len()).unwrap();
        assert_eq!(recovered, RMS);

        let recovered = reconstruct(&[shares[0].clone(), shares[2].clone()], RMS.len()).unwrap();
        assert_eq!(recovered, RMS);
    }

    #[test]
    fn all_three_shares_also_reconstruct() {
        let shares = split(RMS, 2, 3).unwrap();
        let recovered = reconstruct(&shares, RMS.len()).unwrap();
        assert_eq!(recovered, RMS);
    }

    #[test]
    fn single_share_is_insufficient() {
        let shares = split(RMS, 2, 3).unwrap();
        assert!(reconstruct(&shares[0..1], RMS.len()).is_err());
    }

    #[test]
    fn serialization_roundtrip() {
        let shares = split(RMS, 2, 3).unwrap();
        let bytes: Vec<Vec<u8>> = shares.iter().map(|s| s.to_bytes()).collect();
        let parsed: Vec<Share> = bytes
            .iter()
            .map(|b| Share::from_bytes(b).unwrap())
            .collect();
        let recovered = reconstruct(&parsed[0..2], RMS.len()).unwrap();
        assert_eq!(recovered, RMS);
    }

    #[test]
    fn split_3of5() {
        let shares = split(RMS, 3, 5).unwrap();
        // 3 shares → success
        let r = reconstruct(&shares[0..3], RMS.len()).unwrap();
        assert_eq!(r, RMS);
        // 2 shares → wrong result (not an error per SSS, just wrong value)
        let r2 = reconstruct(&shares[0..2], RMS.len()).unwrap();
        assert_ne!(r2, RMS, "2 shares must not reconstruct the secret in a 3-of-5 scheme");
    }

    #[test]
    fn gf_mul_commutativity() {
        assert_eq!(gf_mul(7, 13), gf_mul(13, 7));
    }

    #[test]
    fn gf_inv_correctness() {
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1);
        }
    }
}
