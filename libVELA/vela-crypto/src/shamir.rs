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

/// Multiply in GF(2^8), in constant time.
///
/// Both operands are secret here — during a split they are polynomial
/// coefficients derived from the RMS, during reconstruction they are share
/// values — so the previous implementation leaked through two channels: the
/// loop ran `bit_length(b)` times, and both reduction steps were branches on
/// secret bits. An attacker able to observe cache or timing on the same machine
/// could narrow the operands.
///
/// This runs a fixed eight iterations and selects with masks instead of
/// branching. `(bit & 1).wrapping_neg()` is 0xFF when the bit is set and 0x00
/// otherwise, so `value & mask` is a branch-free conditional.
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut result: u8 = 0;
    for _ in 0..8 {
        let add = (b & 1).wrapping_neg();
        result ^= a & add;

        let overflow = ((a >> 7) & 1).wrapping_neg();
        a <<= 1;
        a ^= ((POLY & 0xff) as u8) & overflow;

        b >>= 1;
    }
    result
}

/// Exponentiate in GF(2^8), in constant time.
///
/// Uniform in the exponent as well as the base: the only caller passes a
/// constant (254), but a schedule that depends on the exponent is the kind of
/// thing that becomes a leak the moment someone reuses it.
fn gf_pow(base: u8, exp: u8) -> u8 {
    let mut result: u8 = 1;
    let mut base = base;
    let mut exp = exp;
    for _ in 0..8 {
        let multiply = (exp & 1).wrapping_neg();
        let product = gf_mul(result, base);
        result = (product & multiply) | (result & !multiply);

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
#[derive(Clone)]
pub struct Share {
    /// Non-zero evaluation point (1..=255).
    pub x: u8,
    /// y-coordinates, one per byte of the secret.
    pub y: Vec<u8>,
    /// Authentication tag over this share, keyed by the secret it belongs to.
    /// `None` for shares written before the tag existed.
    pub mac: Option<[u8; MAC_LEN]>,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("x", &self.x)
            .field("y", &"[REDACTED]")
            .field("mac", &self.mac.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Truncated BLAKE3 tag length. 16 bytes is far past what a share-swapping
/// attacker could brute-force, and keeps a printed share short.
pub const MAC_LEN: usize = 16;

/// Marker byte for the authenticated format. Legacy shares start with a
/// *non-zero* x-coordinate, so a leading zero cannot be mistaken for one.
const AUTHENTICATED_MARKER: u8 = 0x00;
const AUTHENTICATED_VERSION: u8 = 0x02;

/// Key the share tags with something only a holder of the reconstructed secret
/// can derive, so the tags reveal nothing to someone holding shares alone.
fn share_mac_key(secret: &[u8]) -> [u8; 32] {
    *crate::kdf::derive("vela shamir share authentication v1", secret).as_bytes()
}

fn share_mac(key: &[u8; 32], x: u8, y: &[u8]) -> [u8; MAC_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&[x]);
    hasher.update(y);
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&hasher.finalize().as_bytes()[..MAC_LEN]);
    tag
}

impl Share {
    /// Serialize.
    ///
    /// Authenticated: `[0x00, version, x, y…, mac]`.
    /// Legacy (no tag): `[x, y…]`, still emitted for a share that carries none.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.mac {
            Some(mac) => {
                let mut out = Vec::with_capacity(3 + self.y.len() + MAC_LEN);
                out.push(AUTHENTICATED_MARKER);
                out.push(AUTHENTICATED_VERSION);
                out.push(self.x);
                out.extend_from_slice(&self.y);
                out.extend_from_slice(&mac);
                out
            }
            None => {
                let mut out = Vec::with_capacity(1 + self.y.len());
                out.push(self.x);
                out.extend_from_slice(&self.y);
                out
            }
        }
    }

    /// Deserialize either format.
    ///
    /// Shares are held by users — printed, written down, stored in a cloud
    /// backup — so a share issued before authentication existed must keep
    /// working forever, not just through a migration window.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(VelaError::ShamirError("share too short".into()));
        }

        if bytes[0] == AUTHENTICATED_MARKER {
            if bytes.len() < 3 + 1 + MAC_LEN {
                return Err(VelaError::ShamirError(
                    "authenticated share too short".into(),
                ));
            }
            if bytes[1] != AUTHENTICATED_VERSION {
                return Err(VelaError::ShamirError(format!(
                    "unsupported share version {}",
                    bytes[1]
                )));
            }
            let x = bytes[2];
            if x == 0 {
                return Err(VelaError::ShamirError(
                    "x-coordinate must be non-zero".into(),
                ));
            }
            let body = &bytes[3..bytes.len() - MAC_LEN];
            let mut mac = [0u8; MAC_LEN];
            mac.copy_from_slice(&bytes[bytes.len() - MAC_LEN..]);
            return Ok(Self {
                x,
                y: body.to_vec(),
                mac: Some(mac),
            });
        }

        let x = bytes[0];
        if x == 0 {
            return Err(VelaError::ShamirError(
                "x-coordinate must be non-zero".into(),
            ));
        }
        Ok(Self {
            x,
            y: bytes[1..].to_vec(),
            mac: None,
        })
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

    // Evaluate each polynomial at x = 1, 2, …, n, and tag each share with a MAC
    // keyed by the secret. Reconstruction can then tell "these shares do not
    // belong together / one was altered" from "here is your key" — previously a
    // tampered share simply produced a different secret, silently (audit C-3).
    let mac_key = share_mac_key(secret);
    let shares: Vec<Share> = (1..=n)
        .map(|x| {
            let y: Vec<u8> = coefficients.iter().map(|poly| eval_poly(poly, x)).collect();
            let mac = share_mac(&mac_key, x, &y);
            Share {
                x,
                y,
                mac: Some(mac),
            }
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
            &shares
                .iter()
                .map(|s| (s.x, s.y[byte_idx]))
                .collect::<Vec<_>>(),
        );
    }

    // Verify every share that carries a tag. Without this, altering one share
    // (or combining shares from two different splits) yields a *different*
    // secret rather than an error — the caller then "recovers" into a vault it
    // cannot decrypt, or, with a server-supplied share, into a key the server
    // chose (audit C-3).
    let mac_key = share_mac_key(&secret);
    for share in shares.iter().filter(|share| share.mac.is_some()) {
        let expected = share_mac(&mac_key, share.x, &share.y);
        let presented = share.mac.expect("filtered to tagged shares");
        if !tags_equal(&expected, &presented) {
            return Err(VelaError::ShamirError(format!(
                "share {} failed authentication — it was altered, or these shares \
                 are from different splits",
                share.x
            )));
        }
    }

    Ok(secret)
}

/// Constant-time tag comparison: a caller feeding candidate shares must not
/// learn how many leading bytes of a tag matched.
fn tags_equal(a: &[u8; MAC_LEN], b: &[u8; MAC_LEN]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
    fn debug_redacts_share_material() {
        let share = Share {
            x: 7,
            y: vec![11, 22, 33],
            mac: Some([44; MAC_LEN]),
        };
        let debug = format!("{share:?}");
        assert!(debug.contains("x: 7"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("11"));
        assert!(!debug.contains("44"));
    }

    #[test]
    fn split_3of5() {
        let shares = split(RMS, 3, 5).unwrap();
        // 3 shares → success
        let r = reconstruct(&shares[0..3], RMS.len()).unwrap();
        assert_eq!(r, RMS);
        // 2 shares → refused. Plain SSS would hand back a *different* secret
        // here, indistinguishable from the real one; the tags turn that into an
        // error, which is what a user combining too few shares needs to see.
        assert!(
            reconstruct(&shares[0..2], RMS.len()).is_err(),
            "2 shares must not reconstruct the secret in a 3-of-5 scheme"
        );
    }

    /// Audit C-3: altering a share used to yield a different secret rather than
    /// an error — "recovery" into a vault that cannot be decrypted, or, with a
    /// server-supplied share, into a key the server chose.
    #[test]
    fn a_tampered_share_is_rejected_not_silently_wrong() {
        let shares = split(RMS, 2, 3).unwrap();

        let mut tampered = shares.clone();
        tampered[0].y[0] ^= 0x01;
        let error = reconstruct(&tampered[0..2], RMS.len()).expect_err("must not succeed");
        assert!(
            format!("{error}").contains("failed authentication"),
            "{error}"
        );

        // A swapped tag is caught too, not just altered data.
        let mut retagged = shares.clone();
        retagged[1].mac = Some([0u8; MAC_LEN]);
        assert!(reconstruct(&retagged[0..2], RMS.len()).is_err());
    }

    #[test]
    fn shares_from_different_splits_do_not_combine() {
        let first = split(RMS, 2, 3).unwrap();
        let second = split(RMS, 2, 3).unwrap();

        // Same secret, different polynomials: interpolation yields garbage, and
        // the tags say so instead of returning it.
        let mixed = vec![first[0].clone(), second[1].clone()];
        assert!(reconstruct(&mixed, RMS.len()).is_err());
    }

    /// Shares live on paper and in cloud backups. One issued before
    /// authentication existed has to keep working.
    #[test]
    fn legacy_untagged_shares_still_reconstruct() {
        let shares = split(RMS, 2, 3).unwrap();
        let legacy: Vec<Share> = shares
            .iter()
            .map(|share| Share {
                x: share.x,
                y: share.y.clone(),
                mac: None,
            })
            .collect();

        // Serialized in the old layout, and parsed back as untagged.
        let bytes = legacy[0].to_bytes();
        assert_eq!(bytes[0], legacy[0].x, "legacy layout starts with x");
        assert!(Share::from_bytes(&bytes).unwrap().mac.is_none());

        assert_eq!(reconstruct(&legacy[0..2], RMS.len()).unwrap(), RMS);
    }

    #[test]
    fn authenticated_shares_round_trip_through_bytes() {
        let shares = split(RMS, 2, 3).unwrap();
        let parsed: Vec<Share> = shares
            .iter()
            .map(|share| Share::from_bytes(&share.to_bytes()).unwrap())
            .collect();

        assert!(parsed.iter().all(|share| share.mac.is_some()));
        assert_eq!(reconstruct(&parsed[0..2], RMS.len()).unwrap(), RMS);
    }

    /// The reference implementation this file used to carry: variable-time, but
    /// known-correct. Kept here so the constant-time rewrite is checked against
    /// it exhaustively rather than by inspection.
    fn gf_mul_reference(mut a: u8, mut b: u8) -> u8 {
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

    #[test]
    fn constant_time_gf_mul_matches_the_reference_everywhere() {
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(gf_mul(a, b), gf_mul_reference(a, b), "gf_mul({a}, {b})");
            }
        }
    }

    #[test]
    fn gf_mul_matches_the_aes_field() {
        // The textbook AES vector for this polynomial (x^8 + x^4 + x^3 + x + 1).
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        assert_eq!(gf_mul(1, 0xab), 0xab);
        assert_eq!(gf_mul(0, 0xab), 0);
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
