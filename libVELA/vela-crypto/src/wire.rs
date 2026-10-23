//! Exact fixed-width wire arithmetic used by the signed share envelope.
//! Primitive integer/slice semantics are trusted; these are application codec
//! contracts, not cryptographic security assumptions.

#[cfg_attr(hax, hax_lib::ensures(|result| {
    result == (bytes[0] as u64) * 72_057_594_037_927_936
        + (bytes[1] as u64) * 281_474_976_710_656
        + (bytes[2] as u64) * 1_099_511_627_776
        + (bytes[3] as u64) * 4_294_967_296
        + (bytes[4] as u64) * 16_777_216
        + (bytes[5] as u64) * 65_536
        + (bytes[6] as u64) * 256 + bytes[7] as u64
}))]
pub fn decode_u64_be(bytes: [u8; 8]) -> u64 {
    let n = bytes[0] as u64;
    let n = n * 256 + bytes[1] as u64;
    let n = n * 256 + bytes[2] as u64;
    let n = n * 256 + bytes[3] as u64;
    let n = n * 256 + bytes[4] as u64;
    let n = n * 256 + bytes[5] as u64;
    let n = n * 256 + bytes[6] as u64;
    n * 256 + bytes[7] as u64
}

/// Quotient/remainder step used to build a byte encoding without overflow.
#[cfg_attr(hax, hax_lib::ensures(|parts| {
    parts.0 == value / 256 && parts.1 as u64 == value % 256
        && value == parts.0 * 256 + parts.1 as u64
}))]
pub fn split_low_byte(value: u64) -> (u64, u8) {
    (value / 256, (value % 256) as u8)
}

#[cfg_attr(hax, hax_lib::ensures(|bytes| {
    decode_u64_be([bytes[0], bytes[1], bytes[2], bytes[3],
                   bytes[4], bytes[5], bytes[6], bytes[7]]) == value
}))]
pub fn encode_u64_be(value: u64) -> [u8; 8] {
    let (n, b7) = split_low_byte(value);
    let (n, b6) = split_low_byte(n);
    let (n, b5) = split_low_byte(n);
    let (n, b4) = split_low_byte(n);
    let (n, b3) = split_low_byte(n);
    let (n, b2) = split_low_byte(n);
    let (n, b1) = split_low_byte(n);
    [n as u8, b1, b2, b3, b4, b5, b6, b7]
}

#[cfg_attr(hax, hax_lib::ensures(|result| result))]
pub fn u64_wire_round_trip(value: u64) -> bool {
    decode_u64_be(encode_u64_be(value)) == value
}

#[cfg_attr(hax, hax_lib::ensures(|result| result))]
pub fn u64_wire_encoding_is_injective(left: u64, right: u64) -> bool {
    let _ = u64_wire_round_trip(left);
    let _ = u64_wire_round_trip(right);
    encode_u64_be(left) != encode_u64_be(right) || left == right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_arithmetic_matches_standard_big_endian_encoding() {
        for value in [
            0,
            1,
            255,
            256,
            65_535,
            65_536,
            0x0102_0304_0506_0708,
            u64::MAX,
        ] {
            assert_eq!(encode_u64_be(value), value.to_be_bytes());
            assert_eq!(decode_u64_be(value.to_be_bytes()), value);
        }
        assert_eq!(
            decode_u64_be([1, 2, 3, 4, 5, 6, 7, 8]),
            0x0102_0304_0506_0708
        );
    }
}
