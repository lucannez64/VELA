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

/// Decode a fixed-width integer and its exact remaining input.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    if input.len() < 8 {
        matches!(result, None)
    } else {
        match result {
            Some((value, rest)) => value == decode_u64_be([
                input[0], input[1], input[2], input[3],
                input[4], input[5], input[6], input[7],
            ]) && rest == &input[8..],
            None => false,
        }
    }
}))]
pub fn split_u64_prefix(input: &[u8]) -> Option<(u64, &[u8])> {
    if input.len() < 8 {
        return None;
    }
    Some((
        decode_u64_be([
            input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
        ]),
        &input[8..],
    ))
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    match split_u64_prefix(input) {
        Some((value, rest)) => result == Some(value) && *future(input) == rest,
        None => matches!(result, None) && *future(input) == *input,
    }
}))]
pub fn take_u64(input: &mut &[u8]) -> Option<u64> {
    match split_u64_prefix(input) {
        Some((value, rest)) => {
            *input = rest;
            Some(value)
        }
        None => None,
    }
}

/// Parse a u64-length-prefixed field, returning its exact payload and remainder.
/// The length is checked before narrowing it to usize or indexing the payload.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    if input.len() < 8 {
        matches!(result, None)
    } else {
        let length = decode_u64_be([input[0], input[1], input[2], input[3],
                                   input[4], input[5], input[6], input[7]]);
        if length > (input.len() - 8) as u64 {
            matches!(result, None)
        } else {
            match result {
                Some((field, rest)) => field == &input[8..8 + length as usize]
                    && rest == &input[8 + length as usize..],
                None => false,
            }
        }
    }
}))]
pub fn split_length_prefixed(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.len() < 8 {
        return None;
    }
    let length = decode_u64_be([
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    ]);
    let payload = &input[8..];
    if length > payload.len() as u64 {
        return None;
    }
    let length = length as usize;
    Some((&payload[..length], &payload[length..]))
}

/// Stateful reader operation: successful reads consume exactly one field;
/// rejected reads preserve the cursor. Used directly by the envelope reader.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    match split_length_prefixed(*input) {
        Some((field, rest)) => result == Some(field) && *future(input) == rest,
        None => matches!(result, None) && *future(input) == *input,
    }
}))]
pub fn take_length_prefixed<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    match split_length_prefixed(input) {
        Some((field, rest)) => {
            *input = rest;
            Some(field)
        }
        None => None,
    }
}

/// Grammar combinators for two and four adjacent LP fields. The stateful
/// operations commit their cursor only after the complete group succeeds.
pub fn split_lp_pair(input: &[u8]) -> Option<((&[u8], &[u8]), &[u8])> {
    let (first, rest) = split_length_prefixed(input)?;
    let (second, rest) = split_length_prefixed(rest)?;
    Some(((first, second), rest))
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    match split_lp_pair(input) {
        Some(((first, second), tail)) => match result {
            Some((a, b)) => a == first && b == second && *future(input) == tail,
            None => false,
        },
        None => matches!(result, None) && *future(input) == *input,
    }
}))]
pub fn take_lp_pair<'a>(input: &mut &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    let mut rest = *input;
    let first = take_length_prefixed(&mut rest)?;
    let second = take_length_prefixed(&mut rest)?;
    *input = rest;
    Some((first, second))
}

pub fn split_lp_four(input: &[u8]) -> Option<(((&[u8], &[u8]), (&[u8], &[u8])), &[u8])> {
    let (first, rest) = split_lp_pair(input)?;
    let (second, rest) = split_lp_pair(rest)?;
    Some(((first, second), rest))
}

#[cfg_attr(hax, hax_lib::ensures(|result| {
    match split_lp_four(input) {
        Some((((a, b), (c, d)), tail)) => match result {
            Some(((w, x), (y, z))) => w == a && x == b && y == c && z == d
                && *future(input) == tail,
            None => false,
        },
        None => matches!(result, None) && *future(input) == *input,
    }
}))]
pub fn take_lp_four<'a>(
    input: &mut &'a [u8],
) -> Option<((&'a [u8], &'a [u8]), (&'a [u8], &'a [u8]))> {
    let mut rest = *input;
    let first = take_lp_pair(&mut rest)?;
    let second = take_lp_pair(&mut rest)?;
    *input = rest;
    Some((first, second))
}

/// Exact body between a fixed prefix and fixed trailer, without allocation.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    if input.len() < prefix_len || input.len() - prefix_len < trailer_len {
        matches!(result, None)
    } else {
        match result {
            Some(body) => body == &input[prefix_len..input.len() - trailer_len],
            None => false,
        }
    }
}))]
pub fn frame_body(input: &[u8], prefix_len: usize, trailer_len: usize) -> Option<&[u8]> {
    if input.len() < prefix_len || input.len() - prefix_len < trailer_len {
        None
    } else {
        Some(&input[prefix_len..input.len() - trailer_len])
    }
}

/// Domain prefix followed by the exact received body. Reject capacities above
/// Rust's byte-vector limit before doing length arithmetic or appending.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    let maximum = isize::MAX as usize;
    match result {
        Some(message) => domain.len() <= maximum && body.len() <= maximum - domain.len()
            && message.len() == domain.len() + body.len()
            && &message.as_slice()[..domain.len()] == domain
            && &message.as_slice()[domain.len()..] == body,
        None => domain.len() > maximum || body.len() > maximum - domain.len(),
    }
}))]
#[cfg_attr(hax, hax_lib::fstar::options("--fuel 2 --ifuel 2"))]
pub fn domain_message(domain: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    let maximum = isize::MAX as usize;
    if domain.len() > maximum || body.len() > maximum - domain.len() {
        return None;
    }
    let mut message = Vec::new();
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_boundaries_preserve_binary_bytes_and_reject_short_frames() {
        let domain = b"d\0\xff";
        let frame = [0xaa, 0, 0xfe, 0xff, 0xbb];
        let body = frame_body(&frame, 1, 1).unwrap();
        assert_eq!(
            domain_message(domain, body).unwrap(),
            [b'd', 0, 0xff, 0, 0xfe, 0xff]
        );
        assert_eq!(frame_body(&frame, 5, 0), Some(&[][..]));
        assert_eq!(frame_body(&frame, 0, 5), Some(&[][..]));
        assert_eq!(frame_body(&frame, 5, 1), None);
        assert_eq!(frame_body(&frame, usize::MAX, 1), None);
        assert_eq!(frame_body(&frame, 1, usize::MAX), None);
        assert_eq!(frame_body(&[], 0, 0), Some(&[][..]));
        assert_eq!(domain_message(&[], &[]), Some(Vec::new()));
    }

    #[test]
    fn length_prefix_rejects_truncation_and_preserves_the_exact_remainder() {
        for n in 0..8 {
            assert!(split_length_prefixed(&[0; 8][..n]).is_none());
        }
        let framed = [0, 0, 0, 0, 0, 0, 0, 3, 0xaa, 0xbb, 0xcc, 0xdd];
        assert_eq!(
            split_length_prefixed(&framed),
            Some((&framed[8..11], &framed[11..]))
        );
        assert!(split_length_prefixed(&framed[..10]).is_none());
        assert_eq!(split_length_prefixed(&[0; 8]), Some((&[][..], &[][..])));
        assert!(split_length_prefixed(&u64::MAX.to_be_bytes()).is_none());
        let exceeds_32_bit = 0x1_0000_0000u64.to_be_bytes();
        assert!(split_length_prefixed(&exceeds_32_bit).is_none());
    }

    #[test]
    fn grouped_fields_do_not_commit_a_partial_cursor() {
        let one = [0, 0, 0, 0, 0, 0, 0, 1, b'a'];
        let mut cursor = one.as_slice();
        assert!(take_lp_pair(&mut cursor).is_none());
        assert_eq!(cursor, one.as_slice());
        let encoded = [0, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 0, 0, 0, 0, 0, 1, b'b'];
        let mut cursor = encoded.as_slice();
        assert!(take_lp_four(&mut cursor).is_none());
        assert_eq!(cursor, encoded.as_slice());
        assert_eq!(take_lp_pair(&mut cursor), Some((&b"a"[..], &b"b"[..])));
        assert!(cursor.is_empty());
    }

    #[test]
    fn integer_cursor_reads_exactly_eight_bytes_and_preserves_failed_input() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 0xff];
        let mut cursor = bytes.as_slice();
        assert_eq!(take_u64(&mut cursor), Some(0x0102_0304_0506_0708));
        assert_eq!(cursor, &[0xff]);
        assert_eq!(take_u64(&mut cursor), None);
        assert_eq!(cursor, &[0xff]);
    }

    #[test]
    fn cursor_failure_is_atomic_and_adjacent_fields_stay_separate() {
        let encoded = [0, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 0, 0, 0, 0, 0, 1, b'b'];
        let mut cursor = encoded.as_slice();
        assert_eq!(take_length_prefixed(&mut cursor), Some(&b"a"[..]));
        assert_eq!(take_length_prefixed(&mut cursor), Some(&b"b"[..]));
        assert!(cursor.is_empty());
        for bytes in [&encoded[..7], &encoded[..8]] {
            let mut cursor = bytes;
            assert!(take_length_prefixed(&mut cursor).is_none());
            assert_eq!(cursor, bytes);
        }
    }

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
