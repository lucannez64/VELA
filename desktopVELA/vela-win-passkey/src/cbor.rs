//! Minimal CBOR encoding — enough to build the `authenticatorGetInfo` blob
//! the platform requires at registration (webauthnplugin.h:
//! "CTAP CBOR encoded authenticatorGetInfo").
//!
//! Deliberately *not* a general CBOR library: the desktop already builds its
//! own attestation CBOR in `vela-desktop-core::passkey`, and importing a
//! dependency to emit one fixed map buys nothing. Structure pinned by unit
//! test against the CTAP2 spec's canonical encoding.

/// Append a CBOR map header with `n` pairs.
pub fn map(out: &mut Vec<u8>, n: usize) {
    major(out, 5, n as u64);
}

/// Append a CBOR array header with `n` items.
pub fn array(out: &mut Vec<u8>, n: usize) {
    major(out, 4, n as u64);
}

/// Append an unsigned or negative integer (COSE uses negative labels).
pub fn integer(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        major(out, 0, value as u64);
    } else {
        major(out, 1, (-1 - value) as u64);
    }
}

pub fn text(out: &mut Vec<u8>, value: &str) {
    major(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

pub fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    major(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

pub fn bool(out: &mut Vec<u8>, value: bool) {
    out.push(if value { 0xF5 } else { 0xF4 });
}

fn major(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    if value < 24 {
        out.push(m | value as u8);
    } else if value <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sample map from CTAP2 §6 (a trimmed reference for our fixed shape):
    /// {"a": 1, "b": [-7, "x"], 3: h'0102', 4: {"up": true}}
    #[test]
    fn encodes_canonical_ctap_shapes() {
        let mut buf = Vec::new();
        map(&mut buf, 4);
        text(&mut buf, "a");
        integer(&mut buf, 1);
        text(&mut buf, "b");
        array(&mut buf, 2);
        integer(&mut buf, -7);
        text(&mut buf, "x");
        integer(&mut buf, 3);
        bytes(&mut buf, &[0x01, 0x02]);
        integer(&mut buf, 4);
        map(&mut buf, 1);
        text(&mut buf, "up");
        bool(&mut buf, true);

        assert_eq!(
            buf,
            vec![
                0xA4, // map(4)
                0x61, b'a', 0x01, // "a": 1
                0x61, b'b', 0x82, 0x26, 0x61, b'x', // "b": [-7, "x"] (-7 => 0x26)
                0x03, 0x42, 0x01, 0x02, // 3: h'0102'
                0x04, 0xA1, 0x62, b'u', b'p', 0xF5, // 4: {"up": true}
            ]
        );
    }
}
