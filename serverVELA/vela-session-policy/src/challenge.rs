//! Pure classification of the purpose tag stored beside a single-use challenge.
//!
//! `GET /auth/challenge` writes one of three short ASCII tags into sled under
//! `challenge:<nonce>`. Every consumer (`/auth/verify`, `/device/enroll`,
//! `/web-session/:id/token`) removes the value with `Store::get_del` and then
//! must decide whether the exact stored bytes were issued for its own purpose.
//! That decision lives here so hax extracts it; the handler only performs the
//! effectful take and renders the resulting category.
//!
//! The stored tag is represented as a bounded byte buffer rather than a slice
//! so the extracted function compares exact byte positions. `StoredTag::len`
//! records the real length: a value longer than [`MAX_CHALLENGE_TAG_LEN`] can
//! never equal a recognized tag and classifies as `Unknown` (and therefore as
//! the wrong purpose). `stored_tag_from_bytes` is the only conversion; its
//! nine loop-free, bounds-checked reads and retained length are extracted and
//! checked in F*, which proves the copied prefix is exact and that a long value
//! cannot alias a short tag.

/// Longest recognized purpose tag (`web_token`).
pub const MAX_CHALLENGE_TAG_LEN: usize = 9;

/// What a challenge may be redeemed for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengePurpose {
    /// `POST /auth/verify`.
    Login,
    /// `POST /device/enroll`.
    Enroll,
    /// `POST /web-session/:id/token`.
    WebToken,
}

/// The bounded raw bytes stored under a challenge key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredTag {
    /// Actual stored length. May exceed `MAX_CHALLENGE_TAG_LEN`; such a value
    /// never matches a recognized tag.
    pub len: usize,
    /// First `min(len, MAX_CHALLENGE_TAG_LEN)` bytes, zero-padded.
    pub bytes: [u8; MAX_CHALLENGE_TAG_LEN],
}

/// Exact recognition of a stored tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagClass {
    Recognized(ChallengePurpose),
    Unknown,
}

/// The decision after the atomic challenge take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeConsumption {
    /// The nonce was present and carried exactly this consumer's purpose tag.
    Accepted,
    /// The nonce was absent, expired or already spent.
    Missing,
    /// The nonce was present but carried another purpose (or an unrecognized
    /// value). The take already removed it, so it is spent.
    WrongPurpose,
}

/// The exact bytes `GET /auth/challenge` stores for `purpose`.
pub fn purpose_tag_bytes(purpose: ChallengePurpose) -> &'static [u8] {
    match purpose {
        ChallengePurpose::Login => b"login",
        ChallengePurpose::Enroll => b"enroll",
        ChallengePurpose::WebToken => b"web_token",
    }
}

/// The bounded representation of `purpose_tag_bytes(purpose)`.
pub fn purpose_stored_tag(purpose: ChallengePurpose) -> StoredTag {
    match purpose {
        ChallengePurpose::Login => StoredTag {
            len: 5,
            bytes: [b'l', b'o', b'g', b'i', b'n', 0, 0, 0, 0],
        },
        ChallengePurpose::Enroll => StoredTag {
            len: 6,
            bytes: [b'e', b'n', b'r', b'o', b'l', b'l', 0, 0, 0],
        },
        ChallengePurpose::WebToken => StoredTag {
            len: 9,
            bytes: [b'w', b'e', b'b', b'_', b't', b'o', b'k', b'e', b'n'],
        },
    }
}

/// The byte at `index` when the raw value is long enough, zero otherwise.
/// Each call is an explicit bounds test plus a checked slice read, so the
/// unrolled copy below never indexes out of bounds and the extracted body is a
/// pure conditional rather than a loop.
fn byte_or_zero(bytes: &[u8], index: usize) -> u8 {
    if index < bytes.len() {
        bytes[index]
    } else {
        0
    }
}

/// Structural contract of the bounded copy, stated over the raw slice: the
/// real length is preserved and each of the nine buffer positions holds the raw
/// byte at that position when the raw value reaches it, and zero otherwise.
/// The comparisons and index reads are written out explicitly rather than by
/// calling [`byte_or_zero`], so the contract does not restate the helper used
/// by the implementation.
pub fn stored_tag_copies_prefix(tag: StoredTag, bytes: &[u8]) -> bool {
    tag.len == bytes.len()
        && tag.bytes[0] == (if bytes.len() > 0 { bytes[0] } else { 0 })
        && tag.bytes[1] == (if bytes.len() > 1 { bytes[1] } else { 0 })
        && tag.bytes[2] == (if bytes.len() > 2 { bytes[2] } else { 0 })
        && tag.bytes[3] == (if bytes.len() > 3 { bytes[3] } else { 0 })
        && tag.bytes[4] == (if bytes.len() > 4 { bytes[4] } else { 0 })
        && tag.bytes[5] == (if bytes.len() > 5 { bytes[5] } else { 0 })
        && tag.bytes[6] == (if bytes.len() > 6 { bytes[6] } else { 0 })
        && tag.bytes[7] == (if bytes.len() > 7 { bytes[7] } else { 0 })
        && tag.bytes[8] == (if bytes.len() > 8 { bytes[8] } else { 0 })
}

/// Copy the stored bytes into the bounded representation. Bytes past
/// `MAX_CHALLENGE_TAG_LEN` are not copied but the real length is retained, so
/// the classifier cannot mistake a truncated long value for a short tag. The
/// nine reads are unrolled so the extracted body is a single record literal;
/// the checked `ensures` states the exact prefix and length relation hax then
/// proves against that body.
#[cfg_attr(hax, hax_lib::ensures(|tag| stored_tag_copies_prefix(tag, bytes)))]
pub fn stored_tag_from_bytes(bytes: &[u8]) -> StoredTag {
    StoredTag {
        len: bytes.len(),
        bytes: [
            byte_or_zero(bytes, 0),
            byte_or_zero(bytes, 1),
            byte_or_zero(bytes, 2),
            byte_or_zero(bytes, 3),
            byte_or_zero(bytes, 4),
            byte_or_zero(bytes, 5),
            byte_or_zero(bytes, 6),
            byte_or_zero(bytes, 7),
            byte_or_zero(bytes, 8),
        ],
    }
}

/// Structural recognition equality over the *significant* stored bytes.
/// Padding past `len` is not part of the stored value and is ignored; the
/// three recognized lengths are 5, 6 and 9. Written without derived
/// `PartialEq` so the hax translation is an explicit conjunction.
pub fn same_stored_tag(a: StoredTag, b: StoredTag) -> bool {
    a.len == b.len
        && (a.len != 5
            || (a.bytes[0] == b.bytes[0]
                && a.bytes[1] == b.bytes[1]
                && a.bytes[2] == b.bytes[2]
                && a.bytes[3] == b.bytes[3]
                && a.bytes[4] == b.bytes[4]))
        && (a.len != 6
            || (a.bytes[0] == b.bytes[0]
                && a.bytes[1] == b.bytes[1]
                && a.bytes[2] == b.bytes[2]
                && a.bytes[3] == b.bytes[3]
                && a.bytes[4] == b.bytes[4]
                && a.bytes[5] == b.bytes[5]))
        && (a.len != 9
            || (a.bytes[0] == b.bytes[0]
                && a.bytes[1] == b.bytes[1]
                && a.bytes[2] == b.bytes[2]
                && a.bytes[3] == b.bytes[3]
                && a.bytes[4] == b.bytes[4]
                && a.bytes[5] == b.bytes[5]
                && a.bytes[6] == b.bytes[6]
                && a.bytes[7] == b.bytes[7]
                && a.bytes[8] == b.bytes[8]))
}

pub fn stored_tag_matches_purpose(tag: StoredTag, purpose: ChallengePurpose) -> bool {
    same_stored_tag(tag, purpose_stored_tag(purpose))
}

pub fn same_purpose(a: ChallengePurpose, b: ChallengePurpose) -> bool {
    matches!(
        (a, b),
        (ChallengePurpose::Login, ChallengePurpose::Login)
            | (ChallengePurpose::Enroll, ChallengePurpose::Enroll)
            | (ChallengePurpose::WebToken, ChallengePurpose::WebToken)
    )
}

/// Independent Rust restatement of exact recognition. The hand-written F*
/// module additionally proves this against literal byte values, not against
/// this predicate.
pub fn classification_matches_spec(tag: StoredTag, class: TagClass) -> bool {
    match class {
        TagClass::Recognized(purpose) => stored_tag_matches_purpose(tag, purpose),
        TagClass::Unknown => {
            !stored_tag_matches_purpose(tag, ChallengePurpose::Login)
                && !stored_tag_matches_purpose(tag, ChallengePurpose::Enroll)
                && !stored_tag_matches_purpose(tag, ChallengePurpose::WebToken)
        }
    }
}

/// Recognize the exact stored bytes. A tag is accepted only if its length and
/// all significant bytes equal one of the three issued tags.
#[cfg_attr(hax, hax_lib::ensures(|class| classification_matches_spec(tag, class)))]
pub fn classify_stored_tag(tag: StoredTag) -> TagClass {
    if same_stored_tag(tag, purpose_stored_tag(ChallengePurpose::Login)) {
        TagClass::Recognized(ChallengePurpose::Login)
    } else if same_stored_tag(tag, purpose_stored_tag(ChallengePurpose::Enroll)) {
        TagClass::Recognized(ChallengePurpose::Enroll)
    } else if same_stored_tag(tag, purpose_stored_tag(ChallengePurpose::WebToken)) {
        TagClass::Recognized(ChallengePurpose::WebToken)
    } else {
        TagClass::Unknown
    }
}

/// Independent Rust restatement of the consumption decision.
pub fn consumption_matches_spec(
    stored: Option<StoredTag>,
    expected: ChallengePurpose,
    decision: ChallengeConsumption,
) -> bool {
    match decision {
        ChallengeConsumption::Accepted => match stored {
            Some(tag) => match classify_stored_tag(tag) {
                TagClass::Recognized(actual) => same_purpose(actual, expected),
                TagClass::Unknown => false,
            },
            None => false,
        },
        ChallengeConsumption::Missing => matches!(stored, None),
        ChallengeConsumption::WrongPurpose => match stored {
            None => false,
            Some(tag) => match classify_stored_tag(tag) {
                TagClass::Recognized(actual) => !same_purpose(actual, expected),
                TagClass::Unknown => true,
            },
        },
    }
}

/// Classify the value returned by the atomic take. The take has already
/// removed the key, so every `Some` outcome (accepted or wrong purpose) spends
/// the nonce.
#[cfg_attr(hax, hax_lib::ensures(|decision| {
    consumption_matches_spec(stored, expected, decision)
}))]
pub fn classify_consumption(
    stored: Option<StoredTag>,
    expected: ChallengePurpose,
) -> ChallengeConsumption {
    match stored {
        None => ChallengeConsumption::Missing,
        Some(tag) => match classify_stored_tag(tag) {
            TagClass::Recognized(actual) => {
                if same_purpose(actual, expected) {
                    ChallengeConsumption::Accepted
                } else {
                    ChallengeConsumption::WrongPurpose
                }
            }
            TagClass::Unknown => ChallengeConsumption::WrongPurpose,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_issued_tags_are_recognized() {
        for purpose in [
            ChallengePurpose::Login,
            ChallengePurpose::Enroll,
            ChallengePurpose::WebToken,
        ] {
            let tag = purpose_stored_tag(purpose);
            assert_eq!(tag.len, purpose_tag_bytes(purpose).len());
            assert_eq!(
                &tag.bytes[..tag.len],
                purpose_tag_bytes(purpose),
                "{purpose:?}"
            );
            assert_eq!(
                classify_stored_tag(tag),
                TagClass::Recognized(purpose),
                "{purpose:?}"
            );
            assert_eq!(
                classify_consumption(Some(tag), purpose),
                ChallengeConsumption::Accepted
            );
        }
    }

    #[test]
    fn bytes_roundtrip_matches_the_issued_tag() {
        for purpose in [
            ChallengePurpose::Login,
            ChallengePurpose::Enroll,
            ChallengePurpose::WebToken,
        ] {
            let bytes = purpose_tag_bytes(purpose);
            let tag = stored_tag_from_bytes(bytes);
            assert_eq!(tag, purpose_stored_tag(purpose));
            assert_eq!(classify_stored_tag(tag), TagClass::Recognized(purpose));
        }
    }

    #[test]
    fn producer_retains_length_and_exact_prefix_for_every_length() {
        let raw: [u8; 12] = [
            b'l', b'o', b'g', b'i', b'n', b'x', b'y', b'z', b'q', b'r', b's', b't',
        ];
        for len in 0..=raw.len() {
            let bytes = &raw[..len];
            let tag = stored_tag_from_bytes(bytes);
            assert!(stored_tag_copies_prefix(tag, bytes), "len {len}");
            assert_eq!(tag.len, len);
            for i in 0..MAX_CHALLENGE_TAG_LEN {
                let expected = if i < len { bytes[i] } else { 0 };
                assert_eq!(tag.bytes[i], expected, "len {len} position {i}");
            }
            if len != 5 {
                assert_eq!(classify_stored_tag(tag), TagClass::Unknown, "len {len}");
            }
        }
    }

    #[test]
    fn producer_preserves_long_input_length_so_it_cannot_alias() {
        let tag = stored_tag_from_bytes(b"login-extra");
        assert_eq!(tag.len, 11);
        assert_eq!(tag.bytes, *b"login-ext");
        assert_ne!(tag, purpose_stored_tag(ChallengePurpose::Login));
        assert_eq!(
            classify_consumption(Some(tag), ChallengePurpose::Login),
            ChallengeConsumption::WrongPurpose
        );

        for padding in 1..8 {
            let mut bytes = b"login".to_vec();
            bytes.resize(5 + padding, b'!');
            let tag = stored_tag_from_bytes(&bytes);
            assert_eq!(tag.len, 5 + padding);
            assert_ne!(tag, purpose_stored_tag(ChallengePurpose::Login));
            assert_eq!(classify_stored_tag(tag), TagClass::Unknown);
        }
    }

    #[test]
    fn producer_contract_rejects_corrupted_and_truncated_values() {
        // Every one-byte corruption of a recognized literal must break both the
        // structural contract and recognition.
        for purpose in [
            ChallengePurpose::Login,
            ChallengePurpose::Enroll,
            ChallengePurpose::WebToken,
        ] {
            let issued = purpose_tag_bytes(purpose);
            for position in 0..issued.len() {
                let mut corrupted = issued.to_vec();
                corrupted[position] ^= 1;
                let tag = stored_tag_from_bytes(&corrupted);
                assert!(!stored_tag_copies_prefix(tag, issued));
                assert_eq!(classify_stored_tag(tag), TagClass::Unknown);
            }

            // A truncation is never the issued tag: the length is retained.
            for cut in 0..issued.len() {
                let tag = stored_tag_from_bytes(&issued[..cut]);
                assert_eq!(tag.len, cut);
                assert_eq!(classify_stored_tag(tag), TagClass::Unknown);
            }
        }
    }

    #[test]
    fn every_cross_purpose_presentation_is_wrong_and_spends() {
        for stored in [
            ChallengePurpose::Login,
            ChallengePurpose::Enroll,
            ChallengePurpose::WebToken,
        ] {
            for expected in [
                ChallengePurpose::Login,
                ChallengePurpose::Enroll,
                ChallengePurpose::WebToken,
            ] {
                let decision = classify_consumption(Some(purpose_stored_tag(stored)), expected);
                if stored == expected {
                    assert_eq!(decision, ChallengeConsumption::Accepted);
                } else {
                    assert_eq!(decision, ChallengeConsumption::WrongPurpose);
                }
            }
        }
    }

    #[test]
    fn one_byte_or_length_mutation_is_unknown() {
        for purpose in [
            ChallengePurpose::Login,
            ChallengePurpose::Enroll,
            ChallengePurpose::WebToken,
        ] {
            let tag = purpose_stored_tag(purpose);
            for position in 0..tag.len {
                let mut bytes = tag.bytes;
                bytes[position] ^= 1;
                let mutated = StoredTag {
                    len: tag.len,
                    bytes,
                };
                assert_eq!(classify_stored_tag(mutated), TagClass::Unknown);
                assert_eq!(
                    classify_consumption(Some(mutated), purpose),
                    ChallengeConsumption::WrongPurpose
                );
            }

            let short = StoredTag {
                len: tag.len - 1,
                bytes: tag.bytes,
            };
            assert_eq!(classify_stored_tag(short), TagClass::Unknown);
        }

        let long = stored_tag_from_bytes(b"login-extra");
        assert_eq!(long.len, 11);
        assert_eq!(classify_stored_tag(long), TagClass::Unknown);
    }

    #[test]
    fn padding_past_the_stored_length_is_not_significant() {
        let login = purpose_stored_tag(ChallengePurpose::Login);
        let mut padded = login.bytes;
        padded[5] = 0xaa;
        padded[8] = 0x55;
        let tag = StoredTag {
            len: login.len,
            bytes: padded,
        };
        assert_eq!(
            classify_stored_tag(tag),
            TagClass::Recognized(ChallengePurpose::Login)
        );

        // A significant byte still matters.
        let mut changed = login.bytes;
        changed[4] ^= 1;
        assert_eq!(
            classify_stored_tag(StoredTag {
                len: login.len,
                bytes: changed
            }),
            TagClass::Unknown
        );
    }

    #[test]
    fn absent_tag_is_missing_not_wrong_purpose() {
        assert_eq!(
            classify_consumption(None, ChallengePurpose::Login),
            ChallengeConsumption::Missing
        );
    }

    #[test]
    fn unknown_and_cross_purpose_tags_never_accept() {
        let mut bytes = purpose_stored_tag(ChallengePurpose::WebToken).bytes;
        bytes[8] = b'x';
        let tag = StoredTag { len: 9, bytes };
        for expected in [
            ChallengePurpose::Login,
            ChallengePurpose::Enroll,
            ChallengePurpose::WebToken,
        ] {
            assert_eq!(
                classify_consumption(Some(tag), expected),
                ChallengeConsumption::WrongPurpose
            );
        }
    }
}
