//! Parsing OpenSSH private keys out of secure-note contents.
//!
//! Scope, deliberately narrow for v1: **unencrypted OpenSSH-format keys,
//! `ssh-ed25519` only** — the `ssh-keygen` default and the modern standard.
//! Passphrase-protected keys are named in the error (re-export the key
//! without a passphrase — VELA's vault is already the encryption layer), and
//! RSA/ECDSA keys are named as unsupported rather than silently skipped.
//!
//! The vault never gains an SSH item type for this: keys live as secure
//! notes holding a `-----BEGIN OPENSSH PRIVATE KEY-----` block, which needs
//! no schema, sync, or UI changes, and is where people's keys already are.

use base64::Engine;
use ed25519_dalek::SigningKey;

/// A parsed key ready for the agent: the SSH wire-format public blob, the
/// comment to advertise, and the signing key.
pub struct SshPrivateKey {
    /// `string "ssh-ed25519" || string vk` — exactly what the agent lists
    /// and what a sign request echoes back.
    pub public_blob: Vec<u8>,
    pub comment: String,
    pub signing_key: SigningKey,
}

/// Extract every supported key from arbitrary note text. Unsupported key
/// blocks produce errors naming their type; a note with no key material
/// yields an empty list.
pub fn extract_keys(text: &str, fallback_comment: &str) -> Result<Vec<SshPrivateKey>, String> {
    let mut keys = Vec::new();

    for (block_no, block) in extract_blocks(text).into_iter().enumerate() {
        let where_: String = if fallback_comment.is_empty() {
            format!("key #{block_no}")
        } else {
            format!("{fallback_comment}, key #{block_no}")
        };
        if let Some(parsed) = parse_block(&block, &where_)? {
            keys.push(parsed);
        }
    }
    Ok(keys)
}

/// Pull `-----BEGIN X-----…-----END X-----` PEM-style blocks out of text.
/// Only the OpenSSH private-key type is returned; other PEM types are
/// surfaced as named errors by the caller via the block header.
fn extract_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, Vec<&str>)> = None;

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let label = rest.trim_end_matches("-----").trim().to_string();
            current = Some((label, Vec::new()));
        } else if let Some(rest) = line.strip_prefix("-----END ") {
            if let Some((label, body)) = current.take() {
                let end_label = rest.trim_end_matches("-----").trim();
                if end_label.eq_ignore_ascii_case(&label) {
                    if label.eq_ignore_ascii_case("OPENSSH PRIVATE KEY") {
                        blocks.push(body.join("\n"));
                    } else {
                        // Non-OpenSSH PEM: surface a precise error rather
                        // than skipping silently — "my key didn't show up"
                        // is a worse bug report than "RSA is unsupported".
                        // Reported by the caller through parse_block.
                        blocks.push(format!("UNSUPPORTED_PEM:{label}"));
                    }
                }
                // Mismatched BEGIN/END: drop the block.
            }
        } else if let Some((_, body)) = current.as_mut() {
            if !line.is_empty() {
                body.push(line);
            }
        }
    }
    blocks
}

/// Parse one block. `Ok(None)` = unsupported PEM type already named in the
/// error path; `Err` = malformed OpenSSH key.
fn parse_block(block: &str, where_: &str) -> Result<Option<SshPrivateKey>, String> {
    if let Some(label) = block.strip_prefix("UNSUPPORTED_PEM:") {
        return Err(format!(
            "{where_}: {label} keys are not supported by the agent — \
             convert to OpenSSH ed25519 (`ssh-keygen -t ed25519`)"
        ));
    }

    let engine = base64::engine::general_purpose::STANDARD;
    let blob = engine
        .decode(block.replace(['\r', '\n'], ""))
        .map_err(|_| format!("{where_}: invalid base64 in the key body"))?;

    let mut r = Reader::new(&blob);

    // The magic is raw bytes, NOT length-prefixed: "openssh-key-v1\0"
    // followed by the length-prefixed fields.
    if r.remaining() < 15 || &r.data()[..15] != b"openssh-key-v1\0" {
        return Err(format!("{where_}: not an OpenSSH-format private key"));
    }
    r.advance(15);

    let cipher = r
        .read_string()
        .map_err(|_| format!("{where_}: truncated key header"))?;
    let kdf = r
        .read_string()
        .map_err(|_| format!("{where_}: truncated key header"))?;
    let _kdf_options = r
        .read_length_prefixed()
        .map_err(|_| format!("{where_}: truncated key header"))?;
    let nkeys = r
        .read_u32()
        .map_err(|_| format!("{where_}: truncated key header"))?;

    if cipher != b"none" || kdf != b"none" {
        return Err(format!(
            "{where_}: this key is passphrase-protected ({}, {}). The agent needs an \
             unencrypted key — VELA's vault is the encryption layer.",
            String::from_utf8_lossy(cipher),
            String::from_utf8_lossy(kdf),
        ));
    }
    if nkeys != 1 {
        return Err(format!(
            "{where_}: {nkeys} keys in one private-key blob is not supported"
        ));
    }

    let public_blob = r
        .read_length_prefixed()
        .map_err(|_| format!("{where_}: truncated key body"))?
        .to_vec();
    let private_section = r
        .read_length_prefixed()
        .map_err(|_| format!("{where_}: truncated key body"))?;

    // The public blob doubles as the key-type check: "ssh-ed25519" only.
    let mut pr = Reader::new(&public_blob);
    let pub_type = pr
        .read_string()
        .map_err(|_| format!("{where_}: malformed public blob"))?;
    if pub_type != b"ssh-ed25519" {
        return Err(format!(
            "{where_}: {} keys are not supported — the agent signs with ed25519",
            String::from_utf8_lossy(pub_type)
        ));
    }

    // Private section: checkint || checkint || [key] || comment (+ padding).
    let mut sr = Reader::new(&private_section);
    let check1 = sr
        .read_u32()
        .map_err(|_| format!("{where_}: truncated private section"))?;
    let check2 = sr
        .read_u32()
        .map_err(|_| format!("{where_}: truncated private section"))?;
    if check1 != check2 {
        return Err(format!(
            "{where_}: key checkints do not match (corrupt key)"
        ));
    }
    let key_type = sr
        .read_string()
        .map_err(|_| format!("{where_}: truncated private section"))?;
    if key_type != b"ssh-ed25519" {
        return Err(format!(
            "{where_}: {} private keys are not supported",
            String::from_utf8_lossy(key_type)
        ));
    }
    let vk = sr
        .read_length_prefixed()
        .map_err(|_| format!("{where_}: truncated private section"))?;
    let sk = sr
        .read_length_prefixed()
        .map_err(|_| format!("{where_}: truncated private section"))?;
    let comment = String::from_utf8_lossy(
        sr.read_length_prefixed()
            .map_err(|_| format!("{where_}: truncated private section"))?,
    )
    .to_string();

    if vk.len() != 32 || sk.len() != 64 || &sk[32..] != vk {
        return Err(format!("{where_}: malformed ed25519 key material"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sk[..32]);
    let signing_key = SigningKey::from_bytes(&seed);

    // The public blob the agent lists must be built from the *parsed* key,
    // not trusted verbatim from the file — the two are cross-checked above,
    // and rebuilding keeps the agent's listed identity consistent.
    let mut clean_blob = Vec::with_capacity(4 + 11 + 4 + 32);
    put_string(&mut clean_blob, b"ssh-ed25519");
    put_string(&mut clean_blob, vk);

    let comment = if comment.trim().is_empty() {
        where_
            .rsplit_once(',')
            .map(|(n, _)| n.trim().to_string())
            .unwrap_or_default()
    } else {
        comment.trim().to_string()
    };

    Ok(Some(SshPrivateKey {
        public_blob: clean_blob,
        comment,
        signing_key,
    }))
}

// ── SSH wire helpers ─────────────────────────────────────────────────────────

pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub fn remaining(&self) -> usize {
        self.data.len()
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn advance(&mut self, n: usize) {
        self.data = &self.data[n.min(self.data.len())..];
    }

    pub fn read_u32(&mut self) -> Result<u32, ()> {
        if self.data.len() < 4 {
            return Err(());
        }
        let v = u32::from_be_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]);
        self.data = &self.data[4..];
        Ok(v)
    }

    pub fn read_length_prefixed(&mut self) -> Result<&'a [u8], ()> {
        let len = self.read_u32()? as usize;
        if self.data.len() < len {
            return Err(());
        }
        let (head, rest) = self.data.split_at(len);
        self.data = rest;
        Ok(head)
    }

    pub fn read_string(&mut self) -> Result<&'a [u8], ()> {
        self.read_length_prefixed()
    }
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;

    /// Build an unencrypted OpenSSH-format ed25519 private key, the
    /// `ssh-keygen -t ed25519` on-disk format, without shelling out.
    pub(super) fn openssh_key_blob(seed: [u8; 32], comment: &str) -> (Vec<u8>, [u8; 32]) {
        use ed25519_dalek::SigningKey;
        let signing = SigningKey::from_bytes(&seed);
        let vk = signing.verifying_key().to_bytes();
        let sk = {
            let mut sk = [0u8; 64];
            sk[..32].copy_from_slice(&seed);
            sk[32..].copy_from_slice(&vk);
            sk
        };

        // Public blob: string "ssh-ed25519" || string vk.
        let mut public = Vec::new();
        put_string(&mut public, b"ssh-ed25519");
        put_string(&mut public, &vk);

        // Private section: checkints || key || comment || padding.
        let mut private = Vec::new();
        put_u32(&mut private, 0x1234);
        put_u32(&mut private, 0x1234);
        put_string(&mut private, b"ssh-ed25519");
        put_string(&mut private, &vk);
        put_string(&mut private, &sk);
        put_string(&mut private, comment.as_bytes());

        let mut blob = Vec::new();
        blob.extend_from_slice(b"openssh-key-v1\0"); // raw magic, not length-prefixed
        put_string(&mut blob, b"none"); // cipher
        put_string(&mut blob, b"none"); // kdf
        put_string(&mut blob, b""); // kdf options
        put_u32(&mut blob, 1);
        put_string(&mut blob, &public);
        put_string(&mut blob, &private);
        (blob, vk)
    }

    fn pem(blob: &[u8]) -> String {
        let engine = base64::engine::general_purpose::STANDARD;
        let b64 = engine.encode(blob);
        let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
        out
    }

    #[test]
    fn parses_signs_and_verifies() {
        let seed = [7u8; 32];
        let (blob, vk) = openssh_key_blob(seed, "octocat@laptop");
        let keys = extract_keys(&pem(&blob), "GitHub key").unwrap();
        assert_eq!(keys.len(), 1);
        let key = &keys[0];
        assert_eq!(key.comment, "octocat@laptop");

        // The rebuilt public blob is the standard wire shape.
        let mut r = Reader::new(&key.public_blob);
        assert_eq!(r.read_string().unwrap(), b"ssh-ed25519");
        assert_eq!(r.read_string().unwrap(), &vk);

        // Signatures verify against the parsed key.
        let sig = key.signing_key.sign(b"hello");
        use ed25519_dalek::VerifyingKey;
        assert!(VerifyingKey::from_bytes(&vk)
            .unwrap()
            .verify_strict(b"hello", &sig)
            .is_ok());
    }

    #[test]
    fn multiple_keys_in_one_note() {
        let (blob_a, _) = openssh_key_blob([1u8; 32], "a@x");
        let (blob_b, _) = openssh_key_blob([2u8; 32], "b@x");
        let text = format!(
            "some intro text\n\n{}\n\ntrailing\n{}",
            pem(&blob_a),
            pem(&blob_b)
        );
        let keys = extract_keys(&text, "My keys").unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].comment, "a@x");
        assert_eq!(keys[1].comment, "b@x");
    }

    #[test]
    fn passphrase_protected_keys_name_the_fix() {
        // Same blob shape but with a cipher/kdf name: what ssh-keygen writes
        // when the key has a passphrase.
        let seed = [9u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vk = signing.verifying_key().to_bytes();
        let mut public = Vec::new();
        put_string(&mut public, b"ssh-ed25519");
        put_string(&mut public, &vk);
        let mut blob = Vec::new();
        blob.extend_from_slice(b"openssh-key-v1\0");
        put_string(&mut blob, b"aes256-ctr");
        put_string(&mut blob, b"bcrypt");
        put_string(&mut blob, &[1, 2, 3]);
        put_u32(&mut blob, 1);
        put_string(&mut blob, &public);
        put_string(&mut blob, &[0xff; 32]); // ciphertext

        let err = match extract_keys(&pem(&blob), "Enc key") {
            Err(e) => e,
            Ok(_) => panic!("passphrase-protected key must be refused"),
        };
        assert!(err.contains("passphrase-protected"), "{err}");
    }

    #[test]
    fn rsa_pem_is_named_not_swallowed() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----";
        let err = match extract_keys(text, "Legacy") {
            Err(e) => e,
            Ok(_) => panic!("RSA keys must be refused with a named error"),
        };
        assert!(err.contains("RSA"), "{err}");
    }

    #[test]
    fn garbage_and_empty_notes_are_safe() {
        assert!(extract_keys("just some text", "note").unwrap().is_empty());
        assert!(extract_keys("", "note").unwrap().is_empty());
        // Truncated OpenSSH body → a clear error, not a panic.
        let text = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert!(extract_keys(text, "broken").is_err());
    }

    #[test]
    fn real_ssh_keygen_output_parses_and_signs() {
        // A throwaway key generated with `ssh-keygen -t ed25519 -N "" -C
        // octo@vela-test` — the real on-disk format, committed as a fixture
        // (it signs nothing real). Exercises the full path: wrapped PEM
        // block, base64 body, comment, "none"-cipher section.
        let text = include_str!("testdata/ed25519.key");

        let keys = extract_keys(text, "smoke").unwrap();
        assert_eq!(keys.len(), 1);
        let key = &keys[0];
        assert_eq!(key.comment, "octo@vela-test");

        // The public blob must be the standard wire encoding: string
        // "ssh-ed25519" || string 32B vk — and signatures verify.
        let mut r = Reader::new(&key.public_blob);
        assert_eq!(r.read_string().unwrap(), b"ssh-ed25519");
        let vk = r.read_string().unwrap();

        let sig = key.signing_key.sign(b"agent smoke");
        use ed25519_dalek::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(vk.try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(sig.to_bytes().as_slice().try_into().unwrap());
        assert!(vk.verify_strict(b"agent smoke", &sig).is_ok());
    }
}
