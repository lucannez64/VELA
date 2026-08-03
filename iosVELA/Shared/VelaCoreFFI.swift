import Foundation
import VelaCore

/// Thin Swift wrapper over the VELA Rust core's C ABI (the `VelaCore` module
/// vended by VelaCore.xcframework). All payloads are UTF-8 JSON; every returned
/// pointer is freed here.
enum VelaCoreFFI {
    private static func consume(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
        guard let ptr = ptr else { return "" }
        defer { vela_ffi_free_string(ptr) }
        return String(cString: ptr)
    }

    private static func json(_ object: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: object),
              let string = String(data: data, encoding: .utf8) else { return "{}" }
        return string
    }

    /// Pull a string field out of a JSON object response, or nil (e.g. on `{"error":...}`).
    private static func field(_ response: String, _ key: String) -> String? {
        guard let data = response.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let value = obj[key] as? String else { return nil }
        return value
    }

    /// Pull a numeric field (e.g. an identity handle) out of a JSON response.
    private static func numberField(_ response: String, _ key: String) -> UInt64? {
        guard let data = response.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let value = obj[key] as? NSNumber else { return nil }
        return value.uint64Value
    }

    /// Pull a `[String]` field out of a JSON object response, or nil on error.
    private static func stringArray(_ response: String, _ key: String) -> [String]? {
        guard let data = response.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let value = obj[key] as? [String] else { return nil }
        return value
    }

    /// e.g. "vela-apple-bridge/0.1.0"
    static func version() -> String {
        consume(vela_ffi_version())
    }

    // MARK: - Identity & auth
    //
    // The device signing key and the share decapsulation key never cross this
    // boundary. Swift `String`s are immutable and un-wipeable, so a base64 key
    // handed back here stayed readable in memory (and in any crash report) for
    // the life of the process (audit C-1). Instead the native side keeps the
    // keys, hands back a handle plus the public halves, and does the signing and
    // share-opening itself. The only secret that crosses is the 32-byte seal
    // key, as `Data` the caller can zero.

    /// A live identity: an opaque handle, the public halves, and the sealed blob
    /// to persist.
    struct IdentityHandle {
        let handle: UInt64
        let hybridEK: String
        let hybridVK: String
        let shareEK: String
        let sealed: String
    }

    private static func parseHandle(_ response: String) -> IdentityHandle? {
        guard let handle = numberField(response, "handle"),
              let ek = field(response, "hybrid_ek_b64"),
              let vk = field(response, "hybrid_vk_b64"),
              let shareEK = field(response, "share_ek_b64"),
              let sealed = field(response, "sealed_b64") else { return nil }
        return IdentityHandle(handle: handle, hybridEK: ek, hybridVK: vk, shareEK: shareEK, sealed: sealed)
    }

    /// Generate a fresh device identity. The private halves stay native.
    static func identityCreate(sealKey: Data) -> IdentityHandle? {
        let response = sealKey.withUnsafeBytes { buffer in
            consume(vela_ffi_identity_create(buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count))
        }
        return parseHandle(response)
    }

    /// Adopt key material that already exists: migrating a device that stored
    /// its keys in the clear, or enrolling from a code that carries the signing
    /// key. The bytes are handed over once and live natively from then on.
    static func identityImport(
        sealKey: Data,
        hybridSKBase64: String,
        shareDKBase64: String = "",
        hybridEKBase64: String = ""
    ) -> IdentityHandle? {
        let request = json([
            "hybrid_sk_b64": hybridSKBase64,
            "share_dk_b64": shareDKBase64,
            "hybrid_ek_b64": hybridEKBase64,
        ])
        let response = sealKey.withUnsafeBytes { buffer in
            request.withCString {
                consume(vela_ffi_identity_import(buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count, $0))
            }
        }
        return parseHandle(response)
    }

    /// Reopen a persisted identity.
    static func identityOpen(sealKey: Data, sealedBase64: String) -> IdentityHandle? {
        let request = json(["sealed_b64": sealedBase64])
        let response = sealKey.withUnsafeBytes { buffer in
            request.withCString {
                consume(vela_ffi_identity_open(buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count, $0))
            }
        }
        return parseHandle(response)
    }

    /// Replace the share keypair; returns the new public half and sealed blob.
    static func identityRotateShareKey(sealKey: Data, handle: UInt64) -> (shareEK: String, sealed: String)? {
        let request = json(["handle": handle])
        let response = sealKey.withUnsafeBytes { buffer in
            request.withCString {
                consume(vela_ffi_identity_rotate_share_key(buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count, $0))
            }
        }
        guard let shareEK = field(response, "share_ek_b64"),
              let sealed = field(response, "sealed_b64") else { return nil }
        return (shareEK, sealed)
    }

    /// Sign a server auth challenge with the held signing key.
    static func identitySign(handle: UInt64, challengeBase64: String, deviceID: String) -> String? {
        let request = json(["handle": handle, "challenge_b64": challengeBase64, "device_id": deviceID])
        let response = request.withCString { consume(vela_ffi_identity_sign_json($0)) }
        return field(response, "signature_b64")
    }

    /// Open a capsule sealed to this device's share key.
    static func identityOpenShare(handle: UInt64, capsuleBase64: String) -> String? {
        let request = json(["handle": handle, "capsule_b64": capsuleBase64])
        let response = request.withCString { consume(vela_ffi_identity_open_share_json($0)) }
        return field(response, "item_json")
    }

    // ── Enrollment v3 (audit P-1) ───────────────────────────────────────────

    /// This device's own enrollment fingerprint.
    ///
    /// Takes only the handle, and that is deliberate: the value shown to the
    /// user is derived from the key this device holds, so there is no way for
    /// the app to display a fingerprint that arrived over the network. If it
    /// could, the user would be comparing two devices' agreement about a
    /// number rather than about a key, and every binding behind it would stop
    /// meaning anything.
    static func identityEnrollmentFingerprint(handle: UInt64) -> String? {
        let request = json(["handle": handle])
        let response = request.withCString {
            consume(vela_ffi_identity_enrollment_fingerprint_json($0))
        }
        return field(response, "fingerprint")
    }

    /// Sign a grant id, to collect the outcome of this device's own enrollment.
    /// Stands in for a session — the device_id it asks for is what a session
    /// would need.
    static func identitySignEnrollmentResult(handle: UInt64, grantID: String) -> String? {
        let request = json(["handle": handle, "grant_id": grantID])
        let response = request.withCString {
            consume(vela_ffi_identity_sign_enrollment_result_json($0))
        }
        return field(response, "signature_b64")
    }

    /// Open the RMS capsule the enrolling device sealed to this device's key.
    /// Returns the root master secret, base64.
    static func identityOpenEnrollmentCapsule(handle: UInt64, capsuleBase64: String) -> String? {
        let request = json(["handle": handle, "capsule_b64": capsuleBase64])
        let response = request.withCString {
            consume(vela_ffi_identity_open_enrollment_capsule_json($0))
        }
        return field(response, "rms_b64")
    }

    /// Drop a handle, wiping its keys. Call on sign-out.
    static func identityForget(handle: UInt64) {
        let request = json(["handle": handle])
        _ = request.withCString { consume(vela_ffi_identity_forget_json($0)) }
    }

    static func identityForgetAll() {
        _ = consume(vela_ffi_identity_forget_all())
    }

    // MARK: - KEM-sealed sharing

    /// Encrypt `itemJSON` for a recipient using their share public key. Returns base64 capsule or nil on error.
    static func sealShare(recipientShareEKBase64: String, itemJSON: String) -> String? {
        let request = json(["recipient_share_ek_b64": recipientShareEKBase64, "item_json": itemJSON])
        let response = request.withCString { consume(vela_ffi_seal_share_json($0)) }
        return field(response, "capsule_b64")
    }

    // MARK: - Sync (per-chunk)

    /// `lamportClock` is the revision this chunk is about to be stored under. It
    /// is sealed into the ciphertext so the server cannot serve an older
    /// revision back as if it were current (audit C-2, rollout step 3). It must
    /// be the clock actually sent with the upload, or the result will not
    /// decrypt.
    static func encryptVaultChunk(
        rmsBase64: String, chunkID: String, vaultJSON: String, lamportClock: Int
    ) -> String? {
        let request = json([
            "rms_b64": rmsBase64,
            "chunk_id": chunkID,
            "vault_json": vaultJSON,
            "lamport_clock": lamportClock,
        ])
        let response = request.withCString { consume(vela_ffi_encrypt_vault_chunk_json($0)) }
        return field(response, "ciphertext_b64")
    }

    /// `lamportClock` is the revision the server claimed for this chunk. It is
    /// verified for ciphertexts sealed with associated data and ignored for the
    /// older unbound ones, so this reads both while the fleet upgrades
    /// (audit C-2, rollout step 2).
    static func decryptVaultChunk(
        rmsBase64: String,
        chunkID: String,
        ciphertextBase64: String,
        // No default. Defaulting it to 0 meant a caller that forgot it got a
        // silent decryption failure against any sealed chunk — which is exactly
        // what happened to this file's own test once writers started sealing
        // (audit C-2).
        lamportClock: Int64
    ) -> String? {
        let request = json([
            "rms_b64": rmsBase64,
            "chunk_id": chunkID,
            "ciphertext_b64": ciphertextBase64,
            "lamport_clock": lamportClock,
        ])
        let response = request.withCString { consume(vela_ffi_decrypt_vault_chunk_json($0)) }
        return field(response, "vault_json")
    }

    // MARK: - Web sessions

    /// The per-chunk vault keys a read-write web session is granted, as
    /// `chunk_id → base64(32-byte key)`. The browser gets these instead of the
    /// RMS, so a leaked capsule yields vault chunks only — no identity, share,
    /// audit or recovery key can be derived from it (audit D-2).
    static func webSessionChunkKeys(rmsBase64: String) -> [String: String]? {
        let request = json(["rms_b64": rmsBase64])
        let response = request.withCString { consume(vela_ffi_web_session_chunk_keys_json($0)) }
        guard let data = response.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let keys = obj["chunk_keys"] as? [String: String], !keys.isEmpty else {
            return nil
        }
        return keys
    }

    // MARK: - Enrollment

    /// Short out-of-band verification code for an enrollment code string.
    /// Compute this right after scanning/pasting an enrollment code and show
    /// it to the user to confirm against the enrolling device's screen
    /// *before* importing — neither device can otherwise establish trust in
    /// who actually produced the code.
    static func enrollmentVerificationCode(_ code: String) -> String {
        code.withCString { consume(vela_ffi_enrollment_verification_code($0)) }
    }

    /// Decrypt an RMS capsule (AEAD under a 32-byte transfer key). Returns base64 RMS.
    static func decryptRMSCapsule(transferKeyBase64: String, capsuleBase64: String) -> String? {
        let request = json(["transfer_key_b64": transferKeyBase64, "capsule_b64": capsuleBase64])
        let response = request.withCString { consume(vela_ffi_decrypt_rms_capsule_json($0)) }
        return field(response, "rms_b64")
    }

    /// Decrypt an enrollment package (AEAD under a 32-byte key). Returns the plaintext JSON.
    static func decryptEnrollmentPackage(keyBase64: String, ciphertextBase64: String) -> String? {
        let request = json(["key_b64": keyBase64, "ciphertext_b64": ciphertextBase64])
        let response = request.withCString { consume(vela_ffi_decrypt_enrollment_package_json($0)) }
        return field(response, "plaintext")
    }

    // MARK: - Recovery (Shamir)

    /// Split the RMS into `n` base64 shares, `threshold` of which reconstruct it.
    static func splitRecovery(rmsBase64: String, threshold: Int, n: Int) -> [String]? {
        let request = json(["rms_b64": rmsBase64, "threshold": threshold, "n": n])
        let response = request.withCString { consume(vela_ffi_split_recovery_json($0)) }
        return stringArray(response, "shares_b64")
    }

    /// Reconstruct the RMS (base64) from `threshold`+ recovery shares.
    static func combineRecovery(sharesBase64: [String]) -> String? {
        let request = json(["shares_b64": sharesBase64])
        let response = request.withCString { consume(vela_ffi_combine_recovery_json($0)) }
        return field(response, "rms_b64")
    }

    static func passwordStrengthJSON(_ password: String) -> String {
        json(["password": password]).withCString { consume(vela_ffi_password_strength_json($0)) }
    }


    /// Encrypt a vault (JSON string) under the RMS. Returns base64 ciphertext, or nil on error.
    static func encryptVault(rmsBase64: String, vaultJSON: String) -> String? {
        let request = json(["rms_b64": rmsBase64, "vault_json": vaultJSON])
        let response = request.withCString { consume(vela_ffi_encrypt_vault_json($0)) }
        return field(response, "ciphertext_b64")
    }

    /// Decrypt a vault. Returns the vault JSON string, or nil on error / wrong RMS.
    static func decryptVault(rmsBase64: String, ciphertextBase64: String) -> String? {
        let request = json(["rms_b64": rmsBase64, "ciphertext_b64": ciphertextBase64])
        let response = request.withCString { consume(vela_ffi_decrypt_vault_json($0)) }
        return field(response, "vault_json")
    }
}
