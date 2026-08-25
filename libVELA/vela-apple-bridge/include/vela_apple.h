#ifndef VELA_APPLE_H
#define VELA_APPLE_H

/* C ABI for the VELA Rust core, consumed from Swift.
 * Every char* return value is heap-allocated and must be freed with
 * vela_ffi_free_string. All payloads are UTF-8 JSON. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

char *vela_ffi_version(void);
void vela_ffi_free_string(char *ptr);
/* Short out-of-band verification code for a device enrollment code string
 * (see vela_crypto::verification). Not JSON in/out like the rest of this
 * ABI: takes and returns a plain string. */
char *vela_ffi_enrollment_verification_code(const char *code);
char *vela_ffi_password_strength_json(const char *request_json);
/* Vault crypto: the RMS crosses as raw bytes the caller can wipe — never as
 * base64 inside the JSON envelope, which would leave an un-wipeable String
 * copy on the heap (audit I-2; same rationale as the seal key, audit C-1). */
char *vela_ffi_encrypt_vault_json(const uint8_t *rms, size_t rms_len,
                                  const char *request_json);
char *vela_ffi_decrypt_vault_json(const uint8_t *rms, size_t rms_len,
                                  const char *request_json);
/* Device identity behind an opaque handle: the signing key and the share
 * decapsulation key never cross this boundary (audit C-1). The seal key is
 * passed as raw bytes so the caller can wipe it — a Swift String cannot be. */
char *vela_ffi_identity_create(const uint8_t *seal_key, size_t seal_key_len);
char *vela_ffi_identity_import(const uint8_t *seal_key, size_t seal_key_len,
                               const char *request_json);
char *vela_ffi_identity_open(const uint8_t *seal_key, size_t seal_key_len,
                             const char *request_json);
char *vela_ffi_identity_rotate_share_key(const uint8_t *seal_key, size_t seal_key_len,
                                         const char *request_json);
char *vela_ffi_identity_sign_json(const char *request_json);
char *vela_ffi_identity_open_share_json(const char *request_json);
/* Enrollment v3 (audit P-1). The fingerprint call takes only a handle: the
   value shown to the user must come from the key this device holds. */
char *vela_ffi_identity_enrollment_fingerprint_json(const char *request_json);
char *vela_ffi_identity_sign_enrollment_result_json(const char *request_json);
char *vela_ffi_identity_open_enrollment_capsule_json(const char *request_json);
char *vela_ffi_identity_forget_json(const char *request_json);
char *vela_ffi_identity_forget_all(void);

/* Phase 4: sync (per-chunk vault crypto), enrollment (RMS capsule / enrollment
 * package), and recovery (Shamir split/combine of the RMS). The RMS-taking
 * calls pass it as raw bytes (see vault crypto above). */
char *vela_ffi_encrypt_vault_chunk_json(const uint8_t *rms, size_t rms_len,
                                        const char *request_json);
/* Per-chunk vault keys granted to a read-write web session (never the RMS). */
char *vela_ffi_web_session_chunk_keys_json(const uint8_t *rms, size_t rms_len,
                                           const char *request_json);
char *vela_ffi_decrypt_vault_chunk_json(const uint8_t *rms, size_t rms_len,
                                        const char *request_json);
char *vela_ffi_decrypt_rms_capsule_json(const char *request_json);
char *vela_ffi_decrypt_enrollment_package_json(const char *request_json);
char *vela_ffi_split_recovery_json(const uint8_t *rms, size_t rms_len,
                                   const char *request_json);
char *vela_ffi_combine_recovery_json(const char *request_json);
char *vela_ffi_seal_contact_share_json(const char *request_json);
char *vela_ffi_open_contact_share_json(const char *request_json);
char *vela_ffi_seal_contact_share_response_json(const char *request_json);
char *vela_ffi_identity_sign_share_ek_json(const char *request_json);
char *vela_ffi_possession_proof_json(const char *request_json);
char *vela_ffi_generate_recovery_request_json(void);
char *vela_ffi_rms_possession_hash_json(const uint8_t *rms, size_t rms_len);
char *vela_ffi_plan_recovery_publication_json(const char *request_json);

/* Real KEM-sealed cross-user sharing (ML-KEM-1024 + X25519 hybrid).
 * seal: { recipient_share_ek_b64, item_json } -> { capsule_b64 }
 * open: { share_dk_b64, capsule_b64 } -> { item_json } */
char *vela_ffi_seal_share_json(const char *request_json);

#ifdef __cplusplus
}
#endif

#endif /* VELA_APPLE_H */
