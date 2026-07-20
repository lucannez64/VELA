#ifndef VELA_APPLE_H
#define VELA_APPLE_H

/* C ABI for the VELA Rust core, consumed from Swift.
 * Every char* return value is heap-allocated and must be freed with
 * vela_ffi_free_string. All payloads are UTF-8 JSON. */

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
char *vela_ffi_encrypt_vault_json(const char *request_json);
char *vela_ffi_decrypt_vault_json(const char *request_json);
char *vela_ffi_generate_identity_json(void);
char *vela_ffi_generate_share_keypair_json(void);
char *vela_ffi_create_auth_signature_json(const char *request_json);

/* Phase 4: sync (per-chunk vault crypto), enrollment (RMS capsule / enrollment
 * package), and recovery (Shamir split/combine of the RMS). */
char *vela_ffi_encrypt_vault_chunk_json(const char *request_json);
char *vela_ffi_decrypt_vault_chunk_json(const char *request_json);
char *vela_ffi_decrypt_rms_capsule_json(const char *request_json);
char *vela_ffi_decrypt_enrollment_package_json(const char *request_json);
char *vela_ffi_split_recovery_json(const char *request_json);
char *vela_ffi_combine_recovery_json(const char *request_json);

/* Real KEM-sealed cross-user sharing (ML-KEM-1024 + X25519 hybrid).
 * seal: { recipient_share_ek_b64, item_json } -> { capsule_b64 }
 * open: { share_dk_b64, capsule_b64 } -> { item_json } */
char *vela_ffi_seal_share_json(const char *request_json);
char *vela_ffi_open_share_json(const char *request_json);

#ifdef __cplusplus
}
#endif

#endif /* VELA_APPLE_H */
