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
char *vela_ffi_password_strength_json(const char *request_json);
char *vela_ffi_encrypt_vault_json(const char *request_json);
char *vela_ffi_decrypt_vault_json(const char *request_json);
char *vela_ffi_generate_identity_json(void);
char *vela_ffi_create_auth_signature_json(const char *request_json);

#ifdef __cplusplus
}
#endif

#endif /* VELA_APPLE_H */
