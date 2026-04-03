#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
typedef enum {
    CYCLO_SUCCESS = 0,
    CYCLO_INVALID_PARAMS = 1,
    CYCLO_INVALID_WITNESS = 2,
    CYCLO_PROOF_FAILED = 3,
    CYCLO_VERIFICATION_FAILED = 4,
    CYCLO_ALLOCATION_FAILED = 5,
    CYCLO_SERIALIZATION_FAILED = 6,
} CycloError;

// Parameter Management
void* cyclo_preset_128(void);
double cyclo_security_bits(void);

// Memory Management
void* cyclo_proof_allocate(void);
void cyclo_proof_free(void* ptr);

// High-Level Prove/Verify API
// Prove: returns proof size on success, negative on error
int cyclo_prove(
    const uint64_t* public_inputs,
    size_t public_len,
    const uint64_t* private_inputs,
    size_t private_len,
    uint8_t* proof_out,
    size_t proof_out_size
);

// Verify: returns 1 if valid, 0 if invalid, negative on error
int cyclo_verify(
    const uint64_t* public_inputs,
    size_t public_len,
    const uint8_t* proof,
    size_t proof_len
);

#ifdef __cplusplus
}
#endif
