#pragma once
#include <stddef.h>
#include <stdint.h>

// Prime64 Plan
void* ntt_plan_create(size_t n, uint64_t p);
void  ntt_plan_destroy(void* handle);

// handle is mutated (scratch space)
void  ntt_mul_poly(
    void* handle,
    const uint64_t* a,
    const uint64_t* b,
    uint64_t* out,
    size_t n
);

void ntt_fwd(const void* handle, uint64_t* poly, size_t n);
void ntt_inv(const void* handle, uint64_t* poly, size_t n);
void ntt_pointwise_mul_normalize(
    const void* handle,
    uint64_t* a,
    const uint64_t* b,
    size_t n
);

// Native64 Plan
void* ntt_native_plan_create(size_t n);
void  ntt_native_plan_destroy(void* handle);

// handle is mutated (scratch space)
void  ntt_native_mul_poly(
    void* handle,
    const uint64_t* a,
    const uint64_t* b,
    uint64_t* out,
    size_t n
);

// Separate functions for Native64
// out_ntt must point to a buffer of size at least 5 * n * sizeof(uint32_t)
// We use uint64_t* for ABI simplicity, but it's treated as uint32_t array internally.
void ntt_native_fwd(
    const void* handle,
    const uint64_t* val,
    uint64_t* out_ntt, 
    size_t n
);

// val_ntt is modified in-place during inverse transform!
void ntt_native_inv(
    const void* handle,
    uint64_t* val_ntt,
    uint64_t* out,
    size_t n
);

void ntt_native_pointwise_mul_normalize(
    const void* handle,
    uint64_t* a_ntt,
    const uint64_t* b_ntt,
    size_t n
);

void ntt_native_add(
    const void* handle,
    uint64_t* a_ntt,
    const uint64_t* b_ntt,
    size_t n
);

void* ntt_incomplete_plan_create(size_t phi, uint64_t q);
void  ntt_incomplete_plan_destroy(void* handle);

void ntt_incomplete_fwd(
    const void* handle,
    const uint64_t* poly,
    uint64_t* out,
    size_t phi
);

void ntt_incomplete_inv(
    const void* handle,
    const uint64_t* ntt,
    uint64_t* out,
    size_t phi
);

void ntt_incomplete_mul_assign(
    const void* handle,
    uint64_t* a,
    const uint64_t* b,
    size_t phi
);

void ntt_incomplete_mul_poly(
    const void* handle,
    const uint64_t* a,
    const uint64_t* b,
    uint64_t* out,
    size_t phi
);
