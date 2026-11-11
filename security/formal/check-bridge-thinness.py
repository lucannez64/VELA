#!/usr/bin/env python3
"""Check that every VELA FFI export is a thin type conversion.

N2a-c and plan step N4 ("Scope decisions", 09-target-contract.md) put every
security decision in the verified Rust core and keep the Android, Apple and
WASM bridges thin: an export may decode its input, call one reviewed core
function, and encode the output. This guard is the CI rule for that boundary.

For every ABI export (``#[no_mangle]``/``#[wasm_bindgen]`` function) the guard
resolves the local helper functions it calls, analyses each reachable body, and
fails when a body contains:

  * a decision keyword (``if``, ``match``, ``while``, ``loop``, ``for``) that is
    not listed for that export/helper with a reason;
  * a fallback default (``unwrap_or(...)``, ``unwrap_or_else(...)``,
    ``unwrap_or_default()``), a ``default_*`` function returning a literal, or
    ``#[serde(default = "...")]``, that is not listed with a reason;
  * an integer literal that is not listed with a reason (this catches a default
    written any other way);
  * a free-function call to anything other than a reviewed core function, a
    macro in the codec list, or a local helper (which is analysed in turn);
  * an ``impl`` block in a bridge file (method calls are otherwise assumed to
    resolve to the standard library or a core crate type).

What it does NOT check (stated in the proof log):

  * that a reviewed core function is itself correct or decision-free -- that is
    the hax/F* corpus' job, not this tokenizer's;
  * method calls: the bridges define no inherent methods, so a method resolves
    to std or a core type, but this guard does not prove which;
  * behaviour or reachability of an export from the app (N5-N7 cover callers);
  * that the allowlisted ``if``/``match`` is a *decode* check rather than a
    security decision -- a reviewer must say why in the entry's reason.

Usage: python3 -I security/formal/check-bridge-thinness.py [--root DIR]
Exit status 0 when every export is thin, 1 with findings otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[2]

BRIDGES = (
    "libVELA/vela-android-bridge/src/lib.rs",
    "libVELA/vela-apple-bridge/src/lib.rs",
    "libVELA/vela-wasm-bridge/src/lib.rs",
)

DECISION_KEYWORDS = {"if", "match", "while", "loop", "for"}

# Calls that only convert values, format text or carry an error. They are the
# same for every bridge and are reviewed once here.
CODEC_CALLS = {
    "B64.decode",
    "B64.encode",
    "Box::from_raw",
    "Box::into_raw",
    "Box::new",
    "CStr::from_ptr",
    "CString::from_raw",
    "CString::new",
    "Default::default",
    "Err",
    "Ok",
    "Some",
    "String::from",
    "String::from_utf8",
    "String::new",
    "Vec::new",
    "Vec::with_capacity",
    "anyhow_like::Error::from",
    "drop",
    "ptr::null_mut",
    "serde_json::from_str",
    "serde_json::to_string",
    "slice::from_raw_parts",
    "slice::from_raw_parts_mut",
    "std::mem::forget",
    "std::ptr::null_mut",
    "std::slice::from_raw_parts",
    "std::slice::from_raw_parts_mut",
    "u32::try_from",
    "u64::try_from",
    "usize::try_from",
}

# Macros are text/codec plumbing, never a decision. The checker compares the
# last path segment plus `!`, so `serde_json::json!` matches `json!`.
CODEC_MACROS = {"concat!", "env!", "format!", "json!", "vec!"}

# Rust keywords that can precede `(` without being a call (tuple patterns,
# control flow). Kept separate from codec calls so a real helper cannot hide
# behind a keyword spelling.
NOT_CALLS = {
    "as", "async", "await", "break", "const", "continue", "crate", "dyn",
    "else", "for", "if", "impl", "in", "let", "loop", "match", "move", "mut",
    "pub", "ref", "return", "self", "static", "super", "unsafe", "use",
    "where", "while",
}

# Reviewed core entry points, one set per bridge. Listing exact functions (no
# wildcards) means a new call fails until a reviewer adds it here.
CORE_CALLS = {
    "libVELA/vela-android-bridge/src/lib.rs": {
        "SecretBytes",
        "admission::admit_download",
        "aead::decrypt",
        "aead::encrypt",
        "calculate_password_strength",
        "kdf::chunk_key",
        "kdf::derive",
        "kdf::web_session_chunk_keys",
        "kem::HybridPublicKey::from_bytes",
        "kem::seal_share",
        "passkey::build_attestation_object",
        "passkey::build_authenticator_data",
        "passkey::keygen",
        "passkey::sign",
        "recovery::CombineShareInput",
        "recovery::RecoveryShareChannel::from_wire_name",
        "recovery::combine_recovery_shares",
        "recovery::open_rms_transfer_capsule",
        "recovery::rms_possession_commitment",
        "rekey::open_fleet_chunk",
        "rekey::open_rekey_capsule",
        "rekey::seal_fleet_chunk_optional_epoch",
        "shamir::Share::from_bytes",
        "shamir::split",
        "vela_client_recovery_policy::plan_publication_resume",
        "vela_core::rich_api::process",
        "vela_crypto::identity::DeviceIdentity::generate",
        "vela_crypto::identity::DeviceIdentity::import",
        "vela_crypto::identity::DeviceIdentity::open",
        "vela_crypto::identity::forget",
        "vela_crypto::identity::forget_all",
        "vela_crypto::identity::register",
        "vela_crypto::identity::with_identity",
        "vela_crypto::verification::enrollment_verification_code",
        "vela_crypto::verification::signing_key_fingerprint",
        "vela_import::parse_import_request",
    },
    "libVELA/vela-apple-bridge/src/lib.rs": {
        "admission::admit_download",
        "aead::decrypt",
        "aead::encrypt",
        "calculate_password_strength",
        "kdf::chunk_key",
        "kdf::derive",
        "kdf::web_session_chunk_keys",
        "kem::HybridPublicKey::from_bytes",
        "kem::HybridSecretKey::from_bytes",
        "kem::generate_keypair",
        "kem::seal_share",
        "recovery::CombineShareInput",
        "recovery::RecoveryShareChannel::from_wire_name",
        "recovery::combine_recovery_shares",
        "recovery::open_contact_share_for_direction",
        "recovery::open_rms_transfer_capsule",
        "recovery::rms_possession_commitment",
        "recovery::rms_possession_sign",
        "recovery::seal_contact_share",
        "recovery::seal_contact_share_response",
        "rekey::open_fleet_chunk_optional_epoch",
        "rekey::open_rekey_capsule",
        "rekey::seal_fleet_chunk_optional_epoch",
        "shamir::Share::from_bytes",
        "shamir::split",
        "vela_client_recovery_policy::plan_publication_resume",
        "vela_core::rich_api::process",
        "vela_crypto::identity::DeviceIdentity::generate",
        "vela_crypto::identity::DeviceIdentity::import",
        "vela_crypto::identity::DeviceIdentity::open",
        "vela_crypto::identity::forget",
        "vela_crypto::identity::forget_all",
        "vela_crypto::identity::register",
        "vela_crypto::identity::with_identity",
        "vela_crypto::verification::enrollment_verification_code",
        "vela_crypto::verification::signing_key_fingerprint",
        "vela_import::parse_import_request",
    },
    "libVELA/vela-wasm-bridge/src/lib.rs": {
        "DownloadAdmissionState::default",
        "calculate_password_strength",
        "kem::HybridSecretKey::from_bytes",
        "kem::generate_keypair",
        "kem::open_share",
        "rekey::seal_fleet_chunk_optional_epoch",
        "signing::HybridSigningKey::from_bytes",
        "signing::auth_message",
        "signing::generate_keypair",
        "signing::sign",
        "vela_crypto::link::open_link",
    },
}

# Every export that must exist, and the reviewed exceptions for exports and
# helpers that keep a justified non-conversion construct. An entry is
# ``{"decisions": {...}, "literals": {...}, "defaults": {...}, "reason": "..."}``.
# Counts are exact: an extra `if`, literal or default fails, and so does a stale
# allowance. Every entry with a non-empty construct map must carry a reason.
ALLOW = {
    "libVELA/vela-android-bridge/src/lib.rs": {
        "exports": [
            "Java_com_vela_android_core_NativeVelaCore_nativeCombineRecoveryJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeDecryptAdmittedVaultChunkJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeDecryptEnrollmentPackageJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeDecryptRmsCapsuleJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeDecryptVaultChunkJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeDecryptVaultJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeEncryptVaultChunkJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeEncryptVaultJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeEnrollmentVerificationCode",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityAdmitShareJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityCreateJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityEnrollmentFingerprintJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityForgetAllJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityForgetJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityImportJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityOpenEnrollmentCapsuleJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityOpenJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityOpenShareJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentityRotateShareKeyJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentitySealSignedShareJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentitySignEnrollmentResultJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentitySignJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeIdentitySignShareEkJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeOpenRekeyCapsuleJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeParseImportJson",
            "Java_com_vela_android_core_NativeVelaCore_nativePasskeyAttestationObjectJson",
            "Java_com_vela_android_core_NativeVelaCore_nativePasskeyAuthDataJson",
            "Java_com_vela_android_core_NativeVelaCore_nativePasskeyKeygenJson",
            "Java_com_vela_android_core_NativeVelaCore_nativePasskeySignJson",
            "Java_com_vela_android_core_NativeVelaCore_nativePlanRecoveryPublicationJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeRichItemsJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeRmsPossessionHashJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeSealShareJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeSplitRecoveryJson",
            "Java_com_vela_android_core_NativeVelaCore_nativeVersion",
            "Java_com_vela_android_core_NativeVelaCore_nativeWebSessionChunkKeysJson",
            "vela_bridge_free_bytes",
            "vela_bridge_free_string",
            "vela_bridge_version",
            "vela_decrypt_vault_json",
            "vela_encrypt_bytes",
            "vela_encrypt_vault_json",
            "vela_password_strength_json",
        ],
        "allow": {
            "Java_com_vela_android_core_NativeVelaCore_nativeEnrollmentVerificationCode": {
                "defaults": {"unwrap_or": 1},
                "reason": "a JString that fails to decode becomes the empty code "
                "string; ABI error mapping, not a security default",
            },
            "android_refusal_message": {
                "decisions": {"match": 1},
                "reason": "renders the core refusal enum into the Android error "
                "envelope; wording only, every fact comes from the core",
            },
            "c_str": {
                "decisions": {"if": 1},
                "reason": "C string pointer decoding: rejects a null pointer",
            },
            "jni_json_result": {
                "decisions": {"match": 2},
                "reason": "JNI/JSON error envelope; the matches are decode failures",
            },
            "jni_json_result_into_secret": {
                "decisions": {"if": 1, "match": 3},
                "literals": {"0": 1},
                "reason": "JNI byte-array write and error envelope; the only "
                "literal is the array offset 0",
            },
            "jni_json_result_with_secret": {
                "decisions": {"match": 3},
                "reason": "JNI/JSON error envelope; the matches are decode failures",
            },
            "jni_secret_json_result": {
                "decisions": {"match": 2},
                "reason": "JNI/JSON error envelope; the matches are decode failures",
            },
            "jni_string": {
                "defaults": {"unwrap_or": 1},
                "reason": "a JNI string allocation failure becomes a null jstring; "
                "ABI fallback, not a security default",
            },
            "error_json": {
                "defaults": {"unwrap_or": 1},
                "reason": "serialization failure becomes the fixed bridge-error "
                "JSON; ABI fallback, not a security default",
            },
            "json_result": {
                "decisions": {"match": 1},
                "reason": "JSON/error envelope; the match is a decode failure",
            },
            "open_rekey_capsule_json": {
                "literals": {"32": 1},
                "reason": "the 32-byte previous_rms wire width, not a default",
            },
            "raw_rms": {
                "decisions": {"if": 1},
                "literals": {"0": 1, "32": 2},
                "reason": "raw-byte pointer decoding: null check and the 32-byte "
                "RMS width",
            },
            "raw_slice": {
                "decisions": {"if": 1},
                "literals": {"0": 1},
                "reason": "raw pointer decoding: rejects a null pointer for a "
                "non-zero length",
            },
            "string_to_ptr": {
                "decisions": {"if": 2},
                "literals": {"0": 2, "1": 1},
                "reason": "C string ownership: interior-NUL fallback and the "
                "one-byte terminator allocation",
            },
            "vela_bridge_free_bytes": {
                "decisions": {"if": 1},
                "literals": {"0": 1},
                "reason": "C ABI free: null/length guard, no decision",
            },
            "vela_bridge_free_string": {
                "decisions": {"if": 1},
                "reason": "C ABI free: null guard, no decision",
            },
            "vela_encrypt_bytes": {
                "decisions": {"match": 1},
                "literals": {"0": 1},
                "reason": "error -> null buffer mapping (dead export, FFI inventory "
                "F12); it makes no admission claim",
            },
        },
    },
    "libVELA/vela-apple-bridge/src/lib.rs": {
        "exports": [
            "vela_ffi_combine_recovery_json",
            "vela_ffi_decrypt_admitted_vault_chunk_json",
            "vela_ffi_decrypt_enrollment_package_json",
            "vela_ffi_decrypt_rms_capsule_json",
            "vela_ffi_decrypt_vault_chunk_json",
            "vela_ffi_decrypt_vault_json",
            "vela_ffi_encrypt_vault_chunk_json",
            "vela_ffi_encrypt_vault_json",
            "vela_ffi_enrollment_verification_code",
            "vela_ffi_free_string",
            "vela_ffi_generate_recovery_request_json",
            "vela_ffi_identity_admit_share_json",
            "vela_ffi_identity_create",
            "vela_ffi_identity_enrollment_fingerprint_json",
            "vela_ffi_identity_forget_all",
            "vela_ffi_identity_forget_json",
            "vela_ffi_identity_import",
            "vela_ffi_identity_open_enrollment_capsule_json",
            "vela_ffi_identity_open",
            "vela_ffi_identity_open_share_json",
            "vela_ffi_identity_rotate_share_key",
            "vela_ffi_identity_seal_signed_share_json",
            "vela_ffi_identity_sign_enrollment_result_json",
            "vela_ffi_identity_sign_json",
            "vela_ffi_identity_sign_share_ek_json",
            "vela_ffi_open_contact_share_json",
            "vela_ffi_open_rekey_capsule_json",
            "vela_ffi_parse_import_json",
            "vela_ffi_password_strength_json",
            "vela_ffi_plan_recovery_publication_json",
            "vela_ffi_possession_proof_json",
            "vela_ffi_rich_items_json",
            "vela_ffi_rms_possession_hash_json",
            "vela_ffi_seal_contact_share_json",
            "vela_ffi_seal_contact_share_response_json",
            "vela_ffi_seal_share_json",
            "vela_ffi_split_recovery_json",
            "vela_ffi_version",
            "vela_ffi_web_session_chunk_keys_json",
        ],
        "allow": {
            "vela_ffi_enrollment_verification_code": {
                "defaults": {"unwrap_or": 1},
                "reason": "a null/invalid C string becomes the empty code string; "
                "ABI error mapping, not a security default",
            },
            "apple_refusal_message": {
                "decisions": {"match": 1},
                "reason": "renders the core refusal enum into the Apple error "
                "envelope; wording only, every fact comes from the core",
            },
            "c_str": {
                "decisions": {"if": 1},
                "reason": "C string pointer decoding: rejects a null pointer",
            },
            "json_result": {
                "decisions": {"match": 1},
                "reason": "JSON/error envelope; the match is a decode failure",
            },
            "error_json": {
                "defaults": {"unwrap_or": 1},
                "reason": "serialization failure becomes the fixed bridge-error "
                "JSON; ABI fallback, not a security default",
            },
            "string_to_ptr": {
                "defaults": {"unwrap_or": 1},
                "reason": "an interior-NUL CString failure falls back to an empty "
                "CString; C string ownership, not a security default",
            },
            "open_rekey_capsule_impl": {
                "literals": {"32": 1},
                "reason": "the 32-byte previous_rms wire width, not a default",
            },
            "possession_proof_json": {
                "literals": {"32": 1},
                "reason": "the 32-byte RMS wire width, not a default",
            },
            "raw_slice": {
                "decisions": {"if": 1},
                "reason": "raw pointer decoding: rejects a null pointer",
            },
            "seal_contact_share_json": {
                "literals": {"1": 1},
                "reason": "the envelope `version: 1` wire constant, not a default",
            },
            "vela_ffi_free_string": {
                "decisions": {"if": 1},
                "reason": "C ABI free: null guard, no decision",
            },
        },
    },
    "libVELA/vela-wasm-bridge/src/lib.rs": {
        "exports": [
            "create_auth_signature_json",
            "decrypt_admitted_vault_chunk_json",
            "encrypt_vault_chunk_json",
            "generate_ephemeral_keypair",
            "generate_signing_keypair",
            "open_link_json",
            "open_share_json",
            "password_strength_json",
            "vela_wasm_version",
        ],
        "allow": {
            "decode_key": {
                "literals": {"32": 1},
                "reason": "the 32-byte chunk-key wire width, not a default",
            },
            "open_link_impl": {
                "decisions": {"if": 1, "match": 1},
                "reason": "an empty passphrase/salt string is the wire encoding of "
                "an absent optional; no security decision",
            },
            "respond": {
                "decisions": {"match": 1},
                "defaults": {"unwrap_or": 1},
                "reason": "JSON/error envelope; the match is a decode failure and "
                "the fallback is the fixed serialization-error JSON",
            },
            "err_json": {
                "defaults": {"unwrap_or": 1},
                "reason": "serialization failure becomes the fixed bridge-error "
                "JSON; ABI fallback, not a security default",
            },
            "wasm_refusal_message": {
                "decisions": {"match": 1},
                "reason": "renders the core refusal enum into the web error "
                "envelope; wording only, every fact comes from the core",
            },
        },
    },
}

# Calls into a hand-mirrored module that this check cannot review. Each entry
# needs a reason and a follow-up; it is printed in the checker output so it is
# never silently accepted.
MODULE_EXEMPTIONS = {
    "libVELA/vela-android-bridge/src/lib.rs": {
        "passkey::": (
            "hand-mirrored WebAuthn primitives (FFI inventory F4); moving them "
            "into a shared core crate is a listed follow-up, not a conversion"
        )
    },
}

# File-level allowances. Empty means the file must contain no serde default
# attribute and no `default_*` helper returning a literal.
FILE_ALLOW = {
    "libVELA/vela-android-bridge/src/lib.rs": {},
    "libVELA/vela-apple-bridge/src/lib.rs": {},
    "libVELA/vela-wasm-bridge/src/lib.rs": {},
}

# Every local function reachable from an export must be named here with the
# category its review found. A new helper fails until a reviewer classifies it.
HELPER_CATEGORIES = {
    "abi": "JNI/C-ABI plumbing: pointer/string decode and the error envelope",
    "codec": "value conversion or wording: base64, UTF-8, key width, enum text",
    "impl": "request DTO -> one reviewed core call -> response DTO",
}

HELPERS = {
    "libVELA/vela-android-bridge/src/lib.rs": {
        "android_refusal_message": "codec",
        "c_str": "abi",
        "chunk_key": "codec",
        "combine_recovery_bytes": "impl",
        "combine_recovery_json": "impl",
        "decode_optional_b64": "codec",
        "decode_rms": "codec",
        "decrypt_admitted_vault_chunk_with_rms": "impl",
        "decrypt_enrollment_package_json": "impl",
        "decrypt_rms_capsule_bytes": "impl",
        "decrypt_rms_capsule_json": "impl",
        "decrypt_vault_chunk_with_rms": "impl",
        "decrypt_vault_json": "impl",
        "decrypt_vault_with_rms": "impl",
        "encrypt_vault_chunk_with_rms": "impl",
        "encrypt_vault_json": "impl",
        "encrypt_vault_with_rms": "impl",
        "error_json": "abi",
        "identity_admit_share": "impl",
        "identity_create": "impl",
        "identity_enrollment_fingerprint": "impl",
        "identity_forget": "impl",
        "identity_forget_all": "impl",
        "identity_import": "impl",
        "identity_open": "impl",
        "identity_open_enrollment_capsule": "impl",
        "identity_open_share": "impl",
        "identity_response": "impl",
        "identity_rotate_share_key": "impl",
        "identity_seal_signed_share": "impl",
        "identity_sign": "impl",
        "identity_sign_enrollment_result": "impl",
        "identity_sign_share_ek": "impl",
        "jni_json_result": "abi",
        "jni_json_result_into_secret": "abi",
        "jni_json_result_with_secret": "abi",
        "jni_secret_bytes": "abi",
        "jni_secret_json_result": "abi",
        "jni_string": "abi",
        "json_result": "abi",
        "key32": "codec",
        "open_rekey_capsule_json": "impl",
        "parse_import_request": "impl",
        "plan_recovery_publication_json": "impl",
        "raw_key32": "abi",
        "raw_rms": "abi",
        "raw_slice": "abi",
        "rms_possession_hash_bytes": "codec",
        "seal_share_json": "impl",
        "split_recovery_with_rms": "impl",
        "string_to_ptr": "abi",
        "vec_to_buffer": "abi",
        "web_session_chunk_keys_with_rms": "impl",
    },
    "libVELA/vela-apple-bridge/src/lib.rs": {
        "apple_refusal_message": "codec",
        "c_str": "abi",
        "chunk_key": "codec",
        "combine_recovery_json": "impl",
        "decode_key32": "codec",
        "decode_optional_b64": "codec",
        "decrypt_admitted_vault_chunk_json": "impl",
        "decrypt_enrollment_package_json": "impl",
        "decrypt_rms_capsule_json": "impl",
        "decrypt_vault_chunk_json": "impl",
        "decrypt_vault_json": "impl",
        "encrypt_vault_chunk_json": "impl",
        "encrypt_vault_json": "impl",
        "error_json": "abi",
        "generate_recovery_request_json": "impl",
        "identity_admit_share_impl": "impl",
        "identity_create_impl": "impl",
        "identity_enrollment_fingerprint_impl": "impl",
        "identity_forget_impl": "impl",
        "identity_import_impl": "impl",
        "identity_open_enrollment_capsule_impl": "impl",
        "identity_open_impl": "impl",
        "identity_open_share_impl": "impl",
        "identity_response": "impl",
        "identity_rotate_share_key_impl": "impl",
        "identity_seal_signed_share_impl": "impl",
        "identity_sign_enrollment_result_impl": "impl",
        "identity_sign_impl": "impl",
        "identity_sign_share_ek_impl": "impl",
        "json_result": "abi",
        "open_contact_share_json": "impl",
        "open_rekey_capsule_impl": "impl",
        "plan_recovery_publication_json": "impl",
        "possession_proof_json": "impl",
        "raw_slice": "abi",
        "rms_from": "codec",
        "seal_contact_share_json": "impl",
        "seal_contact_share_response_json": "impl",
        "seal_key_from": "codec",
        "seal_share_json": "impl",
        "split_recovery_json": "impl",
        "string_to_ptr": "abi",
        "web_session_chunk_keys_json": "impl",
    },
    "libVELA/vela-wasm-bridge/src/lib.rs": {
        "create_auth_signature_impl": "impl",
        "decode_key": "codec",
        "decrypt_admitted_vault_chunk_impl": "impl",
        "encrypt_vault_chunk_impl": "impl",
        "err_json": "codec",
        "generate_ephemeral_keypair_impl": "impl",
        "generate_signing_keypair_impl": "impl",
        "open_link_impl": "impl",
        "open_share_impl": "impl",
        "password_strength_impl": "impl",
        "record_admission": "codec",
        "respond": "codec",
        "wasm_refusal_message": "codec",
        "with_admission": "codec",
    },
}


@dataclass
class Token:
    text: str
    kind: str
    line: int


@dataclass
class Function:
    name: str
    attrs: list[str]
    body: list[Token]
    params: set[str]
    line: int
    is_export: bool


def lex(source: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(source)
    line = 1
    while i < n:
        c = source[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if source.startswith("//", i):
            j = source.find("\n", i)
            i = n if j < 0 else j
            continue
        if source.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                elif source[i] == "\n":
                    line += 1
                    i += 1
                else:
                    i += 1
            continue
        end = _string_end(source, i)
        if end is not None:
            tokens.append(Token("<string>", "string", line))
            line += source.count("\n", i, end)
            i = end
            continue
        if c == "'":
            # A lifetime starts with an apostrophe and an identifier and has no
            # closing apostrophe; anything else is a char literal.
            if (
                i + 1 < n
                and (source[i + 1].isalpha() or source[i + 1] == "_")
                and not (i + 2 < n and source[i + 2] == "'")
            ):
                j = i + 1
                while j < n and (source[j].isalnum() or source[j] == "_"):
                    j += 1
                tokens.append(Token("<lifetime>", "lifetime", line))
                i = j
                continue
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == "'":
                    j += 1
                    break
                j += 1
            tokens.append(Token("<char>", "char", line))
            i = j
            continue
        if c.isalpha() or c == "_":
            j = i + 1
            while j < n and (source[j].isalnum() or source[j] == "_"):
                j += 1
            tokens.append(Token(source[i:j], "ident", line))
            i = j
            continue
        if c.isdigit():
            j = i + 1
            while j < n and (source[j].isalnum() or source[j] in "._"):
                j += 1
            tokens.append(Token(source[i:j], "number", line))
            i = j
            continue
        for op in (
            "::", "->", "=>", "..=", "..", "<=", ">=", "==", "!=", "&&", "||",
            "+=", "-=", "*=", "/=", "<<", ">>",
        ):
            if source.startswith(op, i):
                tokens.append(Token(op, "punct", line))
                i += len(op)
                break
        else:
            tokens.append(Token(c, "punct", line))
            i += 1
    return tokens


def _string_end(source: str, i: int) -> int | None:
    """Return the end index of a string/char-prefixed literal at ``i``."""
    n = len(source)
    prefix = ""
    j = i
    if j < n and source[j] in "bc":
        prefix = source[j]
        j += 1
    if j < n and source[j] == "r":
        raw = True
        j += 1
    else:
        raw = False
    if j < n and source[j] == "#" and not raw:
        # `r#ident` is a raw identifier, not a string.
        return None
    if not raw and prefix == "" and j < n and source[j] != '"':
        return None
    if raw and j < n and source[j] == "#":
        hashes = 0
        while j < n and source[j] == "#":
            hashes += 1
            j += 1
    else:
        hashes = 0
    if j >= n or source[j] != '"':
        return None
    if not raw:
        k = j + 1
        while k < n:
            if source[k] == "\\":
                k += 2
                continue
            if source[k] == '"':
                return k + 1
            k += 1
        return n
    closing = '"' + "#" * hashes
    k = source.find(closing, j + 1)
    return n if k < 0 else k + len(closing)


def attributes_before(tokens: list[Token], index: int) -> list[str]:
    attrs: list[str] = []
    k = index - 1
    while k >= 0:
        if tokens[k].text == "]":
            depth = 0
            m = k
            while m >= 0:
                if tokens[m].text == "]":
                    depth += 1
                elif tokens[m].text == "[":
                    depth -= 1
                    if depth == 0:
                        break
                m -= 1
            if m > 0 and tokens[m - 1].text == "#":
                attrs.append("".join(t.text for t in tokens[m + 1 : k]))
                k = m - 2
                continue
            break
        if tokens[k].text in {"pub", "unsafe", "extern", "const", "async", "default"}:
            k -= 1
            continue
        if tokens[k].kind == "string":
            k -= 1
            continue
        break
    return attrs


def _brace_end(tokens: list[Token], open_index: int) -> int:
    depth = 0
    k = open_index
    while k < len(tokens):
        if tokens[k].text == "{":
            depth += 1
        elif tokens[k].text == "}":
            depth -= 1
            if depth == 0:
                return k
        k += 1
    return len(tokens) - 1


def _module_ranges(tokens: list[Token]) -> list[tuple[int, int]]:
    """Token ranges of `mod tests { ... }` blocks."""
    ranges: list[tuple[int, int]] = []
    for i, tok in enumerate(tokens):
        if tok.text == "mod" and i + 2 < len(tokens) and tokens[i + 2].text == "{":
            if tokens[i + 1].text == "tests":
                ranges.append((i, _brace_end(tokens, i + 2)))
    return ranges


def _impl_ranges(tokens: list[Token]) -> list[tuple[int, int, str]]:
    """Token ranges of `impl ... { ... }` blocks and their headers."""
    ranges: list[tuple[int, int, str]] = []
    paren = 0
    for i, tok in enumerate(tokens):
        if tok.text == "(":
            paren += 1
            continue
        if tok.text == ")":
            paren -= 1
            continue
        if tok.text != "impl" or paren != 0:
            continue
        # `-> impl Trait` and `+ impl Trait` are bounds, not item impls.
        if i > 0 and tokens[i - 1].text in {"->", ":", "+"}:
            continue
        j = i + 1
        header: list[str] = []
        while j < len(tokens) and tokens[j].text != "{":
            header.append(tokens[j].text)
            j += 1
        if j < len(tokens):
            ranges.append((i, _brace_end(tokens, j), "".join(header)))
    return ranges


def _strip_attributes(tokens: list[Token]) -> list[Token]:
    """Remove `#[...]` attributes (inner struct derives, serde defaults)."""
    out: list[Token] = []
    i = 0
    while i < len(tokens):
        if (
            tokens[i].text == "#"
            and i + 1 < len(tokens)
            and tokens[i + 1].text == "["
        ):
            depth = 0
            j = i + 1
            while j < len(tokens):
                if tokens[j].text == "[":
                    depth += 1
                elif tokens[j].text == "]":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            i = j + 1
            continue
        out.append(tokens[i])
        i += 1
    return out


def _params(tokens: list[Token], open_index: int, close_index: int) -> set[str]:
    """Parameter names between the signature parentheses."""
    names: set[str] = set()
    for i in range(open_index + 1, close_index):
        if (
            tokens[i].kind == "ident"
            and i + 1 < close_index
            and tokens[i + 1].text == ":"
        ):
            names.add(tokens[i].text)
    return names


def find_functions(tokens: list[Token]) -> list[Function]:
    tests = _module_ranges(tokens)
    impls = _impl_ranges(tokens)
    functions: list[Function] = []
    i = 0
    while i < len(tokens):
        if tokens[i].kind == "ident" and tokens[i].text == "fn" and i + 1 < len(tokens):
            if any(start <= i <= end for start, end in tests):
                i += 1
                continue
            if any(start <= i <= end for start, end, _ in impls):
                i += 1
                continue
            name = tokens[i + 1].text
            j = i + 2
            angle = 0
            while j < len(tokens):
                t = tokens[j].text
                if t == "<":
                    angle += 1
                elif t == ">":
                    angle -= 1
                elif t == "(" and angle == 0:
                    break
                j += 1
            params_open = j
            paren = 0
            while j < len(tokens):
                t = tokens[j].text
                if t == "(":
                    paren += 1
                elif t == ")":
                    paren -= 1
                    if paren == 0:
                        break
                j += 1
            params_close = j
            while j < len(tokens):
                if tokens[j].text == "{" and paren == 0:
                    break
                j += 1
            if j >= len(tokens):
                break
            end = _brace_end(tokens, j)
            attrs = attributes_before(tokens, i)
            is_export = any(
                "no_mangle" in attr or "wasm_bindgen" in attr for attr in attrs
            )
            functions.append(
                Function(
                    name,
                    attrs,
                    _strip_attributes(tokens[j + 1 : end]),
                    _params(tokens, params_open, params_close),
                    tokens[i].line,
                    is_export,
                )
            )
            i = end + 1
            continue
        i += 1
    return functions


def _numeric_value(text: str) -> int | None:
    match = re.match(r"([0-9][0-9_]*)", text)
    if not match:
        return None
    try:
        return int(match.group(1).replace("_", ""))
    except ValueError:
        return None


def _path_call(tokens: list[Token], close_paren: int) -> tuple[str, str] | None:
    """Return (kind, path) for the call whose `(` is at ``close_paren``."""
    j = close_paren - 1
    if j < 0:
        return None
    macro = False
    if tokens[j].text == "!":
        macro = True
        j -= 1
    if j < 0 or tokens[j].kind != "ident":
        return None
    parts = [tokens[j].text]
    start = j
    while (
        start - 1 >= 0
        and tokens[start - 1].text == "::"
        and start - 2 >= 0
        and tokens[start - 2].kind == "ident"
    ):
        parts.insert(0, tokens[start - 2].text)
        start -= 2
    path = "::".join(parts)
    if macro:
        return ("macro", path + "!")
    if start > 0 and tokens[start - 1].text == ".":
        return ("method", path)
    return ("path", path)


def body_facts(body: list[Token]) -> dict:
    decisions: Counter[str] = Counter()
    literals: Counter[str] = Counter()
    defaults: Counter[str] = Counter()
    calls: list[tuple[str, str]] = []
    for index, tok in enumerate(body):
        if tok.kind == "ident" and tok.text in DECISION_KEYWORDS:
            decisions[tok.text] += 1
        if tok.kind == "number":
            value = _numeric_value(tok.text)
            if value is not None:
                literals[str(value)] += 1
        if tok.text == "(":
            call = _path_call(body, index)
            if call is not None:
                calls.append(call)
        if tok.kind == "ident" and tok.text in {
            "unwrap_or",
            "unwrap_or_else",
            "unwrap_or_default",
        }:
            # Any fallback value is a default a reviewer must see, even when the
            # argument is a constant or the type's `Default` (which can be a
            # numeric 0). Numeric arguments are also counted by value so a
            # default cannot hide behind a helper spelling.
            defaults["unwrap_or"] += 1
            k = index + 1
            if k < len(body) and body[k].text == "(":
                k += 1
                if tok.text == "unwrap_or_else":
                    while k < len(body) and body[k].text in {"|", "||"}:
                        k += 1
                if k < len(body) and body[k].kind == "number":
                    value = _numeric_value(body[k].text)
                    if value is not None:
                        defaults[str(value)] += 1
    return {
        "decisions": decisions,
        "literals": literals,
        "defaults": defaults,
        "calls": calls,
    }


def _local_calls(facts: dict, local_names: set[str]) -> list[str]:
    return sorted(
        {path for kind, path in facts["calls"] if kind == "path" and path in local_names}
    )


def _referenced_locals(body: list[Token], local_names: set[str]) -> set[str]:
    """Local helpers referenced without a call, e.g. passed to `map_err`."""
    refs: set[str] = set()
    for i, tok in enumerate(body):
        if tok.kind != "ident" or tok.text not in local_names:
            continue
        if i > 0 and body[i - 1].text in {".", "::"}:
            continue
        refs.add(tok.text)
    return refs


def _external_calls(
    facts: dict, local_names: set[str], params: set[str], bridge: str
) -> list[str]:
    allowed = CORE_CALLS[bridge] | CODEC_CALLS
    found = set()
    for kind, path in facts["calls"]:
        if kind == "method":
            continue
        if kind == "macro":
            if path.split("::")[-1] not in CODEC_MACROS:
                found.add(path)
            continue
        if path in NOT_CALLS or path in params:
            continue
        if path in local_names or path in allowed:
            continue
        found.add(path)
    return sorted(found)


def check_bridge(root: Path, bridge: str) -> tuple[list[str], set[str]]:
    findings: list[str] = []
    source_path = root / bridge
    if not source_path.is_file():
        return [f"{bridge}: missing"], set()
    source = source_path.read_text(encoding="utf-8")
    functions = find_functions(lex(source))
    exports = {fn.name: fn for fn in functions if fn.is_export}
    locals_ = {fn.name: fn for fn in functions if not fn.is_export}
    manifest = set(ALLOW[bridge]["exports"])
    allowance = ALLOW[bridge]["allow"]

    for name in sorted(set(exports) - manifest):
        findings.append(f"{bridge}: export `{name}` is not in the reviewed manifest")
    for name in sorted(manifest - set(exports)):
        findings.append(f"{bridge}: manifest lists missing export `{name}`")
    for name in sorted(set(locals_) & manifest):
        findings.append(f"{bridge}: `{name}` is both an export and a helper")

    # The bridges must not define inherent methods: method calls are otherwise
    # assumed to resolve to std or a core crate type. The only reviewed impls
    # are the zeroize-on-drop / deref plumbing on SecretBytes.
    for _, _, header in _impl_ranges(lex(source)):
        if not re.match(r"^(std::ops::)?(Drop|Deref)for", header):
            findings.append(
                f"{bridge}: bridge defines impl `{header}`; method calls can no "
                "longer be assumed to be std/core"
            )

    # Serde defaults and `default_*` literal helpers are defaults hidden from
    # the export bodies.
    file_allow = FILE_ALLOW[bridge]
    for match in re.finditer(r'#\[serde\(default\s*=\s*"([^"]+)"\)\]', source):
        name = match.group(1)
        if name not in file_allow.get("serde_defaults", {}):
            findings.append(
                f"{bridge}: serde default `{name}` is a hidden default; move the "
                "default into the core or allow it with a reason"
            )
    for fn in functions:
        if fn.name.startswith("default_") and fn.body:
            literals = body_facts(fn.body)["literals"]
            if literals and fn.name not in file_allow.get("default_functions", {}):
                findings.append(
                    f"{bridge}: `{fn.name}` returns a numeric literal default; "
                    "move the default into the core or allow it with a reason"
                )

    # Resolve the export -> local-helper graph and analyse every reachable body.
    analysed: set[str] = set()
    for export_name, export in sorted(exports.items()):
        stack = [export_name]
        while stack:
            name = stack.pop()
            if name in analysed:
                continue
            analysed.add(name)
            fn = exports.get(name) or locals_.get(name)
            if fn is None:
                continue
            facts = body_facts(fn.body)
            entry = allowance.get(name, {})
            reason = entry.get("reason", "")
            _compare(
                findings, bridge, name, "decision", facts["decisions"],
                entry.get("decisions", {}), reason,
            )
            _compare(
                findings, bridge, name, "literal", facts["literals"],
                entry.get("literals", {}), reason,
            )
            _compare(
                findings, bridge, name, "default", facts["defaults"],
                entry.get("defaults", {}), reason,
            )
            if (
                (entry.get("decisions") or entry.get("literals") or entry.get("defaults"))
                and not reason
            ):
                findings.append(
                    f"{bridge}: `{name}` has allowances without a reason"
                )
            for helper in sorted(
                set(_local_calls(facts, set(locals_)))
                | _referenced_locals(fn.body, set(locals_))
            ):
                if helper not in locals_:
                    findings.append(f"{bridge}: `{name}` calls unknown helper `{helper}`")
                    continue
                if helper not in HELPERS[bridge]:
                    findings.append(
                        f"{bridge}: `{name}` calls unreviewed local helper `{helper}`"
                    )
                    continue
                if helper != name:
                    stack.append(helper)
            for path in _external_calls(facts, set(locals_), fn.params, bridge):
                if _module_exempt(bridge, path):
                    continue
                findings.append(
                    f"{bridge}: `{name}` calls `{path}`, which is neither a "
                    "reviewed core function nor a codec helper"
                )

    for name in sorted(set(allowance) - analysed):
        findings.append(f"{bridge}: allowance for `{name}` matches no reachable body")
    for name in sorted(set(HELPERS[bridge]) - (analysed - set(exports))):
        findings.append(f"{bridge}: helper `{name}` is listed but not reachable")

    return findings, set(exports)


def _module_exempt(bridge: str, path: str) -> bool:
    for prefix in MODULE_EXEMPTIONS.get(bridge, {}):
        if path.startswith(prefix):
            return True
    return False


def _compare(
    findings: list[str],
    bridge: str,
    name: str,
    kind: str,
    actual: Counter[str],
    allowed: dict[str, int],
    reason: str,
) -> None:
    for construct, count in sorted(actual.items()):
        if allowed.get(construct, 0) != count:
            findings.append(
                f"{bridge}: `{name}` has {count} {kind}(s) `{construct}`; "
                f"allowlist has {allowed.get(construct, 0)}"
                + (f" ({reason})" if reason else "")
            )
    for construct in sorted(set(allowed) - set(actual)):
        findings.append(
            f"{bridge}: `{name}` allowance for {kind} `{construct}` is stale"
        )


def check_repo(root: Path) -> list[str]:
    findings: list[str] = []
    for bridge in BRIDGES:
        bridge_findings, _ = check_bridge(root, bridge)
        findings.extend(bridge_findings)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args(argv)
    findings = check_repo(args.root)
    for bridge, prefixes in MODULE_EXEMPTIONS.items():
        for prefix, reason in prefixes.items():
            print(f"note: {bridge}: `{prefix}*` not analysed: {reason}")
    if findings:
        for finding in findings:
            print(f"FAIL {finding}")
        return 1
    print(
        "bridge thinness: "
        + ", ".join(
            f"{Path(bridge).parent.parent.name} "
            f"{len(ALLOW[bridge]['exports'])} exports"
            for bridge in BRIDGES
        )
        + " are conversions around reviewed core calls"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
