//! Ceremony translation: Windows CTAP2-CBOR requests ⇄ VELA vault ceremonies.
//!
//! This is deliberately a *thin* adapter. The single security-relevant rule
//! from the ADR (`security/passkey-native-provider-adr.md`) is honored by
//! construction here: the RP ID, client-data hash and credential lists are
//! passed through from the OS request to the desktop **verbatim**, and the
//! user-verification flag in the returned authenticator data is whatever the
//! desktop's presence gate actually minted — never something this layer
//! asserts. One ceremony per human action stays the desktop's property.

use crate::desktop;
use crate::ffi::{self, hresult, WebAuthn};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use serde_json::json;
use windows::Win32::Foundation::BOOL;

/// Result of a completed ceremony: an encoded CTAP response buffer the OS
/// allocated (`CoTaskMemAlloc`), which the caller transfers to the platform
/// untouched.
pub struct EncodedResponse {
    pub bytes: *mut u8,
    pub len: u32,
}

/// Verify the platform's request signature, then decode the CTAP request.
/// The signature check is not ceremony decoration: it is what proves the
/// request came from the OS WebAuthn service rather than from a process that
/// merely found our COM class object.
fn verify_platform_signature(webauthn: &WebAuthn, request: &ffi::WEBAUTHN_PLUGIN_OPERATION_REQUEST) -> Result<(), i32> {
    unsafe {
        let mut cb_key = 0u32;
        let mut pb_key = std::ptr::null_mut();
        let clsid = crate::COM_CLSID;
        if (webauthn.plugin_get_operation_signing_public_key)(&clsid, &mut cb_key, &mut pb_key) < 0 {
            // No signing key on file (not yet registered): refuse everything.
            return Err(hresult::E_FAIL);
        }
        let key = std::slice::from_raw_parts(pb_key, cb_key as usize);
        let signature = if request.cbRequestSignature > 0 && !request.pbRequestSignature.is_null() {
            std::slice::from_raw_parts(request.pbRequestSignature, request.cbRequestSignature as usize)
        } else {
            &[][..]
        };
        let data = std::slice::from_raw_parts(request.pbEncodedRequest, request.cbEncodedRequest as usize);
        let outcome = ffi::verify_request_signature(data, key, signature);
        (webauthn.plugin_free_public_key_response)(pb_key);
        outcome
    }
}

fn credential_ids(list: &ffi::WEBAUTHN_CREDENTIAL_LIST) -> Vec<String> {
    let mut out = Vec::new();
    if list.cCredentials == 0 || list.ppCredentials.is_null() {
        return out;
    }
    unsafe {
        let entries = std::slice::from_raw_parts(list.ppCredentials, list.cCredentials as usize);
        for entry in entries.iter().filter(|e| !e.is_null() && !(*(**e)).pbId.is_null()) {
            let e = &**entry;
            let id = std::slice::from_raw_parts(e.pbId, e.cbId as usize);
            out.push(B64URL.encode(id));
        }
    }
    out
}

fn uv_required(options: *const ffi::WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS) -> bool {
    // +1 = true, 0 = undefined, -1 = false (webauthnplugin.h).
    if options.is_null() {
        return false;
    }
    unsafe { (*options).lUv == 1 }
}

/// `WEBAUTHN_PLUGIN_REQUEST_TYPE` must be CTAP2 CBOR — anything else means a
/// platform revision this adapter was not built for; refuse rather than guess.
fn request_buffer(request: &ffi::WEBAUTHN_PLUGIN_OPERATION_REQUEST) -> Result<&[u8], i32> {
    if request.requestType != ffi::WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR {
        return Err(hresult::NTE_NOT_SUPPORTED);
    }
    if request.pbEncodedRequest.is_null() || request.cbEncodedRequest == 0 {
        return Err(hresult::E_FAIL);
    }
    Ok(unsafe { std::slice::from_raw_parts(request.pbEncodedRequest, request.cbEncodedRequest as usize) })
}

/// Map a desktop refusal onto the HRESULT the platform understands. The
/// wording comes from `vela-desktop-core`'s IPC layer; match on the stable
/// substrings, never on exact strings.
fn map_refusal(reason: &str) -> i32 {
    let lowered = reason.to_lowercase();
    if lowered.contains("declined") || lowered.contains("said no") {
        hresult::NTE_USER_CANCELLED
    } else if lowered.contains("vault is locked") {
        hresult::NTE_BAD_KEYSET
    } else if lowered.contains("no passkey") || lowered.contains("no credential") {
        hresult::NTE_NOT_FOUND
    } else if lowered.contains("algorithm") {
        hresult::NTE_NOT_SUPPORTED
    } else if lowered.contains("excluded") {
        hresult::NTE_EXISTS
    } else {
        hresult::E_FAIL
    }
}

pub fn make_credential(
    webauthn: &WebAuthn,
    request: &ffi::WEBAUTHN_PLUGIN_OPERATION_REQUEST,
) -> Result<EncodedResponse, i32> {
    request_buffer(request)?;
    verify_platform_signature(webauthn, request)?;

    let decoded = unsafe {
        let mut ptr = std::ptr::null_mut();
        if (webauthn.decode_make_credential_request)(request.cbEncodedRequest, request.pbEncodedRequest, &mut ptr) < 0 {
            return Err(hresult::E_FAIL);
        }
        ptr
    };

    // Keep the free on every path after decode.
    struct Decoded(*mut ffi::WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST, WebAuthn);
    impl Drop for Decoded {
        fn drop(&mut self) {
            unsafe { (self.1.free_decoded_make_credential_request)(self.0) };
        }
    }
    let _guard = Decoded(decoded, *webauthn);

    let vela_request = unsafe {
        let decoded = &*decoded;
        let rp_id_bytes = std::slice::from_raw_parts(decoded.pbRpId, decoded.cbRpId as usize);
        let rp_id = match std::str::from_utf8(rp_id_bytes) {
            Ok(id) => id.to_string(),
            Err(_) => return Err(hresult::E_FAIL),
        };
        let client_data_hash =
            std::slice::from_raw_parts(decoded.pbClientDataHash, decoded.cbClientDataHash as usize);
        let (rp_name, user_name, user_display_name, user_handle) =
            if decoded.pUserInformation.is_null() {
                (String::new(), String::new(), String::new(), Vec::new())
            } else {
                let user = &*decoded.pUserInformation;
                (
                    ffi::pwstr_to_string((*decoded.pRpInformation).pwszName),
                    ffi::pwstr_to_string(user.pwszName),
                    ffi::pwstr_to_string(user.pwszDisplayName),
                    if user.pbId.is_null() {
                        Vec::new()
                    } else {
                        std::slice::from_raw_parts(user.pbId, user.cbId as usize).to_vec()
                    },
                )
            };
        let algorithms: Vec<i32> = if decoded.WebAuthNCredentialParameters.pCredentialParameters.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(
                decoded.WebAuthNCredentialParameters.pCredentialParameters,
                decoded.WebAuthNCredentialParameters.cCredentialParameters as usize,
            )
            .iter()
            .map(|p| p.lAlg)
            .collect()
        };

        json!({
            "rp_id": rp_id,
            "rp_name": rp_name,
            "user_handle": desktop::encode_b64url(&user_handle),
            "user_name": user_name,
            "user_display_name": user_display_name,
            "client_data_hash": desktop::encode_b64url(client_data_hash),
            "algorithms": algorithms,
            "exclude_credentials": credential_ids(&decoded.CredentialList),
            "require_user_verification": uv_required(decoded.pAuthenticatorOptions),
        })
    };

    use serde_json::Value;
    let vela_request: Value = vela_request;

    let outcome = desktop::make_credential(&vela_request).map_err(|reason| {
        tracing_disabled_warn(&reason);
        map_refusal(&reason)
    })?;

    // The desktop's `fmt: "none"` attestation means the OS helper only needs
    // the authenticator data; the attestation statement is CBOR null.
    let attestation = ffi::WEBAUTHN_CREDENTIAL_ATTESTATION {
        dwVersion: ffi::WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION,
        pwszFormatType: ffi::WEBAUTHN_ATTESTATION_TYPE_NONE,
        cbAuthenticatorData: outcome.authenticator_data.len() as u32,
        pbAuthenticatorData: outcome.authenticator_data.as_ptr() as *mut u8,
        cbAttestation: 0,
        pbAttestation: std::ptr::null_mut(),
        dwAttestationDecodeType: 0,
        pvAttestationDecode: std::ptr::null_mut(),
        cbAttestationObject: 0,
        pbAttestationObject: std::ptr::null_mut(),
        cbCredentialId: outcome.credential_id.len() as u32,
        pbCredentialId: outcome.credential_id.as_ptr() as *mut u8,
        Extensions: ffi::WEBAUTHN_EXTENSIONS { cExtensions: 0, pExtensions: std::ptr::null_mut() },
        dwUsedTransport: 0,
        bEpAtt: BOOL(0),
        bLargeBlobSupported: BOOL(0),
        bResidentKey: BOOL(0),
        bPrfEnabled: BOOL(0),
        cbUnsignedExtensionOutputs: 0,
        pbUnsignedExtensionOutputs: std::ptr::null_mut(),
        pHmacSecret: std::ptr::null_mut(),
        bThirdPartyPayment: BOOL(0),
        dwTransports: 0,
        cbClientDataJSON: 0,
        pbClientDataJSON: std::ptr::null_mut(),
        cbRegistrationResponseJSON: 0,
        pbRegistrationResponseJSON: std::ptr::null_mut(),
    };

    unsafe {
        let mut len = 0u32;
        let mut bytes = std::ptr::null_mut();
        if (webauthn.encode_make_credential_response)(&attestation, &mut len, &mut bytes) < 0 {
            return Err(hresult::E_FAIL);
        }
        // Surface the new passkey to the OS autofill cache; a cache miss here
        // degrades autofill only, never the ceremony itself.
        let _ = push_created_credential_metadata(webauthn, &vela_request, &outcome.credential_id);
        Ok(EncodedResponse { bytes, len })
    }
}

pub fn get_assertion(
    webauthn: &WebAuthn,
    request: &ffi::WEBAUTHN_PLUGIN_OPERATION_REQUEST,
) -> Result<EncodedResponse, i32> {
    request_buffer(request)?;
    verify_platform_signature(webauthn, request)?;

    let decoded = unsafe {
        let mut ptr = std::ptr::null_mut();
        if (webauthn.decode_get_assertion_request)(request.cbEncodedRequest, request.pbEncodedRequest, &mut ptr) < 0 {
            return Err(hresult::E_FAIL);
        }
        ptr
    };
    struct Decoded(*mut ffi::WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST, WebAuthn);
    impl Drop for Decoded {
        fn drop(&mut self) {
            unsafe { (self.1.free_decoded_get_assertion_request)(self.0) };
        }
    }
    let _guard = Decoded(decoded, *webauthn);

    use serde_json::Value;
    let vela_request: Value = unsafe {
        let decoded = &*decoded;
        let rp_id = ffi::pwstr_to_string(decoded.pwszRpId);
        let client_data_hash =
            std::slice::from_raw_parts(decoded.pbClientDataHash, decoded.cbClientDataHash as usize);
        json!({
            "rp_id": rp_id,
            "client_data_hash": desktop::encode_b64url(client_data_hash),
            "allow_credentials": credential_ids(&decoded.CredentialList),
            "require_user_verification": uv_required(decoded.pAuthenticatorOptions),
        })
    };

    let outcome = desktop::get_assertion(&vela_request).map_err(|reason| {
        tracing_disabled_warn(&reason);
        map_refusal(&reason)
    })?;

    let assertion = ffi::WEBAUTHN_ASSERTION {
        dwVersion: ffi::WEBAUTHN_ASSERTION_CURRENT_VERSION,
        cbAuthenticatorData: outcome.authenticator_data.len() as u32,
        pbAuthenticatorData: outcome.authenticator_data.as_ptr() as *mut u8,
        cbSignature: outcome.signature.len() as u32,
        pbSignature: outcome.signature.as_ptr() as *mut u8,
        Credential: ffi::WEBAUTHN_CREDENTIAL {
            dwVersion: ffi::WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: outcome.credential_id.len() as u32,
            pbId: outcome.credential_id.as_ptr() as *mut u8,
            pwszCredentialType: ffi::WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        },
        cbUserId: outcome.user_handle.len() as u32,
        pbUserId: outcome.user_handle.as_ptr() as *mut u8,
        Extensions: ffi::WEBAUTHN_EXTENSIONS { cExtensions: 0, pExtensions: std::ptr::null_mut() },
        cbCredLargeBlob: 0,
        pbCredLargeBlob: std::ptr::null_mut(),
        dwCredLargeBlobStatus: 0,
        pHmacSecret: std::ptr::null_mut(),
        dwUsedTransport: 0,
        cbUnsignedExtensionOutputs: 0,
        pbUnsignedExtensionOutputs: std::ptr::null_mut(),
        cbClientDataJSON: 0,
        pbClientDataJSON: std::ptr::null_mut(),
        cbAuthenticationResponseJSON: 0,
        pbAuthenticationResponseJSON: std::ptr::null_mut(),
    };
    let ctap_response = ffi::WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE {
        WebAuthNAssertion: assertion,
        pUserInformation: std::ptr::null_mut(),
        dwNumberOfCredentials: 1,
        lUserSelected: 0,
        cbLargeBlobKey: 0,
        pbLargeBlobKey: std::ptr::null_mut(),
        cbUnsignedExtensionOutputs: 0,
        pbUnsignedExtensionOutputs: std::ptr::null_mut(),
    };

    unsafe {
        let mut len = 0u32;
        let mut bytes = std::ptr::null_mut();
        if (webauthn.encode_get_assertion_response)(&ctap_response, &mut len, &mut bytes) < 0 {
            return Err(hresult::E_FAIL);
        }
        Ok(EncodedResponse { bytes, len })
    }
}

/// Register the just-created passkey with the OS autofill cache, using the
/// same entity information the platform itself supplied in the request.
unsafe fn push_created_credential_metadata(
    webauthn: &WebAuthn,
    vela_request: &serde_json::Value,
    credential_id: &[u8],
) -> windows::core::Result<()> {
    let rp_id = vela_request.get("rp_id").and_then(|v| v.as_str()).unwrap_or("");
    let rp_name = vela_request.get("rp_name").and_then(|v| v.as_str()).unwrap_or(rp_id);
    let user_name = vela_request.get("user_name").and_then(|v| v.as_str()).unwrap_or("");
    let user_display_name = vela_request
        .get("user_display_name")
        .and_then(|v| v.as_str())
        .unwrap_or(user_name);
    let user_handle_b64 = vela_request.get("user_handle").and_then(|v| v.as_str()).unwrap_or("");
    let user_handle = B64URL.decode(user_handle_b64).unwrap_or_default();

    let rp_id_w = ffi::wide(rp_id);
    let rp_name_w = ffi::wide(rp_name);
    let user_name_w = ffi::wide(user_name);
    let display_w = ffi::wide(user_display_name);

    let details = ffi::WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
        cbCredentialId: credential_id.len() as u32,
        pbCredentialId: credential_id.as_ptr(),
        pwszRpId: windows::core::PCWSTR::from_raw(rp_id_w.as_ptr()),
        pwszRpName: windows::core::PCWSTR::from_raw(rp_name_w.as_ptr()),
        cbUserId: user_handle.len() as u32,
        pbUserId: user_handle.as_ptr(),
        pwszUserName: windows::core::PCWSTR::from_raw(user_name_w.as_ptr()),
        pwszUserDisplayName: windows::core::PCWSTR::from_raw(display_w.as_ptr()),
    };
    let clsid = crate::COM_CLSID;
    let hr = (webauthn.plugin_add_credentials)(&clsid, 1, &details);
    if hr < 0 {
        Err(windows::core::Error::from_hresult(windows::core::HRESULT(hr)))
    } else {
        Ok(())
    }
}

/// The provider process does not pull the whole `tracing` stack in; ceremony
/// refusals are already audited where the decision is made (the desktop).
fn tracing_disabled_warn(reason: &str) {
    eprintln!("VELA passkey provider: ceremony refused: {reason}");
}


