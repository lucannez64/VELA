//! Native CTAP2/FIDO2 client for the security-key recovery method —
//! replaces the original React frontend's browser `navigator.credentials`
//! calls (see `src/lib/webauthn.ts`) with a real hardware ceremony, talking
//! directly to a connected USB/NFC security key via `ctap-hid-fido2`.
//!
//! The wire protocol (what gets sent to/received from the server) uses
//! `webauthn-rs-proto` — the server's own wire-format crate, pinned to the
//! exact version `serverVELA` depends on — so the JSON shapes match by
//! construction rather than by hand-transcription.
//!
//! Two real gaps had to be closed to make a *raw CTAP2* library produce
//! something a *WebAuthn* relying party (the server's `webauthn-rs`) will
//! accept:
//!
//! 1. **clientDataJSON.** `ctap-hid-fido2`'s own "challenge" parameter is
//!    hashed directly (`sha256(challenge)`) to get the value sent to the
//!    authenticator — it has no concept of the browser's
//!    `{"type":...,"challenge":...,"origin":...,"crossOrigin":false}`
//!    envelope that a real WebAuthn verifier expects to hash instead. This
//!    module builds that envelope itself and feeds *its* bytes in as the
//!    "challenge" parameter — the crate ends up hashing exactly what a
//!    browser would have hashed, and the same envelope bytes are relayed to
//!    the server for it to verify independently.
//!
//! 2. **origin.** A browser's ceremony origin is implicit (the page's own
//!    origin); a native app has none. The server's `webauthn-rs` verifier
//!    strictly checks the ceremony origin against its own configured
//!    `WEBAUTHN_RP_ORIGIN` — inventing a value would fail verification on
//!    any deployment that isn't using the exact default. `[ApiClient::
//!    get_webauthn_config]` fetches the real configured value instead of
//!    guessing.
//!
//! 3. **attestationObject.** `ctap-hid-fido2` returns the registration
//!    result as a parsed [`Attestation`] struct, not the raw CBOR blob the
//!    server expects. This module re-encodes it via `ciborium`, matching
//!    the WebAuthn spec's `{fmt, attStmt, authData}` CBOR map. Only the
//!    "packed" and "none" attestation statement formats are handled (the
//!    two essentially every FIDO2 security key uses); an unrecognized `fmt`
//!    falls back to a best-effort `{alg, sig, x5c}` attStmt.
//!
//! No masking/PRF/`hmac-secret` extension is used anywhere in this
//! ceremony (confirmed against the server's stored credential and the
//! original TS client — grepped for `prf`/`hmac-secret`, zero hits): the
//! security key is purely a release gate for Share 2, not a KDF input, so
//! there is nothing beyond standard registration/assertion to implement.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ciborium::value::Value as Cbor;
use ctap_hid_fido2::{
    fidokey::{
        get_assertion::get_assertion_params::Assertion, make_credential::make_credential_params::Attestation,
        GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
    },
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
    Cfg, FidoKeyHidFactory,
};
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw,
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs, RequestChallengeResponse,
};

use crate::api::ApiClient;
use crate::AppState;

/// Builds the standard W3C clientDataJSON envelope. A real browser
/// constructs and hashes exactly this before handing the hash to the
/// authenticator; `ctap-hid-fido2` has no equivalent step, so this module
/// does it and passes the resulting bytes in as the crate's own "challenge"
/// parameter (which it hashes directly) — see the module doc.
fn client_data_json(ceremony_type: &str, challenge_b64url: &str, origin: &str) -> Vec<u8> {
    let value = serde_json::json!({
        "type": ceremony_type,
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": false,
    });
    serde_json::to_vec(&value).expect("serializing a fixed JSON shape cannot fail")
}

/// Re-encodes a parsed [`Attestation`] back into the raw CBOR
/// `attestationObject` bytes (`{fmt, attStmt, authData}`) the server's
/// `webauthn-rs` verifier expects to decode. `auth_data` is already the
/// complete raw `authenticatorData` bytes (attested credential data and
/// all) — only `attStmt` needs reconstructing from the parsed fields.
fn encode_attestation_object(attestation: &Attestation) -> Result<Vec<u8>, String> {
    let att_stmt = match attestation.fmt.as_str() {
        "none" => Cbor::Map(vec![]),
        _ => {
            // Covers "packed" (the near-universal case for real FIDO2 keys)
            // and used as a best-effort fallback for any other fmt string —
            // all attestation statement formats this server is likely to
            // see share this {alg, sig, x5c?} shape.
            let mut fields = vec![
                (Cbor::Text("alg".into()), Cbor::Integer((attestation.attstmt_alg as i64).into())),
                (Cbor::Text("sig".into()), Cbor::Bytes(attestation.attstmt_sig.clone())),
            ];
            if !attestation.attstmt_x5c.is_empty() {
                fields.push((
                    Cbor::Text("x5c".into()),
                    Cbor::Array(attestation.attstmt_x5c.iter().cloned().map(Cbor::Bytes).collect()),
                ));
            }
            Cbor::Map(fields)
        }
    };

    let object = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text(attestation.fmt.clone())),
        (Cbor::Text("attStmt".into()), att_stmt),
        (Cbor::Text("authData".into()), Cbor::Bytes(attestation.auth_data.clone())),
    ]);

    let mut bytes = Vec::new();
    ciborium::into_writer(&object, &mut bytes).map_err(|e| format!("Failed to encode attestation object: {e}"))?;
    Ok(bytes)
}

/// Registers this device's connected security key as the account's
/// recovery credential — port of `RecoverySettings.tsx`'s/`SetupScreen.
/// tsx`'s `handleSecurityKeySetup`. Requires exactly one FIDO2 HID device
/// connected (surfaces a clear error otherwise, matching the crate's own
/// "not found"/"multiple found" cases rather than guessing which to use).
pub async fn register_security_key(state: &AppState, pin: String) -> Result<(), String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);
    let token = state.get_session_token().ok_or("Not authenticated — unlock your vault and be online first.")?;

    let rp_config =
        client.get_webauthn_config().await.map_err(|e| format!("Failed to fetch WebAuthn config: {e}"))?;

    let (start_resp, new_token) = client
        .start_recovery_webauthn_registration(&token, None, None)
        .await
        .map_err(|e| format!("Failed to start WebAuthn registration: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    let ccr: CreationChallengeResponse = serde_json::from_value(start_resp.public_key)
        .map_err(|e| format!("Unexpected registration challenge shape from server: {e}"))?;
    let options = ccr.public_key;

    let challenge_b64 = B64URL.encode(options.challenge.as_ref());
    let client_data = client_data_json("webauthn.create", &challenge_b64, &rp_config.rp_origin);

    let exclude_ids: Vec<Vec<u8>> =
        options.exclude_credentials.unwrap_or_default().into_iter().map(|d| d.id.as_ref().to_vec()).collect();
    let user_id = options.user.id.as_ref().to_vec();
    let user_name = options.user.name.clone();
    let user_display_name = options.user.display_name.clone();
    let rp_id = rp_config.rp_id.clone();

    // Real hardware I/O — blocks this thread until the key responds (or the
    // crate's own internal timeout elapses), so must run on a blocking
    // thread rather than the async runtime.
    let client_data_for_ceremony = client_data.clone();
    let attestation = tokio::task::spawn_blocking(move || -> Result<Attestation, String> {
        let device = FidoKeyHidFactory::create(&Cfg::init())
            .map_err(|e| format!("No security key found: {e}"))?;

        let user_entity =
            PublicKeyCredentialUserEntity::new(Some(&user_id), Some(&user_name), Some(&user_display_name));
        let mut builder =
            MakeCredentialArgsBuilder::new(&rp_id, &client_data_for_ceremony).pin(&pin).user_entity(&user_entity);
        for id in &exclude_ids {
            builder = builder.exclude_authenticator(id);
        }
        let args = builder.build();

        device.make_credential_with_args(&args).map_err(|e| format!("Security key registration failed: {e}"))
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))??;

    let attestation_object = encode_attestation_object(&attestation)?;
    let credential_id = attestation.credential_descriptor.id.clone();

    let credential = RegisterPublicKeyCredential {
        id: B64URL.encode(&credential_id),
        raw_id: credential_id.into(),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: attestation_object.into(),
            client_data_json: client_data.into(),
            transports: None,
        },
        type_: "public-key".to_string(),
        extensions: RegistrationExtensionsClientOutputs::default(),
    };
    let credential_json =
        serde_json::to_value(&credential).map_err(|e| format!("Failed to serialize credential: {e}"))?;

    let (finish_resp, new_token) = client
        .finish_recovery_webauthn_registration(&token, credential_json)
        .await
        .map_err(|e| format!("Server rejected the security key registration: {e}"))?;
    if let Some(t) = new_token {
        state.session.write().set_server_token(t);
    }

    if !finish_resp.registered {
        return Err("Server did not confirm the security key registration".to_string());
    }

    // The recovery passkey is now registered server-side — immediately hand
    // it the share it's meant to gate (Share 2 of the 2-of-3 split; see
    // `crate::recovery`). Registering the credential without ever storing a
    // share behind it would leave "security key recovery" enabled in the UI
    // but functionally inert.
    let current_token = state.get_session_token().ok_or("No session token available")?;
    crate::recovery::deliver_security_key_share(state, &current_token).await?;

    Ok(())
}

/// Completes a lost-account recovery using a security key — port of
/// `RecoverAccountModal.tsx`'s `handleVerify`. `user_id` identifies the
/// account being recovered (looked up by the caller some other way, e.g. a
/// remembered device/user id — there is no session yet, by definition,
/// since this is the "I lost every device" path). Returns the raw Shamir
/// Share 2 and a single-use recovery grant on success, exactly as the
/// server hands them back; combining Share 2 with Share 1/3 and redeeming
/// the grant via `enroll_device_via_recovery` is the caller's job.
pub async fn recover_account_with_security_key(
    state: &AppState,
    user_id: &str,
    pin: String,
) -> Result<crate::api::RecoveryRecoverResponse, String> {
    let server_url = state.server_url.read().clone();
    let client = ApiClient::with_url(server_url);

    let rp_config =
        client.get_webauthn_config().await.map_err(|e| format!("Failed to fetch WebAuthn config: {e}"))?;

    let initiate_resp =
        client.initiate_recovery(user_id).await.map_err(|e| format!("Failed to start account recovery: {e}"))?;

    let rcr: RequestChallengeResponse = serde_json::from_value(initiate_resp.public_key)
        .map_err(|e| format!("Unexpected recovery challenge shape from server: {e}"))?;
    let options = rcr.public_key;

    let challenge_b64 = B64URL.encode(options.challenge.as_ref());
    let client_data = client_data_json("webauthn.get", &challenge_b64, &rp_config.rp_origin);

    let allow_ids: Vec<Vec<u8>> = options.allow_credentials.iter().map(|d| d.id.as_ref().to_vec()).collect();
    let rp_id = rp_config.rp_id.clone();

    let client_data_for_ceremony = client_data.clone();
    let assertion = tokio::task::spawn_blocking(move || -> Result<Assertion, String> {
        let device = FidoKeyHidFactory::create(&Cfg::init())
            .map_err(|e| format!("No security key found: {e}"))?;

        let mut builder = GetAssertionArgsBuilder::new(&rp_id, &client_data_for_ceremony).pin(&pin);
        for id in &allow_ids {
            builder = builder.credential_id(id);
        }
        let args = builder.build();

        let assertions =
            device.get_assertion_with_args(&args).map_err(|e| format!("Security key verification failed: {e}"))?;
        assertions.into_iter().next().ok_or_else(|| "Security key returned no assertion".to_string())
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))??;

    let user_handle = if assertion.user.id.is_empty() { None } else { Some(assertion.user.id.clone().into()) };

    let credential = PublicKeyCredential {
        id: B64URL.encode(&assertion.credential_id),
        raw_id: assertion.credential_id.clone().into(),
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: assertion.auth_data.clone().into(),
            client_data_json: client_data.into(),
            signature: assertion.signature.clone().into(),
            user_handle,
        },
        extensions: AuthenticationExtensionsClientOutputs::default(),
        type_: "public-key".to_string(),
    };
    let credential_json =
        serde_json::to_value(&credential).map_err(|e| format!("Failed to serialize credential: {e}"))?;

    let request = crate::api::RecoveryRecoverRequest {
        user_id: user_id.to_string(),
        recovery_id: initiate_resp.recovery_id.clone(),
        credential: credential_json,
    };

    client.recover_account(&request).await.map_err(|e| format!("Account recovery failed: {e}"))
}
