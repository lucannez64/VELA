//! The M7 ceremonies, verified by a real WebAuthn relying party.
//!
//! Every other passkey test in this crate checks our code against our own
//! expectations, which cannot catch the failure that matters most: producing
//! bytes that are self-consistent but that no real verifier accepts. A wrong
//! COSE key layout, a mis-ordered `authenticatorData` field, a raw `r ‖ s`
//! signature where DER was required — all of those pass a round-trip test
//! written by the same person who wrote the encoder.
//!
//! So this drives [`crate::passkey`] against `webauthn-rs`, the same crate and
//! version `serverVELA` uses as its relying party, and lets *it* decide whether
//! the ceremony is valid. The `clientDataJSON` envelope is built here exactly
//! as `extension/src/content/webauthn-shim.js` builds it in the page, so what
//! is under test is the whole chain's output, not just the Rust half.
//!
//! Hermetic: no network, no browser, no live site. The relying party is an
//! in-process `Webauthn` instance.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttestationResponseRaw, RegistrationExtensionsClientOutputs,
};

use crate::crypto::Crypto;
use crate::passkey::{
    get_assertion, make_credential, GetAssertionRequest, MakeCredentialRequest, PresenceToken,
};
use crate::AppState;

const RP_ID: &str = "vela.example";
const RP_ORIGIN: &str = "https://vela.example";

fn unlocked_state() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::for_test(dir.path());
    state.unlock_for_test(&Crypto::generate_rms());
    (dir, state)
}

fn relying_party() -> Webauthn {
    WebauthnBuilder::new(RP_ID, &Url::parse(RP_ORIGIN).unwrap())
        .unwrap()
        .rp_name("VELA test relying party")
        .build()
        .unwrap()
}

/// The envelope the shim builds in the page, byte for byte.
///
/// `origin` comes from the page's real origin there and is checked by the
/// relying party here — which is what makes an assertion useless anywhere but
/// the site it was minted for.
fn client_data(ceremony: &str, challenge: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let json = serde_json::json!({
        "type": ceremony,
        "challenge": B64URL.encode(challenge),
        "origin": RP_ORIGIN,
        "crossOrigin": false,
    });
    let bytes = serde_json::to_vec(&json).unwrap();
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    (bytes, hash)
}

/// Register a credential and have the relying party accept it.
fn register(state: &AppState, webauthn: &Webauthn) -> Passkey {
    let (challenge_response, registration_state) = webauthn
        .start_passkey_registration(Uuid::new_v4(), "alice", "Alice Example", None)
        .unwrap();

    let challenge = challenge_response.public_key.challenge.as_ref().to_vec();
    let (client_data_json, client_data_hash) = client_data("webauthn.create", &challenge);

    let created = make_credential(
        state,
        &MakeCredentialRequest {
            rp_id: RP_ID.to_string(),
            rp_name: "VELA test relying party".to_string(),
            user_handle: b"alice-handle".to_vec(),
            user_name: "alice".to_string(),
            user_display_name: "Alice Example".to_string(),
            client_data_hash,
            algorithms: challenge_response
                .public_key
                .pub_key_cred_params
                .iter()
                .map(|p| p.alg as i32)
                .collect(),
            excluded_credential_ids: Vec::new(),
            require_user_verification: false,
        },
        // Registration with a verifying factor, so the UV flag is set — a
        // passkey ceremony asks for user verification by default.
        PresenceToken::mint(true),
    )
    .expect("our own ceremony should succeed");

    let raw_id = B64URL.decode(&created.credential_id).unwrap();
    let credential = RegisterPublicKeyCredential {
        id: created.credential_id.clone(),
        raw_id: raw_id.into(),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: created.attestation_object.into(),
            client_data_json: client_data_json.into(),
            transports: None,
        },
        type_: "public-key".to_string(),
        extensions: RegistrationExtensionsClientOutputs::default(),
    };

    webauthn
        .finish_passkey_registration(&credential, &registration_state)
        .expect("a real relying party must accept our attestation")
}

/// Authenticate, and have the relying party accept the assertion.
fn authenticate(state: &AppState, webauthn: &Webauthn, passkey: &Passkey) -> AuthenticationResult {
    let (challenge_response, authentication_state) = webauthn
        .start_passkey_authentication(std::slice::from_ref(passkey))
        .unwrap();

    let challenge = challenge_response.public_key.challenge.as_ref().to_vec();
    let (client_data_json, client_data_hash) = client_data("webauthn.get", &challenge);

    let asserted = get_assertion(
        state,
        &GetAssertionRequest {
            rp_id: RP_ID.to_string(),
            client_data_hash,
            allow_credential_ids: challenge_response
                .public_key
                .allow_credentials
                .iter()
                .map(|c| B64URL.encode(c.id.as_ref()))
                .collect(),
            require_user_verification: false,
        },
        PresenceToken::mint(true),
    )
    .expect("our own ceremony should succeed");

    let raw_id = B64URL.decode(&asserted.credential_id).unwrap();
    let credential = PublicKeyCredential {
        id: asserted.credential_id.clone(),
        raw_id: raw_id.into(),
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: asserted.authenticator_data.into(),
            client_data_json: client_data_json.into(),
            signature: asserted.signature.into(),
            user_handle: Some(asserted.user_handle.into()),
        },
        type_: "public-key".to_string(),
        extensions: AuthenticationExtensionsClientOutputs::default(),
    };

    webauthn
        .finish_passkey_authentication(&credential, &authentication_state)
        .expect("a real relying party must accept our assertion")
}

/// The headline: a credential we mint registers, and an assertion we sign
/// authenticates, against an independent implementation of the spec.
#[test]
fn a_real_relying_party_accepts_registration_and_authentication() {
    let (_dir, state) = unlocked_state();
    let webauthn = relying_party();

    let passkey = register(&state, &webauthn);
    let result = authenticate(&state, &webauthn, &passkey);

    assert_eq!(result.cred_id().as_ref(), passkey.cred_id().as_ref());
    assert!(result.user_verified(), "UV was set, the RP should see it");
}

/// The signature counter has to keep moving, because that is the only thing a
/// relying party can use to notice a cloned authenticator. `webauthn-rs`
/// reports a counter regression as a failure, so this also proves we never
/// send a stale one.
#[test]
fn the_relying_party_sees_the_counter_advance() {
    let (_dir, state) = unlocked_state();
    let webauthn = relying_party();
    let passkey = register(&state, &webauthn);

    let first = authenticate(&state, &webauthn, &passkey);
    let second = authenticate(&state, &webauthn, &passkey);

    assert!(
        second.counter() > first.counter(),
        "counter went {} -> {}",
        first.counter(),
        second.counter()
    );
}

/// An assertion minted for one origin must be worthless at another.
///
/// This is `assertion_is_origin_bound` from the model, checked by a verifier
/// that has no idea what our model says: the challenge and credential are
/// genuine, only the relying party differs, and it must refuse.
#[test]
fn an_assertion_does_not_verify_at_a_different_relying_party() {
    let (_dir, state) = unlocked_state();
    let webauthn = relying_party();
    let passkey = register(&state, &webauthn);

    // A lookalike site, with its own challenge, asking our credential to sign.
    let impostor = WebauthnBuilder::new("evil.example", &Url::parse("https://evil.example").unwrap())
        .unwrap()
        .build()
        .unwrap();
    let (challenge_response, authentication_state) = impostor
        .start_passkey_authentication(std::slice::from_ref(&passkey))
        .unwrap();
    let challenge = challenge_response.public_key.challenge.as_ref().to_vec();

    // Sign for the *real* relying party, as our core would if asked, then try
    // to pass that assertion off at the impostor.
    let (client_data_json, client_data_hash) = client_data("webauthn.get", &challenge);
    let asserted = get_assertion(
        &state,
        &GetAssertionRequest {
            rp_id: RP_ID.to_string(),
            client_data_hash,
            allow_credential_ids: Vec::new(),
            require_user_verification: false,
        },
        PresenceToken::mint(true),
    )
    .unwrap();

    let raw_id = B64URL.decode(&asserted.credential_id).unwrap();
    let credential = PublicKeyCredential {
        id: asserted.credential_id.clone(),
        raw_id: raw_id.into(),
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: asserted.authenticator_data.into(),
            client_data_json: client_data_json.into(),
            signature: asserted.signature.into(),
            user_handle: Some(asserted.user_handle.into()),
        },
        type_: "public-key".to_string(),
        extensions: AuthenticationExtensionsClientOutputs::default(),
    };

    assert!(
        impostor
            .finish_passkey_authentication(&credential, &authentication_state)
            .is_err(),
        "an assertion for {RP_ID} must not authenticate at evil.example"
    );
}
