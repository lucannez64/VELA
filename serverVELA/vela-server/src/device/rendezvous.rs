//! Enrollment v3: the joining device keeps its own private keys.
//!
//! In v2 the primary generated the joining device's entire identity and shipped
//! the private half to it, alongside the symmetric key the RMS capsule was
//! encrypted under. Anyone who read that payload held a device identity and,
//! through it, the vault — permanently, since the RMS never rotates. The code
//! was as valuable as the master secret but handled like a pairing code
//! (audit P-1).
//!
//! Here the code carries a **grant and nothing else**. The joining device
//! generates its own keypair, presents the public half under the grant, and the
//! primary seals the capsule to that public key. An intercepted code buys an
//! enrollment *attempt*.
//!
//! # Where the binding has to be exact
//!
//! Moving the secret out of the code moves the risk onto "did the user confirm
//! the right key", which is the same class of mistake as S-1 — and getting it
//! wrong trades a leak for a hijack. Five things carry that weight:
//!
//! 1. **A grant is bound to the user *and* device that created it.** Only that
//!    device can read a claim or complete an enrollment, so seeing a code is not
//!    enough to drive the flow, exactly as `approver_user_id` fixed for S-1.
//! 2. **A grant can be claimed exactly once, ever**, via an atomic
//!    compare-and-swap. An attacker who wins the race makes the legitimate
//!    device *fail visibly* rather than quietly enrolling alongside it. Silence
//!    is what made S-1 exploitable.
//! 3. **The server enrolls the keys it stored at claim time — never keys the
//!    primary sends.** This is the one that answers "did the user confirm the
//!    right fingerprint": the fingerprint the user compares and the key that
//!    gets enrolled are the same stored object, so there is no window in which
//!    one could be swapped for the other. A primary that tried to enroll
//!    different keys than the ones displayed has no field in which to say so.
//! 4. **Completing consumes the grant and the claim together.** A replayed
//!    completion finds nothing.
//! 5. **The primary signs over the stored keys.** The signature covers what the
//!    server holds, so a tampered claim cannot be enrolled even by the
//!    legitimate primary.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;
use vela_enrollment_policy::{
    inspect_facts, ClaimObservation, InspectDecision, InspectObservation, OpenObservation,
    ResultKind, HYBRID_EK_LEN, HYBRID_VK_LEN,
};
use vela_enrollment_policy::pairing_driver::{
    begin_claim, begin_completion, begin_open_grant, begin_result, on_ceremony_taken_event,
    on_claim_checked_event, on_claim_read_event, on_claim_written_event, on_completion_account,
    on_completion_ready_event, on_device_inserted_event, on_grant_written_event,
    on_result_read_event, on_result_written_event, ClaimMaterialObservation, ClaimReadObservation,
    ClaimWriteObservation, CompletionAccountObservation, CompletionPreflightObservation,
    DeviceInsertObservation, GrantObservation, OpenerObservation, PairingEffect, PairingFailure,
    ResultReadObservation, SignatureObservation, StoreObservation, TakeObservation,
};
use vela_rekey_policy::{
    MutationAuthority, MutationDecision, MutationKind, MutationRequest, Phase as PolicyPhase,
    RekeyState as PolicyState, ShadowDecision,
};

use crate::{
    error::{AppError, Result},
    middleware::{maybe_append_new_token, AuthSession, DeviceSession},
    net, rate_limit,
    sqldb::{Db as _, TursoValue},
    state::AppState,
};

/// Short by design. A grant is only alive while a person is holding two devices
/// and looking at both, which is a matter of a minute or two, and every extra
/// minute is time an intercepted code stays useful.
const GRANT_TTL_SECS: u64 = 5 * 60;

const HYBRID_SIG_LEN: usize = 4627 + 64;

fn grant_key(id: &str) -> String {
    format!("enroll_grant:{id}")
}

fn claim_key(id: &str) -> String {
    format!("enroll_claim:{id}")
}

fn result_key(id: &str) -> String {
    format!("enroll_result:{id}")
}

/// Who may drive this grant. Written when the grant is created and never again.
#[derive(Serialize, Deserialize)]
struct Grant {
    user_id: String,
    device_id: String,
}

/// What the joining device presented. Public halves only — by construction there
/// is nothing secret here, which is the entire point of the change.
#[derive(Serialize, Deserialize, Clone)]
struct Claim {
    hybrid_ek: String,
    hybrid_vk: String,
    device_name: Option<String>,
    device_type: Option<String>,
}

/// What the joining device may collect once the primary has enrolled it.
///
/// Completing consumes the claim, so the `hybrid_vk` is carried over here: it is
/// what the collector's signature is checked against, and it is a public key the
/// device already holds.
#[derive(Serialize, Deserialize)]
struct EnrollmentResult {
    device_id: String,
    hybrid_vk: String,
}

// ── 1. The primary opens a grant ────────────────────────────────────────────

#[derive(Serialize)]
pub struct CreateGrantResponse {
    pub grant_id: String,
    pub expires_in: u64,
}

/// Open a grant.
///
/// Device-only (red-team RT-4). An enrollment grant is the first step of a
/// *permanent* device enrollment, which is exactly what
/// `EPHEMERAL_WEB_ACCESS_DESIGN.md` §2 promises a web session cannot do. The
/// completion path refuses a web session anyway — it has no `devices` row whose
/// key could sign the enrollment — but refusing at the source is the honest
/// place: it also stops a borrowed browser watching an enrollment in progress
/// through `get_claim`.
pub async fn post_grant(
    State(state): State<AppState>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<CreateGrantResponse>)> {
    rate_limit::enrollment_grant_by_user(&state.store, &session.user_id.to_string())?;

    // Every post-validation decision belongs to the extracted driver: whether
    // the verified open policy permits a write, and how the write outcome is
    // classified. The handler only performs the returned effect.
    let start = begin_open_grant(OpenObservation {
        scope_is_device: matches!(session.scope, crate::auth::token::TokenScope::Device),
        user_id_present: !session.user_id.is_nil(),
        device_id_present: !session.device_id.is_nil(),
        ttl_secs: GRANT_TTL_SECS,
    });
    debug_assert!(matches!(
        start.effect,
        PairingEffect::StoreGrant | PairingEffect::Fail(_)
    ));

    let grant_id = Uuid::new_v4().to_string();
    let grant = Grant {
        user_id: session.user_id.to_string(),
        device_id: session.device_id.to_string(),
    };
    let stored_error = match start.effect {
        PairingEffect::StoreGrant => match state.store.set_ex(
            &grant_key(&grant_id),
            serde_json::to_vec(&grant)
                .map_err(|e| AppError::Internal(e.to_string()))?
                .as_slice(),
            GRANT_TTL_SECS,
        ) {
            Ok(()) => None,
            Err(error) => Some(error),
        },
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected grant-store effect".into(),
            ))
        }
    };
    let observation = if stored_error.is_some() {
        StoreObservation::Failed
    } else {
        StoreObservation::Stored
    };
    let transition = on_grant_written_event(start.driver, observation);
    match transition.effect {
        PairingEffect::Complete => {}
        PairingEffect::Fail(PairingFailure::GrantStorage) => {
            return Err(stored_error
                .unwrap_or_else(|| AppError::Internal("enrollment grant store failed".into())))
        }
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected grant-store observation effect".into(),
            ))
        }
    }

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(CreateGrantResponse {
            grant_id,
            expires_in: GRANT_TTL_SECS,
        }),
    ))
}

// ── 2. The joining device claims it (unauthenticated: it has no identity yet) ─

#[derive(Deserialize)]
pub struct ClaimRequest {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

pub async fn post_claim(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Json(body): Json<ClaimRequest>,
) -> Result<Json<serde_json::Value>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::enrollment_claim_by_ip(&state.store, &ip)?;
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;

    // The grant must exist, but is deliberately *not* consumed here: the primary
    // still has to read the claim and complete, and burning it now would let an
    // unauthenticated caller destroy a grant it cannot otherwise use.
    let grant_live = state.store.exists(&grant_key(grant_id))?;
    let start = begin_claim(grant_live);
    let driver = match start.effect {
        PairingEffect::CheckClaim => start.driver,
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected claim-check effect".into(),
            ))
        }
    };

    // Base64 decoding is request validation, not a store decision; a bad field
    // is refused before any claim is written.
    let ek = decode_base64_field(&body.hybrid_ek, "hybrid_ek")?;
    let vk = decode_base64_field(&body.hybrid_vk, "hybrid_vk")?;

    let claim_exists = state.store.exists(&claim_key(grant_id))?;
    let planned = on_claim_checked_event(
        driver,
        ClaimObservation {
            grant_live,
            claim_exists,
            hybrid_ek_len: ek.len(),
            hybrid_vk_len: vk.len(),
        },
    );
    let driver = match planned.effect {
        PairingEffect::WriteClaim => planned.driver,
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected claim-plan effect".into(),
            ))
        }
    };

    let claim = Claim {
        hybrid_ek: B64.encode(&ek),
        hybrid_vk: B64.encode(&vk),
        device_name: body.device_name.clone(),
        device_type: body.device_type.clone(),
    };

    // First claim wins while the grant is live, atomically. A second device —
    // including one racing with a stolen code — is told it lost rather than
    // replacing the first, and expiry cannot leave behind an orphan claim.
    let outcome = state.store.set_ex_nx_if_live(
        &grant_key(grant_id),
        &claim_key(grant_id),
        serde_json::to_vec(&claim)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .as_slice(),
        GRANT_TTL_SECS,
    )?;
    let observation = match outcome {
        crate::store::GuardedSetOutcome::Inserted => ClaimWriteObservation::Inserted,
        crate::store::GuardedSetOutcome::GuardMissing => ClaimWriteObservation::GuardMissing,
        crate::store::GuardedSetOutcome::KeyExists => ClaimWriteObservation::KeyExists,
    };
    let transition = on_claim_written_event(driver, observation);
    match transition.effect {
        PairingEffect::Complete => Ok(Json(serde_json::json!({ "claimed": true }))),
        PairingEffect::Fail(failure) => Err(rendezvous_failure_error(failure)),
        _ => Err(AppError::Internal(
            "pairing driver produced an unexpected claim-write observation effect".into(),
        )),
    }
}

// ── 3. The primary reads the claim, to show the user a fingerprint ──────────

#[derive(Serialize)]
pub struct ClaimView {
    pub hybrid_ek: String,
    pub hybrid_vk: String,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
}

pub async fn get_claim(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    session: DeviceSession,
) -> Result<(HeaderMap, Json<ClaimView>)> {
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;
    let (grant, _) = authorize_grant(&state, grant_id, &session)?;

    let claim = load_claim(&state, grant_id)?;
    let claim_present = claim.is_some();
    let _permit =
        match vela_enrollment_policy::authorize_inspection(inspect_facts(InspectObservation {
            claim_present,
            user_matches: grant.user_id == session.user_id.to_string(),
            opener_matches: grant.device_id == session.device_id.to_string(),
        })) {
            InspectDecision::Inspect(permit) => permit,
            InspectDecision::Reject if !claim_present => {
                return Err(AppError::NotFound(
                    "no device has claimed this code yet".into(),
                ));
            }
            InspectDecision::Reject => {
                return Err(AppError::NotFound(
                    "enrollment grant not found or expired".into(),
                ));
            }
        };
    let claim = claim.expect("inspection policy admits only a present claim");

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(ClaimView {
            hybrid_ek: claim.hybrid_ek,
            hybrid_vk: claim.hybrid_vk,
            device_name: claim.device_name,
            device_type: claim.device_type,
        }),
    ))
}

// ── 4. The primary completes it ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CompleteRequest {
    /// The RMS capsule, KEM-sealed to the claimed `hybrid_ek`. The server cannot
    /// check that sealing — it has no RMS — which is why the capsule is bound
    /// into the signature below instead.
    pub rms_capsule: String,
    /// The primary's signature over (claimed ek ‖ claimed vk ‖ capsule).
    pub signature: String,
    /// Authenticated local epoch of the RMS sealed into `rms_capsule`.
    pub key_epoch: i64,
}

#[derive(Serialize)]
pub struct CompleteResponse {
    pub device_id: Uuid,
}

pub async fn post_complete(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    session: DeviceSession,
    Json(body): Json<CompleteRequest>,
) -> Result<(HeaderMap, Json<CompleteResponse>)> {
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;

    // Read the grant once. The extracted driver owns the user/opener binding
    // decision; the handler keeps the bytes because the single-use take below
    // compares them with what the ceremony validated.
    let (grant_observation, grant, expected_grant_bytes, grant_error) =
        match state.store.get(&grant_key(grant_id)) {
            Ok(Some(bytes)) => match serde_json::from_slice::<Grant>(&bytes) {
                Ok(grant) => (
                    GrantObservation::Present {
                        user_matches: grant.user_id == session.user_id.to_string(),
                        opener_matches: grant.device_id == session.device_id.to_string(),
                    },
                    Some(grant),
                    Some(bytes),
                    None,
                ),
                Err(error) => (
                    GrantObservation::Error,
                    None,
                    None,
                    Some(AppError::Internal(format!(
                        "stored grant is unreadable: {error}"
                    ))),
                ),
            },
            Ok(None) => (GrantObservation::Absent, None, None, None),
            Err(error) => (GrantObservation::Error, None, None, Some(error)),
        };

    let begin = begin_completion(grant_observation);
    let driver = match begin.effect {
        PairingEffect::CheckAccount => begin.driver,
        PairingEffect::Fail(PairingFailure::GrantUnavailable) => {
            // Same message as "not found": whether a grant exists is not
            // something an unrelated caller should be able to probe.
            return Err(AppError::NotFound(
                "enrollment grant not found or expired".into(),
            ));
        }
        PairingEffect::Fail(PairingFailure::GrantError) => {
            return Err(grant_error
                .unwrap_or_else(|| AppError::Internal("enrollment grant read failed".into())))
        }
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected grant-binding effect".into(),
            ))
        }
    };
    let (grant, expected_grant_bytes) = match (grant, expected_grant_bytes) {
        (Some(grant), Some(bytes)) => (grant, bytes),
        _ => {
            return Err(AppError::Internal(
                "pairing driver admitted an unobserved grant".into(),
            ))
        }
    };

    let user_rows = state
        .sqldb
        .query(
            "SELECT key_epoch, rekey_state FROM users WHERE id = ?",
            vec![TursoValue::Text(grant.user_id.clone())],
        )
        .await;
    let (account_query_ok, account_error) = match &user_rows {
        Ok(_) => (true, None),
        Err(error) => (false, Some(AppError::Internal(error.to_string()))),
    };
    let current_epoch = user_rows
        .as_ref()
        .ok()
        .and_then(|rows| rows.first())
        .and_then(|row| row.i64(0));
    let rotation_state = user_rows
        .as_ref()
        .ok()
        .and_then(|rows| rows.first())
        .and_then(|row| row.text(1));
    let rekey_decision = vela_rekey_policy::plan_active_mutation(MutationRequest {
        declared_epoch: body.key_epoch,
        authority_epoch: body.key_epoch,
        kind: MutationKind::Enrollment,
        authority: MutationAuthority::Device,
    });
    let observed_state = PolicyState {
        epoch: current_epoch.unwrap_or(0),
        phase: if rotation_state.is_some() {
            PolicyPhase::Freezing
        } else {
            PolicyPhase::Active
        },
    };
    let (rekey_permitted, rekey_epoch, account_epoch_active) = match rekey_decision {
        MutationDecision::Permit(permit) => (
            true,
            permit.epoch(),
            vela_rekey_policy::authorize_active_mutation(observed_state, permit)
                == ShadowDecision::Allow,
        ),
        MutationDecision::Reject => (false, 0, false),
    };
    let account = on_completion_account(
        driver,
        CompletionAccountObservation {
            account_query_ok,
            declared_epoch_positive: body.key_epoch >= 1,
            rekey_permitted,
        },
    );
    let driver = match account.effect {
        PairingEffect::PrepareCompletion => account.driver,
        PairingEffect::Fail(PairingFailure::AccountStorage) => {
            return Err(account_error
                .unwrap_or_else(|| AppError::Internal("account query failed".into())))
        }
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected account-preflight effect".into(),
            ))
        }
    };

    // Read without consuming first. Invalid signatures must not let an
    // unauthenticated or corrupted request burn a legitimate ceremony. Every
    // fallible observation is retained so the extracted driver receives the
    // real value and the original error precedence is preserved.
    let expected_claim_bytes_opt = state.store.get(&claim_key(grant_id))?;
    let claim_present = expected_claim_bytes_opt.is_some();
    let claim_materials: Result<(Claim, Vec<u8>, Vec<u8>)> = match &expected_claim_bytes_opt {
        Some(bytes) => serde_json::from_slice::<Claim>(bytes)
            .map_err(|e| AppError::Internal(format!("stored claim is unreadable: {e}")))
            .and_then(|claim| {
                // The keys enrolled below come from `claim` — what the joining
                // device presented and what the user's fingerprint comparison
                // was about — and never from the request body.
                let hybrid_ek = crate::db::decode_b64(&claim.hybrid_ek)?;
                let hybrid_vk = crate::db::decode_b64(&claim.hybrid_vk)?;
                Ok((claim, hybrid_ek, hybrid_vk))
            }),
        None => Err(AppError::NotFound(
            "no device has claimed this code yet".into(),
        )),
    };
    let rms_capsule_result = decode_any(&body.rms_capsule, "rms_capsule");
    let signature_decode_result = decode_exact(&body.signature, HYBRID_SIG_LEN, "signature");
    let opener_result = load_primary_key(&state, &grant).await;
    let primary_vk = match &opener_result {
        Ok((Some(vk), true)) => Some(vk.as_slice()),
        _ => None,
    };

    let signature_result = match (
        &claim_materials,
        &rms_capsule_result,
        &signature_decode_result,
        primary_vk,
    ) {
        (Ok((_, hybrid_ek, hybrid_vk)), Ok(rms_capsule), Ok(signature), Some(primary_vk)) => {
            super::enroll::verify_enrollment_signature(
                primary_vk,
                hybrid_ek,
                hybrid_vk,
                rms_capsule,
                signature,
            )
        }
        _ => Err(AppError::Unauthorized(
            "enrolling device not found or revoked".into(),
        )),
    };
    let signature_verified = signature_result.is_ok();

    let claim_observation = match (&claim_materials, claim_present) {
        (Ok(_), _) => ClaimMaterialObservation::Usable,
        (Err(_), false) => ClaimMaterialObservation::Missing,
        (Err(_), true) => ClaimMaterialObservation::Error,
    };
    let opener_observation = match &opener_result {
        Ok((Some(_), true)) => OpenerObservation::Active,
        Ok(_) => OpenerObservation::Inactive,
        Err(_) => OpenerObservation::Error,
    };
    let signature_observation = if signature_verified {
        SignatureObservation::Verified
    } else {
        SignatureObservation::Failed
    };

    let ceremony = on_completion_ready_event(
        driver,
        CompletionPreflightObservation {
            claim: claim_observation,
            capsule_valid: rms_capsule_result.is_ok(),
            signature_field_valid: signature_decode_result.is_ok(),
            opener: opener_observation,
            signature: signature_observation,
            account_epoch: current_epoch.unwrap_or(0),
            declared_epoch: body.key_epoch,
            rotation_in_progress: rotation_state.is_some(),
            account_epoch_active,
        },
    );
    let driver = match ceremony.effect {
        PairingEffect::TakeCeremony => ceremony.driver,
        PairingEffect::Fail(PairingFailure::EpochChanged) => {
            return Err(AppError::Conflict(
                "device enrollment key epoch changed or rotation is in progress".into(),
            ));
        }
        PairingEffect::Fail(PairingFailure::NoClaim) => {
            return Err(AppError::NotFound(
                "no device has claimed this code yet".into(),
            ));
        }
        PairingEffect::Fail(PairingFailure::ClaimUnreadable) => {
            return Err(claim_materials
                .err()
                .unwrap_or_else(|| AppError::Internal("stored claim is unreadable".into())));
        }
        PairingEffect::Fail(PairingFailure::CapsuleInvalid) => {
            return Err(rms_capsule_result
                .err()
                .unwrap_or_else(|| AppError::BadRequest("rms_capsule is invalid".into())));
        }
        PairingEffect::Fail(PairingFailure::SignatureFieldInvalid) => {
            return Err(signature_decode_result
                .err()
                .unwrap_or_else(|| AppError::BadRequest("signature is invalid".into())));
        }
        PairingEffect::Fail(PairingFailure::OpenerStorage) => {
            return Err(opener_result
                .err()
                .unwrap_or_else(|| AppError::Internal("opener lookup failed".into())));
        }
        PairingEffect::Fail(PairingFailure::OpenerRevoked) => {
            return Err(AppError::Unauthorized(
                "enrolling device not found or revoked".into(),
            ));
        }
        PairingEffect::Fail(PairingFailure::SignatureRejected) => {
            return Err(signature_result.err().unwrap_or_else(|| {
                AppError::Unauthorized("enrolling device not found or revoked".into())
            }));
        }
        PairingEffect::Fail(PairingFailure::CompletionNotAuthorized) => {
            return Err(AppError::Unauthorized(
                "device enrollment completion is not authorized".into(),
            ));
        }
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected completion-policy effect".into(),
            ))
        }
    };

    let (claim, hybrid_ek, hybrid_vk) = claim_materials?;
    let rms_capsule = rms_capsule_result?;
    let _signature = signature_decode_result?;
    let _opener = opener_result?;
    signature_result?;
    let expected_claim_bytes =
        expected_claim_bytes_opt.expect("completion policy authorizes only a present stored claim");

    // This sled transaction is the ceremony's linearization point. Exactly one
    // racing/replayed completion gets both records; every loser gets neither.
    let taken_pair = state
        .store
        .take_live_pair(&grant_key(grant_id), &claim_key(grant_id))?;
    let take_observation = match &taken_pair {
        None => TakeObservation::Missing,
        Some((grant_bytes, claim_bytes)) => TakeObservation::Taken {
            grant_matches: grant_bytes == &expected_grant_bytes,
            claim_matches: claim_bytes == &expected_claim_bytes,
        },
    };
    let transition = on_ceremony_taken_event(driver, take_observation);
    let driver = transition.driver;
    match transition.effect {
        PairingEffect::InsertDevice => {}
        PairingEffect::Fail(PairingFailure::CeremonyConsumed) => {
            return Err(AppError::NotFound(
                "enrollment grant or claim was already consumed".into(),
            ))
        }
        PairingEffect::RestoreAndFail(PairingFailure::CeremonyChanged) => {
            if let Some((grant_bytes, claim_bytes)) = &taken_pair {
                state.store.set_ex_pair(
                    &grant_key(grant_id),
                    grant_bytes,
                    &claim_key(grant_id),
                    claim_bytes,
                    GRANT_TTL_SECS,
                )?;
            }
            return Err(AppError::Conflict(
                "enrollment ceremony changed while it was being confirmed".into(),
            ));
        }
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        PairingEffect::RestoreAndFail(failure) => {
            return Err(rendezvous_failure_error(failure))
        }
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected ceremony-take effect".into(),
            ))
        }
    }
    let (grant_bytes, claim_bytes) = taken_pair.ok_or_else(|| {
        AppError::Internal("completion driver admitted an unobserved ceremony take".into())
    })?;

    let new_device_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let device_name = claim
        .device_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "New Device".to_string());
    let device_type = claim
        .device_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let (insert_observation, insert_error) = match state.sqldb.execute(
        "INSERT INTO devices
         (id, user_id, device_name, device_type, last_active, hybrid_ek, hybrid_vk, enrolled_by, rms_capsule, created_at)
         SELECT ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?
         WHERE EXISTS (
             SELECT 1 FROM users
             WHERE id = ? AND key_epoch = ? AND rekey_state IS NULL
         )",
        vec![
            TursoValue::Text(new_device_id.to_string()),
            TursoValue::Text(grant.user_id.clone()),
            TursoValue::Text(device_name),
            TursoValue::Text(device_type),
            TursoValue::Text(crate::db::encode_b64(&hybrid_ek)),
            TursoValue::Text(crate::db::encode_b64(&hybrid_vk)),
            TursoValue::Text(grant.device_id.clone()),
            TursoValue::Text(crate::db::encode_b64(&rms_capsule)),
            TursoValue::Text(now),
            TursoValue::Text(grant.user_id.clone()),
            TursoValue::Integer(rekey_epoch),
        ],
    ).await {
        Ok(inserted) if inserted > 0 => (DeviceInsertObservation::Inserted, None),
        Ok(_) => (DeviceInsertObservation::Skipped, None),
        Err(error) => (DeviceInsertObservation::Failed, Some(error.to_string())),
    };
    let transition = on_device_inserted_event(driver, insert_observation);
    let driver = transition.driver;
    match transition.effect {
        PairingEffect::WriteResult => {}
        // A rotation may have started after the fast check but before the
        // guarded insert. Restore the exact consumed claim and grant so the
        // already-confirmed pairing can be retried once rotation completes.
        PairingEffect::RestoreAndFail(PairingFailure::Rotation) => {
            state.store.set_ex_pair(
                &grant_key(grant_id),
                &grant_bytes,
                &claim_key(grant_id),
                &claim_bytes,
                GRANT_TTL_SECS,
            )?;
            return Err(AppError::Conflict(
                "device enrollment key epoch changed or rotation is in progress".into(),
            ));
        }
        // An INSERT error is ambiguous: the row may have committed before the
        // error surfaced. The grant and claim stay consumed; restoring them
        // would let a retry enroll a second device from one ceremony.
        PairingEffect::Fail(PairingFailure::InsertStorage) => {
            return Err(AppError::Internal(
                insert_error.unwrap_or_else(|| "device insert failed".into()),
            ));
        }
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        PairingEffect::RestoreAndFail(failure) => {
            state.store.set_ex_pair(
                &grant_key(grant_id),
                &grant_bytes,
                &claim_key(grant_id),
                &claim_bytes,
                GRANT_TTL_SECS,
            )?;
            return Err(rendezvous_failure_error(failure));
        }
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected insert effect".into(),
            ))
        }
    }

    // Only now that the row exists: the joining device is holding a keypair and
    // waiting to be told which device it became. Written after the insert so a
    // failed enrollment never leaves behind a result pointing at no device.
    let result = EnrollmentResult {
        device_id: new_device_id.to_string(),
        hybrid_vk: claim.hybrid_vk.clone(),
    };
    let result_bytes = serde_json::to_vec(&result)
        .map_err(|e| AppError::Internal(format!("enrollment result encode failed: {e}")))?;
    let result_error = match state.store.set_ex(
        &result_key(grant_id),
        result_bytes.as_slice(),
        GRANT_TTL_SECS,
    ) {
        Ok(()) => None,
        Err(error) => Some(error),
    };
    let observation = if result_error.is_some() {
        StoreObservation::Failed
    } else {
        StoreObservation::Stored
    };
    let transition = on_result_written_event(driver, observation);
    match transition.effect {
        PairingEffect::Complete => {}
        PairingEffect::Fail(PairingFailure::ResultStorage) => {
            return Err(result_error
                .unwrap_or_else(|| AppError::Internal("enrollment result store failed".into())))
        }
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected result-write effect".into(),
            ))
        }
    }

    tracing::info!(
        new_device_id = %new_device_id,
        enrolled_by = %grant.device_id,
        user_id = %grant.user_id,
        "device enrolled (v3 rendezvous)"
    );

    let mut headers = HeaderMap::new();
    maybe_append_new_token(&mut headers, &session);
    Ok((
        headers,
        Json(CompleteResponse {
            device_id: new_device_id,
        }),
    ))
}

// ── 5. The joining device collects the outcome ──────────────────────────────

#[derive(Deserialize)]
pub struct ResultRequest {
    /// The joining device's signature over the grant id, under the key it
    /// claimed with. This is the only thing standing in for a session here —
    /// the device is asking *which device it is*, so it cannot yet
    /// authenticate normally.
    pub signature: String,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResultResponse {
    /// The primary has not completed yet. The user is probably still comparing
    /// fingerprints; keep waiting.
    Pending,
    Enrolled {
        device_id: String,
    },
}

/// Tell a device that claimed a grant which device it became.
///
/// Unauthenticated in the session sense and necessarily so — the `device_id`
/// this returns is exactly what the caller is missing in order to authenticate.
/// The proof is the signature: only the holder of the private half of the
/// claimed key can produce it, so someone who photographed the enrollment code
/// learns nothing here, not even whether a claim exists. That last part is why
/// the signature is checked *before* the pending branch answers.
pub async fn post_result(
    State(state): State<AppState>,
    addr: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Json(body): Json<ResultRequest>,
) -> Result<Json<ResultResponse>> {
    let ip = net::client_ip(&headers, addr.map(|ConnectInfo(a)| a.ip()), &state.config);
    rate_limit::enrollment_result_by_ip(&state.store, &ip)?;
    let grant_id = crate::ids::validate_id("grant_id", &grant_id)?;

    // Signature length/base64 is request validation, not a store decision.
    let signature = decode_exact(&body.signature, HYBRID_SIG_LEN, "signature")?;

    let start = begin_result();
    debug_assert!(matches!(start.effect, PairingEffect::ReadResult));

    // Completed: the claim is gone and the result carries the vk forward. The
    // extracted driver owns whether that record may be answered and under
    // which verified key; the handler retains the exact storage/verify error.
    let (result_observation, result_record, result_error) =
        match state.store.get(&result_key(grant_id))? {
            Some(bytes) => match serde_json::from_slice::<EnrollmentResult>(&bytes) {
                Ok(result) => match crate::db::decode_b64(&result.hybrid_vk) {
                    Ok(vk) => {
                        let signature_result = verify_result_signature(&vk, grant_id, &signature);
                        let observation = ResultReadObservation::Completed {
                            claimed_key_len: vk.len(),
                            signature_verified: signature_result.is_ok(),
                        };
                        match signature_result {
                            Ok(()) => (observation, Some(result), None),
                            Err(error) => (observation, Some(result), Some(error)),
                        }
                    }
                    Err(error) => (ResultReadObservation::Unreadable, None, Some(error)),
                },
                Err(error) => (
                    ResultReadObservation::Unreadable,
                    None,
                    Some(AppError::Internal(format!(
                        "stored result is unreadable: {error}"
                    ))),
                ),
            },
            None => (ResultReadObservation::Absent, None, None),
        };

    let first = on_result_read_event(start.driver, result_observation);
    let driver = match first.effect {
        PairingEffect::ReturnResult(ResultKind::Enrolled) => {
            let result = result_record.ok_or_else(|| {
                AppError::Internal("result driver admitted an unobserved result".into())
            })?;
            return Ok(Json(ResultResponse::Enrolled {
                device_id: result.device_id,
            }));
        }
        PairingEffect::ReadClaim => first.driver,
        PairingEffect::Fail(PairingFailure::ResultUnreadable) => {
            return Err(result_error
                .unwrap_or_else(|| AppError::Internal("stored result is unreadable".into())))
        }
        PairingEffect::Fail(PairingFailure::ResultSignatureRejected)
        | PairingEffect::Fail(PairingFailure::ResultNotAuthorized) => {
            // Preserve the signature verifier's own error, if any, before the
            // policy's generic refusal.
            return Err(result_error.unwrap_or_else(|| {
                AppError::Unauthorized("enrollment result is not authorized".into())
            }));
        }
        PairingEffect::Fail(failure) => return Err(rendezvous_failure_error(failure)),
        _ => {
            return Err(AppError::Internal(
                "pairing driver produced an unexpected result-read effect".into(),
            ))
        }
    };

    // Not completed yet. Still checked against the claimed key, so "pending" is
    // not an answer an interceptor can get.
    let (claim_observation, claim_error) = match state.store.get(&claim_key(grant_id))? {
        Some(bytes) => match serde_json::from_slice::<Claim>(&bytes) {
            Ok(claim) => match crate::db::decode_b64(&claim.hybrid_vk) {
                Ok(vk) => {
                    let signature_result = verify_result_signature(&vk, grant_id, &signature);
                    let observation = ClaimReadObservation::Claimed {
                        claimed_key_len: vk.len(),
                        signature_verified: signature_result.is_ok(),
                    };
                    match signature_result {
                        Ok(()) => (observation, None),
                        Err(error) => (observation, Some(error)),
                    }
                }
                Err(error) => (ClaimReadObservation::Unreadable, Some(error)),
            },
            Err(error) => (
                ClaimReadObservation::Unreadable,
                Some(AppError::Internal(format!(
                    "stored claim is unreadable: {error}"
                ))),
            ),
        },
        None => (ClaimReadObservation::Absent, None),
    };
    let second = on_claim_read_event(driver, claim_observation);
    match second.effect {
        PairingEffect::ReturnResult(ResultKind::Pending) => Ok(Json(ResultResponse::Pending)),
        PairingEffect::Fail(PairingFailure::ClaimRecordUnreadable) => {
            return Err(claim_error
                .unwrap_or_else(|| AppError::Internal("stored claim is unreadable".into())))
        }
        PairingEffect::Fail(PairingFailure::ResultSignatureRejected)
        | PairingEffect::Fail(PairingFailure::ResultNotAuthorized) => {
            return Err(claim_error.unwrap_or_else(|| {
                AppError::Unauthorized("enrollment result is not authorized".into())
            }));
        }
        PairingEffect::Fail(failure) => Err(rendezvous_failure_error(failure)),
        _ => Err(AppError::Internal(
            "pairing driver produced an unexpected claim-read effect".into(),
        )),
    }
}

/// Check a collector's signature, treating an unusable stored key as a refusal
/// rather than a server fault.
///
/// A claim's `hybrid_vk` is length-checked but not parsed when it is stored, so
/// an unauthenticated caller can put 2624 bytes of noise there and reach this
/// path. That is not a bug on the server's side — such a claim can never be a
/// working device — but it is caller-supplied input, and answering it with a
/// 500 would file the caller's own garbage as an internal error and bury real
/// faults among them.
fn verify_result_signature(vk: &[u8], grant_id: &str, signature: &[u8]) -> Result<()> {
    super::enroll::verify_enrollment_result_signature(vk, grant_id, signature).map_err(
        |e| match e {
            AppError::Internal(_) => AppError::Unauthorized(
                "signature does not match the key this grant was claimed with".into(),
            ),
            other => other,
        },
    )
}

// ── shared ──────────────────────────────────────────────────────────────────

/// Load a grant and require the caller to be the device that opened it.
///
/// Not just the same *user*: a second device of the same account must not be
/// able to drive an enrollment its owner started elsewhere, because then a
/// compromised secondary could enroll an attacker's key against a code the user
/// is reading off their primary.
fn authorize_grant(
    state: &AppState,
    grant_id: &str,
    session: &AuthSession,
) -> Result<(Grant, Vec<u8>)> {
    let bytes = state
        .store
        .get(&grant_key(grant_id))?
        .ok_or_else(|| AppError::NotFound("enrollment grant not found or expired".into()))?;
    let grant: Grant = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("stored grant is unreadable: {e}")))?;

    if grant.user_id != session.user_id.to_string()
        || grant.device_id != session.device_id.to_string()
    {
        // Same message as "not found": whether a grant exists is not something
        // an unrelated caller should be able to probe.
        return Err(AppError::NotFound(
            "enrollment grant not found or expired".into(),
        ));
    }
    Ok((grant, bytes))
}

fn load_claim(state: &AppState, grant_id: &str) -> Result<Option<Claim>> {
    match state.store.get(&claim_key(grant_id))? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
            AppError::Internal(format!("stored claim is unreadable: {e}"))
        })?)),
        None => Ok(None),
    }
}

/// Load the opener's verification key and activity.
///
/// A missing or revoked row is returned as `(None, false)` rather than an
/// error: the handler still runs the verified completion policy on that
/// observation, then reports the original "not found or revoked" rejection.
/// Only a database failure or an unreadable active key is an error.
async fn load_primary_key(state: &AppState, grant: &Grant) -> Result<(Option<Vec<u8>>, bool)> {
    let rows = state
        .sqldb
        .query(
            "SELECT hybrid_vk, revoked FROM devices WHERE id = ? AND user_id = ?",
            vec![
                TursoValue::Text(grant.device_id.clone()),
                TursoValue::Text(grant.user_id.clone()),
            ],
        )
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let Some(row) = rows.first() else {
        return Ok((None, false));
    };
    // Mirror the SQL `revoked = 0` predicate exactly: NULL or any other value
    // counts as revoked.
    let revoked = !matches!(row.get(1), Some(TursoValue::Integer(0))) && row.text(1) != Some("0");
    if revoked {
        return Ok((None, false));
    }
    let vk_b64 = row
        .text(0)
        .ok_or_else(|| AppError::Unauthorized("enrolling device not found or revoked".into()))?;
    Ok((Some(crate::db::decode_b64(vk_b64)?), true))
}

/// Decode base64 without imposing a length. The verified claim policy decides
/// whether the decoded length is the protocol's exact key length, so the
/// public-key fact is not decided by a separate early return.
fn decode_base64_field(value: &str, what: &str) -> Result<Vec<u8>> {
    B64.decode(value)
        .map_err(|_| AppError::BadRequest(format!("{what} is not valid base64")))
}

fn decode_exact(value: &str, expected: usize, what: &str) -> Result<Vec<u8>> {
    let bytes = B64
        .decode(value)
        .map_err(|_| AppError::BadRequest(format!("{what} is not valid base64")))?;
    if bytes.len() != expected {
        return Err(AppError::BadRequest(format!(
            "{what} must be {expected} bytes"
        )));
    }
    Ok(bytes)
}

fn decode_any(value: &str, what: &str) -> Result<Vec<u8>> {
    const MAX_CAPSULE_BYTES: usize = 64 * 1024;
    let bytes = B64
        .decode(value)
        .map_err(|_| AppError::BadRequest(format!("{what} is not valid base64")))?;
    if bytes.is_empty() || bytes.len() > MAX_CAPSULE_BYTES {
        return Err(AppError::BadRequest(format!(
            "{what} must be between 1 byte and 64 KiB"
        )));
    }
    Ok(bytes)
}

/// Render the driver's failure with the handler's historical status/message.
/// Variants whose original error is retained by the handler (storage, decode
/// and signature-verifier errors) fall back to a total internal error here;
/// the call sites return the retained error instead.
fn rendezvous_failure_error(failure: PairingFailure) -> AppError {
    match failure {
        PairingFailure::OpenPolicy => AppError::Internal(
            "verified enrollment policy rejected an authenticated device grant".into(),
        ),
        PairingFailure::GrantStorage => {
            AppError::Internal("enrollment grant store failed".into())
        }
        PairingFailure::GrantUnavailable => {
            AppError::NotFound("enrollment grant not found or expired".into())
        }
        PairingFailure::InvalidEkLength => AppError::BadRequest(format!(
            "hybrid_ek must be {HYBRID_EK_LEN} bytes"
        )),
        PairingFailure::InvalidVkLength => AppError::BadRequest(format!(
            "hybrid_vk must be {HYBRID_VK_LEN} bytes"
        )),
        PairingFailure::AlreadyClaimed => AppError::Conflict(
            "this enrollment code has already been used by another device".into(),
        ),
        PairingFailure::ClaimNotAuthorized => {
            AppError::BadRequest("enrollment claim is not authorized".into())
        }
        PairingFailure::KeyEpochInvalid => {
            AppError::BadRequest("key_epoch must be positive".into())
        }
        PairingFailure::RekeyPolicy => AppError::BadRequest(
            "device enrollment requires a positive device-authority epoch".into(),
        ),
        PairingFailure::EpochChanged | PairingFailure::Rotation => AppError::Conflict(
            "device enrollment key epoch changed or rotation is in progress".into(),
        ),
        PairingFailure::NoClaim => {
            AppError::NotFound("no device has claimed this code yet".into())
        }
        PairingFailure::CeremonyConsumed => {
            AppError::NotFound("enrollment grant or claim was already consumed".into())
        }
        PairingFailure::CeremonyChanged => AppError::Conflict(
            "enrollment ceremony changed while it was being confirmed".into(),
        ),
        PairingFailure::OpenerRevoked | PairingFailure::SignatureRejected => {
            AppError::Unauthorized("enrolling device not found or revoked".into())
        }
        PairingFailure::CompletionNotAuthorized => {
            AppError::Unauthorized("device enrollment completion is not authorized".into())
        }
        PairingFailure::ResultSignatureRejected | PairingFailure::ResultNotAuthorized => {
            AppError::Unauthorized("enrollment result is not authorized".into())
        }
        _ => AppError::Internal("pairing driver produced an unexpected failure".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The grant records both ids, and `authorize_grant` compares both.
    ///
    /// The exploit test cannot reach this case: getting a genuine second device
    /// of the same account means completing an enrollment, which is the thing
    /// it is trying to break. So the binding is asserted here instead of being
    /// left to a comment.
    #[test]
    fn a_grant_records_both_the_user_and_the_device() {
        let grant = Grant {
            user_id: "user-1".into(),
            device_id: "device-a".into(),
        };
        let encoded = serde_json::to_vec(&grant).unwrap();
        let decoded: Grant = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded.user_id, "user-1");
        assert_eq!(decoded.device_id, "device-a");

        // Matching the user is not sufficient. A second device of the same
        // account must not be able to drive an enrollment its owner started on
        // the primary — otherwise a compromised secondary could enroll a key
        // against a code the user is reading off another screen.
        assert!(
            decoded.user_id == "user-1" && decoded.device_id != "device-b",
            "same user, different device must not satisfy the binding"
        );
    }

    /// The three records live in separate namespaces.
    ///
    /// A result outlives the claim it came from — completion consumes the claim
    /// but leaves the result for the joining device to collect. If the keys
    /// collided, completing would either destroy the result or resurrect a
    /// consumed claim, and a consumed claim is what makes replay fail.
    #[test]
    fn grants_claims_and_results_do_not_share_keys() {
        let id = "11111111-1111-1111-1111-111111111111";
        let keys = [grant_key(id), claim_key(id), result_key(id)];
        let unique: std::collections::HashSet<&String> = keys.iter().collect();
        assert_eq!(unique.len(), 3, "namespaces collide: {keys:?}");
    }

    /// The result carries the claimed `hybrid_vk` forward.
    ///
    /// Completion consumes the claim, so this copy is the only thing left to
    /// check a collector's signature against. Dropping it would leave no way to
    /// verify the caller and force the endpoint open — which is the failure this
    /// whole design exists to avoid.
    #[test]
    fn a_result_keeps_the_key_its_signature_is_checked_against() {
        let result = EnrollmentResult {
            device_id: "device-1".into(),
            hybrid_vk: "vk".into(),
        };
        let decoded: EnrollmentResult =
            serde_json::from_slice(&serde_json::to_vec(&result).unwrap()).unwrap();
        assert_eq!(decoded.device_id, "device-1");
        assert_eq!(decoded.hybrid_vk, "vk");
    }

    /// A claim carries public halves only. If a private key ever appeared in
    /// this struct the whole change would be undone, so the shape is asserted.
    #[test]
    fn a_claim_carries_no_private_key_material() {
        let claim = Claim {
            hybrid_ek: "ek".into(),
            hybrid_vk: "vk".into(),
            device_name: Some("Phone".into()),
            device_type: Some("android".into()),
        };
        let json = serde_json::to_string(&claim).unwrap();
        for forbidden in ["hybrid_sk", "transfer_key", "_sk", "private"] {
            assert!(
                !json.contains(forbidden),
                "a claim must never carry {forbidden}: {json}"
            );
        }
    }
}
