//! Exhaustive transition tests for the pure M19/M21 sharing driver.
//!
//! These tests exercise decision coverage, not the effectful HTTP handlers.
//! Handler conformance remains in `vela-server/tests/share_channel_model.rs`.

use vela_share_policy::driver::{
    begin_ek_registration, begin_inbox_delete, begin_link_revoke, begin_link_update, begin_send,
    on_cleanup_completed, on_ek_observation, on_link_observation, on_rows_observed,
    on_send_completed, share_effect_is_sound, share_state_is_sound, CleanupObservation,
    EkDeviceObservation, EkRegistrationStartObservation, LinkUpdateStartObservation,
    RowsObservation, SendRequestObservation, SendResultObservation, ShareDriver, ShareEffect,
    ShareEvent, ShareFailure, ShareRequestKind, ShareStage, ShareTransition,
};
use vela_share_policy::{
    EkRegistrationObservation, LinkMutationObservation, SendObservation, MAX_CAPSULE_BYTES,
    MAX_RECIPIENT_INBOX_BYTES, SHARE_EK_LEN,
};

const VALID_LEN: i64 = 128;

fn send_observation() -> SendRequestObservation {
    SendRequestObservation {
        policy: SendObservation {
            session_user_id_present: true,
            recipient_has_share_ek: true,
            capsule_len: VALID_LEN,
            existing_inbox_bytes: 0,
        },
        decode_failed: false,
        inbox_count: 0,
        pair_bytes: 0,
    }
}

fn link_observation() -> LinkMutationObservation {
    LinkMutationObservation {
        item_present: true,
        caller_matches_sender: true,
        item_not_revoked: true,
    }
}

fn ek_start() -> EkRegistrationStartObservation {
    EkRegistrationStartObservation {
        ek_decode_failed: false,
        ek_len: SHARE_EK_LEN,
        signed_at_not_canonical: false,
        signed_at_unparseable: false,
        signed_at_future: false,
    }
}

fn ek_device() -> EkDeviceObservation {
    EkDeviceObservation {
        registration: EkRegistrationObservation {
            ek_len: SHARE_EK_LEN,
            signature_verified: true,
            device_row_present: true,
            device_user_matches: true,
            device_active: true,
            signed_at_is_fresher: true,
            binding_exists: false,
        },
        stored_identity_vk_decode_failed: false,
        signature_decode_failed: false,
    }
}

fn apply(driver: ShareDriver, event: ShareEvent) -> ShareTransition {
    let transition = match event {
        ShareEvent::LinkObserved(observation) => on_link_observation(driver, observation),
        ShareEvent::EkObserved(observation) => on_ek_observation(driver, observation),
        ShareEvent::SendResult(observation) => on_send_completed(driver, observation),
        ShareEvent::Mutated(observation) => on_rows_observed(driver, observation),
        ShareEvent::Cleaned(observation) => on_cleanup_completed(driver, observation),
    };
    assert!(
        share_effect_is_sound(transition.driver, transition.effect),
        "step emitted an effect unsupported by its post-state: {driver:?} / {event:?} -> {transition:?}"
    );
    assert!(
        !share_state_is_sound(driver) || share_state_is_sound(transition.driver),
        "step broke the soundness invariant: {driver:?} / {event:?} -> {transition:?}"
    );
    transition
}

fn advance(mut driver: ShareDriver, events: &[ShareEvent]) -> (ShareDriver, ShareEffect) {
    let mut effect = ShareEffect::Idle;
    for event in events {
        let transition = apply(driver, *event);
        driver = transition.driver;
        effect = transition.effect;
    }
    (driver, effect)
}

fn begin_valid_send() -> ShareDriver {
    let transition = begin_send(send_observation());
    assert!(matches!(transition.effect, ShareEffect::InsertCapsule(_)));
    transition.driver
}

fn begin_valid_link_update() -> ShareDriver {
    let transition = begin_link_update(LinkUpdateStartObservation {
        decode_failed: false,
        capsule_len: VALID_LEN,
    });
    assert!(matches!(transition.effect, ShareEffect::ObserveLink));
    transition.driver
}

fn begin_valid_link_revoke() -> ShareDriver {
    let transition = begin_link_revoke();
    assert!(matches!(transition.effect, ShareEffect::ObserveLink));
    transition.driver
}

fn to_update_apply() -> ShareDriver {
    let (driver, effect) = advance(
        begin_valid_link_update(),
        &[ShareEvent::LinkObserved(link_observation())],
    );
    assert!(matches!(effect, ShareEffect::UpdateLinkedItem(_)));
    driver
}

fn to_revoke_apply() -> ShareDriver {
    let (driver, effect) = advance(
        begin_valid_link_revoke(),
        &[ShareEvent::LinkObserved(link_observation())],
    );
    assert!(matches!(effect, ShareEffect::RevokeLinkedItem));
    driver
}

fn to_revoke_cleanup() -> ShareDriver {
    let (driver, effect) = advance(
        to_revoke_apply(),
        &[ShareEvent::Mutated(RowsObservation { rows: 1 })],
    );
    assert!(matches!(effect, ShareEffect::DeleteLinkedInbox));
    driver
}

fn begin_valid_ek() -> ShareDriver {
    let transition = begin_ek_registration(ek_start());
    assert!(matches!(transition.effect, ShareEffect::ObserveDevice));
    transition.driver
}

fn to_ek_register() -> ShareDriver {
    let (driver, effect) = advance(begin_valid_ek(), &[ShareEvent::EkObserved(ek_device())]);
    assert!(matches!(effect, ShareEffect::UpdateShareEk(_)));
    driver
}

fn reachable_stages() -> Vec<ShareDriver> {
    vec![
        begin_valid_send(),
        begin_valid_link_update(),
        to_update_apply(),
        begin_valid_link_revoke(),
        to_revoke_apply(),
        to_revoke_cleanup(),
        begin_inbox_delete().driver,
        begin_valid_ek(),
        to_ek_register(),
    ]
}

fn all_events() -> Vec<ShareEvent> {
    let mut observations = vec![
        link_observation(),
        LinkMutationObservation {
            item_present: true,
            caller_matches_sender: false,
            item_not_revoked: true,
        },
        LinkMutationObservation {
            item_present: true,
            caller_matches_sender: true,
            item_not_revoked: false,
        },
        LinkMutationObservation {
            item_present: false,
            caller_matches_sender: false,
            item_not_revoked: false,
        },
    ];
    let mut events = Vec::new();
    for observation in observations.drain(..) {
        events.push(ShareEvent::LinkObserved(observation));
    }
    for registration in [
        ek_device(),
        EkDeviceObservation {
            registration: EkRegistrationObservation {
                signature_verified: false,
                ..ek_device().registration
            },
            ..ek_device()
        },
        EkDeviceObservation {
            registration: EkRegistrationObservation {
                device_user_matches: false,
                ..ek_device().registration
            },
            ..ek_device()
        },
        EkDeviceObservation {
            registration: EkRegistrationObservation {
                device_active: false,
                ..ek_device().registration
            },
            ..ek_device()
        },
        EkDeviceObservation {
            registration: EkRegistrationObservation {
                signed_at_is_fresher: false,
                ..ek_device().registration
            },
            ..ek_device()
        },
        EkDeviceObservation {
            stored_identity_vk_decode_failed: true,
            ..ek_device()
        },
        EkDeviceObservation {
            signature_decode_failed: true,
            ..ek_device()
        },
    ] {
        events.push(ShareEvent::EkObserved(registration));
    }
    events.push(ShareEvent::SendResult(SendResultObservation::Committed));
    events.push(ShareEvent::SendResult(SendResultObservation::StorageFailed));
    events.push(ShareEvent::SendResult(
        SendResultObservation::CommitConflict,
    ));
    events.push(ShareEvent::Mutated(RowsObservation { rows: 0 }));
    events.push(ShareEvent::Mutated(RowsObservation { rows: 1 }));
    events.push(ShareEvent::Cleaned(CleanupObservation {
        storage_failed: false,
    }));
    events.push(ShareEvent::Cleaned(CleanupObservation {
        storage_failed: true,
    }));
    events
}

fn event_is_in_stage(event: &ShareEvent, stage: ShareStage) -> bool {
    match (event, stage) {
        (
            ShareEvent::LinkObserved(_),
            ShareStage::LinkUpdateObserve | ShareStage::LinkRevokeObserve,
        ) => true,
        (ShareEvent::EkObserved(_), ShareStage::EkObserve) => true,
        (ShareEvent::SendResult(_), ShareStage::SendInsert) => true,
        (
            ShareEvent::Mutated(_),
            ShareStage::LinkUpdateApply
            | ShareStage::LinkRevokeApply
            | ShareStage::InboxDelete
            | ShareStage::EkRegister,
        ) => true,
        (ShareEvent::Cleaned(_), ShareStage::LinkCleanup) => true,
        _ => false,
    }
}

fn effect_is_link_mutation(effect: ShareEffect) -> bool {
    matches!(
        effect,
        ShareEffect::UpdateLinkedItem(_) | ShareEffect::RevokeLinkedItem
    )
}

#[test]
fn every_stage_ignores_every_out_of_order_event() {
    let drivers = reachable_stages();
    let events = all_events();
    for driver in drivers {
        assert!(share_state_is_sound(driver), "{driver:?}");
        for event in &events {
            let transition = apply(driver, *event);
            if !event_is_in_stage(event, driver.stage) {
                assert_eq!(
                    transition.effect,
                    ShareEffect::Idle,
                    "{driver:?} / {event:?}"
                );
                assert_eq!(transition.driver, driver, "{driver:?} / {event:?}");
            }
        }
    }
}

#[test]
fn every_reachable_transition_preserves_soundness_and_effect_authority() {
    let mut frontier: Vec<ShareDriver> = vec![
        begin_send(send_observation()).driver,
        begin_link_update(LinkUpdateStartObservation {
            decode_failed: false,
            capsule_len: VALID_LEN,
        })
        .driver,
        begin_valid_link_revoke(),
        begin_inbox_delete().driver,
        begin_valid_ek(),
    ];
    let events = all_events();
    for _ in 0..10 {
        let mut next = Vec::new();
        for driver in &frontier {
            assert!(share_state_is_sound(*driver), "{driver:?}");
            for event in &events {
                let transition = apply(*driver, *event);
                match transition.effect {
                    ShareEffect::InsertCapsule(permit) => {
                        assert!(
                            transition.driver.authorized
                                && transition.driver.sender_authenticated
                                && transition.driver.stage == ShareStage::SendInsert,
                            "send emitted without session+plan authority: {driver:?} / {event:?}"
                        );
                        assert_eq!(permit.capsule_len, transition.driver.capsule_len);
                    }
                    ShareEffect::UpdateLinkedItem(permit) => {
                        assert!(
                            transition.driver.authorized
                                && transition.driver.caller_is_sender
                                && transition.driver.link_live
                                && transition.driver.stage == ShareStage::LinkUpdateApply,
                            "update emitted without sender+live authority: {driver:?} / {event:?}"
                        );
                        assert_eq!(permit.capsule_len, transition.driver.capsule_len);
                    }
                    ShareEffect::RevokeLinkedItem => {
                        assert!(
                            transition.driver.authorized
                                && transition.driver.caller_is_sender
                                && transition.driver.link_live
                                && transition.driver.stage == ShareStage::LinkRevokeApply,
                            "revoke emitted without sender+live authority: {driver:?} / {event:?}"
                        );
                    }
                    ShareEffect::DeleteInboxItem(permit) => {
                        assert!(permit.recipient_scoped && transition.driver.recipient_scoped);
                    }
                    ShareEffect::UpdateShareEk(permit) => {
                        assert!(summary_ek_authorized(&transition.driver, permit));
                    }
                    ShareEffect::Complete => assert!(transition.driver.committed),
                    ShareEffect::Fail(_) => assert!(!transition.driver.committed),
                    _ => {}
                }
                if !next.contains(&transition.driver) {
                    next.push(transition.driver);
                }
            }
        }
        frontier = next;
    }
}

fn summary_ek_authorized(
    driver: &ShareDriver,
    permit: vela_share_policy::EkRegistrationPermit,
) -> bool {
    driver.kind == ShareRequestKind::RegisterShareEk
        && driver.stage == ShareStage::EkRegister
        && driver.observe_issued
        && driver.authorized
        && driver.effect_issued
        && !driver.committed
        && permit.binds_device_signature()
}

#[test]
fn send_requires_an_authenticated_session_and_the_real_plan() {
    // The recipient gate wins first.
    let mut observation = send_observation();
    observation.policy.recipient_has_share_ek = false;
    assert_eq!(
        begin_send(observation).effect,
        ShareEffect::Fail(ShareFailure::RecipientUnavailable)
    );

    // An unauthenticated session reaches `plan_send` and is rejected there.
    let mut observation = send_observation();
    observation.policy.session_user_id_present = false;
    assert_eq!(
        begin_send(observation).effect,
        ShareEffect::Fail(ShareFailure::CapsulePolicyRejected)
    );

    // A registered recipient with a valid capsule is admitted exactly once.
    let transition = begin_send(send_observation());
    assert!(matches!(transition.effect, ShareEffect::InsertCapsule(_)));
    assert!(transition.driver.sender_authenticated && transition.driver.authorized);
}

#[test]
fn send_quota_checks_keep_the_handlers_historical_order() {
    let cases = [
        (
            SendRequestObservation {
                decode_failed: true,
                ..send_observation()
            },
            ShareFailure::MalformedCapsule,
        ),
        (
            SendRequestObservation {
                policy: SendObservation {
                    capsule_len: MAX_CAPSULE_BYTES + 1,
                    ..send_observation().policy
                },
                ..send_observation()
            },
            ShareFailure::CapsuleTooLarge,
        ),
        (
            SendRequestObservation {
                inbox_count: 500,
                ..send_observation()
            },
            ShareFailure::InboxItemLimit,
        ),
        (
            SendRequestObservation {
                pair_bytes: 8 * 1024 * 1024 - VALID_LEN + 1,
                ..send_observation()
            },
            ShareFailure::SenderQuotaExceeded,
        ),
        (
            SendRequestObservation {
                policy: SendObservation {
                    existing_inbox_bytes: MAX_RECIPIENT_INBOX_BYTES,
                    ..send_observation().policy
                },
                ..send_observation()
            },
            ShareFailure::RecipientQuotaExceeded,
        ),
    ];
    for (observation, failure) in cases {
        assert_eq!(
            begin_send(observation).effect,
            ShareEffect::Fail(failure),
            "{observation:?}"
        );
    }

    // A well-formed empty capsule is not a size error; the real plan rejects
    // it, exactly as the handler did.
    let empty = SendRequestObservation {
        policy: SendObservation {
            capsule_len: 0,
            ..send_observation().policy
        },
        ..send_observation()
    };
    assert_eq!(
        begin_send(empty).effect,
        ShareEffect::Fail(ShareFailure::CapsulePolicyRejected)
    );
}

#[test]
fn link_mutations_require_the_sender_and_a_live_item() {
    for observation in [
        LinkMutationObservation {
            item_present: true,
            caller_matches_sender: false,
            item_not_revoked: true,
        },
        LinkMutationObservation {
            item_present: true,
            caller_matches_sender: true,
            item_not_revoked: false,
        },
        LinkMutationObservation {
            item_present: false,
            caller_matches_sender: false,
            item_not_revoked: false,
        },
    ] {
        let update = apply(
            begin_valid_link_update(),
            ShareEvent::LinkObserved(observation),
        );
        assert_eq!(update.effect, ShareEffect::Fail(ShareFailure::LinkNotFound));
        assert!(!update.driver.effect_issued);

        let revoke = apply(
            begin_valid_link_revoke(),
            ShareEvent::LinkObserved(observation),
        );
        assert_eq!(revoke.effect, ShareEffect::Fail(ShareFailure::LinkNotFound));
        assert!(!revoke.driver.effect_issued);
    }
}

#[test]
fn update_and_revoke_are_distinguished_by_the_observed_plan() {
    let update = apply(
        begin_valid_link_update(),
        ShareEvent::LinkObserved(link_observation()),
    );
    assert!(matches!(update.effect, ShareEffect::UpdateLinkedItem(_)));
    assert_eq!(update.driver.stage, ShareStage::LinkUpdateApply);

    let revoke = apply(
        begin_valid_link_revoke(),
        ShareEvent::LinkObserved(link_observation()),
    );
    assert_eq!(revoke.effect, ShareEffect::RevokeLinkedItem);
    assert_eq!(revoke.driver.stage, ShareStage::LinkRevokeApply);

    // A zero-row guarded update is a miss, not a success.
    let missing = apply(
        update.driver,
        ShareEvent::Mutated(RowsObservation { rows: 0 }),
    );
    assert_eq!(
        missing.effect,
        ShareEffect::Fail(ShareFailure::LinkNotFound)
    );
    assert!(!missing.driver.committed);
}

#[test]
fn revoke_commits_then_requests_the_inbox_cleanup_before_success() {
    let cleanup = apply(
        to_revoke_apply(),
        ShareEvent::Mutated(RowsObservation { rows: 1 }),
    );
    assert_eq!(cleanup.effect, ShareEffect::DeleteLinkedInbox);
    assert_eq!(cleanup.driver.stage, ShareStage::LinkCleanup);
    assert!(cleanup.driver.revoked && cleanup.driver.committed && cleanup.driver.cleanup_issued);

    for storage_failed in [false, true] {
        let (driver, effect) = advance(
            cleanup.driver,
            &[ShareEvent::Cleaned(CleanupObservation { storage_failed })],
        );
        assert_eq!(effect, ShareEffect::Complete);
        assert_eq!(driver.stage, ShareStage::Done);
        assert!(driver.committed && driver.revoked);
    }
}

#[test]
fn send_and_ek_results_are_classified_without_extra_effects() {
    let (driver, effect) = advance(
        begin_valid_send(),
        &[ShareEvent::SendResult(SendResultObservation::Committed)],
    );
    assert_eq!(effect, ShareEffect::Complete);
    assert!(driver.committed);

    for (observation, failure) in [
        (
            SendResultObservation::StorageFailed,
            ShareFailure::SendStorage,
        ),
        (
            SendResultObservation::CommitConflict,
            ShareFailure::SendConflict,
        ),
    ] {
        let (driver, effect) = advance(begin_valid_send(), &[ShareEvent::SendResult(observation)]);
        assert_eq!(effect, ShareEffect::Fail(failure));
        assert!(!driver.committed);
    }

    for rows in [0, 1] {
        let (driver, effect) = advance(
            to_ek_register(),
            &[ShareEvent::Mutated(RowsObservation { rows })],
        );
        if rows > 0 {
            assert_eq!(effect, ShareEffect::Complete);
            assert!(driver.committed);
        } else {
            assert_eq!(effect, ShareEffect::Fail(ShareFailure::UserNotFound));
        }
    }
}

#[test]
fn ek_registration_keeps_the_handlers_error_precedence() {
    assert_eq!(
        begin_ek_registration(EkRegistrationStartObservation {
            ek_decode_failed: true,
            ek_len: 0,
            ..ek_start()
        })
        .effect,
        ShareEffect::Fail(ShareFailure::ShareEkDecode)
    );
    assert_eq!(
        begin_ek_registration(EkRegistrationStartObservation {
            ek_len: SHARE_EK_LEN - 1,
            ..ek_start()
        })
        .effect,
        ShareEffect::Fail(ShareFailure::ShareEkSize)
    );
    for (observation, failure) in [
        (
            EkRegistrationStartObservation {
                signed_at_not_canonical: true,
                ..ek_start()
            },
            ShareFailure::SignedAtNotCanonical,
        ),
        (
            EkRegistrationStartObservation {
                signed_at_unparseable: true,
                ..ek_start()
            },
            ShareFailure::SignedAtUnparseable,
        ),
        (
            EkRegistrationStartObservation {
                signed_at_future: true,
                ..ek_start()
            },
            ShareFailure::SignedAtFuture,
        ),
    ] {
        assert_eq!(
            begin_ek_registration(observation).effect,
            ShareEffect::Fail(failure)
        );
    }

    for (observation, failure) in [
        (
            EkDeviceObservation {
                registration: EkRegistrationObservation {
                    signature_verified: false,
                    ..ek_device().registration
                },
                ..ek_device()
            },
            ShareFailure::EkPolicyRejected,
        ),
        (
            EkDeviceObservation {
                registration: EkRegistrationObservation {
                    device_row_present: false,
                    ..ek_device().registration
                },
                ..ek_device()
            },
            ShareFailure::DeviceNotEnrolled,
        ),
        (
            EkDeviceObservation {
                registration: EkRegistrationObservation {
                    device_user_matches: false,
                    ..ek_device().registration
                },
                ..ek_device()
            },
            ShareFailure::DeviceNotEnrolled,
        ),
        (
            EkDeviceObservation {
                stored_identity_vk_decode_failed: true,
                registration: EkRegistrationObservation {
                    signature_verified: false,
                    ..ek_device().registration
                },
                ..ek_device()
            },
            ShareFailure::StoredIdentityKey,
        ),
        (
            EkDeviceObservation {
                signature_decode_failed: true,
                registration: EkRegistrationObservation {
                    signature_verified: false,
                    ..ek_device().registration
                },
                ..ek_device()
            },
            ShareFailure::SignatureDecode,
        ),
        (
            EkDeviceObservation {
                registration: EkRegistrationObservation {
                    signed_at_is_fresher: false,
                    ..ek_device().registration
                },
                ..ek_device()
            },
            ShareFailure::EkPolicyRejected,
        ),
    ] {
        let transition = apply(begin_valid_ek(), ShareEvent::EkObserved(observation));
        assert_eq!(
            transition.effect,
            ShareEffect::Fail(failure),
            "{observation:?}"
        );
        assert!(!transition.driver.effect_issued);
    }
}

#[test]
fn inbox_delete_is_recipient_scoped_and_classifies_rows() {
    let transition = begin_inbox_delete();
    assert!(matches!(
        transition.effect,
        ShareEffect::DeleteInboxItem(permit) if permit.recipient_scoped
    ));
    assert!(transition.driver.recipient_scoped);

    let (driver, effect) = advance(
        transition.driver,
        &[ShareEvent::Mutated(RowsObservation { rows: 0 })],
    );
    assert_eq!(effect, ShareEffect::Fail(ShareFailure::InboxNotFound));
    assert!(!driver.committed);

    let (driver, effect) = advance(
        transition.driver,
        &[ShareEvent::Mutated(RowsObservation { rows: 1 })],
    );
    assert_eq!(effect, ShareEffect::Complete);
    assert!(driver.committed);
}

#[test]
fn link_mutation_length_checks_precede_the_row_observation() {
    for (observation, failure) in [
        (
            LinkUpdateStartObservation {
                decode_failed: true,
                capsule_len: 0,
            },
            ShareFailure::MalformedCapsule,
        ),
        (
            LinkUpdateStartObservation {
                decode_failed: false,
                capsule_len: MAX_CAPSULE_BYTES + 1,
            },
            ShareFailure::CapsuleTooLarge,
        ),
    ] {
        let transition = begin_link_update(observation);
        assert_eq!(transition.effect, ShareEffect::Fail(failure));
        assert_eq!(transition.driver.stage, ShareStage::Done);
    }
}

#[test]
fn a_done_driver_is_inert_for_every_event() {
    let terminal = [
        advance(
            begin_valid_send(),
            &[ShareEvent::SendResult(SendResultObservation::Committed)],
        )
        .0,
        advance(
            begin_valid_link_update(),
            &[ShareEvent::LinkObserved(LinkMutationObservation {
                item_present: false,
                caller_matches_sender: false,
                item_not_revoked: false,
            })],
        )
        .0,
        advance(
            to_revoke_cleanup(),
            &[ShareEvent::Cleaned(CleanupObservation {
                storage_failed: false,
            })],
        )
        .0,
        begin_send(SendRequestObservation {
            decode_failed: true,
            ..send_observation()
        })
        .driver,
    ];
    for driver in terminal {
        assert_eq!(driver.stage, ShareStage::Done, "{driver:?}");
        for event in all_events() {
            let transition = apply(driver, event);
            assert_eq!(
                transition.effect,
                ShareEffect::Idle,
                "{driver:?} / {event:?}"
            );
            assert_eq!(transition.driver, driver, "{driver:?} / {event:?}");
        }
    }
}

#[test]
fn link_mutation_effects_are_never_emitted_for_a_revoked_observation() {
    let revoked = LinkMutationObservation {
        item_present: true,
        caller_matches_sender: true,
        item_not_revoked: false,
    };
    for driver in [begin_valid_link_update(), begin_valid_link_revoke()] {
        let transition = apply(driver, ShareEvent::LinkObserved(revoked));
        assert!(!effect_is_link_mutation(transition.effect));
        assert!(!transition.driver.effect_issued);
    }
}
