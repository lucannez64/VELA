use vela_session_policy::{
    CapabilityScope, GrantDecision, GrantFacts, RenewalDecision, RouteClass, RouteDecision,
    SessionMode, SessionPhase, TokenClaims, TokenDecision, WebTokenFacts,
};

#[test]
fn every_bounded_grant_and_exchange_matches_the_m12_relation() {
    let phases = [
        SessionPhase::Pending,
        SessionPhase::Granted,
        SessionPhase::Revoked,
        SessionPhase::Expired,
    ];
    let modes = [SessionMode::ReadOnly, SessionMode::ReadWrite];

    for phase in phases {
        for mode in modes {
            for approver in [false, true] {
                for nonce in [false, true] {
                    for has_web_vk in [false, true] {
                        for epoch in 0..=2 {
                            let grant_facts = GrantFacts {
                                phase,
                                mode,
                                approver_matches: approver,
                                nonce_matches: nonce,
                                has_web_vk,
                                declared_epoch: epoch,
                            };
                            let expected = phase == SessionPhase::Pending
                                && approver
                                && nonce
                                && epoch >= 1
                                && (mode == SessionMode::ReadOnly || has_web_vk);
                            assert_eq!(
                                matches!(
                                    vela_session_policy::plan_grant(grant_facts),
                                    GrantDecision::Grant(_)
                                ),
                                expected,
                                "grant mismatch: {grant_facts:?}"
                            );
                        }
                    }

                    for challenge in [false, true] {
                        for signature in [false, true] {
                            let token_facts = WebTokenFacts {
                                phase,
                                mode,
                                approver_bound: approver,
                                nonce_bound: nonce,
                                challenge_consumed: challenge,
                                signature_valid: signature,
                            };
                            let expected = phase == SessionPhase::Granted
                                && mode == SessionMode::ReadWrite
                                && approver
                                && nonce
                                && challenge
                                && signature;
                            assert_eq!(
                                matches!(
                                    vela_session_policy::plan_web_session_token(
                                        token_facts,
                                        10,
                                        20,
                                        1,
                                    ),
                                    TokenDecision::Issue(_)
                                ),
                                expected,
                                "exchange mismatch: {token_facts:?}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn every_bounded_renewal_preserves_capability_or_fails_closed() {
    let scopes = [CapabilityScope::Device, CapabilityScope::WebSession];
    let epochs = [None, Some(0), Some(1)];

    for scope in scopes {
        for key_epoch in epochs {
            for now in 0..=3 {
                for expires_at in 0..=5 {
                    for hard_cap in 0..=5 {
                        let claims = TokenClaims {
                            scope,
                            key_epoch,
                            expires_at,
                            hard_cap,
                        };
                        let shape_valid = match scope {
                            CapabilityScope::Device => key_epoch.is_none(),
                            CapabilityScope::WebSession => {
                                key_epoch.is_none() || key_epoch.is_some_and(|epoch| epoch >= 1)
                            }
                        };
                        let input_valid = shape_valid
                            && hard_cap > now
                            && expires_at > now
                            && expires_at <= hard_cap;
                        match vela_session_policy::plan_renewal(claims, now) {
                            RenewalDecision::Renew(plan) => {
                                assert!(input_valid && expires_at < hard_cap);
                                assert_eq!(plan.scope(), scope);
                                assert_eq!(plan.key_epoch(), key_epoch);
                                assert_eq!(plan.hard_cap(), hard_cap);
                                assert!(plan.expires_at() <= hard_cap);
                            }
                            RenewalDecision::Keep => {
                                assert!(input_valid && expires_at == hard_cap);
                            }
                            RenewalDecision::Reject => assert!(!input_valid),
                        }
                        assert!(!vela_session_policy::renewal_escalates_authority(
                            claims, now
                        ));
                    }
                }
            }
        }
    }
}

#[test]
fn route_matrix_never_gives_web_sessions_permanent_authority() {
    for scope in [CapabilityScope::Device, CapabilityScope::WebSession] {
        for class in [RouteClass::Vault, RouteClass::PermanentAccount] {
            let allowed = matches!(
                vela_session_policy::authorize_route(scope, class),
                RouteDecision::Allow(_)
            );
            assert_eq!(
                allowed,
                scope == CapabilityScope::Device || class == RouteClass::Vault
            );
        }
    }
}
