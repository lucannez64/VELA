//! Pure policy for admitting server responses into the local vault (M23).
//!
//! The sync engine is the one place a malicious or buggy server could
//! silently rewrite client history: roll an item back to an earlier Lamport
//! clock, resurrect a deleted item, skip the device past a key-rotation
//! transition, or adopt a capsule sealed for a different epoch. This crate
//! owns every accept/refuse decision for that boundary. I/O, KEM opening,
//! AEAD, clocks and storage stay outside — callers turn their authenticated
//! observations into facts and act only from the permits built here. hax
//! extracts these exact decisions to F*.

pub const INITIAL_EPOCH: i64 = 1;

// ── Epoch probe & adoption ──────────────────────────────────────────────────

/// Durable observations from `GET /vault/epoch` and the adoption capsule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochAdoptionFacts {
    /// Server reports `state == "active"` (no rotation mid-flight).
    pub rotation_state_active: bool,
    pub server_epoch: i64,
    /// Epoch authenticated by this device's local `key_epoch.enc`.
    pub local_epoch: i64,
    /// `server_epoch == local_epoch + 1`, computed by the caller (the one
    /// arithmetic atom in the protocol — ProVerif/F* prelude i64 math is
    /// opaque, so the transition relation crosses as an observation).
    pub server_epoch_is_next: bool,
    /// The adoption capsule's inner plaintext epoch equals `server_epoch`.
    /// `None` before the capsule is fetched.
    pub capsule_epoch_matches: Option<bool>,
    /// The committed rotation id is present in both capsule and metadata.
    /// `None` before the capsule is fetched.
    pub rotation_id_present: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionDecision {
    /// Epochs already agree: nothing to migrate.
    Keep,
    /// A sequential advance with no capsule facts yet: fetch the adoption
    /// capsule and re-run this decision with real observations.
    FetchCapsule,
    /// Open the capsule and migrate every local RMS consumer to this epoch.
    Adopt(EpochAdoptionPermit),
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochAdoptionPermit {
    epoch: i64,
    /// The adopted RMS came from a capsule bound to exactly this transition.
    binds_capsule_epoch: bool,
}

impl EpochAdoptionPermit {
    pub const fn epoch(self) -> i64 {
        self.epoch
    }

    pub const fn binds_capsule_epoch(self) -> bool {
        self.binds_capsule_epoch
    }
}

/// The adoption ladder: refuse inactive rotations, refuse rollback, refuse
/// skipped transitions, then require the capsule to be bound to exactly the
/// advertised epoch before permitting migration.
pub fn epoch_adoption_is_authorized(facts: EpochAdoptionFacts) -> bool {
    facts.rotation_state_active
        && facts.server_epoch >= INITIAL_EPOCH
        && facts.local_epoch >= INITIAL_EPOCH
        && facts.server_epoch > facts.local_epoch
        && facts.server_epoch_is_next
        && facts.capsule_epoch_matches == Some(true)
        && facts.rotation_id_present == Some(true)
}

/// A sequential advance whose capsule has not been fetched yet (fact fields
/// `None`) asks the caller to fetch it; every other unauthorized shape is a
/// plain rejection.
fn epoch_adoption_is_fetch_pending(facts: EpochAdoptionFacts) -> bool {
    facts.server_epoch_is_next
        && (facts.capsule_epoch_matches.is_none() || facts.rotation_id_present.is_none())
}

pub fn epoch_adoption_decision_matches_spec(
    facts: EpochAdoptionFacts,
    decision: AdoptionDecision,
) -> bool {
    if !facts.rotation_state_active {
        matches!(decision, AdoptionDecision::Reject)
    } else if facts.server_epoch < INITIAL_EPOCH || facts.local_epoch < INITIAL_EPOCH {
        matches!(decision, AdoptionDecision::Reject)
    } else if facts.server_epoch == facts.local_epoch {
        matches!(decision, AdoptionDecision::Keep)
    } else if !facts.server_epoch_is_next {
        matches!(decision, AdoptionDecision::Reject)
    } else if epoch_adoption_is_fetch_pending(facts) {
        matches!(decision, AdoptionDecision::FetchCapsule)
    } else if epoch_adoption_is_authorized(facts) {
        matches!(
            decision,
            AdoptionDecision::Adopt(ref permit)
                if permit.epoch() == facts.server_epoch && permit.binds_capsule_epoch()
        )
    } else {
        matches!(decision, AdoptionDecision::Reject)
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    epoch_adoption_decision_matches_spec(facts, decision)
}))]
pub fn plan_epoch_adoption(facts: EpochAdoptionFacts) -> AdoptionDecision {
    if !facts.rotation_state_active {
        return AdoptionDecision::Reject;
    }
    if facts.server_epoch < INITIAL_EPOCH || facts.local_epoch < INITIAL_EPOCH {
        return AdoptionDecision::Reject;
    }
    if facts.server_epoch == facts.local_epoch {
        return AdoptionDecision::Keep;
    }
    if !facts.server_epoch_is_next {
        return AdoptionDecision::Reject;
    }
    if epoch_adoption_is_authorized(facts) {
        AdoptionDecision::Adopt(EpochAdoptionPermit {
            epoch: facts.server_epoch,
            binds_capsule_epoch: true,
        })
    } else if epoch_adoption_is_fetch_pending(facts) {
        AdoptionDecision::FetchCapsule
    } else {
        AdoptionDecision::Reject
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rolled_back_server_epoch_can_adopt(mut facts: EpochAdoptionFacts) -> bool {
    // One epoch older than local, clamped at the initial epoch.
    facts.server_epoch = if facts.local_epoch <= INITIAL_EPOCH {
        INITIAL_EPOCH
    } else {
        facts.local_epoch - 1
    };
    epoch_adoption_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn skipped_transition_can_adopt(mut facts: EpochAdoptionFacts) -> bool {
    // A gap of two or more is not a sequential transition.
    facts.server_epoch_is_next = false;
    epoch_adoption_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn freezing_rotation_can_adopt(mut facts: EpochAdoptionFacts) -> bool {
    facts.rotation_state_active = false;
    epoch_adoption_is_authorized(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn foreign_capsule_can_adopt(mut facts: EpochAdoptionFacts) -> bool {
    facts.capsule_epoch_matches = Some(false);
    epoch_adoption_is_authorized(facts)
}

// ── Mobile sync epoch agreement ────────────────────────────────────────────

/// Epoch observations for a client that deliberately does **not** adopt a
/// rotated RMS automatically. The two integers are the epoch the server's
/// manifest advertises and the epoch this device authenticated from its local
/// `key_epoch.enc` marker. Passing two numbers — rather than a precomputed
/// `matches`/`is_next` boolean — keeps the comparison itself in verified code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncEpochFacts {
    pub server_epoch: i64,
    pub local_epoch: i64,
}

/// Mobile chunk downloads require the manifest epoch and the locally
/// authenticated epoch to be exactly equal and positive. A mismatch is a
/// rotation this device has not adopted yet; it must refuse rather than guess.
pub fn sync_epochs_agree_for_download(facts: SyncEpochFacts) -> bool {
    facts.server_epoch >= INITIAL_EPOCH
        && facts.local_epoch >= INITIAL_EPOCH
        && facts.server_epoch == facts.local_epoch
}

pub fn sync_epoch_decision_matches_spec(facts: SyncEpochFacts, allowed: bool) -> bool {
    allowed == sync_epochs_agree_for_download(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|allowed| {
    sync_epoch_decision_matches_spec(facts, allowed)
}))]
pub fn plan_sync_epoch_match(facts: SyncEpochFacts) -> bool {
    sync_epochs_agree_for_download(facts)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == true))]
pub fn equal_positive_epoch_admits_download() -> bool {
    sync_epochs_agree_for_download(SyncEpochFacts {
        server_epoch: 4,
        local_epoch: 4,
    })
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn mismatched_positive_epoch_admits_download() -> bool {
    sync_epochs_agree_for_download(SyncEpochFacts {
        server_epoch: 4,
        local_epoch: 5,
    })
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn nonpositive_epoch_admits_download() -> bool {
    sync_epochs_agree_for_download(SyncEpochFacts {
        server_epoch: 0,
        local_epoch: 0,
    })
}

// ── Chunk download admission (Lamport rollback guard) ───────────────────────

/// Observations when a chunk download returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkDownloadFacts {
    pub server_lamport: i64,
    /// Lamport clock this device last recorded for the chunk, if any.
    pub last_seen_lamport: Option<i64>,
    /// The chunk decrypted successfully under its derived key with the
    /// epoch-bound AAD (epoch ‖ chunk_id ‖ lamport).
    pub aad_binding_verified: bool,
    pub key_epoch_positive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkDownloadDecision {
    Accept(ChunkDownloadPermit),
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkDownloadPermit {
    lamport: i64,
}

impl ChunkDownloadPermit {
    pub const fn lamport(self) -> i64 {
        self.lamport
    }
}

pub fn chunk_download_is_authorized(facts: ChunkDownloadFacts) -> bool {
    let no_seen_clock = matches!(facts.last_seen_lamport, None);
    let not_older = matches!(facts.last_seen_lamport, Some(seen) if facts.server_lamport >= seen);
    (no_seen_clock || not_older)
        && facts.aad_binding_verified
        && facts.key_epoch_positive
        && facts.server_lamport >= INITIAL_EPOCH
}

pub fn chunk_download_decision_matches_spec(
    facts: ChunkDownloadFacts,
    decision: ChunkDownloadDecision,
) -> bool {
    match decision {
        ChunkDownloadDecision::Accept(permit) => {
            chunk_download_is_authorized(facts) && permit.lamport == facts.server_lamport
        }
        ChunkDownloadDecision::Reject => !chunk_download_is_authorized(facts),
    }
}

#[cfg_attr(hax, hax_lib::ensures(|decision| {
    chunk_download_decision_matches_spec(facts, decision)
}))]
pub fn plan_chunk_download(facts: ChunkDownloadFacts) -> ChunkDownloadDecision {
    if chunk_download_is_authorized(facts) {
        ChunkDownloadDecision::Accept(ChunkDownloadPermit {
            lamport: facts.server_lamport,
        })
    } else {
        ChunkDownloadDecision::Reject
    }
}

/// Witness: a device that recorded Lamport 7 refuses a server revision at
/// Lamport 3. The universal statement — *no* older revision admits — follows
/// from `chunk_download_is_authorized`'s single `server >= seen` conjunct
/// (verified through `chunk_download_decision_matches_spec`) together with
/// this concrete instantiation.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn rolled_back_chunk_can_be_accepted() -> bool {
    chunk_download_is_authorized(ChunkDownloadFacts {
        server_lamport: 3,
        last_seen_lamport: Some(7),
        aad_binding_verified: true,
        key_epoch_positive: true,
    })
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn unbound_aad_chunk_can_be_accepted(mut facts: ChunkDownloadFacts) -> bool {
    facts.aad_binding_verified = false;
    chunk_download_is_authorized(facts)
}

// ── Item merge classification ───────────────────────────────────────────────

/// Per-item observations during a merge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemMergeFacts {
    /// A tombstone exists whose `deleted_at` is at or after the item's
    /// `updated_at` on the side it came from.
    pub tombstone_covers_item: bool,
    pub server_updated_at_newer: bool,
    /// The local copy's `last_modified_device` is THIS device (an unsynced
    /// local edit), as opposed to another device's edit propagating.
    pub local_modified_by_this_device: bool,
    /// The item was already flagged as a conflict in this merge pass.
    pub already_conflicted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeAction {
    /// Deletion wins: drop the item locally.
    StayDeleted,
    /// Server newer, local edit synced elsewhere: take the server copy.
    AcceptServer,
    /// Unsynced local edit vs newer server copy: surface to the user.
    Conflict,
    /// Local is at least as new, or the server edit would clobber a
    /// conflicted local edit: keep what we have.
    KeepLocal,
}

pub fn merge_action_matches_spec(facts: ItemMergeFacts, action: MergeAction) -> bool {
    let expected = if facts.tombstone_covers_item {
        MergeAction::StayDeleted
    } else if facts.server_updated_at_newer {
        if facts.already_conflicted {
            MergeAction::KeepLocal
        } else if facts.local_modified_by_this_device {
            MergeAction::Conflict
        } else {
            MergeAction::AcceptServer
        }
    } else {
        MergeAction::KeepLocal
    };
    same_merge_action(action, expected)
}

#[cfg_attr(hax, hax_lib::ensures(|action| {
    merge_action_matches_spec(facts, action)
}))]
pub fn classify_merge_action(facts: ItemMergeFacts) -> MergeAction {
    if facts.tombstone_covers_item {
        MergeAction::StayDeleted
    } else if facts.server_updated_at_newer {
        if facts.already_conflicted {
            MergeAction::KeepLocal
        } else if facts.local_modified_by_this_device {
            MergeAction::Conflict
        } else {
            MergeAction::AcceptServer
        }
    } else {
        MergeAction::KeepLocal
    }
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn tombstoned_item_can_be_resurrected(mut facts: ItemMergeFacts) -> bool {
    facts.tombstone_covers_item = true;
    merge_action_matches_spec(facts, MergeAction::AcceptServer)
}

#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn conflicted_local_edit_can_be_overwritten(mut facts: ItemMergeFacts) -> bool {
    facts.already_conflicted = true;
    facts.server_updated_at_newer = true;
    merge_action_matches_spec(facts, MergeAction::AcceptServer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adoption_ladder_rejects_everything_but_the_next_epoch() {
        let valid = EpochAdoptionFacts {
            rotation_state_active: true,
            server_epoch: 5,
            local_epoch: 4,
            server_epoch_is_next: true,
            capsule_epoch_matches: Some(true),
            rotation_id_present: Some(true),
        };
        let AdoptionDecision::Adopt(permit) = plan_epoch_adoption(valid) else {
            panic!("valid adoption rejected");
        };
        assert_eq!(permit.epoch(), 5);
        assert!(permit.binds_capsule_epoch());

        // Equal epochs keep without adopting.
        let mut same = valid;
        same.server_epoch = 4;
        assert_eq!(plan_epoch_adoption(same), AdoptionDecision::Keep);

        // A sequential advance before the capsule is fetched asks for it.
        let mut unfetched = valid;
        unfetched.capsule_epoch_matches = None;
        unfetched.rotation_id_present = None;
        assert_eq!(
            plan_epoch_adoption(unfetched),
            AdoptionDecision::FetchCapsule
        );

        // Rollback, skip, freezing, foreign capsule all reject.
        assert!(!rolled_back_server_epoch_can_adopt(valid));
        assert!(!skipped_transition_can_adopt(valid));
        assert!(!freezing_rotation_can_adopt(valid));
        assert!(!foreign_capsule_can_adopt(valid));

        let mut older_local = valid;
        older_local.local_epoch = 9;
        assert_eq!(plan_epoch_adoption(older_local), AdoptionDecision::Reject);
    }

    #[test]
    fn chunk_download_rejects_rollback_and_unbound_aad() {
        let first_sync = ChunkDownloadFacts {
            server_lamport: 3,
            last_seen_lamport: None,
            aad_binding_verified: true,
            key_epoch_positive: true,
        };
        let ChunkDownloadDecision::Accept(permit) = plan_chunk_download(first_sync) else {
            panic!("first sync rejected");
        };
        assert_eq!(permit.lamport(), 3);

        // Equal-clock re-delivery (same revision re-sent) is accepted.
        let seen = ChunkDownloadFacts {
            server_lamport: 5,
            last_seen_lamport: Some(5),
            ..first_sync
        };
        assert!(matches!(
            plan_chunk_download(seen),
            ChunkDownloadDecision::Accept(_) // equal clock re-delivery ok
        ));
        assert!(!rolled_back_chunk_can_be_accepted());
        assert!(!unbound_aad_chunk_can_be_accepted(first_sync));

        let mut stale = seen;
        stale.server_lamport = 4; // < last seen 5
        assert_eq!(plan_chunk_download(stale), ChunkDownloadDecision::Reject);
    }

    #[test]
    fn chunk_admission_boundary_grid_matches_independent_predicate() {
        // Boundary grid: both signed extremes, the positive-clock boundary
        // (-1/0 rejected, 1 admitted), first contact (None), a recorded zero
        // baseline, ordinary baselines and both i64 extremes as baselines,
        // crossed with every flag combination.
        // (The universal F* proof is in
        // `proofs/fstar/chunk-lemmas/Vela_sync_policy_chunk_lemmas.fst`.)
        let clocks = [i64::MIN, -1, 0, 1, 2, 5, i64::MAX];
        let baselines = [
            None,
            Some(0),
            Some(1),
            Some(5),
            Some(i64::MIN),
            Some(i64::MAX),
        ];
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for &clock in &clocks {
            for &baseline in &baselines {
                for &aad in &[true, false] {
                    for &epoch in &[true, false] {
                        let facts = ChunkDownloadFacts {
                            server_lamport: clock,
                            last_seen_lamport: baseline,
                            aad_binding_verified: aad,
                            key_epoch_positive: epoch,
                        };
                        // Stated independently of `chunk_download_is_authorized`.
                        let admissible = aad
                            && epoch
                            && clock >= 1
                            && match baseline {
                                None => true,
                                Some(seen) => clock >= seen,
                            };
                        match plan_chunk_download(facts) {
                            ChunkDownloadDecision::Accept(permit) => {
                                assert!(
                                    admissible,
                                    "accepted inadmissible clock {clock} / baseline {baseline:?}"
                                );
                                assert_eq!(
                                    permit.lamport(),
                                    clock,
                                    "permit must carry the admitted server clock"
                                );
                                accepted += 1;
                            }
                            ChunkDownloadDecision::Reject => {
                                assert!(
                                    !admissible,
                                    "refused admissible clock {clock} / baseline {baseline:?}"
                                );
                                rejected += 1;
                            }
                        }
                    }
                }
            }
        }
        // Nonvacuity: the grid exercises both outcomes.
        assert!(accepted > 0 && rejected > 0);

        // `None` and `Some 0` decide identically at every clock: the `>= 1`
        // conjunct already excludes the only clock where a naive
        // "treat a missing baseline as zero" reading could differ. They remain
        // distinct caller states (first contact vs. recorded zero), which the
        // permit does not record.
        for &clock in &clocks {
            for &aad in &[true, false] {
                for &epoch in &[true, false] {
                    let first_contact = ChunkDownloadFacts {
                        server_lamport: clock,
                        last_seen_lamport: None,
                        aad_binding_verified: aad,
                        key_epoch_positive: epoch,
                    };
                    let zero_baseline = ChunkDownloadFacts {
                        last_seen_lamport: Some(0),
                        ..first_contact
                    };
                    assert_eq!(
                        plan_chunk_download(first_contact),
                        plan_chunk_download(zero_baseline)
                    );
                }
            }
        }

        // Clock 0 is refused with no baseline and with a zero baseline; the
        // least signed baseline does not launder a nonpositive clock; the least
        // signed clock is always refused; and a positive epoch/AAD flag is
        // load-bearing even at the largest clock.
        let base = ChunkDownloadFacts {
            server_lamport: 0,
            last_seen_lamport: None,
            aad_binding_verified: true,
            key_epoch_positive: true,
        };
        assert_eq!(plan_chunk_download(base), ChunkDownloadDecision::Reject);
        assert_eq!(
            plan_chunk_download(ChunkDownloadFacts {
                last_seen_lamport: Some(0),
                ..base
            }),
            ChunkDownloadDecision::Reject
        );
        assert_eq!(
            plan_chunk_download(ChunkDownloadFacts {
                last_seen_lamport: Some(i64::MIN),
                ..base
            }),
            ChunkDownloadDecision::Reject
        );
        assert_eq!(
            plan_chunk_download(ChunkDownloadFacts {
                server_lamport: i64::MIN,
                last_seen_lamport: None,
                ..base
            }),
            ChunkDownloadDecision::Reject
        );
        // The least signed baseline is dominated by the positive-clock floor.
        assert!(matches!(
            plan_chunk_download(ChunkDownloadFacts {
                server_lamport: 1,
                last_seen_lamport: Some(i64::MIN),
                ..base
            }),
            ChunkDownloadDecision::Accept(permit) if permit.lamport() == 1
        ));
        let largest = ChunkDownloadFacts {
            server_lamport: i64::MAX,
            last_seen_lamport: None,
            aad_binding_verified: true,
            key_epoch_positive: false,
        };
        assert_eq!(plan_chunk_download(largest), ChunkDownloadDecision::Reject);
        assert_eq!(
            plan_chunk_download(ChunkDownloadFacts {
                key_epoch_positive: true,
                aad_binding_verified: false,
                ..largest
            }),
            ChunkDownloadDecision::Reject
        );
    }

    #[test]
    fn mobile_sync_epoch_requires_exact_positive_agreement() {
        assert!(plan_sync_epoch_match(SyncEpochFacts {
            server_epoch: 4,
            local_epoch: 4,
        }));
        // Any gap in either direction is an unadopted rotation, not a licence
        // to guess which key to use.
        for (server, local) in [(5, 4), (4, 5), (9, 3), (3, 9)] {
            assert!(!plan_sync_epoch_match(SyncEpochFacts {
                server_epoch: server,
                local_epoch: local,
            }));
        }
        // Zero and negative epochs never name a real account state.
        for (server, local) in [(0, 0), (0, 1), (1, 0), (-1, -1), (-1, 1)] {
            assert!(!plan_sync_epoch_match(SyncEpochFacts {
                server_epoch: server,
                local_epoch: local,
            }));
        }
        assert!(equal_positive_epoch_admits_download());
        assert!(!mismatched_positive_epoch_admits_download());
        assert!(!nonpositive_epoch_admits_download());

        // The same property on a grid, stated independently of the spec
        // function: accepted exactly when both epochs are positive and equal.
        // (The parametric proof lives in
        // `proofs/fstar/epoch-lemmas/Vela_sync_policy_epoch_lemmas.fst`.)
        for server in -3i64..=6 {
            for local in -3i64..=6 {
                let admissible = server > 0 && local > 0 && server == local;
                assert_eq!(
                    plan_sync_epoch_match(SyncEpochFacts {
                        server_epoch: server,
                        local_epoch: local,
                    }),
                    admissible,
                    "epoch pair ({server}, {local}) must decide exactly as positivity + equality"
                );
            }
        }
    }

    #[test]
    fn merge_classification_covers_every_combination() {
        // Exhaustive over the four booleans: spec equality holds everywhere,
        // and the two impossibility claims hold globally.
        for &tombstoned in &[true, false] {
            for &server_newer in &[true, false] {
                for &local_edit in &[true, false] {
                    for &conflicted in &[true, false] {
                        let facts = ItemMergeFacts {
                            tombstone_covers_item: tombstoned,
                            server_updated_at_newer: server_newer,
                            local_modified_by_this_device: local_edit,
                            already_conflicted: conflicted,
                        };
                        let action = classify_merge_action(facts);
                        assert!(merge_action_matches_spec(facts, action));

                        // A tombstoned item is never accepted from the server…
                        if tombstoned {
                            assert_ne!(action, MergeAction::AcceptServer);
                        }
                        // …and a conflicted local edit is never overwritten:
                        // once flagged, the server copy loses even when newer.
                        if conflicted && !tombstoned && server_newer {
                            assert_eq!(action, MergeAction::KeepLocal);
                            assert_ne!(action, MergeAction::AcceptServer);
                        }
                    }
                }
            }
        }
        assert!(!tombstoned_item_can_be_resurrected(ItemMergeFacts {
            tombstone_covers_item: false,
            server_updated_at_newer: true,
            local_modified_by_this_device: false,
            already_conflicted: false,
        }));
        assert!(!conflicted_local_edit_can_be_overwritten(ItemMergeFacts {
            tombstone_covers_item: false,
            server_updated_at_newer: true,
            local_modified_by_this_device: true,
            already_conflicted: false,
        }));
    }
}

fn same_merge_action(a: MergeAction, b: MergeAction) -> bool {
    matches!(
        (a, b),
        (MergeAction::StayDeleted, MergeAction::StayDeleted)
            | (MergeAction::AcceptServer, MergeAction::AcceptServer)
            | (MergeAction::Conflict, MergeAction::Conflict)
            | (MergeAction::KeepLocal, MergeAction::KeepLocal)
    )
}
#[cfg(test)]
mod structural_equality_tests {
    use super::*;
    #[test]
    fn structural_merge_equality_matches_derived_equality_exhaustively() {
        let values = [
            MergeAction::StayDeleted,
            MergeAction::AcceptServer,
            MergeAction::Conflict,
            MergeAction::KeepLocal,
        ];
        for a in values {
            for b in values {
                assert_eq!(same_merge_action(a, b), a == b);
            }
        }
    }
}
