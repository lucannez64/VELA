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
        decision == AdoptionDecision::Reject
    } else if facts.server_epoch < INITIAL_EPOCH || facts.local_epoch < INITIAL_EPOCH {
        decision == AdoptionDecision::Reject
    } else if facts.server_epoch == facts.local_epoch {
        decision == AdoptionDecision::Keep
    } else if !facts.server_epoch_is_next {
        decision == AdoptionDecision::Reject
    } else if epoch_adoption_is_fetch_pending(facts) {
        decision == AdoptionDecision::FetchCapsule
    } else if epoch_adoption_is_authorized(facts) {
        matches!(
            decision,
            AdoptionDecision::Adopt(ref permit)
                if permit.epoch() == facts.server_epoch && permit.binds_capsule_epoch()
        )
    } else {
        decision == AdoptionDecision::Reject
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
    action == expected
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

// ── Organization fields (tags / folder) ─────────────────────────────────────

/// A recorded tag removal, carried inside the item so a removal survives
/// merges with copies that still have the tag.
///
/// `tag` is the canonical key (the lowercased, trimmed spelling) and
/// `deleted_at_ms` the unix-millisecond time of the removal — plain data so
/// this crate stays dependency-free; the cores convert to/from their own
/// timestamp types at the boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagRemoval {
    pub tag: String,
    pub deleted_at_ms: i64,
}

/// Removal records older than this stop suppressing stale copies — the same
/// retention window item tombstones get. Long enough for any realistic
/// offline device to catch up.
pub const TAG_REMOVAL_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Canonical tag form: trimmed, empties dropped, deduplicated
/// case-insensitively (first spelling wins), sorted. Sorting is what makes
/// the merged output byte-identical no matter which side was local and which
/// was server.
pub fn normalize_tags<I: IntoIterator<Item = String>>(tags: I) -> Vec<String> {
    // Keyed by the lowercase spelling so "Work" and "work" cannot coexist;
    // `BTreeMap` yields values in key order, which is the canonical order.
    let mut by_key: std::collections::BTreeMap<String, String> = Default::default();
    for tag in tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() {
            continue;
        }
        by_key
            .entry(trimmed.to_lowercase())
            .or_insert_with(|| trimmed.to_string());
    }
    by_key.into_values().collect()
}

/// Collapses removal records: deduplicated per key keeping the *newest*
/// removal, expired ones dropped. Order of the output is the sorted key
/// order, so it is deterministic.
pub fn normalize_tag_removals(
    removals: impl IntoIterator<Item = TagRemoval>,
    now_ms: i64,
) -> Vec<TagRemoval> {
    let mut by_key: std::collections::BTreeMap<String, i64> = Default::default();
    for removal in removals {
        if removal.deleted_at_ms > now_ms.saturating_sub(TAG_REMOVAL_RETENTION_MS) {
            by_key
                .entry(removal.tag)
                .and_modify(|newest| {
                    if removal.deleted_at_ms > *newest {
                        *newest = removal.deleted_at_ms;
                    }
                })
                .or_insert(removal.deleted_at_ms);
        }
    }
    by_key
        .into_iter()
        .map(|(tag, deleted_at_ms)| TagRemoval { tag, deleted_at_ms })
        .collect()
}

/// Observations when two versions of one item meet during a merge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrgMergeFacts {
    pub local_tags: Vec<String>,
    pub server_tags: Vec<String>,
    pub local_folder: Option<String>,
    pub server_folder: Option<String>,
    /// Is the server copy at least as new as the local one (`updated_at`)?
    /// Ties resolve to the server, like the rest of the merge.
    pub server_updated_at_newer: bool,
    /// Unix-millisecond `updated_at` of each copy: a removal record only
    /// suppresses a tag on copies that have not been edited since the
    /// removal. An edit of a copy that still carries the tag counts as
    /// re-affirming it — the same whole-item reasoning every other field
    /// gets.
    pub local_updated_at_ms: i64,
    pub server_updated_at_ms: i64,
    /// Removal records each copy carries (see [`TagRemoval`]).
    pub local_tag_removals: Vec<TagRemoval>,
    pub server_tag_removals: Vec<TagRemoval>,
    /// Now, for removal-record retention.
    pub now_ms: i64,
}

/// The organizational metadata an item carries after a merge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrgMergeOutcome {
    pub tags: Vec<String>,
    pub folder: Option<String>,
    /// The merged removal records (newest per key, expired dropped). Kept
    /// even for tags that survived: a stale third copy that still carries
    /// the tag must still lose it on its next merge.
    pub tag_removals: Vec<TagRemoval>,
}

/// The spec `merge_org_fields` is held to, stated so the implementation and
/// the property can be checked against each other (same pattern as
/// [`merge_action_matches_spec`]).
pub fn org_merge_matches_spec(facts: OrgMergeFacts, outcome: &OrgMergeOutcome) -> bool {
    let expected = merge_org_fields(facts);
    *outcome == expected
}

#[cfg_attr(hax, hax_lib::ensures(|outcome| {
    org_merge_matches_spec(facts, &outcome)
}))]
pub fn merge_org_fields(facts: OrgMergeFacts) -> OrgMergeOutcome {
    let removals = normalize_tag_removals(
        facts.local_tag_removals.into_iter().chain(facts.server_tag_removals),
        facts.now_ms,
    );

    let mut by_key: std::collections::BTreeMap<String, String> = Default::default();
    let mut add_all = |tags: &[String]| {
        for tag in tags {
            let trimmed = tag.trim();
            if trimmed.is_empty() {
                continue;
            }
            by_key
                .entry(trimmed.to_lowercase())
                .or_insert_with(|| trimmed.to_string());
        }
    };
    add_all(&facts.local_tags);
    add_all(&facts.server_tags);

    let local_updated = facts.local_updated_at_ms;
    let server_updated = facts.server_updated_at_ms;
    let tags: Vec<String> = by_key
        .into_iter()
        .filter(|(key, _)| match removals.iter().find(|r| &r.tag == key) {
            // A removal record wins against any copy that has not been
            // edited since the removal; the newest edit of a copy that
            // still carries the tag beats the removal (re-affirmation).
            Some(removal) => {
                let mut carriers: Vec<i64> = Vec::with_capacity(2);
                if facts.local_tags.iter().any(|t| t.trim().to_lowercase() == *key) {
                    carriers.push(local_updated);
                }
                if facts.server_tags.iter().any(|t| t.trim().to_lowercase() == *key) {
                    carriers.push(server_updated);
                }
                match carriers.iter().min() {
                    Some(oldest_carrier) => removal.deleted_at_ms < *oldest_carrier,
                    None => false,
                }
            }
            None => true,
        })
        .map(|(_, spelling)| spelling)
        .collect();

    OrgMergeOutcome {
        tags,
        folder: if facts.server_updated_at_newer {
            facts.server_folder
        } else {
            facts.local_folder
        }
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty()),
        tag_removals: removals,
    }
}

/// Witness: a tag added offline survives the server's newer copy arriving —
/// the additive edit that whole-item last-writer-wins would have lost.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn local_tag_is_lost_to_a_newer_server_copy(tag: String) -> bool {
    let outcome = merge_org_fields(OrgMergeFacts {
        local_tags: vec![tag.clone()],
        server_tags: Vec::new(),
        local_folder: None,
        server_folder: None,
        server_updated_at_newer: true,
        local_updated_at_ms: 1_000,
        server_updated_at_ms: 2_000,
        local_tag_removals: Vec::new(),
        server_tag_removals: Vec::new(),
        now_ms: 3_000,
    });
    !outcome.tags.contains(&tag)
}

/// Witness: the folder obeys last-writer-wins. A newer server copy that names
/// folder B is never answered with the local folder A.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn folder_disobeys_last_writer_wins() -> bool {
    let outcome = merge_org_fields(OrgMergeFacts {
        local_tags: Vec::new(),
        server_tags: Vec::new(),
        local_folder: Some("Personal".to_string()),
        server_folder: Some("Work".to_string()),
        server_updated_at_newer: true,
        local_updated_at_ms: 1_000,
        server_updated_at_ms: 2_000,
        local_tag_removals: Vec::new(),
        server_tag_removals: Vec::new(),
        now_ms: 3_000,
    });
    outcome.folder.as_deref() != Some("Work")
}

/// Witness: a recorded removal beats a stale copy that still carries the tag
/// — union alone would resurrect it on every merge.
#[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
pub fn a_removed_tag_is_resurrected_by_a_stale_copy() -> bool {
    let outcome = merge_org_fields(OrgMergeFacts {
        // Local removed the tag (its copy no longer carries it); the server
        // copy is older and still has it.
        local_tags: Vec::new(),
        server_tags: vec!["work".to_string()],
        local_folder: None,
        server_folder: None,
        server_updated_at_newer: false,
        local_updated_at_ms: 2_000,
        server_updated_at_ms: 1_000,
        local_tag_removals: vec![TagRemoval { tag: "work".into(), deleted_at_ms: 2_000 }],
        server_tag_removals: Vec::new(),
        now_ms: 3_000,
    });
    outcome.tags.contains(&"work".to_string())
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
    fn org_merge_unions_tags_and_keeps_the_newer_folder() {
        // Both sides tag offline; the union keeps both, canonically ordered.
        let outcome = merge_org_fields(OrgMergeFacts {
            local_tags: vec!["work".into(), " VPN ".into()],
            server_tags: vec!["Work".into(), "banking".into()],
            local_folder: Some("Personal".into()),
            server_folder: Some("Work".into()),
            server_updated_at_newer: true,
            local_updated_at_ms: 1_000,
            server_updated_at_ms: 2_000,
            local_tag_removals: Vec::new(),
            server_tag_removals: Vec::new(),
            now_ms: 3_000,
        });
        assert_eq!(outcome.tags, vec!["banking", "VPN", "work"]);
        assert_eq!(outcome.folder.as_deref(), Some("Work"));

        // A local edit that is the newest wins the folder back.
        let outcome = merge_org_fields(OrgMergeFacts {
            local_tags: Vec::new(),
            server_tags: Vec::new(),
            local_folder: Some("Personal".into()),
            server_folder: Some("Work".into()),
            server_updated_at_newer: false,
            local_updated_at_ms: 2_000,
            server_updated_at_ms: 1_000,
            local_tag_removals: Vec::new(),
            server_tag_removals: Vec::new(),
            now_ms: 3_000,
        });
        assert_eq!(outcome.folder.as_deref(), Some("Personal"));

        // And the spec function agrees with the implementation everywhere.
        let facts = OrgMergeFacts {
            local_tags: vec!["a".into()],
            server_tags: vec!["b".into()],
            local_folder: None,
            server_folder: Some("F".into()),
            server_updated_at_newer: true,
            local_updated_at_ms: 1_000,
            server_updated_at_ms: 2_000,
            local_tag_removals: Vec::new(),
            server_tag_removals: Vec::new(),
            now_ms: 3_000,
        };
        assert!(org_merge_matches_spec(facts.clone(), &merge_org_fields(facts)));
    }

    #[test]
    fn org_merge_is_symmetric_in_the_sides() {
        // The canonical order exists so that which device was "local" during
        // the merge does not change the merged tags.
        let a = merge_org_fields(OrgMergeFacts {
            local_tags: vec!["B".into(), "a".into()],
            server_tags: vec!["C".into()],
            local_folder: None,
            server_folder: None,
            server_updated_at_newer: true,
            local_updated_at_ms: 1_000,
            server_updated_at_ms: 2_000,
            local_tag_removals: Vec::new(),
            server_tag_removals: Vec::new(),
            now_ms: 3_000,
        });
        let b = merge_org_fields(OrgMergeFacts {
            local_tags: vec!["C".into()],
            server_tags: vec!["a".into(), "B".into()],
            local_folder: None,
            server_folder: None,
            server_updated_at_newer: true,
            local_updated_at_ms: 2_000,
            server_updated_at_ms: 1_000,
            local_tag_removals: Vec::new(),
            server_tag_removals: Vec::new(),
            now_ms: 3_000,
        });
        assert_eq!(a.tags, b.tags);
        assert_eq!(a.tags, vec!["a", "B", "C"]);
    }

    #[test]
    fn a_removal_beats_stale_copies_but_not_newer_edits() {
        // This device removed "work" at 2_000 (its copy carries the removal
        // record); the server copy is older (1_000) and still has the tag.
        // The removal must win — plain union resurrected it forever.
        let outcome = merge_org_fields(OrgMergeFacts {
            local_tags: Vec::new(),
            server_tags: vec!["work".into()],
            local_folder: None,
            server_folder: None,
            server_updated_at_newer: false,
            local_updated_at_ms: 2_000,
            server_updated_at_ms: 1_000,
            local_tag_removals: vec![TagRemoval { tag: "work".into(), deleted_at_ms: 2_000 }],
            server_tag_removals: Vec::new(),
            now_ms: 3_000,
        });
        assert!(!outcome.tags.contains(&"work".to_string()));
        // The record is kept even though the tag is gone: a third stale copy
        // that still carries the tag must lose it on ITS next merge.
        assert_eq!(outcome.tag_removals.len(), 1);

        // The other direction: the other device edited the item AFTER the
        // removal (2_500 > 2_000) and still carries the tag — an edit
        // affirms the tags its copy carries, so the tag survives.
        let outcome = merge_org_fields(OrgMergeFacts {
            local_tags: Vec::new(),
            server_tags: vec!["work".into()],
            local_folder: None,
            server_folder: None,
            server_updated_at_newer: true,
            local_updated_at_ms: 2_000,
            server_updated_at_ms: 2_500,
            local_tag_removals: vec![TagRemoval { tag: "work".into(), deleted_at_ms: 2_000 }],
            server_tag_removals: Vec::new(),
            now_ms: 3_000,
        });
        assert!(outcome.tags.contains(&"work".to_string()));
        // The stale removal record is retained until it expires: copies that
        // have not edited since the removal must still lose the tag.
        assert_eq!(outcome.tag_removals.len(), 1);
    }

    #[test]
    fn expired_removals_stop_suppressing() {
        // The removal is older than the retention window: it no longer
        // suppresses anything, and it does not come back in the output.
        let outcome = merge_org_fields(OrgMergeFacts {
            local_tags: Vec::new(),
            server_tags: vec!["work".into()],
            local_folder: None,
            server_folder: None,
            server_updated_at_newer: false,
            local_updated_at_ms: 2_000,
            server_updated_at_ms: 1_000,
            local_tag_removals: vec![TagRemoval {
                tag: "work".into(),
                deleted_at_ms: 2_000,
            }],
            server_tag_removals: Vec::new(),
            now_ms: 2_000 + TAG_REMOVAL_RETENTION_MS + 1,
        });
        assert_eq!(outcome.tags, vec!["work"]);
        assert!(outcome.tag_removals.is_empty());
    }

    #[test]
    fn witnesses_hold_for_the_org_merge() {
        assert!(!local_tag_is_lost_to_a_newer_server_copy("banking".to_string()));
        assert!(!folder_disobeys_last_writer_wins());
        assert!(!a_removed_tag_is_resurrected_by_a_stale_copy());
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
