//! Safe wrappers around `vela_client_share_policy` with the scalar-only
//! signatures the Kush bridge ABI supports.
use vela_client_share_policy::{
    initial_acceptance_is_authorized, next_store_generation, plan_share_admission,
    recovery_should_apply, ShareAdmissionDecision, ShareAdmissionFacts,
};

#[allow(clippy::too_many_arguments)]
fn decide(
    auth: bool,
    addr: bool,
    sender: bool,
    has_pin: bool,
    signer: bool,
    lineage: bool,
    pinned: u64,
    cand: u64,
) -> ShareAdmissionDecision {
    plan_share_admission(ShareAdmissionFacts {
        envelope_authenticated: auth,
        addressed_to_recipient: addr,
        sender_matches_attribution: sender,
        has_pin,
        signer_matches_pin: signer,
        lineage_matches_pin: lineage,
        pinned_revision: pinned,
        candidate_revision: cand,
    })
}

/// 0 = reject, 1 = first contact, 2 = update.
#[allow(clippy::too_many_arguments)]
pub fn plan_code(
    auth: bool,
    addr: bool,
    sender: bool,
    has_pin: bool,
    signer: bool,
    lineage: bool,
    pinned: u64,
    cand: u64,
) -> i64 {
    match decide(auth, addr, sender, has_pin, signer, lineage, pinned, cand) {
        ShareAdmissionDecision::Reject => 0,
        ShareAdmissionDecision::AcceptFirstContact(_) => 1,
        ShareAdmissionDecision::ApplyUpdate(_) => 2,
    }
}

/// The permit revision, or -1 for a rejection. Tests only pass revisions
/// that fit in `i64`.
#[allow(clippy::too_many_arguments)]
pub fn plan_revision(
    auth: bool,
    addr: bool,
    sender: bool,
    has_pin: bool,
    signer: bool,
    lineage: bool,
    pinned: u64,
    cand: u64,
) -> i64 {
    match decide(auth, addr, sender, has_pin, signer, lineage, pinned, cand) {
        ShareAdmissionDecision::Reject => -1,
        ShareAdmissionDecision::AcceptFirstContact(permit)
        | ShareAdmissionDecision::ApplyUpdate(permit) => permit.revision() as i64,
    }
}

/// The next generation, or -1 for `None`.
pub fn next_generation(current: u64, snapshot: u64, pending: bool) -> i64 {
    match next_store_generation(current, snapshot, pending) {
        Some(next) => next as i64,
        None => -1,
    }
}

pub fn recovery(matches_before: bool, current_present: bool, tombstoned: bool) -> bool {
    recovery_should_apply(matches_before, current_present, tombstoned)
}

pub fn acceptance(accepted: bool, has_pin: bool, has_payload: bool) -> bool {
    initial_acceptance_is_authorized(accepted, has_pin, has_payload)
}

/// The benchmark loop of `src/main.kush`, in Rust: the same input
/// generator and checksum, so both sides do the same work.
pub fn bench(iterations: i64) -> i64 {
    let mut checksum: i64 = 0;
    for i in 0..iterations {
        let x = (i * 2654435761) % 4294967296;
        let bit = |k: i64| (x >> k) & 1 == 1;
        let pinned = ((x >> 6) & 7) as u64;
        let cand = ((x >> 9) & 7) as u64;
        let decision = decide(bit(0), bit(1), bit(2), bit(3), bit(4), bit(5), pinned, cand);
        let (code, revision) = match decision {
            ShareAdmissionDecision::Reject => (0, -1),
            ShareAdmissionDecision::AcceptFirstContact(p) => (1, p.revision() as i64),
            ShareAdmissionDecision::ApplyUpdate(p) => (2, p.revision() as i64),
        };
        checksum = (checksum + code * 8 + revision) % 1000000007;
    }
    checksum
}
