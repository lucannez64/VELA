//! The async executor shape every device-pairing handler passes to
//! `pairing_interpreter!`.
//!
//! The policy crate's `PairingIo` trait is synchronous because hax extracts
//! `run_pairing`; the server's handlers are async. This trait mirrors the same
//! twelve methods with `.await` available, and gives every method a default
//! body so a handler implements only the effects its ceremony can reach. The
//! driver should never emit an effect outside that ceremony; if it ever did,
//! the default reports a missing, refused or failed observation so the request
//! fails closed instead of panicking.

use vela_enrollment_policy::pairing_driver::{
    ClaimMaterialObservation, ClaimReadObservation, ClaimWriteObservation,
    CompletionAccountObservation, OpenerObservation, SignatureObservation,
    CompletionPreflightObservation, DeviceInsertObservation, RedeemObservation,
    ResultReadObservation, StoreObservation, TakeObservation,
};
use vela_enrollment_policy::ClaimObservation;

pub trait PairingExecutor {
    async fn store_package(&mut self) -> StoreObservation {
        StoreObservation::Failed
    }
    async fn redeem_package(&mut self) -> RedeemObservation {
        RedeemObservation::Missing
    }
    async fn store_grant(&mut self) -> StoreObservation {
        StoreObservation::Failed
    }
    async fn check_claim(&mut self) -> ClaimObservation {
        ClaimObservation { grant_live: false, claim_exists: false, hybrid_ek_len: 0, hybrid_vk_len: 0 }
    }
    async fn write_claim(&mut self) -> ClaimWriteObservation {
        ClaimWriteObservation::GuardMissing
    }
    async fn check_account(&mut self) -> CompletionAccountObservation {
        CompletionAccountObservation { account_query_ok: false, declared_epoch_positive: false, rekey_permitted: false }
    }
    async fn prepare_completion(&mut self) -> CompletionPreflightObservation {
        CompletionPreflightObservation {
            claim: ClaimMaterialObservation::Error,
            capsule_valid: false,
            signature_field_valid: false,
            opener: OpenerObservation::Error,
            signature: SignatureObservation::Failed,
            account_epoch: 0,
            declared_epoch: 0,
            rotation_in_progress: true,
            account_epoch_active: false,
        }
    }
    async fn take_ceremony(&mut self) -> TakeObservation {
        TakeObservation::Missing
    }
    async fn insert_device(&mut self) -> DeviceInsertObservation {
        DeviceInsertObservation::Failed
    }
    async fn write_result(&mut self) -> StoreObservation {
        StoreObservation::Failed
    }
    async fn read_result(&mut self) -> ResultReadObservation {
        ResultReadObservation::Unreadable
    }
    async fn read_claim(&mut self) -> ClaimReadObservation {
        ClaimReadObservation::Unreadable
    }
}
