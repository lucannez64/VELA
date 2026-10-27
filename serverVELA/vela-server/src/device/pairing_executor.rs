//! The async executor shape every device-pairing handler passes to
//! `pairing_interpreter!`.
//!
//! The policy crate's `PairingIo` trait is synchronous because hax extracts
//! `run_pairing`; the server's handlers are async. This trait mirrors the same
//! twelve methods with `.await` available, and gives every method a default
//! body so a handler implements only the effects its ceremony can reach. The
//! driver never emits an effect outside that ceremony, so a default body is
//! unreachable; the integration tests exercise every reachable effect.

use vela_enrollment_policy::pairing_driver::{
    ClaimReadObservation, ClaimWriteObservation, CompletionAccountObservation,
    CompletionPreflightObservation, DeviceInsertObservation, RedeemObservation,
    ResultReadObservation, StoreObservation, TakeObservation,
};
use vela_enrollment_policy::ClaimObservation;

pub trait PairingExecutor {
    async fn store_package(&mut self) -> StoreObservation {
        unreachable!("package store handler cannot reach this pairing effect")
    }
    async fn redeem_package(&mut self) -> RedeemObservation {
        unreachable!("package fetch handler cannot reach this pairing effect")
    }
    async fn store_grant(&mut self) -> StoreObservation {
        unreachable!("grant-open handler cannot reach this pairing effect")
    }
    async fn check_claim(&mut self) -> ClaimObservation {
        unreachable!("claim handler cannot reach this pairing effect")
    }
    async fn write_claim(&mut self) -> ClaimWriteObservation {
        unreachable!("claim handler cannot reach this pairing effect")
    }
    async fn check_account(&mut self) -> CompletionAccountObservation {
        unreachable!("completion handler cannot reach this pairing effect")
    }
    async fn prepare_completion(&mut self) -> CompletionPreflightObservation {
        unreachable!("completion handler cannot reach this pairing effect")
    }
    async fn take_ceremony(&mut self) -> TakeObservation {
        unreachable!("completion handler cannot reach this pairing effect")
    }
    async fn insert_device(&mut self) -> DeviceInsertObservation {
        unreachable!("completion handler cannot reach this pairing effect")
    }
    async fn write_result(&mut self) -> StoreObservation {
        unreachable!("completion handler cannot reach this pairing effect")
    }
    async fn read_result(&mut self) -> ResultReadObservation {
        unreachable!("result handler cannot reach this pairing effect")
    }
    async fn read_claim(&mut self) -> ClaimReadObservation {
        unreachable!("result handler cannot reach this pairing effect")
    }
}
