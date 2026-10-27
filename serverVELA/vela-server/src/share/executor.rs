//! The async executor shape every sharing handler passes to
//! `share_interpreter!`.
//!
//! The policy crate's `ShareIo` trait is synchronous because hax extracts
//! `run_share`; the server's handlers are async. This trait mirrors the same
//! eight methods with `.await` available, and gives every method a default body
//! so a handler implements only the effects its request kind can reach. The
//! driver never emits an effect outside that request kind, so a default body is
//! unreachable; the integration and model tests exercise every reachable
//! effect.

use vela_share_policy::driver::{
    CleanupObservation, EkDeviceObservation, InboxDeletePermit, LinkUpdatePermit, RowsObservation,
    SendInsertPermit, SendResultObservation,
};
use vela_share_policy::{EkRegistrationPermit, LinkMutationObservation};

pub trait ShareExecutor {
    async fn observe_link(&mut self) -> LinkMutationObservation {
        unreachable!("sharing request cannot reach this effect")
    }
    async fn observe_device(&mut self) -> EkDeviceObservation {
        unreachable!("sharing request cannot reach this effect")
    }
    async fn insert_capsule(&mut self, _permit: SendInsertPermit) -> SendResultObservation {
        unreachable!("sharing request cannot reach this effect")
    }
    async fn update_linked_item(&mut self, _permit: LinkUpdatePermit) -> RowsObservation {
        unreachable!("sharing request cannot reach this effect")
    }
    async fn revoke_linked_item(&mut self) -> RowsObservation {
        unreachable!("sharing request cannot reach this effect")
    }
    async fn delete_linked_inbox(&mut self) -> CleanupObservation {
        unreachable!("sharing request cannot reach this effect")
    }
    async fn delete_inbox_item(&mut self, _permit: InboxDeletePermit) -> RowsObservation {
        unreachable!("sharing request cannot reach this effect")
    }
    async fn update_share_ek(&mut self, _permit: EkRegistrationPermit) -> RowsObservation {
        unreachable!("sharing request cannot reach this effect")
    }
}
