//! The async executor shape every sharing handler passes to
//! `share_interpreter!`.
//!
//! The policy crate's `ShareIo` trait is synchronous because hax extracts
//! `run_share`; the server's handlers are async. This trait mirrors the same
//! eight methods with `.await` available, and gives every method a default body
//! so a handler implements only the effects its request kind can reach. The
//! driver should never emit an effect outside that request kind; if it ever
//! did, the default reports a refusal or storage failure so the request fails
//! closed instead of panicking.

use vela_share_policy::driver::{
    CleanupObservation, EkDeviceObservation, InboxDeletePermit, LinkUpdatePermit, RowsObservation,
    SendInsertPermit, SendResultObservation,
};
use vela_share_policy::{EkRegistrationPermit, LinkMutationObservation};

pub trait ShareExecutor {
    async fn observe_link(&mut self) -> LinkMutationObservation {
        LinkMutationObservation { item_present: false, caller_matches_sender: false, item_not_revoked: false }
    }
    async fn observe_device(&mut self) -> EkDeviceObservation {
        EkDeviceObservation {
            registration: vela_share_policy::EkRegistrationObservation {
                ek_len: 0,
                signature_verified: false,
                device_row_present: false,
                device_user_matches: false,
                device_active: false,
                signed_at_is_fresher: false,
                binding_exists: false,
            },
            stored_identity_vk_decode_failed: true,
            signature_decode_failed: true,
        }
    }
    async fn insert_capsule(&mut self, _permit: SendInsertPermit) -> SendResultObservation {
        SendResultObservation::StorageFailed
    }
    async fn update_linked_item(&mut self, _permit: LinkUpdatePermit) -> RowsObservation {
        RowsObservation { rows: 0 }
    }
    async fn revoke_linked_item(&mut self) -> RowsObservation {
        RowsObservation { rows: 0 }
    }
    async fn delete_linked_inbox(&mut self) -> CleanupObservation {
        CleanupObservation { storage_failed: true }
    }
    async fn delete_inbox_item(&mut self, _permit: InboxDeletePermit) -> RowsObservation {
        RowsObservation { rows: 0 }
    }
    async fn update_share_ek(&mut self, _permit: EkRegistrationPermit) -> RowsObservation {
        RowsObservation { rows: 0 }
    }
}
