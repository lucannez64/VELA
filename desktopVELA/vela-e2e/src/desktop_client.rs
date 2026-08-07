//! Thin driver around the real `vela-desktop-core` production code, so the
//! E2E exercises the actual account-registration, sync, and device-enrollment
//! paths rather than a reimplementation.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use tempfile::TempDir;
use vela_desktop_core::api::{ApiClient, RegisterRequest};
use vela_desktop_core::commands::devices::generate_enrollment_code;
use vela_desktop_core::crypto;
use vela_desktop_core::sync::trigger_sync;
use vela_desktop_core::vault::{VaultItem, VaultMeta};
use vela_desktop_core::AppState;

pub struct DesktopClient {
    pub state: AppState,
    pub device_id: String,
    pub user_id: String,
    _dir: TempDir,
}

impl DesktopClient {
    /// Create a brand-new account: unlock a hermetic store, register the
    /// device against the server, persist the identity keys.
    pub async fn new(rms: [u8; 32], server_url: &str) -> Result<Self, String> {
        let dir = TempDir::new().map_err(|e| format!("tempdir: {e}"))?;
        let state = AppState::for_test(dir.path());
        *state.server_url.write() = server_url.to_string();
        state.unlock_for_test(&rms);

        let identity = crypto::generate_identity_keypair()?;
        let client = ApiClient::with_url(server_url.to_string());
        let resp = client
            .register_account(&RegisterRequest {
                hybrid_ek: B64.encode(&identity.hybrid_ek),
                hybrid_vk: B64.encode(&identity.hybrid_vk),
                device_name: Some("Desktop E2E".to_string()),
                device_type: Some("desktop".to_string()),
                share_ek: Some(B64.encode(&identity.share_ek)),
            })
            .await
            .map_err(|e| format!("register account: {e}"))?;

        {
            let crypto_obj = crypto::Crypto::new(&rms);
            state
                .store
                .save_identity_keys_full(
                    &vela_desktop_core::store::IdentityKeysStore {
                        hybrid_ek: identity.hybrid_ek.clone(),
                        hybrid_dk: identity.hybrid_dk.clone(),
                        hybrid_vk: identity.hybrid_vk.clone(),
                        hybrid_sk: identity.hybrid_sk.clone(),
                        share_ek: identity.share_ek.clone(),
                        share_dk: identity.share_dk.clone(),
                    },
                    &crypto_obj,
                )
                .map_err(|e| format!("save identity keys: {e}"))?;
        }
        state
            .store
            .save_device_id_with_user_id(&resp.device_id, &resp.user_id)
            .map_err(|e| format!("save device id: {e}"))?;
        {
            let mut session = state.session.write();
            session.device_id = Some(resp.device_id.clone());
            session.user_id = Some(resp.user_id.clone());
        }

        Ok(Self { state, device_id: resp.device_id, user_id: resp.user_id, _dir: dir })
    }

    pub fn add_login(&self, id: &str, name: &str, url: &str, username: &str, password: &str) {
        let meta = VaultMeta {
            id: id.to_string(),
            name: name.to_string(),
            notes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_modified_device: Some(self.device_id.clone()),
            favorite: false,
            shared: false,
            share_recipient: None,
        };
        self.state.vault.write().add_item(VaultItem::Login {
            meta,
            url: url.to_string(),
            username: username.to_string(),
            pass: password.to_string(),
            totp: None,
            app_ids: Vec::new(),
            credential_change_needs_reauth: false,
        });
    }

    pub fn delete_item(&self, id: &str) {
        self.state.vault.write().delete_item(id, Some(&self.device_id));
    }

    /// Rewrite `updated_at` (used to stage a concurrent-edit scenario).
    pub fn set_item_updated_at(&self, id: &str, ts: chrono::DateTime<chrono::Utc>) {
        let mut vault = self.state.vault.write();
        if let Some(item) = vault.items.iter_mut().find(|i| i.id() == id) {
            let updated = item.clone().with_updated_at(ts);
            *item = updated;
        }
    }

    pub async fn sync(&self) -> Result<vela_desktop_core::sync::SyncStatus, String> {
        trigger_sync(&self.state).await
    }

    /// Enroll a second device, returning a `VELA-ENROLL:v2:` code for it.
    pub async fn enrollment_code(&self) -> Result<String, String> {
        generate_enrollment_code(&self.state).await
    }

    /// Open an enrollment v3 grant, returning the code to show as a QR.
    ///
    /// Nothing is created on the account here: unlike v2, no keypair is
    /// generated and no device row exists until a fingerprint is confirmed.
    pub async fn open_enrollment_invite(
        &self,
    ) -> Result<vela_desktop_core::commands::enrollment_v3::EnrollmentInvite, String> {
        vela_desktop_core::commands::enrollment_v3::open_enrollment_invite(&self.state).await
    }

    /// Poll for the joining device's claim. `None` until one arrives.
    pub async fn poll_enrollment_claim(
        &self,
        grant_id: &str,
    ) -> Result<Option<vela_desktop_core::commands::enrollment_v3::ClaimedDevice>, String> {
        vela_desktop_core::commands::enrollment_v3::poll_enrollment_claim(&self.state, grant_id)
            .await
    }

    /// Answer the fingerprint question with `chosen`, as the user would.
    ///
    /// A wrong value does not merely fail: it discards the pending enrollment,
    /// which is what stops an n-way choice from becoming a 1-in-1 by repetition.
    pub async fn confirm_enrollment(
        &self,
        grant_id: &str,
        chosen: &str,
    ) -> Result<String, String> {
        vela_desktop_core::commands::enrollment_v3::confirm_enrollment(
            &self.state,
            grant_id,
            chosen,
        )
        .await
    }

    pub fn item_ids(&self) -> Vec<String> {
        self.state.vault.read().items.iter().map(|i| i.id().to_string()).collect()
    }

    pub fn item_names(&self) -> Vec<String> {
        self.state.vault.read().items.iter().map(|i| i.name().to_string()).collect()
    }

    pub fn find_item(&self, id: &str) -> Option<VaultItem> {
        self.state.vault.read().items.iter().find(|i| i.id() == id).cloned()
    }
}
