//! Explicit extension editor operations. Content scripts never call this route;
//! plaintext reads and mutations also require approval in the native window.
use std::sync::Arc;
use serde_json::{json, Value};
use crate::{host::Host, ipc_peer::PeerIdentity, vault::{ItemType, VaultItem}};

fn unlocked(host: &dyn Host) -> Result<(), String> {
    crate::commands::vault::require_unlocked(host.state())?;
    let session = host.state().session.read();
    if !session.active || session.is_expired() { return Err("Unlock the vault first".into()); }
    Ok(())
}

pub async fn handle(host: &Arc<dyn Host>, peer: &PeerIdentity, request: &Value) -> Result<Value, String> {
    if peer.exe.as_deref().is_some_and(crate::ipc_gate::is_provider) {
        return Err("The credential provider cannot manage vault items".into());
    }
    unlocked(host.as_ref())?;
    let op = request["operation"].as_str().ok_or("Missing editor operation")?;
    if op == "list" {
        let items = crate::commands::vault::get_items(host.state())?;
        let metadata: Vec<Value> = items.iter().map(metadata).collect();
        return Ok(json!({"items": metadata, "collections": crate::commands::organization::get_organization(host.state())?}));
    }
    let action = match op {
        "read" => "Read this item's credentials in the extension editor",
        "create" => "Create a vault item from the extension editor",
        "update" => "Save changes from the extension editor",
        "delete" => "Delete this vault item from the extension editor",
        "activate" => "Enable folders and richer fields for this vault",
        "mutate" => "Change folders or tags from the extension editor",
        "assign" => "Move or tag the selected vault items",
        _ => return Err("Unknown editor operation".into()),
    };
    // The caption and body describe this action, rather than borrowing a
    // passkey prompt. No credential values are interpolated into the dialog.
    let target = if matches!(op, "read" | "delete" | "update") {
        let id = if op == "update" { request["item"]["id"].as_str() } else { request["id"].as_str() }.ok_or("Choose an item")?;
        let item = crate::commands::vault::get_item(host.state(), id)?.ok_or("Item no longer exists")?;
        let name: String = item.meta().name.chars().filter(|c| !c.is_control()).take(80).collect();
        format!("\nItem: {name} ({id})")
    } else { String::new() };
    let prompt = format!("{action}?{target}\nRequested by {}.", peer.describe());
    let approval_host = host.clone();
    let approved = tokio::task::spawn_blocking(move || approval_host.confirm_presence("VELA — extension editor", &prompt))
        .await.map_err(|_| "Approval unavailable")?;
    if approved != Some(true) { return Err("Editor action was not approved".into()); }
    unlocked(host.as_ref())?;
    let state = host.state();
    let id = || request["id"].as_str().filter(|id| !id.is_empty() && id.len() <= 256).ok_or("Choose an item");
    let result = match op {
        "read" => {
            let item = crate::commands::vault::get_item(state, id()?)?.ok_or("Item no longer exists")?;
            let mut value = serde_json::to_value(&item).map_err(|_| "Cannot read this item")?;
            if let Some(object) = value.as_object_mut() { object.remove("private_key"); }
            state.try_record_credential_release(&format!("extension-editor:{}", item.id()))?;
            crate::audit::record_audit_event_checked(state, crate::audit::AuditAction::CredentialReleased {
                caller: peer.describe(), domain: "extension editor (explicit item approval)".into(),
            }).map_err(|_| "Cannot update the activity log")?;
            return Ok(json!({"item": value, "readOnly": item.is_received_share()}));
        }
        "activate" => serde_json::to_value(crate::commands::organization::activate_rich_items(state).await?).map_err(|_| "Cannot read collections")?,
        "mutate" => {
            let action = serde_json::from_value(request["action"].clone()).map_err(|_| "Invalid collection change")?;
            serde_json::to_value(crate::commands::organization::mutate_organization(state, action)?).map_err(|_| "Cannot read collections")?
        }
        "assign" => {
            let changes = serde_json::from_value(request["changes"].clone()).map_err(|_| "Invalid item selection")?;
            crate::commands::organization::assign_items(state, changes)?;
            json!({"ok": true})
        }
        "create" | "update" => {
            let item: VaultItem = serde_json::from_value(request["item"].clone()).map_err(|_| "Invalid item fields")?;
            if !matches!(item.item_type(), ItemType::Login | ItemType::CreditCard | ItemType::SecureNote | ItemType::Identity) {
                return Err("Use the desktop editor for this item type".into());
            }
            if op == "update" {
                let old = crate::commands::vault::get_item(state, item.id())?.ok_or("Item no longer exists")?;
                if old.item_type() != item.item_type() { return Err("Item type cannot change".into()); }
                crate::commands::vault::update_item(state, item).await?;
            } else {
                if crate::commands::vault::get_item(state, item.id())?.is_some() { return Err("Item already exists".into()); }
                crate::commands::vault::add_item(state, item).await?;
            }
            json!({"ok": true})
        }
        "delete" => { crate::commands::vault::delete_item(state, id()?).await?; json!({"ok": true}) }
        _ => unreachable!(),
    };
    host.notify_vault_items_changed();
    Ok(result)
}

fn metadata(item: &VaultItem) -> Value {
    // An allowlist prevents future concealed fields from entering list responses.
    let meta = item.meta();
    json!({"id": item.id(), "name": meta.name, "kind": item.item_type(),
        "folderId": meta.rich.folder_id, "tagIds": meta.rich.tag_ids,
        "readOnly": item.is_received_share()})
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestHost { state: Arc<crate::AppState>, approve: bool }
    impl Host for TestHost {
        fn state(&self) -> &Arc<crate::AppState> { &self.state }
        fn focus_main_window(&self) {}
        fn app_identifier(&self) -> String { "test".into() }
        fn open_quick_search(&self) {}
        fn notify_vault_items_changed(&self) {}
        fn show_toast(&self, _: &str) {}
        fn confirm_presence(&self, _: &str, _: &str) -> Option<bool> { Some(self.approve) }
    }
    fn setup(approve: bool) -> (tempfile::TempDir, Arc<dyn Host>) {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(crate::AppState::for_test(dir.path()));
        state.unlock_for_test(&crate::crypto::Crypto::generate_rms());
        (dir, Arc::new(TestHost { state, approve }))
    }
    fn login() -> VaultItem {
        serde_json::from_value(json!({"item_type":"login","id":"one","name":"Example","url":"https://example.test","username":"user","password":"secret","customFields":[{"id":"07bca7a1-371a-42fb-9074-818d04d034b4","label":"PIN","type":"concealed","value":"hidden"}]})).unwrap()
    }
    #[tokio::test]
    async fn list_is_metadata_only_and_read_requires_native_approval() {
        let (_dir, host) = setup(false);
        host.state().vault.write().add_item(login());
        let list = handle(&host, &PeerIdentity::default(), &json!({"operation":"list"})).await.unwrap();
        assert_eq!(list["items"][0]["name"], "Example");
        assert!(!list.to_string().contains("secret"));
        assert!(!list.to_string().contains("hidden"));
        assert!(handle(&host, &PeerIdentity::default(), &json!({"operation":"read","id":"one"})).await.is_err());
        assert!(handle(&host, &PeerIdentity::default(), &json!({"operation":"delete","id":"one"})).await.is_err());
        assert!(host.state().vault.read().get_item("one").is_some());
    }
    #[tokio::test]
    async fn locked_and_provider_requests_are_rejected() {
        let (_dir, host) = setup(true);
        let peer = PeerIdentity { exe: Some(std::path::PathBuf::from(crate::ipc_gate::PROVIDER_BINARY_NAME)), ..Default::default() };
        assert!(handle(&host, &peer, &json!({"operation":"list"})).await.is_err());
        host.state().session.write().lock();
        assert!(handle(&host, &PeerIdentity::default(), &json!({"operation":"list"})).await.is_err());
    }
    #[tokio::test]
    async fn approved_editor_can_manage_collections_and_roundtrip_rich_fields() {
        let (_dir, host) = setup(true); let peer = PeerIdentity::default();
        handle(&host, &peer, &json!({"operation":"activate"})).await.unwrap();
        handle(&host, &peer, &json!({"operation":"mutate","action":{"operation":"createTag","name":"Work"}})).await.unwrap();
        let mut item = serde_json::to_value(login()).unwrap(); item["id"] = json!("");
        handle(&host, &peer, &json!({"operation":"create","item":item})).await.unwrap();
        let list = handle(&host, &peer, &json!({"operation":"list"})).await.unwrap();
        let id = list["items"][0]["id"].as_str().unwrap();
        let result = handle(&host, &peer, &json!({"operation":"read","id":id})).await.unwrap();
        assert_eq!(result["item"]["customFields"][0]["value"], "hidden");
        assert_eq!(list["collections"]["organization"]["tags"][0]["name"], "Work");
    }
    #[tokio::test]
    async fn passkey_private_key_never_enters_editor_response() {
        let (_dir, host) = setup(true);
        let item: VaultItem = serde_json::from_value(json!({"item_type":"passkey","id":"key","name":"Key","private_key":"never-release"})).unwrap();
        host.state().vault.write().add_item(item);
        let response = handle(&host, &PeerIdentity::default(), &json!({"operation":"read","id":"key"})).await.unwrap();
        assert_eq!(response["item"]["item_type"], "passkey");
        assert!(response["item"].get("private_key").is_none());
        assert!(!response.to_string().contains("never-release"));
    }
    #[tokio::test]
    async fn failed_item_persistence_does_not_publish_changes() {
        let (dir, host) = setup(true);
        let moved = dir.path().with_extension("saved");
        std::fs::rename(dir.path(), &moved).unwrap();
        std::fs::write(dir.path(), b"not a directory").unwrap();
        let result = crate::commands::vault::add_item(host.state(), login().with_rich(Default::default())).await;
        // Restore the temp path even when the assertion below fails.
        std::fs::remove_file(dir.path()).unwrap();
        std::fs::rename(moved, dir.path()).unwrap();
        assert!(result.is_err());
        assert!(crate::commands::vault::get_items(host.state()).unwrap().is_empty());
    }

}
