use super::vault::require_unlocked;
use crate::{vault::VaultStore, AppState};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vela_core::rich_items::OrganizationData;

#[derive(Debug, Serialize)]
pub struct OrganizationStatus {
    pub enabled: bool,
    pub organization: OrganizationData,
}

pub fn get_organization(state: &Arc<AppState>) -> Result<OrganizationStatus, String> {
    require_unlocked(state)?;
    let vault = state.vault.read();
    Ok(OrganizationStatus {
        enabled: vault.schema_version == Some(2),
        organization: vault.organization.clone(),
    })
}

pub async fn activate_rich_items(state: &Arc<AppState>) -> Result<OrganizationStatus, String> {
    require_unlocked(state)?;
    let _sync = state.sync_mutex.lock().await;
    state.persist_current_vault().map_err(|e| e.to_string())?;
    let backup = state.store.store_path().join("vault.before-rich-items.enc");
    if !backup.exists() {
        std::fs::copy(state.store.store_path().join("vault.enc"), &backup)
            .map_err(|_| "Could not create the encrypted safety backup".to_string())?;
        std::fs::File::open(&backup)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
    }
    let server = state.server_url.read().clone();
    if !server.is_empty() {
        let token = state
            .get_session_token()
            .ok_or("Connect and unlock before enabling richer items")?;
        crate::api::ApiClient::with_url(server)
            .rich_schema(&token, true)
            .await
            .map_err(|e| e.to_string())?;
    }
    transaction(state, |vault| {
        vault.schema_version = Some(2);
        Ok(())
    })?;
    get_organization(state)
}

/// Persist the candidate before replacing memory; lock order matches lock/rekey.
pub fn transaction<T>(
    state: &Arc<AppState>,
    edit: impl FnOnce(&mut VaultStore) -> Result<T, String>,
) -> Result<T, String> {
    require_unlocked(state)?;
    let result = {
        let _transition = state
            .key_transition_lock
            .read()
            .map_err(|_| "Key transition unavailable")?;
        let crypto = state.crypto.read();
        let crypto = crypto.as_ref().ok_or("Vault is locked")?;
        let mut current = state.vault.write();
        let mut candidate = current.clone();
        let result = edit(&mut candidate)?;
        candidate.touch_generation();
        state
            .store
            .save_vault(&candidate, crypto)
            .map_err(|e| e.to_string())?;
        *current = candidate;
        result
    };
    state.notify_vault_changed();
    Ok(result)
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase")]
pub enum OrganizationAction {
    CreateFolder {
        name: String,
        #[serde(rename = "parentId")]
        parent_id: Option<Uuid>,
    },
    UpdateFolder {
        id: Uuid,
        name: String,
        #[serde(rename = "parentId")]
        parent_id: Option<Uuid>,
    },
    RenameFolder {
        id: Uuid,
        name: String,
    },
    MoveFolder {
        id: Uuid,
        #[serde(rename = "parentId")]
        parent_id: Option<Uuid>,
    },
    DeleteFolder {
        id: Uuid,
    },
    CreateTag {
        name: String,
    },
    RenameTag {
        id: Uuid,
        name: String,
    },
    DeleteTag {
        id: Uuid,
    },
}

pub fn mutate_organization(
    state: &Arc<AppState>,
    action: OrganizationAction,
) -> Result<OrganizationStatus, String> {
    let device = state
        .store
        .load_device_id()
        .unwrap_or_else(|_| "local-desktop".into());
    transaction(state, |vault| {
        if vault.schema_version != Some(2) {
            return Err("Enable folders and richer items first".into());
        }
        let now = Utc::now();
        let org = &mut vault.organization;
        match action {
            OrganizationAction::CreateFolder { name, parent_id } => {
                org.create_folder(&name, parent_id, &device, now)
                    .map_err(|e| e.to_string())?;
            }
            OrganizationAction::UpdateFolder {
                id,
                name,
                parent_id,
            } => {
                org.rename_folder(id, &name, &device, now)
                    .map_err(|e| e.to_string())?;
                org.move_folder(id, parent_id, &device, now)
                    .map_err(|e| e.to_string())?;
            }
            OrganizationAction::RenameFolder { id, name } => org
                .rename_folder(id, &name, &device, now)
                .map_err(|e| e.to_string())?,
            OrganizationAction::MoveFolder { id, parent_id } => org
                .move_folder(id, parent_id, &device, now)
                .map_err(|e| e.to_string())?,
            OrganizationAction::DeleteFolder { id } => org
                .delete_folder(id, &device, now)
                .map_err(|e| e.to_string())?,
            OrganizationAction::CreateTag { name } => {
                org.create_tag(&name, &device, now)
                    .map_err(|e| e.to_string())?;
            }
            OrganizationAction::RenameTag { id, name } => org
                .rename_tag(id, &name, &device, now)
                .map_err(|e| e.to_string())?,
            OrganizationAction::DeleteTag { id } => {
                org.delete_tag(id).map_err(|e| e.to_string())?
            }
        }
        // Repair local assignments in the same transaction as deletion.
        for item in &mut vault.items {
            let mut rich = item.meta().rich.clone();
            if rich.folder_id.as_ref().is_some_and(|id| {
                !id.is_empty()
                    && Uuid::parse_str(id)
                        .ok()
                        .and_then(|id| org.folder(id))
                        .is_none()
            }) {
                rich.folder_id = Some(String::new());
            }
            if let Some(tags) = &mut rich.tag_ids {
                tags.retain(|id| org.tag(*id).is_some());
            }
            if rich != item.meta().rich {
                *item = item
                    .with_rich(rich)
                    .with_updated_at(now)
                    .with_last_modified_device(device.clone());
            }
        }
        Ok(())
    })?;
    get_organization(state)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignItems {
    pub ids: Vec<String>,
    pub folder_id: Option<String>,
    pub add_tags: Vec<Uuid>,
    pub remove_tags: Vec<Uuid>,
}

pub fn assign_items(state: &Arc<AppState>, changes: AssignItems) -> Result<(), String> {
    let device = state
        .store
        .load_device_id()
        .unwrap_or_else(|_| "local-desktop".into());
    transaction(state, |vault| {
        if vault.schema_version != Some(2) {
            return Err("Enable folders and richer items first".into());
        }
        if let Some(folder) = changes.folder_id.as_ref().filter(|s| !s.is_empty()) {
            let id = Uuid::parse_str(folder).map_err(|_| "Invalid folder ID")?;
            if vault.organization.folder(id).is_none() {
                return Err("Folder not found".into());
            }
        }
        for id in &changes.add_tags {
            if vault.organization.tag(*id).is_none() {
                return Err("Tag not found".into());
            }
        }
        for id in &changes.ids {
            let item = vault.get_item(id).ok_or("Item not found")?;
            if item.is_received_share() {
                return Err("Received shared items cannot be reorganized".into());
            }
        }
        for id in &changes.ids {
            let item = vault.get_item(id).ok_or("Item not found")?;
            let mut rich = item.meta().rich.clone();
            if let Some(folder) = &changes.folder_id {
                rich.folder_id = Some(folder.clone());
            }
            let tags = rich.tag_ids.get_or_insert_with(Vec::new);
            tags.retain(|id| !changes.remove_tags.contains(id));
            for id in &changes.add_tags {
                if !tags.contains(id) {
                    tags.push(*id);
                }
            }
            vela_core::rich_items::ItemOrganization {
                folder_id: rich
                    .folder_id
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| Uuid::parse_str(s).ok()),
                tag_ids: rich.tag_ids.clone().unwrap_or_default(),
                custom_fields: vec![],
            }
            .validate_for_write()
            .map_err(|e| e.to_string())?;
            let updated = item
                .with_rich(rich)
                .with_updated_at(Utc::now())
                .with_last_modified_device(device.clone());
            vault.update_item(updated);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commands::vault, crypto::Crypto, vault::VaultItem};
    use serde_json::json;

    fn setup() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(AppState::for_test(dir.path()));
        state.unlock_for_test(&Crypto::generate_rms());
        (dir, state)
    }
    fn login() -> VaultItem {
        serde_json::from_value(json!({"item_type":"login","id":"","name":"Test login","url":"https://example.com","username":"test","password":"fixture-password"})).unwrap()
    }

    #[tokio::test]
    async fn folder_edit_saves_name_and_parent_atomically() {
        let (_dir, state) = setup();
        activate_rich_items(&state).await.unwrap();
        let status = mutate_organization(
            &state,
            OrganizationAction::CreateFolder {
                name: "Parent".into(),
                parent_id: None,
            },
        )
        .unwrap();
        let root = status.organization.folders[0].id;
        let status = mutate_organization(
            &state,
            OrganizationAction::CreateFolder {
                name: "Child".into(),
                parent_id: Some(root),
            },
        )
        .unwrap();
        let child = status
            .organization
            .folders
            .iter()
            .find(|f| f.id != root)
            .unwrap()
            .id;
        let before = serde_json::to_value(state.vault.read().clone()).unwrap();
        assert!(mutate_organization(
            &state,
            OrganizationAction::UpdateFolder {
                id: root,
                name: "Invalid rename".into(),
                parent_id: Some(child)
            }
        )
        .is_err());
        assert_eq!(
            serde_json::to_value(state.vault.read().clone()).unwrap(),
            before
        );
        let status = mutate_organization(
            &state,
            OrganizationAction::UpdateFolder {
                id: child,
                name: "Projects".into(),
                parent_id: None,
            },
        )
        .unwrap();
        let folder = status.organization.folder(child).unwrap();
        assert_eq!(folder.name, "Projects");
        assert_eq!(folder.parent_id, None);
        let saved = state
            .store
            .load_vault(state.crypto.read().as_ref().unwrap())
            .unwrap();
        assert_eq!(saved.organization.folder(child).unwrap().name, "Projects");
    }

    #[tokio::test]
    async fn rich_vault_lifecycle_persists_organization_and_preserves_omitted_fields() {
        let (dir, state) = setup();
        let item = vault::add_item(&state, login()).await.unwrap();
        activate_rich_items(&state).await.unwrap();
        assert!(dir.path().join("vault.before-rich-items.enc").exists());
        let status = mutate_organization(
            &state,
            OrganizationAction::CreateFolder {
                name: "Personal".into(),
                parent_id: None,
            },
        )
        .unwrap();
        let folder = status.organization.folders[0].id;
        let status = mutate_organization(
            &state,
            OrganizationAction::CreateTag {
                name: "Important".into(),
            },
        )
        .unwrap();
        let tag = status.organization.tags[0].id;
        assign_items(
            &state,
            AssignItems {
                ids: vec![item.id().into()],
                folder_id: Some(folder.to_string()),
                add_tags: vec![tag],
                remove_tags: vec![],
            },
        )
        .unwrap();
        let mut rich = state
            .vault
            .read()
            .get_item(item.id())
            .unwrap()
            .meta()
            .rich
            .clone();
        rich.custom_fields=Some(vec![serde_json::from_value(json!({"id":Uuid::new_v4(),"label":"Recovery","type":"concealed","value":"fixture-recovery"})).unwrap()]);
        vault::update_item(&state, item.with_rich(rich))
            .await
            .unwrap();
        // An older editor omits all rich keys while changing its known name.
        let updated = vault::update_item(&state, item.with_name("Renamed".into()))
            .await
            .unwrap();
        assert_eq!(
            updated.meta().rich.folder_id.as_deref(),
            Some(folder.to_string().as_str())
        );
        assert_eq!(
            updated.meta().rich.custom_fields.as_ref().unwrap()[0]
                .value
                .0,
            "fixture-recovery"
        );
        let saved = state
            .store
            .load_vault(state.crypto.read().as_ref().unwrap())
            .unwrap();
        assert_eq!(saved.organization.folders[0].id, folder);
        assert_eq!(
            saved.get_item(item.id()).unwrap().meta().rich,
            updated.meta().rich
        );
        mutate_organization(&state, OrganizationAction::DeleteFolder { id: folder }).unwrap();
        mutate_organization(&state, OrganizationAction::DeleteTag { id: tag }).unwrap();
        let saved = state.vault.read();
        let rich = &saved.get_item(item.id()).unwrap().meta().rich;
        assert_eq!(rich.folder_id.as_deref(), Some(""));
        assert!(rich.tag_ids.as_ref().unwrap().is_empty());
        assert_eq!(rich.custom_fields.as_ref().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn bulk_assignment_is_atomic_when_selection_contains_a_missing_item() {
        let (_dir, state) = setup();
        activate_rich_items(&state).await.unwrap();
        let item = vault::add_item(&state, login()).await.unwrap();
        let before = serde_json::to_value(state.vault.read().clone()).unwrap();
        assert!(assign_items(
            &state,
            AssignItems {
                ids: vec![item.id().into(), "missing".into()],
                folder_id: Some(String::new()),
                add_tags: vec![],
                remove_tags: vec![]
            }
        )
        .is_err());
        assert_eq!(
            before,
            serde_json::to_value(state.vault.read().clone()).unwrap()
        );
    }

    #[tokio::test]
    async fn encrypted_archive_restores_rich_vault_on_a_clean_install() {
        let (_dir, state) = setup();
        activate_rich_items(&state).await.unwrap();
        let item = vault::add_item(&state, login()).await.unwrap();
        let status = mutate_organization(
            &state,
            OrganizationAction::CreateFolder {
                name: "Backup folder".into(),
                parent_id: None,
            },
        )
        .unwrap();
        let folder = status.organization.folders[0].id;
        assign_items(
            &state,
            AssignItems {
                ids: vec![item.id().into()],
                folder_id: Some(folder.to_string()),
                add_tags: vec![],
                remove_tags: vec![],
            },
        )
        .unwrap();
        let data = vault::export_vault_encrypted(&state, "fixture-backup-passphrase").unwrap();
        let (_other_dir, other) = setup();
        activate_rich_items(&other).await.unwrap();
        vault::import_vela_archive(&other, &data, "fixture-backup-passphrase").unwrap();
        let restored = other.vault.read();
        assert_eq!(restored.schema_version, Some(2));
        assert_eq!(restored.organization.folders[0].id, folder);
        assert_eq!(
            restored
                .get_item(item.id())
                .unwrap()
                .meta()
                .rich
                .folder_id
                .as_deref(),
            Some(folder.to_string().as_str())
        );
    }
}
