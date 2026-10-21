//! Explicit, isolated demo profile. Never constructs the user's default store.
use std::{path::PathBuf, sync::Arc};
use vela_desktop_core::{crypto::Crypto, vault::VaultItem, AppState, Uuid};

pub struct DemoMode;
impl gpui::Global for DemoMode {}

pub struct DemoVault {
    pub state: Arc<AppState>,
    directory: PathBuf,
}
impl DemoVault {
    pub fn new() -> Result<Self, String> {
        let directory = std::env::temp_dir().join(format!("vela-demo-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).map_err(|e| e.to_string())?;
        let state = Arc::new(AppState::for_test(&directory));
        state.unlock_for_test(&Crypto::generate_rms());
        state
            .session
            .write()
            .unlock("demo-device".into(), "demo-user".into(), 86400);
        let settings = vela_desktop_core::settings::Settings {
            auto_lock_minutes: 24 * 60,
            sync_on_startup: false,
            background_sync_minutes: 0,
            ..Default::default()
        };
        state
            .store
            .save_settings(&settings)
            .map_err(|e| e.to_string())?;
        let now = chrono::Utc::now();
        // Spread change dates so password age and staleness have something to show.
        let ago = |days: i64| (now - chrono::Duration::days(days)).to_rfc3339();
        {
            let mut vault = state.vault.write();
            vault.schema_version = Some(2);
            let org = &mut vault.organization;
            let personal = org
                .create_folder("Personal", None, "demo", now)
                .map_err(|e| e.to_string())?;
            let work = org
                .create_folder("Work", None, "demo", now)
                .map_err(|e| e.to_string())?;
            let projects = org
                .create_folder("Projects", Some(work), "demo", now)
                .map_err(|e| e.to_string())?;
            let travel = org
                .create_folder("Travel", Some(personal), "demo", now)
                .map_err(|e| e.to_string())?;
            let important = org
                .create_tag("Important", "demo", now)
                .map_err(|e| e.to_string())?;
            let family = org
                .create_tag("Family", "demo", now)
                .map_err(|e| e.to_string())?;
            let review = org
                .create_tag("Review later", "demo", now)
                .map_err(|e| e.to_string())?;
            let mut records = vec![
                serde_json::json!({"item_type":"login","name":"Personal email","url":"https://mail.example.test","username":"alex@example.test","password":"Demo-only-Password!42","totp":"JBSWY3DPEHPK3PXP","favorite":true,"updatedAt":ago(12),"folderId":personal,"tagIds":[important],"customFields":[{"id":Uuid::new_v4(),"label":"Recovery code","type":"concealed","value":"DEMO-1234-5678"},{"id":Uuid::new_v4(),"label":"Account number","type":"text","value":"DEMO-0001"},{"id":Uuid::new_v4(),"label":"Two-step verification","type":"boolean","value":true}],"additionalUrls":[{"id":Uuid::new_v4(),"url":"https://accounts.example.test","match":"origin"}]}),
                serde_json::json!({"item_type":"login","name":"Team workspace","url":"https://team.example.test","username":"alex@work.example.test","password":"Demo-team-Password!42","totp":"GEZDGNBVGY3TQOJQ","favorite":true,"updatedAt":ago(41),"folderId":work,"tagIds":[important]}),
                serde_json::json!({"item_type":"login","name":"Project dashboard","url":"https://project.example.test","username":"demo-alex","password":"Demo-project-Password!42","folderId":projects,"tagIds":[review]}),
                serde_json::json!({"item_type":"creditCard","name":"Travel card (test)","number":"4242424242424242","exp":"12/29","cvv":"123","cardholder_name":"Alex Demo","favorite":true,"folderId":travel,"tagIds":[family],"notes":"Test card number. This is not a real payment card."}),
                serde_json::json!({"item_type":"secureNote","name":"Family travel checklist","title":"Family travel checklist","content":"Synthetic demo note\n\nPack chargers\nBook the train\nWater the plants","folderId":travel,"tagIds":[family]}),
                serde_json::json!({"item_type":"identity","name":"Alex Demo","first_name":"Alex","last_name":"Demo","ssn":"DEMO-NOT-A-REAL-ID","folderId":personal,"tagIds":[family],"identityDetails":{"email":"alex@example.test","phone":"+1 202 555 0123","company":"Example Company","jobTitle":"Designer","addresses":[{"id":Uuid::new_v4(),"label":"Home (fictional)","line1":"123 Example Street","city":"Sample City","postalCode":"00000","countryCode":"US"}]}}),
                serde_json::json!({"item_type":"secureNote","name":"Unfiled note","title":"Unfiled note","content":"Try moving this note to a folder using the selection checkbox and Move…","tagIds":[review]}),
            ];
            for index in 1..=18 {
                records.push(serde_json::json!({"item_type":"login","name":format!("Sample account {index:02}"),"url":format!("https://account{index}.example.test"),"username":"demo@example.test","password":match index { 4 | 9 => "Demo-shared-Password!".to_string(), 6 => "kitten".to_string(), _ => format!("Demo-only-{index:02}-Password!") },"updatedAt":ago(match index { 11 => 520, 15 => 800, 17 => 400, i => i as i64 * 19 }),"folderId":if index%2==0{work}else{personal},"tagIds":if index%3==0{vec![review]}else{vec![]}}));
            }
            for mut record in records {
                record["id"] = serde_json::json!(Uuid::new_v4().to_string());
                let item: VaultItem = serde_json::from_value(record).map_err(|e| e.to_string())?;
                vault.add_item(item);
            }
        }
        state
            .store
            .save_vault(&state.vault.read(), state.crypto.read().as_ref().unwrap())
            .map_err(|e| e.to_string())?;
        demo_activity(&state, now)?;
        tracing::info!(
            "Demo vault: {} fake items in {}",
            state.vault.read().items.len(),
            directory.display()
        );
        Ok(Self { state, directory })
    }
}
/// A believable activity history: about 60 fake events over 15 weeks.
fn demo_activity(state: &AppState, now: chrono::DateTime<chrono::Utc>) -> Result<(), String> {
    use vela_desktop_core::audit::{AuditAction, AuditEntry, AuditLog, AuditSubject};
    let actions = [
        AuditAction::VaultUnlocked,
        AuditAction::CredentialReleased { caller: "Firefox extension".into(), domain: "mail.example.test".into() },
        AuditAction::ItemUpdated { item_type: "login".into() },
        AuditAction::PasswordGenerated { length: 20 },
        AuditAction::VaultLocked,
        AuditAction::ShareLinkCreated { has_passphrase: true, view_once: true },
        AuditAction::ItemAdded { item_type: "login".into() },
        AuditAction::SettingsChanged,
    ];
    let mut log = AuditLog::default();
    for i in 0..60u32 {
        let days = ((i * 7919) % 105) as i64;
        let minutes = ((i * 131) % 600) as i64 + 30;
        log.add_entry(AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: now - chrono::Duration::days(days) - chrono::Duration::minutes(minutes),
            action: actions[i as usize % actions.len()].clone(),
            subject: AuditSubject::Device { device_name: "Demo laptop".into() },
        });
    }
    log.add_entry(AuditEntry {
        id: Uuid::new_v4().to_string(),
        timestamp: now - chrono::Duration::minutes(2),
        action: AuditAction::VaultUnlocked,
        subject: AuditSubject::Device { device_name: "Demo laptop".into() },
    });
    log.entries.sort_by_key(|e| e.timestamp);
    vela_desktop_core::audit::save_audit_log(state, &log)
}

impl Drop for DemoVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn demo_is_isolated_editable_and_disposable() {
        let demo = DemoVault::new().unwrap();
        assert!(demo.state.server_url.read().is_empty());
        assert!(demo.state.get_session_token().is_none());
        assert_eq!(demo.state.vault.read().items.len(), 25);
        for item in &demo.state.vault.read().items {
            item.meta().rich.validate_for_write().unwrap();
        }
        let org = vela_desktop_core::commands::organization::get_organization(&demo.state).unwrap();
        assert!(org.enabled);
        assert_eq!(org.organization.folders.len(), 4);
        vela_desktop_core::commands::organization::mutate_organization(
            &demo.state,
            vela_desktop_core::commands::organization::OrganizationAction::CreateTag {
                name: "Test edits".into(),
            },
        )
        .unwrap();
        let saved = demo
            .state
            .store
            .load_vault(demo.state.crypto.read().as_ref().unwrap())
            .unwrap();
        assert_eq!(saved.organization.tags.len(), 4);
        let path = demo.directory.clone();
        drop(demo);
        assert!(!path.exists());
    }
}

/// Synthetic device cards, only used by the explicitly disposable demo.
pub fn devices() -> Vec<vela_desktop_core::commands::devices::Device> {
    use vela_desktop_core::commands::devices::{Device, DeviceType};
    let now=chrono::Utc::now();
    [("demo-laptop","Demo laptop",DeviceType::Desktop,true,false),
     ("demo-phone","Demo phone",DeviceType::Mobile,false,false),
     ("demo-old","Old demo laptop",DeviceType::Desktop,false,true)]
        .into_iter().enumerate().map(|(i,(id,name,device_type,this_device,revoked))|Device{
            id:id.into(),name:name.into(),device_type,this_device,revoked,pending:false,
            enrolled_at:now-chrono::Duration::days(20+i as i64*40),
            last_active:Some(now-chrono::Duration::minutes(i as i64*120)),
        }).collect()
}
