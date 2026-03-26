use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub enrolled_at: DateTime<Utc>,
    pub last_active: Option<DateTime<Utc>>,
    pub this_device: bool,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Desktop,
    Mobile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub device_id: String,
    pub confirm: bool,
}

#[tauri::command]
pub async fn get_devices() -> Result<Vec<Device>, String> {
    let now = Utc::now();
    Ok(vec![
        Device {
            id: "device-1".to_string(),
            name: "Windows Desktop (this device)".to_string(),
            device_type: DeviceType::Desktop,
            enrolled_at: now - chrono::Duration::days(30),
            last_active: Some(now),
            this_device: true,
            revoked: false,
        },
        Device {
            id: "device-2".to_string(),
            name: "MacBook Pro".to_string(),
            device_type: DeviceType::Desktop,
            enrolled_at: now - chrono::Duration::days(60),
            last_active: Some(now - chrono::Duration::hours(2)),
            this_device: false,
            revoked: false,
        },
        Device {
            id: "device-3".to_string(),
            name: "iPhone 15 Pro".to_string(),
            device_type: DeviceType::Mobile,
            enrolled_at: now - chrono::Duration::days(45),
            last_active: Some(now - chrono::Duration::days(4)),
            this_device: false,
            revoked: false,
        },
    ])
}

#[tauri::command]
pub async fn revoke_device(request: RevokeRequest) -> Result<(), String> {
    if !request.confirm {
        return Err("Revocation must be confirmed".to_string());
    }
    Ok(())
}
