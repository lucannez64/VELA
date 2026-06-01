use crate::vault::VaultItem;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillRequest {
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillResponse {
    pub items: Vec<VaultItem>,
    pub requires_biometric: bool,
}

#[tauri::command]
pub async fn handle_autofill_request(
    _request: AutofillRequest,
) -> Result<AutofillResponse, String> {
    Ok(AutofillResponse {
        items: vec![],
        requires_biometric: true,
    })
}
