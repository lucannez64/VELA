//! One validation and organization engine for mobile and browser clients.
//! JSON crosses the FFI boundary, but errors never include values or credentials.
use crate::rich_items::*;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

type Result<T> = std::result::Result<T, ValidationError>;
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T> {
    serde_json::from_value(value.clone()).map_err(|_| ValidationError("Invalid richer-item request"))
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase")]
enum Action {
    CreateFolder { name: String, #[serde(rename="parentId")] parent: Option<Uuid> },
    UpdateFolder { id: Uuid, name: String, #[serde(rename="parentId")] parent: Option<Uuid> },
    DeleteFolder { id: Uuid }, CreateTag { name: String },
    RenameTag { id: Uuid, name: String }, DeleteTag { id: Uuid },
}
/// No whole-vault parsing/re-encoding: unrelated and future JSON stays with the caller.
pub fn process(request: &str) -> Result<Value> {
    if request.len() > 8 * 1024 * 1024 { return Err(ValidationError("Richer-item request exceeds size limit")); }
    let req: Value = serde_json::from_str(request).map_err(|_| ValidationError("Invalid richer-item request"))?;
    let operation = req["operation"].as_str().ok_or(ValidationError("Missing operation"))?;
    if operation == "capabilities" { return Ok(json!({"supportedSchema":2})); }
    let org: OrganizationData = decode(req.get("organization").unwrap_or(&json!({})))?;
    match operation {
        "merge" => {
            let other: OrganizationData = decode(&req["other"])?;
            Ok(serde_json::to_value(org.merged(&other)?).map_err(|_| ValidationError("Could not encode organization"))?)
        }
        "mutate" => {
            let mut org = org.merged(&OrganizationData::default())?;
            let device = req["deviceId"].as_str().filter(|s| !s.trim().is_empty()).ok_or(ValidationError("Writer device ID is required"))?;
            let now = Utc::now();
            match decode::<Action>(&req["action"])? {
                Action::CreateFolder {name,parent} => { org.create_folder(&name,parent,device,now)?; }
                Action::UpdateFolder {id,name,parent} => { org.rename_folder(id,&name,device,now)?; org.move_folder(id,parent,device,now)?; }
                Action::DeleteFolder {id} => org.delete_folder(id,device,now)?,
                Action::CreateTag {name} => { org.create_tag(&name,device,now)?; }
                Action::RenameTag {id,name} => org.rename_tag(id,&name,device,now)?,
                Action::DeleteTag {id} => org.delete_tag(id)?,
            }
            serde_json::to_value(org).map_err(|_| ValidationError("Could not encode organization"))
        }
        "validate" => {
            let rich: RichItemData = decode(&req["rich"])?;
            let old: RichItemData = decode(req.get("old").unwrap_or(&json!({})))?;
            let mut checked = rich.clone();
            // A future record can be carried through an unrelated edit, never edited here.
            if let Some(fields) = &mut checked.custom_fields {
                fields.retain(|f| !matches!(f.kind, CustomFieldType::Unknown(_)) || !old.custom_fields.as_ref().is_some_and(|v| v.contains(f)));
            }
            if let Some(urls) = &mut checked.additional_urls {
                urls.retain(|u| !matches!(u.match_mode, UrlMatch::Unknown(_)) || !old.additional_urls.as_ref().is_some_and(|v| v.contains(u)));
            }
            checked.validate_for_write()?;
            if rich.folder_id.as_ref().filter(|s| !s.is_empty()).is_some_and(|id| Uuid::parse_str(id).ok().and_then(|id| org.folder(id)).is_none()) {
                return Err(ValidationError("Folder no longer exists"));
            }
            if rich.tag_ids.as_ref().is_some_and(|ids| ids.iter().any(|id| org.tag(*id).is_none())) { return Err(ValidationError("Tag no longer exists")); }
            Ok(json!({"ok":true}))
        }
        "repair" => {
            let mut raw = req["rich"].clone();
            let rich: RichItemData = decode(&raw)?;
            if rich.folder_id.as_ref().filter(|s| !s.is_empty()).is_some_and(|id| Uuid::parse_str(id).ok().and_then(|id| org.folder(id)).is_none()) { raw["folderId"] = json!(""); }
            if let Some(ids) = rich.tag_ids { raw["tagIds"] = json!(ids.into_iter().filter(|id| org.tag(*id).is_some()).collect::<Vec<_>>()); }
            Ok(raw)
        }
        _ => Err(ValidationError("Unknown richer-item operation")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mobile_operations_share_unicode_cycle_and_delete_rules() {
        let org = process(&json!({"operation":"mutate","deviceId":"android","organization":{},"action":{"operation":"createFolder","name":"Café"}}).to_string()).unwrap();
        assert!(process(&json!({"operation":"mutate","deviceId":"ios","organization":org,"action":{"operation":"createFolder","name":"Cafe\u{301}"}}).to_string()).is_err());
        let id = org["folders"][0]["id"].clone();
        assert!(process(&json!({"operation":"mutate","deviceId":"ios","organization":org,"action":{"operation":"updateFolder","id":id,"name":"Café","parentId":id}}).to_string()).is_err());
        let gone = process(&json!({"operation":"mutate","deviceId":"ios","organization":org,"action":{"operation":"deleteFolder","id":id}}).to_string()).unwrap();
        let merged = process(&json!({"operation":"merge","organization":org,"other":gone}).to_string()).unwrap();
        assert_eq!(merged["folders"].as_array().unwrap().len(),0);
        let repaired = process(&json!({"operation":"repair","organization":merged,"rich":{"folderId":id,"future":{"value":"untouched"}}}).to_string()).unwrap();
        assert_eq!(repaired["folderId"],""); assert_eq!(repaired["future"]["value"],"untouched");
    }
    #[test]
    fn future_fields_are_preserved_but_cannot_be_changed() {
        let rich = json!({"customFields":[{"id":Uuid::new_v4(),"label":"Future","type":"future-v3","value":{"secret":"example"},"future":true}]});
        assert!(process(&json!({"operation":"validate","organization":{},"rich":rich,"old":rich}).to_string()).is_ok());
        assert!(process(&json!({"operation":"validate","organization":{},"rich":rich,"old":{}}).to_string()).is_err());
        assert!(!process("{ broken").unwrap_err().to_string().contains("broken"));
    }
}
