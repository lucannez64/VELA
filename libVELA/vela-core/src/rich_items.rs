//! Wire types and validation for the next vault-data schema.
//!
//! Deliberately separate from the live `VaultStore`: every fleet serializer,
//! merge path and server write gate must support these fields before activation.
//! Rich records preserve unknown properties; envelope/item property preservation
//! belongs to the live serializer integration. Validation is for new writes,
//! not a reason to discard a newer client's data during decode.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zeroize::Zeroize;

pub const RICH_SCHEMA_VERSION: u32 = 2;
pub const MAX_NAME_CHARS: usize = 128;
pub const MAX_FOLDER_DEPTH: usize = 16;
pub const MAX_TAGS_PER_ITEM: usize = 64;
pub const MAX_CUSTOM_FIELDS: usize = 128;
pub const MAX_CUSTOM_VALUE_BYTES: usize = 16 * 1024;
pub const MAX_ADDITIONAL_URLS: usize = 32;
pub const MAX_URL_BYTES: usize = 4 * 1024;
pub const MAX_ADDRESSES: usize = 16;

/// Static messages only: errors must never interpolate user values or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationError(pub &'static str);

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ValidationError {}

type Result<T> = std::result::Result<T, ValidationError>;

/// Unknown properties can contain credentials. Never derive Debug for raw JSON.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SensitiveValue(pub serde_json::Value);

impl std::fmt::Debug for SensitiveValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Drop for SensitiveValue {
    fn drop(&mut self) {
        fn wipe(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(text) => text.zeroize(),
                serde_json::Value::Array(values) => values.iter_mut().for_each(wipe),
                serde_json::Value::Object(values) => values.values_mut().for_each(wipe),
                _ => {}
            }
            *value = serde_json::Value::Null;
        }
        wipe(&mut self.0);
    }
}

pub type ExtraProperties = BTreeMap<String, SensitiveValue>;

/// Optional fields distinguish an older editor omitting a property from a
/// supported editor explicitly clearing its collection (or folder assignment).
/// An empty string clears folderId; UUID validation happens at the write edge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RichItemData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_ids: Option<Vec<Uuid>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_urls: Option<Vec<AdditionalUrl>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_details: Option<IdentityDetails>,
}

impl RichItemData {
    pub fn preserve_omitted(&mut self, old: &Self) {
        if self.folder_id.is_none() {
            self.folder_id = old.folder_id.clone();
        }
        if self.tag_ids.is_none() {
            self.tag_ids = old.tag_ids.clone();
        }
        if self.custom_fields.is_none() {
            self.custom_fields = old.custom_fields.clone();
        }
        if self.additional_urls.is_none() {
            self.additional_urls = old.additional_urls.clone();
        }
        if self.identity_details.is_none() {
            self.identity_details = old.identity_details.clone();
        }
    }

    pub fn has_data(&self) -> bool {
        self.folder_id.as_ref().is_some_and(|s| !s.is_empty())
            || self.tag_ids.as_ref().is_some_and(|v| !v.is_empty())
            || self.custom_fields.as_ref().is_some_and(|v| !v.is_empty())
            || self.additional_urls.as_ref().is_some_and(|v| !v.is_empty())
            || self.identity_details.is_some()
    }

    pub fn validate_for_write(&self) -> Result<()> {
        let folder_id = self
            .folder_id
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| Uuid::parse_str(s).map_err(|_| ValidationError("Invalid folder ID")))
            .transpose()?;
        ItemOrganization {
            folder_id,
            tag_ids: self.tag_ids.clone().unwrap_or_default(),
            custom_fields: self.custom_fields.clone().unwrap_or_default(),
        }
        .validate_for_write()?;
        LoginDetails {
            additional_urls: self.additional_urls.clone().unwrap_or_default(),
        }
        .validate_for_write()?;
        if let Some(details) = &self.identity_details {
            details.validate_for_write()?;
        }
        Ok(())
    }

    pub fn strip_personal_organization(&mut self) {
        self.folder_id = None;
        self.tag_ids = None;
    }
}

/// A tag is intentionally a string on the wire so future types round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum CustomFieldType {
    Text,
    Concealed,
    Boolean,
    Unknown(String),
}

impl From<String> for CustomFieldType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "text" => Self::Text,
            "concealed" => Self::Concealed,
            "boolean" => Self::Boolean,
            _ => Self::Unknown(value),
        }
    }
}

impl From<CustomFieldType> for String {
    fn from(value: CustomFieldType) -> Self {
        match value {
            CustomFieldType::Text => "text".into(),
            CustomFieldType::Concealed => "concealed".into(),
            CustomFieldType::Boolean => "boolean".into(),
            CustomFieldType::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub id: Uuid,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: CustomFieldType,
    pub value: SensitiveValue,
    #[serde(flatten)]
    pub extra: ExtraProperties,
}

impl CustomField {
    pub fn validate_for_write(&self) -> Result<()> {
        valid_id(self.id)?;
        normalized_name(&self.label)?;
        match (&self.kind, &self.value.0) {
            (CustomFieldType::Text | CustomFieldType::Concealed, serde_json::Value::String(s))
                if s.len() <= MAX_CUSTOM_VALUE_BYTES =>
            {
                Ok(())
            }
            (CustomFieldType::Boolean, serde_json::Value::Bool(_)) => Ok(()),
            (CustomFieldType::Unknown(_), _) => Err(ValidationError(
                "Unsupported custom-field type is read-only",
            )),
            _ => Err(ValidationError(
                "Custom-field value has an invalid type or exceeds its size limit",
            )),
        }
    }
}

/// Flatten into item metadata only after preservation and write-gating ship.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemOrganization {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tag_ids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_fields: Vec<CustomField>,
}

impl ItemOrganization {
    /// Missing referenced records are valid on decode: stale clients may still
    /// reference a deleted folder. Views resolve those as unfiled.
    pub fn validate_for_write(&self) -> Result<()> {
        if let Some(id) = self.folder_id {
            valid_id(id)?;
        }
        if self.tag_ids.len() > MAX_TAGS_PER_ITEM || self.custom_fields.len() > MAX_CUSTOM_FIELDS {
            return Err(ValidationError("Too many tags or custom fields"));
        }
        unique_ids(self.tag_ids.iter().copied())?;
        unique_ids(self.custom_fields.iter().map(|f| f.id))?;
        for field in &self.custom_fields {
            field.validate_for_write()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum UrlMatch {
    Exact,
    Origin,
    Unknown(String),
}

impl From<String> for UrlMatch {
    fn from(value: String) -> Self {
        match value.as_str() {
            "exact" => Self::Exact,
            "origin" => Self::Origin,
            _ => Self::Unknown(value),
        }
    }
}

impl From<UrlMatch> for String {
    fn from(value: UrlMatch) -> Self {
        match value {
            UrlMatch::Exact => "exact".into(),
            UrlMatch::Origin => "origin".into(),
            UrlMatch::Unknown(value) => value,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdditionalUrl {
    pub id: Uuid,
    pub url: String,
    #[serde(rename = "match")]
    pub match_mode: UrlMatch,
    #[serde(flatten)]
    pub extra: ExtraProperties,
}

impl std::fmt::Debug for AdditionalUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdditionalUrl")
            .field("id", &self.id)
            .field("url", &"[REDACTED]")
            .field("match_mode", &self.match_mode)
            .finish_non_exhaustive()
    }
}

impl Drop for AdditionalUrl {
    fn drop(&mut self) {
        self.url.zeroize();
    }
}

impl AdditionalUrl {
    /// This validates storage only. It never authorizes a credential release.
    /// HTTP alternates are deferred until a scoped development policy exists.
    pub fn validate_for_write(&self) -> Result<()> {
        valid_id(self.id)?;
        if matches!(self.match_mode, UrlMatch::Unknown(_)) {
            return Err(ValidationError("Unsupported URL match mode is read-only"));
        }
        if self.url.len() > MAX_URL_BYTES || self.url.trim() != self.url {
            return Err(ValidationError(
                "Additional URL exceeds its size limit or has surrounding whitespace",
            ));
        }
        let parsed =
            url::Url::parse(&self.url).map_err(|_| ValidationError("Invalid additional URL"))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(ValidationError(
                "Additional URLs require HTTPS and must not contain credentials",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginDetails {
    #[serde(default)]
    pub additional_urls: Vec<AdditionalUrl>,
}

impl LoginDetails {
    pub fn validate_for_write(&self) -> Result<()> {
        if self.additional_urls.len() > MAX_ADDITIONAL_URLS {
            return Err(ValidationError("Too many additional URLs"));
        }
        unique_ids(self.additional_urls.iter().map(|u| u.id))?;
        for entry in &self.additional_urls {
            entry.validate_for_write()?;
        }
        Ok(())
    }
}

/// Contact fields are optional and are not country-specific requirements.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityDetails {
    pub middle_name: Option<String>,
    pub preferred_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub company: Option<String>,
    pub job_title: Option<String>,
    #[serde(default)]
    pub addresses: Vec<PostalAddress>,
    #[serde(flatten)]
    pub extra: ExtraProperties,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostalAddress {
    pub id: Uuid,
    pub label: Option<String>,
    pub line1: Option<String>,
    pub line2: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country_code: Option<String>,
    #[serde(flatten)]
    pub extra: ExtraProperties,
}

macro_rules! redact_debug {
    ($($ty:ty),+) => {$(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([REDACTED])"))
            }
        }
    )+};
}
redact_debug!(IdentityDetails, PostalAddress);

impl Drop for IdentityDetails {
    fn drop(&mut self) {
        self.middle_name.zeroize();
        self.preferred_name.zeroize();
        self.email.zeroize();
        self.phone.zeroize();
        self.company.zeroize();
        self.job_title.zeroize();
    }
}

impl Drop for PostalAddress {
    fn drop(&mut self) {
        self.label.zeroize();
        self.line1.zeroize();
        self.line2.zeroize();
        self.city.zeroize();
        self.region.zeroize();
        self.postal_code.zeroize();
        self.country_code.zeroize();
    }
}

impl IdentityDetails {
    pub fn validate_for_write(&self) -> Result<()> {
        if self.addresses.len() > MAX_ADDRESSES {
            return Err(ValidationError("Too many addresses"));
        }
        unique_ids(self.addresses.iter().map(|a| a.id))?;
        let contacts = [
            &self.middle_name,
            &self.preferred_name,
            &self.email,
            &self.phone,
            &self.company,
            &self.job_title,
        ];
        for value in contacts {
            bounded_optional(value)?;
        }
        for address in &self.addresses {
            for value in [
                &address.label,
                &address.line1,
                &address.line2,
                &address.city,
                &address.region,
                &address.postal_code,
                &address.country_code,
            ] {
                bounded_optional(value)?;
            }
        }
        Ok(())
    }
}

fn bounded_optional(value: &Option<String>) -> Result<()> {
    if value
        .as_ref()
        .is_some_and(|v| v.len() > MAX_CUSTOM_VALUE_BYTES)
    {
        return Err(ValidationError("Identity field exceeds its size limit"));
    }
    Ok(())
}

fn valid_id(id: Uuid) -> Result<()> {
    if id.is_nil() {
        return Err(ValidationError("An ID must not be nil"));
    }
    Ok(())
}

fn unique_ids(ids: impl IntoIterator<Item = Uuid>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for id in ids {
        valid_id(id)?;
        if !seen.insert(id) {
            return Err(ValidationError("Duplicate ID"));
        }
    }
    Ok(())
}

pub fn normalized_name(name: &str) -> Result<String> {
    let name: String = name.trim().nfc().collect();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(ValidationError(
            "Name must contain 1–128 characters without control characters",
        ));
    }
    Ok(name)
}

fn name_key(name: &str) -> String {
    name.nfc().case_fold().nfc().collect()
}

/// Logical revision comparison never depends on wall-clock accuracy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRevision {
    pub counter: u64,
    pub device_id: String,
}

impl OrganizationRevision {
    fn validate(&self) -> Result<()> {
        if self.counter == 0 || self.device_id.trim().is_empty() {
            return Err(ValidationError("Invalid organization revision"));
        }
        Ok(())
    }

    fn next(&self, device_id: &str) -> Result<Self> {
        if device_id.trim().is_empty() {
            return Err(ValidationError("Writer device ID is required"));
        }
        let counter = self
            .counter
            .checked_add(1)
            .ok_or(ValidationError("Organization revision overflow"))?;
        Ok(Self {
            counter,
            device_id: device_id.into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub revision: OrganizationRevision,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(flatten)]
    pub extra: ExtraProperties,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tag {
    pub id: Uuid,
    pub name: String,
    pub revision: OrganizationRevision,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(flatten)]
    pub extra: ExtraProperties,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationKind {
    Folder,
    Tag,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrganizationTombstone {
    pub kind: OrganizationKind,
    pub id: Uuid,
}

/// Organization arrays live in the encrypted envelope, not in credential items.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationData {
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub tags: Vec<Tag>,
    #[serde(default)]
    pub organization_tombstones: Vec<OrganizationTombstone>,
}

impl OrganizationData {
    pub fn folder(&self, id: Uuid) -> Option<&Folder> {
        if self.is_deleted(OrganizationKind::Folder, id) {
            return None;
        }
        self.folders.iter().find(|f| f.id == id)
    }

    pub fn tag(&self, id: Uuid) -> Option<&Tag> {
        if self.is_deleted(OrganizationKind::Tag, id) {
            return None;
        }
        self.tags.iter().find(|t| t.id == id)
    }

    fn is_deleted(&self, kind: OrganizationKind, id: Uuid) -> bool {
        self.organization_tombstones
            .iter()
            .any(|t| t.kind == kind && t.id == id)
    }

    pub fn create_folder(
        &mut self,
        name: &str,
        parent_id: Option<Uuid>,
        device: &str,
        now: DateTime<Utc>,
    ) -> Result<Uuid> {
        let name = normalized_name(name)?;
        self.check_folder_name(&name, parent_id, None)?;
        let revision = OrganizationRevision {
            counter: 0,
            device_id: String::new(),
        }
        .next(device)?;
        let id = Uuid::new_v4();
        self.check_parent(id, parent_id)?;
        self.folders.push(Folder {
            id,
            name,
            parent_id,
            revision,
            created_at: now,
            updated_at: now,
            extra: BTreeMap::new(),
        });
        Ok(id)
    }

    pub fn rename_folder(
        &mut self,
        id: Uuid,
        name: &str,
        device: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let existing = self.folder(id).ok_or(ValidationError("Folder not found"))?;
        let name = normalized_name(name)?;
        self.check_folder_name(&name, existing.parent_id, Some(id))?;
        let revision = existing.revision.next(device)?;
        let record = self
            .folders
            .iter_mut()
            .find(|f| f.id == id)
            .ok_or(ValidationError("Folder not found"))?;
        record.name = name;
        record.revision = revision;
        record.updated_at = now;
        Ok(())
    }

    pub fn move_folder(
        &mut self,
        id: Uuid,
        parent: Option<Uuid>,
        device: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let existing = self.folder(id).ok_or(ValidationError("Folder not found"))?;
        self.check_folder_name(&existing.name, parent, Some(id))?;
        self.check_parent(id, parent)?;
        // Include the moving subtree when checking the maximum depth.
        let parents = self.display_parents();
        for descendant in parents.keys() {
            let mut cursor = Some(*descendant);
            let mut depth = 0;
            while let Some(node) = cursor {
                depth += 1;
                cursor = if node == id {
                    parent
                } else {
                    parents.get(&node).copied().flatten()
                };
                if depth > MAX_FOLDER_DEPTH {
                    return Err(ValidationError("Folder nesting limit exceeded"));
                }
            }
        }
        let revision = existing.revision.next(device)?;
        let record = self
            .folders
            .iter_mut()
            .find(|f| f.id == id)
            .ok_or(ValidationError("Folder not found"))?;
        record.parent_id = parent;
        record.revision = revision;
        record.updated_at = now;
        Ok(())
    }

    fn check_folder_name(
        &self,
        name: &str,
        parent: Option<Uuid>,
        except: Option<Uuid>,
    ) -> Result<()> {
        let key = name_key(name);
        if self.folders.iter().any(|f| {
            Some(f.id) != except
                && f.parent_id == parent
                && !self.is_deleted(OrganizationKind::Folder, f.id)
                && name_key(&f.name) == key
        }) {
            return Err(ValidationError("A sibling folder already has this name"));
        }
        Ok(())
    }

    fn check_parent(&self, id: Uuid, parent: Option<Uuid>) -> Result<()> {
        let parents = self.display_parents();
        let mut cursor = parent;
        let mut depth = 1;
        while let Some(node) = cursor {
            if node == id {
                return Err(ValidationError(
                    "A folder cannot be moved into its own subtree",
                ));
            }
            if self.folder(node).is_none() {
                return Err(ValidationError("Parent folder not found"));
            }
            depth += 1;
            if depth > MAX_FOLDER_DEPTH {
                return Err(ValidationError("Folder nesting limit exceeded"));
            }
            cursor = parents.get(&node).copied().flatten();
        }
        Ok(())
    }

    pub fn create_tag(&mut self, name: &str, device: &str, now: DateTime<Utc>) -> Result<Uuid> {
        let name = normalized_name(name)?;
        self.check_tag_name(&name, None)?;
        let revision = OrganizationRevision {
            counter: 0,
            device_id: String::new(),
        }
        .next(device)?;
        let id = Uuid::new_v4();
        self.tags.push(Tag {
            id,
            name,
            revision,
            created_at: now,
            updated_at: now,
            extra: BTreeMap::new(),
        });
        Ok(id)
    }

    pub fn rename_tag(
        &mut self,
        id: Uuid,
        name: &str,
        device: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let name = normalized_name(name)?;
        self.check_tag_name(&name, Some(id))?;
        let revision = self
            .tag(id)
            .ok_or(ValidationError("Tag not found"))?
            .revision
            .next(device)?;
        let record = self
            .tags
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or(ValidationError("Tag not found"))?;
        record.name = name;
        record.revision = revision;
        record.updated_at = now;
        Ok(())
    }

    fn check_tag_name(&self, name: &str, except: Option<Uuid>) -> Result<()> {
        if self.tags.iter().any(|t| {
            Some(t.id) != except
                && !self.is_deleted(OrganizationKind::Tag, t.id)
                && name_key(&t.name) == name_key(name)
        }) {
            return Err(ValidationError("A tag already has this name"));
        }
        Ok(())
    }

    /// Caller must persist the organization and changed item assignments in one
    /// vault transaction. This method does not delete credential items.
    pub fn delete_folder(&mut self, id: Uuid, device: &str, now: DateTime<Utc>) -> Result<()> {
        self.folder(id).ok_or(ValidationError("Folder not found"))?;
        let parent = self.display_parents().get(&id).copied().flatten();
        // Preflight all child revisions before changing anything.
        let revisions: BTreeMap<_, _> = self
            .folders
            .iter()
            .filter(|f| f.parent_id == Some(id))
            .map(|f| Ok((f.id, f.revision.next(device)?)))
            .collect::<Result<_>>()?;
        if device.trim().is_empty() {
            return Err(ValidationError("Writer device ID is required"));
        }
        for child in &mut self.folders {
            if let Some(revision) = revisions.get(&child.id) {
                child.parent_id = parent;
                child.revision = revision.clone();
                child.updated_at = now;
            }
        }
        self.folders.retain(|f| f.id != id);
        self.organization_tombstones.push(OrganizationTombstone {
            kind: OrganizationKind::Folder,
            id,
        });
        Ok(())
    }

    pub fn delete_tag(&mut self, id: Uuid) -> Result<()> {
        self.tag(id).ok_or(ValidationError("Tag not found"))?;
        self.tags.retain(|t| t.id != id);
        self.organization_tombstones.push(OrganizationTombstone {
            kind: OrganizationKind::Tag,
            id,
        });
        Ok(())
    }

    /// Derive a usable tree without rewriting the winning records. Unknown
    /// parents become roots; break each cycle at its greatest UUID.
    pub fn display_parents(&self) -> BTreeMap<Uuid, Option<Uuid>> {
        let deleted: BTreeSet<_> = self
            .organization_tombstones
            .iter()
            .filter(|t| t.kind == OrganizationKind::Folder)
            .map(|t| t.id)
            .collect();
        let active: BTreeSet<_> = self
            .folders
            .iter()
            .filter(|f| !deleted.contains(&f.id))
            .map(|f| f.id)
            .collect();
        let mut parents: BTreeMap<_, _> = self
            .folders
            .iter()
            .filter(|f| active.contains(&f.id))
            .map(|f| (f.id, f.parent_id.filter(|p| active.contains(p))))
            .collect();
        let ids: Vec<_> = parents.keys().copied().collect();
        for id in ids {
            let mut path = Vec::new();
            let mut cursor = Some(id);
            while let Some(node) = cursor {
                if let Some(start) = path.iter().position(|n| *n == node) {
                    if let Some(greatest) = path[start..].iter().max() {
                        parents.insert(*greatest, None);
                    }
                    break;
                }
                path.push(node);
                cursor = parents.get(&node).copied().flatten();
            }
        }
        parents
    }

    /// Missing folder IDs resolve as Unfiled; missing tags are hidden. Custom
    /// fields are untouched, including future field types.
    pub fn repair_assignment(&self, item: &mut ItemOrganization) {
        item.folder_id = item.folder_id.filter(|id| self.folder(*id).is_some());
        item.tag_ids.retain(|id| self.tag(*id).is_some());
        let mut seen = BTreeSet::new();
        item.tag_ids.retain(|id| seen.insert(*id));
    }

    /// Pure, deterministic merge. Equal revisions with unequal payloads are
    /// rejected so a corrupt device cannot make merge order choose a winner.
    /// The original inputs are left intact on error.
    pub fn merged(&self, other: &Self) -> Result<Self> {
        let tombstones: BTreeSet<_> = self
            .organization_tombstones
            .iter()
            .chain(&other.organization_tombstones)
            .cloned()
            .collect();
        for tombstone in &tombstones {
            valid_id(tombstone.id)?;
        }
        let mut folders: BTreeMap<Uuid, Folder> = BTreeMap::new();
        let mut folder_revisions = BTreeMap::new();
        for folder in self.folders.iter().chain(&other.folders) {
            valid_id(folder.id)?;
            folder.revision.validate()?;
            if tombstones.contains(&OrganizationTombstone {
                kind: OrganizationKind::Folder,
                id: folder.id,
            }) {
                continue;
            }
            let key = (folder.id, folder.revision.clone());
            if let Some(previous) = folder_revisions.insert(key, folder) {
                if previous != folder {
                    return Err(ValidationError(
                        "Conflicting folder records have the same revision",
                    ));
                }
            }
            match folders.get(&folder.id) {
                Some(old) if old.revision == folder.revision && old != folder => {
                    return Err(ValidationError(
                        "Conflicting folder records have the same revision",
                    ))
                }
                Some(old) if old.revision >= folder.revision => {}
                _ => {
                    folders.insert(folder.id, folder.clone());
                }
            }
        }
        let mut tags: BTreeMap<Uuid, Tag> = BTreeMap::new();
        let mut tag_revisions = BTreeMap::new();
        for tag in self.tags.iter().chain(&other.tags) {
            valid_id(tag.id)?;
            tag.revision.validate()?;
            if tombstones.contains(&OrganizationTombstone {
                kind: OrganizationKind::Tag,
                id: tag.id,
            }) {
                continue;
            }
            let key = (tag.id, tag.revision.clone());
            if let Some(previous) = tag_revisions.insert(key, tag) {
                if previous != tag {
                    return Err(ValidationError(
                        "Conflicting tag records have the same revision",
                    ));
                }
            }
            match tags.get(&tag.id) {
                Some(old) if old.revision == tag.revision && old != tag => {
                    return Err(ValidationError(
                        "Conflicting tag records have the same revision",
                    ))
                }
                Some(old) if old.revision >= tag.revision => {}
                _ => {
                    tags.insert(tag.id, tag.clone());
                }
            }
        }
        Ok(Self {
            folders: folders.into_values().collect(),
            tags: tags.into_values().collect(),
            organization_tombstones: tombstones.into_iter().collect(),
        })
    }
}
