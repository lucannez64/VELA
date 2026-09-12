use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use uuid::Uuid;

fn default_created_at() -> DateTime<Utc> {
    Utc::now()
}

fn default_updated_at() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ItemType {
    Login,
    CreditCard,
    SecureNote,
    Identity,
    FileBlob,
    BreachMonitor,
    Passkey,
    Address,
    BankAccount,
    ApiKey,
    SshKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultMeta {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default = "default_created_at", alias = "created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_updated_at", alias = "updated_at")]
    pub updated_at: DateTime<Utc>,
    #[serde(default, alias = "last_modified_device")]
    pub last_modified_device: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    /// User-assigned tags, in canonical form (trimmed, deduplicated
    /// case-insensitively, sorted). Written by the item editor, merged by
    /// union during sync — see `vela-sync-policy`'s `merge_org_fields`.
    ///
    /// `#[serde(default)]` is the A-2 rule: a client that predates the field
    /// parses an item that has it, and re-serializes it without error, instead
    /// of failing to decode the vault at all.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Removal records for tags (§1.1). A tag deleted on one device must not
    /// come back when another device's stale copy still carries it: the
    /// merge suppresses union'd tags whose removal record is newer than the
    /// carrying copy's last edit. `#[serde(default, skip_serializing_if)]`
    /// is the A-2 rule, as for `tags` above; the alias accepts the
    /// snake_case spelling older drafts wrote.
    #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "tag_tombstones")]
    pub tag_tombstones: Vec<TagTombstone>,
    /// User-defined extra fields (§1.3), available on every item type.
    /// `#[serde(default, skip_serializing_if)]` is the A-2 rule; the alias
    /// tolerates the snake_case spelling.
    #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "custom_fields")]
    pub custom_fields: Vec<CustomField>,
    /// The single optional folder this item sits in, stored as the folder's
    /// *name*. A folder is not an entity — there is no folder list to sync,
    /// no schema beyond this field, and renaming a folder is a batch update of
    /// the items that carry the old name. Merged last-writer-wins on
    /// `updated_at`, like every other single-valued field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default, alias = "share_recipient")]
    pub share_recipient: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "item_type", rename_all = "camelCase")]
pub enum VaultItem {
    Login {
        #[serde(flatten)]
        meta: VaultMeta,
        url: String,
        username: String,
        #[serde(rename = "password")]
        pass: String,
        /// Previous password values, newest first (§1.3). Recorded by the
        /// editing clients when an edit changes the password; the live `pass`
        /// is never in here. A-2: an old client's JSON without the field
        /// parses with empty history, and it is only serialized when
        /// non-empty.
        #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "passwordHistory")]
        password_history: Vec<PasswordHistoryEntry>,
        #[serde(default)]
        totp: Option<String>,
        /// Mobile apps the user has linked to this login, as `androidapp://<package>`.
        ///
        /// A package name cannot be turned into a domain by rule — `com.ubercab`
        /// is not `ubercab.com`, and anyone can publish `com.paypal.anything` —
        /// so the association is recorded when the user confirms it, the way
        /// every other password manager does it (audit A-2). Defaulted and
        /// preserved on round trip so a client that predates the field does not
        /// silently drop someone's links.
        #[serde(default, alias = "appIds")]
        app_ids: Vec<String>,
        /// Does this site make you re-prove the old password before changing
        /// it? Set on desktop, where in-core login uses it to tell the user
        /// what a leaked session is worth (`m9a_in_core_login.spthy`'s
        /// `SiteMode`). Carried here for the same reason as `app_ids`: a field
        /// this client does not know is a field it deletes from every one of
        /// the user's devices on the next write (audit A-2).
        #[serde(default, skip_serializing_if = "Option::is_none",
                alias = "credentialChangeNeedsReauth")]
        credential_change_needs_reauth: Option<bool>,
        /// May a second-factor prompt be answered with this item's TOTP code
        /// when the site asked for something stronger (a security key)? Set on
        /// desktop by in-core login; carried here so a client that does not
        /// know the field does not delete it for every device (audit A-2).
        #[serde(default, skip_serializing_if = "Option::is_none",
                alias = "allowSecondFactorDowngrade")]
        allow_second_factor_downgrade: Option<bool>,
    },
    CreditCard {
        #[serde(flatten)]
        meta: VaultMeta,
        number: String,
        exp: String,
        cvv: String,
        #[serde(default)]
        pin: Option<String>,
        #[serde(default, alias = "cardholder_name")]
        cardholder_name: Option<String>,
    },
    SecureNote {
        #[serde(flatten)]
        meta: VaultMeta,
        title: String,
        content: String,
    },
    Identity {
        #[serde(flatten)]
        meta: VaultMeta,
        #[serde(alias = "first_name")]
        first_name: String,
        #[serde(alias = "last_name")]
        last_name: String,
        ssn: String,
    },
    FileBlob {
        #[serde(flatten)]
        meta: VaultMeta,
        #[serde(alias = "file_name")]
        filename: String,
        #[serde(alias = "mime_type")]
        mime: String,
        #[serde(default)]
        chunks: Vec<Uuid>,
    },
    BreachMonitor {
        #[serde(flatten)]
        meta: VaultMeta,
        email: String,
        #[serde(default, alias = "checked_at")]
        checked_at: Option<DateTime<Utc>>,
        #[serde(default, alias = "breach_count")]
        breach_count: u32,
        #[serde(default)]
        breaches: Vec<BreachEntry>,
    },
    /// A WebAuthn credential: one ES256 keypair scoped to one relying party.
    ///
    /// Unlike a [`VaultItem::Login`], the secret here is never released to
    /// anything — not to the browser, not to the page, not over IPC. It is used
    /// where it is stored, to sign one assertion at a time, and only the
    /// signature leaves. That is the whole point of the item type; see
    /// `security/formal/m7_oneshot_assertion.spthy` for the property it is
    /// meant to deliver (`credential_never_leaks`, which holds even for the
    /// credential in active use).
    Passkey {
        #[serde(flatten)]
        meta: VaultMeta,
        /// The relying party ID this credential is scoped to, e.g.
        /// `example.com`. An assertion is only ever produced for a request
        /// whose RP ID matches this exactly.
        #[serde(alias = "rpId")]
        rp_id: String,
        #[serde(default, alias = "rpName")]
        rp_name: String,
        /// Opaque credential ID, base64url. The relying party stores this and
        /// echoes it back in `allowCredentials`.
        #[serde(alias = "credentialId")]
        credential_id: String,
        /// The user handle the relying party knows this credential by,
        /// base64url.
        #[serde(default, alias = "userHandle")]
        user_handle: String,
        #[serde(default, alias = "userName")]
        user_name: String,
        #[serde(default, alias = "userDisplayName")]
        user_display_name: String,
        /// The ES256 private scalar, base64url. **The secret.**
        #[serde(alias = "privateKey")]
        private_key: String,
        /// WebAuthn signature counter. Incremented on every assertion so a
        /// relying party can spot a cloned authenticator.
        #[serde(default, alias = "signCount")]
        sign_count: u32,
    },
    /// A postal address (§1.3). Nothing here is secret-grade; it is stored
    /// for form-filling and reference, like the Identity type.
    Address {
        #[serde(flatten)]
        meta: VaultMeta,
        #[serde(default, alias = "fullName")]
        full_name: String,
        #[serde(default, alias = "street_address")]
        street: String,
        #[serde(default, alias = "street_line2")]
        street2: String,
        #[serde(default)]
        city: String,
        #[serde(default)]
        state: String,
        #[serde(default, alias = "postalCode", alias = "zip")]
        postal_code: String,
        #[serde(default)]
        country: String,
        #[serde(default)]
        phone: String,
    },
    /// A bank account (§1.3). `account_number` and `iban` are secrets:
    /// zeroized and redacted like every other credential value.
    BankAccount {
        #[serde(flatten)]
        meta: VaultMeta,
        #[serde(default, alias = "bankName")]
        bank_name: String,
        /// `checking`, `savings`, … — free text, the site's own vocabulary.
        #[serde(default, alias = "account_type")]
        account_kind: String,
        #[serde(default)]
        holder: String,
        #[serde(default, alias = "accountNumber")]
        account_number: String,
        #[serde(default, alias = "routingNumber")]
        routing_number: String,
        #[serde(default)]
        iban: String,
        #[serde(default)]
        swift: String,
    },
    /// An API credential (§1.3). `api_key` is a secret: it *does* leave the
    /// vault (the user pastes it into config), so it gets the password
    /// treatment — masked, copyable, zeroized on drop.
    ApiKey {
        #[serde(flatten)]
        meta: VaultMeta,
        /// Base URL of the service the key belongs to, if any.
        #[serde(default, alias = "base_url")]
        url: String,
        #[serde(default)]
        username: String,
        #[serde(default, alias = "apiKey")]
        api_key: String,
        /// Free-form expiry as the user recorded it ("2027-01", "never").
        #[serde(default, alias = "expires_at")]
        expires: Option<String>,
    },
    /// An SSH key pair (§1.3), stored for the CLI/SSH agent. The private key
    /// is a secret; the public key is not — it is the part the user pastes
    /// into `authorized_keys`, so it is the copyable display value.
    SshKey {
        #[serde(flatten)]
        meta: VaultMeta,
        /// `ed25519`, `rsa-4096`, `ecdsa-p256`, … — informational.
        #[serde(default, alias = "keyType")]
        kind: String,
        #[serde(default, alias = "publicKey")]
        public_key: String,
        #[serde(default, alias = "privateKey")]
        private_key: String,
        #[serde(default)]
        passphrase: String,
        #[serde(default)]
        comment: String,
    },
}

/// A user-defined extra field (§1.3), attachable to every item type.
///
/// `Hidden` values are secrets: they zeroize like passwords and print
/// `[REDACTED]` from `Debug`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CustomFieldType {
    Text,
    Hidden,
}

impl Default for CustomFieldType {
    fn default() -> Self {
        CustomFieldType::Text
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub label: String,
    #[serde(default)]
    pub value: String,
    #[serde(default, alias = "field_type")]
    pub field_type: CustomFieldType,
}

/// A previous password value (§1.3), recorded when an edit changes a login's
/// password. Old passwords are still secrets — they may still work on the
/// site or on other sites the user reused them on — so they zeroize and
/// redact exactly like the live one.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordHistoryEntry {
    #[serde(rename = "password")]
    pub value: String,
    #[serde(default = "default_created_at", alias = "changedAt")]
    pub changed_at: DateTime<Utc>,
}

/// Redacted `Debug`, because the derived one printed the secrets.
///
/// A single `tracing::debug!("{item:?}")` anywhere — in this crate, in a
/// consumer, in a test someone leaves in — put passwords, card numbers, CVVs and
/// SSNs into a log file. Logs get shipped, attached to bug reports and read by
/// people who are not the vault's owner, so the fix is at the type: there is no
/// formatting of a `VaultItem` that reveals a secret, whoever writes it (audit,
/// crypto hardening).
///
/// The non-secret metadata is kept — an item you cannot identify is useless to
/// debug with.
impl VaultItem {
    /// Wipe the secret fields in place.
    ///
    /// Called from `Drop`, so every path that lets an item go — locking the
    /// vault, replacing the store after a sync, a temporary clone falling out of
    /// scope — clears the plaintext rather than handing the allocator a buffer
    /// that still holds a password. That is the whole point of doing it in
    /// `Drop` and not at chosen call sites: the ones you forget are exactly the
    /// ones that matter.
    ///
    /// Only the secrets. Names, URLs and usernames are not wiped: they are not
    /// what this protects, and zeroing them would cost on every drop for nothing.
    fn zeroize_secrets(&mut self) {
        use zeroize::Zeroize;
        // Custom fields live on the meta shared by every variant; a hidden
        // field's value is a secret exactly like the variant secrets below.
        let hidden_custom = &mut self.meta_mut().custom_fields;
        for field in hidden_custom.iter_mut() {
            if field.field_type == CustomFieldType::Hidden {
                field.value.zeroize();
            }
        }
        match self {
            VaultItem::Login { pass, totp, password_history, .. } => {
                pass.zeroize();
                if let Some(totp) = totp {
                    totp.zeroize();
                }
                // An old password may still work somewhere; the history is
                // wiped with the same rigor as the live value.
                for entry in password_history.iter_mut() {
                    entry.value.zeroize();
                }
            }
            VaultItem::CreditCard { number, cvv, pin, .. } => {
                number.zeroize();
                cvv.zeroize();
                if let Some(pin) = pin {
                    pin.zeroize();
                }
            }
            VaultItem::SecureNote { content, .. } => content.zeroize(),
            VaultItem::Identity { ssn, .. } => ssn.zeroize(),
            VaultItem::Passkey { private_key, .. } => private_key.zeroize(),
            VaultItem::BankAccount { account_number, iban, .. } => {
                account_number.zeroize();
                iban.zeroize();
            }
            VaultItem::ApiKey { api_key, .. } => api_key.zeroize(),
            VaultItem::SshKey { private_key, passphrase, .. } => {
                private_key.zeroize();
                if !passphrase.is_empty() {
                    passphrase.zeroize();
                }
            }
            // Nothing secret: a file blob's bytes live in chunks, a breach
            // monitor holds an address the user already published, and an
            // address item is reference data by design.
            VaultItem::FileBlob { .. } | VaultItem::BreachMonitor { .. } | VaultItem::Address { .. } => {}
        }
    }
}

impl Drop for VaultItem {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

impl std::fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &str = "[REDACTED]";
        let mut out = f.debug_struct("VaultItem");
        out.field("kind", &self.item_type())
            .field("id", &self.id())
            .field("name", &self.name())
            .field("folder", &self.folder())
            .field("tags", &self.tags())
            .field("custom_fields", &self.redacted_custom_fields())
            .field("password_history_len", &self.password_history().map(|h| h.len()));
        match self {
            VaultItem::Login { url, username, totp, .. } => {
                out.field("url", url)
                    .field("username", username)
                    .field("password", &REDACTED)
                    // Whether a login *has* a TOTP secret is metadata; the seed
                    // is not.
                    .field("totp", &totp.as_ref().map(|_| REDACTED));
            }
            VaultItem::CreditCard { exp, .. } => {
                out.field("number", &REDACTED)
                    .field("exp", exp)
                    .field("cvv", &REDACTED)
                    .field("pin", &REDACTED);
            }
            VaultItem::SecureNote { .. } => {
                out.field("content", &REDACTED);
            }
            VaultItem::Identity { first_name, last_name, .. } => {
                out.field("first_name", first_name)
                    .field("last_name", last_name)
                    .field("ssn", &REDACTED);
            }
            VaultItem::FileBlob { filename, mime, .. } => {
                out.field("filename", filename).field("mime", mime);
            }
            VaultItem::BreachMonitor { email, breach_count, .. } => {
                out.field("email", email).field("breach_count", breach_count);
            }
            VaultItem::Passkey { rp_id, user_name, sign_count, .. } => {
                out.field("rp_id", rp_id)
                    .field("user_name", user_name)
                    .field("sign_count", sign_count)
                    .field("private_key", &REDACTED);
            }
            VaultItem::Address { full_name, city, country, .. } => {
                out.field("full_name", full_name)
                    .field("city", city)
                    .field("country", country);
            }
            VaultItem::BankAccount { bank_name, holder, .. } => {
                out.field("bank_name", bank_name)
                    .field("holder", holder)
                    .field("account_number", &REDACTED)
                    .field("iban", &REDACTED);
            }
            VaultItem::ApiKey { url, username, .. } => {
                out.field("url", url)
                    .field("username", username)
                    .field("api_key", &REDACTED);
            }
            VaultItem::SshKey { kind, comment, .. } => {
                out.field("kind", kind)
                    .field("comment", comment)
                    .field("private_key", &REDACTED)
                    .field("passphrase", &REDACTED);
            }
        }
        out.finish()
    }
}


/// Record of a deleted item, propagated via sync so that deletions
/// are honoured on all devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    pub id: String,
    #[serde(default = "default_created_at")]
    pub deleted_at: DateTime<Utc>,
    #[serde(default)]
    pub deleted_by: Option<String>,
}

/// A recorded tag removal, carried inside the item so the sync merge can
/// tell "this tag was removed at T" apart from "this copy never had the
/// tag" — without it, plain union resurrects a removed tag on every merge
/// with a stale copy. `tag` is the canonical key (lowercased, trimmed); the
/// display spelling lives in `tags` while the tag exists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagTombstone {
    pub tag: String,
    #[serde(default = "default_created_at")]
    pub deleted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BreachEntry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub breach_date: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub data_classes: Vec<String>,
    #[serde(default)]
    pub is_verified: bool,
    #[serde(default)]
    pub is_fabricated: bool,
    #[serde(default)]
    pub is_sensitive: bool,
    #[serde(default)]
    pub is_retired: bool,
    #[serde(default)]
    pub is_spam_list: bool,
}

impl VaultItem {
    fn meta(&self) -> &VaultMeta {
        match self {
            VaultItem::Login { meta, .. }
            | VaultItem::CreditCard { meta, .. }
            | VaultItem::SecureNote { meta, .. }
            | VaultItem::Identity { meta, .. }
            | VaultItem::FileBlob { meta, .. }
            | VaultItem::BreachMonitor { meta, .. }
            | VaultItem::Passkey { meta, .. }
            | VaultItem::Address { meta, .. }
            | VaultItem::BankAccount { meta, .. }
            | VaultItem::ApiKey { meta, .. }
            | VaultItem::SshKey { meta, .. } => meta,
        }
    }

    fn meta_mut(&mut self) -> &mut VaultMeta {
        match self {
            VaultItem::Login { meta, .. }
            | VaultItem::CreditCard { meta, .. }
            | VaultItem::SecureNote { meta, .. }
            | VaultItem::Identity { meta, .. }
            | VaultItem::FileBlob { meta, .. }
            | VaultItem::BreachMonitor { meta, .. }
            | VaultItem::Passkey { meta, .. }
            | VaultItem::Address { meta, .. }
            | VaultItem::BankAccount { meta, .. }
            | VaultItem::ApiKey { meta, .. }
            | VaultItem::SshKey { meta, .. } => meta,
        }
    }

    /// Replaces the tags with `tags`, canonicalized the same way
    /// `vela-sync-policy`'s `normalize_tags` does, so a client that writes
    /// tags through this crate stores exactly the bytes the desktop sync
    /// merge would produce.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.meta_mut().tags = {
            let mut by_key: std::collections::BTreeMap<String, String> = Default::default();
            for tag in tags {
                let trimmed = tag.trim();
                if trimmed.is_empty() {
                    continue;
                }
                by_key
                    .entry(trimmed.to_lowercase())
                    .or_insert_with(|| trimmed.to_string());
            }
            by_key.into_values().collect()
        };
        self
    }

    /// Sets or clears the folder; `None` and `Some("")` both mean "none".
    pub fn with_folder(mut self, folder: Option<String>) -> Self {
        self.meta_mut().folder = folder
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty());
        self
    }

    pub fn id(&self) -> &str {
        &self.meta().id
    }

    pub fn name(&self) -> &str {
        &self.meta().name
    }

    pub fn item_type(&self) -> ItemType {
        match self {
            VaultItem::Login { .. } => ItemType::Login,
            VaultItem::CreditCard { .. } => ItemType::CreditCard,
            VaultItem::SecureNote { .. } => ItemType::SecureNote,
            VaultItem::Identity { .. } => ItemType::Identity,
            VaultItem::FileBlob { .. } => ItemType::FileBlob,
            VaultItem::BreachMonitor { .. } => ItemType::BreachMonitor,
            VaultItem::Passkey { .. } => ItemType::Passkey,
            VaultItem::Address { .. } => ItemType::Address,
            VaultItem::BankAccount { .. } => ItemType::BankAccount,
            VaultItem::ApiKey { .. } => ItemType::ApiKey,
            VaultItem::SshKey { .. } => ItemType::SshKey,
        }
    }

    /// Deliberately `None` for a passkey.
    ///
    /// This is what password autofill matches on, and a passkey has no password
    /// to fill — surfacing one here would offer it as a credential to paste into
    /// a form. Passkeys are looked up by relying party via [`VaultItem::rp_id`].
    pub fn url(&self) -> Option<&str> {
        match self {
            VaultItem::Login { url, .. } => Some(url),
            _ => None,
        }
    }

    /// The relying party this item is scoped to, for passkeys only.
    pub fn rp_id(&self) -> Option<&str> {
        match self {
            VaultItem::Passkey { rp_id, .. } => Some(rp_id),
            _ => None,
        }
    }

    pub fn username(&self) -> Option<&str> {
        match self {
            VaultItem::Login { username, .. } => Some(username),
            VaultItem::Identity { first_name, .. } => Some(first_name),
            VaultItem::Passkey { user_name, .. } => Some(user_name),
            _ => None,
        }
    }

    pub fn password(&self) -> Option<&str> {
        match self {
            VaultItem::Login { pass, .. } => Some(pass),
            _ => None,
        }
    }

    pub fn notes(&self) -> Option<&str> {
        self.meta().notes.as_deref()
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.meta().created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.meta().updated_at
    }

    /// The item's tags, in canonical form.
    pub fn tags(&self) -> &[String] {
        &self.meta().tags
    }

    /// The user-defined extra fields (§1.3), on every item type.
    pub fn custom_fields(&self) -> &[CustomField] {
        &self.meta().custom_fields
    }

    /// The previous password values (§1.3), newest first — logins only.
    pub fn password_history(&self) -> Option<&[PasswordHistoryEntry]> {
        match self {
            VaultItem::Login { password_history, .. } => Some(password_history),
            _ => None,
        }
    }

    /// Redacted `(label, value)` pairs for `Debug`: hidden custom fields
    /// print as `[REDACTED]`, text fields as themselves.
    fn redacted_custom_fields(&self) -> Vec<(&str, &str)> {
        self.meta()
            .custom_fields
            .iter()
            .map(|f| {
                let value = if f.field_type == CustomFieldType::Hidden {
                    "[REDACTED]"
                } else {
                    f.value.as_str()
                };
                (f.label.as_str(), value)
            })
            .collect()
    }

    /// The folder this item sits in, if any.
    pub fn folder(&self) -> Option<&str> {
        self.meta().folder.as_deref()
    }
}

/// An item sitting in the trash (§1.2) — see the desktop core's
/// `DeletedItem`. This crate only carries the field through round-trips.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeletedItem {
    pub item: VaultItem,
    #[serde(default = "default_created_at")]
    pub deleted_at: DateTime<Utc>,
    #[serde(default)]
    pub deleted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "VaultStoreRepr")]
pub struct VaultStore {
    pub items: Vec<VaultItem>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    /// The trash (§1.2). This crate never writes it — the desktop owns
    /// delete/restore — but the field is defaulted and re-serialized so a
    /// store that round-trips through the web vault does not strip another
    /// client's trash (the A-2 rule).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deleted_items: Vec<DeletedItem>,
    #[serde(skip, default = "HashMap::new")]
    item_index: HashMap<String, usize>,
}

/// Two stores hold the same vault when they hold the same items and tombstones.
///
/// Derived, `item_index` counted: a store just read off disk compared unequal
/// to the identical store built by `add_item`, purely because one had had its
/// index built and the other had not. The index is derived state, so it is not
/// part of the value.
impl PartialEq for VaultStore {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items
            && self.tombstones == other.tombstones
            && self.deleted_items == other.deleted_items
    }
}

/// The wire shape of a `VaultStore`, so that deserializing one also builds its
/// lookup index.
///
/// `item_index` is `#[serde(skip)]`, so a store read back from storage or off
/// the sync wire arrived with an empty index and kept it until the first
/// mutation — every `get_item` before that was a linear scan of the whole
/// vault. Building it here costs one pass at load and makes the lookups after
/// it O(1).
#[derive(Deserialize)]
struct VaultStoreRepr {
    items: Vec<VaultItem>,
    #[serde(default)]
    tombstones: Vec<Tombstone>,
    #[serde(default)]
    deleted_items: Vec<DeletedItem>,
}

impl From<VaultStoreRepr> for VaultStore {
    fn from(repr: VaultStoreRepr) -> Self {
        let mut store = Self {
            items: repr.items,
            tombstones: repr.tombstones,
            deleted_items: repr.deleted_items,
            item_index: HashMap::new(),
        };
        store.reindex();
        store
    }
}

impl Default for VaultStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultStore {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            tombstones: Vec::new(),
            deleted_items: Vec::new(),
            item_index: HashMap::new(),
        }
    }

    fn reindex(&mut self) {
        self.item_index.clear();
        self.item_index.reserve(self.items.len());
        for (i, item) in self.items.iter().enumerate() {
            self.item_index.insert(item.id().to_string(), i);
        }
    }

    /// Rebuild the index whenever it can no longer describe `items`.
    ///
    /// "The index is empty" was never a sufficient staleness test: `items` is
    /// public, so a caller that replaces it wholesale left the index holding the
    /// *old* positions and `get_item` handed back whichever item had moved into
    /// that slot. Comparing lengths catches a wholesale replacement, and
    /// `get_item` re-checks the id at the position it lands on for the rest.
    fn ensure_index(&mut self) {
        if self.item_index.len() != self.items.len() {
            self.reindex();
        }
    }

    pub fn add_item(&mut self, item: VaultItem) {
        self.ensure_index();
        let id = item.id().to_string();
        let idx = self.items.len();
        self.items.push(item);
        self.item_index.insert(id, idx);
    }

    pub fn update_item(&mut self, item: VaultItem) {
        self.ensure_index();
        let id = item.id().to_string();
        if let Some(&idx) = self.item_index.get(&id) {
            self.items[idx] = item;
        } else if let Some(existing) = self.items.iter_mut().find(|i| i.id() == id) {
            *existing = item;
            self.reindex();
            return;
        } else {
            self.add_item(item);
            return;
        }
    }

    pub fn delete_item(&mut self, id: &str, device_id: Option<&str>) {
        self.ensure_index();
        if let Some(idx) = self.item_index.remove(id) {
            self.items.remove(idx);
            // Only the entries after the hole moved. A full `reindex()` here
            // re-hashed and re-allocated the id of every item in the vault on
            // every single delete.
            for position in self.item_index.values_mut() {
                if *position > idx {
                    *position -= 1;
                }
            }
        } else {
            self.items.retain(|item| item.id() != id);
        }
        self.tombstones.push(Tombstone {
            id: id.to_string(),
            deleted_at: Utc::now(),
            deleted_by: device_id.map(ToOwned::to_owned),
        });
    }

    pub fn get_item(&self, id: &str) -> Option<&VaultItem> {
        if let Some(&idx) = self.item_index.get(id) {
            // The index is only refreshed on the `&mut self` paths, so a caller
            // that wrote straight into the public `items` vector can leave it
            // pointing at the wrong slot; trust it only when the id still
            // matches, and fall back to the scan when it does not.
            if let Some(item) = self.items.get(idx) {
                if item.id() == id {
                    return Some(item);
                }
            }
        }
        self.items.iter().find(|item| item.id() == id)
    }

    pub fn search(&self, query: &str) -> Vec<&VaultItem> {
        let query_lower = query.to_lowercase();
        self.items
            .iter()
            .filter(|item| {
                item.name().to_lowercase().contains(&query_lower)
                    || item
                        .username()
                        .is_some_and(|u| u.to_lowercase().contains(&query_lower))
                    || item
                        .url()
                        .is_some_and(|u| u.to_lowercase().contains(&query_lower))
                    || item
                        .notes()
                        .is_some_and(|n| n.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    pub fn search_by_domain(&self, base_domain: &str) -> Vec<&VaultItem> {
        if base_domain.trim().is_empty() {
            return Vec::new();
        }

        // Parsed once instead of once per item: the query side of `urls_match`
        // re-lowercased the domain, re-parsed it as a URL and re-ran the
        // public-suffix lookup for every entry in the vault, on the path
        // autofill hits for each page load.
        let query = DomainQuery::new(base_domain);
        self.items
            .iter()
            .filter(|item| {
                item.item_type() == ItemType::Login
                    && item.url().is_some_and(|url| query.matches(url))
            })
            .collect()
    }
}

/// The pre-parsed left-hand side of a URL match: everything `urls_match` used
/// to recompute for the query on each candidate it was handed.
struct DomainQuery {
    host: String,
    port: Option<u16>,
    is_ip: bool,
    registrable_domain: Option<String>,
}

impl DomainQuery {
    fn new(url: &str) -> Self {
        let lowered = to_lowercase_cow(url);
        let (host, port) = extract_host_and_port(&lowered);
        let host = normalize_host(&host).into_owned();
        Self {
            is_ip: is_ip_address(&host),
            registrable_domain: psl::domain_str(&host).map(str::to_string),
            host,
            port,
        }
    }

    fn matches(&self, stored_url: &str) -> bool {
        let lowered = to_lowercase_cow(stored_url);
        let (stored_host, stored_port) = extract_host_and_port(&lowered);
        let stored_host = normalize_host(&stored_host);

        if let (Some(query_port), Some(stored_port)) = (self.port, stored_port) {
            if query_port != stored_port {
                return false;
            }
        }

        if self.host == stored_host.as_ref() {
            return true;
        }

        if self.is_ip || is_ip_address(&stored_host) {
            return false;
        }

        let (Some(query_domain), Some(stored_domain)) = (
            self.registrable_domain.as_deref(),
            psl::domain_str(&stored_host),
        ) else {
            return false;
        };

        query_domain == stored_domain && is_subdomain_of(&self.host, &stored_host)
    }
}

/// `host.ends_with(&format!(".{suffix}"))`, without building the string.
fn is_subdomain_of(host: &str, suffix: &str) -> bool {
    let host = host.as_bytes();
    let suffix = suffix.as_bytes();
    let Some(dot) = host.len().checked_sub(suffix.len() + 1) else {
        return false;
    };
    host[dot] == b'.' && &host[dot + 1..] == suffix
}

/// Lowercase only when it changes something, so the common already-lowercase
/// URL is borrowed rather than copied.
fn to_lowercase_cow(s: &str) -> Cow<'_, str> {
    if s.is_ascii() && !s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.to_lowercase())
    }
}

/// Split `url` into host and port without going through the full URL parser.
///
/// `search_by_domain` parses one URL per login on every autofill lookup, and
/// `url::Url::parse` — scheme handling, percent-decoding, IDNA — dominated that
/// scan. `None` means "not obviously simple": userinfo, IPv6 literals,
/// percent-encoding, backslashes, whitespace, non-ASCII and anything the parser
/// would rewrite fall through to it, so it stays the authority on what those
/// mean. Callers pass an already-lowercased URL.
fn extract_host_and_port_fast(url: &str) -> Option<(&str, Option<u16>)> {
    if !url.is_ascii() {
        return None;
    }

    // `url::Url` elides a scheme's default port, so this has to as well.
    let (rest, default_port) = if let Some(rest) = url.strip_prefix("https://") {
        (rest, 443)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (rest, 80)
    } else {
        // The slow path prepends `https://` to a bare host, so that is the
        // scheme this would have been parsed under.
        (url, 443)
    };

    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
        None => (authority, None),
    };

    // Only hosts the parser would hand back unchanged. The last label must
    // start with a letter, which is what keeps the parser's IPv4 rewriting
    // (`0x7f.1`, `127.1`, `2130706433`) out of the fast path.
    let last_label = host.rsplit('.').find(|label| !label.is_empty())?;
    if !last_label.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }

    Some((host, port.filter(|p| *p != default_port)))
}

fn extract_host_and_port(url: &str) -> (Cow<'_, str>, Option<u16>) {
    let url = url.trim();

    if let Some((host, port)) = extract_host_and_port_fast(url) {
        return (Cow::Borrowed(host), port);
    }

    let parsed = if url.starts_with("http://") || url.starts_with("https://") {
        url::Url::parse(url).ok()
    } else {
        url::Url::parse(&format!("https://{url}")).ok()
    };

    if let Some(parsed) = parsed {
        return (
            Cow::Owned(parsed.host_str().unwrap_or("").to_string()),
            parsed.port(),
        );
    }

    if let Some(colon_pos) = url.rfind(':') {
        if let Ok(port) = url[colon_pos + 1..].parse::<u16>() {
            return (Cow::Borrowed(&url[..colon_pos]), Some(port));
        }
    }

    (Cow::Borrowed(url), None)
}

fn is_ip_address(host: &str) -> bool {
    host.split('.').all(|part| part.parse::<u8>().is_ok())
}

fn normalize_host(host: &str) -> Cow<'_, str> {
    to_lowercase_cow(host.trim_matches('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(id: &str, url: &str, username: &str) -> VaultItem {
        let now = Utc::now();
        VaultItem::Login {
            meta: VaultMeta {
                id: id.to_string(),
                name: url.to_string(),
                notes: Some("note".to_string()),
                created_at: now,
                updated_at: now,
                last_modified_device: None,
                favorite: false,
                tags: Vec::new(),
                tag_tombstones: Vec::new(),
                custom_fields: Vec::new(),
                folder: None,
                shared: false,
                share_recipient: None,
            },
            url: url.to_string(),
            username: username.to_string(),
            pass: "secret".to_string(),
            totp: None,
            app_ids: Vec::new(),
            password_history: Vec::new(),
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
        }
    }

    /// Wiping an item in place clears every secret field, so a dropped item
    /// does not leave its password behind in freed heap memory (audit, crypto
    /// hardening: plaintext `String`s lacked `Zeroize`).
    #[test]
    fn zeroizing_an_item_clears_every_secret_field() {
        let now = Utc::now();
        let meta = |id: &str| VaultMeta {
            id: id.to_string(),
            name: "Bank".into(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            tags: Vec::new(),
            tag_tombstones: Vec::new(),
            custom_fields: Vec::new(),
            folder: None,
            shared: false,
            share_recipient: None,
        };

        let mut login_item = VaultItem::Login {
            meta: meta("1"),
            url: "https://bank.example".into(),
            username: "ada".into(),
            pass: "hunter2-SECRET".into(),
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            app_ids: Vec::new(),
            password_history: Vec::new(),
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
        };
        login_item.zeroize_secrets();
        let VaultItem::Login { pass, totp, username, .. } = &login_item else {
            panic!("wrong variant");
        };
        assert!(
            pass.as_bytes().iter().all(|&b| b == 0),
            "the password must be wiped"
        );
        assert!(
            totp.as_ref().expect("totp kept").bytes().all(|b| b == 0),
            "the TOTP seed must be wiped"
        );
        assert_eq!(username, "ada", "non-secret metadata is not wiped");

        let mut card = VaultItem::CreditCard {
            meta: meta("2"),
            number: "4111111111111111".into(),
            exp: "12/30".into(),
            cvv: "123".into(),
            pin: Some("9876".into()),
            cardholder_name: None,
        };
        card.zeroize_secrets();
        let VaultItem::CreditCard { number, cvv, pin, exp, .. } = &card else {
            panic!("wrong variant");
        };
        assert!(number.bytes().all(|b| b == 0), "the PAN must be wiped");
        assert!(cvv.bytes().all(|b| b == 0), "the CVV must be wiped");
        assert!(
            pin.as_ref().expect("pin kept").bytes().all(|b| b == 0),
            "the PIN must be wiped"
        );
        assert_eq!(exp, "12/30", "non-secret metadata is not wiped");
    }

    #[test]
    fn debug_never_prints_a_secret() {
        let now = Utc::now();
        let meta = |id: &str| VaultMeta {
            id: id.to_string(),
            name: "Bank".into(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            tags: Vec::new(),
            tag_tombstones: Vec::new(),
            custom_fields: Vec::new(),
            folder: None,
            shared: false,
            share_recipient: None,
        };

        let items = vec![
            VaultItem::Login {
                meta: meta("1"),
                url: "https://bank.example".into(),
                username: "ada".into(),
                pass: "hunter2-SECRET".into(),
                totp: Some("JBSWY3DPEHPK3PXP".into()),
                app_ids: Vec::new(),
                password_history: Vec::new(),
                credential_change_needs_reauth: None,
                allow_second_factor_downgrade: None,
            },
            VaultItem::CreditCard {
                meta: meta("2"),
                number: "4111111111111111".into(),
                exp: "12/30".into(),
                cvv: "987".into(),
                pin: Some("4242".into()),
                cardholder_name: None,
            },
            VaultItem::SecureNote {
                meta: meta("3"),
                title: "t".into(),
                content: "the recovery phrase is SECRET".into(),
            },
            VaultItem::Identity {
                meta: meta("4"),
                first_name: "Ada".into(),
                last_name: "Lovelace".into(),
                ssn: "078-05-1120".into(),
            },
        ];

        for item in &items {
            let rendered = format!("{item:?}");
            for secret in [
                "hunter2-SECRET",
                "JBSWY3DPEHPK3PXP",
                "4111111111111111",
                "987",
                "4242",
                "the recovery phrase is SECRET",
                "078-05-1120",
            ] {
                assert!(
                    !rendered.contains(secret),
                    "Debug leaked {secret:?} in {rendered}"
                );
            }
            // Still identifiable, or it would be useless for debugging.
            assert!(rendered.contains("Bank"), "lost the name: {rendered}");
        }

        // Whether a TOTP exists is metadata worth keeping; the seed is not.
        let with_totp = format!("{:?}", items[0]);
        assert!(with_totp.contains("totp: Some"), "{with_totp}");
    }

    #[test]
    fn search_matches_name_username_url_and_notes() {
        let mut store = VaultStore::new();
        store.add_item(login("1", "https://example.com", "alice@example.com"));

        assert_eq!(store.search("example").len(), 1);
        assert_eq!(store.search("alice").len(), 1);
        assert_eq!(store.search("note").len(), 1);
        assert_eq!(store.search("missing").len(), 0);
    }

    #[test]
    fn domain_search_matches_subdomains_and_rejects_ports() {
        let mut store = VaultStore::new();
        store.add_item(login("1", "https://eduid.ch", "alice"));
        store.add_item(login("2", "http://127.0.0.1:3000", "local"));

        assert_eq!(store.search_by_domain("epfl.login.eduid.ch").len(), 1);
        assert_eq!(store.search_by_domain("127.0.0.1:4000").len(), 0);
    }

    #[test]
    fn domain_search_respects_public_suffix_boundaries() {
        let mut store = VaultStore::new();
        store.add_item(login("1", "https://victim.github.io", "alice"));
        store.add_item(login("2", "https://example.co.uk", "bob"));

        assert_eq!(store.search_by_domain("login.victim.github.io").len(), 1);
        assert_eq!(store.search_by_domain("evil.github.io").len(), 0);
        assert_eq!(store.search_by_domain("login.example.co.uk").len(), 1);
        assert_eq!(store.search_by_domain("attacker.co.uk").len(), 0);
    }

    #[test]
    fn serialization_uses_desktop_compatible_item_tag() {
        let json = serde_json::to_string(&login("1", "https://example.com", "alice")).unwrap();
        assert!(json.contains("\"item_type\":\"login\""));
        assert!(json.contains("\"password\":\"secret\""));
    }

    #[test]
    fn serialization_roundtrips_through_old_format() {
        let old_json = r#"{"item_type":"login","id":"abc","name":"test","url":"https://example.com","username":"user","password":"pwd","createdAt":"2024-01-01T00:00:00Z","updatedAt":"2024-01-01T00:00:00Z"}"#;
        let item: VaultItem = serde_json::from_str(old_json).unwrap();
        assert_eq!(item.id(), "abc");
        assert_eq!(item.name(), "test");
        let roundtrip = serde_json::to_string(&item).unwrap();
        let re_read: VaultItem = serde_json::from_str(&roundtrip).unwrap();
        assert_eq!(re_read, item);
    }

    /// The §1.1 organization fields round-trip (A-2): an item carrying them
    /// survives a JSON cycle intact, an item from before the fields parses
    /// with "no tags, no folder", and a write through the typed API
    /// canonicalizes (trims, dedups, sorts) so every client stores the same
    /// bytes for the same tags.
    #[test]
    fn organization_fields_round_trip_and_default_to_empty() {
        let item = login("1", "https://uber.com", "ada")
            .with_tags(vec!["  Work ".into(), "work".into(), "VPN".into(), "".into()])
            .with_folder(Some("  Dev ".into()));
        assert_eq!(item.tags(), &["VPN".to_string(), "Work".to_string()]);
        assert_eq!(item.folder(), Some("Dev"));

        let json = serde_json::to_string(&item).unwrap();
        let back: VaultItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tags(), item.tags());
        assert_eq!(back.folder(), item.folder());

        // Written by an older client: no tags, no folder at all.
        let old = r#"{"item_type":"login","id":"abc","name":"t","url":"https://uber.com","username":"u","password":"p","createdAt":"2024-01-01T00:00:00Z","updatedAt":"2024-01-01T00:00:00Z"}"#;
        let item: VaultItem = serde_json::from_str(old).unwrap();
        assert!(item.tags().is_empty());
        assert_eq!(item.folder(), None);
        let back = serde_json::to_string(&item).unwrap();
        assert!(!back.contains("\"folder\""), "{back}");
    }

    #[test]
    fn app_links_survive_a_json_round_trip_and_default_to_none() {
        // Written by an older client: no app_ids at all.
        let old = r#"{"item_type":"login","id":"abc","name":"t","url":"https://uber.com","username":"u","password":"p","createdAt":"2024-01-01T00:00:00Z","updatedAt":"2024-01-01T00:00:00Z"}"#;
        let item: VaultItem = serde_json::from_str(old).unwrap();
        match &item {
            VaultItem::Login { app_ids, .. } => assert!(app_ids.is_empty()),
            _ => panic!("expected a login"),
        }

        let mut linked = login("1", "https://uber.com", "ada");
        if let VaultItem::Login { app_ids, .. } = &mut linked {
            app_ids.push("androidapp://com.ubercab".to_string());
        }
        let json = serde_json::to_string(&linked).unwrap();
        assert!(json.contains("\"app_ids\":[\"androidapp://com.ubercab\"]"));
        assert_eq!(serde_json::from_str::<VaultItem>(&json).unwrap(), linked);

        // camelCase, as a JS client would write it.
        let camel = r#"{"item_type":"login","id":"abc","name":"t","url":"https://uber.com","username":"u","password":"p","appIds":["androidapp://com.ubercab"],"createdAt":"2024-01-01T00:00:00Z","updatedAt":"2024-01-01T00:00:00Z"}"#;
        match &serde_json::from_str::<VaultItem>(camel).unwrap() {
            VaultItem::Login { app_ids, .. } => {
                assert_eq!(app_ids, &vec!["androidapp://com.ubercab".to_string()])
            }
            _ => panic!("expected a login"),
        }
    }

    #[test]
    fn get_item_is_o1_with_index() {
        let mut store = VaultStore::new();
        for i in 0..100 {
            let id = format!("id-{:03}", i);
            store.add_item(login(&id, "https://x.com", "user"));
        }
        assert!(store.get_item("id-050").is_some());
        assert!(store.get_item("id-000").is_some());
        assert!(store.get_item("id-099").is_some());
        assert!(store.get_item("nonexistent").is_none());
    }

    #[test]
    fn update_item_maintains_index() {
        let mut store = VaultStore::new();
        let item = login("1", "https://old.com", "alice");
        store.add_item(item);
        let updated = login("1", "https://new.com", "bob");
        store.update_item(updated);
        let found = store.get_item("1").unwrap();
        assert_eq!(found.url(), Some("https://new.com"));
        assert_eq!(found.username(), Some("bob"));
    }

    #[test]
    fn deleting_from_the_middle_keeps_every_other_lookup_correct() {
        let mut store = VaultStore::new();
        for i in 0..6 {
            store.add_item(login(&i.to_string(), "https://x.com", "user"));
        }
        store.delete_item("2", None);

        assert!(store.get_item("2").is_none());
        // The index entries after the hole are shifted rather than rebuilt, so
        // an off-by-one there would surface as the wrong item coming back.
        for id in ["0", "1", "3", "4", "5"] {
            assert_eq!(store.get_item(id).map(|i| i.id()), Some(id));
        }
    }

    /// A sync merge replaces `items` wholesale, which used to leave the index
    /// pointing at the previous positions — `get_item` then returned whichever
    /// item had moved into the slot.
    #[test]
    fn replacing_items_directly_does_not_return_the_wrong_item() {
        let mut store = VaultStore::new();
        store.add_item(login("a", "https://a.com", "alice"));
        store.add_item(login("b", "https://b.com", "bob"));

        store.items = vec![
            login("b", "https://b.com", "bob"),
            login("a", "https://a.com", "alice"),
        ];

        assert_eq!(store.get_item("a").unwrap().username(), Some("alice"));
        assert_eq!(store.get_item("b").unwrap().username(), Some("bob"));

        // And the next mutation repairs the index instead of building on a lie.
        store.add_item(login("c", "https://c.com", "carol"));
        assert_eq!(store.get_item("a").unwrap().username(), Some("alice"));
        assert_eq!(store.get_item("c").unwrap().username(), Some("carol"));
    }

    #[test]
    fn deserializing_a_vault_indexes_it() {
        let mut store = VaultStore::new();
        for i in 0..4 {
            store.add_item(login(&i.to_string(), "https://x.com", "user"));
        }
        let json = serde_json::to_vec(&store).unwrap();
        let loaded: VaultStore = serde_json::from_slice(&json).unwrap();

        assert_eq!(
            loaded.item_index.len(),
            4,
            "index is built at load, not on the first write"
        );
        for i in 0..4 {
            let id = i.to_string();
            assert_eq!(loaded.get_item(&id).map(|i| i.id()), Some(id.as_str()));
        }
        assert!(loaded.get_item("nope").is_none());
        // The index is derived state, so it plays no part in equality.
        assert_eq!(loaded, store);
    }

    #[test]
    fn fast_host_split_agrees_with_the_url_parser() {
        fn slow(url: &str) -> Option<(String, Option<u16>)> {
            let parsed = if url.starts_with("http://") || url.starts_with("https://") {
                url::Url::parse(url).ok()
            } else {
                url::Url::parse(&format!("https://{url}")).ok()
            }?;
            Some((parsed.host_str().unwrap_or("").to_string(), parsed.port()))
        }

        let corpus = [
            "https://example.com",
            "http://example.com",
            "example.com",
            "https://example.com/",
            "https://example.com/login?next=/a#frag",
            "https://login.sub.example.co.uk/path",
            "https://example.com:8443",
            "http://example.com:8080/x",
            "https://example.com:443",
            "http://example.com:80",
            "http://example.com:443",
            "https://example.com:80",
            "example.com:8443",
            "example.com:443",
            "https://xn--bcher-kva.example",
            "https://my-host.example-site.com",
            "https://a.b.c.d.e.example.org",
            "https://example.com.",
            // Shapes the fast path is expected to decline on; when it does not,
            // it still has to be right.
            "https://user:pw@example.com",
            "https://127.0.0.1:3000",
            "http://0x7f.1",
            "http://127.1",
            "http://2130706433",
            "https://[::1]:8080",
            "https://exa mple.com",
            "https://éxample.com",
            "https://example.com:99999",
            "https://example.com:",
            "https://",
            "",
            "not a url at all",
            "ftp://example.com",
            "https://a..b",
            "https://-example.com",
        ];

        // Plus every combination of the pieces that make up a stored URL, so
        // the agreement is not just checked on hand-picked strings.
        let mut generated = Vec::new();
        for scheme in ["", "http://", "https://"] {
            for host in [
                "example.com", "a.example.com", "example.co.uk", "localhost",
                "127.0.0.1", "0x7f.1", "2130706433", "ex-ample.com", "example.com.",
                "a..b", "1example.com", "example.1",
            ] {
                for port in ["", ":80", ":443", ":8080", ":0", ":65535", ":65536"] {
                    for path in ["", "/", "/login", "/a?b=c#d", "?q=1"] {
                        generated.push(format!("{scheme}{host}{port}{path}"));
                    }
                }
            }
        }

        for url in corpus.iter().map(|u| u.to_string()).chain(generated) {
            let Some((host, port)) = extract_host_and_port_fast(&url) else {
                continue;
            };
            assert_eq!(
                Some((host.to_string(), port)),
                slow(&url),
                "fast path disagreed on {url:?}"
            );
        }
    }

    #[test]
    fn subdomain_suffix_check_matches_the_formatted_version() {
        for (host, suffix) in [
            ("login.example.com", "example.com"),
            ("example.com", "example.com"),
            ("notexample.com", "example.com"),
            ("a.b", "b"),
            ("b", "b"),
            ("", "example.com"),
            ("example.com", ""),
        ] {
            assert_eq!(
                is_subdomain_of(host, suffix),
                host.ends_with(&format!(".{suffix}")),
                "{host:?} / {suffix:?}"
            );
        }
    }

    #[test]
    fn delete_item_removes_from_index() {
        let mut store = VaultStore::new();
        store.add_item(login("1", "https://x.com", "user"));
        store.delete_item("1", None);
        assert!(store.get_item("1").is_none());
    }
}
