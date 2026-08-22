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
    #[serde(default)]
    pub shared: bool,
    #[serde(default, alias = "share_recipient")]
    pub share_recipient: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "item_type", rename_all = "camelCase")]
pub enum VaultItem {
    Login {
        #[serde(flatten)]
        meta: VaultMeta,
        url: String,
        username: String,
        #[serde(rename = "password")]
        pass: String,
        #[serde(default)]
        totp: Option<String>,
        /// Mobile apps the user linked to this login (`androidapp://<package>`).
        ///
        /// Desktop never sets these, but it must carry them: this struct is what
        /// desktop deserializes the synced vault into and re-serializes on the
        /// next write, so a field it does not know about is a field it deletes
        /// from every one of the user's devices (audit A-2).
        #[serde(default, alias = "appIds")]
        app_ids: Vec<String>,
        /// Does this site make you re-prove the old password before changing
        /// it? The model's `SiteMode` (`security/formal/m9a_in_core_login.spthy`).
        ///
        /// It decides what an in-core login session is worth if it leaks. Where
        /// this is true the site is 'hardened': the residual dies when the
        /// session does. Where it is false a session can rotate the credential
        /// to one the holder picked, and the takeover outlives eviction — so
        /// `false` is the default, because a site has to be shown to be careful
        /// rather than assumed to be. See [`crate::login::SiteMode`].
        #[serde(default, skip_serializing_if = "Option::is_none",
                alias = "credentialChangeNeedsReauth")]
        credential_change_needs_reauth: Option<bool>,
        /// May VELA answer a second-factor prompt with this item's TOTP code
        /// when the site asked for something stronger?
        ///
        /// A site that demands a security key has chosen a phishing-resistant
        /// factor. Where it also offers "use your authenticator app instead",
        /// taking that route completes the login — by deliberately using the
        /// weaker of the two factors the site offered. That is a real security
        /// decision and it is the account owner's to make, so it is off unless
        /// they turn it on, per item. See `crate::login::perform_login`.
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
}

/// Redacted `Debug`, because the derived one printed the secrets.
///
/// A single `tracing::debug!("{item:?}")` anywhere — in this crate, in a
/// consumer, in a test someone leaves in — put passwords, card numbers, CVVs and
/// SSNs into a log file. Logs get shipped, attached to bug reports and read by
/// people who are not the vault's owner, so the fix belongs at the type: there
/// is no formatting of a `VaultItem` that reveals a secret, whoever writes it
/// (audit, crypto hardening).
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
        match self {
            VaultItem::Login { pass, totp, .. } => {
                pass.zeroize();
                if let Some(totp) = totp {
                    totp.zeroize();
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
            // Nothing secret: a file blob's bytes live in chunks, and a breach
            // monitor holds an address the user already published.
            VaultItem::FileBlob { .. } | VaultItem::BreachMonitor { .. } => {}
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
            .field("name", &self.name());
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
        }
        out.finish()
    }
}


/// Record of a deleted item, propagated via sync so that deletions
/// are honoured on all devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tombstone {
    pub id: String,
    #[serde(default = "default_created_at")]
    pub deleted_at: DateTime<Utc>,
    #[serde(default)]
    pub deleted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn meta(&self) -> &VaultMeta {
        match self {
            VaultItem::Login { meta, .. }
            | VaultItem::CreditCard { meta, .. }
            | VaultItem::SecureNote { meta, .. }
            | VaultItem::Identity { meta, .. }
            | VaultItem::FileBlob { meta, .. }
            | VaultItem::BreachMonitor { meta, .. }
            | VaultItem::Passkey { meta, .. } => meta,
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
            | VaultItem::Passkey { meta, .. } => meta,
        }
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

    pub fn last_modified_device(&self) -> Option<&str> {
        self.meta().last_modified_device.as_deref()
    }

    pub fn favorite(&self) -> bool {
        self.meta().favorite
    }

    pub fn shared(&self) -> bool {
        self.meta().shared
    }

    pub fn share_recipient(&self) -> Option<&str> {
        self.meta().share_recipient.as_deref()
    }

    pub fn is_received_share(&self) -> bool {
        self.shared() && self.share_recipient().is_none()
    }

    pub fn url(&self) -> Option<&str> {
        match self {
            VaultItem::Login { url, .. } => Some(url),
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

    /// The relying party this item is scoped to, for passkeys only.
    ///
    /// Passkeys deliberately do not answer [`VaultItem::url`], so they never
    /// surface as password-autofill candidates; this is how they are looked up
    /// instead.
    pub fn rp_id(&self) -> Option<&str> {
        match self {
            VaultItem::Passkey { rp_id, .. } => Some(rp_id),
            _ => None,
        }
    }

    /// This passkey's credential ID, base64url.
    pub fn credential_id(&self) -> Option<&str> {
        match self {
            VaultItem::Passkey { credential_id, .. } => Some(credential_id),
            _ => None,
        }
    }

    pub fn password(&self) -> Option<&str> {
        match self {
            VaultItem::Login { pass, .. } => Some(pass),
            _ => None,
        }
    }

    /// Whether this site is 'hardened' in the M9a sense: a live session cannot
    /// change the account password without re-proving the old one. Everything
    /// that is not a login answers `false`, which is the safe answer.
    pub fn credential_change_needs_reauth(&self) -> bool {
        match self {
            VaultItem::Login {
                credential_change_needs_reauth,
                ..
            } => credential_change_needs_reauth.unwrap_or(false),
            _ => false,
        }
    }

    /// Whether this item permits answering a stronger factor with its TOTP
    /// code. Anything that is not a login answers `false`, the safe answer.
    pub fn allow_second_factor_downgrade(&self) -> bool {
        match self {
            VaultItem::Login {
                allow_second_factor_downgrade,
                ..
            } => allow_second_factor_downgrade.unwrap_or(false),
            _ => false,
        }
    }

    pub fn display_value(&self) -> String {
        match self {
            VaultItem::Login { pass, .. } => pass.clone(),
            VaultItem::CreditCard { number, .. } => number.clone(),
            VaultItem::SecureNote { .. } => "Secure Note".to_string(),
            VaultItem::Identity { first_name, .. } => first_name.clone(),
            VaultItem::FileBlob { filename, .. } => filename.clone(),
            VaultItem::BreachMonitor { email, .. } => email.clone(),
            // Deliberately the account name and not the key. Every other arm
            // here returns the item's secret because every other item type has
            // one that is meant to be copied; a passkey's is meant to be used
            // where it sits and never displayed, copied or released.
            VaultItem::Passkey { user_name, .. } => user_name.clone(),
        }
    }

    pub fn masked_value(&self) -> String {
        match self {
            VaultItem::Login { .. } => "••••••••••••".to_string(),
            VaultItem::CreditCard { number, .. } => {
                if number.len() >= 4 {
                    format!("•••• •••• •••• {}", &number[number.len() - 4..])
                } else {
                    "•••• •••• •••• ••••".to_string()
                }
            }
            VaultItem::SecureNote { .. } => "••••••••••••".to_string(),
            VaultItem::Identity { .. } => "••••••••".to_string(),
            VaultItem::FileBlob { filename, .. } => filename.clone(),
            VaultItem::BreachMonitor { email, .. } => email.clone(),
            VaultItem::Passkey { user_name, .. } => user_name.clone(),
        }
    }

    pub fn with_id(&self, new_id: String) -> Self {
        let mut new = self.clone();
        new.meta_mut().id = new_id;
        new
    }

    pub fn with_updated_at(&self, new_updated_at: DateTime<Utc>) -> Self {
        let mut new = self.clone();
        new.meta_mut().updated_at = new_updated_at;
        new
    }

    /// Keeps app associations the caller did not send.
    ///
    /// Desktop has no UI for `androidapp://` links — they are made on the phone
    /// (audit A-2) — so an edit that simply does not mention them means
    /// "unchanged", not "unlink". Without this, editing a login on a laptop
    /// would quietly detach every phone app from it on the next sync.
    pub fn preserving_app_ids(mut self, existing: &VaultItem) -> Self {
        if let (
            VaultItem::Login {
                app_ids,
                credential_change_needs_reauth,
                allow_second_factor_downgrade,
                ..
            },
            VaultItem::Login {
                app_ids: previous_app_ids,
                credential_change_needs_reauth: previous_reauth,
                allow_second_factor_downgrade: previous_downgrade,
                ..
            },
        ) = (&mut self, existing)
        {
            if app_ids.is_empty() {
                *app_ids = previous_app_ids.clone();
            }
            // The M9a flags, for the same reason and with the same failure.
            // They are `Option` precisely so that "the editor did not mention
            // this" is a state distinct from "the user turned it off": a plain
            // `bool` defaults to false on deserialise, and an edit form that
            // has never heard of the field is indistinguishable from one where
            // the user unticked it. Without this, changing a password would
            // quietly clear the site's hardened annotation and re-arm a factor
            // downgrade the owner had deliberately allowed.
            if credential_change_needs_reauth.is_none() {
                *credential_change_needs_reauth = *previous_reauth;
            }
            if allow_second_factor_downgrade.is_none() {
                *allow_second_factor_downgrade = *previous_downgrade;
            }
        }
        self
    }

    pub fn with_shared_status(&self, shared: bool, share_recipient: Option<String>) -> Self {
        let mut new = self.clone();
        let meta = new.meta_mut();
        meta.shared = shared;
        meta.share_recipient = share_recipient;
        new
    }

    pub fn with_favorite(&self, favorite: bool) -> Self {
        let mut new = self.clone();
        new.meta_mut().favorite = favorite;
        new
    }

    pub fn with_name(&self, new_name: String) -> Self {
        let mut new = self.clone();
        new.meta_mut().name = new_name;
        new
    }
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(from = "VaultStoreRepr")]
pub struct VaultStore {
    pub items: Vec<VaultItem>,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    /// Bumped by every mutation of `items`. [`Self::items_snapshot`] keys its
    /// cached `Arc` on this, so repeated reads share one allocation instead
    /// of deep-cloning the vault per request.
    ///
    /// Direct assignments to `items` outside [`Self::add_item`] /
    /// [`Self::update_item`] / [`Self::delete_item`] /
    /// [`Self::replace_items`] leave both this counter and the lookup index
    /// stale — use those methods instead. (`get_item` still reads correctly
    /// through its scan fallback, which is why the compiler can't catch it.)
    #[serde(skip, default)]
    pub generation: u64,
    /// The last snapshot handed out by [`Self::items_snapshot`], valid for
    /// the current [`Self::generation`]. Cleared on every mutation so the
    /// store never pins two copies of the item list between an edit and the
    /// next read.
    ///
    /// Living inside the store — not in `AppState` — is what makes whole-store
    /// swaps safe: unlock/lock/recovery replace `*vault_state = new_store`,
    /// and a fresh store carries no stale cache. A deserialized store always
    /// starts here with `generation == 0`, which would collide with a stale
    /// AppState-side cache keyed on generation alone.
    #[serde(skip, default)]
    snapshot: parking_lot::RwLock<Option<std::sync::Arc<Vec<VaultItem>>>>,
    #[serde(skip, default = "HashMap::new")]
    item_index: HashMap<String, usize>,
}

/// The wire shape of a `VaultStore`, so that deserializing one also builds its
/// lookup index.
///
/// `item_index` is `#[serde(skip)]`, so a store read back from `vault.enc` or
/// off the sync wire arrived with an empty index and kept it until the first
/// mutation — every `get_item` before that was a linear scan of the whole
/// vault, which is exactly the window the UI spends listing and opening items.
/// Building it here costs one pass at load and makes the lookups after it O(1).
#[derive(Deserialize)]
struct VaultStoreRepr {
    items: Vec<VaultItem>,
    #[serde(default)]
    tombstones: Vec<Tombstone>,
}

impl From<VaultStoreRepr> for VaultStore {
    fn from(repr: VaultStoreRepr) -> Self {
        let mut store = Self {
            items: repr.items,
            tombstones: repr.tombstones,
            generation: 0,
            snapshot: parking_lot::RwLock::new(None),
            item_index: HashMap::new(),
        };
        store.reindex();
        store
    }
}

impl Clone for VaultStore {
    fn clone(&self) -> Self {
        Self {
            items: self.items.clone(),
            tombstones: self.tombstones.clone(),
            generation: self.generation,
            // A clone rebuilds its snapshot lazily on first read rather than
            // sharing this store's slot — one extra copy on the rare clone
            // path in exchange for never having to reason about which store
            // a cached `Arc` belongs to.
            snapshot: parking_lot::RwLock::new(None),
            item_index: self.item_index.clone(),
        }
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
            generation: 0,
            snapshot: parking_lot::RwLock::new(None),
            item_index: HashMap::new(),
        }
    }

    /// Records that `items` changed and drops the cached snapshot, so the
    /// store never holds two copies of the item list between an edit and the
    /// next read. Consumers holding earlier `Arc`s keep their (now stale)
    /// copy alive until they drop it — that is the point of the Arc.
    pub fn touch_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        *self.snapshot.write() = None;
    }

    /// Bulk-replaces `items` — the one sanctioned way to write the vector
    /// outside the CRUD methods. The sync merge is the motivating caller;
    /// anything else should use [`Self::add_item`] / [`Self::update_item`] /
    /// [`Self::delete_item`].
    ///
    /// Assigning `.items` directly instead leaves the lookup index pointing
    /// at wrong slots (`get_item` falls back to a linear scan when it notices,
    /// so reads stay *correct* — just O(n) until the next mutation) and keeps
    /// serving the pre-replacement snapshot cache.
    pub fn replace_items(&mut self, items: Vec<VaultItem>) {
        self.items = items;
        self.reindex();
        self.touch_generation();
    }

    /// A shared, cheap-to-clone view of `items`, rebuilt only after a
    /// mutation. The rebuild happens under whatever lock the caller already
    /// holds (`AppState.vault`), i.e. no worse than the per-request clone
    /// this replaces; concurrent first readers may race to build and the
    /// loser's copy is dropped.
    ///
    /// The cache is keyed on the store instance itself, so unlock/lock/recovery
    /// paths that swap in a whole new `VaultStore` can never observe another
    /// session's snapshot.
    pub fn items_snapshot(&self) -> std::sync::Arc<Vec<VaultItem>> {
        if let Some(snapshot) = self.snapshot.read().clone() {
            return snapshot;
        }

        let built = std::sync::Arc::new(self.items.clone());
        // Another reader may have built one while we cloned; either way both
        // snapshots have identical content for this generation.
        *self.snapshot.write() = Some(built.clone());
        built
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
    /// public, and a wholesale replacement (historically `local.items = …` in
    /// the sync merge, now [`Self::replace_items`]) leaves the index holding
    /// the *old* positions — `get_item` then handed back whichever item had
    /// moved into that slot. Comparing lengths catches a wholesale
    /// replacement, and `get_item` re-checks the id at the position it lands
    /// on for the rest.
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
        self.touch_generation();
    }

    pub fn update_item(&mut self, item: VaultItem) {
        self.ensure_index();
        let id = item.id().to_string();
        if let Some(&idx) = self.item_index.get(&id) {
            self.items[idx] = item;
            self.touch_generation();
        } else if let Some(existing) = self.items.iter_mut().find(|i| i.id() == id) {
            *existing = item;
            self.reindex();
            self.touch_generation();
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
            deleted_by: device_id.map(|s| s.to_string()),
        });
        self.touch_generation();
    }

    pub fn prune_tombstones(&mut self, max_age: chrono::Duration) {
        let cutoff = Utc::now() - max_age;
        self.tombstones.retain(|t| t.deleted_at >= cutoff);
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

    /// Mutable access to one item, for in-place field updates.
    ///
    /// Deliberately narrow: this exists for bookkeeping a caller must do
    /// without rewriting the item — the passkey signature counter is the
    /// motivating case. Use [`Self::update_item`] to replace an item wholesale,
    /// which is what keeps `updated_at` and the sync index honest.
    pub fn get_item_mut(&mut self, id: &str) -> Option<&mut VaultItem> {
        // Eager rather than on-write-back: we cannot observe what the caller
        // does through the returned `&mut`, and an unnecessary bump only
        // invalidates a snapshot one read earlier than strictly needed.
        self.touch_generation();
        if let Some(&idx) = self.item_index.get(id) {
            return self.items.get_mut(idx);
        }
        self.items.iter_mut().find(|item| item.id() == id)
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
        if base_domain.is_empty() {
            return Vec::new();
        }

        // Parsed once instead of once per item: the query side of `urls_match`
        // re-lowercased the domain, re-parsed it as a URL and re-ran the
        // public-suffix lookup for every entry in the vault, on a path the
        // autofill bridge hits for each page load.
        let query = DomainQuery::new(base_domain);

        self.items
            .iter()
            .filter(|item| {
                item.item_type() == ItemType::Login
                    && item.url().is_some_and(|url| query.matches(url))
            })
            .collect()
    }

    /// Passkeys scoped to exactly this relying party ID.
    ///
    /// Exact match, not the suffix matching [`Self::search_by_domain`] does for
    /// logins. WebAuthn's RP ID is already the scoping decision — a credential
    /// registered for `example.com` must not answer a request from
    /// `evil-example.com`, and loosening the comparison here is precisely how
    /// `assertion_is_origin_bound` would stop holding.
    pub fn passkeys_for_rp(&self, rp_id: &str) -> Vec<&VaultItem> {
        if rp_id.is_empty() {
            return Vec::new();
        }
        let wanted = rp_id.to_lowercase();
        self.items
            .iter()
            .filter(|item| item.rp_id().is_some_and(|id| id.to_lowercase() == wanted))
            .collect()
    }

    /// The passkey with this credential ID, if the vault holds it.
    pub fn passkey_by_credential_id(&self, credential_id: &str) -> Option<&VaultItem> {
        self.items
            .iter()
            .find(|item| item.credential_id() == Some(credential_id))
    }

    pub fn by_type(&self, item_type: &ItemType) -> Vec<&VaultItem> {
        self.items
            .iter()
            .filter(|item| &item.item_type() == item_type)
            .collect()
    }

    pub fn count_by_type(&self) -> (usize, usize, usize, usize, usize) {
        // One pass, not five.
        let (mut logins, mut cards, mut notes, mut identities, mut files) = (0, 0, 0, 0, 0);
        for item in &self.items {
            match item.item_type() {
                ItemType::Login => logins += 1,
                ItemType::CreditCard => cards += 1,
                ItemType::SecureNote => notes += 1,
                ItemType::Identity => identities += 1,
                ItemType::FileBlob => files += 1,
                ItemType::BreachMonitor | ItemType::Passkey => {}
            }
        }
        (logins, cards, notes, identities, files)
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

/// The shape the URL-matching tests are written against; real callers build a
/// `DomainQuery` once and reuse it across the vault.
#[cfg(test)]
fn urls_match(current_url: &str, stored_url: &str) -> bool {
    DomainQuery::new(current_url).matches(stored_url)
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

    // Drop an explicit port that equals the scheme's default — exactly what
    // url's own parser does (`if opt_port == default_port() { opt_port = None }`,
    // parser.rs), which is why the slow path's `parsed.port()` reports the same
    // value. This is a mirror of the parser, not a divergence; the differential
    // test (`fast_host_split_agrees_with_the_url_parser`) enforces the
    // agreement across the corpus and ~5k generated URLs.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordGeneratorOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub easy_to_type: bool,
    pub pronounceable: bool,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            easy_to_type: false,
            pronounceable: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictItem {
    pub item_id: String,
    pub local_version: VaultItem,
    pub server_version: VaultItem,
    pub conflict_detected_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str, name: &str) -> VaultMeta {
        let now = Utc::now();
        VaultMeta {
            id: id.into(),
            name: name.into(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            shared: false,
            share_recipient: None,
        }
    }

    fn login(id: &str, name: &str, url: &str, user: &str, pass: &str) -> VaultItem {
        VaultItem::Login {
            meta: meta(id, name),
            url: url.into(),
            username: user.into(),
            pass: pass.into(),
            totp: None,
            app_ids: Vec::new(),
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
        }
    }

    #[test]
    fn dropping_an_item_wipes_its_secrets() {
        // Reach the buffer the String owns, drop the item, and read it back.
        // Testing `zeroize_secrets` directly would only prove zeroize works;
        // what matters is that Drop reaches it, because Drop is what covers the
        // paths nobody remembered to clean up.
        let mut item = login("1", "Bank", "https://bank.example", "ada", "hunter2-SECRET");
        let (ptr, len) = match &item {
            VaultItem::Login { pass, .. } => (pass.as_ptr(), pass.len()),
            _ => unreachable!(),
        };
        assert_eq!(
            unsafe { std::slice::from_raw_parts(ptr, len) },
            b"hunter2-SECRET",
            "precondition: the plaintext is really there"
        );

        item.zeroize_secrets();

        // SAFETY: the String still owns this allocation — zeroize_secrets
        // overwrites in place and does not free.
        assert!(
            unsafe { std::slice::from_raw_parts(ptr, len) }.iter().all(|b| *b == 0),
            "the password survived the wipe"
        );
    }

    #[test]
    fn debug_never_prints_a_secret() {
        let items = vec![
            VaultItem::Login {
                meta: meta("1", "Bank"),
                url: "https://bank.example".into(),
                username: "ada".into(),
                pass: "hunter2-SECRET".into(),
                totp: Some("JBSWY3DPEHPK3PXP".into()),
                app_ids: Vec::new(),
                credential_change_needs_reauth: None,
                allow_second_factor_downgrade: None,
            },
            VaultItem::CreditCard {
                meta: meta("2", "Bank"),
                number: "4111111111111111".into(),
                exp: "12/30".into(),
                cvv: "987".into(),
                pin: Some("4242".into()),
                cardholder_name: None,
            },
            VaultItem::SecureNote {
                meta: meta("3", "Bank"),
                title: "t".into(),
                content: "the recovery phrase is SECRET".into(),
            },
            VaultItem::Identity {
                meta: meta("4", "Bank"),
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
                assert!(!rendered.contains(secret), "Debug leaked {secret:?} in {rendered}");
            }
            assert!(rendered.contains("Bank"), "lost the name: {rendered}");
        }

        let with_totp = format!("{:?}", items[0]);
        assert!(with_totp.contains("totp: Some"), "{with_totp}");
    }

    #[test]
    fn masked_value_per_item_type() {
        assert_eq!(login("1", "n", "u", "u", "secret").masked_value(), "••••••••••••");

        let card = VaultItem::CreditCard {
            meta: meta("2", "Visa"),
            number: "4111111111111111".into(),
            exp: "12/30".into(),
            cvv: "123".into(),
            pin: None,
            cardholder_name: None,
        };
        assert_eq!(card.masked_value(), "•••• •••• •••• 1111");
        assert_eq!(card.display_value(), "4111111111111111");

        let short_card = VaultItem::CreditCard {
            meta: meta("3", "odd"),
            number: "12".into(),
            exp: "12/30".into(),
            cvv: "123".into(),
            pin: None,
            cardholder_name: None,
        };
        assert_eq!(short_card.masked_value(), "•••• •••• •••• ••••");

        let note = VaultItem::SecureNote {
            meta: meta("4", "note"),
            title: "t".into(),
            content: "c".into(),
        };
        assert_eq!(note.masked_value(), "••••••••••••");
        assert_eq!(note.display_value(), "Secure Note");

        let identity = VaultItem::Identity {
            meta: meta("5", "id"),
            first_name: "Ada".into(),
            last_name: "L".into(),
            ssn: "000".into(),
        };
        assert_eq!(identity.masked_value(), "••••••••");
        assert_eq!(identity.display_value(), "Ada");
        assert_eq!(identity.username(), Some("Ada"));

        let file = VaultItem::FileBlob {
            meta: meta("6", "f"),
            filename: "doc.pdf".into(),
            mime: "application/pdf".into(),
            chunks: vec![],
        };
        assert_eq!(file.masked_value(), "doc.pdf");

        let breach = VaultItem::BreachMonitor {
            meta: meta("7", "b"),
            email: "a@b.c".into(),
            checked_at: None,
            breach_count: 0,
            breaches: vec![],
        };
        assert_eq!(breach.masked_value(), "a@b.c");
    }

    #[test]
    fn editing_a_login_here_keeps_the_app_links_made_on_a_phone() {
        let mut linked = login("1", "Uber", "https://uber.com", "ada", "p");
        if let VaultItem::Login { app_ids, .. } = &mut linked {
            app_ids.push("androidapp://com.ubercab".into());
        }

        // What a desktop edit sends back: same item, no app_ids field.
        let edited = login("1", "Uber", "https://uber.com", "ada", "p2")
            .preserving_app_ids(&linked);

        match &edited {
            VaultItem::Login { app_ids, pass, .. } => {
                assert_eq!(pass, "p2", "the actual edit still applies");
                assert_eq!(app_ids, &vec!["androidapp://com.ubercab".to_string()]);
            }
            _ => panic!("expected a login"),
        }
    }

    /// The same failure as the app-links one, for the M9a flags.
    ///
    /// Found by asking why the flags had no UI, not by a test failing — which
    /// is why it is written down. An edit form that has never heard of a field
    /// sends the item without it; a `bool` would deserialise to `false` and the
    /// user's decisions would be gone. Changing a password on a site would have
    /// cleared its hardened annotation and re-armed a factor downgrade they had
    /// deliberately allowed, with nothing on screen to say so.
    #[test]
    fn editing_a_login_here_keeps_the_second_factor_decisions() {
        let mut configured = login("1", "GitHub", "https://github.com", "ada", "p");
        if let VaultItem::Login {
            credential_change_needs_reauth,
            allow_second_factor_downgrade,
            ..
        } = &mut configured
        {
            *credential_change_needs_reauth = Some(true);
            *allow_second_factor_downgrade = Some(true);
        }

        // What an edit form that predates these fields sends back.
        let edited = login("1", "GitHub", "https://github.com", "ada", "p2")
            .preserving_app_ids(&configured);

        match &edited {
            VaultItem::Login {
                pass,
                credential_change_needs_reauth,
                allow_second_factor_downgrade,
                ..
            } => {
                assert_eq!(pass, "p2", "the actual edit still applies");
                assert_eq!(*credential_change_needs_reauth, Some(true));
                assert_eq!(*allow_second_factor_downgrade, Some(true));
            }
            _ => panic!("expected a login"),
        }
    }

    /// And turning one off has to survive, which is the whole reason these are
    /// `Option` rather than `bool`: `Some(false)` is a decision, `None` is
    /// silence, and only silence inherits.
    #[test]
    fn turning_a_second_factor_flag_off_is_not_undone_by_the_old_value() {
        let mut configured = login("1", "GitHub", "https://github.com", "ada", "p");
        if let VaultItem::Login {
            allow_second_factor_downgrade,
            ..
        } = &mut configured
        {
            *allow_second_factor_downgrade = Some(true);
        }

        let mut turned_off = login("1", "GitHub", "https://github.com", "ada", "p");
        if let VaultItem::Login {
            allow_second_factor_downgrade,
            ..
        } = &mut turned_off
        {
            *allow_second_factor_downgrade = Some(false);
        }

        match &turned_off.preserving_app_ids(&configured) {
            VaultItem::Login {
                allow_second_factor_downgrade,
                ..
            } => assert_eq!(
                *allow_second_factor_downgrade,
                Some(false),
                "an explicit opt-out was overwritten by the previous opt-in"
            ),
            _ => panic!("expected a login"),
        }
    }

    /// The exact JSON the desktop's item form sends, parsed by the type that
    /// receives it.
    ///
    /// The two sides are written in different languages and nothing else checks
    /// that they agree: `toBackendItem` in `src/context/AppContext.tsx` builds
    /// this object, `update_item` deserialises it here, and a rename on either
    /// side would show up as a setting that silently refuses to stick.
    #[test]
    fn the_item_form_can_set_both_second_factor_flags() {
        let from_the_form = r#"{
            "id": "1", "name": "GitHub",
            "created_at": "2026-08-07T10:00:00Z", "updated_at": "2026-08-07T10:00:00Z",
            "last_modified_device": null, "favorite": false, "shared": false,
            "share_recipient": null,
            "item_type": "login",
            "url": "https://github.com", "username": "ada", "password": "p",
            "totp": null, "notes": null,
            "credential_change_needs_reauth": true,
            "allow_second_factor_downgrade": true
        }"#;

        let item: VaultItem = serde_json::from_str(from_the_form).expect("the form's item");
        match &item {
            VaultItem::Login {
                credential_change_needs_reauth,
                allow_second_factor_downgrade,
                pass,
                ..
            } => {
                assert_eq!(*credential_change_needs_reauth, Some(true));
                assert_eq!(*allow_second_factor_downgrade, Some(true));
                assert_eq!(pass, "p", "the form spells the password field 'password'");
            }
            _ => panic!("expected a login"),
        }
        assert!(item.credential_change_needs_reauth());

        // And turning them off is distinguishable from not mentioning them,
        // which is what makes the preservation above correct.
        let turned_off = from_the_form.replace("true,\n            \"allow", "false,\n            \"allow");
        let item: VaultItem = serde_json::from_str(&turned_off).unwrap();
        match &item {
            VaultItem::Login {
                credential_change_needs_reauth,
                ..
            } => assert_eq!(*credential_change_needs_reauth, Some(false)),
            _ => panic!("expected a login"),
        }
    }

    /// A vault written before these fields exist must load, and must not be
    /// read as "the user turned both off".
    #[test]
    fn a_login_from_before_these_fields_reads_as_undecided() {
        let json = r#"{
            "item_type": "login", "id": "1", "name": "Old", "url": "https://x.example",
            "username": "ada", "password": "p"
        }"#;
        let item: VaultItem = serde_json::from_str(json).expect("an older item should load");
        match &item {
            VaultItem::Login {
                credential_change_needs_reauth,
                allow_second_factor_downgrade,
                ..
            } => {
                assert_eq!(*credential_change_needs_reauth, None);
                assert_eq!(*allow_second_factor_downgrade, None);
            }
            _ => panic!("expected a login"),
        }
        // Undecided still behaves as the safe answer everywhere it is read.
        assert!(!item.credential_change_needs_reauth());
        // And round-trips without inventing a decision the user never made.
        let back = serde_json::to_string(&item).unwrap();
        assert!(!back.contains("credential_change_needs_reauth"), "{back}");
        assert!(!back.contains("allow_second_factor_downgrade"), "{back}");
    }

    #[test]
    fn app_links_sent_by_the_caller_win() {
        let mut previous = login("1", "Uber", "https://uber.com", "ada", "p");
        if let VaultItem::Login { app_ids, .. } = &mut previous {
            app_ids.push("androidapp://com.old".into());
        }
        let mut incoming = login("1", "Uber", "https://uber.com", "ada", "p");
        if let VaultItem::Login { app_ids, .. } = &mut incoming {
            app_ids.push("androidapp://com.ubercab".into());
        }

        match &incoming.preserving_app_ids(&previous) {
            VaultItem::Login { app_ids, .. } => {
                assert_eq!(app_ids, &vec!["androidapp://com.ubercab".to_string()]);
            }
            _ => panic!("expected a login"),
        }
    }

    #[test]
    fn is_received_share_semantics() {
        let received = login("1", "n", "u", "u", "p").with_shared_status(true, None);
        assert!(received.is_received_share());
        // A share we SENT (recipient set) is still ours to modify.
        let sent = login("1", "n", "u", "u", "p").with_shared_status(true, Some("bob".into()));
        assert!(!sent.is_received_share());
        let unshared = login("1", "n", "u", "u", "p");
        assert!(!unshared.is_received_share());
    }

    #[test]
    fn search_matches_name_username_url_notes_case_insensitively() {
        let mut vault = VaultStore::new();
        vault.add_item(login("1", "GitHub", "https://github.com", "alice", "p"));
        vault.add_item(login("2", "GitLab", "https://gitlab.com", "bob", "p"));
        let mut notes_meta = meta("3", "Bank");
        notes_meta.notes = Some("my pet name".into());
        vault.add_item(VaultItem::Login {
            meta: notes_meta,
            url: "https://bank.example".into(),
            username: "carol".into(),
            pass: "p".into(),
            totp: None,
            app_ids: Vec::new(),
            credential_change_needs_reauth: None,
            allow_second_factor_downgrade: None,
        });

        assert_eq!(vault.search("GIT").len(), 2);
        assert_eq!(vault.search("github").len(), 1);
        assert_eq!(vault.search("ALICE").len(), 1);
        assert_eq!(vault.search("gitlab.com").len(), 1);
        assert_eq!(vault.search("pet").len(), 1, "notes are searchable");
        assert!(vault.search("nonexistent").is_empty());
    }

    #[test]
    fn urls_match_cases() {
        // Exact host.
        assert!(urls_match("example.com", "https://example.com/login"));
        // Subdomain of the stored host.
        assert!(urls_match("login.example.com", "https://example.com"));
        // The reverse (parent visiting a stored subdomain) must NOT match.
        assert!(!urls_match("example.com", "https://login.example.com"));
        // Different registrable domain.
        assert!(!urls_match("evil-example.com", "https://example.com"));
        // PSL multi-label suffix: subdomains of victim.co.uk match, but a
        // different registrable domain under the same public suffix doesn't.
        assert!(urls_match("sub.victim.co.uk", "https://victim.co.uk"));
        assert!(!urls_match("victim.co.uk", "https://other.co.uk"));
        // Scheme-less stored URLs work.
        assert!(urls_match("github.com", "github.com"));
        // IP literals: exact IP matches (ports compatible), different IP doesn't.
        assert!(urls_match("192.168.1.1", "http://192.168.1.1:8080"));
        assert!(!urls_match("192.168.1.1", "http://192.168.1.2"));
        // Both ports present and different → no match.
        assert!(!urls_match("example.com:8443", "https://example.com:9443"));
        // Case-insensitive.
        assert!(urls_match("ExAmPlE.CoM", "https://EXAMPLE.com"));
    }

    #[test]
    fn search_by_domain_filters_to_logins_and_matches_psl() {
        let mut vault = VaultStore::new();
        vault.add_item(login("1", "GH", "https://github.com", "alice", "p"));
        vault.add_item(VaultItem::SecureNote {
            meta: meta("2", "github note"),
            title: "t".into(),
            content: "github.com".into(),
        });
        vault.add_item(login("3", "Other", "https://example.org", "bob", "p"));

        let hits = vault.search_by_domain("gist.github.com");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id(), "1");

        assert!(vault.search_by_domain("").is_empty());
        assert!(vault.search_by_domain("unrelated.net").is_empty());
    }

    #[test]
    fn update_item_replaces_or_adds() {
        let mut vault = VaultStore::new();
        vault.add_item(login("1", "Old", "u", "a", "p"));
        vault.update_item(login("1", "New", "u", "b", "p2"));
        assert_eq!(vault.items.len(), 1);
        assert_eq!(vault.get_item("1").unwrap().name(), "New");
        assert_eq!(vault.get_item("1").unwrap().username(), Some("b"));

        // Unknown id → added (upsert semantics used by sync merge).
        vault.update_item(login("2", "Added", "u", "c", "p"));
        assert_eq!(vault.items.len(), 2);
        assert_eq!(vault.get_item("2").unwrap().name(), "Added");
    }

    #[test]
    fn delete_item_tombstones_and_prune() {
        let mut vault = VaultStore::new();
        vault.add_item(login("1", "A", "u", "a", "p"));
        vault.add_item(login("2", "B", "u", "b", "p"));
        vault.delete_item("1", Some("dev-x"));
        assert!(vault.get_item("1").is_none());
        assert_eq!(vault.items.len(), 1);
        assert_eq!(vault.tombstones.len(), 1);
        assert_eq!(vault.tombstones[0].deleted_by.as_deref(), Some("dev-x"));

        // Backdate the tombstone, add a fresh one, then prune.
        vault.tombstones[0].deleted_at = Utc::now() - chrono::Duration::hours(2);
        vault.delete_item("2", None);
        vault.prune_tombstones(chrono::Duration::hours(1));
        assert_eq!(vault.tombstones.len(), 1);
        assert_eq!(vault.tombstones[0].id, "2");
    }

    #[test]
    fn count_and_filter_by_type() {
        let mut vault = VaultStore::new();
        vault.add_item(login("1", "A", "u", "a", "p"));
        vault.add_item(login("2", "B", "u", "b", "p"));
        vault.add_item(VaultItem::SecureNote {
            meta: meta("3", "N"),
            title: "t".into(),
            content: "c".into(),
        });
        assert_eq!(vault.count_by_type(), (2, 0, 1, 0, 0));
        assert_eq!(vault.by_type(&ItemType::Login).len(), 2);
        assert_eq!(vault.by_type(&ItemType::CreditCard).len(), 0);
    }

    #[test]
    fn meta_deserializes_legacy_snake_case_fields() {
        let json = serde_json::json!({
            "id": "1",
            "name": "Old item",
            "created_at": "2024-01-02T03:04:05Z",
            "updated_at": "2024-01-02T03:04:05Z",
            "last_modified_device": "dev-legacy"
        });
        let meta: VaultMeta = serde_json::from_value(json).unwrap();
        assert_eq!(meta.name, "Old item");
        assert_eq!(meta.last_modified_device.as_deref(), Some("dev-legacy"));
        assert_eq!(meta.created_at.to_rfc3339(), "2024-01-02T03:04:05+00:00");
    }

    #[test]
    fn vault_item_tagged_serde_roundtrip() {
        let item = login("1", "GH", "https://github.com", "alice", "pw");
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["item_type"], "login");
        assert_eq!(json["password"], "pw");
        let back: VaultItem = serde_json::from_value(json).unwrap();
        assert_eq!(back.id(), "1");
        assert_eq!(back.password(), Some("pw"));
    }

    #[test]
    fn vault_store_serde_roundtrip_preserves_items_and_tombstones() {
        let mut vault = VaultStore::new();
        vault.add_item(login("1", "A", "u", "a", "p"));
        vault.delete_item("1", Some("d"));
        let json = serde_json::to_vec(&vault).unwrap();
        let back: VaultStore = serde_json::from_slice(&json).unwrap();
        assert!(back.get_item("1").is_none());
        assert_eq!(back.tombstones.len(), 1);
        // Index is rebuilt lazily — lookup still works after deserialize.
        assert!(back.items.is_empty());
    }

    fn passkey(id: &str, rp_id: &str, user: &str) -> VaultItem {
        let now = chrono::Utc::now();
        VaultItem::Passkey {
            meta: VaultMeta {
                id: id.to_string(),
                name: rp_id.to_string(),
                notes: None,
                created_at: now,
                updated_at: now,
                last_modified_device: Some("test".to_string()),
                favorite: false,
                shared: false,
                share_recipient: None,
            },
            rp_id: rp_id.to_string(),
            rp_name: rp_id.to_string(),
            credential_id: format!("cred-{id}"),
            user_handle: "aGFuZGxl".to_string(),
            user_name: user.to_string(),
            user_display_name: user.to_string(),
            private_key: "c2VjcmV0LXNjYWxhcg".to_string(),
            sign_count: 0,
        }
    }

    #[test]
    fn passkey_serde_roundtrip_keeps_the_scoping_fields() {
        let item = passkey("1", "example.com", "alice");
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["item_type"], "passkey");
        assert_eq!(json["rp_id"], "example.com");

        let back: VaultItem = serde_json::from_value(json).unwrap();

        assert_eq!(back.rp_id(), Some("example.com"));
        assert_eq!(back.credential_id(), Some("cred-1"));
        assert_eq!(back.username(), Some("alice"));
    }

    /// The redacted `Debug` has to cover the new secret too — the whole reason
    /// that impl exists is that the derived one leaked passwords into logs, and
    /// a credential key is worth strictly more than a password.
    #[test]
    fn debug_never_prints_a_credential_key() {
        let item = passkey("1", "example.com", "alice");

        let rendered = format!("{item:?}");

        assert!(!rendered.contains("c2VjcmV0LXNjYWxhcg"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert!(rendered.contains("example.com"), "{rendered}");
    }

    /// A passkey is not a password, and must never be offered as one.
    #[test]
    fn a_passkey_is_not_an_autofill_candidate() {
        let mut vault = VaultStore::new();
        vault.add_item(passkey("1", "example.com", "alice"));

        assert!(vault.search_by_domain("example.com").is_empty());
        assert_eq!(vault.get_item("1").unwrap().url(), None);
        assert_eq!(vault.get_item("1").unwrap().password(), None);
    }

    /// The snapshot cache must share one allocation across reads and go stale
    /// the moment `items` changes — including through the out-of-band paths
    /// (sync merge, whole-store swap) that bypass the CRUD methods.
    #[test]
    fn items_snapshot_shares_until_mutated() {
        let mut vault = VaultStore::new();
        vault.add_item(login("1", "Bank", "https://bank.example", "ada", "hunter2"));

        let first = vault.items_snapshot();
        let second = vault.items_snapshot();
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "reads between mutations must share one snapshot"
        );
        assert_eq!(first.len(), 1);

        // A method-mediated edit invalidates it.
        vault.update_item(login("1", "Bank Renamed", "https://bank.example", "ada", "hunter2"));
        assert!(!std::sync::Arc::ptr_eq(&first, &vault.items_snapshot()));
        assert_eq!(vault.items_snapshot()[0].name(), "Bank Renamed");

        // So does an out-of-band assignment that skips touch_generation…
        vault.items = vec![login("2", "Solo", "https://s.example", "bob", "p")];
        let stale = vault.items_snapshot();

        // …but a merge-style touch repairs it.
        vault.items = vec![login("3", "Merged", "https://m.example", "carol", "p")];
        vault.touch_generation();
        let fresh = vault.items_snapshot();
        assert!(!std::sync::Arc::ptr_eq(&stale, &fresh));
        assert_eq!(fresh[0].name(), "Merged");
    }

    /// Unlock/lock/recovery replace the whole store (`*vault_state = new`).
    /// Because the snapshot cache lives inside the store, a fresh or
    /// deserialized store can never serve another session's cached list —
    /// even though every deserialized store restarts at generation 0.
    #[test]
    fn a_replaced_store_never_serves_the_previous_sessions_snapshot() {
        let mut vault = VaultStore::new();
        vault.add_item(login("1", "Old session", "https://old.example", "ada", "p"));
        let old = vault.items_snapshot();

        // What unlock does: deserialize from disk (generation resets to 0)
        // and swap the store in wholesale.
        let json = serde_json::to_string(&vault).unwrap();
        let fresh: VaultStore = serde_json::from_str(&json).unwrap();
        assert_eq!(fresh.generation, 0, "generation is not serialized");

        let new_view = fresh.items_snapshot();
        assert!(!std::sync::Arc::ptr_eq(&old, &new_view));
        assert_eq!(old[0].name(), "Old session");
        assert_eq!(new_view[0].name(), "Old session"); // same content, own copy
    }

    #[test]
    fn passkeys_for_rp_matches_exactly_and_not_by_suffix() {
        let mut vault = VaultStore::new();
        vault.add_item(passkey("1", "example.com", "alice"));

        assert_eq!(vault.passkeys_for_rp("example.com").len(), 1);
        // The lookalike a login's PSL matching would happily accept.
        assert!(vault.passkeys_for_rp("evil-example.com").is_empty());
        assert!(vault.passkeys_for_rp("login.example.com").is_empty());
        assert!(vault.passkeys_for_rp("").is_empty());
    }

    #[test]
    fn passkey_lookup_by_credential_id() {
        let mut vault = VaultStore::new();
        vault.add_item(passkey("1", "example.com", "alice"));
        vault.add_item(passkey("2", "other.test", "bob"));

        assert_eq!(vault.passkey_by_credential_id("cred-2").unwrap().id(), "2");
        assert!(vault.passkey_by_credential_id("cred-nope").is_none());
    }

    #[test]
    fn deleting_from_the_middle_keeps_every_other_lookup_correct() {
        let mut vault = VaultStore::new();
        for i in 0..6 {
            vault.add_item(login(&i.to_string(), "N", "u", "a", "p"));
        }
        vault.delete_item("2", None);

        assert!(vault.get_item("2").is_none());
        // The index entries after the hole are shifted rather than rebuilt, so
        // an off-by-one there would surface as the wrong item coming back.
        for id in ["0", "1", "3", "4", "5"] {
            assert_eq!(vault.get_item(id).map(|i| i.id()), Some(id));
        }

        vault.delete_item("0", None);
        for id in ["1", "3", "4", "5"] {
            assert_eq!(vault.get_item(id).map(|i| i.id()), Some(id));
        }
    }

    /// The sync merge assigns `local.items` wholesale, which used to leave the
    /// index pointing at the previous positions — `get_item` then returned
    /// whichever item had moved into the slot.
    ///
    /// [`VaultStore::replace_items`] is the sanctioned replacement path: it
    /// reindexes up front, so lookups never fall into the scan fallback at
    /// all. The first half of this test pins the legacy direct-assignment
    /// behavior (reads stay *correct*, just O(n) until a mutation repairs the
    /// index); the second pins what merges should actually do.
    #[test]
    fn replacing_items_directly_does_not_return_the_wrong_item() {
        let mut vault = VaultStore::new();
        vault.add_item(login("a", "A", "u", "alice", "p"));
        vault.add_item(login("b", "B", "u", "bob", "p"));

        // Legacy shape: raw assignment leaves a lying index.
        vault.items = vec![
            login("b", "B", "u", "bob", "p"),
            login("a", "A", "u", "alice", "p"),
        ];

        assert_eq!(vault.get_item("a").unwrap().username(), Some("alice"));
        assert_eq!(vault.get_item("b").unwrap().username(), Some("bob"));

        // And the next mutation repairs the index instead of building on a lie.
        vault.add_item(login("c", "C", "u", "carol", "p"));
        assert_eq!(vault.get_item("a").unwrap().username(), Some("alice"));
        assert_eq!(vault.get_item("c").unwrap().username(), Some("carol"));
    }

    /// The merge path must go through [`VaultStore::replace_items`], which
    /// keeps the index honest immediately and drops the snapshot cache.
    #[test]
    fn replace_items_reindexes_and_invalidates_the_snapshot() {
        let mut vault = VaultStore::new();
        vault.add_item(login("a", "A", "u", "alice", "p"));
        vault.add_item(login("b", "B", "u", "bob", "p"));
        let before = vault.items_snapshot();

        // What a merge does now: a fresh vector, in a different order.
        vault.replace_items(vec![
            login("b", "B2", "u", "bob", "p"),
            login("a", "A2", "u", "alice", "p"),
        ]);

        assert_eq!(vault.get_item("a").unwrap().name(), "A2");
        assert_eq!(vault.get_item("b").unwrap().name(), "B2");
        assert_eq!(
            vault.item_index.len(),
            vault.items.len(),
            "index rebuilt to match the replacement"
        );

        let after = vault.items_snapshot();
        assert!(!std::sync::Arc::ptr_eq(&before, &after));
        assert_eq!(after.len(), 2);
        assert_eq!(after.iter().find(|i| i.id() == "a").unwrap().name(), "A2");
    }

    #[test]
    fn deserializing_a_vault_indexes_it() {
        let mut vault = VaultStore::new();
        for i in 0..4 {
            vault.add_item(login(&i.to_string(), "N", "u", "a", "p"));
        }
        let json = serde_json::to_vec(&vault).unwrap();
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
    }

    #[test]
    fn url_crate_elides_default_ports_like_the_fast_path() {
        // Why the fast path's `port.filter(|p| *p != default_port)` is not a
        // divergence from the URL parser: url's parser itself drops an
        // explicit port equal to the scheme's default (`parser.rs`:
        // `if opt_port == default_port() { opt_port = None }`), so
        // `Url::port()` never reports one. Pinned here so an `url` upgrade
        // that stopped eliding would surface as a test failure instead of a
        // silent mismatch between the two extraction paths.
        for (url, port) in [
            ("https://example.com:443", None),
            ("https://example.com", None),
            ("http://example.com:80", None),
            ("http://example.com", None),
            ("http://example.com:443", Some(443)),
            ("https://example.com:80", Some(80)),
            ("https://example.com:8443", Some(8443)),
        ] {
            let parsed = url::Url::parse(url).unwrap();
            assert_eq!(parsed.port(), port, "{url}");
        }
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
    fn password_generator_defaults() {
        let opts = PasswordGeneratorOptions::default();
        assert_eq!(opts.length, 20);
        assert!(opts.uppercase && opts.lowercase && opts.numbers && opts.symbols);
        assert!(!opts.easy_to_type && !opts.pronounceable);
    }
}
