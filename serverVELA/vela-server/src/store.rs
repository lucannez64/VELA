//! Embedded key-value store backed by **sled**, providing Redis-like operations
//! with TTL support.
//!
//! sled is used instead of Redis to eliminate an external infrastructure
//! dependency.  TTL is implemented by storing the expiry epoch alongside each
//! value and checking on read.
//!
//! Keys are stored in separate trees for efficient prefix-scoped cleanup:
//! - `ttl` tree: keys with TTL (expiring)
//! - `persist` tree: keys without TTL (persistent)
//! - Default tree: legacy keys (auto-migrated on first access)

use std::sync::Arc;

use sled::{Db, Tree};

use crate::error::{AppError, Result};

const TTL_TREE: &str = "ttl";
const PERSIST_TREE: &str = "persist";

#[derive(Clone, Copy)]
enum LookupSource {
    Ttl,
    Persist,
    Legacy,
}

fn map_err(e: sled::Error) -> AppError {
    AppError::Internal(format!("sled error: {e}"))
}

/// Wrapper around a sled database providing TTL-aware operations.
#[derive(Clone)]
pub struct Store {
    db: Arc<Db>,
    ttl: Arc<Tree>,
    persist: Arc<Tree>,
}

impl Store {
    /// Open a sled database at the given path.  
    /// Opens the `ttl` and `persist` trees for prefix-scoped access.
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path).map_err(|e| {
            AppError::Internal(format!("failed to open sled database at {path}: {e}"))
        })?;
        let ttl = db
            .open_tree(TTL_TREE)
            .map_err(|e| AppError::Internal(format!("failed to open ttl tree: {e}")))?;
        let persist = db
            .open_tree(PERSIST_TREE)
            .map_err(|e| AppError::Internal(format!("failed to open persist tree: {e}")))?;
        // One-time migration of legacy keys from the default tree.
        Self::migrate_legacy_keys(&db, &ttl, &persist);
        Ok(Self {
            db: Arc::new(db),
            ttl: Arc::new(ttl),
            persist: Arc::new(persist),
        })
    }

    /// Open a temporary in-memory database (for tests).
    pub fn open_temp() -> Result<Self> {
        let db = sled::Config::new().temporary(true).open().map_err(|e| {
            AppError::Internal(format!("failed to open temporary sled database: {e}"))
        })?;
        let ttl = db
            .open_tree(TTL_TREE)
            .map_err(|e| AppError::Internal(format!("failed to open ttl tree: {e}")))?;
        let persist = db
            .open_tree(PERSIST_TREE)
            .map_err(|e| AppError::Internal(format!("failed to open persist tree: {e}")))?;
        Ok(Self {
            db: Arc::new(db),
            ttl: Arc::new(ttl),
            persist: Arc::new(persist),
        })
    }

    pub fn inner(&self) -> &Db {
        &self.db
    }

    /// One-time migration: move legacy keys from the default tree into
    /// `ttl` or `persist` based on whether they have an expiry.
    fn migrate_legacy_keys(db: &Db, ttl: &Tree, persist: &Tree) {
        let mut migrated = 0u64;
        for item in db.iter() {
            let (k, v) = match item {
                Ok(iv) => iv,
                Err(_) => continue,
            };
            // Set-metadata keys (`set:meta:{key}`) live in the default tree by
            // design — del_set/smembers read them from here. Migrating them
            // into the ttl tree would detach expiry checks from the set trees.
            if k.starts_with(b"set:meta:") {
                continue;
            }
            if v.len() < 8 {
                let _ = persist.insert(&k, v);
                let _ = db.remove(&k);
                migrated += 1;
                continue;
            }
            let mut exp_bytes = [0u8; 8];
            exp_bytes.copy_from_slice(&v[..8]);
            let expiry = u64::from_le_bytes(exp_bytes);
            if expiry == u64::MAX {
                let _ = persist.insert(&k, v);
            } else {
                let _ = ttl.insert(&k, v);
            }
            let _ = db.remove(&k);
            migrated += 1;
        }
        if migrated > 0 {
            tracing::info!(migrated, "sled legacy key migration complete");
        }
    }

    // ─── String-like operations ──────────────────────────────────────────────

    /// Set a key with a TTL in seconds.
    pub fn set_ex(&self, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        let expiry = epoch_secs() + ttl_secs;
        let mut entry = expiry.to_le_bytes().to_vec();
        entry.extend_from_slice(value);
        self.ttl
            .insert(key.as_bytes(), entry)
            .map_err(|e| AppError::Internal(format!("sled set_ex error: {e}")))?;
        Ok(())
    }

    /// Set a key without TTL (persists until deleted).
    pub fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut entry = u64::MAX.to_le_bytes().to_vec();
        entry.extend_from_slice(value);
        self.persist
            .insert(key.as_bytes(), entry)
            .map_err(|e| AppError::Internal(format!("sled set error: {e}")))?;
        Ok(())
    }

    fn lookup_tree(&self, key: &str) -> Result<Option<(Vec<u8>, LookupSource)>> {
        if let Some(data) = self.ttl.get(key.as_bytes()).map_err(map_err)? {
            return Ok(Some((data.to_vec(), LookupSource::Ttl)));
        }
        if let Some(data) = self.persist.get(key.as_bytes()).map_err(map_err)? {
            return Ok(Some((data.to_vec(), LookupSource::Persist)));
        }
        if let Some(data) = self.db.get(key.as_bytes()).map_err(map_err)? {
            return Ok(Some((data.to_vec(), LookupSource::Legacy)));
        }
        Ok(None)
    }

    fn remove_from_source(&self, key: &str, source: LookupSource) -> Result<()> {
        match source {
            LookupSource::Ttl => {
                self.ttl.remove(key.as_bytes()).map_err(map_err)?;
            }
            LookupSource::Persist => {
                self.persist.remove(key.as_bytes()).map_err(map_err)?;
            }
            LookupSource::Legacy => {
                self.db.remove(key.as_bytes()).map_err(map_err)?;
            }
        }
        Ok(())
    }

    /// Get a key's value. Returns `None` if missing or expired.
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.lookup_tree(key)? {
            Some((data, source)) => {
                let (value, expired) = extract_value(&data);
                if expired {
                    let _ = match source {
                        LookupSource::Ttl => self.ttl.remove(key.as_bytes()),
                        LookupSource::Persist => self.persist.remove(key.as_bytes()),
                        LookupSource::Legacy => self.db.remove(key.as_bytes()),
                    };
                    Ok(None)
                } else {
                    Ok(Some(value))
                }
            }
            None => Ok(None),
        }
    }

    /// Get and delete a key atomically. Returns `None` if missing or expired.
    pub fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.lookup_tree(key)? {
            Some((data, source)) => {
                self.remove_from_source(key, source)?;
                let (value, expired) = extract_value(&data);
                if expired {
                    Ok(None)
                } else {
                    Ok(Some(value))
                }
            }
            None => Ok(None),
        }
    }

    /// Delete a key. Returns how many keys were removed (0 or 1).
    pub fn del(&self, key: &str) -> Result<i64> {
        match self.lookup_tree(key)? {
            Some((_, source)) => {
                self.remove_from_source(key, source)?;
                Ok(1)
            }
            None => Ok(0),
        }
    }

    /// Check whether a key exists (and is not expired).
    pub fn exists(&self, key: &str) -> Result<bool> {
        match self.lookup_tree(key)? {
            Some((data, source)) => {
                let (_, expired) = extract_value(&data);
                if expired {
                    let _ = match source {
                        LookupSource::Ttl => self.ttl.remove(key.as_bytes()),
                        LookupSource::Persist => self.persist.remove(key.as_bytes()),
                        LookupSource::Legacy => self.db.remove(key.as_bytes()),
                    };
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
            None => Ok(false),
        }
    }

    /// Atomically increment a counter key by `delta` and set/refresh its TTL.
    /// Returns the new count.
    ///
    /// Uses sled's compare-and-swap `update_and_fetch` so concurrent requests
    /// cannot lose updates — this counter backs rate limiting, so a non-atomic
    /// read-modify-write would let an attacker undercount past the limit by
    /// issuing requests in parallel.
    pub fn incr_expire(&self, key: &str, delta: u64, ttl_secs: i64) -> Result<u64> {
        let now = epoch_secs();
        let expiry = now + ttl_secs as u64;

        let updated = self
            .ttl
            .update_and_fetch(key.as_bytes(), |old| {
                // Decode the live count, treating missing/expired entries as 0.
                let current = match old {
                    Some(data) if data.len() >= 16 => {
                        let mut exp = [0u8; 8];
                        exp.copy_from_slice(&data[..8]);
                        let stored_expiry = u64::from_le_bytes(exp);
                        if stored_expiry != u64::MAX && now >= stored_expiry {
                            0
                        } else {
                            let mut cnt = [0u8; 8];
                            cnt.copy_from_slice(&data[8..16]);
                            u64::from_le_bytes(cnt)
                        }
                    }
                    _ => 0,
                };

                let new_count = current.saturating_add(delta);
                let mut entry = expiry.to_le_bytes().to_vec();
                entry.extend_from_slice(&new_count.to_le_bytes());
                Some(entry)
            })
            .map_err(|e| AppError::Internal(format!("sled incr_expire error: {e}")))?;

        let data = updated
            .ok_or_else(|| AppError::Internal("sled incr_expire returned no value".into()))?;
        if data.len() < 16 {
            return Err(AppError::Internal("sled incr_expire wrote short value".into()));
        }
        let mut cnt = [0u8; 8];
        cnt.copy_from_slice(&data[8..16]);
        Ok(u64::from_le_bytes(cnt))
    }

    /// Get remaining TTL for a key in seconds. Returns -1 if no TTL, -2 if
    /// key doesn't exist or is expired.
    pub fn ttl(&self, key: &str) -> Result<i64> {
        match self.lookup_tree(key)? {
            Some((data, source)) if data.len() >= 8 => {
                let mut exp_bytes = [0u8; 8];
                exp_bytes.copy_from_slice(&data[..8]);
                let expiry = u64::from_le_bytes(exp_bytes);

                if expiry == u64::MAX {
                    return Ok(-1);
                }

                let now = epoch_secs();
                if now >= expiry {
                    self.remove_from_source(key, source)?;
                    Ok(-2)
                } else {
                    Ok((expiry - now) as i64)
                }
            }
            Some(_) => Ok(-1),
            None => Ok(-2),
        }
    }

    // ─── Set-like operations ─────────────────────────────────────────────────

    /// Add a member to a set stored at `key`. The set's TTL is refreshed to
    /// `ttl_secs`.
    pub fn sadd(&self, key: &str, member: &str, ttl_secs: i64) -> Result<()> {
        let set_tree_name = format!("set:{key}");
        let tree = self
            .db
            .open_tree(&set_tree_name)
            .map_err(|e| AppError::Internal(format!("sled sadd tree error: {e}")))?;

        tree.insert(member.as_bytes(), &[])
            .map_err(|e| AppError::Internal(format!("sled sadd error: {e}")))?;

        let meta_key = format!("set:meta:{key}");
        let expiry = epoch_secs() + ttl_secs as u64;
        self.db
            .insert(meta_key.as_bytes(), &expiry.to_le_bytes())
            .map_err(|e| AppError::Internal(format!("sled sadd meta error: {e}")))?;

        Ok(())
    }

    /// Get all members of a set.
    pub fn smembers(&self, key: &str) -> Result<Vec<String>> {
        let set_tree_name = format!("set:{key}");

        let meta_key = format!("set:meta:{key}");
        if let Some(meta) = self
            .db
            .get(meta_key.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled smembers meta error: {e}")))?
        {
            if meta.len() >= 8 {
                let mut exp_bytes = [0u8; 8];
                exp_bytes.copy_from_slice(&meta[..8]);
                let expiry = u64::from_le_bytes(exp_bytes);
                if epoch_secs() >= expiry {
                    self.del_set(key)?;
                    return Ok(Vec::new());
                }
            }
        }

        let tree = self
            .db
            .open_tree(&set_tree_name)
            .map_err(|e| AppError::Internal(format!("sled smembers tree error: {e}")))?;

        let mut members = Vec::new();
        for item in tree.iter() {
            let (k, _) =
                item.map_err(|e| AppError::Internal(format!("sled smembers iterate error: {e}")))?;
            members.push(String::from_utf8(k.to_vec()).unwrap_or_default());
        }
        Ok(members)
    }

    /// Delete an entire set (tree + metadata).
    pub fn del_set(&self, key: &str) -> Result<()> {
        let set_tree_name = format!("set:{key}");
        self.db
            .drop_tree(set_tree_name.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled del_set tree error: {e}")))?;

        let meta_key = format!("set:meta:{key}");
        self.db
            .remove(meta_key.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled del_set meta error: {e}")))?;

        Ok(())
    }

    /// Run a background cleanup pass that removes expired entries.
    /// **Only scans the `ttl` tree** for O(ttl_keys) efficiency.
    /// Call periodically from a tokio task.
    pub fn cleanup_expired(&self) -> Result<u64> {
        let now = epoch_secs();
        let mut removed = 0u64;

        for item in self.ttl.iter() {
            let (k, v) =
                item.map_err(|e| AppError::Internal(format!("sled cleanup iterate error: {e}")))?;

            if v.len() >= 8 {
                let mut exp_bytes = [0u8; 8];
                exp_bytes.copy_from_slice(&v[..8]);
                let expiry = u64::from_le_bytes(exp_bytes);
                if now >= expiry {
                    self.ttl.remove(&k).map_err(|e| {
                        AppError::Internal(format!("sled cleanup remove error: {e}"))
                    })?;
                    removed += 1;
                }
            }
        }

        // Sweep expired set trees: their `set:meta:{key}` expiry markers live
        // in the default tree, so collect expired set keys first (del_set
        // writes back into the default tree, so we must not mutate while
        // iterating).
        let mut expired_sets: Vec<String> = Vec::new();
        for item in self.db.iter() {
            let (k, v) =
                item.map_err(|e| AppError::Internal(format!("sled cleanup iterate error: {e}")))?;
            if !k.starts_with(b"set:meta:") || v.len() < 8 {
                continue;
            }
            let mut exp_bytes = [0u8; 8];
            exp_bytes.copy_from_slice(&v[..8]);
            if now >= u64::from_le_bytes(exp_bytes) {
                if let Ok(meta_key) = String::from_utf8(k.to_vec()) {
                    expired_sets.push(meta_key["set:meta:".len()..].to_string());
                }
            }
        }
        for set_key in expired_sets {
            self.del_set(&set_key)?;
            removed += 1;
        }

        Ok(removed)
    }
}

fn extract_value(data: &[u8]) -> (Vec<u8>, bool) {
    if data.len() < 8 {
        return (data.to_vec(), false);
    }

    let mut exp_bytes = [0u8; 8];
    exp_bytes.copy_from_slice(&data[..8]);
    let expiry = u64::from_le_bytes(exp_bytes);

    let expired = expiry != u64::MAX && epoch_secs() >= expiry;
    let value = data[8..].to_vec();

    (value, expired)
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
