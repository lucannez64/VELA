//! Embedded key-value store backed by **sled**, providing Redis-like operations
//! with TTL support.
//!
//! sled is used instead of Redis to eliminate an external infrastructure
//! dependency.  TTL is implemented by storing the expiry epoch alongside each
//! value and checking on read.

use std::sync::Arc;

use sled::Db;

use crate::error::{AppError, Result};

/// Wrapper around a sled database providing TTL-aware operations.
#[derive(Clone)]
pub struct Store {
    db: Arc<Db>,
}

impl Store {
    /// Open a sled database at the given path.
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path).map_err(|e| {
            AppError::Internal(format!("failed to open sled database at {path}: {e}"))
        })?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Open a temporary in-memory database (for tests).
    pub fn open_temp() -> Result<Self> {
        let db = sled::Config::new().temporary(true).open().map_err(|e| {
            AppError::Internal(format!("failed to open temporary sled database: {e}"))
        })?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn inner(&self) -> &Db {
        &self.db
    }

    // ─── String-like operations ──────────────────────────────────────────────

    /// Set a key with a TTL in seconds.
    pub fn set_ex(&self, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        let expiry = epoch_secs() + ttl_secs;
        let mut entry = expiry.to_le_bytes().to_vec();
        entry.extend_from_slice(value);
        self.db
            .insert(key.as_bytes(), entry)
            .map_err(|e| AppError::Internal(format!("sled set_ex error: {e}")))?;
        Ok(())
    }

    /// Set a key without TTL (persists until deleted).
    pub fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut entry = u64::MAX.to_le_bytes().to_vec();
        entry.extend_from_slice(value);
        self.db
            .insert(key.as_bytes(), entry)
            .map_err(|e| AppError::Internal(format!("sled set error: {e}")))?;
        Ok(())
    }

    /// Get a key's value. Returns `None` if missing or expired.
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let ivec = self
            .db
            .get(key.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled get error: {e}")))?;

        match ivec {
            Some(data) => {
                let (value, expired) = extract_value(&data);
                if expired {
                    let _ = self.db.remove(key.as_bytes());
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
        let ivec = self
            .db
            .get(key.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled get_del error: {e}")))?;

        self.db
            .remove(key.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled get_del remove error: {e}")))?;

        match ivec {
            Some(data) => {
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
        let existed = self
            .db
            .contains_key(key.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled del check error: {e}")))?;
        self.db
            .remove(key.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled del error: {e}")))?;
        Ok(if existed { 1 } else { 0 })
    }

    /// Check whether a key exists (and is not expired).
    pub fn exists(&self, key: &str) -> Result<bool> {
        let ivec = self
            .db
            .get(key.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled exists error: {e}")))?;

        match ivec {
            Some(data) => {
                let (_, expired) = extract_value(&data);
                if expired {
                    let _ = self.db.remove(key.as_bytes());
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
            None => Ok(false),
        }
    }

    /// Increment a counter key by `delta` and set/refresh its TTL.
    /// Returns the new count.
    pub fn incr_expire(&self, key: &str, delta: u64, ttl_secs: i64) -> Result<u64> {
        let current = match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => {
                let (value, expired) = extract_value(&data);
                if expired {
                    0u64
                } else {
                    let bytes: [u8; 8] = value.try_into().unwrap_or_else(|v: Vec<u8>| {
                        let mut arr = [0u8; 8];
                        let len = v.len().min(8);
                        arr[..len].copy_from_slice(&v[..len]);
                        arr
                    });
                    u64::from_le_bytes(bytes)
                }
            }
            _ => 0,
        };

        let new_count = current + delta;
        let expiry = epoch_secs() + ttl_secs as u64;
        let mut entry = expiry.to_le_bytes().to_vec();
        entry.extend_from_slice(&new_count.to_le_bytes());

        self.db
            .insert(key.as_bytes(), entry)
            .map_err(|e| AppError::Internal(format!("sled incr_expire error: {e}")))?;

        Ok(new_count)
    }

    /// Get remaining TTL for a key in seconds. Returns -1 if no TTL, -2 if
    /// key doesn't exist or is expired.
    pub fn ttl(&self, key: &str) -> Result<i64> {
        let ivec = self
            .db
            .get(key.as_bytes())
            .map_err(|e| AppError::Internal(format!("sled ttl error: {e}")))?;

        match ivec {
            Some(data) if data.len() >= 8 => {
                let mut exp_bytes = [0u8; 8];
                exp_bytes.copy_from_slice(&data[..8]);
                let expiry = u64::from_le_bytes(exp_bytes);

                if expiry == u64::MAX {
                    return Ok(-1);
                }

                let now = epoch_secs();
                if now >= expiry {
                    let _ = self.db.remove(key.as_bytes());
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
    /// Call periodically from a tokio task.
    pub fn cleanup_expired(&self) -> Result<u64> {
        let now = epoch_secs();
        let mut removed = 0u64;

        for item in self.db.iter() {
            let (k, v) =
                item.map_err(|e| AppError::Internal(format!("sled cleanup iterate error: {e}")))?;

            if v.len() >= 8 {
                let mut exp_bytes = [0u8; 8];
                exp_bytes.copy_from_slice(&v[..8]);
                let expiry = u64::from_le_bytes(exp_bytes);
                if expiry != u64::MAX && now >= expiry {
                    self.db.remove(&k).map_err(|e| {
                        AppError::Internal(format!("sled cleanup remove error: {e}"))
                    })?;
                    removed += 1;
                }
            }
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
