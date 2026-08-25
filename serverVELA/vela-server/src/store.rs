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

use sled::{
    transaction::{ConflictableTransactionError, TransactionError},
    Db, Tree,
};

use crate::error::{AppError, Result};

const TTL_TREE: &str = "ttl";
const PERSIST_TREE: &str = "persist";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardedSetOutcome {
    Inserted,
    GuardMissing,
    KeyExists,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardedSetAbort {
    GuardMissing,
    KeyExists,
}

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

    /// Store two expiring records in one serializable transaction.
    ///
    /// Enrollment uses this only to restore a grant and its claim after the
    /// SQL epoch guard rejects a completion. Keeping the pair atomic prevents
    /// a retry from observing half a ceremony.
    pub fn set_ex_pair(
        &self,
        first_key: &str,
        first_value: &[u8],
        second_key: &str,
        second_value: &[u8],
        ttl_secs: u64,
    ) -> Result<()> {
        if first_key == second_key {
            return Err(AppError::Internal(
                "atomic TTL pair requires two distinct keys".into(),
            ));
        }
        let expiry = epoch_secs() + ttl_secs;
        let mut first_entry = expiry.to_le_bytes().to_vec();
        first_entry.extend_from_slice(first_value);
        let mut second_entry = expiry.to_le_bytes().to_vec();
        second_entry.extend_from_slice(second_value);

        self.ttl
            .transaction(|tree| {
                tree.insert(first_key.as_bytes(), first_entry.as_slice())?;
                tree.insert(second_key.as_bytes(), second_entry.as_slice())?;
                Ok(())
            })
            .map_err(|e: TransactionError<()>| match e {
                TransactionError::Storage(error) => map_err(error),
                TransactionError::Abort(()) => {
                    AppError::Internal("atomic TTL pair restore aborted".into())
                }
            })
    }

    /// Set a key **only if it is absent or expired**, atomically.
    ///
    /// Returns whether this caller was the one that set it.
    ///
    /// `set_ex` followed by a read cannot express "first writer wins": two
    /// racing callers both read absent and both write, and the second silently
    /// replaces the first. That is fine for a cache and fatal for a claim —
    /// enrollment depends on exactly one device ever being able to claim a
    /// grant, so a lost race has to be visible to the loser rather than
    /// overwritten (audit P-1).
    ///
    /// sled's `compare_and_swap` is the atomicity: the swap only lands if the
    /// stored bytes are still exactly what we read, so a concurrent writer makes
    /// ours fail rather than clobber.
    pub fn set_ex_nx(&self, key: &str, value: &[u8], ttl_secs: u64) -> Result<bool> {
        let expiry = epoch_secs() + ttl_secs;
        let mut entry = expiry.to_le_bytes().to_vec();
        entry.extend_from_slice(value);

        let current = self.ttl.get(key.as_bytes()).map_err(map_err)?;
        if let Some(ref data) = current {
            let (_, expired) = extract_value(data);
            // Present and still live: someone else already claimed this.
            if !expired {
                return Ok(false);
            }
        }

        // `current` is the exact bytes we based the decision on. If anything
        // changed in between — another claim landing — the swap fails and we
        // report the loss instead of overwriting their claim.
        let swapped = self
            .ttl
            .compare_and_swap(
                key.as_bytes(),
                current.as_ref().map(|d| d.as_ref()),
                Some(entry),
            )
            .map_err(|e| AppError::Internal(format!("sled cas error: {e}")))?;
        Ok(swapped.is_ok())
    }

    /// Set an expiring key only while another expiring key is live, with both
    /// predicates checked in the same serializable transaction.
    ///
    /// The enrollment claim uses the grant as its guard. This closes the gap
    /// between separately observing a live grant and winning `set_ex_nx`: an
    /// expiring grant can no longer leave behind a newly-created orphan claim.
    pub fn set_ex_nx_if_live(
        &self,
        guard_key: &str,
        key: &str,
        value: &[u8],
        ttl_secs: u64,
    ) -> Result<GuardedSetOutcome> {
        if guard_key == key {
            return Err(AppError::Internal(
                "guarded TTL set requires two distinct keys".into(),
            ));
        }
        let now = epoch_secs();
        let expiry = now + ttl_secs;
        let mut entry = expiry.to_le_bytes().to_vec();
        entry.extend_from_slice(value);

        let outcome = self.ttl.transaction(|tree| {
            match tree.get(guard_key.as_bytes())? {
                Some(guard) if !entry_is_expired_at(&guard, now) => {}
                _ => {
                    return Err(ConflictableTransactionError::Abort(
                        GuardedSetAbort::GuardMissing,
                    ));
                }
            }
            if let Some(current) = tree.get(key.as_bytes())? {
                if !entry_is_expired_at(&current, now) {
                    return Err(ConflictableTransactionError::Abort(
                        GuardedSetAbort::KeyExists,
                    ));
                }
            }
            tree.insert(key.as_bytes(), entry.as_slice())?;
            Ok(())
        });

        match outcome {
            Ok(()) => Ok(GuardedSetOutcome::Inserted),
            Err(TransactionError::Abort(GuardedSetAbort::GuardMissing)) => {
                Ok(GuardedSetOutcome::GuardMissing)
            }
            Err(TransactionError::Abort(GuardedSetAbort::KeyExists)) => {
                Ok(GuardedSetOutcome::KeyExists)
            }
            Err(TransactionError::Storage(error)) => Err(map_err(error)),
        }
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
    ///
    /// `Tree::remove` is the linearization point: it returns the bytes that
    /// this caller alone removed. The previous lookup-then-remove sequence let
    /// two racing recovery requests both read the same one-shot challenge or
    /// enrollment grant before either deletion landed.
    pub fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let removed = if let Some(data) = self.ttl.remove(key.as_bytes()).map_err(map_err)? {
            Some(data)
        } else if let Some(data) = self.persist.remove(key.as_bytes()).map_err(map_err)? {
            Some(data)
        } else {
            self.db.remove(key.as_bytes()).map_err(map_err)?
        };
        match removed {
            Some(data) => {
                let (value, expired) = extract_value(&data);
                Ok((!expired).then_some(value))
            }
            None => Ok(None),
        }
    }

    /// Atomically take two live TTL records, or leave both untouched.
    ///
    /// The transaction is the permanent-enrollment ceremony's linearization
    /// point: exactly one completion can consume both the grant and claim. A
    /// missing or expired member aborts without deleting its partner.
    pub fn take_live_pair(
        &self,
        first_key: &str,
        second_key: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        if first_key == second_key {
            return Err(AppError::Internal(
                "atomic TTL pair requires two distinct keys".into(),
            ));
        }
        let now = epoch_secs();
        let taken = self.ttl.transaction(|tree| {
            let first = match tree.get(first_key.as_bytes())? {
                Some(value) if !entry_is_expired_at(&value, now) => value,
                _ => return Err(ConflictableTransactionError::Abort(())),
            };
            let second = match tree.get(second_key.as_bytes())? {
                Some(value) if !entry_is_expired_at(&value, now) => value,
                _ => return Err(ConflictableTransactionError::Abort(())),
            };
            tree.remove(first_key.as_bytes())?;
            tree.remove(second_key.as_bytes())?;
            Ok((first, second))
        });

        match taken {
            Ok((first, second)) => Ok(Some((
                extract_value_at(&first, now).0,
                extract_value_at(&second, now).0,
            ))),
            Err(TransactionError::Abort(())) => Ok(None),
            Err(TransactionError::Storage(error)) => Err(map_err(error)),
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

    /// Atomically increment a counter whose TTL is **refreshed on every touch**,
    /// so it only forgets after `ttl_secs` of complete silence. Returns the new
    /// count.
    ///
    /// This is a *streak* counter, not a rate-limit window. Use it where
    /// "consecutive, with no long gap" is the intended meaning — the
    /// `/auth/verify` and web-session failure streaks that drive exponential
    /// backoff. For anything shaped like "N per minute" use
    /// [`incr_fixed_window`](Self::incr_fixed_window): refreshing the TTL makes
    /// a budget cumulative rather than periodic (red-team RT-7), so a caller
    /// that never pauses is charged for every request it has ever made.
    ///
    /// Uses sled's compare-and-swap `update_and_fetch` so concurrent requests
    /// cannot lose updates — this counter backs rate limiting, so a non-atomic
    /// read-modify-write would let an attacker undercount past the limit by
    /// issuing requests in parallel.
    pub fn incr_expire(&self, key: &str, delta: u64, ttl_secs: i64) -> Result<u64> {
        self.incr_inner(key, delta, ttl_secs, true)
    }

    /// Atomically increment a fixed-window counter. The window opens on the
    /// first increment and closes `window_secs` later regardless of traffic, so
    /// the count really does decay.
    ///
    /// This is what every "N per minute" limit needs. The previous behaviour
    /// pushed the expiry forward on each request, so the counter never reset
    /// while traffic continued: a browser polling every 2 s against a
    /// "120/min" cap accumulated to 120 and then locked itself out until it
    /// went quiet for a full minute (red-team RT-7).
    ///
    /// It is a fixed window, not a rolling one: a caller that saturates the end
    /// of one window and the start of the next can briefly send up to 2×`limit`
    /// across the boundary. That is the standard cost of an O(1)-memory counter,
    /// and it is bounded — unlike the old behaviour, which was unbounded in the
    /// other direction. Keeping per-key hit timestamps would remove it at the
    /// price of memory that grows with an attacker's request rate, which is a
    /// poor trade on a limiter whose job is to survive abuse.
    pub fn incr_fixed_window(&self, key: &str, delta: u64, window_secs: i64) -> Result<u64> {
        self.incr_inner(key, delta, window_secs, false)
    }

    fn incr_inner(&self, key: &str, delta: u64, ttl_secs: i64, refresh_ttl: bool) -> Result<u64> {
        let now = epoch_secs();
        let fresh_expiry = now + ttl_secs as u64;

        let updated = self
            .ttl
            .update_and_fetch(key.as_bytes(), |old| {
                // Decode the live count, treating missing/expired entries as 0.
                // Decode the live count and the window it belongs to, treating
                // missing/expired entries as a fresh window.
                let (current, live_expiry) = match old {
                    Some(data) if data.len() >= 16 => {
                        let mut exp = [0u8; 8];
                        exp.copy_from_slice(&data[..8]);
                        let stored_expiry = u64::from_le_bytes(exp);
                        if stored_expiry != u64::MAX && now >= stored_expiry {
                            (0, None)
                        } else {
                            let mut cnt = [0u8; 8];
                            cnt.copy_from_slice(&data[8..16]);
                            (u64::from_le_bytes(cnt), Some(stored_expiry))
                        }
                    }
                    _ => (0, None),
                };

                // A fixed window keeps the expiry it opened with, so the count
                // actually decays; a streak counter pushes it forward and only
                // forgets after a quiet period (red-team RT-7).
                let expiry = match live_expiry {
                    Some(stored) if !refresh_ttl => stored,
                    _ => fresh_expiry,
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
            return Err(AppError::Internal(
                "sled incr_expire wrote short value".into(),
            ));
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
    extract_value_at(data, epoch_secs())
}

fn extract_value_at(data: &[u8], now: u64) -> (Vec<u8>, bool) {
    if data.len() < 8 {
        return (data.to_vec(), false);
    }

    let mut exp_bytes = [0u8; 8];
    exp_bytes.copy_from_slice(&data[..8]);
    let expiry = u64::from_le_bytes(exp_bytes);

    let expired = expiry != u64::MAX && now >= expiry;
    let value = data[8..].to_vec();

    (value, expired)
}

fn entry_is_expired_at(data: &[u8], now: u64) -> bool {
    extract_value_at(data, now).1
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed-window counter must keep the expiry it opened with (red-team
    /// RT-7).
    ///
    /// The old behaviour pushed the expiry forward on every increment, so a
    /// counter never reset while traffic continued and "N per minute" silently
    /// meant "N since the last full minute of silence". A browser polling every
    /// 2 s against a 120/min cap reached 120 in four minutes and then locked
    /// itself out.
    #[test]
    fn a_fixed_window_keeps_the_expiry_it_opened_with() {
        let store = Store::open_temp().unwrap();
        for _ in 0..3 {
            store.incr_fixed_window("rl:test", 1, 60).unwrap();
        }
        let after_first_burst = store.ttl("rl:test").unwrap();

        // More traffic inside the same window must not buy more time.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(store.incr_fixed_window("rl:test", 1, 60).unwrap(), 4);
        let after_more_traffic = store.ttl("rl:test").unwrap();
        assert!(
            after_more_traffic < after_first_burst,
            "the window must keep closing while traffic continues: {after_first_burst}s -> \
             {after_more_traffic}s"
        );
    }

    /// The streak counter deliberately behaves the other way round: it forgets
    /// only after a quiet period, which is what "consecutive failures" means.
    /// Making it decay on a fixed window would let an attacker reset their own
    /// backoff by straddling a boundary.
    #[test]
    fn a_streak_counter_still_refreshes_its_ttl() {
        let store = Store::open_temp().unwrap();
        store.incr_expire("rl:streak:test", 1, 60).unwrap();
        let after_first = store.ttl("rl:streak:test").unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(store.incr_expire("rl:streak:test", 1, 60).unwrap(), 2);
        let after_second = store.ttl("rl:streak:test").unwrap();
        assert!(
            after_second >= after_first,
            "a streak must not expire while failures keep arriving: {after_first}s -> \
             {after_second}s"
        );
    }

    /// First-claim-wins is the whole point of `set_ex_nx`; a lost race has to be
    /// reported to the loser, not silently overwritten (audit P-1).
    #[test]
    fn set_ex_nx_lets_exactly_one_writer_win() {
        let store = Store::open_temp().unwrap();
        assert!(store.set_ex_nx("grant:1", b"device-a", 60).unwrap());
        assert!(
            !store.set_ex_nx("grant:1", b"device-b", 60).unwrap(),
            "a second claim must lose"
        );
        assert_eq!(store.get("grant:1").unwrap().unwrap(), b"device-a");
    }

    #[test]
    fn set_ex_nx_wins_under_concurrency_exactly_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let store = Arc::new(Store::open_temp().unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let winners = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let store = store.clone();
                let barrier = barrier.clone();
                let winners = winners.clone();
                std::thread::spawn(move || {
                    // Release them together, so this is a real race rather than
                    // eight sequential calls.
                    barrier.wait();
                    if store
                        .set_ex_nx("grant:race", format!("device-{i}").as_bytes(), 60)
                        .unwrap()
                    {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            winners.load(Ordering::SeqCst),
            1,
            "exactly one of eight racing claims may win"
        );
    }

    #[test]
    fn an_expired_claim_does_not_block_a_new_one() {
        // Otherwise an abandoned grant would poison its key until sled's own
        // cleanup ran, and the user would see enrollment fail for no reason.
        let store = Store::open_temp().unwrap();
        assert!(store.set_ex_nx("grant:2", b"stale", 0).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(store.set_ex_nx("grant:2", b"fresh", 60).unwrap());
        assert_eq!(store.get("grant:2").unwrap().unwrap(), b"fresh");
    }

    #[test]
    fn taking_a_pair_is_all_or_nothing() {
        let store = Store::open_temp().unwrap();
        store.set_ex("grant:pair", b"grant", 60).unwrap();

        assert_eq!(
            store.take_live_pair("grant:pair", "claim:pair").unwrap(),
            None
        );
        assert_eq!(store.get("grant:pair").unwrap().unwrap(), b"grant");

        store.set_ex("claim:pair", b"claim", 60).unwrap();
        assert_eq!(
            store.take_live_pair("grant:pair", "claim:pair").unwrap(),
            Some((b"grant".to_vec(), b"claim".to_vec()))
        );
        assert!(!store.exists("grant:pair").unwrap());
        assert!(!store.exists("claim:pair").unwrap());
    }

    #[test]
    fn a_claim_cannot_be_created_without_a_live_grant() {
        let store = Store::open_temp().unwrap();
        assert_eq!(
            store
                .set_ex_nx_if_live("grant:guard", "claim:guard", b"claim", 60)
                .unwrap(),
            GuardedSetOutcome::GuardMissing
        );
        assert!(!store.exists("claim:guard").unwrap());

        store.set_ex("grant:guard", b"grant", 60).unwrap();
        assert_eq!(
            store
                .set_ex_nx_if_live("grant:guard", "claim:guard", b"first", 60)
                .unwrap(),
            GuardedSetOutcome::Inserted
        );
        assert_eq!(
            store
                .set_ex_nx_if_live("grant:guard", "claim:guard", b"second", 60)
                .unwrap(),
            GuardedSetOutcome::KeyExists
        );
        assert_eq!(store.get("claim:guard").unwrap().unwrap(), b"first");
    }

    #[test]
    fn exactly_one_racing_completion_takes_the_whole_pair() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let store = Arc::new(Store::open_temp().unwrap());
        store.set_ex("grant:complete-race", b"grant", 60).unwrap();
        store.set_ex("claim:complete-race", b"claim", 60).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let winners = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                let barrier = barrier.clone();
                let winners = winners.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    if store
                        .take_live_pair("grant:complete-race", "claim:complete-race")
                        .unwrap()
                        .is_some()
                    {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(winners.load(Ordering::SeqCst), 1);
        assert!(!store.exists("grant:complete-race").unwrap());
        assert!(!store.exists("claim:complete-race").unwrap());
    }

    #[test]
    fn get_del_redeems_a_one_shot_artifact_exactly_once_under_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let store = Arc::new(Store::open_temp().unwrap());
        store.set_ex("recovery:one-shot", b"challenge", 60).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let winners = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                let barrier = barrier.clone();
                let winners = winners.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    if store.get_del("recovery:one-shot").unwrap().is_some() {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(winners.load(Ordering::SeqCst), 1);
    }
}
