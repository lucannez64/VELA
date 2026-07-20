//! Path ORAM state management (client-side).
//!
//! The client maintains a position map (`chunk_id → current leaf index`) and a
//! local stash of chunks evicted from the tree during path reads.
//!
//! This module implements the *client state machine* only — it does NOT perform
//! any network I/O or encryption.  Callers are responsible for:
//!   1. Reading the path from the server (the bucket sequence root→leaf).
//!   2. Decrypting each bucket to recover [`OramBlock`] values.
//!   3. Feeding the decrypted path into [`PathOram::read_path`].
//!   4. Encrypting the returned write-back path and uploading it.
//!
//! For vaults with ≤ 4 active chunks the client uses trivial ORAM: every sync
//! downloads and re-uploads all chunks regardless of which one is needed.
//! Switch to Path ORAM once [`PathOram::use_trivial_oram`] returns `false`.

use rand_core::{OsRng, RngCore};
use std::collections::HashMap;

use crate::error::{Result, VelaError};

// ── Parameters ────────────────────────────────────────────────────────────────

/// Number of real blocks per bucket (Z in the Path ORAM paper).
pub const BUCKET_SIZE: usize = 4;
/// Use trivial ORAM for vaults with at most this many chunks.
pub const TRIVIAL_ORAM_THRESHOLD: usize = 4;
/// Vault chunk size in bytes (1 MB, as per spec §5.2).
pub const CHUNK_SIZE: usize = 1024 * 1024;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A 128-bit chunk identifier (UUID compatible).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChunkId(pub [u8; 16]);

impl ChunkId {
    pub fn random() -> Self {
        let mut buf = [0u8; 16];
        OsRng.fill_bytes(&mut buf);
        // Set UUID v4 version and variant bits.
        buf[6] = (buf[6] & 0x0f) | 0x40;
        buf[8] = (buf[8] & 0x3f) | 0x80;
        Self(buf)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A leaf index (0-based) in the binary ORAM tree.
pub type LeafIdx = u64;

/// A single ORAM block: an optional real chunk, or a dummy filler.
#[derive(Clone, Debug)]
pub enum OramBlock {
    Real { id: ChunkId, data: Vec<u8> },
    Dummy,
}

impl OramBlock {
    pub fn is_real(&self) -> bool {
        matches!(self, OramBlock::Real { .. })
    }

    pub fn chunk_id(&self) -> Option<&ChunkId> {
        match self {
            OramBlock::Real { id, .. } => Some(id),
            OramBlock::Dummy => None,
        }
    }
}

/// A single bucket in the ORAM tree: up to `BUCKET_SIZE` blocks.
pub type Bucket = Vec<OramBlock>;

/// A path from root to leaf: `[root_bucket, …, leaf_bucket]`.
pub type OramPath = Vec<Bucket>;

// ── PathOram ─────────────────────────────────────────────────────────────────

/// Client-side Path ORAM state.
pub struct PathOram {
    /// Tree height (number of levels above leaves).  Total leaves = 2^height.
    height: u32,
    /// Position map: chunk_id → current leaf.
    position_map: HashMap<ChunkId, LeafIdx>,
    /// Client-side stash of blocks not yet evicted into the tree.
    stash: Vec<OramBlock>,
    /// Total number of leaves = 2^height.
    num_leaves: u64,
}

impl PathOram {
    /// Create a new ORAM instance with a tree sized to hold at least
    /// `capacity` real blocks.  Minimum height is 1 (2 leaves).
    pub fn new(capacity: usize) -> Self {
        // Height h such that 2^h >= capacity * 2  (factor 2 for headroom).
        let needed_leaves = ((capacity * 2) as f64).log2().ceil() as u32;
        let height = needed_leaves.max(1);
        let num_leaves = 1u64 << height;
        Self {
            height,
            position_map: HashMap::new(),
            stash: Vec::new(),
            num_leaves,
        }
    }

    /// Returns `true` when trivial ORAM should be used instead.
    pub fn use_trivial_oram(chunk_count: usize) -> bool {
        chunk_count <= TRIVIAL_ORAM_THRESHOLD
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn num_leaves(&self) -> u64 {
        self.num_leaves
    }

    /// Return the current leaf for `id`, or assign a fresh random one.
    pub fn position_of(&mut self, id: &ChunkId) -> LeafIdx {
        *self
            .position_map
            .entry(*id)
            .or_insert_with(|| random_leaf(self.num_leaves))
    }

    /// Register a new chunk with a random leaf position.
    pub fn register(&mut self, id: ChunkId) -> LeafIdx {
        let leaf = random_leaf(self.num_leaves);
        self.position_map.insert(id, leaf);
        leaf
    }

    /// Remove a chunk from the position map (e.g. on vault item deletion).
    pub fn unregister(&mut self, id: &ChunkId) {
        self.position_map.remove(id);
        self.stash.retain(|b| b.chunk_id() != Some(id));
    }

    /// **Step 1 of a Path ORAM access.**
    ///
    /// Look up the current leaf for `target`, re-assign it a fresh random leaf
    /// (so the next access hits a different path), and return the *old* leaf
    /// (which tells the caller which path to download from the server).
    pub fn prepare_access(&mut self, target: &ChunkId) -> Result<LeafIdx> {
        if !self.position_map.contains_key(target) {
            return Err(VelaError::OramError(format!(
                "chunk {:?} not found in position map",
                target
            )));
        }
        let old_leaf = self.position_map[target];
        // Remap to a fresh random leaf.
        self.position_map
            .insert(*target, random_leaf(self.num_leaves));
        Ok(old_leaf)
    }

    /// **Step 2 of a Path ORAM access.**
    ///
    /// Absorb the downloaded path (root→leaf) into the stash, then extract the
    /// target block (returning its data) and a new block to write back in its
    /// place (data provided by caller for writes; `None` for reads).
    ///
    /// Returns `(target_data, write_back_path)`.
    ///
    /// * `path`        — decrypted blocks from the server, root-to-leaf.
    /// * `target`      — the chunk being accessed.
    /// * `write_data`  — for writes, the new plaintext; `None` for reads.
    pub fn access(
        &mut self,
        path: OramPath,
        target: &ChunkId,
        write_data: Option<Vec<u8>>,
    ) -> Result<(Option<Vec<u8>>, OramPath)> {
        // Absorb path into stash.
        for bucket in path {
            for block in bucket {
                if block.is_real() {
                    self.stash.push(block);
                }
            }
        }

        // Extract the target block from the stash.
        let target_idx = self.stash.iter().position(|b| b.chunk_id() == Some(target));

        let existing_data = target_idx.map(|i| {
            let block = self.stash.remove(i);
            match block {
                OramBlock::Real { data, .. } => data,
                OramBlock::Dummy => unreachable!(),
            }
        });

        // If this is a write (or a read-then-write), push updated block back.
        let new_leaf = *self.position_map.get(target).ok_or_else(|| {
            VelaError::OramError(format!("chunk {:?} not found in position map", target))
        })?;
        let new_data = write_data.or_else(|| existing_data.clone());
        if let Some(data) = new_data {
            self.stash.push(OramBlock::Real { id: *target, data });
        }

        // Evict from stash into write-back path (greedy algorithm).
        let write_path = self.evict(new_leaf);

        Ok((existing_data, write_path))
    }

    /// Greedily evict stash blocks into the write-back path using the Path ORAM
    /// greedy algorithm: each real block is placed at the **deepest** level
    /// whose subtree (on the path root→`leaf`) also contains the block's
    /// assigned leaf — i.e. the level of the lowest common ancestor. This keeps
    /// per-access bandwidth at O(BUCKET_SIZE · log N) instead of dumping every
    /// block into the root bucket. Each bucket is capped at `BUCKET_SIZE`;
    /// overflow stays in the stash (standard Path ORAM behavior — the stash is
    /// re-read into on the next access). Buckets are padded with dummies so all
    /// buckets are a constant size.
    fn evict(&mut self, leaf: LeafIdx) -> OramPath {
        let levels = (self.height + 1) as usize;
        let mut path: OramPath = vec![Vec::new(); levels];

        // Move the stash into an owned Vec first so we can borrow `self`
        // (position_map / deepest_shared_level) while deciding placement.
        let stash = std::mem::take(&mut self.stash);
        let mut remaining: Vec<OramBlock> = Vec::with_capacity(stash.len());
        for block in stash {
            // Decide the destination level using only the block's id, without
            // holding a borrow on `block` (so it can be moved into the bucket).
            let dest_level: Option<usize> = block.chunk_id().and_then(|id| {
                self.position_map
                    .get(id)
                    .copied()
                    .and_then(|bl| self.deepest_shared_level(leaf, bl))
            });
            match dest_level {
                Some(level) if path[level].len() < BUCKET_SIZE => {
                    path[level].push(block);
                }
                _ => {
                    // Bucket at the deepest shared level is full, or the block
                    // has no leaf mapping: keep it in the stash for next time.
                    remaining.push(block);
                }
            }
        }
        self.stash = remaining;

        // Pad every bucket to BUCKET_SIZE with dummies for constant-size buckets.
        for level in 0..levels {
            while path[level].len() < BUCKET_SIZE {
                path[level].push(OramBlock::Dummy);
            }
        }

        path
    }

    /// Deepest level `L` (0=root .. `height`=leaf) whose subtree on the path to
    /// `leaf` also contains `other`. This is the level of the lowest common
    /// ancestor of `leaf` and `other`. Always returns at least `0` for any
    /// `other < num_leaves`, since level 0 (the root) spans every leaf.
    fn deepest_shared_level(&self, leaf: LeafIdx, other: LeafIdx) -> Option<usize> {
        for level in (0..=self.height).rev() {
            if self.level_leaf_range(leaf, level).contains(&other) {
                return Some(level as usize);
            }
        }
        None
    }

    /// Compute the leaf range covered at tree `level` when targeting `leaf`.
    /// Level 0 = root (covers all leaves), level `height` = the leaf itself.
    fn level_leaf_range(&self, leaf: LeafIdx, level: u32) -> std::ops::RangeInclusive<LeafIdx> {
        let shift = self.height - level;
        let node = leaf >> shift;
        let start = node << shift;
        let end = start + (1u64 << shift) - 1;
        start..=end
    }

    pub fn stash_size(&self) -> usize {
        self.stash.len()
    }

    pub fn position_map(&self) -> &HashMap<ChunkId, LeafIdx> {
        &self.position_map
    }
}

fn random_leaf(num_leaves: u64) -> LeafIdx {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    u64::from_le_bytes(buf) % num_leaves
}

// ── TrivialOram ───────────────────────────────────────────────────────────────

/// Trivial ORAM: download everything, update target, re-upload everything.
/// Used when chunk_count ≤ TRIVIAL_ORAM_THRESHOLD.
pub struct TrivialOram {
    chunks: HashMap<ChunkId, Vec<u8>>,
}

impl TrivialOram {
    pub fn new() -> Self {
        Self {
            chunks: HashMap::new(),
        }
    }

    /// Return all chunk IDs (caller downloads all of them).
    pub fn all_ids(&self) -> Vec<ChunkId> {
        self.chunks.keys().copied().collect()
    }

    pub fn read(&self, id: &ChunkId) -> Option<&[u8]> {
        self.chunks.get(id).map(|v| v.as_slice())
    }

    pub fn write(&mut self, id: ChunkId, data: Vec<u8>) {
        self.chunks.insert(id, data);
    }

    pub fn remove(&mut self, id: &ChunkId) {
        self.chunks.remove(id);
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn should_upgrade_to_path_oram(&self) -> bool {
        self.chunks.len() > TRIVIAL_ORAM_THRESHOLD
    }
}

impl Default for TrivialOram {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trivial_oram_read_write() {
        let mut oram = TrivialOram::new();
        let id = ChunkId::random();
        oram.write(id, b"hello".to_vec());
        assert_eq!(oram.read(&id).unwrap(), b"hello");
        assert!(!oram.should_upgrade_to_path_oram());
    }

    #[test]
    fn trivial_oram_upgrade_threshold() {
        let mut oram = TrivialOram::new();
        for _ in 0..=TRIVIAL_ORAM_THRESHOLD {
            oram.write(ChunkId::random(), vec![0u8; 8]);
        }
        assert!(oram.should_upgrade_to_path_oram());
    }

    #[test]
    fn path_oram_register_and_prepare() {
        let mut oram = PathOram::new(16);
        let id = ChunkId::random();
        let leaf = oram.register(id);
        assert!(leaf < oram.num_leaves());
        let old = oram.prepare_access(&id).unwrap();
        assert_eq!(old, leaf);
        // After prepare_access the leaf must have changed.
        let new_leaf = oram.position_map()[&id];
        // Note: there's a tiny probability new_leaf == old if num_leaves == 1.
        // With height ≥ 1 (2 leaves) this is unlikely but technically possible;
        // the important invariant is that new leaf is valid.
        assert!(new_leaf < oram.num_leaves());
    }

    #[test]
    fn path_oram_eviction_fills_buckets() {
        let mut oram = PathOram::new(8);
        // Register several chunks.
        let ids: Vec<ChunkId> = (0..6)
            .map(|_| {
                let id = ChunkId::random();
                oram.register(id);
                id
            })
            .collect();

        // Fake a downloaded path (all dummies).
        let target = ids[0];
        let _leaf = oram.prepare_access(&target).unwrap();
        let levels = (oram.height() + 1) as usize;
        let fake_path: OramPath = vec![vec![OramBlock::Dummy; BUCKET_SIZE]; levels];

        let (data, write_back) = oram
            .access(fake_path, &target, Some(b"chunk data".to_vec()))
            .unwrap();

        // Target was not in the path, so existing_data is None.
        assert!(data.is_none());
        // Write-back path must have exactly `levels` buckets.
        assert_eq!(write_back.len(), levels);
        // Each bucket must be padded to BUCKET_SIZE.
        for bucket in &write_back {
            assert_eq!(bucket.len(), BUCKET_SIZE);
        }
    }

    #[test]
    fn chunk_id_random_uuid_v4_bits() {
        let id = ChunkId::random();
        assert_eq!(id.0[6] & 0xf0, 0x40, "version nibble must be 4");
        assert_eq!(id.0[8] & 0xc0, 0x80, "variant bits must be 10xx xxxx");
    }

    #[test]
    fn path_oram_eviction_distributes_blocks_across_levels() {
        // Regression for the "every block lands in the root bucket" bug. With a
        // tall tree and many stash blocks whose assigned leaves differ from the
        // accessed leaf, real blocks must spread across multiple levels, not
        // all pile into path[0].
        let mut oram = PathOram::new(256);
        let levels = (oram.height() + 1) as usize;

        // Seed the stash directly with many real blocks at diverse leaves.
        for i in 0..40u64 {
            let id = ChunkId::random();
            let leaf = i % oram.num_leaves();
            oram.position_map.insert(id, leaf);
            oram.stash.push(OramBlock::Real {
                id,
                data: vec![0u8; 4],
            });
        }

        // Evict along the path to leaf 0.
        let write_path = oram.evict(0);

        assert_eq!(write_path.len(), levels);
        for bucket in &write_path {
            assert_eq!(bucket.len(), BUCKET_SIZE);
        }
        let root_real = write_path[0].iter().filter(|b| b.is_real()).count();
        let total_real: usize = write_path.iter().flatten().filter(|b| b.is_real()).count();
        assert!(
            total_real > BUCKET_SIZE,
            "expected more than BUCKET_SIZE real blocks to be placed, got {total_real}"
        );
        assert!(
            root_real <= BUCKET_SIZE,
            "root bucket must be capped at BUCKET_SIZE, held {root_real} real blocks"
        );
        let levels_with_real = write_path
            .iter()
            .skip(1)
            .filter(|b| b.iter().any(|x| x.is_real()))
            .count();
        assert!(
            levels_with_real >= 1,
            "expected real blocks below the root, got {levels_with_real} non-root levels with real blocks"
        );
    }

    #[test]
    fn path_oram_access_unknown_chunk_errors_not_panics() {
        let mut oram = PathOram::new(16);
        let unknown = ChunkId::random();
        let levels = (oram.height() + 1) as usize;
        let fake_path: OramPath = vec![vec![OramBlock::Dummy; BUCKET_SIZE]; levels];
        // Accessing a chunk that was never registered must return an error,
        // not panic (panics across FFI would abort the host process).
        let result = oram.access(fake_path, &unknown, None);
        assert!(result.is_err());
    }
}
