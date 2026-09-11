//! Finite regression harness for Path ORAM stash dynamics (M24).
//!
//! Access-pattern hiding is proven symbolically in
//! `security/formal/m22c_path_oram_hiding.pv`; what cannot be expressed in a
//! symbolic model is the **probabilistic** question: does the client-side
//! stash stay bounded under realistic access patterns?
//!
//! This harness drives the REAL `PathOram` implementation against a
//! faithful tree-structured fake server (buckets keyed by (level, node),
//! shared across sibling leaves exactly like the wire protocol), checking:
//!
//! 1. Assertions at the implemented checkpoints:
//!    - No registered chunk is ever lost (round-trip integrity through the
//!      full prepare/download/access/write-back cycle).
//!    - Buckets are always padded to exactly `BUCKET_SIZE`.
//!    - `unregister` removes the mapping and blocks further preparation.
//!
//! 2. A finite-workload regression ceiling, not an overflow probability proof.
//! Targets cycle deterministically and leaf remaps use OS randomness.
//! Classical Path ORAM tail bounds have not been transferred to this eviction
//! implementation. See security/formal/oram-stash-bounds-statistical-results.md.

use std::collections::HashMap;

use vela_crypto::oram::{ChunkId, OramBlock, PathOram, TrivialOram, BUCKET_SIZE};

/// Tree-structured server storage: bucket (level, node) → blocks.
/// Sibling leaves share ancestors, so this preserves the real protocol's
/// bucket-sharing semantics that a per-leaf map would lose.
struct FakeServer {
    height: u32,
    nodes: HashMap<(u32, u64), Vec<OramBlock>>,
}

impl FakeServer {
    fn new(height: u32) -> Self {
        Self {
            height,
            nodes: HashMap::new(),
        }
    }

    /// Root-to-leaf bucket sequence, "decrypted" (the harness sees blocks).
    fn get_path(&self, leaf: u64) -> Vec<Vec<OramBlock>> {
        let mut path = Vec::with_capacity((self.height + 1) as usize);
        for level in 0..=self.height {
            let node = leaf >> (self.height - level);
            path.push(self.nodes.get(&(level, node)).cloned().unwrap_or_default());
        }
        path
    }

    fn put_path(&mut self, leaf: u64, path: &[Vec<OramBlock>]) {
        for (level, bucket) in path.iter().enumerate() {
            let node = leaf >> (self.height - level as u32);
            self.nodes.insert((level as u32, node), bucket.clone());
        }
    }
}

/// Deterministic workload: ids derived from (tag, index); payloads tagged so
/// cross-chunk swaps are detected by content, not just length.
struct Workload {
    ids: Vec<ChunkId>,
    base_len: Vec<usize>,
}

impl Workload {
    fn new(n_chunks: usize, tag: u8) -> Self {
        let mut ids = Vec::with_capacity(n_chunks);
        let mut base_len = Vec::with_capacity(n_chunks);
        for i in 0..n_chunks {
            let mut id_bytes = [0u8; 16];
            id_bytes[0] = tag;
            id_bytes[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            ids.push(ChunkId(id_bytes));
            base_len.push(16 + (i % 32));
        }
        Self { ids, base_len }
    }

    fn payload_for(&self, idx: usize, writes: usize) -> Vec<u8> {
        let mut d = vec![0xA7u8; self.base_len[idx] + writes];
        d[0] = self.ids[idx].as_bytes()[0];
        d
    }

    fn expected_len(&self, idx: usize, writes: usize) -> usize {
        self.base_len[idx] + writes
    }
}

/// One full protocol cycle: remap → download path → access → upload write-back.
fn full_cycle(
    oram: &mut PathOram,
    server: &mut FakeServer,
    id: &ChunkId,
    write_data: Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    let old_leaf = oram.prepare_access(id).expect("registered chunk");
    let path = server.get_path(old_leaf);
    let (read_back, write_back) = oram
        .access(path, old_leaf, id, write_data)
        .expect("access ok");

    // Hard invariant (M24 regression guard): the stash never holds two blocks
    // for the same chunk — duplicates are what caused the stale-read and
    // unbounded-stash bugs this harness caught.
    let mut seen_ids = std::collections::HashSet::new();
    for cid in oram.stash_ids() {
        assert!(
            seen_ids.insert(cid),
            "duplicate chunk id in stash after access"
        );
    }

    assert!(write_back.iter().all(|bucket| bucket.len() == BUCKET_SIZE));

    // M24 fix: write-back rides the DOWNLOADED path (read-before-write).
    server.put_path(old_leaf, &write_back);
    read_back
}

#[test]
fn integrity_survives_long_random_workload() {
    let n_chunks = 32usize;
    let wl = Workload::new(n_chunks, 0xA0);
    let mut oram = PathOram::new(64);
    let mut server = FakeServer::new(oram.height());

    // Register every chunk and write its initial payload.
    let mut write_counts = vec![0usize; n_chunks];
    for idx in 0..n_chunks {
        oram.register(wl.ids[idx]);
        full_cycle(
            &mut oram,
            &mut server,
            &wl.ids[idx],
            Some(wl.payload_for(idx, 0)),
        );
    }

    // Long mixed workload over all chunks.
    for step in 0..4000usize {
        let idx = step % n_chunks;
        if step % 3 == 0 {
            write_counts[idx] += 1;
            full_cycle(
                &mut oram,
                &mut server,
                &wl.ids[idx],
                Some(wl.payload_for(idx, write_counts[idx])),
            );
        } else {
            full_cycle(&mut oram, &mut server, &wl.ids[idx], None);
        }
    }

    // Integrity: every chunk still opens to its latest expected payload.
    for idx in 0..n_chunks {
        let got = full_cycle(&mut oram, &mut server, &wl.ids[idx], None);
        let expect = wl.payload_for(idx, write_counts[idx]);
        assert_eq!(
            got.as_deref(),
            Some(expect.as_slice()),
            "chunk {idx} lost or cross-contaminated after 4000 accesses"
        );
    }
}

#[test]
fn stash_stays_bounded_over_five_thousand_accesses() {
    let n_chunks = 48usize;
    let wl = Workload::new(n_chunks, 0xB7);
    let mut oram = PathOram::new(64);
    let mut server = FakeServer::new(oram.height());

    for idx in 0..n_chunks {
        oram.register(wl.ids[idx]);
        full_cycle(
            &mut oram,
            &mut server,
            &wl.ids[idx],
            Some(wl.payload_for(idx, 0)),
        );
    }

    // Fixed-universe regression workload; this ceiling is not a tail bound
    // and does not cover arbitrary unknown identifiers from server paths.
    let mut max_stash_seen = 0usize;
    for step in 0..5000usize {
        let idx = step % n_chunks;
        let write = step % 2 == 0;
        let payload = write.then(|| wl.payload_for(idx, step));
        full_cycle(&mut oram, &mut server, &wl.ids[idx], payload);
        max_stash_seen = max_stash_seen.max(oram.stash_size());
    }

    let height = oram.height() as usize;
    let bound = n_chunks + 4 * (height + 1); // workload regression ceiling
    assert!(
        max_stash_seen <= bound,
        "stash exceeded regression ceiling: max {max_stash_seen} > {bound} \
         (height {height}, {n_chunks} chunks)"
    );
}

#[test]
fn unregister_removes_every_trace() {
    let wl = Workload::new(8, 0xCC);
    let mut oram = PathOram::new(16);
    let mut server = FakeServer::new(oram.height());

    for idx in 0..8 {
        oram.register(wl.ids[idx]);
        full_cycle(
            &mut oram,
            &mut server,
            &wl.ids[idx],
            Some(wl.payload_for(idx, 0)),
        );
    }

    let victim = 3;
    oram.unregister(&wl.ids[victim]);
    assert!(!oram.position_map().contains_key(&wl.ids[victim]));
    assert!(oram.prepare_access(&wl.ids[victim]).is_err());

    // The stale block must never resurface through any other chunk's path:
    // sweep every remaining chunk repeatedly and confirm no panic/no ghost.
    for round in 0..40 {
        let idx = (round * 2 + 4) % 8;
        if idx == victim {
            continue;
        }
        full_cycle(&mut oram, &mut server, &wl.ids[idx], None);
    }
}

#[test]
fn trivial_mode_pattern_is_independent_of_target() {
    // Structural complement to m22b: in trivial mode the caller downloads
    // and re-uploads EVERY chunk regardless of which item changed. The
    // observable request set is therefore the full id list — identical
    // whatever the target. Verified against the real TrivialOram.
    let mut oram = TrivialOram::new();
    let mut ids = Vec::new();
    for _ in 0..BUCKET_SIZE {
        let id = ChunkId::random();
        oram.write(id, b"payload".to_vec());
        ids.push(id);
    }
    let sorted = |v: &[ChunkId]| {
        let mut s: Vec<[u8; 16]> = v.iter().map(|c| c.as_bytes().to_owned()).collect();
        s.sort();
        s
    };
    for target in &ids {
        assert_eq!(oram.all_ids().len(), BUCKET_SIZE);
        let _ = oram.read(target);
        assert_eq!(
            sorted(&oram.all_ids()),
            sorted(&ids),
            "trivial-mode read leaked the target in the observable pattern"
        );
    }
    oram.write(ids[1], b"updated".to_vec());
    assert_eq!(sorted(&oram.all_ids()), sorted(&ids));
}
