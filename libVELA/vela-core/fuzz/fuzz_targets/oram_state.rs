//! Fuzz the Path ORAM client state machine.
//!
//! The client (`PathOram`) plus a *faithful* simulated server modelled as a
//! real tree: uploads write each bucket into its `(level, node)` slot,
//! downloads assemble the requested path node-by-node. That matters because
//! eviction parks blocks at the lowest-common-ancestor of the access path and
//! the block's own leaf — ancestor nodes are shared between many leaves'
//! paths, and only a tree-shaped server preserves them. Under this protocol
//! the state machine has a hard property: every registered chunk reads back
//! its last write byte-exact through adversarial op sequences. Stash-overflow,
//! wrong-LCA, or lost-block bugs all surface here.
//!
//! Input drives an op sequence over a small tree.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_crypto::oram::{Bucket, ChunkId, OramBlock, OramPath, PathOram, BUCKET_SIZE};

/// Tree-backed server: `(level, node_within_level) -> bucket`.
struct FakeServer {
    /// Node index at `level`: leaf >> (height - level).
    nodes: std::collections::HashMap<(usize, u64), Bucket>,
}

impl FakeServer {
    fn new() -> Self {
        Self { nodes: Default::default() }
    }

    fn download(&self, height: u32, leaf: u64) -> OramPath {
        (0..=height as usize)
            .map(|level| {
                let shift = height as usize - level;
                let node = leaf >> shift;
                self.nodes
                    .get(&(level, node))
                    .cloned()
                    .unwrap_or_else(|| vec![OramBlock::Dummy; BUCKET_SIZE])
            })
            .collect()
    }

    fn upload(&mut self, height: u32, leaf: u64, path: OramPath) {
        for (level, bucket) in path.into_iter().enumerate() {
            let shift = height as usize - level;
            let node = leaf >> shift;
            self.nodes.insert((level, node), bucket);
        }
    }
}

fn chunk_id(seed: u64) -> ChunkId {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&seed.to_le_bytes());
    ChunkId(buf)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 || data.len() > 2048 {
        return;
    }
    let capacity = ((data[0] as usize) % 6) + 2; // 2..=7
    let mut oram = PathOram::new(capacity);
    let height = oram.height();
    let mut server = FakeServer::new();

    let mut registered: Vec<ChunkId> = Vec::new();
    let mut contents: std::collections::HashMap<ChunkId, Vec<u8>> = Default::default();

    // Full protocol round trip for one id+payload: download old path,
    // access, upload write-back to the reassigned leaf.
    macro_rules! round_trip {
        ($id:expr, $payload:expr) => {{
            let id: ChunkId = $id;
            let payload: Option<Vec<u8>> = $payload;
            let old_leaf = oram.prepare_access(&id).unwrap();
            let path = server.download(height, old_leaf);
            let (got, write_back) = oram.access(path, old_leaf, &id, payload).unwrap();
            server.upload(height, old_leaf, write_back);
            got
        }};
    }

    // Ids must be unique for the *lifetime of the run* — deriving them from
    // `registered.len()` breaks after an unregister shrinks the list (the
    // same seed is minted twice; the second `register` overwrites the
    // position map of a live chunk and the list keeps a stale entry).
    let mut next_seed: u64 = 0;
    let ops = &data[1..];
    for pair in ops.chunks(2) {
        if pair.len() < 2 {
            break;
        }
        let op = pair[0] % 4;
        let arg = pair[1];

        match op {
            0 => {
                // Register + first write.
                if registered.len() < capacity + 2 {
                    let id = chunk_id(next_seed);
                    next_seed += 1;
                    oram.register(id);
                    let payload = vec![arg; 16];
                    contents.insert(id, payload.clone());
                    round_trip!(id, Some(payload));
                    registered.push(id);
                }
            }
            1 => {
                // Read a registered id; must return its last write exactly.
                if let Some(id) = registered
                    .iter()
                    .find(|id| id.as_bytes()[0] == arg || arg == 0xff)
                    .copied()
                {
                    let got = round_trip!(id, None);
                    assert_eq!(
                        got.as_deref(),
                        contents.get(&id).map(|v| v.as_slice()),
                        "ORAM returned wrong data for {id:?}"
                    );
                }
            }
            2 => {
                // Rewrite a registered id.
                if let Some(&id) = registered.get((arg as usize) % registered.len().max(1)) {
                    let payload = vec![arg ^ 0x5a; 16];
                    contents.insert(id, payload.clone());
                    round_trip!(id, Some(payload));
                }
            }
            _ => {
                // Unregister: gone from map and stash; orphaned server-side
                // blocks are expected and never touched again.
                if let Some(id) = registered.first().copied() {
                    oram.unregister(&id);
                    registered.remove(0);
                    contents.remove(&id);
                }
            }
        }
    }

    // Final sweep: every surviving id reads back exactly its last write.
    for id in &registered {
        let got = round_trip!(*id, None);
        assert_eq!(
            got.as_deref(),
            contents.get(id).map(|v| v.as_slice()),
            "final consistency check failed for {id:?}"
        );
    }
});
