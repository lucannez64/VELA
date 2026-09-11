//! Local CPU measurements; modeled slot bytes are not network measurements.
use std::{collections::HashMap, hint::black_box, time::Instant};
use vela_crypto::{
    aead, kdf,
    oram::{ChunkId, OramPath, PathOram, BUCKET_SIZE},
    rekey,
};

fn cycle(
    o: &mut PathOram,
    tree: &mut HashMap<(u32, u64), Vec<vela_crypto::oram::OramBlock>>,
    id: &ChunkId,
    data: Option<Vec<u8>>,
) {
    let leaf = o.prepare_access(id).unwrap();
    let path: OramPath = (0..=o.height())
        .map(|l| {
            tree.get(&(l, leaf >> (o.height() - l)))
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    let (_, back) = o.access(path, leaf, id, data).unwrap();
    for (l, bucket) in back.into_iter().enumerate() {
        assert_eq!(bucket.len(), BUCKET_SIZE);
        tree.insert((l as u32, leaf >> (o.height() - l as u32)), bucket);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(100);
    let bytes: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(4096);
    assert!(samples >= 2 && bytes > 0);
    println!("platform,arch,case,chunks,payload_bytes,sample,elapsed_ns,modeled_slot_bytes,stash");
    for n in [1usize, 4, 5, 16, 64, 256] {
        let mut o = PathOram::new(n);
        let mut tree = HashMap::new();
        let ids: Vec<_> = (0..n).map(|i| ChunkId((i as u128).to_le_bytes())).collect();
        for id in &ids {
            o.register(*id);
            cycle(&mut o, &mut tree, id, Some(vec![7; bytes]));
        }
        let blobs: Vec<_> = (0..n)
            .map(|_| {
                aead::encrypt(
                    kdf::derive("assurance", &[1; 32]).as_bytes(),
                    &vec![7; bytes],
                )
                .unwrap()
            })
            .collect();
        // Rotate order each sample to reduce systematic case-order drift.
        for sample in 0..samples + 1 {
            for offset in 0..4 {
                let case = (sample + offset) % 4;
                let start = Instant::now();
                let (name, slots) = match case {
                    0 => {
                        cycle(&mut o, &mut tree, &ids[sample % n], None);
                        ("path_cpu", 2 * BUCKET_SIZE * (o.height() as usize + 1))
                    }
                    1 => {
                        for blob in &blobs {
                            black_box(blob.clone());
                        }
                        ("whole_vault_copy_proxy", 2 * n)
                    }
                    2 => {
                        black_box(blobs[sample % n].clone());
                        ("single_blob_copy_proxy", 2)
                    }
                    _ => {
                        for blob in &blobs {
                            black_box(
                                rekey::rekey_blob(&[1; 32], &[2; 32], "assurance", blob).unwrap(),
                            );
                        }
                        ("rekey_crypto", n)
                    }
                };
                let ns = start.elapsed().as_nanos();
                if sample > 0 {
                    println!(
                        "{},{},{name},{n},{bytes},{},{ns},{},{}",
                        std::env::consts::OS,
                        std::env::consts::ARCH,
                        sample - 1,
                        slots * (bytes + aead::OVERHEAD),
                        o.stash_size()
                    );
                }
            }
        }
    }
}
