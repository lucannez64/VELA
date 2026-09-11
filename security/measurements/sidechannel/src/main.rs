//! Production source probes with explicit synthetic OS and UI boundaries.
#![allow(dead_code)]
use std::{
    collections::HashMap,
    hint::black_box,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use vela_crypto::oram::{ChunkId, OramBlock, PathOram};

// These shims replace external boundaries only. They are not OS identity,
// hardware verification, credential release, or IPC transport implementations.
mod ipc_peer {
    use std::path::PathBuf;
    pub struct PeerIdentity {
        pub pid: Option<u32>,
        pub uid: Option<u32>,
        pub exe: Option<PathBuf>,
    }
    impl PeerIdentity {
        pub fn is_same_user(&self) -> bool {
            self.uid == Some(42)
        }
    }
    pub fn exe_for_pid(_: u32) -> Option<PathBuf> {
        None
    }
    pub fn parent_pid(_: u32) -> Option<u32> {
        None
    }
}
mod host {
    pub trait Host: Send + Sync {
        fn confirm_presence(&self, title: &str, prompt: &str) -> Option<bool>;
    }
}
mod biometric {
    pub enum PresenceOutcome {
        Confirmed,
        Denied(String),
        Unavailable,
    }
    pub fn verify_presence(_: &str) -> PresenceOutcome {
        PresenceOutcome::Unavailable
    }
}
mod passkey {
    pub struct PresenceToken;
    impl PresenceToken {
        pub fn mint(_: bool) -> Self {
            Self
        }
    }
}
mod login {
    pub struct LoginGrant;
    impl LoginGrant {
        pub fn mint(_: String, _: String, _: bool) -> Self {
            Self
        }
    }
}
#[path = "../../../../desktopVELA/vela-desktop-core/src/ipc_gate.rs"]
mod ipc_gate;
#[path = "../../../../desktopVELA/vela-desktop-core/src/presence.rs"]
mod presence;

struct Tree(u32);
impl ipc_gate::ProcessTable for Tree {
    fn info(&self, pid: u32) -> Option<ipc_gate::ProcessInfo> {
        Some(ipc_gate::ProcessInfo {
            exe: Some(PathBuf::from(if pid == self.0 {
                "chrome"
            } else {
                "wrapper"
            })),
            parent_pid: Some(pid + 1),
        })
    }
}
struct ScriptedHost {
    answer: Option<bool>,
    delay: Duration,
}
impl host::Host for ScriptedHost {
    fn confirm_presence(&self, _: &str, _: &str) -> Option<bool> {
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        self.answer
    }
}
fn row(case: &str, n: usize, sample: usize, start: Instant, slots: usize, stash: usize) {
    let ns = start.elapsed().as_nanos();
    println!("{case},{n},{sample},{ns},{slots},{stash}");
}
fn cycle(
    o: &mut PathOram,
    tree: &mut HashMap<(u32, u64), Vec<OramBlock>>,
    id: &ChunkId,
    data: Option<Vec<u8>>,
) {
    let leaf = o.prepare_access(id).unwrap();
    let path = (0..=o.height())
        .map(|l| {
            tree.get(&(l, leaf >> (o.height() - l)))
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    let (_, back) = o.access(path, leaf, id, data).unwrap();
    for (l, b) in back.into_iter().enumerate() {
        assert_eq!(b.len(), 4);
        tree.insert((l as u32, leaf >> (o.height() - l as u32)), b);
    }
}
fn main() {
    // Public workload-order seed, distinct from production OS leaf randomness.
    let mut rng = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "27".into())
        .parse::<u64>()
        .unwrap();
    let mut coin = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng & 1 == 0
    };
    std::env::remove_var("VELA_NM_BROWSER_NAMES");
    println!("case,chunks,sample,elapsed_ns,path_slots,stash");
    let request = presence::PresenceRequest {
        rp_id: "example.test".into(),
        requester: "synthetic host".into(),
        kind: presence::CeremonyKind::Authenticate,
    };
    for delay in [0, 2] {
        for sample in 0..201 {
            let order = if coin() { [true, false] } else { [false, true] };
            for answer in order {
                let h: Arc<dyn host::Host> = Arc::new(ScriptedHost {
                    answer: Some(answer),
                    delay: Duration::from_millis(delay),
                });
                let label = format!("approval_{}_{}ms", if answer { "yes" } else { "no" }, delay);
                let start = Instant::now();
                let result = presence::confirm(&h, &request);
                assert_eq!(result.is_ok(), answer);
                if sample > 0 {
                    row(&label, 0, sample - 1, start, 0, 0);
                }
            }
        }
    }
    for sample in 0..201 {
        let order = if coin() { [2, 8, 9] } else { [9, 8, 2] };
        for depth in order {
            let peer = ipc_peer::PeerIdentity {
                pid: Some(1),
                uid: Some(42),
                exe: Some("/untrusted/vela-native-messaging-host".into()),
            };
            let label = format!("gate_depth_{depth}_batch100");
            let start = Instant::now();
            // Batch to reduce clock resolution effects; record per-batch timing.
            for _ in 0..100 {
                assert_eq!(
                    black_box(ipc_gate::authorize_host(&Tree(depth), &peer)).is_ok(),
                    depth <= 8
                );
            }
            if sample > 0 {
                row(&label, 0, sample - 1, start, 0, 0);
            }
        }
    }
    for n in [4usize, 5, 16, 64, 256] {
        let mut o = PathOram::new(n);
        let mut tree = HashMap::new();
        let ids: Vec<_> = (0..n).map(|i| ChunkId((i as u128).to_le_bytes())).collect();
        for id in &ids {
            o.register(*id);
            cycle(&mut o, &mut tree, id, Some(vec![7; 4096]));
        }
        for sample in 0..1001 {
            let order = if coin() { [0, n - 1] } else { [n - 1, 0] };
            for idx in order {
                let start = Instant::now();
                cycle(&mut o, &mut tree, &ids[idx], None);
                if sample > 0 {
                    row(
                        if idx == 0 {
                            "path_target_a"
                        } else {
                            "path_target_b"
                        },
                        n,
                        sample - 1,
                        start,
                        4 * (o.height() as usize + 1),
                        o.stash_size(),
                    );
                }
            }
        }
    }
}
