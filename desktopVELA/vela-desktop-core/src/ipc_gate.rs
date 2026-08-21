//! May this process connect to the desktop's autofill IPC endpoint at all?
//!
//! This gate replaces the capability file. The old design wrote a bearer
//! token to `ipc_auth.json` (0600) and checked it on every message, which
//! against the attacker that matters — code already running as the user —
//! was theatre: that process can read a 0600 file (audit D-4), and rewriting
//! the endpoint inside it was finding #69.
//!
//! The transport is now native messaging only: the *browser* spawns our host
//! binary over stdio, and the host relays to the desktop over a well-known
//! per-user socket/pipe with no secret in it. What stands between an
//! arbitrary same-uid process and this endpoint is three questions about who
//! connected, all answered by the kernel or by /proc rather than by anything
//! the peer can say:
//!
//! 1. **Same user** — `SO_PEERCRED` and friends (`ipc_peer`).
//! 2. **The VELA host binary** — the connecting executable must be
//!    `vela-native-messaging-host`. `/proc/<pid>/exe` names the real binary,
//!    not argv[0], so a renamed script does not pass; copying our own binary
//!    elsewhere does, which is why check 3 exists.
//! 3. **Spawned by a browser** — some ancestor of the peer within a small
//!    window is a known browser process. A copy of the host binary launched
//!    from a terminal has no browser parent and is refused. To satisfy this
//!    check an attacker needs a browser to spawn their process for them:
//!    i.e. they must be an extension, or inject into the browser — exactly
//!    the bar option B in issue #149 aims for.
//!
//! All three fail closed: a peer we cannot identify is refused, not waved
//! through. The residual is stated plainly: pid recycling can race an
//! ancestry lookup, and a hostile browser *extension* still gets everything
//! the legitimate one gets. This gate bounds who can knock, not what an
//! approved caller may carry — the presence, cap and audit limits from the
//! D work in issue #149 sit above it unchanged.

use std::path::PathBuf;

use crate::ipc_peer::PeerIdentity;

/// The only non-VELA executable allowed on the other end of the socket.
pub const NM_HOST_BINARY_NAME: &str = "vela-native-messaging-host";

/// How many ancestors of a connecting process we walk looking for a browser.
///
/// Deep enough to see through a wrapper script between browser and host;
/// shallow enough that a walk terminates quickly even on a hostile lineage.
pub const MAX_ANCESTRY_HOPS: u32 = 8;

/// Executables accepted as the spawner of the native messaging host.
///
/// Matched against the resolved executable's file name, lower-cased, with a
/// trailing `.exe` stripped. Deliberately a list of concrete browsers rather
/// than "anything named like a browser": adding a name here is what allows a
/// new browser through, and that should take a diff, not a typo.
const BROWSER_PROCESS_NAMES: &[&str] = &[
    "firefox",
    "firefox-esr",
    "chrome",
    "google-chrome",
    "chromium",
    "brave",
    "brave-browser",
    "msedge",
    "microsoft-edge",
    "opera",
    "vivaldi",
    "thorium-browser",
    "librewolf",
    "waterfox",
];

/// Extra browser names accepted as spawners, from `VELA_NM_BROWSER_NAMES`
/// (comma-separated). Escape hatch for setups where the browser spawns its
/// helper under a name nobody could predict — sandboxed wrappers mostly.
/// Empty unless the user says otherwise.
/// Split out so the parsing is testable without mutating process-global
/// environment state from a test thread — which races every other thread's
/// `getenv` and produces maddening cross-test flakes.
fn parse_extra_browser_names(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// What the platform knows about one process in the peer's lineage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessInfo {
    pub exe: Option<PathBuf>,
    pub parent_pid: Option<u32>,
}

/// Where lineage facts come from. A trait so the tests can feed synthetic
/// family trees instead of arranging real processes.
pub trait ProcessTable {
    fn info(&self, pid: u32) -> Option<ProcessInfo>;
}

/// The real table: /proc on Linux, proc_pidpath + ps on macOS, ToolHelp on
/// Windows. Every lookup is best-effort and racy; absence refuses.
pub struct OsProcessTable;

impl ProcessTable for OsProcessTable {
    fn info(&self, pid: u32) -> Option<ProcessInfo> {
        Some(ProcessInfo {
            exe: super::ipc_peer::exe_for_pid(pid),
            parent_pid: super::ipc_peer::parent_pid(pid),
        })
    }
}

fn exe_basename(exe: &std::path::Path) -> String {
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    // A trailing ".exe" is Windows spelling of the same binary.
    name.strip_suffix(".exe").unwrap_or(&name).to_string()
}

fn is_host_binary(exe: &std::path::Path) -> bool {
    exe_basename(exe) == NM_HOST_BINARY_NAME
}

fn is_browser_process(exe: &std::path::Path) -> bool {
    let name = exe_basename(exe);
    if name.is_empty() {
        return false;
    }
    BROWSER_PROCESS_NAMES.contains(&name.as_str())
        || parse_extra_browser_names(&std::env::var("VELA_NM_BROWSER_NAMES").unwrap_or_default())
            .iter()
            .any(|extra| *extra == name)
}

/// Decide whether `peer` may talk to us at all. Err text reaches the caller
/// as the IPC error message, so it is written to be read by a person
/// debugging their extension connection.
pub fn authorize_host(table: &dyn ProcessTable, peer: &PeerIdentity) -> Result<(), String> {
    if !peer.is_same_user() {
        return Err("This request did not come from your own session.".to_string());
    }

    let pid = peer.pid.ok_or_else(|| {
        "Connection from a process the system could not identify.".to_string()
    })?;

    // Check 2 needs no table walk — the kernel handed us the exe with the
    // identity. If it did not, refuse: an unidentified peer is not ours.
    let peer_exe = match &peer.exe {
        Some(exe) if is_host_binary(exe) => exe.clone(),
        Some(other) => {
            return Err(format!(
                "Connected process is {}, not the VELA native messaging host.",
                other.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
            ));
        }
        None => {
            return Err(
                "Connected process could not be identified as the VELA native messaging host."
                    .to_string(),
            );
        }
    };

    // Check 3: a browser somewhere up the tree spawned the host.
    let mut cursor = pid;
    for _ in 0..MAX_ANCESTRY_HOPS {
        let info = table.info(cursor).ok_or_else(|| {
            format!(
                "Could not verify that {} was started by a browser.",
                peer_exe.display()
            )
        })?;
        match (info.exe, info.parent_pid) {
            (Some(exe), _) if is_browser_process(&exe) => return Ok(()),
            (_, Some(parent)) => cursor = parent,
            // Reached init/reaper without meeting a browser: orphaned or
            // reparented after its true spawner exited. Either way we cannot
            // vouch for it.
            _ => break,
        }
    }

    Err(format!(
        "{} was not started by a recognized browser; refusing. \
         If your browser is sandboxed and launches helpers under another \
         name, add it via VELA_NM_BROWSER_NAMES.",
        peer_exe.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Synthetic family tree: pid -> (exe, parent).
    struct FakeTree(HashMap<u32, (Option<&'static str>, Option<u32>)>);

    impl ProcessTable for FakeTree {
        fn info(&self, pid: u32) -> Option<ProcessInfo> {
            self.0.get(&pid).map(|(exe, parent)| ProcessInfo {
                exe: exe.map(PathBuf::from),
                parent_pid: *parent,
            })
        }
    }

    fn host_exe() -> PathBuf {
        PathBuf::from("/usr/bin/vela-native-messaging-host")
    }

    fn peer(pid: u32, exe: Option<PathBuf>) -> PeerIdentity {
        PeerIdentity { pid: Some(pid), uid: Some(crate::ipc_peer::current_uid()), exe }
    }

    #[test]
    fn browser_spawned_host_is_admitted() {
        // browser(100) -> host(200): the real shape of a native messaging spawn.
        let tree = FakeTree(HashMap::from([
            (200u32, (Some("vela-native-messaging-host") as Option<&'static str>, Some(100u32))),
            (100u32, (Some("firefox"), None)),
        ]));
        assert!(authorize_host(&tree, &peer(200, Some(host_exe()))).is_ok());
    }

    #[test]
    fn wrapper_between_browser_and_host_still_admitted() {
        // browser -> sh -> host: a wrapper script must not break legit users.
        let tree = FakeTree(HashMap::from([
            (300u32, (None, Some(200u32))),
            (200u32, (Some("sh"), Some(100u32))),
            (100u32, (Some("chrome"), None)),
        ]));
        assert!(authorize_host(&tree, &peer(300, Some(host_exe()))).is_ok());
    }

    #[test]
    fn copy_of_the_host_run_from_a_terminal_is_refused() {
        // The easy attack after B: exec our own binary directly. No browser
        // anywhere in the tree.
        let tree = FakeTree(HashMap::from([
            (400u32, (Some("vela-native-messaging-host"), Some(500u32))),
            (500u32, (Some("zsh"), Some(1u32))),
            (1u32, (Some("systemd"), None)),
        ]));
        let err = authorize_host(&tree, &peer(400, Some(host_exe()))).unwrap_err();
        assert!(err.contains("not started by a recognized browser"), "{err}");
    }

    #[test]
    fn arbitrary_process_is_refused_before_the_lineage_walk() {
        let tree = FakeTree(HashMap::from([(600u32, (Some("python3"), Some(1u32)))]));
        let err =
            authorize_host(&tree, &peer(600, Some(PathBuf::from("/usr/bin/python3"))))
                .unwrap_err();
        assert!(err.contains("not the VELA native messaging host"), "{err}");
    }

    #[test]
    fn unidentifiable_peer_is_refused_not_waved_through() {
        let tree = FakeTree(HashMap::new());
        assert!(authorize_host(&tree, &peer(700, None)).is_err());
        assert!(authorize_host(&tree, &PeerIdentity::default()).is_err());
    }

    #[test]
    fn another_users_connection_is_refused_first() {
        let stranger = PeerIdentity { pid: Some(1), uid: Some(u32::MAX - 1), exe: Some(host_exe()) };
        let tree = FakeTree(HashMap::new());
        let err = authorize_host(&tree, &stranger).unwrap_err();
        assert!(err.contains("your own session"), "{err}");
    }

    #[test]
    fn orphaned_host_with_no_parent_left_is_refused() {
        // Parent died before we looked; the entry has neither exe nor parent.
        let tree = FakeTree(HashMap::from([
            (800u32, (Some("vela-native-messaging-host"), Some(900u32))),
        ]));
        let err = authorize_host(&tree, &peer(800, Some(host_exe()))).unwrap_err();
        assert!(err.contains("started by a browser"), "{err}");
    }

    #[test]
    fn deep_lineage_beyond_the_hop_limit_does_not_rescue_anything() {
        // A browser far beyond MAX_ANCESTRY_HOPS is not a spawner any more.
        let mut map = HashMap::new();
        let mut pid = 2000u32;
        for _ in 0..20 {
            map.insert(pid, (Some("filler"), Some(pid + 1)));
            pid += 1;
        }
        map.insert(pid, (Some("firefox"), None));
        let tree = FakeTree(map);
        assert!(authorize_host(&tree, &peer(2000, Some(host_exe()))).is_err());
    }

    #[test]
    fn windows_spelled_names_match() {
        // Forward slashes because the test runs on Unix, where `\` is not a
        // separator — what is under test is the ".exe" suffix handling.
        assert!(is_host_binary(&PathBuf::from(
            "/Program Files/VELA/vela-native-messaging-host.exe"
        )));
        assert!(is_browser_process(&PathBuf::from("/Apps/Firefox.EXE")));
    }

    #[test]
    fn extra_browser_names_env_adds_to_the_list() {
        // Pure parsing: no env mutation here — a test thread writing the
        // process environment races every other test's getenv calls.
        let extra = parse_extra_browser_names("fuzzball, my-sandboxed-browser");
        assert_eq!(extra, ["fuzzball", "my-sandboxed-browser"]);
        let name = exe_basename(&PathBuf::from("/opt/wrapper/my-sandboxed-browser"));
        assert!(extra.iter().any(|e| *e == name));
        // And nothing matches when unset.
        assert!(parse_extra_browser_names("").is_empty());
        // Whitespace and empties are tolerated.
        assert_eq!(parse_extra_browser_names(" a ,, b "), ["a", "b"]);
    }
}
