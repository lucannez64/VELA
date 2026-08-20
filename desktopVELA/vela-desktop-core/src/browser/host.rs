//! Discover and drive a real browser for the browser-driven login tier.
//!
//! The core spawns a disposable browser (Chrome/Chromium/Edge) with a fresh
//! temp profile, driven over the CDP **debugging pipe** (`--remote-debugging-pipe`,
//! CDP over fds 3/4, no TCP listener) and tears the whole thing down afterwards
//! — profile deleted, process killed. Driving the browser over the pipe instead
//! of an HTTP/WebSocket debug port means there is no 127.0.0.1 listener a
//! co-resident same-user process could attach to and read the credential out of
//! (RT-10). See `security/browser-driven-login-design.md`.
//!
//! Process isolation: on Linux the browser's child processes are readable by
//! any same-UID process, so a co-resident process can read the substituted
//! password out of the browser during a login. `VELA_BROWSER_SANDBOX` routes
//! the spawn through a setuid launcher that drops the whole browser to a
//! dedicated unprivileged UID (see `vela-browser-sandbox/`), closing that.
//! `spawn()` fails closed if the sandbox is requested but not effecting a
//! distinct UID, and warns when the tier runs without it.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// The parent's ends of the CDP debugging pipe.
///
/// Chromium's `--remote-debugging-pipe` reads commands from **fd 3** and writes
/// messages to **fd 4**; the parent holds the write end of the command pipe and
/// the read end of the message pipe. Both are length-prefixed (u32 big-endian +
/// JSON) in each direction; see the CDP client in `cdp.rs`.
#[cfg(unix)]
#[derive(Debug)]
pub struct PipeIo {
    pub command: std::os::unix::io::OwnedFd,
    pub message: std::os::unix::io::OwnedFd,
}

/// A running disposable browser. Dropping it kills the process and wipes the
/// profile.
pub struct Browser {
    child: Option<Child>,
    profile_dir: PathBuf,
}

impl Drop for Browser {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.profile_dir);
    }
}

/// The browser binaries we look for, best first, per platform.
fn candidates() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        for name in [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
            "microsoft-edge-stable",
        ] {
            if let Some(path) = which(name) {
                out.push(path);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        for name in [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ] {
            let path = PathBuf::from(name);
            if path.exists() {
                out.push(path);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let program_files_x86 =
            std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
        for root in [&program_files, &program_files_x86] {
            for relative in [
                r"Google\Chrome\Application\chrome.exe",
                r"Microsoft\Edge\Application\msedge.exe",
            ] {
                let path = PathBuf::from(root).join(relative);
                if path.exists() {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Find an executable on PATH.
fn which(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Create an `O_CLOEXEC` pipe, returning (read end, write end).
#[cfg(unix)]
fn new_pipe() -> Result<(std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd), String> {
    use std::os::unix::io::FromRawFd;
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a two-element mutable array of int, a valid `pipe2` out.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(format!("pipe2 failed: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: on success `pipe2` filled `fds` with two valid open file descriptors.
    Ok((
        unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fds[0]) },
        unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fds[1]) },
    ))
}

/// Path to the setuid launcher that runs the disposable browser under a
/// dedicated, unprivileged UID (Linux only).
///
/// Why this is needed: Chromium's child processes — the ones that move the
/// login request, and the renderers — are left readable by any *same-UID*
/// process on a default `kernel.yama.ptrace_scope=1` kernel. Verified
/// empirically: a co-resident same-user process can recover the substituted
/// password from the disposable browser's memory during a login (see
/// `security/exploits/test_browser_tier_memleak.py`). The core process is not
/// affected — a plain process is gated against unrelated same-UID reads — but
/// the browser's process tree is open to them.
///
/// Running the whole disposable browser under a *different*, unprivileged UID
/// closes that: cross-UID `process_vm_readv` and `/proc/<pid>/mem` reads are
/// refused by the kernel unless the reader is root. Turning a user-spawned
/// subprocess into a different UID needs a privileged bootstrap, so this is
/// done with a small setuid helper (`desktopVELA/vela-browser-sandbox/`),
/// which an operator installs `setuid root` (one-time, see its README).
///
/// Opt-in via `VELA_BROWSER_SANDBOX`: either a path to the launcher, or `1`
/// to use the launcher installed next to the app's own binary. When it is
/// configured we fail closed; when it is absent we keep the legacy same-UID
/// behaviour but warn loudly that the documented residual is reachable.
#[cfg(target_os = "linux")]
fn sandbox_launcher() -> Option<PathBuf> {
    let value = std::env::var_os("VELA_BROWSER_SANDBOX")?;
    let empty = std::ffi::OsStr::new("");
    if value == empty {
        return None;
    }
    if value == "1" {
        // The launcher installed alongside the running binary.
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("vela-browser-sandbox")))
    } else {
        Some(PathBuf::from(value))
    }
}

/// A process's effective UID, from `/proc/<pid>/status` (Linux). `None` if the
/// process is gone or the file is unreadable.
#[cfg(target_os = "linux")]
fn euid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    // Uid:	real	effective	saved	fs  (effective is the 3rd token)
    line.split_whitespace().nth(2)?.parse().ok()
}

/// Spawn a disposable browser driven over the CDP debugging pipe.
///
/// On unix the browser gets **fd 3** = commands-in and **fd 4** = messages-out,
/// so no TCP debug port exists at all (RT-10). Returns the running browser and
/// the parent's ends of the pipe, for the CDP client to drive.
#[cfg(unix)]
pub async fn spawn() -> Result<(Browser, PipeIo), String> {
    // Test seam: lets a unit test prove the fallback wiring without opening a
    // real browser window (which would sit on a mock 403 page doing nothing).
    if std::env::var("VELA_BROWSER_LOGIN_DISABLED").is_ok() {
        return Err(
            "the disposable browser tier is disabled in this environment \
             (VELA_BROWSER_LOGIN_DISABLED is set)"
                .to_string(),
        );
    }
    let binary = candidates()
        .into_iter()
        .next()
        .ok_or_else(|| "no Chrome, Chromium or Edge browser was found on this machine".to_string())?;
    let profile_dir = std::env::temp_dir().join(format!(
        "vela-browser-{}-{}",
        std::process::id(),
        rand_hex(8)
    ));
    std::fs::create_dir_all(&profile_dir).map_err(|e| format!("could not create the browser profile: {e}"))?;

    let mut browser_args: Vec<String> = vec![
        "--remote-debugging-pipe".into(),
        format!("--user-data-dir={}", profile_dir.display()),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--disable-background-networking".into(),
        "--disable-component-update".into(),
        "--disable-default-apps".into(),
        "--window-size=1280,800".into(),
    ];

    #[cfg(target_os = "linux")]
    let sandbox = sandbox_launcher();
    #[cfg(not(target_os = "linux"))]
    let sandbox: Option<PathBuf> = None;

    // When a setuid launcher is configured, the browser is spawned *through*
    // it: `launcher <binary> <profile-dir> <browser-args…>`. The launcher drops
    // the whole browser to a dedicated unprivileged UID and wraps its lifetime
    // (chowning the profile back to us when it exits, so we can wipe it). The
    // pipe fds survive its `execv` (they are not `FD_CLOEXEC` after `dup2`).
    let mut command = match &sandbox {
        Some(launcher) => {
            let mut c = Command::new(launcher);
            c.arg(&binary).arg(&profile_dir).args(&browser_args);
            c
        }
        None => {
            let mut c = Command::new(&binary);
            c.args(&browser_args);
            c
        }
    };
    // Visible by default: a real, human-visible window is both harder for bot
    // checks to reject and lets the user finish a second factor.
    command.stdout(Stdio::null()).stderr(Stdio::null());

    // Wire the CDP pipe: the child gets fd 3 (commands-in) and fd 4
    // (messages-out), copied from our pipe fds in `pre_exec`. The parent keeps
    // the write end of the command pipe and the read end of the message pipe.
    let (cmd_r, cmd_w) = new_pipe()?;
    let (msg_r, msg_w) = new_pipe()?;
    let cmd_r_fd = cmd_r.as_raw_fd();
    let msg_w_fd = msg_w.as_raw_fd();
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `pre_exec` runs trapped in the forked child before exec; the
        // closure only dup2/closes real fds and allocates nothing.
        unsafe {
            command.pre_exec(move || {
                // SAFETY: called in the forked child before exec; fds are real.
                unsafe {
                    if libc::dup2(cmd_r_fd, 3) < 0 || libc::dup2(msg_w_fd, 4) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::close(cmd_r_fd);
                    libc::close(msg_w_fd);
                }
                Ok(())
            });
        }
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not start {binary:?}: {e}"))?;

    // Sandbox self-check. When isolation was explicitly requested, the browser
    // *must* actually be running under a different UID than the app; otherwise
    // the isolation is not effecting anything and we fail closed rather than
    // proceed as if the residual were mitigated.
    #[cfg(target_os = "linux")]
    if let Some(_launcher) = &sandbox {
        let isolated = match (euid_of(child.id()), euid_of(std::process::id())) {
            (Some(browser_euid), Some(app_euid)) => browser_euid != app_euid,
            _ => false,
        };
        if !isolated {
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                "the browser sandbox (VELA_BROWSER_SANDBOX) was requested but the \
                 disposable browser is not running under a distinct UID — the \
                 vela-browser-sandbox launcher may not be installed setuid-root, so \
                 refusing to continue with an ineffective sandbox"
                    .to_string(),
            );
        }
    }

    // Without a sandbox the disposable browser runs as the user's own UID, and
    // the documented residual (a co-resident same-user process reading the
    // substituted password from the browser's memory) is empirically reachable.
    // Say so once, loudly, instead of letting it pass silently.
    #[cfg(target_os = "linux")]
    if sandbox.is_none() {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "the disposable login browser runs as your own UID: a co-resident \
                 same-user process can read its memory during the login (the \
                 substituted password). Enable process isolation with VELA_BROWSER_SANDBOX \
                 and the vela-browser-sandbox setuid launcher (see \
                 desktopVELA/vela-browser-sandbox/)."
            );
        });
    }

    // We are done dup2-ing the child ends; drop them so the parent holds only
    // the ends it needs (command write, message read).
    drop(cmd_r);
    drop(msg_w);

    Ok((
        Browser {
            child: Some(child),
            profile_dir,
        },
        PipeIo {
            command: cmd_w,
            message: msg_r,
        },
    ))
}

/// The browser tier is not yet supported on non-unix platforms (CDP-over-pipe
/// wires via unix fds 3/4). A non-unix build reports this honestly rather than
/// silently opening a debug port.
#[cfg(not(unix))]
pub async fn spawn() -> Result<(Browser, PipeIo), String> {
    Err(format!(
        "the browser-driven login tier is not yet supported on this platform \
         (CDP-over-pipe requires unix fds 3 and 4)"
    ))
}

#[cfg(not(unix))]
#[derive(Debug)]
pub struct PipeIo;


fn rand_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn sandbox_launcher_uses_the_configured_path() {
        std::env::set_var("VELA_BROWSER_SANDBOX", "/opt/vela/libexec/vela-browser-sandbox");
        assert_eq!(
            sandbox_launcher(),
            Some(PathBuf::from("/opt/vela/libexec/vela-browser-sandbox"))
        );
        std::env::remove_var("VELA_BROWSER_SANDBOX");
    }

    #[test]
    fn sandbox_launcher_is_absent_when_not_configured() {
        std::env::remove_var("VELA_BROWSER_SANDBOX");
        assert_eq!(sandbox_launcher(), None);
    }

    #[test]
    fn euid_of_self_reads_the_effective_uid() {
        let uid = euid_of(std::process::id()).expect("self /proc status is readable");
        // We must be running as some uid; cross-check against /proc/self.
        let self_status = std::fs::read_to_string("/proc/self/status").unwrap();
        let expected = self_status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap();
        assert_eq!(uid, expected);
    }
}

