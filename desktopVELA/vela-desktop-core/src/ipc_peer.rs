//! Who is on the other end of the IPC connection.
//!
//! There is no capability token any more (issue #149, option B removed the
//! `ipc_auth.json` bearer): what a caller *says* proves nothing, because
//! anything running as this user could read whatever file we once shared with
//! it. What cannot be forged by the peer is the kernel's answer to "who is on
//! the other end": `SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`LOCAL_PEERPID` on
//! macOS and `GetNamedPipeClientProcessId` on Windows. That does not stop a
//! process that legitimately runs as the user, but it turns an anonymous
//! request into a named one — which is what lets the connection gate
//! (`ipc_gate`) verify the peer is a browser-spawned VELA host binary, and
//! what lets a plaintext release be bound to a pid, audited per caller, and
//! refused outright when it comes from something that is not expected.

use std::path::PathBuf;

/// What the kernel says about the process at the other end.
///
/// Every field is optional because platforms differ in what they expose, and a
/// missing field must never read as "allowed" — callers check for the value
/// they need rather than assuming absence is benign.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerIdentity {
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    /// Resolved from the pid where the OS allows it. Best-effort and racy by
    /// nature (the pid can be recycled), so it is used for display and for
    /// coarse checks, never as the only thing standing between a caller and a
    /// password.
    pub exe: Option<PathBuf>,
}

impl PeerIdentity {
    /// Whether this peer runs as the same user as we do.
    ///
    /// `None` uid means the platform did not tell us, which is *not* a pass:
    /// the socket's own 0600 mode is then the only thing enforcing it.
    pub fn is_same_user(&self) -> bool {
        match self.uid {
            Some(uid) => uid == current_uid(),
            None => false,
        }
    }

    /// A short description for logs and for the confirmation prompt. Never
    /// includes the full path in logs — a home directory can carry a username.
    pub fn describe(&self) -> String {
        let name = self
            .exe
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown program".to_string());
        match self.pid {
            Some(pid) => format!("{name} (pid {pid})"),
            None => name,
        }
    }
}

#[cfg(unix)]
pub fn current_uid() -> u32 {
    // SAFETY: getuid is always safe; it reads a process property and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
pub fn current_uid() -> u32 {
    0
}

/// Resolve a pid to its executable path, where the platform allows it.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
pub(crate) fn exe_for_pid(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; 4096];
        // SAFETY: proc_pidpath writes at most buf.len() bytes into buf.
        let len = unsafe {
            proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
        };
        if len <= 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(PathBuf::from(String::from_utf8_lossy(&buf).to_string()))
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        };

        const PROCESS_NAME_WIN32: u32 = 0;
        // SAFETY: `pid` names a possibly-live process; OpenProcess either
        // yields a handle we close below or fails. The buffer and its length
        // are passed as a pair, as the API requires.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let result = QueryFullProcessImageNameW(
                HANDLE(handle.0),
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
            );
            let _ = windows::Win32::Foundation::CloseHandle(HANDLE(handle.0));
            if result.is_err() || len == 0 {
                return None;
            }
            Some(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = pid;
        None
    }
}

/// The pid of `pid`'s parent process, where the platform allows it.
///
/// Best-effort and racy by nature: the parent may exit between the connect
/// and this lookup, and pids can be recycled. Callers treat "unknown" as
/// refusal, never as a pass.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos", windows)), allow(dead_code))]
pub fn parent_pid(pid: u32) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        // /proc/<pid>/stat: fields after the final ')' are space-separated,
        // the first being the process state and the second being ppid (comm
        // may contain spaces and parentheses, so everything before the last
        // ')' is skipped wholesale).
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = stat.rsplit_once(')')?.1;
        let ppid = rest.split_whitespace().nth(1)?.parse::<u32>().ok()?;
        (ppid > 0).then_some(ppid)
    }
    #[cfg(target_os = "macos")]
    {
        // No cheap libc-only route to ppid; `ps` is always present on macOS.
        let out = std::process::Command::new("ps")
            .args(["-o", "ppid=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        std::str::from_utf8(&out.stdout)
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|p| *p > 0)
    }
    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };

        // SAFETY: the snapshot handle is closed before every return; the
        // PROCESSENTRY32W struct is size-initialised as the API demands and
        // only ever written by Process32*W.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
            let _guard = HandleGuard(snapshot);
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            if Process32FirstW(snapshot, &mut entry).is_err() {
                return None;
            }
            loop {
                if entry.th32ProcessID == pid {
                    let ppid = entry.th32ParentProcessID;
                    return (ppid > 0).then_some(ppid);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    return None;
                }
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = pid;
        None
    }
}

#[cfg(windows)]
struct HandleGuard(windows::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        // SAFETY: closing a handle we own exactly once.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
}

/// Identify the peer of a connected Unix domain socket.
#[cfg(unix)]
pub fn identify_unix<S: std::os::unix::io::AsRawFd>(stream: &S) -> PeerIdentity {
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `cred`, and `len`
        // is initialised to its true size.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return PeerIdentity::default();
        }
        let pid = (cred.pid > 0).then_some(cred.pid as u32);
        return PeerIdentity {
            pid,
            uid: Some(cred.uid),
            exe: pid.and_then(exe_for_pid),
        };
    }

    #[cfg(target_os = "macos")]
    {
        // LOCAL_PEERCRED gives the uid; the pid needs LOCAL_PEERPID separately.
        let mut xucred: libc::xucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
        // SAFETY: as above.
        let uid = unsafe {
            let rc = libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                &mut xucred as *mut libc::xucred as *mut libc::c_void,
                &mut len,
            );
            (rc == 0).then_some(xucred.cr_uid)
        };

        const LOCAL_PEERPID: libc::c_int = 2;
        let mut pid: libc::pid_t = 0;
        let mut pid_len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: as above.
        let pid = unsafe {
            let rc = libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                LOCAL_PEERPID,
                &mut pid as *mut libc::pid_t as *mut libc::c_void,
                &mut pid_len,
            );
            (rc == 0 && pid > 0).then_some(pid as u32)
        };

        return PeerIdentity { pid, uid, exe: pid.and_then(exe_for_pid) };
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        PeerIdentity::default()
    }
}

/// Identify the client of a connected Windows named pipe.
#[cfg(windows)]
pub fn identify_named_pipe<S: std::os::windows::io::AsRawHandle>(pipe: &S) -> PeerIdentity {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

    // windows-rs 0.58 models HANDLE as a raw pointer, and RawHandle already is
    // one — going via isize does not compile.
    let handle = HANDLE(pipe.as_raw_handle());
    let mut pid: u32 = 0;
    // SAFETY: `handle` is a live pipe handle for the duration of the call.
    let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) }.is_ok();
    if !ok || pid == 0 {
        return PeerIdentity::default();
    }
    // A named pipe with reject_remote_clients only accepts local callers, and
    // the pipe's DACL already restricts it to this user; there is no cheap uid
    // equivalent to read here, so same-user is enforced by the DACL alone.
    PeerIdentity { pid: Some(pid), uid: Some(current_uid()), exe: exe_for_pid(pid) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_we_could_not_identify_is_not_treated_as_ours() {
        // The important direction: absence of information must not read as a
        // pass, or the check would be worse than no check at all.
        assert!(!PeerIdentity::default().is_same_user());
    }

    #[test]
    fn describe_names_the_program_without_leaking_the_path() {
        let peer = PeerIdentity {
            pid: Some(4321),
            uid: Some(current_uid()),
            exe: Some(PathBuf::from("/home/someone/.local/share/firefox/firefox")),
        };
        let described = peer.describe();
        assert_eq!(described, "firefox (pid 4321)");
        assert!(!described.contains("someone"), "home directory leaked: {described}");
    }

    #[test]
    fn describe_survives_an_unidentifiable_peer() {
        assert_eq!(PeerIdentity::default().describe(), "unknown program");
    }

    #[cfg(unix)]
    #[test]
    fn our_own_socket_peer_is_us() {
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().unwrap();
        let peer = identify_unix(&a);
        assert_eq!(peer.uid, Some(current_uid()));
        assert!(peer.is_same_user());
    }
}
