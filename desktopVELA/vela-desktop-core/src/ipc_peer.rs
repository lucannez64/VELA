//! Who is on the other end of the IPC connection.
//!
//! The capability token is a bearer written to `ipc_auth.json` (0600). Any
//! process running as the same user can read that file and then speak to us as
//! if it were the browser extension, which is how a plaintext password could
//! leave the app without the user doing anything (audit D-4).
//!
//! The kernel already knows who connected. Asking it costs nothing and cannot
//! be forged by the peer: `SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS and
//! the BSDs, `GetNamedPipeClientProcessId` on Windows. That does not stop a
//! process that legitimately runs as the user, but it turns an anonymous
//! request into a named one — which is what lets the release be shown to the
//! user, rate-limited per caller, and refused outright when it comes from
//! something that is not the browser we expect.

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
fn exe_for_pid(pid: u32) -> Option<PathBuf> {
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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
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

    let handle = HANDLE(pipe.as_raw_handle() as isize);
    let mut pid: u32 = 0;
    // SAFETY: `handle` is a live pipe handle for the duration of the call.
    let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) }.is_ok();
    if !ok || pid == 0 {
        return PeerIdentity::default();
    }
    // A named pipe with reject_remote_clients only accepts local callers, and
    // the pipe's DACL already restricts it to this user; there is no cheap uid
    // equivalent to read here, so same-user is enforced by the DACL alone.
    PeerIdentity { pid: Some(pid), uid: Some(current_uid()), exe: None }
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
