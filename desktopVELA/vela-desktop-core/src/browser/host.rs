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
//! Process isolation: Linux can route the launch through a dedicated UID via
//! `VELA_BROWSER_SANDBOX`. Windows keeps Chromium's own sandbox enabled and
//! contains the complete process tree in a kill-on-close Job Object. That is
//! strong lifecycle containment, but not yet the Linux launcher's distinct-
//! principal memory boundary; requesting that boundary on Windows fails
//! closed rather than mislabelling Chromium's sandbox as equivalent.

use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Child, Command, Stdio};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// The parent's ends of the CDP debugging pipe.
///
/// Chromium's `--remote-debugging-pipe` reads commands from **fd 3** and writes
/// messages to **fd 4**; the parent holds the write end of the command pipe and
/// the read end of the message pipe. Both directions carry **NUL-delimited
/// JSON** (a JSON value followed by `\0`); see the CDP client in `cdp.rs`.
#[cfg(unix)]
#[derive(Debug)]
pub struct PipeIo {
    pub command: std::os::unix::io::OwnedFd,
    pub message: std::os::unix::io::OwnedFd,
}

/// The parent's ends of Chromium's named debugging pipes on Windows.
#[cfg(windows)]
#[derive(Debug)]
pub struct PipeIo {
    pub command: tokio::fs::File,
    pub message: tokio::fs::File,
}

/// A running disposable browser. Dropping it kills the process and wipes the
/// profile.
pub struct Browser {
    #[cfg(unix)]
    child: Option<Child>,
    #[cfg(windows)]
    process: Option<WindowsProcess>,
    profile_dir: PathBuf,
}

impl Drop for Browser {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        #[cfg(windows)]
        drop(self.process.take());

        // Windows antivirus and Chromium children can keep profile handles
        // alive for a few milliseconds after the job is terminated.
        for _ in 0..20 {
            match std::fs::remove_dir_all(&self.profile_dir) {
                Ok(()) if !self.profile_dir.exists() => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                _ => std::thread::sleep(std::time::Duration::from_millis(25)),
            }
        }
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
            "google-chrome-beta",
            "google-chrome-unstable",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
            "microsoft-edge-stable",
            "microsoft-edge-beta",
            "microsoft-edge-dev",
            "brave-browser",
            "brave",
            "thorium-browser",
            "helium",
            "vivaldi-stable",
            "opera",
            "ungoogled-chromium",
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
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Vivaldi.app/Contents/MacOS/Vivaldi",
            "/Applications/Opera.app/Contents/MacOS/Opera",
        ] {
            let path = PathBuf::from(name);
            if path.exists() {
                out.push(path);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        for name in [
            "chrome.exe",
            "msedge.exe",
            "chromium.exe",
            "brave.exe",
            "vivaldi.exe",
            "helium.exe",
            "thorium.exe",
        ] {
            if let Some(path) = which(name) {
                out.push(path);
            }
        }
        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let program_files_x86 =
            std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
        for root in [&program_files, &program_files_x86, &local_app_data] {
            for relative in [
                r"Google\Chrome\Application\chrome.exe",
                r"Microsoft\Edge\Application\msedge.exe",
                r"Chromium\Application\chrome.exe",
                r"BraveSoftware\Brave-Browser\Application\brave.exe",
                r"Vivaldi\Application\vivaldi.exe",
                r"Helium\Application\helium.exe",
                r"Helium\Application\chrome.exe",
                r"imput\Helium\Application\chrome.exe",
                r"Thorium\Application\thorium.exe",
                r"Thorium\Application\chrome.exe",
                r"Programs\Opera\opera.exe",
            ] {
                let path = PathBuf::from(root).join(relative);
                if path.exists() {
                    out.push(path);
                }
            }
        }

        // Some Windows installations expose the full Edge executable only
        // under a versioned EdgeCore directory (there is no
        // Microsoft\Edge\Application shim). Keep it as a fallback after the
        // user's installed browser builds: challenge cookies copied from an
        // active tab can be bound to the browser build that minted them.
        for root in [&program_files, &program_files_x86] {
            out.extend(edge_core_binaries(std::path::Path::new(root)));
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn edge_core_binaries(root: &std::path::Path) -> Vec<PathBuf> {
    let edge_core = root.join(r"Microsoft\EdgeCore");
    let Ok(entries) = std::fs::read_dir(edge_core) else {
        return Vec::new();
    };
    let mut binaries: Vec<(Vec<u32>, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let version = entry
                .file_name()
                .to_string_lossy()
                .split('.')
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            let binary = entry.path().join("msedge.exe");
            binary.is_file().then_some((version, binary))
        })
        .collect();
    binaries.sort_by(|left, right| right.0.cmp(&left.0));
    binaries.into_iter().map(|(_, path)| path).collect()
}

#[cfg(windows)]
struct WindowsProcess {
    process: windows_sys::Win32::Foundation::HANDLE,
    job: windows_sys::Win32::Foundation::HANDLE,
}

// These are owned kernel handles. Moving their numeric values to another
// thread does not change ownership; Drop remains the only closer.
#[cfg(windows)]
unsafe impl Send for WindowsProcess {}

#[cfg(windows)]
impl Drop for WindowsProcess {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        // KILL_ON_JOB_CLOSE is the backstop. Terminating explicitly lets us
        // wait until every Chromium child has released the disposable profile.
        unsafe {
            let _ = TerminateJobObject(self.job, 1);
            let _ = WaitForSingleObject(self.process, 5_000);
            CloseHandle(self.process);
            CloseHandle(self.job);
        }
    }
}

#[cfg(windows)]
fn quote_windows_arg(arg: &std::ffi::OsStr) -> String {
    let text = arg.to_string_lossy();
    if !text.is_empty() && !text.bytes().any(|b| b == b' ' || b == b'\t' || b == b'"') {
        return text.into_owned();
    }
    let mut out = String::from("\"");
    let mut slashes = 0usize;
    for ch in text.chars() {
        if ch == '\\' {
            slashes += 1;
        } else if ch == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
            out.push('"');
            slashes = 0;
        } else {
            out.push_str(&"\\".repeat(slashes));
            slashes = 0;
            out.push(ch);
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

#[cfg(windows)]
fn spawn_windows(
    binary: &std::path::Path,
    args: &[String],
) -> Result<(WindowsProcess, PipeIo), String> {
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        ResumeThread, UpdateProcThreadAttribute, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        STARTUPINFOEXW,
    };

    fn winerr(context: &str) -> String {
        format!("{context}: {}", std::io::Error::last_os_error())
    }
    unsafe fn close_if_valid(handle: HANDLE) {
        if !handle.is_null() {
            CloseHandle(handle);
        }
    }

    let mut security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let (mut command_read, mut command_write) = (null_mut(), null_mut());
    let (mut message_read, mut message_write) = (null_mut(), null_mut());
    unsafe {
        if CreatePipe(&mut command_read, &mut command_write, &mut security, 0) == 0
            || CreatePipe(&mut message_read, &mut message_write, &mut security, 0) == 0
        {
            let error = winerr("could not create Chromium debugging pipes");
            close_if_valid(command_read);
            close_if_valid(command_write);
            close_if_valid(message_read);
            close_if_valid(message_write);
            return Err(error);
        }
        if SetHandleInformation(command_write, HANDLE_FLAG_INHERIT, 0) == 0
            || SetHandleInformation(message_read, HANDLE_FLAG_INHERIT, 0) == 0
        {
            let error = winerr("could not protect parent debugging-pipe handles");
            close_if_valid(command_read);
            close_if_valid(command_write);
            close_if_valid(message_read);
            close_if_valid(message_write);
            return Err(error);
        }
    }

    let io_arg = format!(
        "--remote-debugging-io-pipes={},{}",
        command_read as usize as u32, message_write as usize as u32
    );
    let mut all_args = args.to_vec();
    all_args.push(io_arg);
    let mut command_parts = vec![quote_windows_arg(binary.as_os_str())];
    command_parts.extend(
        all_args
            .iter()
            .map(|arg| quote_windows_arg(std::ffi::OsStr::new(arg))),
    );
    let mut command_line = command_parts
        .join(" ")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    use std::os::windows::ffi::OsStrExt;
    let application = binary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    let mut attr_size = 0usize;
    unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attr_size) };
    let mut attr_storage = vec![0u8; attr_size];
    let attrs = attr_storage.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
    let child_handles = [command_read, message_write];
    let attrs_initialized =
        unsafe { InitializeProcThreadAttributeList(attrs, 1, 0, &mut attr_size) != 0 };
    let attrs_updated = attrs_initialized
        && unsafe {
            UpdateProcThreadAttribute(
                attrs,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                child_handles.as_ptr() as *mut _,
                std::mem::size_of_val(&child_handles),
                null_mut(),
                null_mut(),
            ) != 0
        };
    if !attrs_updated {
        let error = winerr("could not restrict Chromium handle inheritance");
        unsafe {
            if attrs_initialized {
                DeleteProcThreadAttributeList(attrs);
            }
            close_if_valid(command_read);
            close_if_valid(command_write);
            close_if_valid(message_read);
            close_if_valid(message_write);
        }
        return Err(error);
    }

    let job = unsafe { CreateJobObjectW(null(), null()) };
    if job.is_null() {
        let error = winerr("could not create Chromium job object");
        unsafe {
            DeleteProcThreadAttributeList(attrs);
            close_if_valid(command_read);
            close_if_valid(command_write);
            close_if_valid(message_read);
            close_if_valid(message_write);
        }
        return Err(error);
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
    {
        let error = winerr("could not configure Chromium job object");
        unsafe {
            DeleteProcThreadAttributeList(attrs);
            CloseHandle(job);
            close_if_valid(command_read);
            close_if_valid(command_write);
            close_if_valid(message_read);
            close_if_valid(message_write);
        }
        return Err(error);
    }

    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attrs;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
            null(),
            null(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    let create_error = (created == 0).then(|| winerr("could not start the disposable browser"));
    unsafe {
        DeleteProcThreadAttributeList(attrs);
        CloseHandle(command_read);
        CloseHandle(message_write);
    }
    if created == 0 {
        unsafe {
            CloseHandle(job);
            close_if_valid(command_write);
            close_if_valid(message_read);
        }
        return Err(create_error.expect("failed CreateProcess has an error"));
    }
    if unsafe { AssignProcessToJobObject(job, info.hProcess) } == 0 {
        let error = unsafe { GetLastError() };
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(info.hProcess, 1);
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
            CloseHandle(job);
            close_if_valid(command_write);
            close_if_valid(message_read);
        }
        return Err(format!(
            "could not contain Chromium in a job object: OS error {error}"
        ));
    }
    if unsafe { ResumeThread(info.hThread) } == u32::MAX {
        let error = winerr("could not resume the disposable browser");
        unsafe {
            CloseHandle(info.hThread);
            close_if_valid(command_write);
            close_if_valid(message_read);
        }
        drop(WindowsProcess {
            process: info.hProcess,
            job,
        });
        return Err(error);
    }
    unsafe { CloseHandle(info.hThread) };

    let command_file = unsafe { std::fs::File::from_raw_handle(command_write as RawHandle) };
    let message_file = unsafe { std::fs::File::from_raw_handle(message_read as RawHandle) };
    Ok((
        WindowsProcess {
            process: info.hProcess,
            job,
        },
        PipeIo {
            command: tokio::fs::File::from_std(command_file),
            message: tokio::fs::File::from_std(message_file),
        },
    ))
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

/// Create a pipe with `FD_CLOEXEC` set on both ends, returning (read, write).
///
/// Uses `libc::pipe` + `fcntl(F_SETFD, FD_CLOEXEC)` rather than `pipe2`, which
/// the `libc` crate only exposes on Linux/Android — the macOS build needs the
/// portable form.
#[cfg(unix)]
fn new_pipe() -> Result<(std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd), String> {
    use std::os::unix::io::FromRawFd;
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a two-element mutable array of int, a valid `pipe` out.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe failed: {}", std::io::Error::last_os_error()));
    }
    for &fd in &fds {
        // SAFETY: `fd` is a valid open fd we just created.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    // SAFETY: on success `pipe` filled `fds` with two valid open file descriptors.
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
    let binary = candidates().into_iter().next().ok_or_else(|| {
        "no Chrome, Chromium or Edge browser was found on this machine".to_string()
    })?;
    tracing::info!(
        browser = %binary.display(),
        "browser login: launching disposable browser"
    );
    let profile_dir = std::env::temp_dir().join(format!(
        "vela-browser-{}-{}",
        std::process::id(),
        rand_hex(8)
    ));
    std::fs::create_dir_all(&profile_dir)
        .map_err(|e| format!("could not create the browser profile: {e}"))?;

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

/// Spawn Chromium on Windows with its two CDP handles as the *only* inherited
/// handles and suspend it until it is inside a kill-on-close Job Object. The
/// browser's own Windows sandbox remains enabled (we never pass --no-sandbox).
#[cfg(windows)]
pub async fn spawn() -> Result<(Browser, PipeIo), String> {
    if std::env::var("VELA_BROWSER_LOGIN_DISABLED").is_ok() {
        return Err(
            "the disposable browser tier is disabled in this environment \
             (VELA_BROWSER_LOGIN_DISABLED is set)"
                .to_string(),
        );
    }
    if std::env::var_os("VELA_BROWSER_SANDBOX").is_some() {
        return Err(
            "VELA_BROWSER_SANDBOX requests dedicated-principal isolation, which \
             is not available on Windows; refusing to pretend the Chromium \
             sandbox is an equivalent boundary"
                .to_string(),
        );
    }
    let binary = candidates().into_iter().next().ok_or_else(|| {
        "no Chrome, Chromium, Edge, Brave or Vivaldi browser was found on this machine".to_string()
    })?;
    tracing::info!(
        browser = %binary.display(),
        "browser login: launching disposable browser"
    );
    let profile_dir = std::env::temp_dir().join(format!(
        "vela-browser-{}-{}",
        std::process::id(),
        rand_hex(8)
    ));
    std::fs::create_dir_all(&profile_dir)
        .map_err(|e| format!("could not create the browser profile: {e}"))?;
    let browser_args = vec![
        "--remote-debugging-pipe".into(),
        format!("--user-data-dir={}", profile_dir.display()),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--window-size=1280,800".into(),
    ];
    match spawn_windows(&binary, &browser_args) {
        Ok((process, pipe)) => Ok((
            Browser {
                process: Some(process),
                profile_dir,
            },
            pipe,
        )),
        Err(error) => {
            let _ = std::fs::remove_dir_all(&profile_dir);
            Err(error)
        }
    }
}

/// Other non-Unix platforms still lack a safe CDP pipe transport.
#[cfg(not(any(unix, windows)))]
pub async fn spawn() -> Result<(Browser, PipeIo), String> {
    Err(format!(
        "the browser-driven login tier is not yet supported on this platform \
         (CDP-over-pipe requires unix fds 3 and 4)"
    ))
}

#[cfg(not(any(unix, windows)))]
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

    // The launcher reads an env var, and env vars are process-global: these
    // two tests raced each other when run in parallel (one asserted presence
    // while the other asserted absence). Serialize every test that touches
    // `VELA_BROWSER_SANDBOX`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn sandbox_launcher_uses_the_configured_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(
            "VELA_BROWSER_SANDBOX",
            "/opt/vela/libexec/vela-browser-sandbox",
        );
        assert_eq!(
            sandbox_launcher(),
            Some(PathBuf::from("/opt/vela/libexec/vela-browser-sandbox"))
        );
        std::env::remove_var("VELA_BROWSER_SANDBOX");
    }

    #[test]
    fn sandbox_launcher_is_absent_when_not_configured() {
        let _guard = ENV_LOCK.lock().unwrap();
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{quote_windows_arg, spawn};
    use std::ffi::OsStr;

    #[test]
    fn windows_arguments_preserve_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote_windows_arg(OsStr::new("plain")), "plain");
        assert_eq!(quote_windows_arg(OsStr::new("two words")), "\"two words\"");
        assert_eq!(quote_windows_arg(OsStr::new(r#"a\"b"#)), "\"a\\\\\\\"b\"");
        assert_eq!(
            quote_windows_arg(OsStr::new("C:\\dir with space\\")),
            "\"C:\\dir with space\\\\\""
        );
    }

    /// Opens a real disposable browser window. Kept ignored for ordinary CI,
    /// but exercises the Windows-only handle adoption and Job Object path on
    /// release machines that have a supported browser installed.
    #[tokio::test]
    #[ignore = "opens an installed browser"]
    async fn real_windows_debugging_pipe_round_trip() {
        assert!(
            std::env::var_os("VELA_BROWSER_SANDBOX").is_none(),
            "unset VELA_BROWSER_SANDBOX for this transport smoke test"
        );
        let (browser, pipe) = spawn().await.expect("spawn disposable browser");
        let profile_dir = browser.profile_dir.clone();
        let cdp = super::super::cdp::Cdp::connect_pipe(pipe.command, pipe.message)
            .await
            .expect("connect CDP pipe");
        let version = cdp
            .call("Browser.getVersion", serde_json::json!({}))
            .await
            .expect("Browser.getVersion");
        assert!(version
            .get("product")
            .and_then(serde_json::Value::as_str)
            .is_some());
        drop(cdp);
        drop(browser);
        assert!(!profile_dir.exists(), "disposable profile was not removed");
    }
}
