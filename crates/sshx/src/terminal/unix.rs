use std::convert::Infallible;
use std::env;
use std::ffi::CString;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{bail, Result};
use close_fds::CloseFdsBuilder;
use nix::errno::Errno;
use nix::libc::{self, login_tty, TIOCGWINSZ, TIOCSWINSZ};
use nix::pty::{self, Winsize};
use nix::sys::signal::{kill, Signal::SIGKILL};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult, Pid};
use pin_project::{pin_project, pinned_drop};
use tokio::fs::{self, File};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tracing::{instrument, trace};

/// Returns the default shell on this system.
pub async fn get_default_shell() -> String {
    if let Ok(shell) = env::var("SHELL") {
        if !shell.is_empty() {
            return shell;
        }
    }
    for shell in [
        "/bin/bash",
        "/bin/sh",
        "/usr/local/bin/bash",
        "/usr/local/bin/sh",
    ] {
        if fs::metadata(shell).await.is_ok() {
            return shell.to_string();
        }
    }
    String::from("sh")
}

/// Environment variable overrides applied to every child shell process.
///
/// `None` as the value means the variable is removed from the environment.
const ENV_OVERRIDES: &[(&str, Option<&str>)] = &[
    ("TERM", Some("xterm-256color")),
    ("COLORTERM", Some("truecolor")),
    ("TERM_PROGRAM", Some("sshx")),
    ("TERM_PROGRAM_VERSION", None),
];

/// Pre-built data for `execve(2)` that is prepared entirely in the parent
/// process before `fork()`.
///
/// Calling `env::set_var` (which wraps `setenv(3)`) in the child of a
/// multi-threaded process is not async-signal-safe. If another thread held the
/// glibc malloc or env lock at the moment of `fork()`, the child will inherit
/// the locked mutex and deadlock. This struct avoids the problem by building
/// the full argv and environment pointer arrays here, in the parent, so the
/// child can call `execve(2)` directly without any new allocations.
struct PreparedExec {
    /// Resolved absolute path to the shell executable.
    path: CString,
    /// Keeps environment `CString`s alive; their heap addresses are stable even
    /// if this struct is moved (CString stores data on the heap).
    _env_strings: Vec<CString>,
    /// Null-terminated argv array: `[path.as_ptr(), null]`.
    argv_ptrs: Vec<*const libc::c_char>,
    /// Null-terminated environment pointer array.
    env_ptrs: Vec<*const libc::c_char>,
}

// Safety: `CString` heap data does not move with the struct, so the raw
// pointers stored in `argv_ptrs` and `env_ptrs` remain valid after a move.
// Access is restricted to the single-threaded child process after `fork()`.
unsafe impl Send for PreparedExec {}

impl PreparedExec {
    /// Build exec data in the calling (parent) process.
    fn build(shell: &str) -> Result<Self> {
        let path = Self::resolve_shell_path(shell)?;

        // Build the child environment: inherit the parent env, then apply
        // overrides. All CString allocations happen here in the parent.
        let override_keys: std::collections::HashSet<&str> =
            ENV_OVERRIDES.iter().map(|(k, _)| *k).collect();
        let mut env_strings: Vec<CString> = env::vars()
            .filter(|(k, _)| !override_keys.contains(k.as_str()))
            .map(|(k, v)| CString::new(format!("{k}={v}")))
            .collect::<std::result::Result<_, _>>()?;
        for &(key, value) in ENV_OVERRIDES {
            if let Some(val) = value {
                env_strings.push(CString::new(format!("{key}={val}"))?);
            }
        }

        // Build null-terminated raw pointer arrays; these are the actual arrays
        // passed to execve(2). No allocation will happen in the child.
        let argv_ptrs = vec![path.as_ptr(), std::ptr::null()];
        let mut env_ptrs: Vec<*const libc::c_char> =
            env_strings.iter().map(|s| s.as_ptr()).collect();
        env_ptrs.push(std::ptr::null());

        Ok(Self {
            path,
            _env_strings: env_strings,
            argv_ptrs,
            env_ptrs,
        })
    }

    /// Resolve a shell name or path to an absolute path before `fork()`.
    ///
    /// If `shell` contains a `/`, it is used as-is. Otherwise, PATH is
    /// searched in the parent process where it is safe to allocate.
    fn resolve_shell_path(shell: &str) -> Result<CString> {
        if shell.contains('/') {
            return Ok(CString::new(shell)?);
        }
        let path_var = env::var("PATH").unwrap_or_default();
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            let candidate = Path::new(dir).join(shell);
            if candidate.is_file() {
                return Ok(CString::new(candidate.to_str().ok_or_else(|| {
                    anyhow::anyhow!("shell path is not valid UTF-8")
                })?)?);
            }
        }
        bail!("shell executable not found in PATH: {shell}")
    }
}

/// An object that stores the state for a terminal session.
#[pin_project(PinnedDrop)]
pub struct Terminal {
    child: Pid,
    #[pin]
    master_read: File,
    #[pin]
    master_write: File,
}

impl Terminal {
    /// Create a new terminal, with attached PTY.
    #[instrument]
    pub async fn new(shell: &str) -> Result<Terminal> {
        let result = pty::openpty(None, None)?;

        // The slave file descriptor was created by openpty() and is forked here.
        let child = Self::fork_child(shell, result.slave.as_raw_fd())?;

        // We need to clone the file object to prevent livelocks in Tokio, when multiple
        // reads and writes happen concurrently on the same file descriptor. This is a
        // current limitation of how the `tokio::fs::File` struct is implemented, due to
        // its blocking I/O on a separate thread.
        let master_read = File::from(std::fs::File::from(result.master));
        let master_write = master_read.try_clone().await?;

        trace!(%child, "creating new terminal");

        Ok(Self {
            child,
            master_read,
            master_write,
        })
    }

    /// Entry point for the child process, which spawns a shell.
    fn fork_child(shell: &str, slave_port: RawFd) -> Result<Pid> {
        // Prepare all exec data in the parent before forking. This builds the
        // child environment and resolves the shell path without performing any
        // async-signal-unsafe operations (such as setenv/malloc) in the child.
        let exec = PreparedExec::build(shell)?;

        // Safety: `execv_child` performs no new heap allocations in the child
        // branch. All data structures were prepared above in the parent.
        match unsafe { fork() }? {
            ForkResult::Parent { child } => Ok(child),
            ForkResult::Child => match Self::execv_child(slave_port, &exec) {
                Ok(infallible) => match infallible {},
                Err(_) => std::process::exit(1),
            },
        }
    }

    fn execv_child(slave_port: RawFd, exec: &PreparedExec) -> Result<Infallible, Errno> {
        // Safety: The slave file descriptor was created by openpty().
        Errno::result(unsafe { login_tty(slave_port) })?;
        // Safety: This is called immediately before execve(), and there are no
        // other threads in this process to interact with its file descriptor
        // table.
        unsafe { CloseFdsBuilder::new().closefrom(3) };

        // Call execve(2) directly using pre-built pointer arrays so that no new
        // memory allocation is required in the child process. setenv(3) and
        // env::set_var are intentionally avoided here.
        //
        // Safety: `exec.argv_ptrs` and `exec.env_ptrs` are null-terminated
        // arrays of valid, non-overlapping C strings allocated in the parent.
        // They remain valid because CString heap data is not invalidated by
        // moving the PreparedExec struct.
        let _ = unsafe {
            libc::execve(
                exec.path.as_ptr(),
                exec.argv_ptrs.as_ptr(),
                exec.env_ptrs.as_ptr(),
            )
        };

        // execve(2) only returns on error; errno is set.
        Err(Errno::last())
    }

    /// Get the window size of the TTY.
    pub fn get_winsize(&self) -> Result<(u16, u16)> {
        nix::ioctl_read_bad!(ioctl_get_winsize, TIOCGWINSZ, Winsize);
        let mut winsize = make_winsize(0, 0);
        // Safety: The master file descriptor was created by openpty().
        unsafe { ioctl_get_winsize(self.master_read.as_raw_fd(), &mut winsize) }?;
        Ok((winsize.ws_row, winsize.ws_col))
    }

    /// Set the window size of the TTY.
    pub fn set_winsize(&mut self, rows: u16, cols: u16) -> Result<()> {
        nix::ioctl_write_ptr_bad!(ioctl_set_winsize, TIOCSWINSZ, Winsize);
        let winsize = make_winsize(rows, cols);
        // Safety: The master file descriptor was created by openpty().
        unsafe { ioctl_set_winsize(self.master_read.as_raw_fd(), &winsize) }?;
        Ok(())
    }
}

// Redirect terminal reads to the read file object.
impl AsyncRead for Terminal {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().master_read.poll_read(cx, buf)
    }
}

// Redirect terminal writes to the write file object.
impl AsyncWrite for Terminal {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().master_write.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().master_write.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().master_write.poll_shutdown(cx)
    }
}

#[pinned_drop]
impl PinnedDrop for Terminal {
    fn drop(self: Pin<&mut Self>) {
        let this = self.project();
        let child = *this.child;
        trace!(%child, "dropping terminal");

        // Kill the child process on closure so that it doesn't keep running.
        kill(child, SIGKILL).ok();

        // Reap the zombie process in a background thread.
        std::thread::spawn(move || {
            waitpid(child, None).ok();
        });
    }
}

fn make_winsize(rows: u16, cols: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0, // ignored
        ws_ypixel: 0, // ignored
    }
}
