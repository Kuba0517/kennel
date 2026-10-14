use anyhow::{bail, Result};
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// Fork. Returns 0 in the child and the child's pid in the parent.
pub fn fork() -> Result<libc::pid_t> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid > 0 {
        CHILD.store(pid, Ordering::Relaxed);
        unsafe {
            // Ctrl-C and Ctrl-\ already reach the agent through the terminal.
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            libc::signal(libc::SIGQUIT, libc::SIG_IGN);
            for sig in [libc::SIGTERM, libc::SIGHUP] {
                libc::signal(sig, forward as *const () as libc::sighandler_t);
            }
        }
    }
    Ok(pid)
}

/// Wait for the agent and return the exit code kennel should exit with.
pub fn wait(pid: libc::pid_t) -> Result<i32> {
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            bail!("waitpid: {err}");
        }
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else {
        Ok(128 + libc::WTERMSIG(status))
    }
}
