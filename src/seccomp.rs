use anyhow::{bail, Result};

// Landlock before ABI v9 can't stop connect() on a unix socket path, which
// leaves the ssh-agent, the D-Bus session bus and docker.sock reachable.
// This filter refuses to create unix sockets at all. socketpair() stays
// allowed since it can only talk to the process itself.

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const OFFSET_ARG0: u32 = 16;

const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const JGE: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

fn op(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

pub fn deny_unix_sockets() -> Result<()> {
    let deny = libc::SECCOMP_RET_ERRNO | libc::EACCES as u32;
    let allow = libc::SECCOMP_RET_ALLOW;
    let filter = [
        op(LD_W_ABS, OFFSET_ARCH, 0, 0),
        op(JEQ, AUDIT_ARCH, 0, 7),
        op(LD_W_ABS, OFFSET_NR, 0, 0),
        op(JGE, X32_SYSCALL_BIT, 5, 0),
        // io_uring can create and connect sockets without calling socket().
        op(JEQ, libc::SYS_io_uring_setup as u32, 4, 0),
        op(JEQ, libc::SYS_socket as u32, 0, 2),
        op(LD_W_ABS, OFFSET_ARG0, 0, 0),
        op(JEQ, libc::AF_UNIX as u32, 1, 0),
        op(RET, allow, 0, 0),
        op(RET, deny, 0, 0),
    ];
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog) != 0
        {
            bail!(
                "installing seccomp filter: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}
