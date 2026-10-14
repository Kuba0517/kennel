use anyhow::{bail, Result};
use std::os::fd::{FromRawFd, OwnedFd};

// Landlock before ABI v9 can't stop connect() on a unix socket path, which
// leaves the ssh-agent, the D-Bus session bus and docker.sock reachable, and
// its TCP rules match a port on any host. So kennel adds a seccomp filter:
// unix sockets can't be created (socketpair() is fine), and in proxy mode
// only TCP sockets can be created and every connect() goes to the supervisor.

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SOCK_TYPE_MASK: u32 = 0xf;

fn arg(n: u32) -> u32 {
    16 + 8 * n
}

#[derive(Clone, Copy, PartialEq)]
enum L {
    Native,
    Allow,
    Deny,
    Notify,
    Socket,
    InetType,
    InetProto,
    SendFlags2,
    SendFlags3,
}

enum Op {
    Load(u32),
    And(u32),
    Jeq(u32, L),
    Jge(u32, L),
    Jset(u32, L),
    Goto(L),
    Ret(u32),
    Label(L),
}

fn assemble(ops: &[Op]) -> Vec<libc::sock_filter> {
    let mut pos = Vec::new();
    let mut n = 0usize;
    for op in ops {
        match op {
            Op::Label(l) => pos.push((*l, n)),
            _ => n += 1,
        }
    }
    let at = |l: L| pos.iter().find(|(x, _)| *x == l).unwrap().1;
    let mut out = Vec::new();
    for op in ops {
        let i = out.len();
        let rel = |l: L| (at(l) - i - 1) as u8;
        let jmp = |code: u32, k: u32, l: L| libc::sock_filter {
            code: (libc::BPF_JMP | code | libc::BPF_K) as u16,
            jt: rel(l),
            jf: 0,
            k,
        };
        out.push(match *op {
            Op::Label(_) => continue,
            Op::Load(off) => libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: off,
            },
            Op::And(k) => libc::sock_filter {
                code: (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k,
            },
            Op::Jeq(k, l) => jmp(libc::BPF_JEQ, k, l),
            Op::Jge(k, l) => jmp(libc::BPF_JGE, k, l),
            Op::Jset(k, l) => jmp(libc::BPF_JSET, k, l),
            Op::Goto(l) => libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JA) as u16,
                jt: 0,
                jf: 0,
                k: (at(l) - i - 1) as u32,
            },
            Op::Ret(k) => libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k,
            },
        });
    }
    out
}

fn program(deny_unix: bool, proxy: bool) -> Vec<libc::sock_filter> {
    use Op::*;
    let fastopen = libc::MSG_FASTOPEN as u32;
    // A non-native arch has different syscall numbers, so deny it outright.
    let mut ops = vec![
        Load(4),
        Jeq(AUDIT_ARCH, L::Native),
        Goto(L::Deny),
        Label(L::Native),
    ];
    ops.extend([
        Load(0),
        Jge(X32_SYSCALL_BIT, L::Deny),
        // io_uring can create and connect sockets without calling socket().
        Jeq(libc::SYS_io_uring_setup as u32, L::Deny),
        Jeq(libc::SYS_socket as u32, L::Socket),
    ]);
    if proxy {
        ops.extend([
            Jeq(libc::SYS_connect as u32, L::Notify),
            // TCP Fast Open connects from sendto/sendmsg without connect().
            Jeq(libc::SYS_sendto as u32, L::SendFlags3),
            Jeq(libc::SYS_sendmmsg as u32, L::SendFlags3),
            Jeq(libc::SYS_sendmsg as u32, L::SendFlags2),
        ]);
    }
    ops.extend([Goto(L::Allow), Label(L::Socket), Load(arg(0))]);
    if deny_unix {
        ops.push(Jeq(libc::AF_UNIX as u32, L::Deny));
    }
    if proxy {
        ops.extend([
            Jeq(libc::AF_UNIX as u32, L::Allow),
            Jeq(libc::AF_NETLINK as u32, L::Allow),
            Jeq(libc::AF_INET as u32, L::InetType),
            Jeq(libc::AF_INET6 as u32, L::InetType),
            Goto(L::Deny),
            Label(L::InetType),
            Load(arg(1)),
            And(SOCK_TYPE_MASK),
            Jeq(libc::SOCK_STREAM as u32, L::InetProto),
            Goto(L::Deny),
            Label(L::InetProto),
            Load(arg(2)),
            Jeq(0, L::Allow),
            Jeq(libc::IPPROTO_TCP as u32, L::Allow),
            Goto(L::Deny),
            Label(L::SendFlags2),
            Load(arg(2)),
            Jset(fastopen, L::Deny),
            Goto(L::Allow),
            Label(L::SendFlags3),
            Load(arg(3)),
            Jset(fastopen, L::Deny),
            Goto(L::Allow),
            Label(L::Notify),
            Ret(libc::SECCOMP_RET_USER_NOTIF),
        ]);
    }
    ops.extend([
        Label(L::Allow),
        Ret(libc::SECCOMP_RET_ALLOW),
        Label(L::Deny),
        Ret(libc::SECCOMP_RET_ERRNO | libc::EACCES as u32),
    ]);
    assemble(&ops)
}

/// Install the filter. In proxy mode, returns the listener fd the supervisor
/// uses to answer connect() calls.
pub fn install(deny_unix: bool, proxy: bool) -> Result<Option<OwnedFd>> {
    let filter = program(deny_unix, proxy);
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };
    let flags = if proxy {
        libc::SECCOMP_FILTER_FLAG_NEW_LISTENER
    } else {
        0
    };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            bail!("PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error());
        }
        let r = libc::syscall(libc::SYS_seccomp, 1, flags, &prog);
        if r < 0 {
            bail!(
                "installing seccomp filter: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(proxy.then(|| OwnedFd::from_raw_fd(r as i32)))
    }
}
