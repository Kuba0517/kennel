use crate::proxy::Log;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

// Every connect() in the sandbox stops here. kennel never lets the agent's own
// call go ahead with an address it read from the agent's memory, since the
// agent could change it after the check. Instead the supervisor makes the
// connection itself and swaps the connected socket into the agent's fd.

// <linux/seccomp.h>: _IOWR('!', 0, seccomp_notif) and friends.
const NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
const NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

pub struct Targets {
    pub proxy_port: u16,
    pub local_ports: Vec<u16>,
}

pub fn serve(listener: OwnedFd, targets: Targets, log: Arc<Log>) {
    std::thread::spawn(move || loop {
        let mut req: libc::seccomp_notif = unsafe { zeroed() };
        let r = unsafe { libc::ioctl(listener.as_raw_fd(), NOTIF_RECV as _, &mut req) };
        if r < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) | Some(libc::ENOENT) => continue,
                _ => return,
            }
        }
        let fd = listener.as_raw_fd();
        let resp = handle(fd, &req, &targets, &log);
        send(fd, req.id, resp);
    });
}

enum Resp {
    Error(i32),
    Continue,
    Connected,
}

fn send(listener: RawFd, id: u64, resp: Resp) {
    let mut r: libc::seccomp_notif_resp = unsafe { zeroed() };
    r.id = id;
    match resp {
        Resp::Error(e) => r.error = -e,
        Resp::Continue => r.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        Resp::Connected => {}
    }
    unsafe {
        libc::ioctl(listener, NOTIF_SEND as _, &r);
    }
}

fn handle(listener: RawFd, req: &libc::seccomp_notif, t: &Targets, log: &Log) -> Resp {
    if req.data.nr as i64 != libc::SYS_connect {
        return Resp::Error(libc::EACCES);
    }
    let pid = req.pid as libc::pid_t;
    let fd = req.data.args[0] as RawFd;
    let addr = read_sockaddr(pid, req.data.args[1], req.data.args[2] as usize);
    if !id_valid(listener, req.id) {
        return Resp::Error(libc::EACCES);
    }
    let Some(sock) = target_fd(pid, fd) else {
        return Resp::Error(libc::EBADF);
    };
    let domain = sockopt(&sock, libc::SO_DOMAIN);
    if domain == Some(libc::AF_NETLINK) || domain == Some(libc::AF_UNIX) {
        // Local only, and the socket's family can't be changed by the agent.
        return Resp::Continue;
    }
    if domain != Some(libc::AF_INET) && domain != Some(libc::AF_INET6) {
        return Resp::Error(libc::EACCES);
    }
    let Some(dest) = addr else {
        return Resp::Error(libc::EINVAL);
    };
    let local = is_loopback(dest.ip());
    if !(local && (dest.port() == t.proxy_port || t.local_ports.contains(&dest.port()))) {
        log.record("block-direct", &dest.to_string());
        return Resp::Error(libc::EACCES);
    }
    let dest = if dest.port() == t.proxy_port {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), t.proxy_port)
    } else {
        dest
    };
    let Ok(stream) = TcpStream::connect_timeout(&dest, Duration::from_secs(10)) else {
        return Resp::Error(libc::ECONNREFUSED);
    };
    let nonblock = unsafe { libc::fcntl(sock.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK;
    if nonblock != 0 {
        let _ = stream.set_nonblocking(true);
    }
    let new = OwnedFd::from(stream);
    let mut add: libc::seccomp_notif_addfd = unsafe { zeroed() };
    add.id = req.id;
    add.flags = libc::SECCOMP_ADDFD_FLAG_SETFD as u32;
    add.srcfd = new.as_raw_fd() as u32;
    add.newfd = fd as u32;
    add.newfd_flags = if cloexec(pid, fd) {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    let r = unsafe { libc::ioctl(listener, NOTIF_ADDFD as _, &add) };
    if r < 0 {
        return Resp::Error(libc::ECONNREFUSED);
    }
    Resp::Connected
}

fn id_valid(listener: RawFd, id: u64) -> bool {
    unsafe { libc::ioctl(listener, NOTIF_ID_VALID as _, &id) == 0 }
}

fn read_sockaddr(pid: libc::pid_t, ptr: u64, len: usize) -> Option<SocketAddr> {
    let mut buf = [0u8; 28];
    let len = len.min(buf.len());
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: ptr as *mut _,
        iov_len: len,
    };
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]) as i32;
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    match family {
        libc::AF_INET if n >= 8 => {
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 if n >= 24 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[8..24]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(b)), port))
        }
        _ => None,
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn target_fd(tid: libc::pid_t, fd: RawFd) -> Option<OwnedFd> {
    let tgid = std::fs::read_to_string(format!("/proc/{tid}/status"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))?
        .trim()
        .parse::<libc::pid_t>()
        .ok()?;
    unsafe {
        let pidfd = libc::syscall(libc::SYS_pidfd_open, tgid, 0);
        if pidfd < 0 {
            return None;
        }
        let pidfd = OwnedFd::from_raw_fd(pidfd as RawFd);
        let dup = libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0);
        if dup < 0 {
            return None;
        }
        Some(OwnedFd::from_raw_fd(dup as RawFd))
    }
}

fn sockopt(sock: &OwnedFd, opt: libc::c_int) -> Option<i32> {
    let mut val: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            &mut val as *mut _ as *mut _,
            &mut len,
        )
    };
    (r == 0).then_some(val)
}

fn cloexec(tid: libc::pid_t, fd: RawFd) -> bool {
    std::fs::read_to_string(format!("/proc/{tid}/fdinfo/{fd}"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("flags:"))
                .and_then(|f| i32::from_str_radix(f.trim(), 8).ok())
        })
        .is_some_and(|f| f & libc::O_CLOEXEC != 0)
}

/// Pass the seccomp listener from the sandboxed child to the supervisor.
pub fn send_fd(sock: RawFd, fd: OwnedFd) -> std::io::Result<()> {
    unsafe {
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: &mut byte as *mut _ as *mut _,
            iov_len: 1,
        };
        let space = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize;
        let mut cbuf = vec![0u8; space];
        let mut msg: libc::msghdr = zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut RawFd, fd.into_raw_fd());
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn recv_fd(sock: RawFd) -> Option<OwnedFd> {
    unsafe {
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: &mut byte as *mut _ as *mut _,
            iov_len: 1,
        };
        let space = libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize;
        let mut cbuf = vec![0u8; space];
        let mut msg: libc::msghdr = zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = space as _;
        if libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) <= 0 {
            return None;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return None;
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const RawFd);
        Some(OwnedFd::from_raw_fd(fd))
    }
}
