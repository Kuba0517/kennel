use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_HEADER: usize = 16 << 10;

pub struct Log {
    path: PathBuf,
    blocked: Mutex<BTreeMap<String, usize>>,
}

impl Log {
    pub fn record(&self, verdict: &str, target: &str) {
        if verdict != "allow" {
            *self
                .blocked
                .lock()
                .unwrap()
                .entry(target.to_string())
                .or_default() += 1;
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{verdict} {target}");
        }
    }

    pub fn blocked(&self) -> BTreeMap<String, usize> {
        self.blocked.lock().unwrap().clone()
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

struct Rules {
    domains: Vec<String>,
    ports: Vec<u16>,
}

impl Rules {
    fn allows(&self, host: &str, port: u16) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.ports.contains(&port)
            && self.domains.iter().any(|d| match d.strip_prefix("*.") {
                Some(base) => host.ends_with(&format!(".{base}")),
                None => host == *d,
            })
    }
}

/// Bound before the fork so the child knows the port; served after it.
pub fn bind() -> std::io::Result<TcpListener> {
    TcpListener::bind("127.0.0.1:0")
}

pub fn serve(
    listener: TcpListener,
    domains: &[String],
    ports: &[u16],
    log_path: PathBuf,
) -> Arc<Log> {
    let rules = Arc::new(Rules {
        domains: domains.iter().map(|d| d.to_ascii_lowercase()).collect(),
        ports: ports.to_vec(),
    });
    let log = Arc::new(Log {
        path: log_path,
        blocked: Mutex::new(BTreeMap::new()),
    });
    let log2 = log.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let rules = rules.clone();
            let log = log2.clone();
            std::thread::spawn(move || handle(conn, &rules, &log));
        }
    });
    log
}

fn handle(mut client: TcpStream, rules: &Rules, log: &Log) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let mut buf = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        match client.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEADER {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let (method, target, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v)) => (m, t, v),
        _ => return,
    };

    let (host, port, rewritten) = if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_host_port(target, 443) else {
            return;
        };
        (host, port, None)
    } else {
        // Plain HTTP: absolute URI, forwarded with an origin-form request line.
        let Some(rest) = target.strip_prefix("http://") else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
        };
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let path = if path.is_empty() { "/" } else { path };
        let Some((host, port)) = split_host_port(authority, 80) else {
            return;
        };
        let mut req = format!("{method} {path} {version}\r\n").into_bytes();
        let after_line = head.find("\r\n").map(|i| i + 2).unwrap_or(header_end);
        req.extend_from_slice(&buf[after_line..]);
        (host, port, Some(req))
    };

    let label = format!("{host}:{port}");
    if !rules.allows(&host, port) {
        log.record("block", &label);
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    let upstream = (host.as_str(), port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| {
            addrs.find_map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(10)).ok())
        });
    let Some(mut upstream) = upstream else {
        log.record("fail", &label);
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        return;
    };
    log.record("allow", &label);
    let _ = client.set_read_timeout(None);

    match rewritten {
        None => {
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .is_err()
            {
                return;
            }
            let _ = upstream.write_all(&buf[header_end..]);
        }
        Some(req) => {
            if upstream.write_all(&req).is_err() {
                return;
            }
        }
    }
    pipe(client, upstream);
}

fn split_host_port(s: &str, default: u16) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default,
        };
        return Some((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((s.to_string(), default)),
    }
}

fn pipe(a: TcpStream, b: TcpStream) {
    let (Ok(a2), Ok(b2)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    let t = std::thread::spawn(move || copy(a2, b2));
    copy(b, a);
    let _ = t.join();
}

fn copy(mut from: TcpStream, mut to: TcpStream) {
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}
