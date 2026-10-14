mod gitguard;
mod notify;
mod policy;
mod proxy;
mod sandbox;
mod seccomp;
mod supervisor;

use anyhow::{bail, Context, Result};
use clap::Parser;
use policy::NetMode;
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Landlock sandbox for AI coding agents.
#[derive(Parser, Debug)]
#[command(version, about, trailing_var_arg = true)]
struct Args {
    /// Profile name (built-in or ~/.config/kennel/profiles/<name>.toml).
    /// Defaults to the command's basename if a profile with that name
    /// exists, otherwise 'generic'.
    #[arg(short, long)]
    profile: Option<String>,

    /// Extra read-only paths (repeatable).
    #[arg(long = "ro", value_name = "PATH")]
    read_only: Vec<PathBuf>,

    /// Extra read-write paths (repeatable).
    #[arg(long = "rw", value_name = "PATH")]
    read_write: Vec<PathBuf>,

    /// Network mode, overriding the profile.
    #[arg(long, value_enum, value_name = "MODE")]
    net: Option<NetMode>,

    /// Extra domain the proxy may connect to (repeatable, `*.example.com` allowed).
    #[arg(long = "allow-domain", value_name = "DOMAIN")]
    allow_domains: Vec<String>,

    /// Extra allowed TCP port (repeatable). In proxy mode this allows direct
    /// connections to that port on localhost.
    #[arg(long = "allow-port", value_name = "PORT")]
    allow_ports: Vec<u16>,

    /// Port the agent may listen on, e.g. for a dev server (repeatable).
    /// It may also connect to it on localhost.
    #[arg(long = "allow-bind", value_name = "PORT")]
    allow_binds: Vec<u16>,

    /// Extra environment variables to pass through (repeatable, `PREFIX*` allowed).
    #[arg(long = "env", value_name = "NAME")]
    env: Vec<String>,

    /// Allow unix sockets (ssh-agent, D-Bus, docker.sock). Only for trusted agents.
    #[arg(long)]
    allow_unix: bool,

    /// Block tools you connected to the agent, like claude.ai connectors.
    /// Use it with --dangerously-skip-permissions.
    #[arg(long)]
    strict: bool,

    /// Same as --net none.
    #[arg(long)]
    no_network: bool,

    /// Do not grant read-write on the current directory.
    #[arg(long)]
    no_cwd: bool,

    /// Approve the current .kennel.toml in this project.
    #[arg(long)]
    trust: bool,

    /// Print the effective policy and exit without running anything.
    #[arg(long)]
    dry_run: bool,

    /// List available profiles and exit.
    #[arg(long)]
    list_profiles: bool,

    /// Print each granted path while setting up.
    #[arg(short, long)]
    verbose: bool,

    /// The agent command to run, with its arguments.
    #[arg(value_name = "COMMAND")]
    command: Vec<String>,
}

fn main() -> Result<()> {
    // Exit quietly on a closed pipe, e.g. `kennel --dry-run | head`.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let args = Args::parse();

    if args.list_profiles {
        for name in policy::builtin_profile_names() {
            println!("{name}");
        }
        return Ok(());
    }

    if args.command.is_empty() {
        bail!("no command given; usage: kennel [OPTIONS] -- <command> [args...]");
    }

    let program = &args.command[0];
    let profile_name = match &args.profile {
        Some(name) => name.clone(),
        None => {
            let base = PathBuf::from(program)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if policy::builtin_profile_names().contains(&base.as_str()) {
                base
            } else {
                "generic".to_string()
            }
        }
    };

    let mut pol = policy::resolve(&profile_name, args.trust)?;

    pol.read.extend(args.read_only.iter().cloned());
    pol.read_write.extend(args.read_write.iter().cloned());
    pol.tcp_connect.extend(&args.allow_ports);
    pol.tcp_bind.extend(&args.allow_binds);
    pol.allow_domains.extend(args.allow_domains.iter().cloned());
    pol.env_pass.extend(args.env.iter().cloned());
    if let Some(mode) = args.net {
        pol.net_mode = mode;
    }
    if args.strict {
        pol.strict = true;
    }
    if !pol.strict {
        let connectors = pol.connector_domains.clone();
        pol.allow_domains.extend(connectors);
    }
    if args.no_network {
        pol.net_mode = NetMode::None;
    }
    if pol.net_mode == NetMode::None {
        pol.tcp_connect.clear();
        pol.tcp_bind.clear();
    }
    if args.allow_unix {
        pol.allow_unix = true;
    }
    if args.no_cwd {
        pol.cwd_rw = false;
    }

    let cwd = std::env::current_dir().context("reading current directory")?;
    let home = policy::home_dir()?;
    if pol.cwd_rw {
        if cwd == home {
            bail!(
                "current directory is your home directory; granting read-write here \
                 would expose everything (~/.ssh, keys, browser data).\n\
                 cd into a project directory, or pass --no-cwd."
            );
        }
        pol.read_write.push(cwd.clone());
    }

    let tmp = private_tmp(&home, &cwd)?;
    pol.read_write.push(tmp.clone());

    if args.dry_run {
        print_policy(&pol, &profile_name);
        return Ok(());
    }

    let git = gitguard::snapshot(&cwd);
    let proxy = match pol.net_mode {
        NetMode::Proxy => Some(proxy::bind().context("starting proxy")?),
        _ => None,
    };
    let proxy_port = proxy.as_ref().map(|l| l.local_addr().unwrap().port());
    let (parent_sock, child_sock) = UnixStream::pair().context("creating socketpair")?;

    let pid = supervisor::fork()?;
    if pid == 0 {
        drop(parent_sock);
        let err = run_agent(&args, &pol, &tmp, proxy_port, &child_sock);
        eprintln!("kennel: {err:#}");
        unsafe { libc::_exit(126) };
    }
    drop(child_sock);

    let log = proxy.map(|listener| {
        let dir = home.join(".cache/kennel/log");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("{}.log", policy::path_id(&cwd)));
        let log = proxy::serve(listener, &pol.allow_domains, &pol.tcp_connect, path);
        if let Some(fd) = notify::recv_fd(parent_sock.as_raw_fd()) {
            let mut local_ports = pol.tcp_connect.clone();
            local_ports.extend(&pol.tcp_bind);
            let targets = notify::Targets {
                proxy_port: proxy_port.unwrap(),
                local_ports,
            };
            notify::serve(fd, targets, log.clone());
        }
        log
    });

    let code = supervisor::wait(pid)?;
    if let Some(log) = log {
        let blocked = log.blocked();
        if !blocked.is_empty() {
            eprintln!("kennel: blocked network connections:");
            for (target, n) in &blocked {
                eprintln!("  {target} ({n}x)");
            }
            eprintln!(
                "kennel: to allow a domain, use --allow-domain once, allow_domains in \
                 .kennel.toml for this project, or in ~/.config/kennel/profiles/{profile_name}.toml \
                 for every project. Log: {}",
                log.path().display()
            );
        }
    }
    if let Some(git) = git {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let quarantine = home
            .join(".cache/kennel/rejected")
            .join(policy::path_id(&cwd))
            .join(stamp.to_string());
        let changes = gitguard::check_and_restore(&git, &quarantine);
        if !changes.is_empty() {
            eprintln!("kennel: undid git changes that would run outside the sandbox:");
            for c in &changes {
                eprintln!("  {c}");
            }
            eprintln!(
                "kennel: the agent's versions are in {}",
                quarantine.display()
            );
        }
    }
    std::process::exit(code);
}

fn run_agent(
    args: &Args,
    pol: &policy::Policy,
    tmp: &Path,
    proxy_port: Option<u16>,
    sock: &UnixStream,
) -> anyhow::Error {
    let report = match sandbox::enforce(pol, args.verbose) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if !report.fully_enforced {
        eprintln!(
            "kennel: warning: kernel supports only part of the policy \
             (older Landlock ABI); enforcement is partial"
        );
    }
    if !pol.allow_unix || proxy_port.is_some() {
        match seccomp::install(!pol.allow_unix, proxy_port.is_some()) {
            Ok(Some(listener)) => {
                if let Err(e) = notify::send_fd(sock.as_raw_fd(), listener) {
                    return anyhow::Error::new(e).context("passing seccomp listener");
                }
            }
            Ok(None) => {}
            Err(e) => return e,
        }
    }
    if args.verbose {
        for skipped in &report.skipped_paths {
            eprintln!("kennel: skipped missing path: {skipped}");
        }
    }

    close_inherited_fds();
    let program = &args.command[0];
    let env = std::env::vars_os().filter(|(k, _)| {
        k.to_str()
            .is_some_and(|k| policy::env_allowed(k, &pol.env_pass))
    });
    let mut cmd = Command::new(program);
    cmd.args(&args.command[1..])
        .env_clear()
        .envs(env)
        .env("TMPDIR", tmp);
    if let Some(port) = proxy_port {
        let url = format!("http://127.0.0.1:{port}");
        for var in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
            cmd.env(var, &url);
        }
        for var in ["NO_PROXY", "no_proxy"] {
            cmd.env(var, "localhost,127.0.0.1,::1");
        }
        cmd.env("NODE_USE_ENV_PROXY", "1");
    }
    let err = cmd.exec();
    anyhow::Error::new(err).context(format!("failed to exec '{program}'"))
}

// /tmp is shared with everything else on the machine, so each project gets its own.
fn private_tmp(home: &Path, cwd: &Path) -> Result<PathBuf> {
    let dir = home.join(".cache/kennel/tmp").join(policy::path_id(cwd));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

// Open fds survive exec and Landlock only checks access at open time, so a
// descriptor the parent leaked would bypass the policy.
fn close_inherited_fds() {
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3 as libc::c_uint,
            libc::c_uint::MAX,
            CLOSE_RANGE_CLOEXEC,
        );
    }
}

fn print_policy(pol: &policy::Policy, profile_name: &str) {
    println!(
        "profile chain: {} (requested: {profile_name})",
        pol.sources.join(" -> ")
    );
    println!("\nread-only:");
    for p in &pol.read {
        println!("  {}", p.display());
    }
    println!("\nread-write:");
    for p in &pol.read_write {
        println!("  {}", p.display());
    }
    println!("\nnetwork:");
    match pol.net_mode {
        NetMode::Open => println!("  unrestricted"),
        NetMode::None => println!("  none"),
        NetMode::Ports => {
            println!("  tcp connect: {:?} on any host", pol.tcp_connect);
            println!("  tcp bind:    {:?}", pol.tcp_bind);
            println!("  (UDP and DNS not restricted)");
        }
        NetMode::Proxy => {
            println!(
                "  through kennel's proxy to ports {:?} on:",
                pol.tcp_connect
            );
            for d in &pol.allow_domains {
                println!("    {d}");
            }
            if pol.strict && !pol.connector_domains.is_empty() {
                println!("  strict: blocking {}", pol.connector_domains.join(" "));
            }
            println!("  tcp bind:    {:?}", pol.tcp_bind);
            println!("  no UDP, no DNS, no direct connections except localhost on allowed ports");
        }
    }
    if pol.allow_unix {
        println!("  unix sockets: allowed");
    } else {
        println!("  unix sockets: denied (socketpair allowed)");
    }
    println!("\nenvironment passed through:");
    println!("  {}", pol.env_pass.join(" "));
    println!("\neverything not listed above is denied by the kernel.");
}
