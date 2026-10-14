mod policy;
mod sandbox;

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
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

    /// Extra allowed TCP connect ports (repeatable).
    #[arg(long = "allow-port", value_name = "PORT")]
    allow_ports: Vec<u16>,

    /// Block all TCP connections, overriding the profile.
    #[arg(long)]
    no_network: bool,

    /// Do not grant read-write on the current directory.
    #[arg(long)]
    no_cwd: bool,

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

    let mut pol = policy::resolve(&profile_name)?;

    pol.read.extend(args.read_only.iter().cloned());
    pol.read_write.extend(args.read_write.iter().cloned());
    pol.tcp_connect.extend(&args.allow_ports);
    if args.no_network {
        pol.net_allow_all = false;
        pol.tcp_connect.clear();
        pol.tcp_bind.clear();
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

    if args.dry_run {
        print_policy(&pol, &profile_name);
        return Ok(());
    }

    let report = sandbox::enforce(&pol, args.verbose)?;
    if !report.fully_enforced {
        eprintln!(
            "kennel: warning: kernel supports only part of the policy \
             (older Landlock ABI); enforcement is partial"
        );
    }
    if args.verbose {
        for skipped in &report.skipped_paths {
            eprintln!("kennel: skipped missing path: {skipped}");
        }
    }

    close_inherited_fds();
    let err = Command::new(program).args(&args.command[1..]).exec();
    Err(err).with_context(|| format!("failed to exec '{program}'"))
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
    if pol.net_allow_all {
        println!("  unrestricted");
    } else {
        println!("  tcp connect: {:?}", pol.tcp_connect);
        println!("  tcp bind:    {:?}", pol.tcp_bind);
        println!("  (all other TCP denied; UDP/ICMP not restricted by Landlock)");
    }
    println!("\neverything not listed above is denied by the kernel.");
}
