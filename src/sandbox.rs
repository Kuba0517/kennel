use crate::policy::Policy;
use anyhow::{bail, Context, Result};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::Path;

const LATEST_ABI: ABI = ABI::V5;

pub struct EnforcementReport {
    pub fully_enforced: bool,
    pub skipped_paths: Vec<String>,
}

pub fn enforce(policy: &Policy, verbose: bool) -> Result<EnforcementReport> {
    let abi = LATEST_ABI;
    let mut skipped = Vec::new();

    let handled_fs = AccessFs::from_all(abi);
    let mut ruleset = Ruleset::default();
    let ruleset_ref = &mut ruleset;
    ruleset_ref
        .handle_access(handled_fs)
        .context("handling filesystem access")?;

    let restrict_net = !policy.net_allow_all;
    if restrict_net {
        ruleset_ref
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .context("handling network access")?;
    }

    let mut created = ruleset.create().context("creating Landlock ruleset")?;

    let read_access = AccessFs::from_read(abi);
    let write_access = AccessFs::from_all(abi);

    for (paths, access, label) in [
        (&policy.read, read_access, "read"),
        (&policy.read_write, write_access, "read_write"),
    ] {
        for path in paths.iter() {
            match add_path_rule(&mut created, path, access) {
                Ok(()) => {
                    if verbose {
                        eprintln!("kennel: allow {label:10} {}", path.display());
                    }
                }
                Err(err) => {
                    skipped.push(format!("{} ({err})", path.display()));
                }
            }
        }
    }

    if restrict_net {
        for port in &policy.tcp_connect {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                .with_context(|| format!("allowing TCP connect to port {port}"))?;
        }
        for port in &policy.tcp_bind {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::BindTcp))
                .with_context(|| format!("allowing TCP bind on port {port}"))?;
        }
    }

    let status = created
        .restrict_self()
        .context("applying Landlock restrictions to this process")?;

    match status.ruleset {
        RulesetStatus::NotEnforced => {
            bail!(
                "Landlock is not supported by this kernel (need Linux 5.13+ with \
                 Landlock enabled); refusing to run unsandboxed"
            )
        }
        RulesetStatus::PartiallyEnforced => Ok(EnforcementReport {
            fully_enforced: false,
            skipped_paths: skipped,
        }),
        RulesetStatus::FullyEnforced => Ok(EnforcementReport {
            fully_enforced: true,
            skipped_paths: skipped,
        }),
    }
}

fn add_path_rule(
    created: &mut landlock::RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<()> {
    let fd = PathFd::new(path)?;
    // Directory-only rights on a file give EINVAL.
    let file_access = if path.is_dir() {
        access
    } else {
        access & AccessFs::from_file(LATEST_ABI)
    };
    created.add_rule(PathBeneath::new(fd, file_access))?;
    Ok(())
}
