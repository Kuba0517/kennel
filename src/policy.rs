use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

const BUILTIN_PROFILES: &[(&str, &str)] = &[
    ("base", include_str!("../profiles/base.toml")),
    ("generic", include_str!("../profiles/generic.toml")),
    ("claude", include_str!("../profiles/claude.toml")),
    ("codex", include_str!("../profiles/codex.toml")),
];

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProfileFile {
    pub extends: Option<String>,
    #[serde(default)]
    pub fs: FsSection,
    #[serde(default)]
    pub net: NetSection,
    #[serde(default)]
    pub env: EnvSection,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FsSection {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub read_write: Vec<String>,
    pub cwd: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetSection {
    #[serde(default)]
    pub tcp_connect: Vec<u16>,
    #[serde(default)]
    pub tcp_bind: Vec<u16>,
    #[serde(default)]
    pub allow_all: bool,
    #[serde(default)]
    pub allow_unix: bool,
    pub mode: Option<NetMode>,
    #[serde(default)]
    pub allow_domains: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Default, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    /// HTTPS through kennel's proxy to allowed domains only
    #[default]
    Proxy,
    /// TCP to the allowed ports on any host
    Ports,
    /// No network
    None,
    /// No restriction
    Open,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnvSection {
    #[serde(default)]
    pub pass: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Policy {
    pub read: Vec<PathBuf>,
    pub read_write: Vec<PathBuf>,
    pub cwd_rw: bool,
    pub tcp_connect: Vec<u16>,
    pub tcp_bind: Vec<u16>,
    pub net_mode: NetMode,
    pub allow_domains: Vec<String>,
    pub allow_unix: bool,
    pub env_pass: Vec<String>,
    pub sources: Vec<String>,
}

pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn expand(raw: &str, home: &Path) -> PathBuf {
    if raw == "~" {
        home.to_path_buf()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(raw)
    }
}

fn user_profile_path(name: &str, home: &Path) -> PathBuf {
    home.join(".config/kennel/profiles")
        .join(format!("{name}.toml"))
}

fn load_profile_source(name: &str, home: &Path) -> Result<String> {
    let user = user_profile_path(name, home);
    if user.is_file() {
        return std::fs::read_to_string(&user)
            .with_context(|| format!("reading {}", user.display()));
    }
    if let Some((_, body)) = BUILTIN_PROFILES.iter().find(|(n, _)| *n == name) {
        return Ok((*body).to_string());
    }
    let as_path = Path::new(name);
    if as_path.is_file() {
        return std::fs::read_to_string(as_path)
            .with_context(|| format!("reading {}", as_path.display()));
    }
    bail!(
        "unknown profile '{name}' (no built-in with that name, and {} does not exist)",
        user.display()
    );
}

pub fn builtin_profile_names() -> Vec<&'static str> {
    BUILTIN_PROFILES.iter().map(|(n, _)| *n).collect()
}

fn merge_profile_chain(
    name: &str,
    home: &Path,
    policy: &mut Policy,
    seen: &mut HashSet<String>,
) -> Result<()> {
    if !seen.insert(name.to_string()) {
        bail!("profile inheritance cycle involving '{name}'");
    }
    let source = load_profile_source(name, home)?;
    let parsed: ProfileFile =
        toml::from_str(&source).with_context(|| format!("parsing profile '{name}'"))?;
    if let Some(parent) = &parsed.extends {
        merge_profile_chain(parent, home, policy, seen)?;
    }
    apply_profile(parsed, home, policy);
    policy.sources.push(name.to_string());
    Ok(())
}

fn apply_profile(profile: ProfileFile, home: &Path, policy: &mut Policy) {
    policy
        .read
        .extend(profile.fs.read.iter().map(|p| expand(p, home)));
    policy
        .read_write
        .extend(profile.fs.read_write.iter().map(|p| expand(p, home)));
    if let Some(cwd) = profile.fs.cwd {
        policy.cwd_rw = cwd;
    }
    policy.tcp_connect.extend(&profile.net.tcp_connect);
    policy.tcp_bind.extend(&profile.net.tcp_bind);
    if profile.net.allow_all {
        policy.net_mode = NetMode::Open;
    }
    if let Some(mode) = profile.net.mode {
        policy.net_mode = mode;
    }
    policy.allow_domains.extend(profile.net.allow_domains);
    if profile.net.allow_unix {
        policy.allow_unix = true;
    }
    policy.env_pass.extend(profile.env.pass);
}

/// `NAME` matches exactly, `PREFIX*` matches by prefix.
pub fn env_allowed(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == p,
    })
}

pub fn resolve(profile_name: &str, trust_project: bool) -> Result<Policy> {
    let home = home_dir()?;
    let mut policy = Policy {
        cwd_rw: true,
        ..Policy::default()
    };
    let mut seen = HashSet::new();
    merge_profile_chain(profile_name, &home, &mut policy, &mut seen)?;

    let project_file = Path::new(".kennel.toml");
    if project_file.is_file() {
        let source = std::fs::read_to_string(project_file).context("reading .kennel.toml")?;
        check_trusted(&source, &home, trust_project)?;
        let parsed: ProfileFile = toml::from_str(&source).context("parsing .kennel.toml")?;
        if parsed.extends.is_some() {
            bail!(".kennel.toml must not use 'extends'; it is always merged on top");
        }
        apply_profile(parsed, &home, &mut policy);
        policy.sources.push(".kennel.toml".to_string());
    }

    Ok(policy)
}

// A repo can loosen its own sandbox through .kennel.toml, so the exact contents
// must be approved once. The approved copy lives outside the sandbox's reach.
fn check_trusted(source: &str, home: &Path, trust: bool) -> Result<()> {
    let cwd = std::env::current_dir().context("reading current directory")?;
    let stored = home
        .join(".config/kennel/trusted")
        .join(format!("{}.toml", path_id(&cwd)));
    if std::fs::read_to_string(&stored).is_ok_and(|s| s == source) {
        return Ok(());
    }
    if trust {
        std::fs::create_dir_all(stored.parent().unwrap())?;
        std::fs::write(&stored, source).with_context(|| format!("writing {}", stored.display()))?;
        return Ok(());
    }
    bail!(
        "{} has a .kennel.toml that is new or changed since you approved it:\n\n{source}\n\
         Review it, then run again with --trust.",
        cwd.display()
    );
}

pub fn path_id(path: &Path) -> String {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
