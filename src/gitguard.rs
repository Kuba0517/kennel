use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// The project is writable, and Landlock can't carve .git/hooks out of a
// writable tree. A hook or a config key the agent plants would run outside
// the sandbox the next time you use git, so kennel checks them on exit.

const MAX_HOOK_SIZE: u64 = 16 << 20;

// Config keys that run a program or send your code somewhere else.
const DANGEROUS_KEYS: &[&str] = &[
    "core.hookspath",
    "core.fsmonitor",
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "core.askpass",
    "core.gitproxy",
    "core.worktree",
    "core.alternaterefscommand",
    "sequence.editor",
    "diff.external",
    "interactive.difffilter",
    "web.browser",
    "gpg.program",
    "gpg.*.program",
    "credential.helper",
    "credential.*.helper",
    "include.path",
    "includeif.*.path",
    "alias.*",
    "pager.*",
    "filter.*",
    "diff.*.command",
    "diff.*.textconv",
    "merge.*.driver",
    "difftool.*.cmd",
    "mergetool.*.cmd",
    "man.*.cmd",
    "browser.*.cmd",
    "uploadpack.packobjectshook",
    "remote.*.url",
    "remote.*.pushurl",
    "remote.*.uploadpack",
    "remote.*.receivepack",
    "url.*.insteadof",
    "url.*.pushinsteadof",
    "protocol.*.allow",
];

#[derive(PartialEq)]
enum Entry {
    File(Vec<u8>, u32),
    Other,
}

pub struct Snapshot {
    dot_git: PathBuf,
    was_dir: bool,
    hooks_dir: PathBuf,
    hooks: Option<BTreeMap<String, Entry>>,
    configs: Vec<(PathBuf, Option<Vec<u8>>)>,
}

pub fn snapshot(cwd: &Path) -> Option<Snapshot> {
    let dot_git = cwd.join(".git");
    let meta = std::fs::symlink_metadata(&dot_git).ok()?;
    let (git_dir, common_dir) = if meta.is_dir() {
        (dot_git.clone(), dot_git.clone())
    } else {
        // Worktree: ".git" is a file pointing at the real git dir.
        let text = std::fs::read_to_string(&dot_git).ok()?;
        let git_dir = cwd.join(text.strip_prefix("gitdir:")?.trim());
        let common = match std::fs::read_to_string(git_dir.join("commondir")) {
            Ok(c) => git_dir.join(c.trim()),
            Err(_) => git_dir.clone(),
        };
        (git_dir, common)
    };
    let hooks_dir = common_dir.join("hooks");
    let configs = [common_dir.join("config"), git_dir.join("config.worktree")]
        .into_iter()
        .map(|p| {
            let data = std::fs::read(&p).ok();
            (p, data)
        })
        .collect();
    Some(Snapshot {
        dot_git,
        was_dir: meta.is_dir(),
        hooks: read_hooks(&hooks_dir),
        hooks_dir,
        configs,
    })
}

fn read_hooks(dir: &Path) -> Option<BTreeMap<String, Entry>> {
    if !std::fs::symlink_metadata(dir).ok()?.is_dir() {
        return None;
    }
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = entry.path().symlink_metadata() else {
            continue;
        };
        let item = if meta.is_file() && meta.len() <= MAX_HOOK_SIZE {
            match std::fs::read(entry.path()) {
                Ok(data) => Entry::File(data, meta.permissions().mode()),
                Err(_) => Entry::Other,
            }
        } else {
            Entry::Other
        };
        out.insert(name, item);
    }
    Some(out)
}

/// Undo hook and dangerous config changes. Returns what was changed.
pub fn check_and_restore(snap: &Snapshot, quarantine: &Path) -> Vec<String> {
    let mut changes = Vec::new();

    let is_dir = std::fs::symlink_metadata(&snap.dot_git).is_ok_and(|m| m.is_dir());
    if is_dir != snap.was_dir {
        changes.push(format!(
            "{} was replaced; check it before running git here",
            snap.dot_git.display()
        ));
        return changes;
    }

    let now = read_hooks(&snap.hooks_dir);
    if now.is_none() && std::fs::symlink_metadata(&snap.hooks_dir).is_ok() {
        // hooks became a symlink or a file
        if move_to(&snap.hooks_dir, quarantine, "hooks").is_ok() {
            changes.push("hooks directory replaced".into());
        }
    }
    if let Some(before) = &snap.hooks {
        let now = read_hooks(&snap.hooks_dir).unwrap_or_default();
        let _ = std::fs::create_dir_all(&snap.hooks_dir);
        for (name, entry) in &now {
            if before.get(name) != Some(entry) {
                let path = snap.hooks_dir.join(name);
                if move_to(&path, quarantine, &format!("hooks/{name}")).is_ok() {
                    changes.push(format!("hook {name} added or changed"));
                }
            }
        }
        for (name, entry) in before {
            if now.get(name) != Some(entry) {
                if let Entry::File(data, mode) = entry {
                    let path = snap.hooks_dir.join(name);
                    let _ = std::fs::write(&path, data);
                    let _ = std::fs::set_permissions(&path, PermissionsExt::from_mode(*mode));
                }
            }
        }
    } else if let Some(now) = read_hooks(&snap.hooks_dir) {
        for name in now.keys() {
            let path = snap.hooks_dir.join(name);
            if move_to(&path, quarantine, &format!("hooks/{name}")).is_ok() {
                changes.push(format!("hook {name} added"));
            }
        }
    }

    for (path, before) in &snap.configs {
        let after = std::fs::read(path).ok();
        if &after == before {
            continue;
        }
        let keys = dangerous_changes(path, before.as_deref());
        if keys.is_empty() {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let _ = move_to(path, quarantine, &name);
        if let Some(data) = before {
            let _ = std::fs::write(path, data);
        }
        changes.push(format!("{name} restored (agent set {})", keys.join(", ")));
    }
    changes
}

fn dangerous_changes(path: &Path, before: Option<&[u8]>) -> Vec<String> {
    let after = match config_entries_file(path) {
        Some(e) => e,
        // git couldn't parse it; treat any change as dangerous
        None => return vec!["unparseable config".into()],
    };
    let before = match before {
        Some(data) => config_entries_bytes(data).unwrap_or_default(),
        None => Vec::new(),
    };
    let mut keys: Vec<String> = after
        .iter()
        .filter(|e| !before.contains(e))
        .map(|(k, _)| k.clone())
        .filter(|k| DANGEROUS_KEYS.iter().any(|p| glob(p, k)))
        .collect();
    keys.dedup();
    keys
}

fn config_entries_bytes(data: &[u8]) -> Option<Vec<(String, String)>> {
    let tmp = std::env::temp_dir().join(format!("kennel-config-{}", std::process::id()));
    std::fs::write(&tmp, data).ok()?;
    let out = config_entries_file(&tmp);
    let _ = std::fs::remove_file(&tmp);
    out
}

fn config_entries_file(path: &Path) -> Option<Vec<(String, String)>> {
    // --file without --includes doesn't follow include.path.
    let out = Command::new("git")
        .args(["config", "--null", "--list", "--file"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        out.stdout
            .split(|b| *b == 0)
            .filter(|e| !e.is_empty())
            .map(|e| {
                let e = String::from_utf8_lossy(e);
                let (k, v) = e.split_once('\n').unwrap_or((&e, ""));
                (k.to_lowercase(), v.to_string())
            })
            .collect(),
    )
}

fn glob(pattern: &str, s: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == s,
        Some((pre, post)) => {
            s.len() >= pre.len() + post.len() && s.starts_with(pre) && s.ends_with(post)
        }
    }
}

fn move_to(path: &Path, quarantine: &Path, name: &str) -> std::io::Result<()> {
    let dest = quarantine.join(name);
    std::fs::create_dir_all(dest.parent().unwrap())?;
    std::fs::rename(path, &dest).or_else(|_| {
        std::fs::copy(path, &dest)?;
        std::fs::remove_file(path)
    })
}
