# kennel

kennel runs a coding agent (Claude Code, Codex, anything else) inside a Landlock sandbox on Linux. It needs no root and no containers.

```bash
kennel claude
```

## Why

A coding agent runs as your user, so it can read everything you can read. That includes `~/.ssh`, `~/.aws/credentials` and your other repos. If the agent picks up a prompt injection from a README or a web page, it can send those files anywhere.

The agent's own permission prompts don't help much here. They run inside the same process you are trying to limit.

Landlock is a Linux kernel feature that lets an unprivileged process restrict its own file and network access. kennel builds a Landlock ruleset from a profile, applies it to itself, and then execs the agent. After that the kernel returns `EACCES` for any path that isn't on the allow-list. TCP is limited to the allowed ports (443 and 80 by default). The rules carry over to every child process, so shells and build tools the agent starts are restricted too, and a process can't remove them.

Before the exec, kennel also:

- drops every environment variable that isn't on the profile's list, so tokens in your shell don't reach the agent
- closes inherited file descriptors
- blocks signals and abstract unix sockets to processes outside the sandbox
- points `TMPDIR` at a private directory per project and denies `/tmp`
- blocks creating unix sockets with a seccomp filter, so the agent can't reach the ssh-agent, the D-Bus session bus or `/var/run/docker.sock`. `socketpair()` still works. Pass `--allow-unix` (or set `allow_unix = true` under `[net]`) for agents that need local sockets.

With that in place I run agents in full-auto mode:

```bash
kennel claude --dangerously-skip-permissions
```

## Install

```bash
cargo install --path .
```

You need Linux 5.13+ with Landlock enabled. TCP rules need 6.7+. Check with `grep landlock /sys/kernel/security/lsm`.

## Usage

```bash
kennel claude                      # profile picked from the command name
kennel codex
kennel -- some-other-agent --flag  # unknown command, uses the 'generic' profile

kennel --dry-run claude            # print the policy and exit
kennel -v claude                   # log every granted path

kennel --ro ~/datasets --rw ~/scratch claude   # extra paths
kennel --no-network -- python untrusted.py     # no TCP at all
kennel --allow-port 5432 claude                # let the agent reach local postgres
kennel --env GITHUB_TOKEN claude               # pass an extra environment variable
```

Run it from the project directory. kennel gives read-write access to the current directory. If the current directory is `$HOME` it refuses to start.

## Profiles

A profile is a TOML allow-list. The built-in ones are `base`, `generic`, `claude` and `codex`.

```toml
# ~/.config/kennel/profiles/myagent.toml
extends = "base"

[fs]
read = ["~/.myagent/config"]
read_write = ["~/.myagent/state"]

[net]
tcp_connect = [443]

[env]
pass = ["MYAGENT_*"]
```

A file in `~/.config/kennel/profiles/<name>.toml` overrides the built-in profile with the same name. A `.kennel.toml` in the project directory is merged on top, so a repo can add the paths it needs. Since that file can loosen the sandbox, kennel refuses to start until you approve it with `kennel --trust`, and again whenever it changes. The approved copy is kept in `~/.config/kennel/trusted/`, which the agent can't write. Paths that don't exist on the machine are skipped, because the built-in profiles list several install locations.

## Threat model

kennel stops an agent from reading or writing outside the allowed paths and from opening TCP connections on other ports. This applies to its child processes too.

It does not stop:

- exfiltration over an allowed port. If a secret is inside the project directory and 443 is open, the agent can still send it out.
- UDP and DNS. Landlock doesn't restrict UDP.
- anything over unix sockets when you pass `--allow-unix`. The D-Bus session bus then lets the agent run commands outside the sandbox with `systemd-run --user`, and if you are in the `docker` group the agent effectively has root.
- writes to `.git/hooks` and `.git/config` in the project. A hook the agent plants runs outside kennel the next time you commit.

Kernel exploits are out of scope, and so is code you later run outside kennel.

If the workload is hostile on purpose, use a VM.

## How it works

It's about 600 lines of Rust. `policy.rs` resolves the profile chain and the optional `.kennel.toml`. `sandbox.rs` opens each allowed path, builds the Landlock ruleset and calls `restrict_self()`. `seccomp.rs` installs the unix socket filter. `main.rs` then calls `exec` on the agent. There is no daemon, proxy or `LD_PRELOAD`.

`tests/smoke.sh` checks the enforcement end to end. Build first with `cargo build`.

## License

MIT OR Apache-2.0
