# kennel

kennel runs a coding agent (Claude Code, Codex, anything else) inside a Landlock sandbox on Linux. It needs no root and no containers.

```bash
kennel claude
```

## Why

A coding agent runs as your user, so it can read everything you can read. That includes `~/.ssh`, `~/.aws/credentials` and your other repos. If the agent picks up a prompt injection from a README or a web page, it can send those files anywhere.

The agent's own permission prompts don't help much here. They run inside the same process you are trying to limit.

Landlock is a Linux kernel feature that lets an unprivileged process restrict its own file and network access. kennel forks, builds a Landlock ruleset from a profile in the child, and execs the agent there. After that the kernel returns `EACCES` for any path that isn't on the allow-list. The rules carry over to every child process, so shells and build tools the agent starts are restricted too, and a process can't remove them.

The agent only reaches the network through a proxy that kennel runs outside the sandbox. The proxy connects to the domains in the profile and nothing else. A seccomp filter sends every `connect()` to kennel, which only lets it reach the proxy, and the agent can't create UDP sockets, so DNS doesn't work either.

kennel also:

- drops every environment variable that isn't on the profile's list, so tokens in your shell don't reach the agent
- closes inherited file descriptors
- blocks signals and abstract unix sockets to processes outside the sandbox
- points `TMPDIR` at a private directory per project and denies `/tmp`
- blocks creating unix sockets with a seccomp filter, so the agent can't reach the ssh-agent, the D-Bus session bus or `/var/run/docker.sock`. `socketpair()` still works. Pass `--allow-unix` (or set `allow_unix = true` under `[net]`) for agents that need local sockets.
- checks `.git/hooks` and `.git/config` when the agent exits. A new or changed hook, or a config key that runs a program or changes where you push (`core.hooksPath`, `core.fsmonitor`, `alias.*`, `remote.*.url` and similar), is undone and the agent's version is moved to `~/.cache/kennel/rejected/`.

With that in place I run agents in full-auto mode:

```bash
kennel claude --dangerously-skip-permissions
```

## Install

```bash
cargo install --path .
```

You need Linux 6.12+ with Landlock enabled. Check with `grep landlock /sys/kernel/security/lsm`. Older kernels get partial enforcement and a warning.

## Usage

```bash
kennel claude                      # profile picked from the command name
kennel codex
kennel -- some-other-agent --flag  # unknown command, uses the 'generic' profile

kennel --dry-run claude            # print the policy and exit
kennel -v claude                   # log every granted path

kennel --ro ~/datasets --rw ~/scratch claude   # extra paths
kennel --allow-domain pypi.org claude          # let the proxy reach another domain
kennel --allow-port 5432 claude                # let the agent reach local postgres
kennel --allow-bind 3000 claude                # let the agent run a dev server on 3000
kennel --no-network -- python untrusted.py     # no network at all
kennel --net ports claude                      # old mode: ports 443 and 80 on any host
kennel --env GITHUB_TOKEN claude               # pass an extra environment variable
```

When the agent exits, kennel lists the connections it blocked. If something you need was blocked, add the domain. The full log is in `~/.cache/kennel/log/`.

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
mode = "proxy"                  # proxy | ports | none | open
allow_domains = ["api.myagent.dev", "*.myagent.dev"]
tcp_connect = [443]

[env]
pass = ["MYAGENT_*"]
```

A file in `~/.config/kennel/profiles/<name>.toml` overrides the built-in profile with the same name. A `.kennel.toml` in the project directory is merged on top, so a repo can add the paths it needs. Since that file can loosen the sandbox, kennel refuses to start until you approve it with `kennel --trust`, and again whenever it changes. The approved copy is kept in `~/.config/kennel/trusted/`, which the agent can't write. Paths that don't exist on the machine are skipped, because the built-in profiles list several install locations.

## Threat model

kennel stops an agent from reading or writing outside the allowed paths and from reaching any host that isn't on the domain list. This applies to its child processes too.

It does not stop:

- exfiltration to an allowed domain. If the agent can push to GitHub, it can push a secret from the project to a repo it controls. Keep the domain list short.
- anything over unix sockets when you pass `--allow-unix`. The D-Bus session bus then lets the agent run commands outside the sandbox with `systemd-run --user`, and if you are in the `docker` group the agent effectively has root.
- files in the project that run later, like `Makefile`, `package.json` scripts or `.envrc`. Read the diff before you run them. Git hooks are handled because they don't show up in `git status`.
- a git hook you run yourself while the agent is still working. The check happens when the agent exits.
- `--net ports` mode allows 443 and 80 on every host, plus UDP and DNS.

Kernel exploits are out of scope, and so is code you later run outside kennel.

If the workload is hostile on purpose, use a VM.

## How it works

It's about 1700 lines of Rust and no dependencies beyond `landlock`, `libc`, `clap` and `toml`.

- `policy.rs` resolves the profile chain and the optional `.kennel.toml`.
- `sandbox.rs` builds the Landlock ruleset and calls `restrict_self()` in the child.
- `seccomp.rs` builds the seccomp filter: no unix sockets, only TCP sockets, and `connect()` goes to the supervisor through seccomp user notification.
- `notify.rs` is the supervisor's side. For each `connect()` it reads the address, and if it's the proxy or an allowed local port it makes the connection itself and puts the socket into the agent's fd table with `SECCOMP_IOCTL_NOTIF_ADDFD`. The agent's own call never runs, so changing the address after the check gets it nothing.
- `proxy.rs` is the HTTP CONNECT proxy with the domain allowlist.
- `gitguard.rs` snapshots and restores git hooks and config.

The cost is about 4 ms at startup and about 80 µs per new connection. File and CPU work run at native speed apart from the seccomp entry cost, which is a few percent at most.

`tests/smoke.sh` checks the enforcement end to end. Build first with `cargo build`.

## License

MIT OR Apache-2.0
