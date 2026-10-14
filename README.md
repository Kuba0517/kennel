# kennel

kennel runs a coding agent (Claude Code, Codex, anything else) inside a Landlock sandbox on Linux. It needs no root and no containers.

```bash
kennel claude
```

## Why

A coding agent runs as your user, so it can read everything you can read. That includes `~/.ssh`, `~/.aws/credentials` and your other repos. If the agent picks up a prompt injection from a README or a web page, it can send those files anywhere.

The agent's own permission prompts don't help much here. They run inside the same process you are trying to limit.

Landlock is a Linux kernel feature that lets an unprivileged process restrict its own file and network access. kennel builds a Landlock ruleset from a profile, applies it to itself, and then execs the agent. After that the kernel returns `EACCES` for any path that isn't on the allow-list. TCP is limited to the allowed ports (443 and 80 by default). The rules carry over to every child process, so shells and build tools the agent starts are restricted too, and a process can't remove them.

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
```

A file in `~/.config/kennel/profiles/<name>.toml` overrides the built-in profile with the same name. A `.kennel.toml` in the project directory is merged on top, so a repo can add the paths it needs. Paths that don't exist on the machine are skipped, because the built-in profiles list several install locations.

## Threat model

kennel stops an agent from reading or writing outside the allowed paths and from opening TCP connections on other ports. This applies to its child processes too.

It does not stop exfiltration over an allowed port. If a secret is inside the project directory and 443 is open, the agent can still send it out. Landlock doesn't restrict UDP or ICMP yet (ABI v5), which is also why DNS keeps working. Kernel exploits are out of scope, and so is code you later run outside kennel.

If the workload is hostile on purpose, use a VM.

## How it works

It's about 430 lines of Rust. `policy.rs` resolves the profile chain and the optional `.kennel.toml`. `sandbox.rs` opens each allowed path, builds the Landlock ruleset and calls `restrict_self()`. `main.rs` then calls `exec` on the agent. There is no daemon, proxy or `LD_PRELOAD`.

`tests/smoke.sh` checks the enforcement end to end. Build first with `cargo build`.

## License

MIT OR Apache-2.0
