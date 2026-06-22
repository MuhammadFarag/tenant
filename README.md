# tenant

A macOS CLI for provisioning isolated user accounts with per-tenant firewall rules and explicit file shares.

## The problem

You want to run a coding agent with elevated privileges — auto-approve turned on, no per-command confirmation — so it can iterate on your project without prompting you for every shell command and dependency install. You do not want it touching anything outside the project: not your `~/.ssh`, not your other clients' repositories, not the credentials in your password manager.

A container is the standard answer. The agent gets its own filesystem, its own network, its own user account — elevated privileges inside the box stay inside the box. But three active projects means three running containers, each with its own memory footprint and CPU draw even at idle. And sharing the project directory back in is its own friction. Bind mounts on macOS are slow, host and container disagree about UIDs in ways that break file ownership, and the back-and-forth of "edit from the host, run from the container" turns into a permissions tangle you relearn for every project.

`tenant` gives the agent its own macOS user account instead. The account has a default-deny firewall, no read access to your home directory, and an explicit list of shared paths declared in a profile. Your project directory stays where you have always edited it; the tenant sees it through a symlink with a group ACL that keeps host-writability intact. No container runtime, no bind mounts, no UID translation — and tenants you are not currently using consume no RAM and no CPU.

## What it does

`tenant create <name>` provisions four artifacts on the host:

- A macOS user account named `<name>` (UID ≥ 600, reserved for tenants).
- A primary group named `<name>-tenant-share`, with you (the host operator) as a secondary member so files the tenant creates in shared directories stay writable from your account.
- A per-tenant PF anchor at `/etc/pf.anchors/tenant-<name>`, loaded from `/etc/pf.conf`. Default-deny egress; allowlist hosts declared in the profile.
- A profile TOML at `~/.config/tenant/profiles/<name>.toml` defining the allowlist and any host-to-tenant file shares.

After provisioning, you enter the tenant with `tenant shell <name>` (interactive login) or `tenant shell <name> -- <cmd>` (single command). Both auto-narrow the firewall to runtime tier on entry and reapply declared shares. Any drift from a previous install-tier session is reset before the shell starts.

`tenant shell` also unlocks the tenant's login keychain before exec: it retrieves the password stashed at `tenant create` time from your operator keychain and runs `security unlock-keychain`. This keeps Claude OAuth tokens and other keychain-stored secrets reachable across host reboots, since macOS re-locks every keychain at boot. Tenants created before the keychain bootstrap shipped lack the stash; for those, `tenant shell` refuses with a one-time migration hint: `tenant destroy <name> && tenant create <name>`.

## Quick start

Install `tenant`. The recommended path is Homebrew (Apple Silicon only):

```sh
brew tap MuhammadFarag/tenant
brew install tenant
```

Verify with `tenant --version`. Other options:

**Pre-built binary** (Apple Silicon macOS only):

```sh
RELEASE=v0.1.0-alpha.2   # check the releases page for the latest tag
curl -L "https://github.com/MuhammadFarag/tenant/releases/download/$RELEASE/tenant-$RELEASE-aarch64-apple-darwin.tar.gz" | tar -xz
sudo mv tenant /usr/local/bin/
```

**Build from source at a tagged release**:

```sh
cargo install --git https://github.com/MuhammadFarag/tenant --tag v0.1.0-alpha.2   # check the releases page for the latest tag
```

**Build from a local clone**:

```sh
git clone https://github.com/MuhammadFarag/tenant
cd tenant
cargo install --path .
```

Cargo-installed binaries land at `~/.cargo/bin/tenant`. Make sure that directory is on your `PATH`. Verify with `tenant --version`.

Create a tenant:

```sh
tenant create dev
```

Edit the scaffolded profile to allowlist the hosts the tenant needs:

```toml
schema_version = 1

[allowlist.runtime]
hosts = ["api.anthropic.com", "github.com"]

[allowlist.install]
hosts = ["registry.npmjs.org"]
```

Apply the edit:

```sh
tenant reload dev
```

Run a one-off command as the tenant:

```sh
tenant shell dev -- ls /tmp
```

Run an install-tier command. The firewall widens for the call and narrows back to runtime on completion:

```sh
tenant shell dev --mode install -- bash -c 'curl https://example.com/install.sh | bash'
```

## Verbs

| Verb | Behavior |
|---|---|
| `create <name>` | Provision user + share group + profile + PF anchor. |
| `destroy <name>` | Symmetric teardown. Convergent — re-running on an absent tenant is a no-op. |
| `shell <name>` | Enter the tenant. Optional `--mode install\|runtime` and `-- <cmd>` for the single-command form. |
| `mode <name> install\|runtime` | Re-render the PF anchor at the requested tier and reload. |
| `inbound <name> restricted\|permissive` | Set the tenant's loopback inbound posture. `restricted` (the default) allows inbound only on profile-declared ports; `permissive` temporarily opens all ports — the localhost-redirect OAuth window. |
| `reload [<name>]` | Reapply the profile to host state. No argument walks every tenant. |
| `doctor [<name>]` | Read-only audit. Surfaces filesystem exposure, share drift, firewall state, and sudoers posture. `--strict` exits non-zero on findings. |
| `setup` | Prepare this host to run tenants (opt-in, host-wide; no tenant argument). Today offers to enable Touch ID for sudo. The per-item prompt defaults to no; `--yes` accepts non-interactively, `--dry-run` previews. |

All verbs accept `--verbose` for plan and step-level detail, and `--dry-run` for a no-substrate preview. Mutating verbs prompt for confirmation by default; `--yes` skips the prompt.

A note on `inbound`: `restricted` is surface-reduction, not host-vs-peer isolation. On a shared loopback (`127.0.0.1`) PF cannot see who opened the connection, so a declared or `permissive` port is reachable by the host and any co-located tenant alike, and only TCP is filtered (UDP loopback is unfiltered). A locked tenant — `restricted` with no declared ports, the default — is unreachable on loopback by anyone.

## Profile

Profiles live at `~/.config/tenant/profiles/<name>.toml`. The schema:

```toml
schema_version = 1

[allowlist.runtime]
hosts = ["api.example.com"]       # Allowed in normal operation.

[allowlist.install]
hosts = ["registry.example.com"]  # Allowed during `--mode install` work.

[[shares]]
host_path = "/Users/operator/projects/myrepo"
mode = "rw"                       # "ro" or "rw"
tenant_path = "$HOME/projects/myrepo"
```

`tenant reload <name>` applies edits. Removed share entries are surfaced by `tenant doctor`; the operator decides how to converge them.

## Host requirements

- **macOS**, currently tested on Darwin 25.x. Tooling assumes `dseditgroup`, `sysadminctl`, `dscl`, `pfctl`, and the absolute paths `/bin/test`, `/bin/mkdir`, `/bin/ln`, `/usr/bin/readlink` are present at their canonical locations.
- **Operator account in the `admin` group**, so `sudo` can prompt and `sudo -u <tenant>` is permitted.
- **PF enabled** (`sudo pfctl -e`). `tenant create` enables it on first run.
- **Touch ID for sudo** is recommended (faster prompts + a hardware auth factor). Run `tenant setup` to enable it — it appends `auth sufficient pam_tid.so` to `/etc/pam.d/sudo_local`, the OS-update-safe customization file (`/etc/pam.d/sudo` includes it, and direct edits there are clobbered by macOS updates). `tenant doctor` reports if it is missing; declining is a valid choice.

## Building from source

The repo uses [`just`](https://github.com/casey/just) as a task runner:

```sh
just check        # fmt + clippy + tests (pre-merge gate)
just install      # cargo install --path .
just run create dev --dry-run -v
```

Pre-commit hooks run `cargo fmt --check` and `cargo clippy -- -D warnings` on Rust files. Run `pre-commit install` once after a fresh clone to wire them up.

## Scope and status

This is a solo-developer tool. It runs on the author's Mac. It is not designed for CI, multi-user provisioning, or automated cron use. The substrate calls are sudo-prompting by design; there is no NOPASSWD sudoers entry and no daemon. If you fork it for other use, expect to revisit those assumptions.

The Rust implementation is a port of an earlier Go prototype. Project doctrine and file-level design notes live in [`CLAUDE.md`](./CLAUDE.md) — useful reading if you intend to extend or modify the tool.

## License

Copyright 2026 Muhammad Farag

Licensed under the Apache License, Version 2.0. See [`LICENSE`](./LICENSE) for the full text.
