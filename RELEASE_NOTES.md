# tenant 0.1.0-alpha.4

Fourth alpha. Still alpha quality: the verbs work end-to-end on the
author's machine, but rough edges remain. Use this release to evaluate
the shape of the tool, not as a foundation for production tenants.

## What `tenant` does

`tenant` provisions isolated macOS user accounts ("tenants") for
running untrusted or experimental software with explicit filesystem
shares and per-tenant network restrictions enforced via PF (the macOS
packet filter).

A tenant runs as a real macOS user. It owns a home directory, a
dedicated share group, and a Packet Filter anchor. The anchor
restricts outbound network access to an allowlist defined in the
tenant's profile, and restricts which loopback ports the tenant
accepts inbound connections on.

The primary use case is running tools — coding agents, build chains,
third-party CLIs — under an account that cannot reach your shell,
your SSH keys, or arbitrary internet hosts unless you explicitly
grant access.

## New since 0.1.0-alpha.3

- **`tenant setup` — opt-in host preparation.** A new host-wide verb
  (no tenant argument) that prepares the Mac to run tenants. Today it
  offers one item: enabling Touch ID for sudo. On accept it appends
  `auth sufficient pam_tid.so` to `/etc/pam.d/sudo_local` — the
  OS-update-safe customization file macOS's `/etc/pam.d/sudo` includes
  (editing `/etc/pam.d/sudo` directly is clobbered by system updates).
  The change is append-only, backed up first, and idempotent: re-running
  never duplicates the directive, and it no-ops if Touch ID is already
  enabled in either pam file.

  Touch ID is offered, not forced. The prompt defaults to no, and a
  non-interactive invocation (piped/scripted) declines unless you pass
  `--yes` — an auth-stack change never auto-applies from a pipe.
  `--dry-run` previews. Declining is a valid choice; `tenant doctor`
  keeps a quiet informational note and `tenant setup` will offer again
  whenever you change your mind. You'll be asked for your password once
  to apply it (Touch ID isn't on yet at that point).

- **`tenant doctor` Touch-ID detection now checks both pam files.**
  Doctor reads `/etc/pam.d/sudo` *and* `/etc/pam.d/sudo_local`, so a
  host configured the sanctioned way no longer trips a false
  "Touch ID not detected" finding. The finding, when it does fire,
  points at `tenant setup` rather than a hand-edited `sed` command.

## What works in this release

- `tenant setup` — opt-in host preparation (enable Touch ID for sudo).
- `tenant create <name>` — provision a new tenant (user account,
  share group, login keychain, co-working dir, profile scaffold, PF
  anchor).
- `tenant destroy <name>` — convergent teardown; safe to re-run. Leaves
  the co-working directory intact.
- `tenant shell <name>` — enter a tenant interactively, or run a
  single command (`tenant shell <name> -- ls /tmp`). Unlocks the
  tenant keychain and reapplies shares on entry.
- `tenant mode <name> install|runtime` — switch the PF anchor between
  a widened install tier and the restricted runtime tier.
- `tenant inbound <name> restricted|permissive` — control which loopback
  ports the tenant accepts inbound connections on (default: none).
- `tenant reload [<name>]` — reapply the profile to host state,
  including filesystem shares and the co-working directory. Walks
  every tenant when called without an argument.
- `tenant doctor [<name>]` — read-only audit covering paths, sudoers,
  PF state, anchor coherence, share grants, inbound exposure, Touch-ID
  posture, and group membership.

## Requirements

- macOS on Apple Silicon. This release does not ship an Intel build.
- `sudo` access. Touch ID for sudo is recommended — run `tenant setup`
  to enable it. `tenant` does not write a NOPASSWD sudoers entry;
  mutating verbs prompt for authentication.
- PF (Packet Filter) enabled. `tenant create` enables it
  automatically and preserves pre-existing rules through the anchor
  model.

## Installation

Recommended — Homebrew (Apple Silicon):

```
brew tap MuhammadFarag/tenant
brew install tenant
```

Or build from source / download the pre-built ARM binary:

```
# Build from source at this release
cargo install --git https://github.com/MuhammadFarag/tenant --tag v0.1.0-alpha.4

# Or download the pre-built ARM binary
curl -L https://github.com/MuhammadFarag/tenant/releases/download/v0.1.0-alpha.4/tenant-v0.1.0-alpha.4-aarch64-apple-darwin.tar.gz | tar -xz
sudo mv tenant /usr/local/bin/
```

Verify with `tenant --version` (expect `tenant 0.1.0-alpha.4`).

## Known rough edges

Still an alpha. Expect sharp edges in error reporting, recovery from
partial failures, and unusual host configurations the author has not
encountered. Specifically:

- Inbound `restricted` mode narrows *which* loopback ports are exposed,
  not *who* reaches them — co-located tenants can reach a tenant's
  declared/permissive ports. Run mutually-distrusting workloads in
  separate tenants only when you don't expose overlapping loopback
  services.
- `tenant setup` always re-offers Touch ID rather than reporting
  "already enabled, nothing to do" on a configured host (accepting is a
  harmless no-op). The interactive prompt also can't be driven over a
  pipe — use `--yes` for scripted enable.
- Pre-confirm summaries are wordier than they need to be (implementation
  detail and group-name jargon leak into the standard view), and the
  `tenant shell -- <cmd>` command form prints the full reapply log
  around the child rather than running quietly.
- `tenant doctor` over a pipe (no TTY) still fails rather than
  prompting — run it from an interactive terminal.
- `destroy` removes the profile TOML without a backup; `create` will
  overwrite an existing profile. Keep your own copy of hand-authored
  profiles for now.
