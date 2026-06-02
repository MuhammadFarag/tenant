# tenant 0.1.0-alpha.2

Second alpha. Still alpha quality: the verbs work end-to-end on the
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
tenant's profile.

The primary use case is running tools — coding agents, build chains,
third-party CLIs — under an account that cannot reach your shell,
your SSH keys, or arbitrary internet hosts unless you explicitly
grant access.

## New since 0.1.0-alpha.1

- **Login keychain provisioning.** `tenant create` now bootstraps the
  tenant's `login.keychain-db`, and `tenant shell` retrieves the
  operator-stashed password and unlocks it before exec — so tools that
  need a keychain (credential helpers, signing) work inside the tenant,
  and the unlock survives a host reboot.
- **Co-working directories.** Each tenant gets a shared directory at
  `/Users/Shared/tenants/<name>`, owned by the operator with the
  tenant's share group, setgid + an inheritable ACL — files created
  there by either side stay collaboratively reachable without a tenant
  umask change.
- **Filesystem shares with recursive grants.** `[[shares]]` entries in
  a tenant's profile grant the share group access to host paths via
  recursive ACLs plus a tenant-side symlink. `tenant reload` applies
  them (and heals drift); mode/shell entry reapplies the lighter pieces.
- **`tenant doctor` works on a fresh terminal.** Doctor's privileged
  reads now prompt for `sudo` at point of use and complete the audit,
  instead of aborting with `sudo: a password is required` when no sudo
  session is cached. The pre-exec audit on mutating verbs is likewise
  quiet when uncached while still surfacing drift it can see without
  sudo.

## What works in this release

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
- `tenant reload [<name>]` — reapply the profile to host state,
  including filesystem shares and the co-working directory. Walks
  every tenant when called without an argument.
- `tenant doctor [<name>]` — read-only audit covering paths, sudoers,
  PF state, anchor coherence, share grants, and group membership.

## Requirements

- macOS on Apple Silicon. This release does not ship an Intel build.
- `sudo` access, ideally with Touch ID configured. `tenant` does not
  write a NOPASSWD sudoers entry; mutating verbs prompt for
  authentication.
- PF (Packet Filter) enabled. `tenant create` enables it
  automatically and preserves pre-existing rules through the anchor
  model.

## Installation

The Homebrew tap is not yet available. Two options for now:

```
# Build from source at this release
cargo install --git https://github.com/MuhammadFarag/tenant --tag v0.1.0-alpha.2

# Or download the pre-built ARM binary
curl -L https://github.com/MuhammadFarag/tenant/releases/download/v0.1.0-alpha.2/tenant-v0.1.0-alpha.2-aarch64-apple-darwin.tar.gz | tar -xz
sudo mv tenant /usr/local/bin/
```

Verify with `tenant --version` (expect `tenant 0.1.0-alpha.2`).

## Known rough edges

Still an alpha. Expect sharp edges in error reporting, recovery from
partial failures, and unusual host configurations the author has not
encountered. Specifically:

- Pre-confirm summaries are wordier than they need to be (implementation
  detail and group-name jargon leak into the standard view), and the
  `tenant shell -- <cmd>` command form prints the full reapply log
  around the child rather than running quietly.
- `tenant doctor` over a pipe (no TTY) still fails rather than
  prompting — run it from an interactive terminal.
- `destroy` removes the profile TOML without a backup; `create` will
  overwrite an existing profile. Keep your own copy of hand-authored
  profiles for now.
