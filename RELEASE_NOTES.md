# tenant 0.1.0-alpha.3

Third alpha. Still alpha quality: the verbs work end-to-end on the
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
tenant's profile, and (new in this release) restricts which loopback
ports the tenant accepts inbound connections on.

The primary use case is running tools — coding agents, build chains,
third-party CLIs — under an account that cannot reach your shell,
your SSH keys, or arbitrary internet hosts unless you explicitly
grant access.

## New since 0.1.0-alpha.2

- **Per-tenant inbound loopback control.** A new `tenant inbound <name>
  restricted|permissive` verb, an `[inbound] ports` profile section, and
  a `tenant shell --inbound` flag govern which loopback (`127.0.0.1`)
  ports a tenant accepts connections on. The default is deny-by-default
  (locked): a tenant accepts no inbound loopback from anyone. Declare
  ports in the profile to expose specific TCP services, or flip a tenant
  to `permissive` temporarily — the motivating case is an OAuth
  localhost-redirect callback, where a tool inside the tenant needs your
  browser to reach a short-lived `127.0.0.1:<port>` server. `tenant
  doctor` flags tenants with exposed ports or left permissive, and
  `tenant shell` prints the current inbound posture on entry. Existing
  tenants flip to locked on the next `tenant reload`.

  *Honest scope:* this is surface reduction, not host-versus-peer
  isolation. On macOS, PF cannot see which user initiated a loopback
  connection, so a declared or permissive port is reachable by the host
  operator and by co-located tenants alike — the control narrows *which
  ports* are exposed, not *who* can reach an exposed one. UDP loopback
  is not filtered.

- **Homebrew tap.** `tenant` now installs from a tap:
  `brew tap MuhammadFarag/tenant && brew install tenant` (Apple Silicon).
  It is the recommended install path; the pre-built tarball and
  `cargo install` remain available.

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
- `tenant inbound <name> restricted|permissive` — control which loopback
  ports the tenant accepts inbound connections on (default: none).
- `tenant reload [<name>]` — reapply the profile to host state,
  including filesystem shares and the co-working directory. Walks
  every tenant when called without an argument.
- `tenant doctor [<name>]` — read-only audit covering paths, sudoers,
  PF state, anchor coherence, share grants, inbound exposure, and group
  membership.

## Requirements

- macOS on Apple Silicon. This release does not ship an Intel build.
- `sudo` access, ideally with Touch ID configured. `tenant` does not
  write a NOPASSWD sudoers entry; mutating verbs prompt for
  authentication.
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
cargo install --git https://github.com/MuhammadFarag/tenant --tag v0.1.0-alpha.3

# Or download the pre-built ARM binary
curl -L https://github.com/MuhammadFarag/tenant/releases/download/v0.1.0-alpha.3/tenant-v0.1.0-alpha.3-aarch64-apple-darwin.tar.gz | tar -xz
sudo mv tenant /usr/local/bin/
```

Verify with `tenant --version` (expect `tenant 0.1.0-alpha.3`).

## Known rough edges

Still an alpha. Expect sharp edges in error reporting, recovery from
partial failures, and unusual host configurations the author has not
encountered. Specifically:

- Inbound `restricted` mode narrows *which* loopback ports are exposed,
  not *who* reaches them — co-located tenants can reach a tenant's
  declared/permissive ports. Run mutually-distrusting workloads in
  separate tenants only when you don't expose overlapping loopback
  services.
- Pre-confirm summaries are wordier than they need to be (implementation
  detail and group-name jargon leak into the standard view), and the
  `tenant shell -- <cmd>` command form prints the full reapply log
  around the child rather than running quietly.
- `tenant doctor` over a pipe (no TTY) still fails rather than
  prompting — run it from an interactive terminal.
- `destroy` removes the profile TOML without a backup; `create` will
  overwrite an existing profile. Keep your own copy of hand-authored
  profiles for now.
