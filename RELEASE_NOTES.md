# tenant 0.1.0-alpha.1

First tagged release. Alpha quality: the verbs work end-to-end on the
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

## What works in this release

- `tenant create <name>` — provision a new tenant (user account,
  share group, profile scaffold, PF anchor).
- `tenant destroy <name>` — convergent teardown; safe to re-run.
- `tenant shell <name>` — enter a tenant interactively, or run a
  single command (`tenant shell <name> -- ls /tmp`).
- `tenant mode <name> install|runtime` — switch the PF anchor between
  a widened install tier and the restricted runtime tier.
- `tenant reload [<name>]` — reapply the profile to host state. Walks
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
cargo install --git https://github.com/MuhammadFarag/tenant --tag v0.1.0-alpha.1

# Or download the pre-built ARM binary
curl -L https://github.com/MuhammadFarag/tenant/releases/download/v0.1.0-alpha.1/tenant-v0.1.0-alpha.1-aarch64-apple-darwin.tar.gz | tar -xz
sudo mv tenant /usr/local/bin/
```

Verify with `tenant --version` (expect `tenant 0.1.0-alpha.1`).

## Known rough edges

This is the first alpha. Expect sharp edges in error reporting,
recovery from partial failures, and unusual host configurations the
author has not encountered.
