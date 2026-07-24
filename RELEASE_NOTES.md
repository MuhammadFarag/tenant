# tenant 0.1.0-alpha.6

Sixth alpha. Still alpha quality: the verbs work end-to-end on the
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

## New since 0.1.0-alpha.5

- **Per-host egress ports in the allowlist.** An allowlist `hosts`
  entry can now declare which TCP ports it opens: a bare string keeps
  the old meaning (TCP 443 only), an inline table declares its own
  ports —

  ```toml
  [allowlist.runtime]
  hosts = [
    "api.anthropic.com",                        # TCP 443 only
    { host = "github.com", ports = [443, 22] }, # + git-over-ssh
  ]
  ```

  The motivating case is git-over-ssh to a forge without opening
  port 22 to every allowlisted host. Existing profiles are untouched:
  bare-string profiles render a byte-identical PF anchor, so upgrading
  does not surface anchor drift in `tenant doctor`. An entry with
  `ports = []` is refused at parse (an unreachable host is a
  contradiction). TCP only, matching `[inbound]`.

- **Profile `include` fragments — share config across a fleet.** A
  profile may declare an ordered list of fragments to merge:

  ```toml
  include = ["base"]
  ```

  Fragments live in `~/.config/tenant/profiles/includes/<name>.toml`
  and are partial profiles: any subset of sections (allowlist tiers,
  `[inbound]` ports, `[[shares]]`) is legal, and the merged result must
  form a complete profile. Merging concatenates lists in order —
  fragments first, the tenant's own entries last; nothing overrides.
  Nested includes are refused (depth one), and two shares mapping to
  the same `tenant_path` across the merge are refused at load.

  This is how a fleet of tenants shares the same agent-API endpoints
  or common shares without hand-duplicating them into every profile:
  edit the fragment once, run `tenant reload` (no argument walks every
  tenant) to converge the fleet. Editing a fragment without reloading
  surfaces as anchor drift in `tenant doctor` on every tenant that
  includes it. The `create` scaffold carries a commented
  `# include = ["base"]` hint, and `tenant help profile` documents the
  schema.

## New since 0.1.0-alpha.4

- **`tenant reload` repairs a tenant's primary group.** A macOS system
  update can reset a tenant account's primary group back to the default
  `staff` (20). That single flipped attribute breaks the sandbox in both
  directions: the tenant loses access to its own shares and co-working
  directory (symlinks resolve, every read and write is denied), and it
  gains `staff` membership — which is enough to enter the host operator's
  home directory and enumerate `~/.ssh`, `~/.aws`, and `~/.config/gh`.

  Until now the primary group was set once, at `create`, and no verb ever
  re-asserted it — so the documented drift remedy (`tenant doctor` →
  `tenant reload`) could not repair it, and the manual fix was a hand-run
  `dscl` command. `tenant reload` now re-asserts it against the live
  share-group record on every run. It is idempotent and a no-op on a
  healthy host. `mode` and `shell` do the lighter reapply and are
  unchanged.

  If you ran a system update since alpha.4, run `tenant reload` and then
  re-enter the tenant — a session already running under the wrong group
  picks up the correction on its next login.

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
- `tenant reload [<name>]` — reapply the profile (with its include
  fragments) to host state, including filesystem shares and the
  co-working directory. Walks every tenant when called without an
  argument.
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
cargo install --git https://github.com/MuhammadFarag/tenant --tag v0.1.0-alpha.6

# Or download the pre-built ARM binary
curl -L https://github.com/MuhammadFarag/tenant/releases/download/v0.1.0-alpha.6/tenant-v0.1.0-alpha.6-aarch64-apple-darwin.tar.gz | tar -xz
sudo mv tenant /usr/local/bin/
```

Verify with `tenant --version` (expect `tenant 0.1.0-alpha.6`).

## Known rough edges

Still an alpha. Expect sharp edges in error reporting, recovery from
partial failures, and unusual host configurations the author has not
encountered. Specifically:

- With include fragments there is no "effective profile" view yet —
  the per-tenant file alone no longer tells the whole story. The merged
  result is what `tenant reload` applies and `tenant doctor` audits;
  read the fragment files alongside the profile for now.
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
