# tenant 0.1.0-alpha.7

Seventh alpha. Still alpha quality: the verbs work end-to-end on the
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

## New since 0.1.0-alpha.6

- **`tenant bootstrap` — profile-declared setup commands.** A profile
  (or an include fragment — that's the point) may declare:

  ```toml
  [bootstrap]
  commands = [
    "command -v rg || brew install ripgrep",
    "test -d ~/dotfiles || git clone https://github.com/you/dotfiles ~/dotfiles",
  ]
  ```

  `tenant bootstrap <name>` runs each command as the tenant, in merged
  order (fragments first), stopping on the first that exits non-zero.
  The run happens inside a temporary install-tier egress widen (so
  commands can reach package registries), and egress always narrows
  back to runtime on completion — even when a command fails. Every
  command is shown verbatim before the confirmation prompt.

  Combined with include fragments this is fleet management: declare
  the setup once in `includes/base.toml`, and bare `tenant bootstrap`
  walks every tenant and converges each — per-tenant failures don't
  stop the walk. You promise the commands are idempotent (use guard
  idioms like the examples above); the verb is then safe to re-run
  anytime. There is no state file and no run-once tracking, and
  `tenant reload` never runs commands — reapplying infrastructure and
  re-running actions stay separate operations.

- **`tenant shell -d/--directory` — start in a tenant-side
  directory.** The enter–cd–run workflow is now one line:

  ```
  tenant shell agent -d projects/foo -- claude
  tenant shell agent -d projects/foo            # interactive, starts there
  ```

  Paths resolve on the TENANT's filesystem: a relative path lands
  under the tenant's home (prefer this form), an absolute path is
  literal, and a quoted `'$HOME/…'` expands to the tenant's home.
  Unquoted `$HOME` is expanded by *your* shell to *your* home before
  the binary sees it — hence the relative form. A missing or
  non-directory path refuses before anything is applied (when a sudo
  session is active to probe with), and a `$` anywhere but the
  leading `$HOME` refuses rather than being silently expanded by the
  tenant's login shell.

## New since 0.1.0-alpha.5

- **Per-host egress ports in the allowlist.** An allowlist `hosts`
  entry can declare which TCP ports it opens: a bare string keeps the
  old meaning (TCP 443 only), an inline table declares its own ports
  (`{ host = "github.com", ports = [443, 22] }` for git-over-ssh).
  Existing profiles render byte-identical anchors — upgrading does not
  surface anchor drift.

- **Profile `include` fragments — share config across a fleet.** A
  profile may declare `include = ["base"]`; fragments live in
  `~/.config/tenant/profiles/includes/<name>.toml` and are partial
  profiles merged in order (fragments first, the profile's own entries
  last; nothing overrides). Edit the fragment once, `tenant reload` to
  converge every includer; editing a fragment without reloading
  surfaces as anchor drift in `tenant doctor` on every tenant that
  includes it. Nested includes are refused (depth one).

## What works in this release

- `tenant setup` — opt-in host preparation (enable Touch ID for sudo).
- `tenant create <name>` — provision a new tenant (user account,
  share group, login keychain, co-working dir, profile scaffold, PF
  anchor).
- `tenant destroy <name>` — convergent teardown; safe to re-run. Leaves
  the co-working directory intact.
- `tenant shell <name>` — enter a tenant interactively, or run a
  single command (`tenant shell <name> -- ls /tmp`); `-d <dir>` starts
  either form in a tenant-side directory. Unlocks the tenant keychain
  and reapplies shares on entry.
- `tenant bootstrap [<name>]` — run the profile's declared idempotent
  setup commands as the tenant; bare form walks every tenant.
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
cargo install --git https://github.com/MuhammadFarag/tenant --tag v0.1.0-alpha.7

# Or download the pre-built ARM binary
curl -L https://github.com/MuhammadFarag/tenant/releases/download/v0.1.0-alpha.7/tenant-v0.1.0-alpha.7-aarch64-apple-darwin.tar.gz | tar -xz
sudo mv tenant /usr/local/bin/
```

Verify with `tenant --version` (expect `tenant 0.1.0-alpha.7`).

## Known rough edges

Still an alpha. Expect sharp edges in error reporting, recovery from
partial failures, and unusual host configurations the author has not
encountered. Specifically:

- `tenant bootstrap` trusts your idempotence promise — an unguarded
  `git clone` in the list fails its second run and stops the verb.
  The pre-confirm command list is the honesty backstop; there is no
  sandbox-level validation of what a command does.
- With include fragments there is no "effective profile" view yet —
  the per-tenant file alone no longer tells the whole story. The
  merged result is what `tenant reload` applies and `tenant doctor`
  audits; read the fragment files alongside the profile for now.
- Inbound `restricted` mode narrows *which* loopback ports are exposed,
  not *who* reaches them — co-located tenants can reach a tenant's
  declared/permissive ports. Run mutually-distrusting workloads in
  separate tenants only when you don't expose overlapping loopback
  services.
- `tenant setup` always re-offers Touch ID rather than reporting
  "already enabled, nothing to do" on a configured host (accepting is a
  harmless no-op). The interactive prompt also can't be driven over a
  pipe — use `--yes` for scripted enable.
- `tenant doctor` over a pipe (no TTY) still fails rather than
  prompting — run it from an interactive terminal.
- `destroy` removes the profile TOML without a backup; `create` will
  overwrite an existing profile. Keep your own copy of hand-authored
  profiles for now.
