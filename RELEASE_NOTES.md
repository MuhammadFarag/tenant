# tenant 0.1.0-alpha.11

Eleventh alpha. Still alpha quality: the verbs work end-to-end on the
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

## New since 0.1.0-alpha.10

Fixes and diagnostics from provisioning JVM (Gradle/Android) and ESP-IDF
tenants, plus the resilience follow-ups from the macOS-update work. No
migration steps.

- **Bootstrap and `shell -- <cmd>` evaluate your command once.** Both
  ran through `sudo -i`, which hands the command to the tenant's login
  shell as a single string, so `$VAR` was expanded before your command
  ran, even inside single quotes. A bootstrap line appending
  `'export PATH="$JAVA_HOME/bin:$PATH"'` to a dotfile wrote an empty
  `JAVA_HOME` and *your* PATH into the tenant. Commands now run as
  `sudo -H -u <name> -- /bin/zsh -lc 'exec "$@"' …`: still a login
  shell with the tenant's dotfile PATH, argv passed through verbatim.
  This also fixes `tenant shell <name> -d <dir> -- <cmd>`, which could
  run nothing and exit 0.

- **Privileged verbs fail fast without a terminal.** Run from a script
  or an agent with a cold sudo timestamp, `reload`, `bootstrap`,
  `shell`, and the other mutating verbs sat forever at a hidden sudo
  prompt with no output. They now exit 64 with: *this verb needs sudo
  and no terminal is attached — run it in your terminal, or run
  'sudo -v' in this session first*. `doctor` and `--dry-run` are
  unaffected.

- **`[inbound] posture = "permissive"` — persistent all-ports
  loopback.** Gradle, Maven, sbt, Bazel and Kotlin fork workers that
  report back over random loopback ports, so JVM builds cannot run
  under `restricted`, and `tenant inbound <name> permissive` was undone
  by every `tenant shell` entry. Declaring the posture in the profile
  (or an include fragment) makes it the steady state that every
  reapply renders. `tenant inbound <name> restricted` and
  `shell --inbound restricted` then refuse (exit 64) and name the
  profile to edit; doctor reports the posture as info. The same
  exposure caveat applies: every listener the tenant opens is reachable
  by the host and peer tenants.

- **Doctor warns when a CDN host has moved.** pf resolves allowlisted
  hostnames once, when the anchor loads; Google, Fastly and other CDNs
  rotate their answers within minutes, and connections to the new
  addresses hang until they time out. `tenant doctor <name>` now
  re-resolves each runtime hostname and warns when an address is
  outside the loaded pf table (CIDR entries are understood). `tenant
  help profile` explains the fix: pin the provider's published ranges
  in an include fragment, and regenerate it when the provider updates
  its list.

- **Doctor lists shared files missing the share ACL.** The inherited
  share-group ACE lands only on files created in place. Tools that
  write a temp file and rename it into the tree (Gradle, Android
  Studio, cargo, npm) leave files the other side gets EACCES on. Doctor
  now walks the co-working directory and each share and names them;
  `tenant reload` repairs them.

- **One un-ACL-able file no longer aborts a reload.** macOS
  `chmod -R +a` applies the ACE to the rest of the tree and exits 1
  when it meets something it cannot change (a dangling socket symlink,
  a protected `.app` bundle); `reload` treated that as fatal and
  skipped every remaining share step for the tenant. It now prints a
  `⚠` line with chmod's message and continues.

- **`shell -- <cmd>` narrows back when the keychain unlock fails.** A
  missing stashed password left the tenant at install tier and/or
  permissive inbound until the next reapply.

- **Doctor finishes the audit when a probe fails.** A deleted share
  path or a never-loaded anchor used to abort `tenant doctor` with exit
  74, and in the no-argument form hid every tenant after it. Each
  failure is now reported and the walk continues, exiting 74 at the end
  when anything could not be checked. A missing anchor file is reported
  as anchor drift.

- **Text.** `tenant help profile` and `tenant inbound --help` now say
  that `[inbound]` governs only listeners the tenant opens; the
  tenant's connections to host-owned loopback services (databases,
  adb, dev servers) always pass.

## New since 0.1.0-alpha.9

A resilience release. Three macOS updates in a row (26.5.1, 26.6.2,
27.0) silently reset host state that `tenant` wrote once at `create`.
This release makes the CLI converge on that state instead of assuming
it persists. **Existing hosts have a one-time step** — see the third
item.

- **Reapply restores the `/etc/pf.conf` anchor reference.** Every
  update replaces `/etc/pf.conf` with Apple's stock file, dropping the
  `anchor "tenant-<name>"` / `load anchor` lines, so pf loaded none of
  the tenant anchors and every tenant had unrestricted egress while
  `tenant reload` reported success. Now `reload`, `mode`, `inbound`,
  `shell`, and `bootstrap` read `/etc/pf.conf` and re-add the
  reference before reloading pf when it is missing. The plan shows the
  step as "Update /etc/pf.conf" with the note "only when /etc/pf.conf
  lacks the anchor reference"; in real runs it appears only when
  needed.

- **Doctor names the cause.** A tenant whose anchor is not referenced
  from `/etc/pf.conf` is a new `critical:` finding, once per affected
  tenant, with `tenant reload <name>` as the fix. While that is the
  case, doctor skips that tenant's kernel-rule checks, so you no longer
  get two misdirecting "pf anchor drift, run `tenant mode`" warnings
  per tenant for a problem `tenant mode` could not fix. Default doctor
  still exits 0; `tenant doctor --strict` exits 2 on it, which is the
  hook for a scheduled check. The guidance also warns against
  restoring `/etc/pf.conf.tenant-backup`: it is create's rollback
  snapshot and omits every tenant created since.

- **Doctor reports primary-group drift.** Updates rewrite local user
  records and each tenant's primary group reverts to `staff` (20),
  which gives the tenant group access to your home directory and drops
  it from its share group. `tenant reload` has repaired this since
  alpha.5, but nothing reported it. Doctor now reads the user record
  (no sudo) and emits a `critical:` finding when the primary group is
  not the tenant's share group.

- **Firewall files are root-owned.** Privileged writes used a tempfile
  and `sudo mv`, and rename preserves ownership, so `/etc/pf.conf` and
  every anchor were owned by you, mode 0644 — the firewall config was
  writable without sudo. Writes now set `root:wheel` and `0644` on the
  tempfile before the move. Anchors re-own themselves on the next
  reload; `/etc/pf.conf` only when it is next rewritten, so on an
  existing host run this once:

  ```
  sudo chown root:wheel /etc/pf.conf /etc/pf.anchors/tenant-*
  ```

- **Text.** The `SSH_AUTH_SOCK` doctor warning now points at
  `/etc/sudoers.d/tenant`, since `/etc/sudoers` itself is replaced by
  updates.

## New since 0.1.0-alpha.8

A compatibility release for macOS 26.6. **Existing tenants need a
one-time manual step** — see the first item.

- **The tenant keychain is now `tenant.keychain-db`, not
  `login.keychain-db`.** macOS 26.6 binds a keychain named
  `login.keychain-db` to the user's Data Protection keybag and refuses
  to create or unlock it from outside that user's login session — which
  is what `sudo -iu <tenant>` from your session is. On an updated host
  every `tenant shell` and `tenant bootstrap` failed at the keychain
  unlock (`security` exit 51), and `tenant create` died at
  `create-keychain`. Any other filename is exempt, on 26.6 and on every
  earlier release, so `create`, `shell`, `bootstrap`, and `doctor` now
  use `tenant.keychain-db`. Same four `security` steps, same stashed
  password, same unlock at shell entry.

  **Migration for tenants created before this release:** their
  `login.keychain-db` can no longer be opened from your session, but
  the stashed password is still valid. Recreate the keychain under the
  new name, keyed to that stash (replace `NAME` with the tenant):

  ```
  sudo -iu NAME security create-keychain -p "$(security find-generic-password -a NAME -s tenant-NAME -w)" tenant.keychain-db
  sudo -iu NAME security default-keychain -s tenant.keychain-db
  sudo -iu NAME security list-keychains -s tenant.keychain-db
  sudo -iu NAME security set-keychain-settings tenant.keychain-db
  ```

  `tenant doctor NAME` reports "keychain absent" for an unmigrated
  tenant and prints this recipe with the name filled in. The new
  keychain starts empty, so apps inside the tenant re-authenticate
  once; the old `login.keychain-db` stays on disk, unused. Tenants
  created with this release need nothing.

- **Run-as-tenant probes no longer mistake a cold sudo cache for an
  answer.** `sudo -n` exits 1 when it cannot authenticate — the same
  code `/bin/test` uses for "no" — so `doctor` could report a healthy
  tenant's keychain as absent, and the host-secrets isolation check
  could report "denied" when it had not actually run. Exit 1 now counts
  only when sudo printed nothing to stderr; otherwise the probe fails
  loudly. As a consequence, `shell`, `mode`, `inbound`, `reload`, and
  `bootstrap` on a tenant with `[[shares]]` prompt for sudo **before**
  showing the plan when your sudo timestamp is cold — one prompt per
  terminal session, the same one the verb would have needed a moment
  later.

- **Text.** Doctor's stashed-password finding no longer describes the
  keychain unlock as a future feature. The keychain ✓ and error lines
  no longer say "login keychain".

## New since 0.1.0-alpha.7

A small release — polish on the alpha.7 features, no new verbs.

- **The profile scaffold now carries a `[bootstrap]` section.** A
  fresh `tenant create` writes the section with a commented example
  and the ground rules (runs as the tenant via `/bin/sh -c`, in
  order, stops on first failure, temporary install-tier egress
  widen), so the feature is discoverable while editing the profile —
  not only via `tenant help profile`. Example entries stay commented:
  a fresh tenant's `tenant bootstrap` remains a quiet no-op.

- **Internal: operator-facing text extracted to embedded resources.**
  The profile scaffold and `tenant help` bodies now live as plain
  files compiled into the binary. No behavior change — the scaffold
  and help output are byte-identical.

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
cargo install --git https://github.com/MuhammadFarag/tenant --tag v0.1.0-alpha.8

# Or download the pre-built ARM binary
curl -L https://github.com/MuhammadFarag/tenant/releases/download/v0.1.0-alpha.8/tenant-v0.1.0-alpha.8-aarch64-apple-darwin.tar.gz | tar -xz
sudo mv tenant /usr/local/bin/
```

Verify with `tenant --version` (expect `tenant 0.1.0-alpha.8`).

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
