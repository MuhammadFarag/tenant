//! Pure functions for the curated path list, severity classification,
//! and finding rendering. No I/O.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::domain::{AccessMode, AccessOutcome, GroupName, HostUserName, TenantUserName};

/// Order is load-bearing: `--strict` maps max severity to exit code
/// (Info → 0, Warning → 1, Critical → 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// Threat-category for a curated path. The (category, outcome) →
/// severity matrix lives in `classify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Host-side secret targets — private keys, cloud credentials,
    /// session tokens, command history.
    HostSecret,
    /// `/Users/<host>/` listability — enumerable file names can
    /// themselves reveal sensitive activity even if individual files
    /// are protected.
    HostHomeListing,
    /// Tenant A's access to tenant B's home directory or `.ssh/`.
    CrossTenant,
    /// Per-tenant profiles in `~/.config/tenant/profiles/` and per-
    /// tenant PF anchor files in `/etc/pf.anchors/`. Anchors are mode
    /// 0644 by design and WILL surface as `Allowed`; classified
    /// `info` because the exposure is intentional.
    TenantArtifact,
    /// Keychain-bootstrap drift: tenant's `login.keychain-db` absent,
    /// or operator-side stash absent. Distinct category because the
    /// (file-existence-on-disk, presence-of-stash) signal doesn't fit
    /// the `probe_access_as_tenant` shape the other categories share.
    Keychain,
}

/// A doctor-detected exposure.
///
/// Severity rationale for the non-obvious cases:
/// - `EnvLeak` is warning (not critical): the leak only triggers if
///   the operator's session env actually holds the var; recovery is a
///   one-line `/etc/sudoers` edit.
/// - `TouchIdMissing` is info: a recommendation aligned with the
///   NOPASSWD-sudoers stance, not a correctness drift. Info doesn't
///   trip `--strict`'s exit-1.
/// - `PfDisabled` is critical: when pf is off, every tenant's anchor
///   is silently inert.
/// - `SymlinkDrift` target comparison is string-exact (no canonicalize)
///   — the profile names declared intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    FilesystemExposure {
        severity: Severity,
        tenant: TenantUserName,
        path: PathBuf,
        access: AccessMode,
    },
    EnvLeak {
        var: String,
    },
    PfRuleDrift {
        tenant: TenantUserName,
        detail: &'static str,
    },
    TouchIdMissing,
    PfDisabled,
    AnchorBodyDrift {
        tenant: TenantUserName,
    },
    AclDrift {
        tenant: TenantUserName,
        host_path: PathBuf,
        group: GroupName,
    },
    SymlinkDrift {
        tenant: TenantUserName,
        tenant_path: PathBuf,
        expected_target: PathBuf,
        actual: SymlinkActual,
    },
    HostNotInShareGroup {
        tenant: TenantUserName,
        host: HostUserName,
        group: GroupName,
    },
    /// Tenant's `login.keychain-db` is absent on disk (manual delete,
    /// or a partial-create that never landed). OAuth-class apps inside
    /// the tenant will fire `errSecNoSuchKeychain`.
    TenantKeychainAbsent {
        tenant: TenantUserName,
    },
    /// Operator-side stash for the tenant is absent under
    /// (account=tenant, service=tenant-<tenant>). A future shell-
    /// entry unlock pass would have no way to retrieve the
    /// protecting password without the stash.
    StashAbsent {
        tenant: TenantUserName,
    },
}

/// What's actually present at a declared share's `tenant_path` when
/// it doesn't match the declared `host_path` symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymlinkActual {
    Absent,
    WrongTarget(PathBuf),
    NotSymlink,
}

impl Finding {
    pub fn severity(&self) -> Severity {
        match self {
            Finding::FilesystemExposure { severity, .. } => *severity,
            Finding::EnvLeak { .. } => Severity::Warning,
            Finding::PfRuleDrift { .. } => Severity::Warning,
            Finding::TouchIdMissing => Severity::Info,
            Finding::PfDisabled => Severity::Critical,
            Finding::AnchorBodyDrift { .. } => Severity::Warning,
            Finding::AclDrift { .. } => Severity::Warning,
            Finding::SymlinkDrift { .. } => Severity::Warning,
            Finding::HostNotInShareGroup { .. } => Severity::Warning,
            Finding::TenantKeychainAbsent { .. } => Severity::Warning,
            Finding::StashAbsent { .. } => Severity::Warning,
        }
    }

    /// Multi-section operator-facing guidance. Section headers at
    /// column 0; body at column 2; no trailing newline.
    ///
    /// `None` for `FilesystemExposure`: per-path guidance depends on
    /// operator intent (file vs directory; intentional-public vs
    /// accidental-leak; POSIX vs ACL fix) — belongs with the
    /// remediation surface, not the detection surface.
    pub fn guidance(&self) -> Option<String> {
        match self {
            Finding::FilesystemExposure { .. } => None,
            Finding::AnchorBodyDrift { tenant } => Some(format!(
                "Why this matters
  The on-disk file at /etc/pf.anchors/tenant-{tenant} is the source of
  truth pf.conf reloads on boot. Its current body diverges from what
  the profile would render \u{2014} so the next reboot or pfctl reload
  will switch the in-kernel ruleset to whatever's on disk, not what
  intent describes. If the divergence is a hand-edit, that edit becomes
  the enforced policy. If it's install-tier widening left behind from a
  prior session, the allowlist stays wide indefinitely.

Recommended fix
  tenant mode {tenant} runtime
  Re-renders the anchor body from the profile (runtime tier) and
  reloads pf, bringing the file and the in-kernel state back in sync
  with intent.

Side-effects to know about
  \u{2022} The pfctl reload causes a sub-millisecond packet-filter disruption.
  \u{2022} Any hand-edits to /etc/pf.anchors/tenant-{tenant} are discarded.
  \u{2022} If install-tier hosts were deliberately on disk, the narrow drops
    them; rerun `tenant mode {tenant} install` after the narrow if
    still needed.

Alternative
  sudo $EDITOR /etc/pf.anchors/tenant-{tenant} && sudo pfctl -f /etc/pf.conf
  Edits the file directly and reloads pf. Preserves operator edits but
  leaves profile and file out of sync \u{2014} the next `tenant mode` or
  `tenant shell` invocation will re-render and overwrite them."
            )),
            Finding::PfRuleDrift { tenant, .. } => Some(format!(
                "Why this matters
  The kernel's pf anchor for tenant '{tenant}' is missing one of the
  structural rule classes the runtime requires \u{2014} either the `pass`
  rule that allows traffic to the allowlist, the `block` rule that
  drops everything else, or both. Whatever is enforcing right now
  doesn't match the file or the profile; packets the tenant sends may
  be flowing through unintended paths until the next reload reinstates
  the full ruleset.

Recommended fix
  tenant mode {tenant} runtime
  Re-renders the anchor file from the profile (runtime tier) and
  reloads pf, reinstating the full pass + block rule pair in the
  in-kernel anchor.

Side-effects to know about
  \u{2022} The pfctl reload causes a sub-millisecond packet-filter disruption.
  \u{2022} If the on-disk anchor file is also drifted, this fixes both \u{2014}
    file and kernel sync to the profile in one step.
  \u{2022} If install-tier widening was previously applied via `tenant mode
    {tenant} install`, the narrow drops it; rerun mode install
    afterward if the wider allowlist is still needed.

Alternative
  sudo pfctl -f /etc/pf.conf
  Reloads the whole pf.conf, which re-reads the (current) on-disk
  anchor file. Faster than re-rendering but only fixes the kernel-side
  drift if the on-disk file itself isn't drifted; otherwise it just
  reinstalls the drifted body into the kernel."
            )),
            Finding::PfDisabled => Some(
                "Why this matters
  pf is globally disabled on this host. Every tenant has an anchor
  installed under /etc/pf.anchors/, every anchor is referenced from
  /etc/pf.conf, but pf itself doesn't consult any of them while
  filtering packets \u{2014} so no tenant's egress allowlist is enforcing
  anything. The isolation guarantee tenants depend on is currently
  zero. Any `tenant create` or `tenant mode` that ran while pf was
  disabled installed correct rules into a kernel that's ignoring them.

Recommended fix
  sudo pfctl -e
  Enables pf globally. Idempotent at the substrate \u{2014} this is the same
  command `tenant create` runs on first invocation when pf isn't
  already on.

Side-effects to know about
  \u{2022} Re-enabling pf may surface live issues the operator originally
    disabled it to escape (debugging a flaky rule, working around a
    misconfigured anchor). Verify with `pfctl -sr` before assuming
    the prior issue is resolved.
  \u{2022} Currently-running tenant sessions immediately start being
    filtered by their anchors; in-flight connections the allowlist
    would block may drop.
  \u{2022} System-wide pf rules in /etc/pf.conf also start enforcing again,
    not just tenant anchors."
                    .to_string(),
            ),
            Finding::EnvLeak { var } => Some(format!(
                "Why this matters
  /etc/sudoers (with drop-ins) doesn't carry an unqualified
  `Defaults env_delete += \"{var}\"` directive, so the operator's
  session env propagates verbatim into every `sudo -u <tenant>`
  invocation \u{2014} which is exactly how `tenant shell` enters a tenant.
  The canonical case is SSH_AUTH_SOCK: macOS's ssh-agent socket gets
  inherited, and any tenant the operator shells into can `ssh` to
  every host the operator has cached keys for. The isolation between
  host and tenant is breached at the SSH layer even though pf, the
  filesystem, and the UID/GID are all correct.

Recommended fix
  echo 'Defaults env_delete += \"{var}\"' | sudo tee -a /etc/sudoers.d/tenant >/dev/null
  Appends to a drop-in file so the main /etc/sudoers stays pristine.
  The directive must be unqualified (no `Defaults:user`, no
  `Defaults>runas`); qualified forms restrict scope and don't protect
  `sudo -u <tenant>` invocations.

Side-effects to know about
  \u{2022} Future `sudo -u <tenant>` sessions won't see {var} in their env.
    A tenant can still set the var manually (e.g. explicit agent
    forwarding) \u{2014} this closes the unintentional leak path, not all
    paths.
  \u{2022} Other shells that invoke sudo (`sudo bash`, `sudo make`) also
    lose {var} from their inherited env, regardless of which user sudo
    is running as. Usually fine; flag if a host-side workflow depended
    on the leak.
  \u{2022} Validate the edit with `sudo visudo -c -f /etc/sudoers.d/tenant`
    before relying on it \u{2014} a syntax error in a drop-in can break sudo
    across the host.

Alternative
  Defaults>tenant env_delete += \"{var}\"
  A `Defaults>runas` form targets only sudo invocations whose -u arg
  matches a tenant by name \u{2014} narrower than the unqualified form but
  doctor will still nag (the parser conservatively rejects qualified
  Defaults per CLAUDE.md's unqualified-directive doctrine). If you
  prefer the qualified form, accept the false-positive warning on
  every doctor run."
            )),
            Finding::TouchIdMissing => Some(
                "Why this matters
  /etc/pam.d/sudo doesn't enable Touch ID for sudo authentication.
  This isn't a correctness drift \u{2014} sudo still works via password \u{2014}
  but it's a recommendation aligned with the project's locked
  no-NOPASSWD-sudoers stance. Touch ID makes sudo prompts faster (a
  fingerprint beats typing a password) AND adds a second auth factor
  (fingerprint plus sudoers membership) instead of just one (sudoers
  membership). Info-tier because absence doesn't compromise isolation;
  it's an ergonomics + defense-in-depth gap.

Recommended fix
  sudo sed -i.bak '/^auth.*pam_opendirectory/i auth       sufficient     pam_tid.so' /etc/pam.d/sudo
  Inserts an `auth sufficient pam_tid.so` line before the existing
  pam_opendirectory module. `sufficient` is the control type the
  threat model expects \u{2014} a Touch ID hit short-circuits the rest of
  the auth stack; a Touch ID miss falls through to password.

Side-effects to know about
  \u{2022} Next sudo invocation pops a Touch ID prompt instead of (or
    before) the password prompt. Touch your sensor on the Touch Bar
    or Magic Keyboard within ~10 seconds.
  \u{2022} If Touch ID hardware isn't available or isn't registered (System
    Settings → Touch ID & Password), pam_tid.so falls through to the
    next module \u{2014} sudo still works, just without the short-circuit.
  \u{2022} The /etc/pam.d/sudo.bak backup file is created by sed -i.bak;
    remove it (`sudo rm /etc/pam.d/sudo.bak`) once the new behavior is
    verified."
                    .to_string(),
            ),
            Finding::AclDrift {
                tenant,
                host_path,
                group,
            } => {
                let path = host_path.display();
                Some(format!(
                    "Why this matters
  The host path {path} is declared as a share for tenant '{tenant}' in
  the profile, but the `{group}` group's ACL entry is missing from the
  path's `ls -lde` listing. The tenant currently cannot reach the share
  via group membership \u{2014} any read or write attempt either fails or
  falls back to whatever POSIX bits the path carries. The most common
  causes are a manual `chmod -a` on the operator's side, or a `cp -R`
  that clobbered the entry as a side-effect.

Recommended fix
  tenant reload {tenant}
  Re-applies every declared share in the tenant's profile. macOS
  `chmod +a` is natively idempotent \u{2014} re-applying an existing
  entry is a noop, not a duplicate \u{2014} so this is safe to run
  regardless of the path's current ACL state.

Side-effects to know about
  \u{2022} Every share in the profile is re-applied, not just this one.
    If another share has an unrelated pending refusal (host_path
    missing on disk, tenant_path occupied by a real file), reload
    will abort on it before reaching this entry; address those first.
  \u{2022} The PF anchor is also re-rendered at runtime tier as a side
    effect of `tenant reload`. If install-tier widening was active
    when the operator last ran `tenant mode {tenant} install`, the
    narrow drops it; rerun `mode install` afterward if still needed.

Alternative
  chmod +a \"group:{group} allow read,write,execute,delete,append,file_inherit,directory_inherit\" {path}
  Re-applies just this one entry. Use when `tenant reload` is blocked
  by an unrelated refusal. The bit list shown is the `rw` default;
  for read-only shares omit `write,delete,append`."
                ))
            }
            Finding::SymlinkDrift {
                tenant,
                tenant_path,
                expected_target,
                actual,
            } => {
                let tpath = tenant_path.display();
                let expected = expected_target.display();
                Some(match actual {
                    SymlinkActual::Absent => format!(
                        "Why this matters
  The tenant_path {tpath} is declared in tenant '{tenant}'s profile to
  symlink {expected}, but no entry exists at that path \u{2014} the tenant
  `rm`'d the symlink, or it was never installed. The tenant cannot
  reach the declared share through this path until the link is
  restored.

Recommended fix
  tenant reload {tenant}
  Re-runs the share-reapply substrate, which calls `sudo -n -u
  {tenant} /bin/ln -sfn {expected} {tpath}`. `ln -sfn` is idempotent
  \u{2014} replaces any existing entry at the same path with the
  declared symlink.

Side-effects to know about
  \u{2022} Every share in the profile is re-applied, not just this one.
    If another share has an unrelated pending refusal, reload aborts
    on it before reaching this entry; address those first.
  \u{2022} The PF anchor is re-rendered at runtime tier as a side effect.
    If install-tier widening was active, the narrow drops it; rerun
    `tenant mode {tenant} install` afterward if still needed.

Alternative
  sudo -n -u {tenant} /bin/ln -sfn {expected} {tpath}
  Recreates just this one link. Use when `tenant reload` is blocked
  by an unrelated refusal."
                    ),
                    SymlinkActual::WrongTarget(actual_target) => {
                        let actual = actual_target.display();
                        format!(
                            "Why this matters
  The tenant_path {tpath} is declared in tenant '{tenant}'s profile to
  symlink {expected}, but the link currently points at {actual}. The
  most common cause is an operator edit to the profile's host_path
  without a follow-up `tenant reload`. The tenant is still reaching A
  share through this path, just not the one the profile names.

Recommended fix
  tenant reload {tenant}
  Re-runs the share-reapply substrate, which calls `sudo -n -u
  {tenant} /bin/ln -sfn {expected} {tpath}`. `ln -sfn` replaces
  the existing symlink in place; no manual `rm` needed.

Side-effects to know about
  \u{2022} The old target {actual} stays on the host filesystem \u{2014} reload
    only updates the link, it doesn't touch what was previously linked.
    Clean up manually if appropriate.
  \u{2022} Every share in the profile is re-applied, not just this one.
    If another share has an unrelated pending refusal, reload aborts
    before reaching this entry; address those first.

Alternative
  sudo -n -u {tenant} /bin/ln -sfn {expected} {tpath}
  Updates just this one link. Use when `tenant reload` is blocked by
  an unrelated refusal."
                        )
                    }
                    SymlinkActual::NotSymlink => format!(
                        "Why this matters
  The tenant_path {tpath} is declared in tenant '{tenant}'s profile to
  symlink {expected}, but a real file or directory currently occupies
  that path \u{2014} not a symlink. `tenant reload` will refuse with
  `TenantPathOccupied` rather than clobber it (the substrate never
  overwrites real operator data). Until the conflict is removed, the
  declared share isn't reachable through this path.

Recommended fix
  sudo -n -u {tenant} rm -rf {tpath} && tenant reload {tenant}
  Removes the conflict from the tenant's perspective, then re-runs
  the share-reapply substrate to install the declared symlink.
  Verify the conflict's contents BEFORE running `rm -rf` \u{2014} this
  step is destructive.

Side-effects to know about
  \u{2022} `rm -rf` deletes whatever's at {tpath}. If that content matters,
    copy it elsewhere first.
  \u{2022} Reload re-applies every declared share, not just this one.

Alternative
  Edit the profile to point tenant_path elsewhere
  If the current content at {tpath} should be preserved AND the share
  is still needed, change tenant_path in the profile to a free path,
  then run `tenant reload {tenant}`."
                    ),
                })
            }
            Finding::HostNotInShareGroup {
                tenant,
                host,
                group,
            } => Some(format!(
                "Why this matters
  Host '{host}' is not a member of '{group}'. The share substrate
  installs an inheritable ACL on every declared `host_path` granting
  `{group}` access \u{2014} the tenant (whose primary group IS `{group}`)
  inherits that grant on any new file they create inside an RW share.
  The host inherits it ONLY if also a member of `{group}`. Without
  the membership, files the tenant creates inside RW shares are
  world-readable (POSIX 644) but not host-writable: host can `ls`
  and `cat` but `vim` reports `E212: Can't open file for writing`.
  Legacy tenants (created before host membership was wired into the
  create flow) all hit this; manual `dseditgroup -o edit -d {host}
  {group}` on a newer tenant also surfaces here.

Recommended fix
  tenant reload {tenant}
  The catch-up path runs `dseditgroup -o edit -a {host} -t user
  {group}` as the first step inside `execute_reapply_plan`.
  Idempotent at the substrate \u{2014} re-applying on an existing
  member is a silent noop.

Side-effects to know about
  \u{2022} '{host}' gains a secondary group membership. `id` and
    `groups` start listing `{group}`; processes the host runs inherit
    it on new files and directories they create. On solo-Mac scope
    this is intended; if multiple human users share the host, only
    the operator running `tenant reload` gets added.
  \u{2022} The PF anchor is re-rendered at runtime tier as a side effect.
    If install-tier widening was active, the narrow drops it; rerun
    `tenant mode {tenant} install` afterward if still needed.
  \u{2022} Every declared share is also re-applied. If another share has
    an unrelated pending refusal, reload aborts before reaching this
    step; address those first.

Alternative
  sudo dseditgroup -o edit -n . -a {host} -t user {group}
  Adds just the membership without running the full reload. Use when
  `tenant reload` is blocked by an unrelated refusal."
            )),
            Finding::TenantKeychainAbsent { tenant } => Some(format!(
                "Why this matters
  Tenant '{tenant}'s login keychain at /Users/{tenant}/Library/Keychains/login.keychain-db
  is absent. Claude OAuth and other credential-stashing apps running
  inside the tenant fire `errSecNoSuchKeychain` warnings and have no
  persistent place to write tokens \u{2014} every login interaction
  re-prompts because nothing survives across sessions. The most common
  causes are a manual `rm` against the tenant's Library/Keychains
  directory, or a partial-create that left the file off disk.

Recommended fix
  tenant destroy {tenant} && tenant create {tenant}
  Re-bootstraps the tenant from scratch: the destroy moves the home to
  /Users/Deleted Users/, the create runs the 4-step keychain provision
  sequence cleanly. Idempotent at the substrate (destroy converges on
  absent tenants; create runs `security create-keychain` with the
  duplicate-keychain escape hatch).

Side-effects to know about
  \u{2022} Any tenant-side state in /Users/{tenant}/ moves to
    /Users/Deleted Users/{tenant}/ (recoverable until the host empties
    /Users/Deleted Users or the host is rebuilt).
  \u{2022} A fresh keychain password is generated and stashed in the
    operator's keychain; the prior password (if any) is discarded.
  \u{2022} Any apps the tenant had open with the old keychain attached
    will lose their reference; restart them after the re-create.

Alternative
  sudo -iu {tenant} security create-keychain -p <password> login.keychain-db
  Manually re-create the keychain, then run the 3 follow-up `security`
  sub-steps (`default-keychain -s`, `list-keychains -s`,
  `set-keychain-settings`) and `security add-generic-password -a {tenant}
  -s tenant-{tenant} -w <password>` against the operator's keychain to
  re-stash. Tedious; the full destroy + create path is faster and
  matches the substrate the create flow runs."
            )),
            Finding::StashAbsent { tenant } => Some(format!(
                "Why this matters
  The operator's login keychain doesn't carry a generic-password entry
  under (account={tenant}, service=tenant-{tenant}). A future shell-
  entry unlock pass would read from that entry to retrieve the
  password that protects the tenant's `login.keychain-db`; without
  the stash, post-reboot the tenant's keychain stays locked and OAuth
  tokens it carries become unreachable. The most common cause is a
  manual `security delete-generic-password` run against the operator's
  keychain, or a partial-create that landed the keychain but missed
  the stash.

Recommended fix
  tenant destroy {tenant} && tenant create {tenant}
  Re-bootstraps both the tenant keychain AND the operator-side stash
  with a fresh shared password. The destroy converges on the
  pre-existing tenant; the create generates a new password, writes it
  to the tenant keychain, and stashes the same bytes in the operator's
  keychain.

Side-effects to know about
  \u{2022} Any tenant-side state in /Users/{tenant}/ moves to
    /Users/Deleted Users/{tenant}/ (recoverable until the host empties
    /Users/Deleted Users or the host is rebuilt).
  \u{2022} The new keychain password is unrelated to any previously-used
    password \u{2014} apps that cached the old one will need re-auth.

Alternative
  In practice, none. The password was never written outside the
  operator's keychain by design, so it can't be recovered after the
  stash is gone. If the tenant's keychain happens to still be unlocked
  and the operator can somehow reproduce the password (e.g. it was
  captured to a password manager out-of-band), they could
  `security add-generic-password -a {tenant} -s tenant-{tenant} -w
  <recovered-password>` to re-stash. Without that, `destroy && create`
  is the only path."
            )),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::FilesystemExposure {
                severity,
                tenant,
                path,
                access,
            } => {
                let verb = match access {
                    AccessMode::Read => "read",
                    AccessMode::List => "list",
                };
                write!(
                    f,
                    "{}: tenant '{}' can {} {}",
                    severity.as_str(),
                    tenant,
                    verb,
                    path.display(),
                )
            }
            Finding::EnvLeak { var } => write!(
                f,
                "warning: {var} not in env_delete \u{2014} host's session env leaks into 'tenant shell' sessions; \
                 add `Defaults env_delete += \"{var}\"` to /etc/sudoers"
            ),
            Finding::PfRuleDrift { tenant, detail } => write!(
                f,
                "warning: tenant '{tenant}' pf anchor drift \u{2014} {detail}; \
                 run `tenant mode {tenant} runtime` to re-render and reload"
            ),
            Finding::TouchIdMissing => write!(
                f,
                "info: Touch ID for sudo not detected \u{2014} \
                 add `auth sufficient pam_tid.so` to /etc/pam.d/sudo \
                 to enable fingerprint-gated sudo"
            ),
            Finding::PfDisabled => write!(
                f,
                "critical: pf is globally disabled \u{2014} no tenant firewall \
                 is enforcing; run `sudo pfctl -e` to enable"
            ),
            Finding::AnchorBodyDrift { tenant } => write!(
                f,
                "warning: tenant '{tenant}' anchor file drift \u{2014} \
                 on-disk body differs from profile-derived render; \
                 run `tenant mode {tenant} runtime` to re-render and reload"
            ),
            Finding::AclDrift {
                tenant,
                host_path,
                group,
            } => write!(
                f,
                "warning: tenant '{tenant}' share ACL drift \u{2014} \
                 group '{group}' missing on {}; \
                 run `tenant reload {tenant}` to re-apply",
                host_path.display(),
            ),
            Finding::SymlinkDrift {
                tenant,
                tenant_path,
                expected_target,
                actual,
            } => {
                let tpath = tenant_path.display();
                let expected = expected_target.display();
                match actual {
                    SymlinkActual::Absent => write!(
                        f,
                        "warning: tenant '{tenant}' share symlink drift \u{2014} \
                         {tpath} is absent (expected symlink to {expected}); \
                         run `tenant reload {tenant}` to re-create"
                    ),
                    SymlinkActual::WrongTarget(actual_target) => write!(
                        f,
                        "warning: tenant '{tenant}' share symlink drift \u{2014} \
                         {tpath} points at {} (expected {expected}); \
                         run `tenant reload {tenant}` to re-link",
                        actual_target.display(),
                    ),
                    SymlinkActual::NotSymlink => write!(
                        f,
                        "warning: tenant '{tenant}' share symlink drift \u{2014} \
                         {tpath} is occupied by a real file or directory (expected symlink to {expected}); \
                         remove it manually, then run `tenant reload {tenant}`"
                    ),
                }
            }
            Finding::HostNotInShareGroup {
                tenant,
                host,
                group,
            } => write!(
                f,
                "warning: host '{host}' is not a member of group '{group}' \u{2014} \
                 files created by tenant '{tenant}' inside RW shares are not host-writable; \
                 run `tenant reload {tenant}` to fix"
            ),
            Finding::TenantKeychainAbsent { tenant } => write!(
                f,
                "warning: tenant '{tenant}' login keychain absent \u{2014} \
                 apps inside the tenant won't be able to persist credentials"
            ),
            Finding::StashAbsent { tenant } => write!(
                f,
                "warning: stashed password absent for tenant '{tenant}' \u{2014} \
                 a future `tenant shell` unlock pass would have nothing to retrieve; \
                 run `tenant destroy {tenant} && tenant create {tenant}` to re-bootstrap"
            ),
        }
    }
}

/// Byte-exact: `render_anchor` is deterministic — same profile +
/// tenant produces identical output across runs — so any difference
/// is real drift, not cosmetic.
pub fn anchor_body_matches(actual: &str, expected: &str) -> bool {
    actual == expected
}

/// Greps sudoers text for an UNQUALIFIED `Defaults env_delete`
/// directive that includes `var`. Recognized shapes:
/// - `Defaults env_delete += "X"`
/// - `Defaults env_delete = "X Y Z"` (space-separated list)
/// - `Defaults env_delete += X` (unquoted single var)
///
/// Qualified forms (`Defaults:user`, `Defaults>runas`, `Defaults@host`,
/// `Defaults!cmd`) are NOT accepted: each restricts scope and may not
/// cover `sudo -u <tenant>` invocations. Conservative-false: a
/// genuinely-covering qualified directive sees a false-positive nag;
/// the alternative is silently missing a real leak.
pub fn has_env_delete_for(policy: &str, var: &str) -> bool {
    for raw_line in policy.lines() {
        let line = raw_line.trim();
        let after_defaults = match line.strip_prefix("Defaults") {
            Some(rest) if rest.starts_with(|c: char| c.is_whitespace()) => rest.trim(),
            _ => continue,
        };
        // Word-boundary check so `env_delete_extra` doesn't false-match.
        let after_envdel = match after_defaults.strip_prefix("env_delete") {
            Some(rest) if rest.starts_with(|c: char| c.is_whitespace() || c == '=' || c == '+') => {
                rest.trim()
            }
            _ => continue,
        };
        let after_op = if let Some(rest) = after_envdel.strip_prefix("+=") {
            rest.trim()
        } else if let Some(rest) = after_envdel.strip_prefix('=') {
            rest.trim()
        } else {
            continue;
        };
        let value = after_op
            .trim_start_matches('"')
            .trim_end_matches('"')
            .trim();
        if value.split_whitespace().any(|tok| tok == var) {
            return true;
        }
    }
    false
}

/// Only `Allowed` produces a finding — `Denied` and `Unknown` are
/// the expected case for sensitive paths on a hardened host.
///
/// `Category::Keychain` returns `None` here: the keychain findings
/// (`TenantKeychainAbsent` / `StashAbsent`) come from
/// presence-probes, not the `probe_access_as_tenant` substrate that
/// drives this classifier, so the (category, AccessOutcome) shape
/// doesn't apply. The category is still useful as a structural label
/// on the `Finding` variants — future cross-cutting filters can group
/// by category without re-deriving from variant identity.
pub fn classify(category: Category, outcome: AccessOutcome) -> Option<Severity> {
    match (category, outcome) {
        (_, AccessOutcome::Denied) | (_, AccessOutcome::Unknown) => None,
        (Category::HostSecret, AccessOutcome::Allowed) => Some(Severity::Critical),
        (Category::HostHomeListing, AccessOutcome::Allowed) => Some(Severity::Warning),
        (Category::CrossTenant, AccessOutcome::Allowed) => Some(Severity::Warning),
        (Category::TenantArtifact, AccessOutcome::Allowed) => Some(Severity::Info),
        (Category::Keychain, AccessOutcome::Allowed) => None,
    }
}

/// Curated list of (category, access, path) tuples for one tenant on
/// one host. `others` may contain `tenant` — that entry is filtered
/// out so callers can pass an unfiltered tenant list. Output order is
/// stable across calls so operator diffs between runs are meaningful.
pub fn curated_paths(
    host: &str,
    tenant: &str,
    others: &[&str],
) -> Vec<(Category, AccessMode, PathBuf)> {
    let mut out: Vec<(Category, AccessMode, PathBuf)> = Vec::new();
    let host_home = format!("/Users/{host}");

    out.push((
        Category::HostHomeListing,
        AccessMode::List,
        PathBuf::from(&host_home),
    ));

    let secret_files: &[&str] = &[
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".aws/credentials",
        ".gnupg/private-keys-v1.d",
        ".config/gh/hosts.yml",
        ".claude.json",
        ".zsh_history",
    ];
    for sub in secret_files {
        out.push((
            Category::HostSecret,
            AccessMode::Read,
            PathBuf::from(format!("{host_home}/{sub}")),
        ));
    }

    let secret_dirs: &[&str] = &[
        ".ssh",
        ".aws",
        ".gnupg",
        ".config/gh",
        ".claude",
        "Library/Keychains",
        "Documents",
        "Desktop",
        "Downloads",
    ];
    for sub in secret_dirs {
        out.push((
            Category::HostSecret,
            AccessMode::List,
            PathBuf::from(format!("{host_home}/{sub}")),
        ));
    }

    for other in others {
        if *other == tenant {
            continue;
        }
        let other_home = format!("/Users/{other}");
        out.push((
            Category::CrossTenant,
            AccessMode::List,
            PathBuf::from(&other_home),
        ));
        out.push((
            Category::CrossTenant,
            AccessMode::List,
            PathBuf::from(format!("{other_home}/.ssh")),
        ));
    }

    for other in others {
        if *other == tenant {
            continue;
        }
        out.push((
            Category::TenantArtifact,
            AccessMode::Read,
            PathBuf::from(format!("{host_home}/.config/tenant/profiles/{other}.toml")),
        ));
        out.push((
            Category::TenantArtifact,
            AccessMode::Read,
            PathBuf::from(format!("/etc/pf.anchors/tenant-{other}")),
        ));
    }

    out
}

/// Match shape: a non-comment line whose trimmed form starts with
/// `Status: Enabled`. Canonical first line is e.g. `Status: Enabled
/// for 3 days 04:32:18` (uptime suffix varies); disabled reports
/// `Status: Disabled`. Prefix match distinguishes cleanly. Leading
/// whitespace is tolerated.
pub fn pf_status_enabled(status: &str) -> bool {
    for raw_line in status.lines() {
        let line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("Status: Enabled") {
            return true;
        }
    }
    false
}

/// Match shape: a non-comment line whose first three tokens are
/// `auth sufficient pam_tid.so`.
///
/// `sufficient` specifically: pam.d's stack semantics give
/// `sufficient` modules a short-circuit-on-success role — a passing
/// `pam_tid.so sufficient` authenticates via Touch ID alone (no
/// password fallback). `required` / `optional` may run Touch ID AND
/// still demand a password. Conservative-false: non-`sufficient`
/// reports as missing, prompting the operator to inspect.
pub fn has_pam_tid(pam_config: &str) -> bool {
    for raw_line in pam_config.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut toks = line.split_whitespace();
        let kind = toks.next();
        let control = toks.next();
        let module = toks.next();
        if kind == Some("auth") && control == Some("sufficient") && module == Some("pam_tid.so") {
            return true;
        }
    }
    false
}

/// Returns up to two `PfRuleDrift` findings: one if no `pass` rule
/// is present, one if no `block` rule is present.
///
/// Structural rather than exact-match: pfctl's output format isn't a
/// stable contract (numerical IPs vs hostnames, table-reference
/// reformatting) so exact-match would false-positive on cosmetic
/// drift. Structural shape catches "kernel anchor empty or missing
/// one of the two required rule classes".
///
/// Match shape: line begins with `pass ` or `block ` (case-sensitive
/// lowercase per pfctl's canonical output). Leading whitespace
/// tolerated; `#`-prefixed lines do not count.
pub fn pf_rule_presence_check(rules: &str, tenant: &str) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    let mut has_pass = false;
    let mut has_block = false;
    for raw in rules.lines() {
        let line = raw.trim_start();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with("pass ") {
            has_pass = true;
        }
        if line.starts_with("block ") {
            has_block = true;
        }
    }
    if !has_pass {
        out.push(Finding::PfRuleDrift {
            tenant: TenantUserName(tenant.to_string()),
            detail: "no `pass` rule in kernel anchor",
        });
    }
    if !has_block {
        out.push(Finding::PfRuleDrift {
            tenant: TenantUserName(tenant.to_string()),
            detail: "no `block` rule in kernel anchor",
        });
    }
    out
}

/// Match shape: any line containing the literal substring
/// `group:<group> allow`. Looser than substring-matching the full
/// canonical entry — macOS canonicalizes bit names on storage
/// (`read,write,execute,delete,append` →
/// `list,add_file,search,delete,add_subdirectory`), so any bit-list
/// comparison would false-negative. The group's `allow` entry
/// presence is the structural invariant; specific bits are the
/// operator's profile choice.
///
/// Word-boundary discipline: the `:` on the left and ` allow` on the
/// right prevent prefix-collision (`group:dev allow` ≠
/// `group:dev-tenant-share allow`).
pub fn has_group_acl_entry(listing: &str, group: &str) -> bool {
    let needle = format!("group:{group} allow");
    for raw_line in listing.lines() {
        let line = raw_line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        if line.contains(&needle) {
            return true;
        }
    }
    false
}

/// Render one curated-path line with its access-mode verb (Read vs
/// List on the same path produce two lines).
pub fn render_curated_line(access: AccessMode, path: &Path) -> String {
    let verb = match access {
        AccessMode::Read => "read",
        AccessMode::List => "list",
    };
    format!("  {} {}", verb, path.display())
}
