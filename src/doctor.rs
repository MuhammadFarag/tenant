//! Pure; all doctor I/O lives in `Tenants::doctor_*`.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::profile::{Inbound, InboundPosture};

use crate::domain::tenants::tenant_share_group_name;
use crate::domain::{
    AccessMode, AccessOutcome, GroupId, GroupName, HostUserName, TENANT_KEYCHAIN_FILE,
    TenantUserName, tenant_keychain_path,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    HostSecret,
    /// Enumerable file names can reveal activity even when files are protected.
    HostHomeListing,
    CrossTenant,
    TenantArtifact,
    // TODO(smell): `Keychain` is never constructed and never reaches `classify` — remove it or give keychain findings their own axis
    Keychain,
}

/// Non-obvious severities: `EnvLeak` is info (launchd's agent socket is private to the
/// operator, so the inherited path is unusable by default); `PfDisabled` is critical (every anchor is
/// inert). `SymlinkDrift` compares targets string-exact — the profile names
/// intent.
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
    PfConfAnchorRefMissing {
        tenant: TenantUserName,
    },
    AnchorBodyDrift {
        tenant: TenantUserName,
    },
    /// Intended, but declared ports are reachable by peer tenants too — pf
    /// can't see the initiator on shared 127.0.0.1. `ports` is non-empty.
    InboundExposure {
        tenant: TenantUserName,
        ports: Vec<u16>,
    },
    /// A temporary widen left behind outside a live shell session.
    InboundPermissive {
        tenant: TenantUserName,
    },
    InboundPermissiveByProfile {
        tenant: TenantUserName,
    },
    /// pf resolves hostnames once, at load; CDN answers rotate away from that set.
    EgressResolveDrift {
        tenant: TenantUserName,
        host: String,
        unloaded: Vec<IpAddr>,
    },
    AclDrift {
        tenant: TenantUserName,
        host_path: PathBuf,
        group: GroupName,
    },
    CoworkAclDrift {
        tenant: TenantUserName,
        path: PathBuf,
        group: GroupName,
    },
    CoworkDirAbsent {
        tenant: TenantUserName,
        path: PathBuf,
    },
    /// Inheritable ACEs land only on creation in place; a rename keeps the ACL it was born with.
    TreeAclDrift {
        tenant: TenantUserName,
        root: PathBuf,
        group: GroupName,
        paths: Vec<PathBuf>,
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
    PrimaryGroupDrift {
        tenant: TenantUserName,
        expected: GroupId,
        actual: GroupId,
    },
    /// OAuth-class apps inside the tenant hit `errSecNoSuchKeychain`.
    TenantKeychainAbsent {
        tenant: TenantUserName,
    },
    StashAbsent {
        tenant: TenantUserName,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymlinkActual {
    Absent,
    WrongTarget(PathBuf),
    NotSymlink,
}

impl Finding {
    /// Every reapply restores the pf.conf reference before it reloads.
    pub fn repaired_by_any_reapply(&self) -> bool {
        matches!(self, Finding::PfConfAnchorRefMissing { .. })
    }

    pub fn severity(&self) -> Severity {
        match self {
            Finding::FilesystemExposure { severity, .. } => *severity,
            Finding::EnvLeak { .. } => Severity::Info,
            Finding::PfRuleDrift { .. } => Severity::Warning,
            Finding::TouchIdMissing => Severity::Info,
            Finding::PfDisabled => Severity::Critical,
            Finding::PfConfAnchorRefMissing { .. } => Severity::Critical,
            Finding::AnchorBodyDrift { .. } => Severity::Warning,
            Finding::InboundExposure { .. } => Severity::Info,
            Finding::InboundPermissive { .. } => Severity::Warning,
            Finding::InboundPermissiveByProfile { .. } => Severity::Info,
            Finding::EgressResolveDrift { .. } => Severity::Warning,
            Finding::AclDrift { .. } => Severity::Warning,
            Finding::CoworkAclDrift { .. } => Severity::Warning,
            Finding::CoworkDirAbsent { .. } => Severity::Warning,
            Finding::TreeAclDrift { .. } => Severity::Warning,
            Finding::SymlinkDrift { .. } => Severity::Warning,
            Finding::HostNotInShareGroup { .. } => Severity::Warning,
            Finding::PrimaryGroupDrift { .. } => Severity::Critical,
            Finding::TenantKeychainAbsent { .. } => Severity::Warning,
            Finding::StashAbsent { .. } => Severity::Warning,
        }
    }

    /// `None` for `FilesystemExposure`: the right fix depends on operator
    /// intent, which detection can't know.
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
            Finding::InboundExposure { tenant, ports } => {
                let port_list = render_port_list(ports);
                Some(format!(
                    "Why this matters
  Tenant '{tenant}'s profile declares inbound loopback ports {port_list}, so
  the anchor passes loopback TCP to those ports. This is intended
  surface \u{2014} a tenant-local service (a dev web server, an OAuth
  redirect target) needs them open. But restricted is SURFACE-REDUCTION,
  NOT host-vs-peer isolation: a declared port is reachable by the host
  AND by every peer tenant, because pf cannot see the initiator across
  the shared 127.0.0.1 loopback. Treat a declared port as open to the
  whole machine, not just this tenant.

Recommended fix
  Nothing to fix \u{2014} this is informational. If a port no longer needs to
  be reachable, remove it from the `[inbound]` ports list in the profile
  and run `tenant reload {tenant}` to re-render the anchor at the narrowed
  surface.

Side-effects to know about
  \u{2022} Removing a declared port narrows the surface but also blocks the
    tenant from reaching its OWN service on that port \u{2014} a tenant
    cannot reach an undeclared loopback port. Re-declare it if the
    tenant-local flow breaks.
  \u{2022} UDP loopback is unfiltered (TCP only); a UDP service on any port
    stays reachable regardless of this list.

Alternative
  tenant inbound {tenant} permissive
  Temporarily opens ALL loopback ports for an ad-hoc flow (e.g. OAuth on
  a random port). Narrows back on `tenant inbound {tenant} restricted` or on
  `tenant shell {tenant}` entry. Prefer declaring the specific port over a
  blanket widen when the port is known."
                ))
            }
            Finding::TreeAclDrift {
                tenant,
                root,
                paths,
                ..
            } => {
                let shown: Vec<String> = paths
                    .iter()
                    .take(20)
                    .map(|p| format!("  {}", p.display()))
                    .collect();
                let more = match paths.len().saturating_sub(20) {
                    0 => String::new(),
                    n => format!("\n  \u{2026} and {n} more"),
                };
                Some(format!(
                    "Why this matters
  Entries under {} carry the share-group ACE only when created in
  place. Tools that write via temp file + rename (Gradle, Maven, cargo,
  npm, Android Studio) move in objects with no ACE and an owner-only
  mode, so the other side gets EACCES on them:
{}{more}

Recommended fix
  tenant reload {tenant}
  Re-walks the tree and re-applies the ACE. Or keep build output
  outside the shared tree (e.g. a Gradle init script redirecting
  `buildDir`).",
                    root.display(),
                    shown.join("\n"),
                ))
            }
            Finding::EgressResolveDrift { tenant, host, .. } => Some(format!(
                "Why this matters
  pf resolves each allowlisted hostname once, when the anchor loads.
  {host} now answers with addresses outside that set, so the tenant's
  connections to it hang until they time out. CDN-fronted hosts
  (Google, Fastly, Cloudflare, CloudFront) rotate their answers every
  few minutes, so a reload only helps until the next rotation.

Recommended fix
  Pin the provider's published CIDR ranges in an include fragment
  instead of the hostname (see `tenant help profile`, Egress), then
  run `tenant reload {tenant}`.

Alternative
  tenant reload {tenant}
  Re-resolves every hostname now. Enough for a host whose address
  moved once; a stopgap for a CDN."
            )),
            Finding::InboundPermissiveByProfile { tenant } => Some(format!(
                "Why this matters
  Tenant '{tenant}'s profile declares `[inbound] posture = \"permissive\"`, so
  every reapply renders all loopback TCP ports open. JVM build tools
  (Gradle, Maven, sbt, Bazel) need this: they fork workers that report
  back over random loopback ports. But every listener the tenant opens
  is reachable by the host AND by every peer tenant (pf can't see the
  initiator across shared 127.0.0.1).

Recommended fix
  Nothing to fix \u{2014} this is informational. If the tenant no longer
  needs it, set `posture = \"restricted\"` (or remove it) in the profile
  and run `tenant reload {tenant}`."
            )),
            Finding::InboundPermissive { tenant } => Some(format!(
                "Why this matters
  Tenant '{tenant}'s anchor is in the PERMISSIVE inbound posture: every
  loopback TCP port is open, not just the profile-declared ones.
  Permissive is meant to be temporary \u{2014} the OAuth-on-a-random-port
  window \u{2014} and normally narrows back automatically on `tenant shell`
  entry. Finding it permissive outside a live shell session means a
  prior widen was left behind: every loopback port the tenant binds is
  reachable by the host AND by every peer tenant (pf can't see the
  initiator across shared 127.0.0.1).

Recommended fix
  tenant inbound {tenant} restricted
  Re-renders the anchor at the restricted posture (profile-declared
  ports only, or locked if none) and reloads pf, dropping the
  all-ports inbound pass.

Side-effects to know about
  \u{2022} The pfctl reload causes a sub-millisecond packet-filter disruption.
  \u{2022} Any tenant-local service listening on a non-declared loopback port
    stops being reachable once narrowed \u{2014} declare the port in the
    profile's `[inbound]` list if the flow must persist.
  \u{2022} `tenant shell {tenant}` also auto-narrows inbound on entry, so the next
    interactive session would have corrected this on its own.

Alternative
  Re-render via any reapply verb
  `tenant reload {tenant}`, `tenant mode {tenant} runtime`, or entering
  `tenant shell {tenant}` all re-render the anchor at steady inbound
  (restricted), narrowing the same way. Use `tenant inbound` when the
  ONLY change needed is the inbound narrow."
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
            Finding::PfConfAnchorRefMissing { tenant } => Some(format!(
                "Why this matters
  /etc/pf.conf carries no `anchor \"tenant-{tenant}\"` / `load anchor` pair,
  so pf never loads /etc/pf.anchors/tenant-{tenant}. The tenant's egress
  allowlist and inbound rules are not enforcing anything \u{2014} the anchor
  file on disk may be perfect and it makes no difference. The usual
  cause is a macOS update: it replaces /etc/pf.conf with Apple's stock
  file, and every tenant loses its reference at once. A reload that ran
  since reported success while loading a file that never named the
  tenant.

Recommended fix
  tenant reload {tenant}
  Re-adds the two lines, re-renders the anchor, and reloads pf. `tenant
  mode` and `tenant shell` do the same on their way in.

Side-effects to know about
  \u{2022} None beyond the reload itself; the added lines are the ones `tenant
    create` writes.
  \u{2022} Do not restore /etc/pf.conf.tenant-backup: it is the rollback
    snapshot from the last create or destroy and omits every tenant
    created since. `tenant reload` rebuilds from the live tenant set.
  \u{2022} While the reference is missing, doctor skips this tenant's
    kernel-rule checks \u{2014} an empty kernel anchor is this finding's
    consequence, not a second problem.

Alternative
  tenant reload
  Without a name, repairs every tenant: after an update it is rarely
  just one. For a scheduled check, `tenant doctor --strict` exits 2 on
  this finding."
            )),
            Finding::EnvLeak { var } => Some(format!(
                "Why this matters
  macOS sudo runs with env_reset and keeps {var} on its default
  env_keep list, so `tenant shell` sessions inherit the path to your
  ssh-agent socket. launchd's agent socket sits in a directory only you
  can open, so the tenant gets Permission denied and can't use your keys.
  It matters if you run an agent whose socket other users can reach (one
  started with `ssh-agent -a <path>`, or a third-party agent).

Recommended fix
  sudo visudo -f /etc/sudoers.d/tenant
  Add `Defaults env_keep -= \"{var}\"`. visudo locks and validates the
  file before saving; a drop-in survives the macOS updates that replace
  /etc/sudoers. The directive must be unqualified (no `Defaults:user`, no
  `Defaults>runas`) to cover `sudo -u <tenant>`.

Side-effects to know about
  \u{2022} No sudo command keeps your agent afterwards (`sudo git ...` included).
  \u{2022} `env_delete` looks like the fix but is ignored while env_reset is on."
            )),
            Finding::TouchIdMissing => Some(
                "Why this matters
  Neither /etc/pam.d/sudo nor /etc/pam.d/sudo_local enables Touch ID for
  sudo. This isn't a correctness drift \u{2014} sudo still works via password
  \u{2014} it's an optional recommendation aligned with the project's locked
  no-NOPASSWD-sudoers stance. Touch ID makes sudo prompts faster (a
  fingerprint beats typing a password) AND adds a second auth factor
  (fingerprint plus sudoers membership) instead of just one (sudoers
  membership). Info-tier because absence doesn't compromise isolation,
  and declining is a valid choice \u{2014} this is an offer, not a defect.

Recommended fix
  tenant setup
  Offers to append `auth sufficient pam_tid.so` to /etc/pam.d/sudo_local
  \u{2014} the OS-update-safe customization file that /etc/pam.d/sudo
  includes (editing /etc/pam.d/sudo directly is clobbered by macOS
  updates). `sufficient` short-circuits the auth stack on a Touch ID
  hit and falls through to password on a miss. You'll be asked for your
  password once to apply it (Touch ID isn't on yet).

Side-effects to know about
  \u{2022} Next sudo invocation pops a Touch ID prompt instead of (or
    before) the password prompt. Touch your sensor within ~10 seconds.
  \u{2022} If Touch ID hardware isn't available or isn't registered (System
    Settings → Touch ID & Password), pam_tid.so falls through to the
    next module \u{2014} sudo still works, just without the short-circuit.
  \u{2022} Inside tmux or screen, the Touch ID prompt won't appear without
    the third-party pam_reattach module.

Alternative
  Ignore this finding if you prefer typing your password. It stays an
  info-tier note, never trips `--strict`, and `tenant setup` will offer
  again whenever you change your mind."
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
  sudo chmod -R +a \"group:{group} allow read,write,execute,delete,append,file_inherit,directory_inherit\" {path}
  Re-applies just this one entry. Use when `tenant reload` is blocked
  by an unrelated refusal. The bit list shown is the `rw` default;
  for read-only shares omit `write,delete,append`. `sudo` is required
  because files written by the tenant inside the share (caches, build
  output) are tenant-owned, and POSIX requires owner-or-root to modify
  ACLs."
                ))
            }
            Finding::CoworkAclDrift {
                tenant,
                path,
                group,
            } => {
                let path = path.display();
                Some(format!(
                    "Why this matters
  The co-working directory {path} is the host\u{2194}tenant collaboration
  surface for tenant '{tenant}'. Files created on either side inside
  this directory inherit the `{group}` group's rw ACE (via
  `file_inherit,directory_inherit`), which is what keeps the operator
  and the tenant mutually reachable. The current `ls -lde` listing is
  missing the group entry on the directory itself \u{2014} new files
  created inside will NOT inherit the rw bits, and existing files
  that previously inherited may become inaccessible from the other
  side. Common causes: a manual `chmod -a` on the cowork-dir root, a
  Time Machine restore that dropped extended ACLs, or a legacy
  tenant whose cowork dir was never provisioned with the ACE.

Recommended fix
  tenant reload {tenant}
  Re-runs the full reapply (PF + shares + cowork dir), which includes
  `EnsureCoworkDir`'s `chmod -R +a` pass on {path}. macOS `chmod +a`
  is natively idempotent; safe to run regardless of the current ACL
  state. `tenant mode` and `tenant shell` do NOT touch the cowork dir
  under their light reapply scope \u{2014} reload is the canonical
  remediation.

Side-effects to know about
  \u{2022} The PF anchor is re-rendered at runtime tier as a side effect
    of `tenant reload`. If install-tier widening was active when the
    operator last ran `tenant mode {tenant} install`, the narrow drops
    it; rerun `mode install` afterward if still needed.
  \u{2022} The recursive ACL pass walks every existing child of the
    cowork dir. On a populated workspace this may take a few seconds.

Alternative
  sudo chmod -R +a \"group:{group} allow read,write,execute,delete,append,file_inherit,directory_inherit\" {path}
  Re-applies just the cowork-dir ACL grant. Same bit list
  `EnsureCoworkDir` uses; `sudo` is required because files inside the
  cowork dir are tenant-owned, and POSIX requires owner-or-root to
  modify ACLs."
                ))
            }
            Finding::CoworkDirAbsent { tenant, path } => {
                let path = path.display();
                let group = tenant_share_group_name(tenant.as_str());
                Some(format!(
                    "Why this matters
  The co-working directory {path} is the per-tenant
  collaboration surface (host operator + tenant share writable access
  via the `{group}` group, mode 2770, inheritable rw ACL).
  It's missing from disk \u{2014} `rm -rf` from the host side, a
  Time Machine restore that skipped the path, or a legacy tenant
  whose cowork dir was never provisioned. The tenant has no shared
  workspace until it's re-provisioned.

Recommended fix
  tenant reload {tenant}
  Re-runs the full reapply (PF + shares + cowork dir), which includes
  `EnsureCoworkDir`'s four-call sequence: `mkdir -p` + `chown` +
  `chmod 2770` + `chmod -R +a` for the inheritable rw ACE. All four
  calls are natively idempotent; safe to re-run.

Side-effects to know about
  \u{2022} The PF anchor is re-rendered at runtime tier as a side effect
    of `tenant reload`. If install-tier widening was active when the
    operator last ran `tenant mode {tenant} install`, the narrow drops
    it; rerun `mode install` afterward if still needed.
  \u{2022} The directory is created empty. Any files that previously
    lived inside (if the dir was rm'd, not just lost its ACE) are
    NOT recovered \u{2014} restore from backup separately if needed.

Alternative
  sudo mkdir -p {path} && sudo chown $USER:{group} {path} && sudo chmod 2770 {path} && sudo chmod -R +a \"group:{group} allow read,write,execute,delete,append,file_inherit,directory_inherit\" {path}
  Re-provisions just the cowork dir manually. Same four substrate
  calls `EnsureCoworkDir` runs. `sudo` is required for ownership and
  mode-bit changes outside the operator's home."
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
            Finding::PrimaryGroupDrift {
                tenant,
                expected,
                actual,
            } => {
                let group = tenant_share_group_name(tenant.as_str());
                Some(format!(
                    "Why this matters
  Tenant '{tenant}' was created with primary group {group} ({expected});
  its record now says {actual}. When that is 20 (staff) \u{2014} the value macOS
  updates write back \u{2014} the tenant gains group access to every staff-group
  directory on the host, including /Users/<operator> (mode 750, group
  staff), and stops being a member of {group}, so every declared share
  denies it. The isolation the tenant depends on is inverted, not just
  weakened. Cause on record: the update's templateMigrator re-creating
  local user records at first boot.

Recommended fix
  tenant reload {tenant}
  Full reapply re-asserts the primary group from the live share-group
  record, then reapplies shares. Processes already running as the tenant
  keep their old group set until they restart.

Side-effects to know about
  \u{2022} Group caches may lag: `sudo dsmemberutil flushcache` if a share still
    denies after the reload.

Alternative
  sudo dscl . -create /Users/{tenant} PrimaryGroupID {expected}
  The single write reload performs; skips the share reapply."
                ))
            }
            Finding::TenantKeychainAbsent { tenant } => {
                let keychain_path = tenant_keychain_path(tenant.as_str());
                Some(format!(
                    "Why this matters
  Tenant '{tenant}'s keychain at {keychain_path}
  is absent. Claude OAuth and other credential-stashing apps running
  inside the tenant fire `errSecNoSuchKeychain` warnings and have no
  persistent place to write tokens \u{2014} every login interaction
  re-prompts because nothing survives across sessions. The most common
  causes are a tenant created before the keychain moved off the
  `login.keychain-db` name (macOS 26.6 binds that name to the user's
  Data Protection keybag and refuses unlocks from the operator's
  session), a manual `rm` against the tenant's Library/Keychains
  directory, or a partial-create that left the file off disk.

Recommended fix
  sudo -iu {tenant} security create-keychain -p \"$(security find-generic-password -a {tenant} -s tenant-{tenant} -w)\" {TENANT_KEYCHAIN_FILE}
  sudo -iu {tenant} security default-keychain -s {TENANT_KEYCHAIN_FILE}
  sudo -iu {tenant} security list-keychains -s {TENANT_KEYCHAIN_FILE}
  sudo -iu {tenant} security set-keychain-settings {TENANT_KEYCHAIN_FILE}
  Creates the keychain keyed to the password already stashed in the
  operator's keychain, makes it the tenant's default and sole
  search-list entry, and clears auto-lock \u{2014} the same four steps
  `tenant create` runs, without touching the tenant's home. Step one
  fails if the stash is absent; doctor reports that separately and
  the alternative below covers it.

Side-effects to know about
  \u{2022} The new keychain starts empty: apps inside the tenant
    re-authenticate once. Anything stored in a pre-26.6
    `login.keychain-db` stays in that file, unused.
  \u{2022} The password is on the command line for the duration of step
    one \u{2014} the same exposure `tenant create` has today.

Alternative
  tenant destroy {tenant} && tenant create {tenant}
  Re-bootstraps the tenant from scratch with a fresh password and
  stash. Moves the tenant's home to /Users/Deleted Users/{tenant}/;
  use it when the stash is gone too."
                ))
            }
            Finding::StashAbsent { tenant } => Some(format!(
                "Why this matters
  The operator's login keychain doesn't carry a generic-password entry
  under (account={tenant}, service=tenant-{tenant}). `tenant shell` and
  `tenant bootstrap` read that entry to retrieve the password that
  protects the tenant's `{TENANT_KEYCHAIN_FILE}`; without the stash they
  refuse to enter, and after a reboot the tenant's keychain stays
  locked so OAuth tokens it carries become unreachable. The most
  common cause is a manual `security delete-generic-password` run
  against the operator's keychain, or a partial-create that landed
  the keychain but missed the stash.

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
                "info: sudo forwards {var} into 'tenant shell' sessions \u{2014} harmless while \
                 your agent's socket sits in launchd's private directory; add \
                 `Defaults env_keep -= \"{var}\"` to /etc/sudoers.d/tenant to stop it"
            ),
            Finding::PfRuleDrift { tenant, detail } => write!(
                f,
                "warning: tenant '{tenant}' pf anchor drift \u{2014} {detail}; \
                 run `tenant mode {tenant} runtime` to re-render and reload"
            ),
            Finding::TouchIdMissing => write!(
                f,
                "info: Touch ID for sudo not detected \u{2014} \
                 run `tenant setup` to enable it \
                 (or ignore if you prefer password auth)"
            ),
            Finding::PfDisabled => write!(
                f,
                "critical: pf is globally disabled \u{2014} no tenant firewall \
                 is enforcing; run `sudo pfctl -e` to enable"
            ),
            Finding::PfConfAnchorRefMissing { tenant } => write!(
                f,
                "critical: tenant '{tenant}' anchor not referenced from /etc/pf.conf \u{2014} \
                 its egress allowlist is not loaded; \
                 run `tenant reload {tenant}` to restore the reference"
            ),
            Finding::AnchorBodyDrift { tenant } => write!(
                f,
                "warning: tenant '{tenant}' anchor file drift \u{2014} \
                 on-disk body differs from profile-derived render; \
                 run `tenant mode {tenant} runtime` to re-render and reload"
            ),
            Finding::InboundExposure { tenant, ports } => {
                let (noun, list) = if ports.len() == 1 {
                    ("port", render_port_list(ports))
                } else {
                    ("ports", render_port_list(ports))
                };
                write!(
                    f,
                    "info: tenant '{tenant}' inbound loopback open on {noun} {list} \u{2014} \
                     reachable by host + peer tenants"
                )
            }
            Finding::TreeAclDrift {
                tenant,
                root,
                group,
                paths,
            } => {
                let (count, verb) = match paths.len() {
                    1 => ("1 entry".to_string(), "lacks"),
                    n => (format!("{n} entries"), "lack"),
                };
                write!(
                    f,
                    "warning: tenant '{tenant}' {count} under {} {verb} the '{group}' ACE \
                     (moved in, not created in place) \u{2014} run `tenant reload {tenant}` \
                     to re-walk",
                    root.display()
                )
            }
            Finding::EgressResolveDrift {
                tenant,
                host,
                unloaded,
            } => write!(
                f,
                "warning: tenant '{tenant}' egress host {host} now resolves to {}, outside the \
                 loaded pf table \u{2014} CDN-backed? pin its CIDR ranges (see `tenant help \
                 profile`), or `tenant reload {tenant}` to re-resolve",
                unloaded
                    .iter()
                    .map(IpAddr::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Finding::InboundPermissiveByProfile { tenant } => write!(
                f,
                "info: tenant '{tenant}' inbound posture is permissive (profile) \u{2014} \
                 every loopback port the tenant opens is reachable by host + peer tenants"
            ),
            Finding::InboundPermissive { tenant } => write!(
                f,
                "warning: tenant '{tenant}' inbound loopback is PERMISSIVE \u{2014} \
                 all ports open to host + peer tenants; \
                 run `tenant inbound {tenant} restricted` to narrow"
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
            Finding::CoworkAclDrift {
                tenant,
                path,
                group,
            } => write!(
                f,
                "warning: tenant '{tenant}' co-working directory ACL drift \u{2014} \
                 group '{group}' missing on {}; \
                 run `tenant reload {tenant}` to re-apply",
                path.display(),
            ),
            Finding::CoworkDirAbsent { tenant, path } => write!(
                f,
                "warning: tenant '{tenant}' co-working directory missing at {}; \
                 run `tenant reload {tenant}` to re-create",
                path.display(),
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
            Finding::PrimaryGroupDrift {
                tenant,
                expected,
                actual,
            } => {
                let group = tenant_share_group_name(tenant.as_str());
                write!(
                    f,
                    "critical: tenant '{tenant}' primary group is gid {actual}, \
                     not {group} ({expected}) \u{2014} \
                     the tenant has joined another group and left its share group; \
                     run `tenant reload {tenant}` to re-assert"
                )
            }
            Finding::TenantKeychainAbsent { tenant } => write!(
                f,
                "warning: tenant '{tenant}' keychain absent \u{2014} \
                 apps inside the tenant won't be able to persist credentials"
            ),
            Finding::StashAbsent { tenant } => write!(
                f,
                "warning: stashed password absent for tenant '{tenant}' \u{2014} \
                 `tenant shell` and `tenant bootstrap` can't unlock the keychain without it; \
                 run `tenant destroy {tenant} && tenant create {tenant}` to re-bootstrap"
            ),
        }
    }
}

/// Byte-exact: `render_anchor` is deterministic, so any difference is drift.
pub fn anchor_body_matches(actual: &str, expected: &str) -> bool {
    actual == expected
}

/// Replays unqualified `Defaults` entries in order, as sudo does: `env_keep -=` removes the
/// var, `+=` adds it back, `=` replaces the whole list. Under env_reset (the macOS default)
/// that list is what forwards; `env_delete` is ignored. Qualified forms (`Defaults:user`,
/// `>runas`, `@host`, `!cmd`) may not cover `sudo -u <tenant>`, so they don't count.
pub fn sudo_strips_env_var(policy: &str, var: &str) -> bool {
    let mut stripped = false;
    for line in policy.lines() {
        let Some(rest) = line.trim().strip_prefix("Defaults") else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        for entry in rest.split(',') {
            let Some(rest) = entry.trim().strip_prefix("env_keep") else {
                continue;
            };
            let rest = rest.trim_start();
            let (op, list) = if let Some(list) = rest.strip_prefix("-=") {
                ('-', list)
            } else if let Some(list) = rest.strip_prefix("+=") {
                ('+', list)
            } else if let Some(list) = rest.strip_prefix('=') {
                ('=', list)
            } else {
                continue;
            };
            let listed = list
                .trim()
                .trim_matches('"')
                .split_whitespace()
                .any(|token| token == var);
            stripped = match op {
                '-' => stripped || listed,
                '+' => stripped && !listed,
                _ => !listed,
            };
        }
    }
    stripped
}

fn render_port_list(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `table_show` is `pfctl -t <table> -T show` output: one address or CIDR per line.
pub fn classify_egress_resolve_drift(
    tenant: &TenantUserName,
    host: &str,
    resolved: &[IpAddr],
    table_show: &str,
) -> Option<Finding> {
    let entries: Vec<&str> = table_show
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('!'))
        .collect();
    let unloaded: Vec<IpAddr> = resolved
        .iter()
        .copied()
        .filter(|ip| !entries.iter().any(|entry| table_entry_covers(entry, *ip)))
        .collect();
    if unloaded.is_empty() {
        return None;
    }
    Some(Finding::EgressResolveDrift {
        tenant: tenant.clone(),
        host: host.to_string(),
        unloaded,
    })
}

fn table_entry_covers(entry: &str, ip: IpAddr) -> bool {
    let (addr, prefix) = match entry.split_once('/') {
        Some((addr, prefix)) => (addr, prefix.parse::<u32>().ok()),
        None => (entry, None),
    };
    let Ok(net) = addr.parse::<IpAddr>() else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = u32::MAX
                .checked_shl(32 - prefix.unwrap_or(32).min(32))
                .unwrap_or(0);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = u128::MAX
                .checked_shl(128 - prefix.unwrap_or(128).min(128))
                .unwrap_or(0);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

/// Observed permissive wins over declared ports: the live surface is wider
/// than intent.
pub fn classify_inbound_exposure(
    tenant: &TenantUserName,
    inbound: &Inbound,
    permissive: bool,
) -> Option<Finding> {
    let ports = &inbound.ports;
    if permissive && inbound.posture == InboundPosture::Permissive {
        return Some(Finding::InboundPermissiveByProfile {
            tenant: tenant.clone(),
        });
    }
    if permissive {
        return Some(Finding::InboundPermissive {
            tenant: tenant.clone(),
        });
    }
    if ports.is_empty() {
        return None;
    }
    Some(Finding::InboundExposure {
        tenant: tenant.clone(),
        ports: ports.to_vec(),
    })
}

/// Only `Allowed` produces a finding — `Denied` and `Unknown` are the
/// expected case on a hardened host.
pub fn classify(category: Category, outcome: AccessOutcome) -> Option<Severity> {
    match (category, outcome) {
        (_, AccessOutcome::Denied) | (_, AccessOutcome::Unknown) => None,
        (Category::HostSecret, AccessOutcome::Allowed) => Some(Severity::Critical),
        (Category::HostHomeListing, AccessOutcome::Allowed) => Some(Severity::Warning),
        (Category::CrossTenant, AccessOutcome::Allowed) => Some(Severity::Warning),
        (Category::TenantArtifact, AccessOutcome::Allowed) => Some(Severity::Warning),
        (Category::Keychain, AccessOutcome::Allowed) => None,
    }
}

/// `others` may include `tenant` (skipped). Order is stable so run-to-run
/// diffs are meaningful.
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

/// Prefix match: pfctl appends a varying uptime (`Status: Enabled for 3 days …`).
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

/// `sufficient` only: `required` / `optional` may run Touch ID and still
/// demand a password, so they report as missing.
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

/// Structural, not exact: pfctl's output isn't a stable contract (IPs vs
/// hostnames, table reformatting), so exact-match false-positives.
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

/// Ignores the bit list: macOS canonicalizes bit names on storage
/// (`read,write` → `list,add_file`, …), so comparing bits false-negatives.
/// `:` and ` allow` bound the name so `dev` can't match `dev-tenant-share`.
/// Parses `ls -leRA <root>`: the root's entries come first, headerless; each subdirectory
/// follows as a blank line + `<path>:` header. Names start after 8 fields (mode, links,
/// owner, group, size, 3-token date).
pub fn entries_missing_group_ace(listing: &str, root: &Path, group: &str) -> Vec<PathBuf> {
    let direct = format!("group:{group} allow");
    let inherited = format!("group:{group} inherited allow");
    let mut dir = root.to_path_buf();
    let mut pending: Option<(PathBuf, bool)> = None;
    let mut missing = Vec::new();
    let mut flush = |pending: &mut Option<(PathBuf, bool)>| {
        if let Some((path, false)) = pending.take() {
            missing.push(path);
        }
    };
    let mut after_blank = false;
    for line in listing.lines() {
        if line.is_empty() {
            flush(&mut pending);
            after_blank = true;
            continue;
        }
        if after_blank && line.ends_with(':') {
            dir = PathBuf::from(line.trim_end_matches(':'));
            after_blank = false;
            continue;
        }
        after_blank = false;
        if line.starts_with(' ') {
            if let Some((_, has_ace)) = pending.as_mut() {
                *has_ace |= line.contains(&direct) || line.contains(&inherited);
            }
            continue;
        }
        flush(&mut pending);
        if line.starts_with("total ") || line.starts_with('l') {
            continue;
        }
        if let Some(name) = after_fields(line, 8) {
            pending = Some((dir.join(name), false));
        }
    }
    flush(&mut pending);
    missing
}

/// The rest of `line` after `n` whitespace-separated fields, byte-exact.
fn after_fields(line: &str, n: usize) -> Option<&str> {
    let mut rest = line;
    for _ in 0..n {
        rest = rest.trim_start();
        rest = &rest[rest.find(char::is_whitespace)?..];
    }
    let name = rest.trim_start();
    (!name.is_empty()).then_some(name)
}

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

pub fn render_curated_line(access: AccessMode, path: &Path) -> String {
    let verb = match access {
        AccessMode::Read => "read",
        AccessMode::List => "list",
    };
    format!("  {} {}", verb, path.display())
}
