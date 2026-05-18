//! Filesystem-exposure detection: pure functions for the curated path
//! list, severity classification, and finding rendering.
//!
//! # Architecture
//!
//! The doctor verb operates in three layers:
//! 1. **Substrate (`Executor::probe_access_as_tenant`)** — invokes
//!    `sudo -n -u <tenant> /usr/bin/test -<mode> <path>` and reports
//!    Allowed / Denied / Unknown. Probe-as-tenant subsumes ACL +
//!    sandbox + TCC semantics at the kernel level; doctor doesn't
//!    re-implement them.
//! 2. **This module (`doctor`)** — curated path list and pure
//!    classification. Knows the project's threat model (which paths
//!    matter, what severity each category produces). No I/O.
//! 3. **Writer (`accounts::Writer::doctor_tenant`)** — orchestrates
//!    probes for one tenant, collects findings, drives the Reporter.
//!    Bare `tenant doctor` runs the all-tenants walk on top.
//!
//! The curated list is fixed (not configurable); verbose mode surfaces
//! the list to the operator so the bounded scope is operator-visible.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::executor::{AccessMode, AccessOutcome};
use crate::ids::{GroupName, HostUserName, TenantUserName};

/// Severity tier of a finding. Order is load-bearing: `--strict` exit
/// code logic consumes `findings.iter().map(severity).max()` to decide
/// between exit 0 (no findings worse than info), 1 (warning max), or
/// 2 (critical present). Info < Warning < Critical.
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

/// Threat-category for a curated path. The severity each category
/// produces (when a probe comes back `Allowed`) is locked by
/// `classify` — see the matrix there.
///
/// The sudoers env-leak finding is rendered separately via
/// `Finding::EnvLeak`; it has no curated path and therefore no
/// `Category` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Host-side secret targets — private keys, cloud credentials,
    /// session tokens, command history. Tenant-readability is a
    /// critical exposure (the agent could exfiltrate without any
    /// network access).
    HostSecret,
    /// Top-level `/Users/<host>/` listability — if a tenant can
    /// `ls /Users/host`, they can enumerate file names that might
    /// themselves reveal sensitive activity even if individual
    /// files are protected. Less severe than reading a secret
    /// directly: warning-tier.
    HostHomeListing,
    /// Cross-tenant exposure — tenant A's access to tenant B's home
    /// directory or `.ssh/` directory. Warning-tier rather than
    /// critical because the leakage is between two operator-managed
    /// principals (no third-party data involved), but still a
    /// boundary the design assumes is intact.
    CrossTenant,
    /// Tenant-project artifacts on the host (per-tenant profiles in
    /// the host's `~/.config/tenant/profiles/`, per-tenant PF anchor
    /// files in `/etc/pf.anchors/`). The anchor files specifically
    /// are mode 0644 by design, so they WILL surface as `Allowed`;
    /// we report as `info` rather than warning because the exposure
    /// is intentional and the operator only needs to know it exists,
    /// not act on it.
    TenantArtifact,
}

/// A doctor-detected exposure.
///
/// `FilesystemExposure` is the per-tenant per-path probe finding from
/// `probe_access_as_tenant` returning Allowed.
///
/// `EnvLeak` is the host-wide finding from the sudoers env-policy
/// check: if `/etc/sudoers` (plus drop-ins) doesn't `env_delete +=
/// "<var>"` an inherited env var, that var propagates from the
/// operator's session into every `sudo -iu <tenant>`. The canonical
/// case is SSH_AUTH_SOCK — macOS ssh-agent's socket gets inherited
/// so the tenant can `ssh` anywhere the host has cached keys for.
/// Warning-tier (not critical) because the leak depends on the
/// operator's session env actually holding the var; recovery is a
/// one-line `/etc/sudoers` edit. The finding line names the directive
/// shape so the operator's fix is mechanical.
///
/// `PfRuleDrift` is the per-tenant kernel-side finding: the kernel's
/// anchor for `tenant-<name>` is missing a structural rule (no `pass`
/// rule, no `block return` rule, or both — empty anchor). Warning-tier
/// because the drift is recoverable via `tenant mode <name> runtime`
/// (re-renders + reloads the anchor). `detail` names which structural
/// rule is missing.
///
/// `TouchIdMissing` is the host-wide finding: `/etc/pam.d/sudo` has
/// no active `pam_tid.so` directive. Info-tier — it's a recommendation
/// aligned with the project's NOPASSWD-sudoers stance (Touch ID
/// makes sudo faster AND adds an auth factor), not a correctness
/// drift. Info findings do not trip `--strict`'s exit-1, so the
/// operator sees the tip once but isn't nagged on every doctor run.
///
/// `PfDisabled` is the host-wide finding: pf's global enable state
/// is off (`pfctl -d` was run, or pf never got enabled on this host).
/// Critical-tier — when pf is off, NO tenant's firewall enforces
/// anything; every tenant's anchor is silently inert. Recovery is
/// `sudo pfctl -e` (idempotent at the substrate; the create flow's
/// `FirewallOp::Enable` is the same command).
///
/// `AnchorBodyDrift` is the per-tenant file-side finding: the on-disk
/// anchor file at `/etc/pf.anchors/tenant-<name>` differs byte-for-byte
/// from what `firewall::render_anchor` would produce from the current
/// profile (runtime tier — install widening is session-scoped, so any
/// sustained install-tier on-disk state IS drift). Warning-tier;
/// recovery is `tenant mode <name> runtime` (re-renders + reloads
/// the anchor), same as `PfRuleDrift`.
///
/// Vocabulary note: the variant says "body" (the technical content
/// concept) and the `Display` impl says "anchor file drift" / "on-disk
/// body" (the operator's mental model — they hand-edited the FILE; the
/// detail names what specifically diverged). Same deliberate
/// two-level framing as `PfRuleDrift` ("rule" internally, "pf anchor"
/// in Display).
///
/// `AclDrift` is the per-tenant finding: a declared `[[shares]]`
/// entry's `host_path` is missing the `<tenant>-tenant-share` group's
/// `allow` ACL entry. Warning-tier; recovery is `tenant reload <name>`
/// (the share substrate is idempotent — Grant re-applies cleanly).
/// The set of paths audited is bounded by the profile's declared
/// shares (orphan-ACL detection across the host filesystem is NOT in
/// scope).
///
/// `SymlinkDrift` is the per-tenant finding: a declared share's
/// `tenant_path` doesn't match the declared `host_path` via symlink.
/// Three sub-cases via `SymlinkActual`: `Absent` (no entry at
/// tenant_path — tenant `rm`'d the symlink or never had one),
/// `WrongTarget(actual)` (symlink exists but points elsewhere — operator
/// changed the profile's host_path without re-running reload), and
/// `NotSymlink` (tenant_path is a real file or directory — reload's
/// pre-flight would refuse; doctor surfaces the conflict before the
/// next reload attempt). Warning-tier; recovery is `tenant reload <name>`
/// for the first two cases and manual cleanup + reload for `NotSymlink`.
/// Target comparison is string-exact (no canonicalize) — the profile
/// names the operator's declared intent.
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
    /// The host operator is not a secondary member of the tenant's
    /// `<name>-tenant-share` group. Surfaces (a) legacy tenants whose
    /// create flow predates the host-membership step, and (b) tenants
    /// where the operator manually removed themselves with
    /// `dseditgroup -o edit -d`. Warning-tier; recovery is `tenant
    /// reload <name>` (the substrate's catch-up path re-adds the host).
    HostNotInShareGroup {
        tenant: TenantUserName,
        host: HostUserName,
        group: GroupName,
    },
}

/// What's actually present at a declared share's `tenant_path`, when
/// it doesn't match the declared `host_path` symlink. Case-tailored
/// guidance per variant — Absent / WrongTarget have the same recovery
/// (`tenant reload <name>` re-creates the link via `ln -sfn`);
/// NotSymlink requires manual cleanup first (reload would refuse with
/// `ShareError::TenantPathOccupied`). All three express "symlink
/// isn't what was declared" — they're modelled as one Finding variant
/// rather than three, so callers route through a single arm.
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
        }
    }

    /// Multi-section operator-facing guidance for a finding. Returned
    /// text is flat (section headers at column 0; body at column 2;
    /// no trailing newline). Reporter prefixes each rendered line with
    /// 2 spaces under the finding line for verbose-mode emission.
    ///
    /// `None` for `FilesystemExposure`: per-path-category guidance
    /// depends on operator intent (file vs directory; intentional-public
    /// vs accidental-leak; POSIX vs ACL fix) and would belong with the
    /// remediation surface, not the detection surface.
    ///
    /// Section structure mirrors the sandbox plugin's
    /// `home_check.HomeCheck::guidance()` prior art:
    /// - **Why this matters**: 1-2 paragraphs framing the stake.
    /// - **Recommended fix**: exact command + one-line justification.
    /// - **Side-effects to know about**: bullet list of consequences.
    /// - **Alternative**: when applicable; omitted for variants where
    ///   no meaningful alternative exists (`TouchIdMissing`,
    ///   `PfDisabled`).
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
        }
    }
}

/// Does the on-disk anchor body match the profile-derived expected
/// body byte-for-byte? Caller passes the actual file content
/// (`Executor::read_anchor_body`) and the expected render
/// (`firewall::render_anchor` over the runtime-tier hosts).
///
/// Byte-exact: `render_anchor` is deterministic — same profile +
/// tenant produces identical output across runs — so any difference
/// is real drift, not cosmetic. If trailing-whitespace or comment-edit
/// false positives ever surface, soften the comparator here.
pub fn anchor_body_matches(actual: &str, expected: &str) -> bool {
    actual == expected
}

/// Does the env policy unconditionally delete `var` from propagation
/// for `sudo -u <tenant>` invocations?
///
/// Greps the concatenated sudoers text for an UNQUALIFIED `Defaults
/// env_delete` directive that includes `var`. Recognized shapes:
/// - `Defaults env_delete += "X"`
/// - `Defaults env_delete = "X Y Z"` (multi-var list, space-separated)
/// - `Defaults env_delete += X` (unquoted single var)
///
/// **Qualified `Defaults` forms are NOT accepted.** Sudo allows
/// `Defaults:user` (invoking-user scoped), `Defaults>runas`
/// (target-user scoped), `Defaults@host` (host scoped), and
/// `Defaults!cmd` (command-tag scoped) — each restricts when the
/// directive applies. A `Defaults>plugin-dev env_delete += "X"`
/// applies only when sudo runs as `plugin-dev`, not when it runs
/// as a tenant — so it doesn't protect the operator's tenant
/// sessions even though the literal text mentions `env_delete`.
/// Tradeoff: conservative-false. Better to nag the operator about a
/// leak covered by a per-runas directive (false positive — they can
/// add an unqualified directive to silence) than to silently miss
/// a real leak.
pub fn has_env_delete_for(policy: &str, var: &str) -> bool {
    for raw_line in policy.lines() {
        let line = raw_line.trim();
        // Accept ONLY unqualified `Defaults` followed directly by
        // whitespace. Qualified forms (`Defaults:`, `Defaults>`,
        // `Defaults@`, `Defaults!`) restrict the directive's scope
        // and don't reliably protect tenant invocations.
        let after_defaults = match line.strip_prefix("Defaults") {
            Some(rest) if rest.starts_with(|c: char| c.is_whitespace()) => rest.trim(),
            _ => continue,
        };
        // Now `after_defaults` should start with `env_delete`. Use a
        // word-boundary check so `env_delete_extra` doesn't false-
        // match.
        let after_envdel = match after_defaults.strip_prefix("env_delete") {
            Some(rest) if rest.starts_with(|c: char| c.is_whitespace() || c == '=' || c == '+') => {
                rest.trim()
            }
            _ => continue,
        };
        // Expect `+=` or `=` next.
        let after_op = if let Some(rest) = after_envdel.strip_prefix("+=") {
            rest.trim()
        } else if let Some(rest) = after_envdel.strip_prefix('=') {
            rest.trim()
        } else {
            continue;
        };
        // The value is either a double-quoted space-separated list or
        // a single bare token. Strip surrounding quotes if present.
        let value = after_op
            .trim_start_matches('"')
            .trim_end_matches('"')
            .trim();
        // Tokenize space-separated entries.
        if value.split_whitespace().any(|tok| tok == var) {
            return true;
        }
    }
    false
}

/// Map a (category, probe-outcome) pair to a finding's severity, or
/// `None` if no finding fires. Only `Allowed` ever produces a
/// finding — `Denied` and `Unknown` are the expected case for
/// sensitive paths on a hardened host and should not pollute output.
pub fn classify(category: Category, outcome: AccessOutcome) -> Option<Severity> {
    match (category, outcome) {
        (_, AccessOutcome::Denied) | (_, AccessOutcome::Unknown) => None,
        (Category::HostSecret, AccessOutcome::Allowed) => Some(Severity::Critical),
        (Category::HostHomeListing, AccessOutcome::Allowed) => Some(Severity::Warning),
        (Category::CrossTenant, AccessOutcome::Allowed) => Some(Severity::Warning),
        (Category::TenantArtifact, AccessOutcome::Allowed) => Some(Severity::Info),
    }
}

/// Build the curated list of (category, access, path) tuples to probe
/// for one tenant on one host. The list is:
///
/// - **HostHomeListing**: `/Users/<host>` (List).
/// - **HostSecret (Read)**: SSH private keys, AWS credentials, GnuPG
///   private-key dir, GitHub PAT (`~/.config/gh/hosts.yml`), Claude
///   OAuth token (`~/.claude.json`), zsh history.
/// - **HostSecret (List)**: `.ssh`, `.aws`, `.gnupg`, `.config/gh`,
///   `.claude`, `Library/Keychains`, `Documents`, `Desktop`,
///   `Downloads` — directory listability checks for the same threat
///   model (a tenant who can list `~/.ssh/` may enumerate key names
///   even if individual files are 0600).
/// - **CrossTenant**: for each `other` tenant ≠ `tenant`,
///   `/Users/<other>` (List) and `/Users/<other>/.ssh` (List).
/// - **TenantArtifact**: for each `other`, the host-side profile
///   `~/.config/tenant/profiles/<other>.toml` (Read) and the per-
///   tenant PF anchor `/etc/pf.anchors/tenant-<other>` (Read).
///
/// `others` is permitted to contain the current `tenant` name; that
/// entry is filtered out so callers can pass an unfiltered tenant
/// list. Order is stable across calls so the operator's diff between
/// two `tenant doctor` runs is meaningful.
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

/// Does `pfctl -si` report pf as enabled?
///
/// Match shape: a non-comment line whose trimmed form starts with
/// `Status: Enabled`. `pfctl -si`'s canonical first line is e.g.
/// `Status: Enabled for 3 days 04:32:18` (uptime suffix varies);
/// when pf is off, it reports `Status: Disabled`. Prefix match on
/// `Status: Enabled` distinguishes cleanly. Leading whitespace is
/// tolerated.
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

/// Does `/etc/pam.d/sudo` enable Touch-ID-for-sudo via an active
/// `pam_tid.so` directive?
///
/// Match shape: a non-comment line whose tokens are `auth sufficient
/// pam_tid.so` (control == `sufficient`, module == `pam_tid.so`).
/// Returns `true` on first hit; `false` if no such line is present.
///
/// Why `sufficient` specifically: pam.d's stack semantics give
/// `sufficient` modules a short-circuit-on-success role — a passing
/// `pam_tid.so sufficient` means sudo authenticates via Touch ID
/// alone (no fallback to password). A `required` or `optional`
/// pam_tid.so doesn't carry the same UX guarantee (Touch ID may
/// run AND then still demand a password). Conservative-false: a
/// non-`sufficient` directive reports as missing, prompting the
/// operator to inspect and confirm.
///
/// Commented (`#`-prefixed) lines do not count. Leading whitespace
/// is tolerated. Inline trailing comments after the module name are
/// not parsed — pam.d doesn't accept them in the canonical sense, so
/// `auth sufficient pam_tid.so # comment` is treated as a real line
/// (the parser sees `auth`, `sufficient`, `pam_tid.so` as the first
/// three tokens).
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

/// Structural-presence check on the kernel's pf rules for the
/// `tenant-<name>` anchor. Returns up to two `PfRuleDrift` findings:
/// one if no `pass` rule is present, one if no `block return` rule
/// is present.
///
/// Structural rather than exact-match: pfctl's output format isn't
/// a stable contract (numerical IPs vs hostnames, table-reference
/// reformatting) so an exact-match check would false-positive on
/// cosmetic drift. The structural shape catches the case that
/// actually matters — "kernel anchor is empty or missing one of
/// the two rule classes the runtime requires".
///
/// Match shape: line begins with `pass ` (any pass rule) and
/// separately a line begins with `block ` (any block rule). Both are
/// case-sensitive lowercase per pfctl's canonical output. Leading
/// whitespace is tolerated; commented-out lines (`#`-prefixed) do
/// not count as a real rule.
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

/// Does the `ls -lde` listing carry an `allow` ACL entry for `group`?
///
/// Match shape: any line containing the literal substring
/// `group:<group> allow`. Looser than substring-matching the full
/// canonical entry string — `chmod +a "group:dev-tenant-share allow
/// read,write,..."` writes bits in one form but macOS canonicalizes
/// to another on storage (e.g. `read,write,execute,delete,append` →
/// `list,add_file,search,delete,add_subdirectory`), so any bit-list
/// comparison would false-negative. The presence of the group's
/// `allow` entry is the structural invariant doctor cares about; the
/// specific bits are the operator's choice via the profile's
/// `mode = "ro"` / `"rw"` translated by the `AclMode` substrate.
///
/// Word-boundary discipline: we delimit the group name with `:` on
/// the left and ` allow` on the right so a prefix-collision case like
/// listing carrying `group:dev` while doctor queries `group:dev-tenant-share`
/// does NOT match (`group:dev allow` ≠ `group:dev-tenant-share allow`).
///
/// Commented lines (`#`-prefixed after trim) do not count, matching
/// the convention of the env-policy + pam parsers. `ls -lde` doesn't
/// actually emit comments — defensive parser shape only.
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

/// Render a curated path for the verbose-mode "Curated sensitive paths
/// checked:" disclosure block. Forms one line per path with the access
/// mode suffix so operators can see which capability was probed
/// (Read vs List on the same path produce two lines).
pub fn render_curated_line(access: AccessMode, path: &Path) -> String {
    let verb = match access {
        AccessMode::Read => "read",
        AccessMode::List => "list",
    };
    format!("  {} {}", verb, path.display())
}
