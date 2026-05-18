use std::path::PathBuf;

use crate::domain::{GroupId, GroupName, HostUserName, TenantUserName, UserId};

use super::errors::{AccountError, AclError, FirewallError};
use super::host_machine::{HostMachine, WritableOp};
use crate::profile::ProfileError;

/// Which filesystem access predicate doctor's probe checks. `Read` maps to
/// `test -r <path>` (POSIX read permission on a file or directory entry);
/// `List` maps to `test -x <path>` against a directory (the POSIX execute
/// bit on a directory grants the ability to list / traverse its entries —
/// the term "list" is the doctor-domain word for that capability, not
/// POSIX's "execute"). The substrate translates one access mode to one
/// probe invocation; doctor's curated path list pairs each path with the
/// access mode that matters for the threat (Read for secret-file
/// contents, List for directory enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    Read,
    List,
}

/// Kind of filesystem entry at a tenant-side path, as the tenant sees
/// it. `Absent` means no entry exists; `Symlink(target)` means an
/// existing symlink (which the share reapply can safely replace via
/// `ln -sfn`) carrying its resolved target so doctor can compare
/// against the declared `host_path`; `Other` means a real file or
/// directory occupies the path — `Other` triggers
/// `ShareError::TenantPathOccupied` so the operator chooses between
/// editing the profile or removing the conflict manually. Substrate
/// never clobbers real operator data.
///
/// Substrate composition: a `sudo -n -u <tenant> /bin/test -L`
/// probe (symlink check) then, on hit, a `sudo -n -u <tenant>
/// /bin/readlink <path>` to capture the target; on miss, a `/bin/test
/// -e` probe distinguishes `Absent` from `Other`. Substrate-machinery
/// failures (sudo prompt cache expired, fork failed) surface as
/// `ProbeError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathKind {
    Absent,
    Symlink(std::path::PathBuf),
    Other,
}

/// Probe verdict. `Allowed` means the tenant CAN access the path under
/// the requested mode (the probe's exit code is zero); `Denied` covers
/// the expected hardened-host case where the kernel refuses (POSIX,
/// ACLs, sandbox, TCC — doctor doesn't distinguish, since
/// mechanism-of-denial belongs with the future remediation surface);
/// `Unknown` is reserved for ambiguous probe outcomes (e.g. probe
/// ran but produced indeterminate stderr). Doctor's `classify`
/// collapses every non-Allowed outcome to no-finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOutcome {
    Allowed,
    Denied,
    Unknown,
}

/// Account-domain operations. The writer expresses *what* to do (create the
/// share group, look up the OD record, log in as the tenant); the substrate
/// knows *how*. macOS-specific tool choices (dseditgroup, sysadminctl, dscl)
/// live in `MacosHostMachine`'s impl, not here.
///
/// `LoginAsUser` is included for the display pipeline (the shell verb's
/// "Shelling into…" plan line goes through `HostMachine::describe_account`),
/// but it is NOT handled by `execute_account` — interactive ops need stdio
/// inheritance and a separate return type (i32 child exit code), which is
/// the dedicated `HostMachine::login` method. The asymmetry is local to the
/// shell verb and documented at the trait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountOp {
    /// Create the share group with the given GID. `group` is the full
    /// macOS short group name (today always `<tenant>-tenant-share` —
    /// `accounts::tenant_share_group_name` appends the suffix at the
    /// Writer boundary). Maps to `sudo dseditgroup -o create -n . -i
    /// <gid> <group>` on macOS.
    CreateShareGroup { group: GroupName, gid: GroupId },

    /// Delete the share group. Used as the create-side rollback step
    /// and the destroy-side cleanup step. Maps to `sudo dseditgroup
    /// -o delete -n . <group>` on macOS.
    DeleteShareGroup { group: GroupName },

    /// Create the tenant user with the given UID + GID. Maps to `sudo
    /// sysadminctl -addUser <name> -fullName "Tenant: <name>" -shell
    /// /bin/zsh -UID <uid> -GID <gid>` on macOS.
    CreateTenantUser {
        name: TenantUserName,
        uid: UserId,
        gid: GroupId,
    },

    /// Delete the tenant user via the OD-aware tool. Maps to `sudo
    /// sysadminctl -deleteUser <name>` on macOS. Distinct from
    /// `DeleteUserRecord` (low-level dscl cleanup); the doctrine separates
    /// these because sysadminctl handles home-directory move-to-Deleted-Users
    /// while dscl only touches the DS record.
    DeleteTenantUser { name: TenantUserName },

    /// Probe for an OD record's presence. Maps to `dscl . -read /Users/<name>`
    /// on macOS. The substrate's `execute_account` reports `Ok(())` when the
    /// record exists and `Err(AccountError::NonZero{..})` when it doesn't —
    /// the writer uses that result to gate the conditional `DeleteUserRecord`
    /// cleanup. No sudo (reads on the local node don't require it).
    LookupUserRecord { name: TenantUserName },

    /// Low-level cleanup of a stale OD record that `DeleteTenantUser` may
    /// have left behind. Maps to `sudo dscl . -delete /Users/<name>` on
    /// macOS. Belt-and-braces; runs only when `LookupUserRecord` finds the
    /// record present.
    DeleteUserRecord { name: TenantUserName },

    /// Interactive login as the tenant. Used by the `shell` verb. The
    /// describe-side renders `sudo -iu <name>`; execution goes through
    /// `HostMachine::login` (NOT `execute_account`) because the return type
    /// is the child shell's exit code, and stdio must inherit so sudo can
    /// prompt and the login shell can drive the controlling terminal.
    LoginAsUser { name: TenantUserName },

    /// Run a single command as the tenant inside a login shell. Used by
    /// the `tenant shell <name> -- <cmd>` command form. Sibling to
    /// `LoginAsUser` under the `sudo -iu` mechanism family — same login
    /// shell semantics (sources `/etc/zprofile` + `~/.zprofile` so PATH
    /// and tooling env match the interactive form), same stdio carve-out
    /// (execution goes through `HostMachine::exec_as_tenant`, not
    /// `execute_account`, because stdio inherits and the return type is
    /// the child's exit code). Substrate: `sudo -iu <name> -- <argv>` —
    /// the `--` separator prevents sudo from interpreting argv[0] as a
    /// sudo flag. `argv` must be non-empty (dispatch routes empty argv
    /// to the interactive branch before any `ExecAsUser` is constructed).
    ExecAsUser {
        name: TenantUserName,
        argv: Vec<String>,
    },

    /// Ensure a directory exists at `path`, created by the tenant `name`.
    /// The shares substrate uses this to pre-create
    /// `parent(tenant_path)` before symlinking — e.g.
    /// `$HOME/.local/share/` so a downstream `$HOME/.local/share/chezmoi`
    /// symlink lands. Maps to `sudo -n -u <name> /bin/mkdir -p <path>`
    /// on macOS; idempotent at the substrate (`mkdir -p` is a noop for
    /// existing directories). Mode bits come from the tenant's umask
    /// (default 022 → directories at 755) which is the right default for
    /// tenant-readable dirs under their home; a future need for explicit
    /// mode adds a `mode: u32` field at the variant.
    EnsureDirAsUser { name: TenantUserName, path: PathBuf },

    /// Ensure a symlink at `link` points at `target`, created by the
    /// tenant `name`. The shares substrate uses this to install the
    /// `tenant_path → host_path` symlink that gives the tenant a
    /// stable filesystem entry point under their home. Maps to
    /// `sudo -n -u <name> /bin/ln -sfn <target> <link>` — `-sfn` is
    /// the idempotent shape (force-overwrite-existing-symlink +
    /// no-follow-existing-dir-target). An existing REAL directory or
    /// file at `link` is the `TenantPathOccupied` case the Writer
    /// guards against before the substrate runs.
    EnsureSymlinkAsUser {
        name: TenantUserName,
        link: PathBuf,
        target: PathBuf,
    },

    /// Add the host operator as a secondary member of the tenant's
    /// share group. Maps to `sudo dseditgroup -o edit -n . -a <host>
    /// -t user <group>` on macOS. Idempotent at the substrate
    /// (`dseditgroup -o edit -a` on an existing member is a silent
    /// noop), so the catch-up path (`execute_reapply_plan` running
    /// this on every reload/mode/shell) costs one dseditgroup
    /// invocation per verb regardless of the tenant's pre-existing
    /// state.
    ///
    /// Ported verbatim from sandbox's `_add_human_to_group` step
    /// (`scripts/lib/phases/phase01_user.py:180-185`); originally
    /// dropped during the initial port, and the symptom —
    /// bidirectional-write asymmetry on RW shares — was caught in
    /// the 2026-05-15 operator setup pass.
    AddHostToShareGroup {
        group: GroupName,
        host: HostUserName,
    },

    /// Symmetric counter to `AddHostToShareGroup`. Maps to `sudo
    /// dseditgroup -o edit -n . -d <host> -t user <group>`. The
    /// describe-side renders only the `-d` edit form; the production
    /// `execute_account` impl invokes `dseditgroup -o checkmember -m
    /// <host> <group>` first and skips the edit when the host is not
    /// a member (idempotence for legacy tenants without host
    /// membership and the orphan-group destroy path on a partially-
    /// created tenant).
    RemoveHostFromShareGroup {
        group: GroupName,
        host: HostUserName,
    },
}

/// Profile-domain operations. The store-backed `~/.config/tenant/profiles/<name>.toml`
/// file is the host-side artifact; the substrate handles the actual fs work
/// (or in-memory recording for tests). The profile read path lives on
/// `HostMachine::read_profile` (a dedicated method, not a variant here)
/// because the return type — file content, not unit — doesn't fit
/// `execute_profile`'s shape. Parallels `login`'s carve-out from
/// `execute_account` for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOp {
    /// Write the default profile content for `name`. Idempotent overwrite.
    Create { name: TenantUserName },

    /// Remove the profile file. Idempotent: NotFound is success, mirroring
    /// the operator's mental model of `rm -f`.
    Delete { name: TenantUserName },
}

/// Firewall-domain operations. macOS implements per-tenant firewall rules
/// as a named PF anchor (`/etc/pf.anchors/tenant-<name>`) referenced from
/// `/etc/pf.conf` and loaded via `pfctl -f`. The substrate handles the
/// actual file writes (atomic tempfile + sudo mv + sudo chmod) and the
/// pfctl invocations; the writer composes these ops into the create/destroy
/// flows.
///
/// `Anchor` stays in the variant names because it's the project's domain
/// vocabulary for "named per-tenant firewall ruleset"; `Pf` prefixes drop
/// from `Reload` / `Enable` because the tool's name (pfctl) lives in
/// `MacosHostMachine`, not here.
/// Per-share access intent at the substrate level — what bits to grant
/// or revoke when invoking `chmod +a` / `chmod -a`. `Ro` maps to the
/// sandbox-plugin `read_exec_inherit_entry` shape (read + execute +
/// directory/file inheritance — execute is needed for directory
/// traversal); `Rw` maps to `rw_inherit_entry` (read + write + execute
/// + delete + append + inheritance — the full operator-writable bundle).
///
/// Substrate-vocab type sibling to `profile::ShareMode` (profile-vocab):
/// the Writer maps `ShareMode → AclMode` at op-construction time. Same
/// two values today, distinct types so the layer boundary is visible —
/// if `ShareMode` grows a profile-only flag (e.g. an "exclude-children"
/// inheritance opt-out), `AclMode` stays binary and the Writer's
/// mapping absorbs the divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMode {
    Ro,
    Rw,
}

impl AclMode {
    /// The bit list embedded in the `chmod +a "group:<g> allow <bits>,..."`
    /// entry string. Centralized here so both `describe_acl` (operator-
    /// facing rendering) and `execute_acl` (idempotence pre-check via
    /// `ls -lde` substring match) reference the same canonical bytes —
    /// any drift between the rendered command and the substring searched
    /// would silently break idempotence.
    pub fn acl_bits(self) -> &'static str {
        match self {
            AclMode::Ro => "read,execute,file_inherit,directory_inherit",
            AclMode::Rw => "read,write,execute,delete,append,file_inherit,directory_inherit",
        }
    }
}

/// ACL-domain operations. `Grant` adds an inheritable ACL entry
/// granting `group` access to `path` at the requested mode; `Revoke`
/// removes the same entry. Both are idempotent at the substrate (macOS
/// `chmod +a` is natively idempotent — re-applying an existing entry
/// is a noop). No `sudo` prefix on the argv — the operator (host
/// user) is expected to own or have ACL-write on `host_path`; if
/// they don't, `chmod` fails with `AclError::NonZero` and the stderr
/// surfaces under `Reporter::*_failed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclOp {
    /// Grant `group` access to `path` at `mode`. ACL entry is inheritable
    /// (`file_inherit,directory_inherit`); descendants automatically pick
    /// up the same grant.
    Grant {
        path: PathBuf,
        group: GroupName,
        mode: AclMode,
    },

    /// Remove the inheritable ACL entry that `Grant` installed. Idempotent:
    /// if the entry isn't present, returns Ok(()) without invoking chmod.
    Revoke {
        path: PathBuf,
        group: GroupName,
        mode: AclMode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallOp {
    /// Write the rendered anchor body to `/etc/pf.anchors/tenant-<name>`.
    /// `name` is the tenant name; the anchor file's full name
    /// (`tenant-<name>`) is constructed by `MacosHostMachine` from it. `body`
    /// is the precomputed anchor content (from `firewall::render_anchor`).
    InstallAnchor { name: TenantUserName, body: String },

    /// Remove `/etc/pf.anchors/tenant-<name>`. Idempotent: NotFound is
    /// success on production, mirroring the operator's mental model of
    /// `rm -f`.
    RemoveAnchor { name: TenantUserName },

    /// Copy `/etc/pf.conf` to `/etc/pf.conf.tenant-backup`. Fixed backup
    /// path (no timestamps) — deterministic recovery, overwritten each
    /// invocation.
    BackupConfig,

    /// Copy `/etc/pf.conf.tenant-backup` back to `/etc/pf.conf`. The
    /// recovery half of `BackupConfig`. Runs on `Reload` failure during
    /// create.
    RestoreConfigFromBackup,

    /// Write the precomputed pf.conf content to `/etc/pf.conf`. `content`
    /// is the output of `firewall::ensure_anchor_ref` (create-side) or
    /// `firewall::remove_anchor_ref` (destroy-side).
    UpdateConfig { content: String },

    /// `pfctl -f /etc/pf.conf` — reload the firewall ruleset. Non-zero
    /// exit on syntax or anchor errors triggers the recovery path on
    /// create.
    Reload,

    /// `sudo pfctl -a tenant-<name> -F all` — flush the in-kernel
    /// rules and tables stored under the named anchor. `pfctl -f` only
    /// walks the parent ruleset and never garbage-collects anchors
    /// whose `load anchor` directive has been removed: without this
    /// explicit flush, destroy leaves the previous tenant's rules
    /// loaded under an orphan anchor name, and the next tenant getting
    /// the same UID would silently inherit them. Symmetric counter to
    /// the create-side `InstallAnchor`. Idempotent: flushing an empty
    /// or unknown anchor is a noop on macOS.
    FlushAnchor { name: TenantUserName },

    /// `pfctl -e` — enable the firewall. Treated as idempotent at the
    /// substrate: "already enabled" stderr maps to `Ok(())`.
    Enable,
}

/// Top-level ADT wrapper for "any op, regardless of domain." Used by the
/// Reporter for uniform display dispatch — `Op::describe_via` picks the
/// right substrate method based on which sub-domain the op belongs to.
/// Execution stays on the bare `AccountOp` / `ProfileOp` types (via the
/// `WritableOp` trait) so per-domain error types stay typed and the
/// dispatcher's `CreateError::Group / User / Profile` distinction is
/// preserved end-to-end. The ADT hierarchy is honest: `Op` is the root,
/// `AccountOp` / `ProfileOp` are the leaf ADTs, each with their own
/// variants.
pub enum Op<'a> {
    Account(&'a AccountOp),
    Profile(&'a ProfileOp),
    Firewall(&'a FirewallOp),
    Acl(&'a AclOp),
}

impl<'a> Op<'a> {
    /// Render the op as an operator-facing display line. The match here
    /// is the one place in the codebase that has to know the
    /// account/profile/firewall/acl split for display purposes.
    pub fn describe_via(&self, machine: &dyn HostMachine) -> String {
        match self {
            Op::Account(op) => machine.describe_account(op),
            Op::Profile(op) => machine.describe_profile(op),
            Op::Firewall(op) => machine.describe_firewall(op),
            Op::Acl(op) => machine.describe_acl(op),
        }
    }

    /// Operator-facing past-tense success label for the op. Drives the
    /// `✓ <label>` lines emitted by `Reporter::progress` after each
    /// substrate step succeeds. Distinct from `describe_via`: describe
    /// is the mechanism-level shell echo (`sudo dseditgroup …`);
    /// business_label is the capability-level summary the operator
    /// reads. Substrate-agnostic — no `dseditgroup` / `sysadminctl`
    /// jargon.
    pub fn business_label(&self) -> String {
        match self {
            Op::Account(op) => account_business_label(op),
            Op::Profile(op) => profile_business_label(op),
            Op::Firewall(op) => firewall_business_label(op),
            Op::Acl(op) => acl_business_label(op),
        }
    }

    /// Operator-facing future-tense capability label for the op. Leads
    /// each step in the verbose pre-prompt plan block as a `• <intent>`
    /// bullet, with the shell line indented underneath. Sibling to
    /// `business_label` (past-tense; drives the `✓` progress lines
    /// emitted post-execution). Substrate-agnostic — no `dseditgroup`
    /// / `sysadminctl` / `pfctl` jargon. The probe variants
    /// (`LookupUserRecord` / `DeleteUserRecord`) are sharpened apart
    /// from their business_label so the future-tense bullet reads
    /// naturally.
    pub fn intent_label(&self) -> String {
        match self {
            Op::Account(op) => account_intent_label(op),
            Op::Profile(op) => profile_intent_label(op),
            Op::Firewall(op) => firewall_intent_label(op),
            Op::Acl(op) => acl_intent_label(op),
        }
    }
}

fn account_business_label(op: &AccountOp) -> String {
    match op {
        AccountOp::CreateShareGroup { group, gid } => {
            format!("Share group '{group}' created (GID {gid})")
        }
        AccountOp::DeleteShareGroup { group } => {
            format!("Share group '{group}' removed")
        }
        AccountOp::CreateTenantUser { name, uid, .. } => {
            format!("User account '{name}' provisioned (UID {uid})")
        }
        AccountOp::DeleteTenantUser { name } => {
            format!("User account '{name}' removed (home moved to /Users/Deleted Users/{name})")
        }
        AccountOp::LookupUserRecord { name } => {
            format!("Residual user record check for '{name}'")
        }
        AccountOp::DeleteUserRecord { name } => {
            format!("Residual user record '{name}' cleaned up")
        }
        AccountOp::LoginAsUser { name } => format!("Entering shell as '{name}'"),
        AccountOp::ExecAsUser { name, argv } => {
            // basename of argv[0] for the ✓ progress line. argv[0]
            // may be an absolute path; the operator's mental model is
            // "the command 'ls' ran", not "the command '/usr/bin/ls' ran".
            let bin = argv
                .first()
                .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
                .unwrap_or("?");
            format!("Command '{bin}' executed as '{name}'")
        }
        AccountOp::EnsureDirAsUser { path, .. } => {
            format!("Parent directory {} ensured", path.display())
        }
        AccountOp::EnsureSymlinkAsUser { link, target, .. } => {
            format!(
                "Symlink {} → {} installed",
                link.display(),
                target.display()
            )
        }
        AccountOp::AddHostToShareGroup { group, host } => {
            format!("Host '{host}' added to share group '{group}'")
        }
        AccountOp::RemoveHostFromShareGroup { group, host } => {
            format!("Host '{host}' removed from share group '{group}'")
        }
    }
}

fn profile_business_label(op: &ProfileOp) -> String {
    match op {
        ProfileOp::Create { name } => {
            format!(
                "Profile written to {}",
                crate::profile::display_path_for(name.as_str())
            )
        }
        ProfileOp::Delete { name } => format!(
            "Profile removed at {}",
            crate::profile::display_path_for(name.as_str())
        ),
    }
}

fn firewall_business_label(op: &FirewallOp) -> String {
    match op {
        FirewallOp::InstallAnchor { name, .. } => format!(
            "Firewall anchor installed at {}",
            crate::firewall::tenant_anchor_path(name.as_str())
        ),
        FirewallOp::RemoveAnchor { name } => format!(
            "Firewall anchor removed at {}",
            crate::firewall::tenant_anchor_path(name.as_str())
        ),
        FirewallOp::BackupConfig => {
            format!(
                "Backed up {} to {}",
                crate::firewall::PF_CONF,
                crate::firewall::PF_CONF_BACKUP
            )
        }
        FirewallOp::RestoreConfigFromBackup => format!(
            "Restored {} from {}",
            crate::firewall::PF_CONF,
            crate::firewall::PF_CONF_BACKUP
        ),
        FirewallOp::UpdateConfig { .. } => format!("Updated {}", crate::firewall::PF_CONF),
        FirewallOp::Reload => "Firewall ruleset reloaded".to_string(),
        FirewallOp::FlushAnchor { name } => format!(
            "Kernel rules under anchor '{}' flushed",
            crate::firewall::tenant_anchor_name(name.as_str())
        ),
        FirewallOp::Enable => "Firewall enabled host-wide".to_string(),
    }
}

fn acl_business_label(op: &AclOp) -> String {
    match op {
        AclOp::Grant { path, group, .. } => {
            format!("ACL granted to group '{group}' on {}", path.display())
        }
        AclOp::Revoke { path, group, .. } => {
            format!("ACL revoked from group '{group}' on {}", path.display())
        }
    }
}

fn account_intent_label(op: &AccountOp) -> String {
    match op {
        AccountOp::CreateShareGroup { group, gid } => {
            format!("Create share group '{group}' (GID {gid})")
        }
        AccountOp::DeleteShareGroup { group } => {
            format!("Remove share group '{group}'")
        }
        AccountOp::CreateTenantUser { name, uid, gid } => {
            format!("Create user account '{name}' (UID {uid}, GID {gid})")
        }
        AccountOp::DeleteTenantUser { name } => {
            format!("Remove user account '{name}' (home moved to /Users/Deleted Users/{name})")
        }
        AccountOp::LookupUserRecord { name } => {
            format!("Probe for residue user record '{name}'")
        }
        AccountOp::DeleteUserRecord { name } => {
            format!("Clean up residue user record '{name}'")
        }
        AccountOp::LoginAsUser { name } => format!("Log in as '{name}'"),
        AccountOp::ExecAsUser { name, argv } => {
            // Full argv joined with single spaces for the operator-display
            // plan bullet. No shell-escaping — the operator typed it; they
            // can read it. Substrate-side, argv is preserved as the
            // already-tokenized vector so a metachar-bearing element
            // arrives at the tenant unchanged.
            format!("Run as '{name}': {}", argv.join(" "))
        }
        AccountOp::EnsureDirAsUser { path, .. } => {
            format!("Ensure directory {} exists (as tenant)", path.display())
        }
        AccountOp::EnsureSymlinkAsUser { link, target, .. } => {
            format!(
                "Install symlink {} \u{2192} {} (as tenant)",
                link.display(),
                target.display()
            )
        }
        AccountOp::AddHostToShareGroup { group, host } => {
            format!("Add host '{host}' to share group '{group}'")
        }
        AccountOp::RemoveHostFromShareGroup { group, host } => {
            format!("Remove host '{host}' from share group '{group}'")
        }
    }
}

fn profile_intent_label(op: &ProfileOp) -> String {
    match op {
        ProfileOp::Create { name } => format!(
            "Write profile config at {}",
            crate::profile::display_path_for(name.as_str())
        ),
        ProfileOp::Delete { name } => format!(
            "Remove profile config at {}",
            crate::profile::display_path_for(name.as_str())
        ),
    }
}

fn firewall_intent_label(op: &FirewallOp) -> String {
    match op {
        FirewallOp::InstallAnchor { name, .. } => format!(
            "Install firewall anchor at {}",
            crate::firewall::tenant_anchor_path(name.as_str())
        ),
        FirewallOp::RemoveAnchor { name } => format!(
            "Remove firewall anchor at {}",
            crate::firewall::tenant_anchor_path(name.as_str())
        ),
        FirewallOp::BackupConfig => format!(
            "Back up {} to {}",
            crate::firewall::PF_CONF,
            crate::firewall::PF_CONF_BACKUP
        ),
        FirewallOp::RestoreConfigFromBackup => {
            format!("Restore {} from backup", crate::firewall::PF_CONF)
        }
        FirewallOp::UpdateConfig { .. } => format!("Update {}", crate::firewall::PF_CONF),
        FirewallOp::Reload => "Reload pf ruleset".to_string(),
        FirewallOp::FlushAnchor { name } => format!(
            "Flush kernel rules under anchor '{}'",
            crate::firewall::tenant_anchor_name(name.as_str())
        ),
        FirewallOp::Enable => "Enable pf host-wide".to_string(),
    }
}

fn acl_intent_label(op: &AclOp) -> String {
    match op {
        AclOp::Grant { path, group, .. } => {
            format!("Grant '{group}' ACL access to {}", path.display())
        }
        AclOp::Revoke { path, group, .. } => {
            format!("Revoke '{group}' ACL access from {}", path.display())
        }
    }
}

impl WritableOp for AccountOp {
    type Error = AccountError;
    fn execute_via(&self, machine: &dyn HostMachine) -> Result<(), AccountError> {
        machine.execute_account(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Account(self)
    }
}

impl WritableOp for ProfileOp {
    type Error = ProfileError;
    fn execute_via(&self, machine: &dyn HostMachine) -> Result<(), ProfileError> {
        machine.execute_profile(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Profile(self)
    }
}

impl WritableOp for FirewallOp {
    type Error = FirewallError;
    fn execute_via(&self, machine: &dyn HostMachine) -> Result<(), FirewallError> {
        machine.execute_firewall(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Firewall(self)
    }
}

impl WritableOp for AclOp {
    type Error = AclError;
    fn execute_via(&self, machine: &dyn HostMachine) -> Result<(), AclError> {
        machine.execute_acl(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Acl(self)
    }
}
