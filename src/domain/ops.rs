use std::path::PathBuf;

use crate::domain::{GroupId, GroupName, HostUserName, KeychainPassword, TenantUserName, UserId};

use super::errors::{AccountError, AclError, FirewallError, KeychainError};
use super::host_machine::{HostMachine, WritableOp};
use crate::profile::ProfileError;

/// Which filesystem access predicate doctor's probe checks. `List` is
/// the doctor-domain word for POSIX execute-on-a-directory (the bit
/// that grants traversal / enumeration), not POSIX's "execute".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    Read,
    List,
}

/// Kind of filesystem entry at a tenant-side path, as the tenant sees
/// it. `Symlink(target)` carries the resolved target so doctor can
/// compare against the declared `host_path`. `Dir` distinguishes a
/// real directory from `Other` (regular file, fifo, socket, etc.) —
/// the cowork-dir pre-flight accepts an existing `Dir` (mkdir-p
/// no-ops) but refuses `Other`. Shares treat both as occupants
/// (substrate never clobbers real operator data, regardless of kind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathKind {
    Absent,
    Symlink(std::path::PathBuf),
    Dir,
    Other,
}

/// Probe verdict. `Denied` does not distinguish mechanism (POSIX, ACL,
/// sandbox, TCC) — that's the remediation surface's job. Doctor's
/// `classify` collapses every non-Allowed outcome to no-finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOutcome {
    Allowed,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountOp {
    CreateShareGroup {
        group: GroupName,
        gid: GroupId,
    },

    DeleteShareGroup {
        group: GroupName,
    },

    CreateTenantUser {
        name: TenantUserName,
        uid: UserId,
        gid: GroupId,
    },

    /// Distinct from `DeleteUserRecord`: deletes the user via the
    /// OD-aware tool (handles home-directory move-to-Deleted-Users),
    /// whereas `DeleteUserRecord` only touches the directory-services
    /// record.
    DeleteTenantUser {
        name: TenantUserName,
    },

    /// Probe variant: `Ok(())` means the record exists, `Err` means
    /// it doesn't. The Tenants struct uses that result to gate the conditional
    /// `DeleteUserRecord` cleanup.
    LookupUserRecord {
        name: TenantUserName,
    },

    /// Belt-and-braces cleanup for a stale record that `DeleteTenantUser`
    /// may have left behind; runs only when `LookupUserRecord` finds
    /// the record present.
    DeleteUserRecord {
        name: TenantUserName,
    },

    LoginAsUser {
        name: TenantUserName,
    },

    /// Run a single command as the tenant inside a login shell.
    /// `argv` must be non-empty (dispatch routes empty argv to the
    /// interactive `LoginAsUser` branch before any `ExecAsUser` is
    /// constructed).
    ExecAsUser {
        name: TenantUserName,
        argv: Vec<String>,
    },

    /// Pre-creates `parent(tenant_path)` before the symlink lands.
    EnsureDirAsUser {
        name: TenantUserName,
        path: PathBuf,
    },

    /// Installs the `tenant_path → host_path` symlink. An existing
    /// REAL file or directory at `link` is the `TenantPathOccupied`
    /// case the Tenants struct guards against before the substrate runs.
    EnsureSymlinkAsUser {
        name: TenantUserName,
        link: PathBuf,
        target: PathBuf,
    },

    /// Add the host operator as a secondary member of the tenant's
    /// share group. Idempotent at the substrate, so the catch-up path
    /// can re-run this on every reload/mode/shell without cost.
    AddHostToShareGroup {
        group: GroupName,
        host: HostUserName,
    },

    RemoveHostFromShareGroup {
        group: GroupName,
        host: HostUserName,
    },

    /// Provision the per-tenant co-working directory under
    /// `/Users/Shared/tenants/<name>`. Owner is the host operator,
    /// primary group is the tenant's share group, mode `2770`
    /// (setgid, group-rwx, zero-other). The inheritable rw ACL grant
    /// on the dir propagates collaborative bits to tenant-created
    /// descendants; `chmod -R +a` is recursive so the catch-up path
    /// picks up children added between reapply cycles. All four
    /// substrate calls are natively idempotent on macOS.
    EnsureCoworkDir {
        path: PathBuf,
        owner: HostUserName,
        group: GroupName,
        mode: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOp {
    /// Idempotent overwrite with the default profile content.
    Create { name: TenantUserName },

    /// Idempotent: absent profile is success.
    Delete { name: TenantUserName },
}

/// Substrate-vocab sibling to `profile::ShareMode` (profile-vocab); the
/// Tenants struct maps `ShareMode → AclMode` at op-construction time. Distinct
/// types so the layer boundary is visible — if `ShareMode` grows a
/// profile-only flag, `AclMode` stays binary and the mapping absorbs
/// the divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMode {
    Ro,
    Rw,
}

impl AclMode {
    /// Canonical ACL bit list per mode. Centralized so describe-side
    /// rendering and any substrate-side idempotence check reference
    /// the same bytes — drift would silently break idempotence.
    pub fn acl_bits(self) -> &'static str {
        match self {
            AclMode::Ro => "read,execute,file_inherit,directory_inherit",
            AclMode::Rw => "read,write,execute,delete,append,file_inherit,directory_inherit",
        }
    }
}

/// ACL operations are unprivileged (no `sudo`): the host operator is
/// expected to own or have ACL-write on `path`. Both variants are
/// idempotent at the substrate; inheritable bits propagate the grant
/// to descendants automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclOp {
    Grant {
        path: PathBuf,
        group: GroupName,
        mode: AclMode,
    },

    Revoke {
        path: PathBuf,
        group: GroupName,
        mode: AclMode,
    },
}

/// `Anchor` stays in the variant names — it's the project's domain
/// vocabulary for "named per-tenant firewall ruleset".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallOp {
    /// `body` is the precomputed anchor content (from `render_anchor`).
    InstallAnchor { name: TenantUserName, body: String },

    /// Idempotent: an absent anchor file is success.
    RemoveAnchor { name: TenantUserName },

    /// Fixed backup path (no timestamps) — deterministic recovery,
    /// overwritten each invocation.
    BackupConfig,

    /// Recovery half of `BackupConfig`. Runs on `Reload` failure
    /// during create.
    RestoreConfigFromBackup,

    /// `content` is the precomputed pf.conf body (from
    /// `ensure_anchor_ref` / `remove_anchor_ref`).
    UpdateConfig { content: String },

    /// Non-zero exit triggers the recovery path on create.
    Reload,

    /// Flush in-kernel rules under the named anchor. Load-bearing on
    /// destroy: reloading the parent config does NOT garbage-collect
    /// anchors whose `load anchor` directive has been removed —
    /// without this, destroy leaves the previous tenant's rules under
    /// an orphan anchor name, and the next tenant getting the same
    /// UID would silently inherit them. Idempotent at the substrate.
    FlushAnchor { name: TenantUserName },

    /// Idempotent: "already enabled" maps to `Ok(())`.
    Enable,
}

/// Keychain operations: pre-create the tenant's `login.keychain-db`
/// so credential-stashing apps (Claude OAuth, etc.) don't trip the
/// "could not find the keychain" warning, and persist the protecting
/// secret in the operator's keychain so a future non-interactive
/// unlock pass can retrieve it. `Stash` / `DeleteStashed` write to
/// the OPERATOR's login keychain (no `sudo`); the four `*Keychain*`
/// provision variants write the TENANT's login keychain via
/// `sudo -iu <name> security`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainOp {
    /// `security create-keychain -p <pw> login.keychain-db`. The
    /// `password` is the secret protecting the new keychain (also
    /// stashed in operator's keychain via `StashPassword`). Natively
    /// idempotent against an existing keychain — see
    /// `execute_keychain`'s comment block in
    /// adapters/macos/host_machine.rs.
    CreateLoginKeychain {
        name: TenantUserName,
        password: KeychainPassword,
    },

    /// `security default-keychain -s login.keychain-db`. Sets the
    /// tenant's default keychain pointer in their per-user prefs.
    /// Natively idempotent (overwrites the pointer).
    SetDefaultKeychain { name: TenantUserName },

    /// `security list-keychains -s login.keychain-db`. Replaces the
    /// tenant's keychain search list with just the new one (+ the
    /// system keychain that macOS preserves implicitly).
    AddKeychainToSearchList { name: TenantUserName },

    /// `security set-keychain-settings login.keychain-db` (no flags
    /// = no auto-lock timer, no lock-on-sleep). Load-bearing for the
    /// "Claude OAuth tokens persist across sessions" guarantee.
    DisableKeychainAutoLock { name: TenantUserName },

    /// `security add-generic-password -U -a <name> -s tenant-<name>
    /// -w <password>` against the operator's login keychain. Password
    /// lives on argv: macOS `security` does NOT support stdin reads
    /// on `-w` (the `-` argument is taken as a literal one-character
    /// password, not a stdin sentinel). Brief argv exposure
    /// (~milliseconds, single `security` invocation) is accepted;
    /// alternative is the Security Framework C API via FFI, which is
    /// out of scope for solo-Mac. Service-name `tenant-<name>` is the
    /// contract a future shell-entry unlock pass reads from.
    StashPassword {
        name: TenantUserName,
        password: KeychainPassword,
    },

    /// `security delete-generic-password -a <name> -s tenant-<name>`.
    /// Maps an absent entry (legacy tenant, prior destroy) to
    /// `KeychainError::NotFound` so `destroy` can converge.
    DeleteStashedPassword { name: TenantUserName },
}

/// Display-only wrapper used for uniform describe-dispatch. Execution
/// stays on the bare per-domain ADTs (via `WritableOp`) so per-domain
/// error types are preserved end-to-end.
pub enum Op<'a> {
    Account(&'a AccountOp),
    Profile(&'a ProfileOp),
    Firewall(&'a FirewallOp),
    Acl(&'a AclOp),
    Keychain(&'a KeychainOp),
}

impl<'a> Op<'a> {
    /// Render the op as an operator-facing display line.
    pub fn describe_via(&self, machine: &dyn HostMachine) -> String {
        match self {
            Op::Account(op) => machine.describe_account(op),
            Op::Profile(op) => machine.describe_profile(op),
            Op::Firewall(op) => machine.describe_firewall(op),
            Op::Acl(op) => machine.describe_acl(op),
            Op::Keychain(op) => machine.describe_keychain(op),
        }
    }

    /// Past-tense capability label for the `✓` progress lines.
    /// Substrate-agnostic, distinct from `describe_via`'s mechanism-
    /// level shell echo.
    pub fn business_label(&self) -> String {
        match self {
            Op::Account(op) => account_business_label(op),
            Op::Profile(op) => profile_business_label(op),
            Op::Firewall(op) => firewall_business_label(op),
            Op::Acl(op) => acl_business_label(op),
            Op::Keychain(op) => keychain_business_label(op),
        }
    }

    /// Future-tense capability label for the verbose plan bullets.
    /// Substrate-agnostic; sibling to `business_label`. Probe variants
    /// (`LookupUserRecord` / `DeleteUserRecord`) are sharpened apart
    /// from their business_label so the future-tense bullet reads
    /// naturally.
    pub fn intent_label(&self) -> String {
        match self {
            Op::Account(op) => account_intent_label(op),
            Op::Profile(op) => profile_intent_label(op),
            Op::Firewall(op) => firewall_intent_label(op),
            Op::Acl(op) => acl_intent_label(op),
            Op::Keychain(op) => keychain_intent_label(op),
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
            // Basename of argv[0]: operator reads "the command 'ls' ran",
            // not "the command '/usr/bin/ls' ran".
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
        AccountOp::EnsureCoworkDir { path, .. } => {
            format!("Co-working directory ensured at {}", path.display())
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

fn keychain_business_label(op: &KeychainOp) -> String {
    match op {
        KeychainOp::CreateLoginKeychain { name, .. } => {
            format!("Tenant '{name}' login keychain created")
        }
        KeychainOp::SetDefaultKeychain { name } => {
            format!("Tenant '{name}' default keychain set")
        }
        KeychainOp::AddKeychainToSearchList { name } => {
            format!("Tenant '{name}' keychain added to search list")
        }
        KeychainOp::DisableKeychainAutoLock { name } => {
            format!("Tenant '{name}' keychain auto-lock disabled")
        }
        KeychainOp::StashPassword { name, .. } => {
            format!("Tenant '{name}' password stashed in operator keychain")
        }
        KeychainOp::DeleteStashedPassword { name } => {
            format!("Tenant '{name}' password removed from operator keychain")
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
            // No shell-escaping in the display bullet — operator typed it,
            // they can read it. Substrate-side argv is passed through as a
            // tokenized vector, so metachars reach the tenant unchanged.
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
        AccountOp::EnsureCoworkDir { path, .. } => {
            format!("Ensure co-working directory at {}", path.display())
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

fn keychain_intent_label(op: &KeychainOp) -> String {
    match op {
        KeychainOp::CreateLoginKeychain { name, .. } => {
            format!("Create login keychain for tenant '{name}'")
        }
        KeychainOp::SetDefaultKeychain { name } => {
            format!("Set tenant '{name}' default keychain to login.keychain-db")
        }
        KeychainOp::AddKeychainToSearchList { name } => {
            format!("Add login.keychain-db to tenant '{name}' search list")
        }
        KeychainOp::DisableKeychainAutoLock { name } => {
            format!("Disable auto-lock on tenant '{name}' login keychain")
        }
        KeychainOp::StashPassword { name, .. } => {
            format!("Stash tenant '{name}' password in operator keychain")
        }
        KeychainOp::DeleteStashedPassword { name } => {
            format!("Remove tenant '{name}' password from operator keychain")
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

impl WritableOp for KeychainOp {
    type Error = KeychainError;
    fn execute_via(&self, machine: &dyn HostMachine) -> Result<(), KeychainError> {
        machine.execute_keychain(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Keychain(self)
    }
}
