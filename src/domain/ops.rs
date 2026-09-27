use std::path::PathBuf;

use crate::domain::{GroupId, GroupName, HostUserName, KeychainPassword, TenantUserName, UserId};

use super::errors::{AccountError, AclError, FirewallError, HostFileError, KeychainError};
use super::host_machine::{HostMachine, WritableOp};
use crate::profile::ProfileError;

/// `List` is execute-on-a-directory (traversal / enumeration), not POSIX "execute".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    Read,
    List,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathKind {
    Absent,
    Symlink(std::path::PathBuf),
    Dir,
    Other,
}

/// `Denied` doesn't distinguish mechanism (POSIX, ACL, sandbox, TCC).
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

    /// Full removal (home moves to Deleted Users); `DeleteUserRecord` only drops the
    /// directory-services record.
    DeleteTenantUser {
        name: TenantUserName,
    },

    // TODO(smell): LookupUserRecord is a probe encoded as Ok/Err on an Op; make it a bool carve-out
    /// `Ok(())` = record present; `NonZero` = absent.
    LookupUserRecord {
        name: TenantUserName,
    },

    /// Cleanup for a stale record `DeleteTenantUser` can leave behind.
    DeleteUserRecord {
        name: TenantUserName,
    },

    // TODO(smell): LoginAsUser / ExecAsUser are render-only (execute_account panics); move them out of AccountOp
    /// Render-only (`execute_account` panics); the real call is `HostMachine::login`.
    LoginAsUser {
        name: TenantUserName,
        dir: Option<PathBuf>,
    },

    /// Render-only, like `LoginAsUser`; the real call is `HostMachine::exec_as_tenant`.
    ExecAsUser {
        name: TenantUserName,
        argv: Vec<String>,
        dir: Option<PathBuf>,
    },

    /// Pre-creates `parent(tenant_path)` before the symlink lands.
    EnsureDirAsUser {
        name: TenantUserName,
        path: PathBuf,
    },

    EnsureSymlinkAsUser {
        name: TenantUserName,
        link: PathBuf,
        target: PathBuf,
    },

    /// Idempotent. macOS snapshots supplementary groups at process creation, so the
    /// operator's already-open shells won't see the membership.
    AddHostToShareGroup {
        group: GroupName,
        host: HostUserName,
    },

    RemoveHostFromShareGroup {
        group: GroupName,
        host: HostUserName,
    },

    EnsureCoworkDir {
        path: PathBuf,
        owner: HostUserName,
        group: GroupName,
        mode: u32,
    },

    /// An OS update can reset a local account's `PrimaryGroupID` to `staff` (20), breaking
    /// share + cowork access and granting `staff`'s reach into the host home.
    EnsurePrimaryGroup {
        name: TenantUserName,
        gid: GroupId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOp {
    /// Idempotent overwrite with the default profile content.
    Create { name: TenantUserName },

    /// Idempotent: absent profile is success.
    Delete { name: TenantUserName },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMode {
    Ro,
    Rw,
}

impl AclMode {
    pub fn acl_bits(self) -> &'static str {
        match self {
            AclMode::Ro => "read,execute,file_inherit,directory_inherit",
            AclMode::Rw => "read,write,execute,delete,append,file_inherit,directory_inherit",
        }
    }
}

/// Unprivileged (no `sudo`): the operator must own or have ACL-write on `path`.
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

/// `RemoveAnchor` (absent file) and `Enable` (already enabled) are idempotent.
/// `BackupConfig` writes a fixed path, no timestamps, so recovery is deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallOp {
    InstallAnchor { name: TenantUserName, body: String },

    RemoveAnchor { name: TenantUserName },

    BackupConfig,

    RestoreConfigFromBackup,

    UpdateConfig { content: String },

    Reload,

    FlushAnchor { name: TenantUserName },

    Enable,
}

/// Not `login.keychain-db`: macOS 26.6 binds that name to the Data Protection keybag and
/// refuses it outside the user's login session, which `sudo -iu` is. Other names work on
/// every release.
pub const TENANT_KEYCHAIN_FILE: &str = "tenant.keychain-db";

pub fn tenant_keychain_path(name: &str) -> String {
    format!("/Users/{name}/Library/Keychains/{TENANT_KEYCHAIN_FILE}")
}

/// Pre-creates the tenant keychain so credential-storing apps don't hit "could not find
/// the keychain", and stashes its password in the OPERATOR's keychain so `shell` /
/// `bootstrap` can unlock it non-interactively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainOp {
    /// "Already exists" maps to `Ok(())` in the adapter.
    CreateTenantKeychain {
        name: TenantUserName,
        password: KeychainPassword,
    },

    /// Natively idempotent (overwrites the pointer).
    SetDefaultKeychain { name: TenantUserName },

    // TODO(smell): rename AddKeychainToSearchList; it replaces the search list rather than appending
    /// Replaces the search list with just this keychain (+ the implicit system keychain).
    AddKeychainToSearchList { name: TenantUserName },

    /// No flags = no auto-lock, no lock-on-sleep; load-bearing for OAuth tokens persisting.
    DisableKeychainAutoLock { name: TenantUserName },

    /// The password rides argv: `security -w` has no stdin mode (`-` is a literal password).
    /// Brief argv exposure is accepted over Security.framework FFI. Service `tenant-<name>`
    /// is the contract the `shell` / `bootstrap` unlock reads.
    StashPassword {
        name: TenantUserName,
        password: KeychainPassword,
    },

    /// An absent entry maps to `KeychainError::NotFound`, which destroy treats as converged.
    DeleteStashedPassword { name: TenantUserName },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PamOp {
    /// Appends `pam_tid` to `/etc/pam.d/sudo_local`; no-ops if `sudo` or `sudo_local`
    /// already has it.
    EnableTouchIdForSudo,
}

/// Display-only umbrella; execution stays on the per-domain ADTs to keep their error types.
pub enum Op<'a> {
    Account(&'a AccountOp),
    Profile(&'a ProfileOp),
    Firewall(&'a FirewallOp),
    Acl(&'a AclOp),
    Keychain(&'a KeychainOp),
    Pam(&'a PamOp),
}

impl<'a> Op<'a> {
    pub fn describe_via(&self, machine: &dyn HostMachine) -> String {
        match self {
            Op::Account(op) => machine.describe_account(op),
            Op::Profile(op) => machine.describe_profile(op),
            Op::Firewall(op) => machine.describe_firewall(op),
            Op::Acl(op) => machine.describe_acl(op),
            Op::Keychain(op) => machine.describe_keychain(op),
            Op::Pam(op) => machine.describe_pam(op),
        }
    }

    // TODO(smell): rename business_label / intent_label so the names say past-tense progress line vs plan bullet
    /// Past-tense `✓` progress line.
    pub fn business_label(&self) -> String {
        match self {
            Op::Account(op) => account_business_label(op),
            Op::Profile(op) => profile_business_label(op),
            Op::Firewall(op) => firewall_business_label(op),
            Op::Acl(op) => acl_business_label(op),
            Op::Keychain(op) => keychain_business_label(op),
            Op::Pam(op) => pam_business_label(op),
        }
    }

    /// Future-tense verbose plan bullet.
    pub fn intent_label(&self) -> String {
        match self {
            Op::Account(op) => account_intent_label(op),
            Op::Profile(op) => profile_intent_label(op),
            Op::Firewall(op) => firewall_intent_label(op),
            Op::Acl(op) => acl_intent_label(op),
            Op::Keychain(op) => keychain_intent_label(op),
            Op::Pam(op) => pam_intent_label(op),
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
        AccountOp::LoginAsUser { name, .. } => format!("Entering shell as '{name}'"),
        AccountOp::ExecAsUser { name, argv, .. } => {
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
        AccountOp::EnsurePrimaryGroup { name, gid } => {
            format!("Tenant '{name}' primary group set to GID {gid}")
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
        KeychainOp::CreateTenantKeychain { name, .. } => {
            format!("Tenant '{name}' keychain created")
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

fn in_dir_suffix(dir: &Option<PathBuf>) -> String {
    dir.as_ref()
        .map(|d| format!(" in {}", d.display()))
        .unwrap_or_default()
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
        AccountOp::LoginAsUser { name, dir } => {
            format!("Log in as '{name}'{}", in_dir_suffix(dir))
        }
        AccountOp::ExecAsUser { name, argv, dir } => {
            // Unescaped on purpose: display-only, and the operator typed it.
            format!("Run as '{name}': {}{}", argv.join(" "), in_dir_suffix(dir))
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
        AccountOp::EnsurePrimaryGroup { name, gid } => {
            format!("Set tenant '{name}' primary group to GID {gid}")
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
        KeychainOp::CreateTenantKeychain { name, .. } => {
            format!("Create keychain for tenant '{name}'")
        }
        KeychainOp::SetDefaultKeychain { name } => {
            format!("Set tenant '{name}' default keychain to {TENANT_KEYCHAIN_FILE}")
        }
        KeychainOp::AddKeychainToSearchList { name } => {
            format!("Add {TENANT_KEYCHAIN_FILE} to tenant '{name}' search list")
        }
        KeychainOp::DisableKeychainAutoLock { name } => {
            format!("Disable auto-lock on tenant '{name}' keychain")
        }
        KeychainOp::StashPassword { name, .. } => {
            format!("Stash tenant '{name}' password in operator keychain")
        }
        KeychainOp::DeleteStashedPassword { name } => {
            format!("Remove tenant '{name}' password from operator keychain")
        }
    }
}

fn pam_business_label(op: &PamOp) -> String {
    match op {
        PamOp::EnableTouchIdForSudo => {
            "Touch ID for sudo enabled in /etc/pam.d/sudo_local".to_string()
        }
    }
}

fn pam_intent_label(op: &PamOp) -> String {
    match op {
        PamOp::EnableTouchIdForSudo => {
            "Enable Touch ID for sudo in /etc/pam.d/sudo_local".to_string()
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

impl WritableOp for PamOp {
    type Error = HostFileError;
    fn execute_via(&self, machine: &dyn HostMachine) -> Result<(), HostFileError> {
        machine.execute_pam(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Pam(self)
    }
}
