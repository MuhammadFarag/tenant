use super::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupId, GroupName, HostFileError, HostUserName, KeychainError, KeychainOp, KeychainPassword,
    Op, PamOp, PathKind, ProbeError, ProfileOp, TenantUserName,
};
use crate::profile::ProfileError;

pub trait HostMachine {
    fn describe_account(&self, op: &AccountOp) -> String;
    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError>;

    /// Returns the child's exit code; stdio inherits. `dir` arrives resolved and probed.
    fn login(
        &self,
        name: &TenantUserName,
        dir: Option<&std::path::Path>,
    ) -> Result<i32, AccountError>;

    /// Runs in a login shell; returns the child's exit code. `argv` must be non-empty.
    fn exec_as_tenant(
        &self,
        name: &TenantUserName,
        argv: &[String],
        dir: Option<&std::path::Path>,
    ) -> Result<i32, AccountError>;

    fn describe_profile(&self, op: &ProfileOp) -> String;
    fn execute_profile(&self, op: &ProfileOp) -> Result<(), ProfileError>;

    fn read_profile(&self, name: &TenantUserName) -> Result<String, ProfileError>;

    /// `fragment` is safe as a path segment: `validate_fragment_name` already ran at parse.
    fn read_profile_fragment(&self, fragment: &str) -> Result<String, ProfileError>;

    /// Unprivileged (group records are world-readable), so plan-build can call it
    /// pre-prompt without tripping the uncached-sudo path.
    fn read_share_group_gid(&self, group: &GroupName) -> Result<GroupId, ProbeError>;

    /// Unprivileged: user records are world-readable.
    fn read_user_primary_gid(&self, name: &TenantUserName) -> Result<GroupId, ProbeError>;

    fn read_pf_conf(&self) -> Result<String, FirewallError>;

    fn pf_conf_references_anchor(&self, name: &TenantUserName) -> Result<bool, FirewallError>;

    fn describe_firewall(&self, op: &FirewallOp) -> String;
    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError>;

    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<PathKind, ProbeError>;

    // TODO(smell): rename tenant_dir_present / tenant_path_kind so the names say follows-symlinks vs lstat-classifies
    /// Follows symlinks (`test -d`): a dangling link must fail `tenant shell -d`'s pre-flight.
    fn tenant_dir_present(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<bool, ProbeError>;

    fn host_path_kind(&self, path: &std::path::Path) -> Result<PathKind, ProbeError>;

    fn describe_acl(&self, op: &AclOp) -> String;
    fn execute_acl(&self, op: &AclOp) -> Result<(), AclError>;

    fn describe_keychain(&self, op: &KeychainOp) -> String;
    fn execute_keychain(&self, op: &KeychainOp) -> Result<(), KeychainError>;

    fn describe_pam(&self, op: &PamOp) -> String;
    fn execute_pam(&self, op: &PamOp) -> Result<(), HostFileError>;

    fn probe_access_as_tenant(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
        mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError>;

    fn read_env_policy(&self) -> Result<String, HostFileError>;

    fn read_kernel_pf_rules(&self, name: &TenantUserName) -> Result<String, FirewallError>;

    /// `pfctl -T show` output for one table of the tenant's loaded anchor.
    fn read_kernel_pf_table(
        &self,
        name: &TenantUserName,
        table: &str,
    ) -> Result<String, FirewallError>;

    /// The host's system resolver: the same lookup pf ran at anchor load.
    fn resolve_host(&self, host: &str) -> Result<Vec<std::net::IpAddr>, ProbeError>;

    fn read_pam_sudo(&self) -> Result<String, HostFileError>;

    /// Absent file ⇒ `Ok(String::new())`. Sanctioned Touch ID setup lands here, so doctor
    /// must check it alongside `read_pam_sudo`.
    fn read_pam_sudo_local(&self) -> Result<String, HostFileError>;

    fn read_pf_status(&self) -> Result<String, FirewallError>;

    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError>;

    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError>;

    /// Infallible: adapters fall back to a placeholder rather than failing the verb.
    fn current_host_user_name(&self) -> HostUserName;

    /// An absent group is non-error: returns `Ok(false)`.
    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError>;

    /// A check, never a prompt. Any spawn failure reads as `false`, so the pre-exec
    /// doctor gate fails closed (skips sudo probes) instead of spamming failures.
    fn sudo_session_cached(&self) -> bool;

    /// Prompting counterpart (`sudo -v`), post-consent: lets deferred `sudo -n` probes
    /// answer before the first mutation.
    fn authenticate_sudo(&self) -> Result<(), ProbeError>;

    fn tenant_keychain_present(&self, name: &TenantUserName) -> Result<bool, ProbeError>;

    fn stash_present(&self, name: &TenantUserName) -> Result<bool, KeychainError>;

    /// Stash-absent maps to `KeychainError::NotFound`.
    fn find_stashed_password(
        &self,
        name: &TenantUserName,
    ) -> Result<KeychainPassword, KeychainError>;

    /// Already-unlocked exits 0 on the substrate, so no idempotence guard.
    fn unlock_tenant_keychain(
        &self,
        name: &TenantUserName,
        password: &KeychainPassword,
    ) -> Result<(), KeychainError>;
}

pub trait WritableOp {
    type Error;
    fn execute_via(&self, machine: &dyn HostMachine) -> Result<(), Self::Error>;
    fn op_ref(&self) -> Op<'_>;
}
