use super::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupId, GroupName, HostFileError, HostUserName, KeychainError, KeychainOp, KeychainPassword,
    Op, PamOp, PathKind, ProbeError, ProfileOp, TenantUserName,
};
use crate::profile::ProfileError;

/// Driven port for host-side substrate. Per-domain `describe_*` / `execute_*`
/// pairs over the four `Op` ADTs, plus carve-out methods for operations whose
/// return shape doesn't fit `Result<(), E>`. Each domain keeps its own error
/// type.
pub trait HostMachine {
    fn describe_account(&self, op: &AccountOp) -> String;
    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError>;

    /// Interactive login as the tenant. Returns the child's exit code; stdio
    /// inherits from the calling process.
    fn login(&self, name: &TenantUserName) -> Result<i32, AccountError>;

    /// Run a single command as the tenant inside a login shell. Returns the
    /// child's exit code; stdio inherits. `argv` must be non-empty.
    fn exec_as_tenant(&self, name: &TenantUserName, argv: &[String]) -> Result<i32, AccountError>;

    fn describe_profile(&self, op: &ProfileOp) -> String;
    fn execute_profile(&self, op: &ProfileOp) -> Result<(), ProfileError>;

    fn read_profile(&self, name: &TenantUserName) -> Result<String, ProfileError>;

    /// Reads the primary gid of the named share group via `dscl . -read
    /// /Groups/<group> PrimaryGroupID`. Full reapply calls this to
    /// resolve the gid for `AccountOp::EnsurePrimaryGroup` before
    /// constructing the op: the tenant's primary group must match the
    /// LIVE share-group record, whose gid was allocated at create and is
    /// not derivable from the name (UID/GID may diverge). Unprivileged
    /// read (group records are world-readable on macOS), so it is safe to
    /// run pre-prompt during plan-build without tripping the uncached-sudo
    /// path. An absent group or unparseable record surfaces as `ProbeError`.
    fn read_share_group_gid(&self, group: &GroupName) -> Result<GroupId, ProbeError>;

    fn read_pf_conf(&self) -> Result<String, FirewallError>;

    fn describe_firewall(&self, op: &FirewallOp) -> String;
    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError>;

    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<PathKind, ProbeError>;

    /// Reads filesystem kind of a host-side path via the host's identity
    /// (no `sudo`, no tenant impersonation). Use this for paths the host
    /// owns by design — cowork dirs, operator-managed state. Use
    /// `tenant_path_kind` for paths whose accessibility depends on the
    /// tenant's perspective (declared share `tenant_path`s).
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

    fn read_pam_sudo(&self) -> Result<String, HostFileError>;

    /// Reads `/etc/pam.d/sudo_local` — the OS-update-safe customization
    /// file that `/etc/pam.d/sudo` includes at the top of its stack on
    /// modern macOS. Touch ID configured the sanctioned way lands here,
    /// so doctor's detection must consult it alongside `read_pam_sudo`.
    /// An absent file is non-error: returns `Ok(String::new())` (the
    /// file is optional; absence just means "no local customizations").
    fn read_pam_sudo_local(&self) -> Result<String, HostFileError>;

    fn read_pf_status(&self) -> Result<String, FirewallError>;

    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError>;

    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError>;

    /// Identity of the operator invoking the binary, used in plan rendering
    /// and as the host-side member of every tenant's share group. Infallible:
    /// adapters fall back to a placeholder rather than failing the verb.
    fn current_host_user_name(&self) -> HostUserName;

    /// An absent group is non-error: returns `Ok(false)`.
    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError>;

    /// True iff the operator already holds a valid cached sudo
    /// timestamp (`sudo -n -v` exits 0). Non-interactive by design:
    /// this is a CHECK, never a prompt. The pre-exec doctor pass gates
    /// every sudo-dependent probe behind it so an uncached operator
    /// sees neither an auth prompt nor a wall of probe-failure frames
    /// pre-consent. Infallible: any spawn/exec hiccup reads as "not
    /// cached" (false), so the gate fails closed (skip probes) rather
    /// than open (spam failures).
    fn sudo_session_cached(&self) -> bool;

    /// True iff `/Users/<tenant>/Library/Keychains/login.keychain-db`
    /// is present on disk. Doctor consults this to surface
    /// `Finding::TenantKeychainAbsent`. Filesystem-existence check from
    /// the operator process — mirrors `tenant_path_kind`'s shape.
    fn tenant_keychain_present(&self, name: &TenantUserName) -> Result<bool, ProbeError>;

    /// True iff the operator's login keychain carries a
    /// generic-password entry under (account=tenant,
    /// service=tenant-<tenant>). Doctor consults this to surface
    /// `Finding::StashAbsent`. Dispatches via `security`, so all the
    /// substrate failures map to `KeychainError`.
    fn stash_present(&self, name: &TenantUserName) -> Result<bool, KeychainError>;

    /// Retrieve the operator-stashed password via
    /// `security find-generic-password -a <name> -s tenant-<name> -w`.
    /// Stash-absent maps to `KeychainError::NotFound`.
    fn find_stashed_password(
        &self,
        name: &TenantUserName,
    ) -> Result<KeychainPassword, KeychainError>;

    /// Unlock the tenant's `login.keychain-db` via
    /// `sudo -iu <name> security unlock-keychain -p <pw> login.keychain-db`.
    /// Already-unlocked exits 0 on the substrate — no idempotence guard.
    fn unlock_tenant_keychain(
        &self,
        name: &TenantUserName,
        password: &KeychainPassword,
    ) -> Result<(), KeychainError>;
}

/// Leaf-op dispatch to the `HostMachine` with a domain-specific error type.
/// `op_ref` projects into the `Op<'_>` umbrella for unified rendering.
pub trait WritableOp {
    type Error;
    fn execute_via(&self, machine: &dyn HostMachine) -> Result<(), Self::Error>;
    fn op_ref(&self) -> Op<'_>;
}
