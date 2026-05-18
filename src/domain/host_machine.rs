use super::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupName, HostFileError, HostUserName, Op, PathKind, ProbeError, ProfileOp, TenantUserName,
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

    fn read_pf_conf(&self) -> Result<String, FirewallError>;

    fn describe_firewall(&self, op: &FirewallOp) -> String;
    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError>;

    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<PathKind, ProbeError>;

    fn describe_acl(&self, op: &AclOp) -> String;
    fn execute_acl(&self, op: &AclOp) -> Result<(), AclError>;

    fn probe_access_as_tenant(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
        mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError>;

    fn read_env_policy(&self) -> Result<String, HostFileError>;

    fn read_kernel_pf_rules(&self, name: &TenantUserName) -> Result<String, FirewallError>;

    fn read_pam_sudo(&self) -> Result<String, HostFileError>;

    fn read_pf_status(&self) -> Result<String, FirewallError>;

    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError>;

    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError>;

    /// Identity of the operator invoking the binary, used in plan rendering
    /// and as the host-side member of every tenant's share group. Infallible:
    /// adapters fall back to a placeholder rather than failing the verb.
    fn current_host_user_name(&self) -> HostUserName;

    /// An absent group is non-error: returns `Ok(false)`.
    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError>;
}

/// Leaf-op dispatch to the `HostMachine` with a domain-specific error type.
/// `op_ref` projects into the `Op<'_>` umbrella for unified rendering.
pub trait WritableOp {
    type Error;
    fn execute_via(&self, machine: &dyn HostMachine) -> Result<(), Self::Error>;
    fn op_ref(&self) -> Op<'_>;
}
