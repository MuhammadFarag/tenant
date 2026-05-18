#![allow(dead_code)]

use tenant::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupName, HostFileError, HostMachine, HostUserName, PathKind, ProbeError, ProfileOp,
    TenantUserName,
};

/// Default host machine for tests that should not reach the exec stage —
/// validation failures, conflicts, and dry-run paths. Panics on any
/// substrate call, so any accidental invocation from a path that's
/// meant to be no-op surfaces loudly instead of being silently absorbed.
pub struct NeverHostMachine;
impl HostMachine for NeverHostMachine {
    fn describe_account(&self, op: &AccountOp) -> String {
        panic!("host machine unexpectedly invoked (describe_account) with op: {op:?}");
    }
    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        panic!("host machine unexpectedly invoked (execute_account) with op: {op:?}");
    }
    fn login(&self, name: &TenantUserName) -> Result<i32, AccountError> {
        panic!("host machine unexpectedly invoked (login) with name: {name:?}");
    }
    fn exec_as_tenant(&self, name: &TenantUserName, argv: &[String]) -> Result<i32, AccountError> {
        panic!("host machine unexpectedly invoked (exec_as_tenant): name={name:?} argv={argv:?}");
    }
    fn describe_profile(&self, op: &ProfileOp) -> String {
        panic!("host machine unexpectedly invoked (describe_profile) with op: {op:?}");
    }
    fn execute_profile(&self, op: &ProfileOp) -> Result<(), tenant::profile::ProfileError> {
        panic!("host machine unexpectedly invoked (execute_profile) with op: {op:?}");
    }
    fn read_profile(&self, name: &TenantUserName) -> Result<String, tenant::profile::ProfileError> {
        panic!("host machine unexpectedly invoked (read_profile) with name: {name:?}");
    }
    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        panic!("host machine unexpectedly invoked (read_pf_conf)");
    }
    fn describe_firewall(&self, op: &FirewallOp) -> String {
        panic!("host machine unexpectedly invoked (describe_firewall) with op: {op:?}");
    }
    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError> {
        panic!("host machine unexpectedly invoked (execute_firewall) with op: {op:?}");
    }
    fn probe_access_as_tenant(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
        mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError> {
        panic!(
            "host machine unexpectedly invoked (probe_access_as_tenant): name={name:?} path={path:?} mode={mode:?}"
        );
    }
    fn read_env_policy(&self) -> Result<String, HostFileError> {
        panic!("host machine unexpectedly invoked (read_env_policy)");
    }
    fn read_kernel_pf_rules(&self, name: &TenantUserName) -> Result<String, FirewallError> {
        panic!("host machine unexpectedly invoked (read_kernel_pf_rules): name={name:?}");
    }
    fn read_pam_sudo(&self) -> Result<String, HostFileError> {
        panic!("host machine unexpectedly invoked (read_pam_sudo)");
    }
    fn read_pf_status(&self) -> Result<String, FirewallError> {
        panic!("host machine unexpectedly invoked (read_pf_status)");
    }
    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        panic!("host machine unexpectedly invoked (read_anchor_body): name={name:?}");
    }
    fn describe_acl(&self, op: &AclOp) -> String {
        panic!("host machine unexpectedly invoked (describe_acl) with op: {op:?}");
    }
    fn execute_acl(&self, op: &AclOp) -> Result<(), AclError> {
        panic!("host machine unexpectedly invoked (execute_acl) with op: {op:?}");
    }
    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<PathKind, ProbeError> {
        panic!("host machine unexpectedly invoked (tenant_path_kind): name={name:?} path={path:?}");
    }
    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError> {
        panic!("host machine unexpectedly invoked (read_host_acl): path={path:?}");
    }
    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError> {
        panic!("host machine unexpectedly invoked (host_in_group): host={host:?} group={group:?}");
    }
}
