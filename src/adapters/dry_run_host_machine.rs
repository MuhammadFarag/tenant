use crate::adapters::macos::MacosHostMachine;
use crate::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupId, GroupName, HostFileError, HostMachine, HostUserName, KeychainError, KeychainOp,
    KeychainPassword, PamOp, PathKind, ProbeError, ProfileOp, TenantUserName,
};
use crate::profile::{ProfileError, default_profile_toml};

/// Mutations no-op; reads and probes return clean-host placeholders so a preview
/// never fires a spurious doctor finding or refusal. `host` is the invoker resolved
/// by the real machine before construction.
pub struct DryRunHostMachine {
    pub host: HostUserName,
}

impl HostMachine for DryRunHostMachine {
    fn describe_account(&self, op: &AccountOp) -> String {
        MacosHostMachine.describe_account(op)
    }
    fn execute_account(&self, _op: &AccountOp) -> Result<(), AccountError> {
        Ok(())
    }
    fn login(
        &self,
        _name: &TenantUserName,
        _dir: Option<&std::path::Path>,
    ) -> Result<i32, AccountError> {
        Ok(0)
    }
    fn exec_as_tenant(
        &self,
        _name: &TenantUserName,
        _argv: &[String],
        _dir: Option<&std::path::Path>,
    ) -> Result<i32, AccountError> {
        Ok(0)
    }
    fn describe_profile(&self, op: &ProfileOp) -> String {
        MacosHostMachine.describe_profile(op)
    }
    fn execute_profile(&self, _op: &ProfileOp) -> Result<(), ProfileError> {
        Ok(())
    }
    fn read_profile(&self, _name: &TenantUserName) -> Result<String, ProfileError> {
        Ok(default_profile_toml())
    }
    fn read_profile_fragment(&self, _fragment: &str) -> Result<String, ProfileError> {
        Ok(String::new())
    }
    fn read_share_group_gid(&self, _group: &GroupName) -> Result<GroupId, ProbeError> {
        Ok(GroupId(crate::allocation::TENANT_UID_FLOOR))
    }
    fn read_user_primary_gid(&self, _name: &TenantUserName) -> Result<GroupId, ProbeError> {
        Ok(GroupId(crate::allocation::TENANT_UID_FLOOR))
    }
    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        Ok(String::new())
    }
    fn pf_conf_references_anchor(&self, _name: &TenantUserName) -> Result<bool, FirewallError> {
        Ok(true)
    }
    fn describe_firewall(&self, op: &FirewallOp) -> String {
        MacosHostMachine.describe_firewall(op)
    }
    fn execute_firewall(&self, _op: &FirewallOp) -> Result<(), FirewallError> {
        Ok(())
    }

    fn probe_access_as_tenant(
        &self,
        _name: &TenantUserName,
        _path: &std::path::Path,
        _mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError> {
        Ok(AccessOutcome::Unknown)
    }

    fn read_env_policy(&self) -> Result<String, HostFileError> {
        Ok("Defaults env_delete += \"SSH_AUTH_SOCK\"\n".to_string())
    }

    fn read_kernel_pf_rules(&self, _name: &TenantUserName) -> Result<String, FirewallError> {
        Ok(
            "block return inet from any to any\npass inet from 192.0.2.1 to <allowed> keep state\n"
                .to_string(),
        )
    }

    fn read_kernel_pf_table(
        &self,
        _name: &TenantUserName,
        _table: &str,
    ) -> Result<String, FirewallError> {
        Ok(String::new())
    }

    /// Empty so the preview never manufactures a resolve-drift finding.
    fn resolve_host(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, ProbeError> {
        Ok(Vec::new())
    }

    fn read_pam_sudo(&self) -> Result<String, HostFileError> {
        Ok("auth       sufficient     pam_tid.so\n".to_string())
    }

    fn read_pam_sudo_local(&self) -> Result<String, HostFileError> {
        Ok("auth       sufficient     pam_tid.so\n".to_string())
    }

    fn read_pf_status(&self) -> Result<String, FirewallError> {
        Ok("Status: Enabled for 0 days 00:00:00\n".to_string())
    }

    /// Must equal the render for `read_profile`'s default, or `AnchorBodyDrift` fires.
    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        Ok(crate::firewall::render_anchor(
            name.as_str(),
            &[] as &[crate::firewall::EgressHost],
            crate::firewall::InboundRules::Restricted(vec![]),
        ))
    }

    fn describe_acl(&self, op: &AclOp) -> String {
        MacosHostMachine.describe_acl(op)
    }

    fn execute_acl(&self, _op: &AclOp) -> Result<(), AclError> {
        Ok(())
    }

    fn tenant_path_kind(
        &self,
        _name: &TenantUserName,
        _path: &std::path::Path,
    ) -> Result<PathKind, ProbeError> {
        Ok(PathKind::Absent)
    }

    fn tenant_dir_present(
        &self,
        _name: &TenantUserName,
        _path: &std::path::Path,
    ) -> Result<bool, ProbeError> {
        Ok(true)
    }

    /// Cowork-pattern paths synthesize `Dir` (matching `read_host_acl`); other paths
    /// delegate, since create's home-symlink checks need real verdicts.
    fn host_path_kind(&self, path: &std::path::Path) -> Result<PathKind, ProbeError> {
        if path
            .strip_prefix(crate::domain::tenants::COWORK_DIR_PARENT)
            .ok()
            .and_then(|p| p.to_str())
            .is_some_and(|s| !s.is_empty() && !s.contains('/'))
        {
            return Ok(PathKind::Dir);
        }
        MacosHostMachine.host_path_kind(path)
    }

    /// Real ACL drift is invisible under `--dry-run`; the tenant is inferred from a
    /// cowork path's last segment.
    fn read_host_acl_tree(&self, _path: &std::path::Path) -> Result<String, ProbeError> {
        Ok(String::new())
    }

    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError> {
        if let Some(name) = path
            .strip_prefix(crate::domain::tenants::COWORK_DIR_PARENT)
            .ok()
            .and_then(|p| p.to_str())
            .filter(|s| !s.is_empty() && !s.contains('/'))
        {
            return Ok(format!(
                " 0: group:{name}-tenant-share allow read,write,execute,delete,append,file_inherit,directory_inherit\n"
            ));
        }
        Ok(String::new())
    }

    fn current_host_user_name(&self) -> HostUserName {
        self.host.clone()
    }

    fn host_in_group(
        &self,
        _host: &HostUserName,
        _group: &GroupName,
    ) -> Result<bool, AccountError> {
        Ok(true)
    }

    /// `true` so the preview runs the full pre-exec audit against the placeholders
    /// instead of skipping every sudo-gated probe.
    fn sudo_session_cached(&self) -> bool {
        true
    }

    fn authenticate_sudo(&self) -> Result<(), ProbeError> {
        Ok(())
    }

    fn describe_keychain(&self, op: &KeychainOp) -> String {
        MacosHostMachine.describe_keychain(op)
    }

    fn execute_keychain(&self, _op: &KeychainOp) -> Result<(), KeychainError> {
        Ok(())
    }

    fn describe_pam(&self, op: &PamOp) -> String {
        MacosHostMachine.describe_pam(op)
    }

    fn execute_pam(&self, _op: &PamOp) -> Result<(), HostFileError> {
        Ok(())
    }

    fn tenant_keychain_present(&self, _name: &TenantUserName) -> Result<bool, ProbeError> {
        Ok(true)
    }

    fn stash_present(&self, _name: &TenantUserName) -> Result<bool, KeychainError> {
        Ok(true)
    }

    // TODO(smell): NotFound makes every `tenant shell --dry-run` exit 64 via the StashAbsent refusal — return a placeholder
    fn find_stashed_password(
        &self,
        _name: &TenantUserName,
    ) -> Result<KeychainPassword, KeychainError> {
        Err(KeychainError::NotFound)
    }

    fn unlock_tenant_keychain(
        &self,
        _name: &TenantUserName,
        _password: &KeychainPassword,
    ) -> Result<(), KeychainError> {
        Ok(())
    }
}
