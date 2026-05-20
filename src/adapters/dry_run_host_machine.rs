use crate::adapters::macos::MacosHostMachine;
use crate::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupName, HostFileError, HostMachine, HostUserName, KeychainError, KeychainOp,
    KeychainPassword, PathKind, ProbeError, ProfileOp, TenantUserName,
};
use crate::profile::{ProfileError, default_profile_toml};

/// Carries the operator identity resolved on the real (non-dry-run) machine
/// before construction — `MacosHostMachine` reads env vars there, and dry-run
/// preserves that answer so plan-render names the actual invoker.
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
    fn login(&self, _name: &TenantUserName) -> Result<i32, AccountError> {
        Ok(0)
    }
    fn exec_as_tenant(
        &self,
        _name: &TenantUserName,
        _argv: &[String],
    ) -> Result<i32, AccountError> {
        Ok(0)
    }
    fn describe_profile(&self, op: &ProfileOp) -> String {
        MacosHostMachine.describe_profile(op)
    }
    fn execute_profile(&self, _op: &ProfileOp) -> Result<(), ProfileError> {
        Ok(())
    }
    /// Returns the scaffolded default so the post-`ProfileOp::Create` read
    /// matches the operator's mental model of "the file would now exist".
    fn read_profile(&self, _name: &TenantUserName) -> Result<String, ProfileError> {
        Ok(default_profile_toml())
    }
    /// Empty pf.conf so the plan focuses on what tenant adds, not what's
    /// already there.
    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        Ok(String::new())
    }
    fn describe_firewall(&self, op: &FirewallOp) -> String {
        MacosHostMachine.describe_firewall(op)
    }
    fn execute_firewall(&self, _op: &FirewallOp) -> Result<(), FirewallError> {
        Ok(())
    }

    /// `Unknown` rather than a fabricated Allowed/Denied — defensive;
    /// the doctor arm short-circuits before reaching this under `--dry-run`.
    fn probe_access_as_tenant(
        &self,
        _name: &TenantUserName,
        _path: &std::path::Path,
        _mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError> {
        Ok(AccessOutcome::Unknown)
    }

    /// "No-leak" placeholder so the preview doesn't fire a spurious
    /// `EnvLeak` finding the operator might then chase outside a real run.
    fn read_env_policy(&self) -> Result<String, HostFileError> {
        Ok("Defaults env_delete += \"SSH_AUTH_SOCK\"\n".to_string())
    }

    /// "No-drift" placeholder so the preview doesn't fire a spurious
    /// `PfRuleDrift` finding.
    fn read_kernel_pf_rules(&self, _name: &TenantUserName) -> Result<String, FirewallError> {
        Ok(
            "block return inet from any to any\npass inet from 192.0.2.1 to <allowed> keep state\n"
                .to_string(),
        )
    }

    /// "Touch-ID-present" placeholder so the preview doesn't fire a
    /// spurious `TouchIdMissing` finding.
    fn read_pam_sudo(&self) -> Result<String, HostFileError> {
        Ok("auth       sufficient     pam_tid.so\n".to_string())
    }

    /// "Pf enabled" placeholder so the preview doesn't fire a spurious
    /// `PfDisabled` finding.
    fn read_pf_status(&self) -> Result<String, FirewallError> {
        Ok("Status: Enabled for 0 days 00:00:00\n".to_string())
    }

    /// Empty-allowlist render matches the `default_profile_toml()` returned
    /// by `read_profile`, so the preview never fires a spurious
    /// `AnchorBodyDrift` finding.
    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        Ok(crate::firewall::render_anchor(name.as_str(), &[]))
    }

    fn describe_acl(&self, op: &AclOp) -> String {
        MacosHostMachine.describe_acl(op)
    }

    fn execute_acl(&self, _op: &AclOp) -> Result<(), AclError> {
        Ok(())
    }

    /// `Absent` so the preview shows what tenant would install rather than
    /// a `TenantPathOccupied` refusal driven by unrelated host state.
    fn tenant_path_kind(
        &self,
        _name: &TenantUserName,
        _path: &std::path::Path,
    ) -> Result<PathKind, ProbeError> {
        Ok(PathKind::Absent)
    }

    /// Empty listing. Unreachable today (default profile has no
    /// `[[shares]]`); defensive against a future default share.
    fn read_host_acl(&self, _path: &std::path::Path) -> Result<String, ProbeError> {
        Ok(String::new())
    }

    fn current_host_user_name(&self) -> HostUserName {
        self.host.clone()
    }

    /// `true` so the preview doesn't fire a spurious `HostNotInShareGroup`
    /// finding.
    fn host_in_group(
        &self,
        _host: &HostUserName,
        _group: &GroupName,
    ) -> Result<bool, AccountError> {
        Ok(true)
    }

    fn describe_keychain(&self, op: &KeychainOp) -> String {
        MacosHostMachine.describe_keychain(op)
    }

    fn execute_keychain(&self, _op: &KeychainOp) -> Result<(), KeychainError> {
        Ok(())
    }

    /// `true` so the preview doesn't fire a spurious
    /// `TenantKeychainAbsent` finding.
    fn tenant_keychain_present(&self, _name: &TenantUserName) -> Result<bool, ProbeError> {
        Ok(true)
    }

    /// `true` so the preview doesn't fire a spurious `StashAbsent`
    /// finding.
    fn stash_present(&self, _name: &TenantUserName) -> Result<bool, KeychainError> {
        Ok(true)
    }

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
