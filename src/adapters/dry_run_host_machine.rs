//! Mode swap-in for `--dry-run`. Composition root selects this when
//! `cli.dry_run` is set; the writer stays mode-agnostic. Describe still
//! renders display lines (the verbose dry-run plan needs them); execute
//! is a no-op.

use crate::adapters::macos::MacosHostMachine;
use crate::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupName, HostFileError, HostMachine, HostUserName, PathKind, ProbeError, ProfileOp,
    TenantUserName,
};
use crate::profile::{ProfileError, default_profile_toml};

/// Mode swap-in for `--dry-run`. Composition root selects this when
/// `cli.dry_run` is set; the writer stays mode-agnostic. Describe still
/// renders display lines (the verbose dry-run plan needs them); execute
/// is a no-op.
pub struct DryRunHostMachine;

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
    /// Dry-run reads return the default profile content. At create-time
    /// the writer reads the profile after the (simulated) `ProfileOp::Create`
    /// step — the operator's mental model is "the file would now exist with
    /// the scaffolded default", so the dry-run read returns exactly that.
    /// No verb reads the profile outside the create flow, so this default
    /// covers every dry-run path that hits `read_profile`.
    fn read_profile(&self, _name: &TenantUserName) -> Result<String, ProfileError> {
        Ok(default_profile_toml())
    }
    /// Dry-run reads return an empty pf.conf — the plan focuses on what
    /// tenant adds to the file, not what's already there. The Writer's
    /// `ensure_anchor_ref(empty, name)` produces a clean two-line conf
    /// representing tenant's contribution.
    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        Ok(String::new())
    }
    fn describe_firewall(&self, op: &FirewallOp) -> String {
        MacosHostMachine.describe_firewall(op)
    }
    fn execute_firewall(&self, _op: &FirewallOp) -> Result<(), FirewallError> {
        Ok(())
    }

    /// Dry-run skips probes entirely. The dispatcher's `Verb::Doctor`
    /// arm short-circuits before calling any host-machine probe under
    /// `--dry-run`; if anything does reach this impl, return Unknown
    /// rather than fabricating a misleading Allowed/Denied answer.
    fn probe_access_as_tenant(
        &self,
        _name: &TenantUserName,
        _path: &std::path::Path,
        _mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError> {
        Ok(AccessOutcome::Unknown)
    }

    /// Dry-run returns a "no-leak" placeholder env policy so the
    /// dry-run plan output doesn't fire an EnvLeak finding. The
    /// real env policy could go either way; for a "would-do"
    /// preview, we lean against producing an actionable warning the
    /// operator might then chase down outside of a real run.
    fn read_env_policy(&self) -> Result<String, HostFileError> {
        Ok("Defaults env_delete += \"SSH_AUTH_SOCK\"\n".to_string())
    }

    /// Dry-run returns a "no-drift" placeholder so the would-do
    /// preview doesn't fire spurious `PfRuleDrift` findings. Same
    /// posture as `read_env_policy`: the plan is about what tenant
    /// WOULD do, not about flagging unrelated host state.
    fn read_kernel_pf_rules(&self, _name: &TenantUserName) -> Result<String, FirewallError> {
        Ok(
            "block return inet from any to any\npass inet from 192.0.2.1 to <allowed> keep state\n"
                .to_string(),
        )
    }

    /// Dry-run returns a "Touch-ID-present" placeholder so the
    /// would-do preview doesn't fire a spurious `TouchIdMissing`
    /// finding. Real pam.d/sudo may differ; we avoid actionable
    /// warnings in the would-do preview.
    fn read_pam_sudo(&self) -> Result<String, HostFileError> {
        Ok("auth       sufficient     pam_tid.so\n".to_string())
    }

    /// Dry-run returns a "pf enabled" placeholder so the would-do
    /// preview doesn't fire a spurious `PfDisabled` finding. Same
    /// posture as the other read_* carve-outs.
    fn read_pf_status(&self) -> Result<String, FirewallError> {
        Ok("Status: Enabled for 0 days 00:00:00\n".to_string())
    }

    /// Dry-run returns the empty-allowlist render so the would-do
    /// preview never fires a spurious `AnchorBodyDrift` finding —
    /// `read_profile` already returns `default_profile_toml()` (empty
    /// allowlists), so a runtime-tier render of the parsed default
    /// is exactly `render_anchor(name, &[])`. Same posture as the
    /// other read_* carve-outs: avoid actionable warnings in the
    /// would-do preview.
    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        Ok(crate::firewall::render_anchor(name.as_str(), &[]))
    }

    fn describe_acl(&self, op: &AclOp) -> String {
        MacosHostMachine.describe_acl(op)
    }

    fn execute_acl(&self, _op: &AclOp) -> Result<(), AclError> {
        Ok(())
    }

    /// Dry-run returns `Absent` so the plan preview never trips the
    /// `TenantPathOccupied` refusal — the operator's "would-do" view
    /// shows what tenant intends to install, not surprise refusals
    /// the real run might encounter on different host state.
    fn tenant_path_kind(
        &self,
        _name: &TenantUserName,
        _path: &std::path::Path,
    ) -> Result<PathKind, ProbeError> {
        Ok(PathKind::Absent)
    }

    /// Dry-run returns an empty listing. Unreachable under production
    /// dry-run because `read_profile` returns `default_profile_toml()`
    /// (no `[[shares]]`), so doctor's per-share-drift loop skips before
    /// reaching this method. Defensive return preserves the
    /// "no actionable warnings in the would-do preview" posture if a
    /// future code path adds a default share.
    fn read_host_acl(&self, _path: &std::path::Path) -> Result<String, ProbeError> {
        Ok(String::new())
    }

    /// Dry-run returns `true` so the would-do preview never trips
    /// doctor's `HostNotInShareGroup` finding — same "no actionable
    /// warnings in dry-run" posture as `read_host_acl` and
    /// `tenant_path_kind`.
    fn host_in_group(
        &self,
        _host: &HostUserName,
        _group: &GroupName,
    ) -> Result<bool, AccountError> {
        Ok(true)
    }
}
