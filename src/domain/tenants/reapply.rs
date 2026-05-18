//! Mode/reload reapply error type. Used by `mode`, the `shell` command
//! form's auto-narrow, `reload`, and the create-side post-provision
//! share pass.

use crate::ModeLevel;
use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, AclError, FirewallError, FirewallOp, HostUserDirectory, HostUserName,
    Op, ProbeError, TenantUserName, UserDirectoryError,
};
use crate::firewall::render_anchor;
use crate::profile::{Profile, ProfileError, parse};

use super::shares::ShareOps;
use super::{ShareError, Tenants, tenant_share_group_name};

/// Failure surface for `mode` and (by reuse) the `shell` auto-narrow,
/// `reload`, and the create-side post-provision share step. ModeError
/// does NOT carry a `UserDirectoryLookup` variant: no method on this
/// surface queries `HostUserDirectory`, so directory failures can only
/// reach dispatch via the dedicated `tenant_names()` call in
/// `reload_all` (which returns `UserDirectoryError` directly).
#[derive(Debug)]
pub(crate) enum ModeError {
    Profile(ProfileError),
    Firewall(FirewallError),
    Acl(AclError),
    Account(AccountError),
    Probe(ProbeError),
    Share(ShareError),
}

/// Pre-built op list for a profile-to-tenant reapply. Construction is
/// separated from execution so verb methods can render the upfront
/// plan over the same ops the substrate will run.
///
/// `add_host` is the catch-up op that restores host membership for
/// legacy tenants created before host membership was wired into create.
pub(crate) struct ReapplyPlan {
    pub(crate) install_anchor: FirewallOp,
    pub(crate) reload: FirewallOp,
    pub(crate) add_host: AccountOp,
    pub(crate) share_ops: Vec<ShareOps>,
}

impl ReapplyPlan {
    pub(crate) fn as_plan_entries(&self) -> Vec<(Op<'_>, Option<&'static str>)> {
        let mut entries: Vec<(Op<'_>, Option<&'static str>)> =
            Vec::with_capacity(3 + self.share_ops.iter().map(|s| s.op_count()).sum::<usize>());
        entries.push((Op::Firewall(&self.install_anchor), None));
        entries.push((Op::Firewall(&self.reload), None));
        entries.push((Op::Account(&self.add_host), None));
        for share in &self.share_ops {
            entries.push((Op::Acl(&share.grant), None));
            if let Some(ensure_dir) = &share.ensure_dir {
                entries.push((Op::Account(ensure_dir), None));
            }
            entries.push((Op::Account(&share.ensure_link), None));
        }
        entries
    }
}

#[derive(Debug)]
pub(crate) struct ReloadAllOutcome {
    pub(crate) failed: u32,
}

/// Runtime: runtime hosts only. Install: runtime then install (order
/// matters for `render_anchor`'s output stability).
pub(crate) fn hosts_for_level(profile: &Profile, level: ModeLevel) -> Vec<String> {
    match level {
        ModeLevel::Runtime => profile.allowlist.runtime.hosts.clone(),
        ModeLevel::Install => {
            let mut hosts = profile.allowlist.runtime.hosts.clone();
            hosts.extend(profile.allowlist.install.hosts.iter().cloned());
            hosts
        }
    }
}

impl<'a> Tenants<'a> {
    /// Apply a pre-built reapply plan at the requested tier. The plan
    /// is built upstream so profile-read failures surface pre-prompt.
    pub(crate) fn mode(
        &self,
        name: &TenantUserName,
        level: ModeLevel,
        plan: &ReapplyPlan,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        reporter.mode_intent(name, level);
        self.execute_reapply_plan(plan, reporter)?;
        reporter.mode_done(name, level);
        Ok(())
    }

    /// Build the op list for a profile-to-tenant reapply at `level`.
    /// Pre-flight refusals (host_path existence, tenant_path occupancy)
    /// surface before any op fires.
    pub(crate) fn build_reapply_plan(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        level: ModeLevel,
    ) -> Result<ReapplyPlan, ModeError> {
        let profile_content = self
            .machine
            .read_profile(name)
            .map_err(ModeError::Profile)?;
        let parsed_profile = parse(&profile_content).map_err(ModeError::Profile)?;
        let hosts = hosts_for_level(&parsed_profile, level);
        let install_anchor = FirewallOp::InstallAnchor {
            name: name.into(),
            body: render_anchor(name.as_str(), &hosts),
        };
        let reload = FirewallOp::Reload;
        let add_host = AccountOp::AddHostToShareGroup {
            group: tenant_share_group_name(name.as_str()),
            host: host.into(),
        };
        let share_ops = self.build_share_ops(name, &parsed_profile)?;
        Ok(ReapplyPlan {
            install_anchor,
            reload,
            add_host,
            share_ops,
        })
    }

    /// PF reapply first; a Reload failure aborts before any share
    /// mutation. `add_host` fires before the per-share ops because host
    /// needs the membership for the inheritable ACL grant to flow through.
    pub(crate) fn execute_reapply_plan(
        &self,
        plan: &ReapplyPlan,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        self.run(&plan.install_anchor, reporter)
            .map_err(ModeError::Firewall)?;
        self.run(&plan.reload, reporter)
            .map_err(ModeError::Firewall)?;
        self.run(&plan.add_host, reporter)
            .map_err(ModeError::Account)?;
        self.execute_share_ops(&plan.share_ops, reporter)
    }

    /// Runtime-tier reapply from a pre-built plan. Profile-read /
    /// share-pre-flight failures surface at the build site upstream.
    pub(crate) fn reload(
        &self,
        name: &TenantUserName,
        plan: &ReapplyPlan,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        reporter.reload_intent(name);
        self.execute_reapply_plan(plan, reporter)?;
        reporter.reload_done(name);
        Ok(())
    }

    /// Walk every tenant. Continue on per-tenant failure, accumulate,
    /// surface a single end-of-run summary.
    pub(crate) fn reload_all(
        &self,
        directory: &dyn HostUserDirectory,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<ReloadAllOutcome, UserDirectoryError> {
        let names = directory.tenant_names()?;
        reporter.reload_all_starting(names.len());
        if names.is_empty() {
            reporter.reload_all_done_summary(0, 0);
            return Ok(ReloadAllOutcome { failed: 0 });
        }
        let mut failed = 0;
        for name in &names {
            let outcome = match self.build_reapply_plan(name, host, ModeLevel::Runtime) {
                Ok(plan) => self.reload(name, &plan, reporter),
                Err(err) => Err(err),
            };
            if let Err(err) = outcome {
                failed += 1;
                match &err {
                    ModeError::Profile(e) => reporter.reload_profile_failed(name, e),
                    ModeError::Firewall(e) => reporter.reload_firewall_failed(name, e),
                    ModeError::Acl(e) => reporter.mode_acl_failed(name, e),
                    ModeError::Account(e) => reporter.mode_account_failed(name, e),
                    ModeError::Probe(e) => reporter.mode_probe_failed(name, e),
                    ModeError::Share(e) => reporter.refuse_reload_share(name, e),
                }
            }
        }
        reporter.reload_all_done_summary(names.len() - failed as usize, failed as usize);
        Ok(ReloadAllOutcome { failed })
    }
}
