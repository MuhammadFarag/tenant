use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, AclError, FirewallError, FirewallOp, HostUserDirectory, HostUserName,
    Op, ProbeError, TenantUserName, UserDirectoryError,
};
use crate::firewall::{
    EgressHost, InboundRules, ensure_anchor_ref, is_anchor_referenced, render_anchor,
};
use crate::profile::{Profile, ProfileError};
use crate::{InboundLevel, ModeLevel};

use super::shares::ShareOps;
use super::{ShareError, Tenants, cowork_dir_path, guard_cowork_dir_kind, tenant_share_group_name};

// TODO(smell): rename ModeError to ReapplyError; it's the error of every reapply, not just `mode`
#[derive(Debug)]
pub(crate) enum ModeError {
    Profile(ProfileError),
    Firewall(FirewallError),
    Acl(AclError),
    Account(AccountError),
    Probe(ProbeError),
    Share(ShareError),
}

/// `Light` (mode, shell) skips the recursive ACL, cowork-dir and primary-group passes;
/// `Full` (reload, create) runs them. Light-skipped drift surfaces via doctor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReapplyScope {
    Light,
    Full,
}

pub(crate) struct ReapplyPlan {
    pub(crate) install_anchor: FirewallOp,
    pub(crate) update_conf: Option<FirewallOp>,
    pub(crate) reload: FirewallOp,
    pub(crate) add_host: AccountOp,
    pub(crate) ensure_primary_group: Option<AccountOp>,
    pub(crate) ensure_cowork_dir: Option<AccountOp>,
    pub(crate) share_ops: Vec<ShareOps>,
}

impl ReapplyPlan {
    pub(crate) fn as_plan_entries(&self) -> Vec<(Op<'_>, Option<&'static str>)> {
        let mut entries: Vec<(Op<'_>, Option<&'static str>)> =
            Vec::with_capacity(6 + self.share_ops.iter().map(|s| s.op_count()).sum::<usize>());
        entries.push((Op::Firewall(&self.install_anchor), None));
        if let Some(update_conf) = &self.update_conf {
            entries.push((
                Op::Firewall(update_conf),
                Some("only when /etc/pf.conf lacks the anchor reference"),
            ));
        }
        entries.push((Op::Firewall(&self.reload), None));
        entries.push((Op::Account(&self.add_host), None));
        if let Some(ensure_primary_group) = &self.ensure_primary_group {
            entries.push((Op::Account(ensure_primary_group), None));
        }
        if let Some(cowork) = &self.ensure_cowork_dir {
            entries.push((Op::Account(cowork), None));
        }
        for share in &self.share_ops {
            if let Some(grant) = &share.grant {
                entries.push((Op::Acl(grant), None));
            }
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

/// The inbound axis for verbs that don't control it; empty ports stays locked.
pub(crate) fn steady_inbound_rules(profile: &Profile) -> InboundRules {
    InboundRules::Restricted(profile.inbound.ports.clone())
}

/// Lives in the domain, not `firewall.rs`, so the renderer stays free of `cli` types.
pub(crate) fn inbound_rules_for_level(profile: &Profile, level: InboundLevel) -> InboundRules {
    match level {
        InboundLevel::Permissive => InboundRules::Permissive,
        InboundLevel::Restricted => InboundRules::Restricted(profile.inbound.ports.clone()),
    }
}

/// Install appends install hosts after runtime; order keeps `render_anchor` output stable.
pub(crate) fn hosts_for_level(profile: &Profile, level: ModeLevel) -> Vec<EgressHost> {
    let to_egress = |entries: &[crate::profile::HostEntry]| -> Vec<EgressHost> {
        entries
            .iter()
            .map(|e| EgressHost {
                host: e.host.clone(),
                ports: e.ports.clone(),
            })
            .collect()
    };
    match level {
        ModeLevel::Runtime => to_egress(&profile.allowlist.runtime.hosts),
        ModeLevel::Install => {
            let mut hosts = to_egress(&profile.allowlist.runtime.hosts);
            hosts.extend(to_egress(&profile.allowlist.install.hosts));
            hosts
        }
    }
}

impl<'a> Tenants<'a> {
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

    pub(crate) fn inbound(
        &self,
        name: &TenantUserName,
        level: InboundLevel,
        plan: &ReapplyPlan,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        reporter.inbound_intent(name, level);
        self.execute_reapply_plan(plan, reporter)?;
        reporter.inbound_done(name, level);
        Ok(())
    }

    pub(crate) fn build_reapply_plan(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        level: ModeLevel,
        inbound_override: Option<InboundLevel>,
        scope: ReapplyScope,
    ) -> Result<ReapplyPlan, ModeError> {
        let parsed_profile = self.load_profile(name).map_err(ModeError::Profile)?;
        self.build_reapply_plan_from_profile(
            name,
            host,
            level,
            inbound_override,
            scope,
            &parsed_profile,
        )
    }

    pub(crate) fn build_reapply_plan_from_profile(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        level: ModeLevel,
        inbound_override: Option<InboundLevel>,
        scope: ReapplyScope,
        parsed_profile: &Profile,
    ) -> Result<ReapplyPlan, ModeError> {
        let hosts = hosts_for_level(parsed_profile, level);
        let inbound = match inbound_override {
            Some(inbound_level) => inbound_rules_for_level(parsed_profile, inbound_level),
            None => steady_inbound_rules(parsed_profile),
        };
        let install_anchor = FirewallOp::InstallAnchor {
            name: name.into(),
            body: render_anchor(name.as_str(), &hosts, inbound),
        };
        let pf_conf = self.machine.read_pf_conf().map_err(ModeError::Firewall)?;
        let update_conf = if is_anchor_referenced(&pf_conf, name.as_str()) {
            None
        } else {
            Some(FirewallOp::UpdateConfig {
                content: ensure_anchor_ref(&pf_conf, name.as_str()),
            })
        };
        let reload = FirewallOp::Reload;
        let group = tenant_share_group_name(name.as_str());
        let add_host = AccountOp::AddHostToShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        // gid comes from the live record: UID/GID allocators are independent, so it isn't derivable.
        let ensure_primary_group = match scope {
            ReapplyScope::Full => {
                let gid = self
                    .machine
                    .read_share_group_gid(&group)
                    .map_err(ModeError::Probe)?;
                Some(AccountOp::EnsurePrimaryGroup {
                    name: name.into(),
                    gid,
                })
            }
            ReapplyScope::Light => None,
        };
        let ensure_cowork_dir = match scope {
            ReapplyScope::Full => {
                let cowork_path = cowork_dir_path(name.as_str());
                guard_cowork_dir_kind(self.machine, &cowork_path).map_err(ModeError::Account)?;
                Some(AccountOp::EnsureCoworkDir {
                    path: cowork_path,
                    owner: host.into(),
                    group,
                    mode: 0o2770,
                })
            }
            ReapplyScope::Light => None,
        };
        let share_ops = self.build_share_ops(name, parsed_profile, scope)?;
        Ok(ReapplyPlan {
            install_anchor,
            update_conf,
            reload,
            add_host,
            ensure_primary_group,
            ensure_cowork_dir,
            share_ops,
        })
    }

    /// Order is load-bearing: a Reload failure aborts before any share mutation, and
    /// `add_host` precedes the shares so the inheritable ACL grant reaches the host.
    pub(crate) fn execute_reapply_plan(
        &self,
        plan: &ReapplyPlan,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        self.run(&plan.install_anchor, reporter)
            .map_err(ModeError::Firewall)?;
        if let Some(update_conf) = &plan.update_conf {
            self.run(update_conf, reporter)
                .map_err(ModeError::Firewall)?;
        }
        self.run(&plan.reload, reporter)
            .map_err(ModeError::Firewall)?;
        self.run(&plan.add_host, reporter)
            .map_err(ModeError::Account)?;
        if let Some(ensure_primary_group) = &plan.ensure_primary_group {
            self.run(ensure_primary_group, reporter)
                .map_err(ModeError::Account)?;
        }
        if let Some(cowork) = &plan.ensure_cowork_dir {
            self.run(cowork, reporter).map_err(ModeError::Account)?;
        }
        self.execute_share_ops(&plan.share_ops, reporter)
    }

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
            let outcome = match self.build_reapply_plan(
                name,
                host,
                ModeLevel::Runtime,
                None,
                ReapplyScope::Full,
            ) {
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
