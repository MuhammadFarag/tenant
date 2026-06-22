//! Mode/reload reapply error type. Used by `mode`, the `shell` command
//! form's auto-narrow, `reload`, and the create-side post-provision
//! share pass.

use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, AclError, FirewallError, FirewallOp, HostUserDirectory, HostUserName,
    Op, ProbeError, TenantUserName, UserDirectoryError,
};
use crate::firewall::{InboundRules, render_anchor};
use crate::profile::{Profile, ProfileError, parse};
use crate::{InboundLevel, ModeLevel};

use super::shares::ShareOps;
use super::{ShareError, Tenants, cowork_dir_path, guard_cowork_dir_kind, tenant_share_group_name};

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

/// `Light` (mode + shell) omits the recursive ACL passes —
/// `AclOp::Grant` per share AND `AccountOp::EnsureCoworkDir`.
/// Inheritable ACE bits (`file_inherit,directory_inherit`) propagate
/// the grant to tenant-created children, so the recursive walk on
/// every entry is redundant in the steady state. Drift on
/// pre-existing files / externally-stripped ACL / missing cowork
/// dir is surfaced by doctor and remediated by `tenant reload`.
///
/// `Full` (reload + create's post-provision) includes both. Create's
/// first apply needs the recursive grant to reach files that
/// pre-existed at the host_path before the inheritable ACE landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReapplyScope {
    Light,
    Full,
}

/// Pre-built op list for a profile-to-tenant reapply. Construction
/// is separated from execution so verb methods can render the
/// upfront plan over the same ops the substrate will run.
///
/// `ensure_cowork_dir` and per-share `grant` are `Option` — `None`
/// under Light scope.
pub(crate) struct ReapplyPlan {
    pub(crate) install_anchor: FirewallOp,
    pub(crate) reload: FirewallOp,
    pub(crate) add_host: AccountOp,
    /// Tenant-side membership catch-up: re-assert the tenant user's
    /// primary group to the share group (OS-update resilience, #26).
    /// `Some` under Full, `None` under Light — same split as
    /// `ensure_cowork_dir`: re-asserting the primary group is a host-state
    /// CONVERGENCE repair, and convergence is reload's "apply everything"
    /// role. mode/shell stay Light to keep the quick paths minimal (one
    /// fewer dscl read per entry) with `tenant reload` as the documented
    /// drift remedy. (Note: shell's `sudo -iu` login runs AFTER the
    /// reapply, so reasserting here WOULD reach the about-to-start session
    /// — that self-heal-on-entry is the separate shell-entry-safety
    /// concern, finding #29, not this op's scope.)
    pub(crate) ensure_primary_group: Option<AccountOp>,
    pub(crate) ensure_cowork_dir: Option<AccountOp>,
    pub(crate) share_ops: Vec<ShareOps>,
}

impl ReapplyPlan {
    pub(crate) fn as_plan_entries(&self) -> Vec<(Op<'_>, Option<&'static str>)> {
        let mut entries: Vec<(Op<'_>, Option<&'static str>)> =
            Vec::with_capacity(5 + self.share_ops.iter().map(|s| s.op_count()).sum::<usize>());
        entries.push((Op::Firewall(&self.install_anchor), None));
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

/// The inbound posture a verb that does NOT control the inbound axis
/// renders: steady state at the profile's declared ports. Per the
/// implicit-current-mode doctrine (no state file), every reapply verb
/// renders both axes; the axis it doesn't widen goes to steady state.
/// For inbound that is `Restricted(profile.inbound.ports)` — empty ports
/// stays the locked posture, declared ports keep their inbound pass.
/// Mirrors how `hosts_for_level` resolves the egress axis from the same
/// parsed profile before `render_anchor` sees it.
///
/// The temporary `Permissive` widen is the `tenant inbound` verb's job;
/// it resolves `InboundLevel` against these ports at that call site.
pub(crate) fn steady_inbound_rules(profile: &Profile) -> InboundRules {
    InboundRules::Restricted(profile.inbound.ports.clone())
}

/// Resolve the `tenant inbound` verb's requested `InboundLevel` against
/// the profile's declared ports into a `firewall::InboundRules`. The
/// `cli::InboundLevel` → `firewall::InboundRules` resolution lives in the
/// domain layer so `firewall.rs` stays free of any `cli` dependency —
/// mirrors how `hosts_for_level` resolves the egress axis before
/// `render_anchor` sees a `&[String]`.
///
/// `Permissive` opens all inbound loopback; `Restricted` keeps the
/// profile's declared ports (empty ⇒ locked, same as steady state).
pub(crate) fn inbound_rules_for_level(profile: &Profile, level: InboundLevel) -> InboundRules {
    match level {
        InboundLevel::Permissive => InboundRules::Permissive,
        InboundLevel::Restricted => InboundRules::Restricted(profile.inbound.ports.clone()),
    }
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

    /// Apply a pre-built reapply plan carrying the requested inbound
    /// posture. Sibling of `mode` on the inbound axis: the plan is built
    /// upstream (egress at runtime tier, inbound at the requested level)
    /// so profile-read failures surface pre-prompt.
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

    /// Build the op list for a profile-to-tenant reapply at `level`
    /// under the given `scope`. Pre-flight refusals (host_path
    /// existence, tenant_path occupancy) surface before any op fires.
    ///
    /// `inbound_override` controls the INBOUND axis: `None` renders it at
    /// steady state (profile-declared ports), which is what every verb
    /// that doesn't control inbound (`mode`/`reload`/create) passes;
    /// `Some(level)` is the `tenant inbound` verb resolving its requested
    /// posture. Per the implicit-current-mode doctrine, both axes always
    /// render — the axis the verb doesn't widen goes to steady state.
    pub(crate) fn build_reapply_plan(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        level: ModeLevel,
        inbound_override: Option<InboundLevel>,
        scope: ReapplyScope,
    ) -> Result<ReapplyPlan, ModeError> {
        let profile_content = self
            .machine
            .read_profile(name)
            .map_err(ModeError::Profile)?;
        let parsed_profile = parse(&profile_content).map_err(ModeError::Profile)?;
        let hosts = hosts_for_level(&parsed_profile, level);
        let inbound = match inbound_override {
            Some(inbound_level) => inbound_rules_for_level(&parsed_profile, inbound_level),
            None => steady_inbound_rules(&parsed_profile),
        };
        let install_anchor = FirewallOp::InstallAnchor {
            name: name.into(),
            body: render_anchor(name.as_str(), &hosts, inbound),
        };
        let reload = FirewallOp::Reload;
        let group = tenant_share_group_name(name.as_str());
        let add_host = AccountOp::AddHostToShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        // Tenant-side membership catch-up (Full only): re-assert the
        // tenant user's primary group to its share group. Resolve the gid
        // from the LIVE share-group record (`read_share_group_gid`, an
        // unprivileged dscl read) rather than trusting a derived value —
        // the gid was allocated at create and isn't recoverable from the
        // name. Borrow `&group` here so it stays available for the cowork
        // op below to move. Light scope skips both the read and the op.
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
        // Kind-check fires only when EnsureCoworkDir will: `mkdir -p`
        // silently follows a symlink, and the subsequent chown /
        // chmod / chmod -R would then mutate the link target.
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
        let share_ops = self.build_share_ops(name, &parsed_profile, scope)?;
        Ok(ReapplyPlan {
            install_anchor,
            reload,
            add_host,
            ensure_primary_group,
            ensure_cowork_dir,
            share_ops,
        })
    }

    /// PF reapply first; a Reload failure aborts before any share
    /// mutation. `add_host` fires before the per-share ops because
    /// the host needs the membership for the inheritable ACL grant
    /// to flow through.
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
        if let Some(ensure_primary_group) = &plan.ensure_primary_group {
            self.run(ensure_primary_group, reporter)
                .map_err(ModeError::Account)?;
        }
        if let Some(cowork) = &plan.ensure_cowork_dir {
            self.run(cowork, reporter).map_err(ModeError::Account)?;
        }
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
