use std::path::PathBuf;

use super::reporter::Reporter;
use super::{
    AccountError, AccountOp, AclMode, AclOp, FirewallError, FirewallOp, GroupId, GroupName,
    HostAccounts, HostFileError, HostMachine, HostUserName, Op, PathKind, ProbeError, ProfileOp,
    TenantUserName, UserId, WritableOp,
};
use crate::ModeLevel;
use crate::doctor::{
    Finding, SymlinkActual, anchor_body_matches, curated_paths, has_env_delete_for,
    has_group_acl_entry, has_pam_tid, pf_rule_presence_check, pf_status_enabled,
};
use crate::firewall::{ensure_anchor_ref, remove_anchor_ref, render_anchor};
use crate::profile::{Profile, ShareMode, display_path_for, expand_tenant_path, parse};

pub mod create;
pub mod destroy;
pub mod doctor;
pub mod reapply;
pub mod shares;
pub mod shell;
pub mod validation;

pub(crate) use create::CreateError;
pub(crate) use destroy::{DestroyError, Eligibility, destroy_eligibility};
pub(crate) use doctor::{DoctorError, DoctorScope};
pub(crate) use reapply::ModeError;
pub(crate) use shares::ShareError;
pub(crate) use shell::ShellError;
pub use validation::{ConflictError, NameError, check_conflict, validate_name};

/// Single source of truth for the `<name>-tenant-share` suffix.
pub fn tenant_share_group_name(name: &str) -> GroupName {
    GroupName(format!("{name}-tenant-share"))
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

/// One per-share entry's op triple. `ensure_dir` is `None` when the
/// tenant_path's parent is the tenant home itself.
pub(crate) struct ShareOps {
    pub(crate) grant: AclOp,
    pub(crate) ensure_dir: Option<AccountOp>,
    pub(crate) ensure_link: AccountOp,
}

impl ShareOps {
    fn op_count(&self) -> usize {
        2 + if self.ensure_dir.is_some() { 1 } else { 0 }
    }
}

#[derive(Debug)]
pub(crate) struct ReloadAllOutcome {
    pub(crate) failed: u32,
}

/// Composes ops into verb-level flows. Real-vs-dry-run is not the
/// Tenants struct's concern: each method always invokes the substrate,
/// and the Reporter + dry-run substrate handle mode-specific filtering.
pub(crate) struct Tenants<'a> {
    machine: &'a dyn HostMachine,
}

impl<'a> Tenants<'a> {
    pub(crate) fn new(machine: &'a dyn HostMachine) -> Self {
        Self { machine }
    }

    pub(crate) fn create(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        uid: UserId,
        gid: GroupId,
        reporter: &mut Reporter,
    ) -> Result<(), CreateError> {
        let group = tenant_share_group_name(name.as_str());
        let create_group = AccountOp::CreateShareGroup {
            group: group.clone(),
            gid,
        };
        let add_host = AccountOp::AddHostToShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        let add_user = AccountOp::CreateTenantUser {
            name: name.into(),
            uid,
            gid,
        };
        let rollback_group = AccountOp::DeleteShareGroup {
            group: group.clone(),
        };
        let create_profile = ProfileOp::Create { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let restore = FirewallOp::RestoreConfigFromBackup;
        let reload = FirewallOp::Reload;
        let enable = FirewallOp::Enable;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };

        reporter.create_starting(name);

        self.run(&create_group, reporter)
            .map_err(CreateError::Group)?;
        self.run(&add_host, reporter)
            .map_err(CreateError::HostMembership)?;
        match self.run(&add_user, reporter) {
            Ok(()) => {
                self.run(&create_profile, reporter)
                    .map_err(CreateError::Profile)?;
                let profile_content = self.machine.read_profile(name).map_err(|e| {
                    CreateError::Firewall(FirewallError::Fs {
                        path: display_path_for(name.as_str()),
                        message: format!("read failed: {e}"),
                    })
                })?;
                let parsed_profile = parse(&profile_content).map_err(|e| {
                    CreateError::Firewall(FirewallError::Fs {
                        path: display_path_for(name.as_str()),
                        message: format!("parse failed: {e}"),
                    })
                })?;
                let pf_conf_current = self.machine.read_pf_conf().map_err(CreateError::Firewall)?;
                let install_anchor = FirewallOp::InstallAnchor {
                    name: name.into(),
                    body: render_anchor(name.as_str(), &parsed_profile.allowlist.runtime.hosts),
                };
                let update_conf = FirewallOp::UpdateConfig {
                    content: ensure_anchor_ref(&pf_conf_current, name.as_str()),
                };
                self.run(&backup, reporter).map_err(CreateError::Firewall)?;
                self.run(&install_anchor, reporter)
                    .map_err(CreateError::Firewall)?;
                self.run(&update_conf, reporter)
                    .map_err(CreateError::Firewall)?;
                if let Err(reload_err) = self.run(&reload, reporter) {
                    // FlushAnchor is the symmetric counter to the partial
                    // in-kernel state from the failed Reload — without
                    // it, restoring pf.conf and removing the anchor file
                    // still leaves the partially-loaded rules in kernel
                    // memory under the now-orphaned anchor name.
                    if self.run(&restore, reporter).is_err() {
                        return Err(CreateError::Firewall(FirewallError::RestoreFailed {
                            path: crate::firewall::PF_CONF_BACKUP.to_string(),
                        }));
                    }
                    let _ = self.run(&remove_anchor, reporter);
                    let _ = self.run(&reload, reporter);
                    let _ = self.run(&flush_anchor, reporter);
                    return Err(CreateError::Firewall(reload_err));
                }
                self.run(&enable, reporter).map_err(CreateError::Firewall)?;
                self.reapply_shares_post_provision(name, &parsed_profile, reporter)
                    .map_err(CreateError::PostProvision)?;
                reporter.create_done(name, uid, gid);
                Ok(())
            }
            Err(user_err) => match self.run(&rollback_group, reporter) {
                Ok(()) => Err(CreateError::User(user_err)),
                Err(rollback_err) => Err(CreateError::UserWithRollback {
                    user: user_err,
                    rollback: rollback_err,
                }),
            },
        }
    }

    pub(crate) fn destroy(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        // PF teardown sits after account/profile cleanup so the tenant
        // can't open new sockets while we're tearing down their ruleset.
        // FlushAnchor is load-bearing: without it, the previous tenant's
        // rules persist in kernel memory under the orphaned anchor name
        // and the next tenant getting the same UID inherits them.
        let group = tenant_share_group_name(name.as_str());
        let delete_user = AccountOp::DeleteTenantUser { name: name.into() };
        let probe = AccountOp::LookupUserRecord { name: name.into() };
        let cleanup = AccountOp::DeleteUserRecord { name: name.into() };
        let remove_host = AccountOp::RemoveHostFromShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        let delete_group = AccountOp::DeleteShareGroup { group };
        let delete_profile = ProfileOp::Delete { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let reload = FirewallOp::Reload;
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };

        reporter.destroy_starting(name);

        self.run(&delete_user, reporter)?;
        match self.run(&probe, reporter) {
            Ok(()) => {
                self.run(&cleanup, reporter)?;
            }
            Err(AccountError::NonZero { .. }) => {
                // Probe found directory service clean — no cleanup.
            }
            Err(other) => return Err(DestroyError::Account(other)),
        }

        self.run(&remove_host, reporter)?;
        self.run(&delete_group, reporter)?;
        self.run(&delete_profile, reporter)
            .map_err(DestroyError::Profile)?;

        let pf_conf_current = self
            .machine
            .read_pf_conf()
            .map_err(DestroyError::Firewall)?;
        let update_conf = FirewallOp::UpdateConfig {
            content: remove_anchor_ref(&pf_conf_current, name.as_str()),
        };
        self.run(&backup, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&remove_anchor, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&update_conf, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&reload, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&flush_anchor, reporter)
            .map_err(DestroyError::Firewall)?;

        reporter.destroy_done(name);
        Ok(())
    }

    /// Convergence path when the tenant user is already absent but the
    /// suffixed group (and possibly anchor / pf.conf reference) remain.
    /// Every step is substrate-idempotent so the path is single-pass.
    pub(crate) fn destroy_orphan_group(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        let group = tenant_share_group_name(name.as_str());
        let remove_host = AccountOp::RemoveHostFromShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        let delete_group = AccountOp::DeleteShareGroup { group };
        let delete_profile = ProfileOp::Delete { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let reload = FirewallOp::Reload;
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };

        reporter.orphan_group_starting(name);

        self.run(&remove_host, reporter)?;
        self.run(&delete_group, reporter)?;
        self.run(&delete_profile, reporter)
            .map_err(DestroyError::Profile)?;

        let pf_conf_current = self
            .machine
            .read_pf_conf()
            .map_err(DestroyError::Firewall)?;
        let update_conf = FirewallOp::UpdateConfig {
            content: remove_anchor_ref(&pf_conf_current, name.as_str()),
        };
        self.run(&backup, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&remove_anchor, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&update_conf, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&reload, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&flush_anchor, reporter)
            .map_err(DestroyError::Firewall)?;

        reporter.orphan_group_done(name);
        Ok(())
    }

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

    fn build_share_ops(
        &self,
        name: &TenantUserName,
        parsed_profile: &Profile,
    ) -> Result<Vec<ShareOps>, ModeError> {
        if parsed_profile.shares.is_empty() {
            return Ok(Vec::new());
        }
        let group = tenant_share_group_name(name.as_str());
        let home_dir = PathBuf::from(format!("/Users/{name}"));
        let mut out = Vec::with_capacity(parsed_profile.shares.len());
        for share in &parsed_profile.shares {
            if !share.host_path.exists() {
                return Err(ModeError::Share(ShareError::HostPathMissing {
                    path: share.host_path.clone(),
                }));
            }
            let tenant_path = expand_tenant_path(name.as_str(), &share.tenant_path);
            let kind = self
                .machine
                .tenant_path_kind(name, &tenant_path)
                .map_err(ModeError::Probe)?;
            if matches!(kind, PathKind::Other) {
                return Err(ModeError::Share(ShareError::TenantPathOccupied {
                    path: tenant_path,
                }));
            }
            let acl_mode = match share.mode {
                ShareMode::Ro => AclMode::Ro,
                ShareMode::Rw => AclMode::Rw,
            };
            let grant = AclOp::Grant {
                path: share.host_path.clone(),
                group: group.clone(),
                mode: acl_mode,
            };
            // Skip parent-dir ensure when the parent is the tenant home itself.
            let ensure_dir = tenant_path.parent().and_then(|parent| {
                if parent == home_dir.as_path() {
                    None
                } else {
                    Some(AccountOp::EnsureDirAsUser {
                        name: name.into(),
                        path: parent.to_path_buf(),
                    })
                }
            });
            let ensure_link = AccountOp::EnsureSymlinkAsUser {
                name: name.into(),
                link: tenant_path,
                target: share.host_path.clone(),
            };
            out.push(ShareOps {
                grant,
                ensure_dir,
                ensure_link,
            });
        }
        Ok(out)
    }

    /// PF reapply first; a Reload failure aborts before any share
    /// mutation. `add_host` fires before the per-share ops because host
    /// needs the membership for the inheritable ACL grant to flow through.
    fn execute_reapply_plan(
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

    /// Share-only reapply at create-time. Skips the PF reapply already
    /// done by the create-time firewall sequence.
    fn reapply_shares_post_provision(
        &self,
        name: &TenantUserName,
        parsed_profile: &Profile,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        let share_ops = self.build_share_ops(name, parsed_profile)?;
        self.execute_share_ops(&share_ops, reporter)
    }

    fn execute_share_ops(
        &self,
        share_ops: &[ShareOps],
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        for share in share_ops {
            self.run(&share.grant, reporter).map_err(ModeError::Acl)?;
            if let Some(ensure_dir) = &share.ensure_dir {
                self.run(ensure_dir, reporter).map_err(ModeError::Account)?;
            }
            self.run(&share.ensure_link, reporter)
                .map_err(ModeError::Account)?;
        }
        Ok(())
    }

    /// Shell-verb entry: empty argv → interactive; non-empty → command.
    pub(crate) fn shell(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        argv: &[String],
        mode: ModeLevel,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        if argv.is_empty() {
            return self.shell_interactive(name, host, reporter);
        }
        self.shell_command(name, host, argv, mode, reporter)
    }

    /// Auto-narrows to runtime, reapplies shares, then logs in.
    fn shell_interactive(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        // Intent emitted before the narrow tries, so the operator sees
        // the verb context even if the pre-flight profile read fails.
        reporter.shell_intent(name);
        let reapply_plan = self
            .build_reapply_plan(name, host, ModeLevel::Runtime)
            .map_err(ShellError::Mode)?;
        let login = AccountOp::LoginAsUser { name: name.into() };
        let mut plan_entries = reapply_plan.as_plan_entries();
        plan_entries.push((Op::Account(&login), None));
        reporter.shell_plan(&plan_entries);
        self.execute_reapply_plan(&reapply_plan, reporter)
            .map_err(ShellError::Mode)?;
        reporter.step(Op::Account(&login));
        self.machine.login(name).map_err(ShellError::Account)
    }

    /// Command-form shell. Build + execute the entry reapply at the
    /// requested tier, run the child, then reapply at runtime on
    /// completion (skipped when the entry tier was already Runtime,
    /// since a second reapply would write the same bytes for zero
    /// on-disk delta). Failure composition:
    ///
    /// - widen-build-failure → `Mode`, no narrow (nothing to undo).
    /// - widen-execute-failure → best-effort narrow inline, then `Mode`.
    /// - child-spawn-failure → `Account`, no narrow (entry reapply
    ///   already reflects the requested tier).
    /// - child-ran + narrow-failed → `NarrowFailed` carrying both the
    ///   child exit and the narrow error; child exit propagates.
    fn shell_command(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        argv: &[String],
        mode: ModeLevel,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        reporter.shell_command_intent(name, mode);

        let entry_plan = self
            .build_reapply_plan(name, host, mode)
            .map_err(ShellError::Mode)?;

        if let Err(entry_err) = self.execute_reapply_plan(&entry_plan, reporter) {
            // Best-effort narrow; drop any secondary failure on the floor —
            // the operator's primary signal is the entry failure.
            let _ = self
                .build_reapply_plan(name, host, ModeLevel::Runtime)
                .and_then(|p| self.execute_reapply_plan(&p, reporter));
            return Err(ShellError::Mode(entry_err));
        }

        let child_result = self.machine.exec_as_tenant(name, argv);

        let narrow_result = if mode == ModeLevel::Runtime {
            Ok(())
        } else {
            self.build_reapply_plan(name, host, ModeLevel::Runtime)
                .and_then(|p| self.execute_reapply_plan(&p, reporter))
        };

        match (child_result, narrow_result) {
            (Ok(code), Ok(())) => Ok(code),
            (Ok(code), Err(narrow_err)) => Err(ShellError::NarrowFailed {
                child_exit: code,
                narrow_err,
            }),
            (Err(spawn_err), _) => Err(ShellError::Account(spawn_err)),
        }
    }

    /// Narrate, execute, narrate. Coupling the three steps means a
    /// Tenants caller can't execute without narrating either side.
    fn run<O: WritableOp>(&self, op: &O, reporter: &mut Reporter) -> Result<(), O::Error> {
        reporter.step(op.op_ref());
        op.execute_via(self.machine)?;
        reporter.progress(op.op_ref());
        Ok(())
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
        accounts: &dyn HostAccounts,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> ReloadAllOutcome {
        let names = accounts.tenant_names();
        reporter.reload_all_starting(names.len());
        if names.is_empty() {
            reporter.reload_all_done_summary(0, 0);
            return ReloadAllOutcome { failed: 0 };
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
        ReloadAllOutcome { failed }
    }

    /// Single-tenant audit. Host-wide checks (env policy, Touch ID,
    /// pf status) run even in single-tenant mode because each affects
    /// every tenant. `others` lists the other tenants on the host for
    /// cross-tenant probes.
    pub(crate) fn doctor(
        &self,
        host: &HostUserName,
        name: &TenantUserName,
        others: &[&TenantUserName],
        reporter: &mut Reporter,
    ) -> Result<DoctorOutcome, DoctorError> {
        let mut findings: Vec<Finding> = Vec::new();
        if let Some(env_leak) = self.check_env_leak(reporter)? {
            findings.push(env_leak);
        }
        if let Some(touch_id) = self.check_touch_id_for_sudo(reporter)? {
            findings.push(touch_id);
        }
        if let Some(pf_disabled) = self.check_pf_status(reporter)? {
            findings.push(pf_disabled);
        }
        findings.extend(self.probe_tenant_paths(host, name, others, reporter)?);
        Ok(DoctorOutcome { findings })
    }

    /// All-tenants audit. Host-wide checks run once; per-tenant walks
    /// follow in alphabetical order. With no tenants, host-wide checks
    /// still run (operator-relevant) before the noop message.
    pub(crate) fn doctor_all(
        &self,
        host: &HostUserName,
        accounts: &dyn HostAccounts,
        reporter: &mut Reporter,
    ) -> Result<DoctorOutcome, DoctorError> {
        let mut findings: Vec<Finding> = Vec::new();
        if let Some(env_leak) = self.check_env_leak(reporter)? {
            findings.push(env_leak);
        }
        if let Some(touch_id) = self.check_touch_id_for_sudo(reporter)? {
            findings.push(touch_id);
        }
        if let Some(pf_disabled) = self.check_pf_status(reporter)? {
            findings.push(pf_disabled);
        }
        let tenants = accounts.tenant_names();
        if tenants.is_empty() {
            reporter.doctor_all_tenants_noop();
            return Ok(DoctorOutcome { findings });
        }
        for name in &tenants {
            let others: Vec<&TenantUserName> = tenants.iter().filter(|n| *n != name).collect();
            findings.extend(self.probe_tenant_paths(host, name, &others, reporter)?);
        }
        Ok(DoctorOutcome { findings })
    }

    fn check_env_leak(&self, reporter: &mut Reporter) -> Result<Option<Finding>, HostFileError> {
        let policy = self.machine.read_env_policy()?;
        if has_env_delete_for(&policy, "SSH_AUTH_SOCK") {
            return Ok(None);
        }
        let finding = Finding::EnvLeak {
            var: "SSH_AUTH_SOCK".to_string(),
        };
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    fn check_touch_id_for_sudo(
        &self,
        reporter: &mut Reporter,
    ) -> Result<Option<Finding>, HostFileError> {
        let pam_config = self.machine.read_pam_sudo()?;
        if has_pam_tid(&pam_config) {
            return Ok(None);
        }
        let finding = Finding::TouchIdMissing;
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    fn check_pf_status(&self, reporter: &mut Reporter) -> Result<Option<Finding>, FirewallError> {
        let status = self.machine.read_pf_status()?;
        if pf_status_enabled(&status) {
            return Ok(None);
        }
        let finding = Finding::PfDisabled;
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    /// Probe one tenant's curated paths + structural pf anchor check.
    /// Host-wide findings are the caller's responsibility.
    fn probe_tenant_paths(
        &self,
        host: &HostUserName,
        name: &TenantUserName,
        others: &[&TenantUserName],
        reporter: &mut Reporter,
    ) -> Result<Vec<Finding>, DoctorError> {
        let others_str: Vec<&str> = others.iter().map(|n| n.as_str()).collect();
        let curated = curated_paths(host.as_str(), name.as_str(), &others_str);
        reporter.doctor_starting(name, &curated);
        let mut findings: Vec<Finding> = Vec::new();
        for (category, mode, path) in &curated {
            let outcome = self.machine.probe_access_as_tenant(name, path, *mode)?;
            if let Some(severity) = crate::doctor::classify(*category, outcome) {
                let finding = Finding::FilesystemExposure {
                    severity,
                    tenant: name.clone(),
                    path: path.clone(),
                    access: *mode,
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
        }
        let rules = self.machine.read_kernel_pf_rules(name)?;
        for drift in crate::doctor::pf_rule_presence_check(&rules, name.as_str()) {
            reporter.doctor_finding(&drift);
            findings.push(drift);
        }
        if let Some(drift) = self.check_anchor_body_drift(name)? {
            reporter.doctor_finding(&drift);
            findings.push(drift);
        }
        for drift in self.check_share_drift(name, reporter)? {
            findings.push(drift);
        }
        if let Some(drift) = self.check_host_in_share_group(name, host, reporter)? {
            findings.push(drift);
        }
        reporter.doctor_done_summary(name, findings.len());
        Ok(findings)
    }

    fn check_host_in_share_group(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<Option<Finding>, DoctorError> {
        let group = tenant_share_group_name(name.as_str());
        let is_member = self.machine.host_in_group(host, &group).map_err(|e| {
            DoctorError::Probe(ProbeError::NonZero {
                code: -1,
                stderr: format!("dseditgroup -o checkmember failed: {e}"),
            })
        })?;
        if is_member {
            return Ok(None);
        }
        let finding = Finding::HostNotInShareGroup {
            tenant: name.clone(),
            host: host.clone(),
            group,
        };
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    /// Walk the profile's `[[shares]]` and emit AclDrift +
    /// SymlinkDrift findings. The two checks are independent — one
    /// share can fire both. An unreadable / unparseable profile
    /// silently skips the check (a future `ProfileMissing` finding
    /// would surface that case separately).
    fn check_share_drift(
        &self,
        name: &TenantUserName,
        reporter: &mut Reporter,
    ) -> Result<Vec<Finding>, DoctorError> {
        let profile_content = match self.machine.read_profile(name) {
            Ok(c) => c,
            Err(_) => return Ok(Vec::new()),
        };
        let parsed = match parse(&profile_content) {
            Ok(p) => p,
            Err(_) => return Ok(Vec::new()),
        };
        let group = tenant_share_group_name(name.as_str());
        let mut findings: Vec<Finding> = Vec::new();
        for share in &parsed.shares {
            let listing = self.machine.read_host_acl(&share.host_path)?;
            if !has_group_acl_entry(&listing, group.as_str()) {
                let finding = Finding::AclDrift {
                    tenant: name.clone(),
                    host_path: share.host_path.clone(),
                    group: group.clone(),
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
            // String-exact comparison — the profile names the operator's
            // declared intent, not a canonicalized path.
            let tenant_path = expand_tenant_path(name.as_str(), &share.tenant_path);
            let kind = self.machine.tenant_path_kind(name, &tenant_path)?;
            let actual_opt = match kind {
                PathKind::Absent => Some(SymlinkActual::Absent),
                PathKind::Other => Some(SymlinkActual::NotSymlink),
                PathKind::Symlink(target) => {
                    if target == share.host_path {
                        None
                    } else {
                        Some(SymlinkActual::WrongTarget(target))
                    }
                }
            };
            if let Some(actual) = actual_opt {
                let finding = Finding::SymlinkDrift {
                    tenant: name.clone(),
                    tenant_path,
                    expected_target: share.host_path.clone(),
                    actual,
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
        }
        Ok(findings)
    }

    /// Compare on-disk anchor body against the runtime-tier render.
    /// An unreadable / unparseable profile skips the check silently.
    /// Runtime-tier only: install-tier widening outside a shell session
    /// IS drift, since shell auto-narrows on entry.
    fn check_anchor_body_drift(
        &self,
        name: &TenantUserName,
    ) -> Result<Option<Finding>, HostFileError> {
        let profile_content = match self.machine.read_profile(name) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };
        let parsed = match parse(&profile_content) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let actual = self.machine.read_anchor_body(name)?;
        let expected = render_anchor(name.as_str(), &parsed.allowlist.runtime.hosts);
        if anchor_body_matches(&actual, &expected) {
            return Ok(None);
        }
        Ok(Some(Finding::AnchorBodyDrift {
            tenant: name.clone(),
        }))
    }

    /// Run a verb-relevant subset of doctor's checks pre-confirm.
    /// Critical findings emit inline; warnings + info aggregate into a
    /// single hint pointing at `tenant doctor`. Substrate failures
    /// surface as stderr frames; the audit is a courtesy and never
    /// aborts the verb.
    pub(crate) fn pre_exec_doctor_summary(
        &self,
        name: Option<&TenantUserName>,
        host: &HostUserName,
        scope: DoctorScope,
        reporter: &mut Reporter,
    ) {
        let mut criticals: Vec<Finding> = Vec::new();
        let mut warning_count: usize = 0;
        let mut record = |finding: Finding| {
            if finding.severity() == crate::doctor::Severity::Critical {
                criticals.push(finding);
            } else {
                warning_count += 1;
            }
        };

        // PfDisabled is host-wide: pf off means no tenant anchor enforces.
        match self.machine.read_pf_status() {
            Ok(text) => {
                if !pf_status_enabled(&text) {
                    record(Finding::PfDisabled);
                }
            }
            Err(e) => reporter.doctor_firewall_failed(&e),
        }

        // EnvLeak is shell-only: only the shell entry path materializes
        // the operator's ssh-agent socket inside the tenant session.
        if matches!(scope, DoctorScope::Shell) {
            match self.machine.read_env_policy() {
                Ok(text) => {
                    if !has_env_delete_for(&text, "SSH_AUTH_SOCK") {
                        record(Finding::EnvLeak {
                            var: "SSH_AUTH_SOCK".to_string(),
                        });
                    }
                }
                Err(e) => reporter.doctor_host_file_failed(&e),
            }
        }

        if let Some(tenant) = name {
            if matches!(
                scope,
                DoctorScope::Shell | DoctorScope::Mode | DoctorScope::Reload
            ) {
                match self.machine.read_kernel_pf_rules(tenant) {
                    Ok(rules) => {
                        for drift in pf_rule_presence_check(&rules, tenant.as_str()) {
                            record(drift);
                        }
                    }
                    Err(e) => reporter.doctor_firewall_failed(&e),
                }
                match self.check_anchor_body_drift(tenant) {
                    Ok(Some(drift)) => record(drift),
                    Ok(None) => {}
                    Err(e) => reporter.doctor_host_file_failed(&e),
                }
            }

            // Share drift — shell + reload only. Mode's focus is the
            // firewall tier; reload's job IS share convergence.
            if matches!(scope, DoctorScope::Shell | DoctorScope::Reload) {
                self.collect_share_drift(tenant, reporter, &mut record);
                match self
                    .machine
                    .host_in_group(host, &tenant_share_group_name(tenant.as_str()))
                {
                    Ok(true) => {}
                    Ok(false) => record(Finding::HostNotInShareGroup {
                        tenant: tenant.clone(),
                        host: host.clone(),
                        group: tenant_share_group_name(tenant.as_str()),
                    }),
                    Err(e) => {
                        reporter.doctor_failed(&ProbeError::NonZero {
                            code: -1,
                            stderr: format!("dseditgroup -o checkmember failed: {e}"),
                        });
                    }
                }
            }
        }

        for finding in &criticals {
            // One-liner only; the aggregate hint already points the
            // operator at `tenant doctor` for guidance body.
            reporter.doctor_finding_one_liner(finding);
        }
        reporter.doctor_summary_pending(warning_count, name);
    }

    /// Quiet counterpart to `check_share_drift` for the pre-exec
    /// aggregator: same probes, no inline emission. Per-share substrate
    /// failures surface via the doctor frame and the walk continues.
    fn collect_share_drift<F: FnMut(Finding)>(
        &self,
        name: &TenantUserName,
        reporter: &mut Reporter,
        record: &mut F,
    ) {
        let profile_content = match self.machine.read_profile(name) {
            Ok(c) => c,
            Err(_) => return,
        };
        let parsed = match parse(&profile_content) {
            Ok(p) => p,
            Err(_) => return,
        };
        let group = tenant_share_group_name(name.as_str());
        for share in &parsed.shares {
            match self.machine.read_host_acl(&share.host_path) {
                Ok(listing) => {
                    if !has_group_acl_entry(&listing, group.as_str()) {
                        record(Finding::AclDrift {
                            tenant: name.clone(),
                            host_path: share.host_path.clone(),
                            group: group.clone(),
                        });
                    }
                }
                Err(e) => {
                    reporter.doctor_failed(&e);
                    continue;
                }
            }
            let tenant_path = expand_tenant_path(name.as_str(), &share.tenant_path);
            match self.machine.tenant_path_kind(name, &tenant_path) {
                Ok(kind) => {
                    let actual_opt = match kind {
                        PathKind::Absent => Some(SymlinkActual::Absent),
                        PathKind::Other => Some(SymlinkActual::NotSymlink),
                        PathKind::Symlink(target) => {
                            if target == share.host_path {
                                None
                            } else {
                                Some(SymlinkActual::WrongTarget(target))
                            }
                        }
                    };
                    if let Some(actual) = actual_opt {
                        record(Finding::SymlinkDrift {
                            tenant: name.clone(),
                            tenant_path,
                            expected_target: share.host_path.clone(),
                            actual,
                        });
                    }
                }
                Err(e) => {
                    reporter.doctor_failed(&e);
                }
            }
        }
    }
}

/// `max_severity()` feeds the `--strict` exit-code decision at dispatch.
#[derive(Debug, Default)]
pub(crate) struct DoctorOutcome {
    pub findings: Vec<Finding>,
}

impl DoctorOutcome {
    pub fn max_severity(&self) -> Option<crate::doctor::Severity> {
        self.findings.iter().map(|f| f.severity()).max()
    }
}

/// Runtime: runtime hosts only. Install: runtime then install (order
/// matters for `render_anchor`'s output stability).
fn hosts_for_level(profile: &Profile, level: ModeLevel) -> Vec<String> {
    match level {
        ModeLevel::Runtime => profile.allowlist.runtime.hosts.clone(),
        ModeLevel::Install => {
            let mut hosts = profile.allowlist.runtime.hosts.clone();
            hosts.extend(profile.allowlist.install.hosts.iter().cloned());
            hosts
        }
    }
}
