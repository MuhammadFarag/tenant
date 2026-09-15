//! Same widen → work → narrow-on-finally shape as `shell_command`, but no child-exit
//! propagation: a failing command is `EX_IOERR` (bootstrap is not shell).

use crate::ModeLevel;
use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, HostUserDirectory, HostUserName, KeychainError, Op, TenantUserName,
    UserDirectoryError,
};

use super::Tenants;
use super::reapply::{ModeError, ReapplyPlan, ReapplyScope};

// TODO(smell): per-variant exit codes live only in dispatch; put them on the error type
#[derive(Debug)]
pub(crate) enum BootstrapError {
    Mode(ModeError),
    StashAbsent { name: TenantUserName },
    UnlockFailed(KeychainError),
    CommandFailed { command: String, code: i32 },
    Account(AccountError),
    NarrowFailed { narrow_err: ModeError },
}

/// Built upfront in dispatch so include / share pre-flight failures surface pre-prompt.
pub(crate) struct BootstrapPlan {
    pub(crate) commands: Vec<String>,
    pub(crate) widen: ReapplyPlan,
}

#[derive(Debug)]
pub(crate) struct BootstrapAllOutcome {
    pub(crate) failed: u32,
}

impl<'a> Tenants<'a> {
    pub(crate) fn build_bootstrap_plan(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
    ) -> Result<BootstrapPlan, ModeError> {
        let profile = self.load_profile(name).map_err(ModeError::Profile)?;
        let commands = profile.bootstrap.commands.clone();
        let widen = self.build_reapply_plan_from_profile(
            name,
            host,
            ModeLevel::Install,
            None,
            ReapplyScope::Light,
            &profile,
        )?;
        Ok(BootstrapPlan { commands, widen })
    }

    pub(crate) fn bootstrap(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        plan: &BootstrapPlan,
        reporter: &mut Reporter,
    ) -> Result<(), BootstrapError> {
        reporter.bootstrap_intent(name);

        if let Err(entry_err) = self.execute_reapply_plan(&plan.widen, reporter) {
            // Best-effort: the widen failure is the operator's signal, so a narrow error is dropped.
            let _ = self
                .narrow_plan(name, host)
                .and_then(|p| self.execute_reapply_plan(&p, reporter));
            return Err(BootstrapError::Mode(entry_err));
        }

        // Unlock counts as post-widen work: the narrow below must still fire when it fails,
        // or the tenant is stranded at install tier (the widen here is unconditional).
        let run_result = self
            .unlock_keychain_for_bootstrap(name, reporter)
            .and_then(|()| self.run_bootstrap_commands(name, &plan.commands, reporter));

        let narrow_result = self
            .narrow_plan(name, host)
            .and_then(|p| self.execute_reapply_plan(&p, reporter));

        match (run_result, narrow_result) {
            (Ok(()), Ok(())) => {
                reporter.bootstrap_done(name);
                Ok(())
            }
            (Ok(()), Err(narrow_err)) => Err(BootstrapError::NarrowFailed { narrow_err }),
            (Err(run_err), _) => Err(run_err),
        }
    }

    fn narrow_plan(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
    ) -> Result<ReapplyPlan, ModeError> {
        self.build_reapply_plan(name, host, ModeLevel::Runtime, None, ReapplyScope::Light)
    }

    fn run_bootstrap_commands(
        &self,
        name: &TenantUserName,
        commands: &[String],
        reporter: &mut Reporter,
    ) -> Result<(), BootstrapError> {
        for command in commands {
            let argv = vec!["/bin/sh".to_string(), "-c".to_string(), command.clone()];
            let echo_op = AccountOp::ExecAsUser {
                name: name.into(),
                argv: argv.clone(),
                dir: None,
            };
            reporter.step(Op::Account(&echo_op));
            match self.machine.exec_as_tenant(name, &argv, None) {
                Ok(0) => reporter.bootstrap_command_ran(name, command),
                Ok(code) => {
                    return Err(BootstrapError::CommandFailed {
                        command: command.clone(),
                        code,
                    });
                }
                Err(err) => return Err(BootstrapError::Account(err)),
            }
        }
        Ok(())
    }

    // TODO(smell): duplicates shell.rs unlock_tenant_keychain except for the error type; share one helper
    /// Bootstrap commands hit git/brew credential helpers, which fail confusingly when locked.
    fn unlock_keychain_for_bootstrap(
        &self,
        name: &TenantUserName,
        reporter: &mut Reporter,
    ) -> Result<(), BootstrapError> {
        let password = match self.machine.find_stashed_password(name) {
            Ok(pw) => pw,
            Err(KeychainError::NotFound) => {
                return Err(BootstrapError::StashAbsent { name: name.clone() });
            }
            Err(other) => return Err(BootstrapError::UnlockFailed(other)),
        };
        self.machine
            .unlock_tenant_keychain(name, &password)
            .map_err(BootstrapError::UnlockFailed)?;
        reporter.keychain_unlocked(name);
        Ok(())
    }

    pub(crate) fn bootstrap_all(
        &self,
        directory: &dyn HostUserDirectory,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<BootstrapAllOutcome, UserDirectoryError> {
        let names = directory.tenant_names()?;
        reporter.bootstrap_all_starting(names.len());
        if names.is_empty() {
            reporter.bootstrap_all_done_summary(0, 0, 0);
            return Ok(BootstrapAllOutcome { failed: 0 });
        }
        let mut failed = 0u32;
        let mut skipped = 0u32;
        for name in &names {
            let outcome = match self.build_bootstrap_plan(name, host) {
                Ok(plan) if plan.commands.is_empty() => {
                    skipped += 1;
                    reporter.bootstrap_walk_nothing_declared(name);
                    continue;
                }
                Ok(plan) => self.bootstrap(name, host, &plan, reporter),
                Err(err) => Err(BootstrapError::Mode(err)),
            };
            if let Err(err) = outcome {
                failed += 1;
                surface_bootstrap_error(reporter, name, &err);
            }
        }
        let succeeded = names.len() as u32 - failed - skipped;
        reporter.bootstrap_all_done_summary(succeeded as usize, failed as usize, skipped as usize);
        Ok(BootstrapAllOutcome { failed })
    }
}

pub(crate) fn surface_bootstrap_error(
    reporter: &mut Reporter,
    name: &TenantUserName,
    error: &BootstrapError,
) {
    match error {
        BootstrapError::Mode(ModeError::Profile(e)) => reporter.mode_profile_failed(name, e),
        BootstrapError::Mode(ModeError::Firewall(e)) => reporter.bootstrap_firewall_failed(name, e),
        BootstrapError::Mode(ModeError::Acl(e)) => reporter.mode_acl_failed(name, e),
        BootstrapError::Mode(ModeError::Account(e)) => reporter.mode_account_failed(name, e),
        BootstrapError::Mode(ModeError::Probe(e)) => reporter.mode_probe_failed(name, e),
        BootstrapError::Mode(ModeError::Share(e)) => reporter.refuse_bootstrap_share(name, e),
        BootstrapError::StashAbsent { name: refused } => {
            reporter.bootstrap_refuse_stash_absent(refused);
        }
        BootstrapError::UnlockFailed(e) => reporter.keychain_unlock_failed(name, e),
        BootstrapError::CommandFailed { command, code } => {
            reporter.bootstrap_command_failed(name, command, *code);
        }
        BootstrapError::Account(e) => reporter.bootstrap_exec_failed(name, e),
        BootstrapError::NarrowFailed { narrow_err } => {
            reporter.bootstrap_narrow_failed(name, narrow_err);
        }
    }
}
