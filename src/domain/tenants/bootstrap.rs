//! Bootstrap-verb error type and the `Tenants::bootstrap` orchestrator.
//! Runs the merged profile's `[bootstrap]` commands AS the tenant inside
//! an install-tier egress widen with narrow-on-finally — the SAME
//! composition as shell's command form (`shell.rs` `shell_command`),
//! with two deliberate differences: the "work" is a loop over the
//! declared commands (stop on the first non-zero exit), and there is NO
//! child-exit propagation (bootstrap is not shell — a failing command is
//! `EX_IOERR`, per the exit-code doctrine).

use crate::ModeLevel;
use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, HostUserDirectory, HostUserName, KeychainError, Op, TenantUserName,
    UserDirectoryError,
};

use super::Tenants;
use super::reapply::{ModeError, ReapplyPlan, ReapplyScope};

/// Failure surface for `bootstrap` (single-tenant + fleet walk).
///
/// `Mode` wraps the widen/narrow reapply failures (shared with mode/
/// reload). `StashAbsent`/`UnlockFailed` mirror shell's keychain
/// pre-spawn error mapping (`StashAbsent` → `EX_USAGE` refusal naming
/// destroy/recreate; other unlock errors → `EX_IOERR`). `CommandFailed`
/// carries the command string + its non-zero exit code (surfaced, not
/// propagated — bootstrap exits `EX_IOERR`). `Account` is an exec spawn
/// failure. `NarrowFailed` fires when the commands ALL ran but the
/// post-run narrow reapply failed — the `⚠` doesn't mask the commands'
/// outcome (they succeeded), but the verb still exits `EX_IOERR` because
/// a substrate op failed (bootstrap is not shell — no child-exit
/// propagation to carry a success code past a substrate failure).
#[derive(Debug)]
pub(crate) enum BootstrapError {
    Mode(ModeError),
    StashAbsent { name: TenantUserName },
    UnlockFailed(KeychainError),
    CommandFailed { command: String, code: i32 },
    Account(AccountError),
    NarrowFailed { narrow_err: ModeError },
}

/// Pre-built plan for a single tenant's bootstrap: the merged profile's
/// `commands` (rendered verbatim pre-confirm — the honesty backstop) and
/// the install-tier widen reapply plan (Light scope). Built upfront in
/// dispatch so a broken include / share pre-flight surfaces pre-prompt,
/// exactly like reload's `ReapplyPlan`. `commands.is_empty()` gates the
/// quiet no-op (a tenant declaring none is a convergent success).
pub(crate) struct BootstrapPlan {
    pub(crate) commands: Vec<String>,
    pub(crate) widen: ReapplyPlan,
}

/// Outcome of the fleet walk (`bootstrap_all`). `failed` drives the
/// caller's `0`/`74` exit. Skipped (no-command) tenants are counted
/// locally in the walk for the summary line, not carried out here.
#[derive(Debug)]
pub(crate) struct BootstrapAllOutcome {
    pub(crate) failed: u32,
}

impl<'a> Tenants<'a> {
    /// Load the merged profile ONCE, extract its `[bootstrap]` commands,
    /// and build the install-tier widen reapply plan from the same parse
    /// (via `build_reapply_plan_from_profile`, so the profile isn't read
    /// twice). Profile-read / include / share pre-flight failures surface
    /// here as `ModeError` — dispatch renders them pre-prompt.
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

    /// Run a single tenant's bootstrap. `plan.commands` is guaranteed
    /// non-empty by the caller (dispatch routes the empty case to the
    /// quiet-noop reporter line before ever reaching here). Composition
    /// mirrors `shell_command`'s widen → unlock → work → narrow-on-finally,
    /// with one deliberate strengthening: bootstrap's widen is
    /// UNCONDITIONAL (always install tier), so once it lands the keychain
    /// unlock joins the commands as post-widen "work" — the mandatory
    /// narrow-on-finally then fires even when the unlock fails (a legacy
    /// tenant's absent stash), so the install-tier widen is never
    /// stranded. (Shell only widens under `--mode install`, so its
    /// unlock-failure can `?`-return without a dangling widen.)
    ///
    /// - widen-execute-failure → best-effort inline narrow, then `Mode`.
    /// - keychain `StashAbsent`/`UnlockFailed` → surfaced as the primary
    ///   error; narrow-on-finally still fires (best-effort).
    /// - commands run in order; the first non-zero exit stops the loop.
    /// - narrow-on-finally ALWAYS fires (we widened to install tier).
    /// - work-ok + narrow-ok → done.
    /// - work-ok + narrow-failed → `NarrowFailed`.
    /// - work-failed → the work error is primary; the finally narrow's own
    ///   failure is dropped (best-effort, mirrors shell's widen-exec-fail
    ///   secondary drop).
    pub(crate) fn bootstrap(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        plan: &BootstrapPlan,
        reporter: &mut Reporter,
    ) -> Result<(), BootstrapError> {
        reporter.bootstrap_intent(name);

        if let Err(entry_err) = self.execute_reapply_plan(&plan.widen, reporter) {
            // Best-effort narrow; drop any secondary failure — the widen
            // failure is the operator's primary signal.
            let _ = self
                .narrow_plan(name, host)
                .and_then(|p| self.execute_reapply_plan(&p, reporter));
            return Err(BootstrapError::Mode(entry_err));
        }

        // Widen landed. Keychain unlock + the command loop are the
        // post-widen "work"; the narrow-on-finally below ALWAYS follows,
        // so an unlock failure narrows the widen back rather than leaving
        // the tenant stranded at install tier.
        let run_result = self
            .unlock_keychain_for_bootstrap(name, reporter)
            .and_then(|()| self.run_bootstrap_commands(name, &plan.commands, reporter));

        // Narrow-on-finally: mandatory regardless of work outcome (we
        // always widened to install tier). Rebuilt fresh at runtime tier,
        // exactly like shell_command's post-child narrow.
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

    /// Runtime-tier Light narrow plan — the steady egress posture the
    /// widen returns to. Shared by the widen-fail best-effort path and
    /// the mandatory narrow-on-finally.
    fn narrow_plan(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
    ) -> Result<ReapplyPlan, ModeError> {
        self.build_reapply_plan(name, host, ModeLevel::Runtime, None, ReapplyScope::Light)
    }

    /// Run each command AS the tenant via `/bin/sh -c <command>` (the
    /// `exec_as_tenant` carve-out provides the `sudo -iu` login context).
    /// The `ExecAsUser` op is constructed purely for the verbose `$` echo
    /// (plan/echo render only — `execute_account` panics on it; the real
    /// run is the `exec_as_tenant` call, exactly like shell). Stops on the
    /// first non-zero exit (`CommandFailed`) or spawn failure (`Account`).
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

    /// Mirror of shell's shared pre-spawn keychain step (`shell.rs`
    /// `unlock_tenant_keychain`): retrieve the operator-stashed password,
    /// unlock the tenant's `login.keychain-db`, emit the `✓` line.
    /// Bootstrap commands hit git/brew credential helpers, so a locked
    /// keychain fails them confusingly. Mirrored, not shared — shell's
    /// helper returns `ShellError`; threading a neutral error across two
    /// verbs would be a leaky abstraction (the doctrine-sanctioned choice
    /// per the design notes: a copy with this comment over a shared error
    /// type). The `✓` reporter line is reused verbatim (verb-agnostic).
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
        reporter.shell_keychain_unlocked(name);
        Ok(())
    }

    /// Walk every tenant, bootstrapping each in turn. Mirrors `reload_all`:
    /// per-tenant failures are recorded and the walk CONTINUES; any
    /// failure ⇒ the caller exits `EX_IOERR`. A tenant declaring no
    /// commands is a quiet skip (not a failure). A legacy tenant missing
    /// its keychain stash refuses that ONE tenant (`StashAbsent`) and the
    /// walk moves on — one broken tenant must not strand the fleet
    /// converge.
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

/// Route a `BootstrapError` to the reporter's stderr frames. Shared by
/// the fleet walk above (per-tenant, walk continues) and the single-tenant
/// dispatch in `commands.rs` (dispatch owns the exit-code mapping —
/// `StashAbsent` is `EX_USAGE`, every other arm `EX_IOERR`). The `Mode`
/// arm reuses the verb-agnostic mode frames for Acl/Account/Probe and
/// bootstrap-named frames for Profile/Firewall/Share.
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
        BootstrapError::UnlockFailed(e) => reporter.shell_unlock_failed(name, e),
        BootstrapError::CommandFailed { command, code } => {
            reporter.bootstrap_command_failed(name, command, *code);
        }
        BootstrapError::Account(e) => reporter.bootstrap_exec_failed(name, e),
        BootstrapError::NarrowFailed { narrow_err } => {
            reporter.bootstrap_narrow_failed(name, narrow_err);
        }
    }
}
