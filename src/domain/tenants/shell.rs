//! Shell-verb error type and the `Tenants::shell` orchestrators.
//! Wraps `ModeError` for the auto-narrow path and adds `NarrowFailed`
//! for the command form's post-child reapply.

use crate::domain::reporter::Reporter;
use crate::domain::{AccountError, AccountOp, HostUserName, KeychainError, Op, TenantUserName};
use crate::{InboundLevel, ModeLevel};

use super::reapply::{ReapplyPlan, ReapplyScope};
use super::{ModeError, Tenants};

/// Failure surface for `shell` (interactive + command forms).
/// `NarrowFailed` is exercised only by the command form when the
/// post-child narrow-on-finally reapply fails; the dispatcher emits
/// a warning and propagates the child's exit code. `StashAbsent`
/// fires when the operator-side keychain entry is missing (legacy
/// tenants) — refuse-with-EX_USAGE because the operator needs to
/// re-bootstrap (`tenant destroy && tenant create`). `UnlockFailed`
/// fires on substrate failures of either the retrieval or unlock
/// call — surfaces as EX_IOERR.
#[derive(Debug)]
pub(crate) enum ShellError {
    Account(AccountError),
    Mode(ModeError),
    NarrowFailed {
        child_exit: i32,
        narrow_err: ModeError,
    },
    StashAbsent {
        name: TenantUserName,
    },
    UnlockFailed(KeychainError),
}

impl<'a> Tenants<'a> {
    /// Shell-verb entry: empty argv → interactive; non-empty → command.
    /// `inbound` controls the command form's inbound-loopback axis;
    /// the interactive form ignores it (it always auto-narrows inbound
    /// to restricted, and `--inbound` is parse-rejected without argv).
    pub(crate) fn shell(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        argv: &[String],
        mode: ModeLevel,
        inbound: InboundLevel,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        if argv.is_empty() {
            return self.shell_interactive(name, host, reporter);
        }
        self.shell_command(name, host, argv, mode, inbound, reporter)
    }

    /// Light reapply (PF + host membership + tenant-side symlinks),
    /// then unlock the keychain and log in. Inbound auto-narrows to
    /// restricted (steady-state `None` ⇒ profile-declared ports).
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
            .build_reapply_plan(name, host, ModeLevel::Runtime, None, ReapplyScope::Light)
            .map_err(ShellError::Mode)?;
        let login = AccountOp::LoginAsUser { name: name.into() };
        let mut plan_entries = reapply_plan.as_plan_entries();
        plan_entries.push((Op::Account(&login), None));
        reporter.shell_plan(&plan_entries);
        self.execute_reapply_plan(&reapply_plan, reporter)
            .map_err(ShellError::Mode)?;
        self.unlock_tenant_keychain(name, reporter)?;
        reporter.step(Op::Account(&login));
        self.machine.login(name).map_err(ShellError::Account)
    }

    /// Command-form shell. Build + execute the entry reapply at the
    /// requested egress tier + inbound posture, run the child, then
    /// reapply at the steady posture (egress runtime + inbound
    /// restricted) on completion. The narrow is skipped only when
    /// NEITHER axis was widened (`mode == Runtime && inbound ==
    /// Restricted`), since a second reapply would write the same bytes
    /// for zero on-disk delta. Failure composition:
    ///
    /// - widen-build-failure → `Mode`, no narrow (nothing to undo).
    /// - widen-execute-failure → best-effort narrow inline, then `Mode`.
    /// - child-spawn-failure → `Account`, no narrow (entry reapply
    ///   already reflects the requested posture).
    /// - child-ran + narrow-failed → `NarrowFailed` carrying both the
    ///   child exit and the narrow error; child exit propagates.
    fn shell_command(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        argv: &[String],
        mode: ModeLevel,
        inbound: InboundLevel,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        reporter.shell_command_intent(name, mode);

        let entry_plan: ReapplyPlan = self
            .build_reapply_plan(name, host, mode, Some(inbound), ReapplyScope::Light)
            .map_err(ShellError::Mode)?;

        if let Err(entry_err) = self.execute_reapply_plan(&entry_plan, reporter) {
            // Best-effort narrow (both axes); drop any secondary failure
            // on the floor — the operator's primary signal is the entry
            // failure.
            let _ = self
                .build_reapply_plan(
                    name,
                    host,
                    ModeLevel::Runtime,
                    Some(InboundLevel::Restricted),
                    ReapplyScope::Light,
                )
                .and_then(|p| self.execute_reapply_plan(&p, reporter));
            return Err(ShellError::Mode(entry_err));
        }

        self.unlock_tenant_keychain(name, reporter)?;

        let child_result = self.machine.exec_as_tenant(name, argv);

        // Narrow when EITHER axis widened. Runtime egress + restricted
        // inbound is the steady posture; a no-widen call skips the
        // redundant second reapply.
        let widened = mode == ModeLevel::Install || inbound == InboundLevel::Permissive;
        let narrow_result = if !widened {
            Ok(())
        } else {
            self.build_reapply_plan(
                name,
                host,
                ModeLevel::Runtime,
                Some(InboundLevel::Restricted),
                ReapplyScope::Light,
            )
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

    /// Shared pre-spawn step (both interactive + command forms): retrieve
    /// the operator-stashed password, unlock the tenant's
    /// `login.keychain-db`, emit the `✓` line. Already-unlocked is a
    /// no-op at the substrate (exit 0 either way); the ✓ still emits
    /// so a silent regression where the pass skipped would be visible.
    /// The dry-run posture lives in the `DryRunHostMachine` carve-outs:
    /// `find_stashed_password` returns `NotFound` and the dispatch arm
    /// surfaces the refusal frame — matches the production refusal
    /// shape so a dry-run preview mirrors what a real run would do
    /// against a legacy tenant.
    fn unlock_tenant_keychain(
        &self,
        name: &TenantUserName,
        reporter: &mut Reporter,
    ) -> Result<(), ShellError> {
        let password = match self.machine.find_stashed_password(name) {
            Ok(pw) => pw,
            Err(KeychainError::NotFound) => {
                return Err(ShellError::StashAbsent { name: name.clone() });
            }
            Err(other) => return Err(ShellError::UnlockFailed(other)),
        };
        self.machine
            .unlock_tenant_keychain(name, &password)
            .map_err(ShellError::UnlockFailed)?;
        reporter.shell_keychain_unlocked(name);
        Ok(())
    }
}
