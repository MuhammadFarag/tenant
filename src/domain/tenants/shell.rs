use std::path::{Path, PathBuf};

use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, HostUserName, KeychainError, Op, ProbeError, TenantUserName,
};
use crate::profile::expand_tenant_path;
use crate::{InboundLevel, ModeLevel};

use super::reapply::{ReapplyPlan, ReapplyScope};
use super::{ModeError, Tenants};

// TODO(smell): per-variant exit codes live only in dispatch; put them on the error type
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
    DirectoryInvalid {
        raw: String,
        reason: &'static str,
    },
    DirectoryUnavailable {
        path: PathBuf,
    },
    DirectoryProbe {
        path: PathBuf,
        err: ProbeError,
    },
}

/// Relative paths resolve against the tenant home, the primary UX: an unquoted `$HOME`
/// expands to the OPERATOR's home before clap sees it. Not folded into
/// `expand_tenant_path`: a relative share `tenant_path` must stay literal.
pub(crate) fn resolve_shell_directory(
    name: &TenantUserName,
    raw: &str,
) -> Result<PathBuf, ShellError> {
    let resolved = if raw == "$HOME" || raw.starts_with("$HOME/") {
        expand_tenant_path(name.as_str(), raw)
    } else if raw.contains("$HOME") {
        return Err(ShellError::DirectoryInvalid {
            raw: raw.to_string(),
            reason: "contains `$HOME` not at the start; `$HOME` expands only as a path prefix",
        });
    } else if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        expand_tenant_path(name.as_str(), &format!("$HOME/{raw}"))
    };
    // Checked on the RESOLVED path so `$HOME/x/$y` is caught too. `sudo -i` leaves `$`
    // unescaped, so it expands in the tenant's login shell even inside the wrapper's
    // quotes: an unset var runs the command in the wrong dir at exit 0, a set one splices
    // into shell code. Quoting can't survive sudo's re-parse, so refuse.
    if resolved.to_string_lossy().contains('$') {
        return Err(ShellError::DirectoryInvalid {
            raw: raw.to_string(),
            reason: "contains `$`, which the tenant's login shell would expand before `cd` runs",
        });
    }
    Ok(resolved)
}

impl<'a> Tenants<'a> {
    /// `directory` pre-flights before either form, so nothing widens, unlocks or reapplies
    /// until it's known-good.
    // Eight distinct-typed params read at one call site each; bundling
    // them would add a struct that exists only to satisfy the lint.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn shell(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        argv: &[String],
        mode: ModeLevel,
        inbound: Option<InboundLevel>,
        directory: Option<&str>,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        let dir = self.prepare_shell_directory(name, directory)?;
        if argv.is_empty() {
            return self.shell_interactive(name, host, dir.as_deref(), reporter);
        }
        self.shell_command(name, host, argv, mode, inbound, dir.as_deref(), reporter)
    }

    /// The probe needs a warm sudo cache: `sudo -n` fails cold and would refuse the first
    /// command in every fresh terminal. Cold ⇒ skip; a bad dir then fails at `cd`.
    fn prepare_shell_directory(
        &self,
        name: &TenantUserName,
        directory: Option<&str>,
    ) -> Result<Option<PathBuf>, ShellError> {
        let Some(raw) = directory else {
            return Ok(None);
        };
        let path = resolve_shell_directory(name, raw)?;
        if !self.machine.sudo_session_cached() {
            return Ok(Some(path));
        }
        match self.machine.tenant_dir_present(name, &path) {
            Ok(true) => Ok(Some(path)),
            Ok(false) => Err(ShellError::DirectoryUnavailable { path }),
            Err(err) => Err(ShellError::DirectoryProbe { path, err }),
        }
    }

    fn shell_interactive(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        dir: Option<&Path>,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        // Intent emitted before the narrow tries, so the operator sees
        // the verb context even if the pre-flight profile read fails.
        reporter.shell_intent(name);
        let reapply_plan = self
            .build_reapply_plan(name, host, ModeLevel::Runtime, None, ReapplyScope::Light)
            .map_err(ShellError::Mode)?;
        let login = AccountOp::LoginAsUser {
            name: name.into(),
            dir: dir.map(Path::to_path_buf),
        };
        let mut plan_entries = reapply_plan.as_plan_entries();
        plan_entries.push((Op::Account(&login), None));
        reporter.shell_plan(&plan_entries);
        self.execute_reapply_plan(&reapply_plan, reporter)
            .map_err(ShellError::Mode)?;
        self.unlock_tenant_keychain(name, reporter)?;
        reporter.step(Op::Account(&login));
        self.machine.login(name, dir).map_err(ShellError::Account)
    }

    #[allow(clippy::too_many_arguments)]
    fn shell_command(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        argv: &[String],
        mode: ModeLevel,
        inbound: Option<InboundLevel>,
        dir: Option<&Path>,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        reporter.shell_command_intent(name, mode);

        let entry_plan: ReapplyPlan = self
            .build_reapply_plan(name, host, mode, inbound, ReapplyScope::Light)
            .map_err(ShellError::Mode)?;

        if let Err(entry_err) = self.execute_reapply_plan(&entry_plan, reporter) {
            // Best-effort: the entry failure is the operator's signal, so a narrow error is dropped.
            let _ = self
                .build_reapply_plan(name, host, ModeLevel::Runtime, None, ReapplyScope::Light)
                .and_then(|p| self.execute_reapply_plan(&p, reporter));
            return Err(ShellError::Mode(entry_err));
        }

        self.unlock_tenant_keychain(name, reporter)?;

        let child_result = self.machine.exec_as_tenant(name, argv, dir);

        let widened = mode == ModeLevel::Install || inbound == Some(InboundLevel::Permissive);
        let narrow_result = if !widened {
            Ok(())
        } else {
            self.build_reapply_plan(name, host, ModeLevel::Runtime, None, ReapplyScope::Light)
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

    // TODO(smell): dry-run shell always refuses (DryRunHostMachine stash lookup ⇒ NotFound, exit 64); a preview shouldn't manufacture a refusal
    /// Unconditional by design, no locked-state pre-probe: `security show-keychain-info` via
    /// `sudo -iu` raises a SecurityAgent GUI prompt on Darwin 25.x and hangs headless runs.
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
        reporter.keychain_unlocked(name);
        Ok(())
    }
}
