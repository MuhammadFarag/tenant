//! Shell-verb error type and the `Tenants::shell` orchestrators.
//! Wraps `ModeError` for the auto-narrow path and adds `NarrowFailed`
//! for the command form's post-child reapply.

use std::path::{Path, PathBuf};

use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, HostUserName, KeychainError, Op, ProbeError, TenantUserName,
};
use crate::profile::expand_tenant_path;
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
/// call — surfaces as EX_IOERR. The two `Directory*` variants are the
/// `-d/--directory` pre-flight refusals (both EX_USAGE); a probe that
/// fails to run at all is a substrate failure and rides `DirectoryProbe`
/// at EX_IOERR.
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

/// Resolve a `-d/--directory` value against the TENANT's filesystem.
/// Three accepted shapes: absolute ⇒ literal; `$HOME`-prefix ⇒ the
/// tenant's home (the same prefix-only contract as a share's
/// `tenant_path`); anything else ⇒ relative to the tenant's home. The
/// relative shape is the primary UX — it sidesteps the quoting footgun
/// where an unquoted `$HOME` expands to the OPERATOR's home before clap
/// ever sees it. Mid-string `$HOME` refuses rather than passing through
/// as a surprising literal.
///
/// Deliberately NOT taught to `expand_tenant_path`: shares' template
/// semantics flow through that helper too, and a relative share
/// `tenant_path` must keep its current literal behavior.
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
        // Relative ⇒ tenant home. Routed through `expand_tenant_path` so
        // `/Users/<name>` has exactly one source.
        expand_tenant_path(name.as_str(), &format!("$HOME/{raw}"))
    };
    // Any surviving `$` refuses — checked on the RESOLVED path, not the
    // raw input, so it also catches a `$` trailing a legal `$HOME/`
    // prefix (`$HOME/projects/$scratch`), which an input-side check
    // would return past. `sudo -i` escapes its command "except
    // alphanumerics, underscores, hyphens, and dollar signs", so a `$`
    // survives into the tenant's login shell and expands there — even
    // inside the wrapper's single quotes, which sudo has already
    // neutralized. An unset variable would silently truncate the path
    // and run the operator's command in the WRONG directory at exit 0;
    // a set one would splice its value into shell code. Quoting cannot
    // fix this across sudo's re-parse, so the shape is refused instead.
    // Never fires spuriously: the tenant-name charset can't introduce a
    // `$`, so the only source is the operator's own value.
    if resolved.to_string_lossy().contains('$') {
        return Err(ShellError::DirectoryInvalid {
            raw: raw.to_string(),
            reason: "contains `$`, which the tenant's login shell would expand before `cd` runs",
        });
    }
    Ok(resolved)
}

impl<'a> Tenants<'a> {
    /// Shell-verb entry: empty argv → interactive; non-empty → command.
    /// `inbound` controls the command form's inbound-loopback axis;
    /// the interactive form ignores it (it always auto-narrows inbound
    /// to restricted, and `--inbound` is parse-rejected without argv).
    /// `directory` is the raw `-d/--directory` value, valid on BOTH
    /// forms; it resolves and pre-flights here — before the branch, so
    /// nothing widens, unlocks or reapplies on either path until the
    /// directory is known-good (the `[[shares]]` pre-flight doctrine).
    // Eight distinct-typed params read at one call site each; bundling
    // them would add a struct that exists only to satisfy the lint.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn shell(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        argv: &[String],
        mode: ModeLevel,
        inbound: InboundLevel,
        directory: Option<&str>,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        let dir = self.prepare_shell_directory(name, directory)?;
        if argv.is_empty() {
            return self.shell_interactive(name, host, dir.as_deref(), reporter);
        }
        self.shell_command(name, host, argv, mode, inbound, dir.as_deref(), reporter)
    }

    /// Resolve + probe the requested working directory. A path that
    /// doesn't resolve (through symlinks) to a directory the tenant can
    /// enter refuses at EX_USAGE naming the RESOLVED path — the operator
    /// typed `projects/foo`, so the error has to say
    /// `/Users/<name>/projects/foo` for the fix to be obvious. No `-d` ⇒
    /// no resolution, no probe.
    ///
    /// The probe is gated on a live sudo session, like every other
    /// `sudo -n` probe in the codebase: sudo exits 1 when it can't
    /// authenticate, which `/bin/test` also uses for "no", so a cold
    /// timestamp would make every existing directory look absent and
    /// refuse the operator's first command in a fresh terminal. Uncached
    /// ⇒ skip the pre-flight and let the entry reapply prompt as usual;
    /// an unusable dir then surfaces as the wrapper's own `cd` failure.
    /// Never refuse on an answer we can't trust.
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

    /// Light reapply (PF + host membership + tenant-side symlinks),
    /// then unlock the keychain and log in. Inbound auto-narrows to
    /// restricted (steady-state `None` ⇒ profile-declared ports).
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
    #[allow(clippy::too_many_arguments)]
    fn shell_command(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        argv: &[String],
        mode: ModeLevel,
        inbound: InboundLevel,
        dir: Option<&Path>,
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

        let child_result = self.machine.exec_as_tenant(name, argv, dir);

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
