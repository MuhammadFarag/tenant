//! Operator-facing output: the layer between domain ops and what the
//! operator reads.
//!
//! Each verb has its own pre-exec / post-exec / refusal / failure methods
//! on `Reporter`. The methods bake in the verb-specific phrasing and
//! handle the mode/verbosity branching internally — callers (commands.rs
//! dispatch, accounts.rs Writer) just say "this verb is starting / done /
//! refused / failed" and the Reporter picks the right output for the
//! current mode.
//!
//! `Reporter` holds a reference to the active `Executor` so it can
//! render plan + echo lines lazily from `AccountOp` / `ProfileOp` values
//! via the `Op::describe_via` ADT method. Plan rendering walks
//! `&[(Op<'_>, Option<&'static str>)]` tuples — `Op` for domain dispatch,
//! the `Option<&'static str>` slot for per-step annotations like
//! `# on rollback`.

use std::io::Write;

use crate::accounts::{ConflictError, NameError, tenant_share_group_name};
use crate::executor::{AccountError, AccountOp, Executor, Op};
use crate::profile::{ProfileError, display_path_for};

pub(crate) struct Reporter<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
    verbose: bool,
    dry_run: bool,
    executor: &'a dyn Executor,
}

impl<'a> Reporter<'a> {
    pub fn new(
        stdout: &'a mut dyn Write,
        stderr: &'a mut dyn Write,
        verbose: bool,
        dry_run: bool,
        executor: &'a dyn Executor,
    ) -> Self {
        Self {
            stdout,
            stderr,
            verbose,
            dry_run,
            executor,
        }
    }

    /// Per-step echo: `$ <rendered>` line. Emits only in real+verbose
    /// (dry-run is silent; standard mode is silent). Rendering goes
    /// through `Op::describe_via` so the same display-dispatch logic
    /// drives both the upfront plan block and the per-step echo.
    pub fn step(&mut self, op: Op<'_>) {
        if self.dry_run || !self.verbose {
            return;
        }
        let line = op.describe_via(self.executor);
        let _ = writeln!(self.stdout, "$ {line}");
    }

    // ============================================================
    // Create verb
    // ============================================================

    /// Pre-exec disclosure for `create`. Standard mode: silent (the
    /// post-exec `create_done` does the talking). Real+verbose: emits
    /// "Creating tenant 'X'." + indented plan block. Dry-run (any
    /// verbosity): emits "Would create tenant 'X'." + (verbose: plan).
    pub fn create_starting(&mut self, name: &str, plan: &[(Op<'_>, Option<&'static str>)]) {
        let summary = match (self.dry_run, self.verbose) {
            (true, _) => Some(format!("Would create tenant '{name}'.")),
            (false, true) => Some(format!("Creating tenant '{name}'.")),
            (false, false) => None,
        };
        if let Some(s) = summary {
            let _ = writeln!(self.stdout, "{s}");
        }
        if self.verbose {
            self.render_plan(plan);
        }
    }

    /// Post-exec confirmation for `create`. Silent in dry-run (would be
    /// a lie). Real+standard: "Created tenant 'X'." Real+verbose: inlines
    /// UID + GID since Phase 3 allocates them independently.
    pub fn create_done(&mut self, name: &str, uid: u32, gid: u32) {
        if self.dry_run {
            return;
        }
        let line = if self.verbose {
            format!("Created tenant '{name}' (UID {uid}, GID {gid}).")
        } else {
            format!("Created tenant '{name}'.")
        };
        let _ = writeln!(self.stdout, "{line}");
    }

    // ============================================================
    // Destroy verb (full path)
    // ============================================================

    /// Pre-exec disclosure for `destroy`. Same mode pattern as
    /// `create_starting`.
    pub fn destroy_starting(&mut self, name: &str, plan: &[(Op<'_>, Option<&'static str>)]) {
        let summary = match (self.dry_run, self.verbose) {
            (true, _) => Some(format!("Would destroy tenant '{name}'.")),
            (false, true) => Some(format!("Destroying tenant '{name}'.")),
            (false, false) => None,
        };
        if let Some(s) = summary {
            let _ = writeln!(self.stdout, "{s}");
        }
        if self.verbose {
            self.render_plan(plan);
        }
    }

    /// Post-exec confirmation for `destroy`. Unlike `create_done` no UID
    /// is inlined — a destroyed account's old UID is not new information.
    pub fn destroy_done(&mut self, name: &str) {
        if self.dry_run {
            return;
        }
        let _ = writeln!(self.stdout, "Destroyed tenant '{name}'.");
    }

    // ============================================================
    // Destroy verb (orphan-group convergence path)
    // ============================================================

    /// Pre-exec disclosure for the orphan-group convergence path.
    /// Standard mode names the tenant; verbose adds the literal group
    /// name. The four mode/verbosity cells produce distinct phrasings —
    /// this is the verb where the dry+verbose phrasing diverges from
    /// dry+standard (group name appears only in verbose).
    pub fn orphan_group_starting(&mut self, name: &str, plan: &[(Op<'_>, Option<&'static str>)]) {
        let group = tenant_share_group_name(name);
        let summary = match (self.dry_run, self.verbose) {
            (true, false) => Some(format!("Would destroy orphan group for tenant '{name}'.")),
            (true, true) => Some(format!(
                "Would destroy orphan group '{group}' for tenant '{name}'."
            )),
            (false, true) => Some(format!(
                "Destroying orphan group '{group}' for tenant '{name}'."
            )),
            (false, false) => None,
        };
        if let Some(s) = summary {
            let _ = writeln!(self.stdout, "{s}");
        }
        if self.verbose {
            self.render_plan(plan);
        }
    }

    /// Post-exec confirmation for the orphan-group convergence path.
    /// Same standard/verbose split as `orphan_group_starting`.
    pub fn orphan_group_done(&mut self, name: &str) {
        if self.dry_run {
            return;
        }
        let group = tenant_share_group_name(name);
        let line = if self.verbose {
            format!("Destroyed orphan group '{group}' for tenant '{name}'.")
        } else {
            format!("Destroyed orphan group for tenant '{name}'.")
        };
        let _ = writeln!(self.stdout, "{line}");
    }

    // ============================================================
    // Shell verb
    // ============================================================

    /// Pre-exec disclosure for `shell`. Unlike create/destroy, the
    /// intent line ("Shelling into 'X'." / "Would shell into 'X'.")
    /// emits in standard mode too — there's no post-exec confirmation
    /// (the operator IS the shell after `login` returns), so without
    /// this line standard mode would leave the operator looking at a
    /// bare sudo prompt with no project-side context.
    pub fn shell_starting(&mut self, name: &str, login_op: &AccountOp) {
        let summary = if self.dry_run {
            format!("Would shell into '{name}'.")
        } else {
            format!("Shelling into '{name}'.")
        };
        let _ = writeln!(self.stdout, "{summary}");
        if self.verbose {
            let line = self.executor.describe_account(login_op);
            let _ = writeln!(self.stdout, "  {line}");
        }
    }

    // ============================================================
    // Convergent noop (destroy on absent tenant)
    // ============================================================

    /// Convergent-noop message: the named tenant doesn't exist; destroy
    /// is a successful no-op. Tense-neutral, emits in both real and
    /// dry-run modes (the verb is idempotent so "would" / "did" is the
    /// same answer).
    pub fn destroy_absent(&mut self, name: &str) {
        let _ = writeln!(
            self.stdout,
            "tenant '{name}' does not exist; nothing to do."
        );
    }

    // ============================================================
    // Refusals (stderr, EX_USAGE)
    // ============================================================

    pub fn refuse_invalid_name(&mut self, name: &str, err: &NameError) {
        let msg = match err {
            NameError::Empty => "tenant: name cannot be empty".to_string(),
            NameError::InvalidStart(c) => {
                format!("tenant: name '{name}' must start with a lowercase letter (got '{c}')")
            }
            NameError::InvalidCharacter(c) => {
                format!("tenant: name '{name}' contains invalid character '{c}'")
            }
            NameError::TooLong { len, max } => {
                format!("tenant: name '{name}' is too long ({len} characters; maximum is {max})")
            }
            NameError::Reserved => {
                format!("tenant: name '{name}' is reserved (matches a system or role name)")
            }
        };
        let _ = writeln!(self.stderr, "{msg}");
    }

    pub fn refuse_name_conflict(&mut self, name: &str, err: &ConflictError) {
        let group = tenant_share_group_name(name);
        let msg = match err {
            ConflictError::UserExists => format!("tenant: user '{name}' already exists"),
            ConflictError::GroupExists => format!("tenant: group '{group}' already exists"),
            ConflictError::Both => {
                format!("tenant: user '{name}' and group '{group}' already exist")
            }
        };
        let _ = writeln!(self.stderr, "{msg}");
    }

    pub fn refuse_not_a_tenant(&mut self, name: &str, uid: u32, floor: u32) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to destroy '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_system_account(&mut self, name: &str) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to destroy '{name}': system account (no tenant-range UID)"
        );
    }

    pub fn refuse_shell_absent(&mut self, name: &str) {
        let _ = writeln!(
            self.stderr,
            "tenant: cannot shell into '{name}': does not exist"
        );
    }

    pub fn refuse_shell_not_a_tenant(&mut self, name: &str, uid: u32, floor: u32) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to shell into '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_shell_system_account(&mut self, name: &str) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to shell into '{name}': system account (no tenant-range UID)"
        );
    }

    // ============================================================
    // Failures (stderr, EX_IOERR)
    // ============================================================

    pub fn create_group_failed(&mut self, name: &str, err: &AccountError) {
        let group = tenant_share_group_name(name);
        let _ = writeln!(
            self.stderr,
            "tenant: failed to create group '{group}' for '{name}': {err}"
        );
    }

    pub fn create_failed(&mut self, name: &str, err: &AccountError) {
        let _ = writeln!(self.stderr, "tenant: failed to create '{name}': {err}");
    }

    /// Em-dash-suffixed recovery hint. Emitted as a SECOND stderr line
    /// after `create_failed` when the rollback itself failed. The
    /// trailing clause points the operator at `tenant destroy` for
    /// convergence (the OrphanGroup eligibility arm).
    pub fn create_rollback_failed(&mut self, name: &str, err: &AccountError) {
        let group = tenant_share_group_name(name);
        let _ = writeln!(
            self.stderr,
            "tenant: rollback of group '{group}' also failed: {err} \
             \u{2014} host now has an orphan group; next 'tenant destroy {name}' will converge"
        );
    }

    pub fn create_profile_failed(&mut self, name: &str, err: &ProfileError) {
        let path = display_path_for(name);
        let _ = writeln!(
            self.stderr,
            "tenant: failed to write profile '{path}' for '{name}': {err}"
        );
    }

    pub fn destroy_failed(&mut self, name: &str, err: &AccountError) {
        let _ = writeln!(self.stderr, "tenant: failed to destroy '{name}': {err}");
    }

    pub fn destroy_profile_failed(&mut self, name: &str, err: &ProfileError) {
        let path = display_path_for(name);
        let _ = writeln!(
            self.stderr,
            "tenant: failed to remove profile '{path}' for '{name}': {err}"
        );
    }

    pub fn shell_failed(&mut self, name: &str, err: &AccountError) {
        let _ = writeln!(self.stderr, "tenant: failed to shell into '{name}': {err}");
    }

    // ============================================================
    // Plan rendering helper (private)
    // ============================================================

    /// Render the upfront plan block: each step on its own line with
    /// `  ` two-space indentation; annotated steps get a trailing
    /// `  # <note>` suffix. Display dispatch goes through
    /// `Op::describe_via` so this single helper works for any mix of
    /// account-domain and profile-domain ops.
    fn render_plan(&mut self, plan: &[(Op<'_>, Option<&'static str>)]) {
        for (op, annotation) in plan {
            let line = op.describe_via(self.executor);
            let formatted = match annotation {
                Some(note) => format!("  {line}  # {note}"),
                None => format!("  {line}"),
            };
            let _ = writeln!(self.stdout, "{formatted}");
        }
    }
}
