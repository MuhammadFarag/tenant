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
use std::path::PathBuf;

use crate::ModeLevel;
use crate::accounts::{ConflictError, NameError, tenant_share_group_name};
use crate::doctor::{Category, Finding};
use crate::executor::{AccessMode, AccountError, Executor, FirewallError, Op, ProbeError};
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
    ///
    /// Plan grew from 1 to 3 lines in cycle 4: the auto-narrow's
    /// `InstallAnchor → Reload` runs before `LoginAsUser`. The plan
    /// shows all three; echo (via `step`) emits each `$ <line>` as
    /// the writer drives the ops.
    pub fn shell_starting(&mut self, name: &str, plan: &[(Op<'_>, Option<&'static str>)]) {
        let summary = if self.dry_run {
            format!("Would shell into '{name}'.")
        } else {
            format!("Shelling into '{name}'.")
        };
        let _ = writeln!(self.stdout, "{summary}");
        if self.verbose {
            self.render_plan(plan);
        }
    }

    // ============================================================
    // Mode verb
    // ============================================================

    /// Pre-exec disclosure for `mode`. Same mode pattern as
    /// `create_starting` / `destroy_starting`: standard real is
    /// silent (the post-exec `mode_done` does the talking); real+verbose
    /// emits the "Applying" intent + indented plan; dry-run (any
    /// verbosity) emits "Would apply" + (verbose: plan).
    pub fn mode_starting(
        &mut self,
        name: &str,
        level: ModeLevel,
        plan: &[(Op<'_>, Option<&'static str>)],
    ) {
        let level_str = level.as_str();
        let summary = match (self.dry_run, self.verbose) {
            (true, _) => Some(format!(
                "Would apply mode '{level_str}' to tenant '{name}'."
            )),
            (false, true) => Some(format!("Applying mode '{level_str}' to tenant '{name}'.")),
            (false, false) => None,
        };
        if let Some(s) = summary {
            let _ = writeln!(self.stdout, "{s}");
        }
        if self.verbose {
            self.render_plan(plan);
        }
    }

    /// Post-exec confirmation for `mode`. Silent in dry-run (would be
    /// a lie — no reapply ran). Real (any verbosity): one summary line
    /// naming the level.
    pub fn mode_done(&mut self, name: &str, level: ModeLevel) {
        if self.dry_run {
            return;
        }
        let level_str = level.as_str();
        let _ = writeln!(
            self.stdout,
            "Applied mode '{level_str}' to tenant '{name}'."
        );
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

    /// Mode-side absent refusal. Like `refuse_shell_absent`, this
    /// collapses `Eligibility::NotPresent` and `Eligibility::OrphanGroup`
    /// — the operator wants to switch a tenant's mode; a lingering
    /// `<name>-tenant-share` group doesn't host one.
    pub fn refuse_mode_absent(&mut self, name: &str) {
        let _ = writeln!(
            self.stderr,
            "tenant: cannot apply mode to '{name}': does not exist"
        );
    }

    pub fn refuse_mode_not_a_tenant(&mut self, name: &str, uid: u32, floor: u32) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to apply mode to '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_mode_system_account(&mut self, name: &str) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to apply mode to '{name}': system account (no tenant-range UID)"
        );
    }

    /// Doctor-side absent refusal. Like `refuse_shell_absent` /
    /// `refuse_mode_absent`, collapses `Eligibility::NotPresent` and
    /// `Eligibility::OrphanGroup` — the operator wants to audit a
    /// tenant, and a lingering `<name>-tenant-share` group with no
    /// user behind it doesn't represent one.
    pub fn refuse_doctor_absent(&mut self, name: &str) {
        let _ = writeln!(
            self.stderr,
            "tenant: cannot run doctor on '{name}': does not exist"
        );
    }

    pub fn refuse_doctor_not_a_tenant(&mut self, name: &str, uid: u32, floor: u32) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to run doctor on '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_doctor_system_account(&mut self, name: &str) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to run doctor on '{name}': system account (no tenant-range UID)"
        );
    }

    // ============================================================
    // Doctor verb (cycle 5)
    // ============================================================

    /// Pre-walk disclosure for `doctor <name>`. Standard real mode is
    /// silent (findings + summary do the talking); verbose (real OR
    /// dry-run) emits a "Curated sensitive paths checked for tenant
    /// 'X':" header followed by one indented `<verb> <path>` line per
    /// curated entry — so the operator can see the bounded scope of
    /// the audit (a clean "no findings" result is not a claim about
    /// the host's overall security; it's about THESE PATHS).
    /// Dry-run any verbosity also emits a "Would run doctor on tenant
    /// 'X'." intent line up front so the verb's existence is visible
    /// even when verbose is off.
    pub fn doctor_starting(&mut self, name: &str, curated: &[(Category, AccessMode, PathBuf)]) {
        if self.dry_run {
            let _ = writeln!(self.stdout, "Would run doctor on tenant '{name}'.");
        }
        if self.verbose {
            let _ = writeln!(
                self.stdout,
                "Curated sensitive paths checked for tenant '{name}':"
            );
            for (_, mode, path) in curated {
                let verb = match mode {
                    AccessMode::Read => "read",
                    AccessMode::List => "list",
                };
                let _ = writeln!(self.stdout, "  {verb} {}", path.display());
            }
        }
    }

    /// One operator-facing line per finding, emitted as soon as the
    /// probe that produced it returns. Output goes to stdout; finding
    /// text is the byte-form pinned by `Finding::Display`.
    ///
    /// In verbose mode (cycle 9), each finding's one-liner is followed
    /// by the structured-guidance block from `Finding::guidance()`,
    /// indented 2 spaces under the finding line. `FilesystemExposure`
    /// returns `None` for guidance and renders the one-liner alone
    /// even in verbose mode (Q3 lock — per-path-category guidance
    /// belongs to the future filesystem-exposure remediation cycle).
    pub fn doctor_finding(&mut self, finding: &Finding) {
        let _ = writeln!(self.stdout, "{finding}");
        if self.verbose
            && let Some(guidance) = finding.guidance()
        {
            for line in guidance.lines() {
                if line.is_empty() {
                    let _ = writeln!(self.stdout);
                } else {
                    let _ = writeln!(self.stdout, "  {line}");
                }
            }
        }
    }

    /// Post-walk summary. With findings: silent (the finding lines did
    /// the talking). Without findings: a single em-dash-suffixed line
    /// confirming the audit ran and produced nothing — analogue of
    /// `destroy_absent`'s "nothing to do" convergent shape. Scoped
    /// to per-tenant findings (filesystem-exposure + pf rule drift) —
    /// host-wide findings (env-leak, Touch-ID, pf-disabled) emit
    /// upstream of this summary and are NOT counted here; the
    /// wording is explicit so the operator doesn't read "no findings"
    /// as "doctor said everything is clean" when host-wide warnings
    /// are visible above.
    pub fn doctor_done_summary(&mut self, name: &str, finding_count: usize) {
        if self.dry_run {
            return;
        }
        if finding_count == 0 {
            let _ = writeln!(
                self.stdout,
                "doctor: tenant '{name}' \u{2014} no per-tenant findings."
            );
        }
    }

    /// Sub-cycle 3 noop for the bare `tenant doctor` (all-tenants)
    /// form. Sub-cycle 5 replaces this with the real enumeration.
    pub fn doctor_all_tenants_noop(&mut self) {
        let _ = writeln!(self.stdout, "doctor: no tenants to audit.");
    }

    /// Substrate-failure framing for `doctor`. Mirrors `mode_failed` /
    /// `shell_failed`: verb-level context, `ProbeError::Display`
    /// carries the spawn / non-zero detail.
    pub fn doctor_failed(&mut self, err: &ProbeError) {
        let _ = writeln!(self.stderr, "tenant: failed to probe doctor: {err}");
    }

    /// Host-config-file read failure for `doctor`. The substrate could
    /// not read a host config file (`/etc/sudoers` + drop-ins via
    /// `read_env_policy`; `/etc/pam.d/sudo` via `read_pam_sudo`).
    /// Most likely cause for sudoers: the operator's sudo session
    /// isn't cached; recovery is `sudo -v` followed by rerunning
    /// doctor. The error's `Display` carries the path / process
    /// detail; this frame adds the verb-level context. Distinct from
    /// `doctor_failed` (filesystem-probe machinery) so the operator
    /// sees which substrate tripped.
    pub fn doctor_host_file_failed(&mut self, err: &crate::executor::HostFileError) {
        let _ = writeln!(self.stderr, "tenant: failed to read host config: {err}");
    }

    /// Firewall-read failure for `doctor`. The substrate could not
    /// read pf state via `pfctl` (cycle 7 SC2's `read_kernel_pf_rules`;
    /// SC4's `read_pf_status`). Most likely cause: sudo session isn't
    /// cached (`sudo -v` recovers). Distinct from
    /// `doctor_host_file_failed` (config-file substrate) so the
    /// operator sees which machinery tripped.
    pub fn doctor_firewall_failed(&mut self, err: &FirewallError) {
        let _ = writeln!(self.stderr, "tenant: failed to read pf state: {err}");
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

    /// Failure shape for any firewall step during create (BackupConfig,
    /// InstallAnchor, UpdateConfig, Reload, Enable) AND for read/parse
    /// failures on the just-written profile (which surface as
    /// `FirewallError::Fs` with the profile path baked in). The
    /// `FirewallError::Display` impl carries enough detail (path or
    /// process exit context) that the operator doesn't need to read
    /// source; the framing here adds the verb-level context.
    pub fn create_firewall_failed(&mut self, name: &str, err: &FirewallError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to install firewall for '{name}': {err}"
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

    /// Failure shape for any firewall teardown step during destroy
    /// (BackupConfig, RemoveAnchor, UpdateConfig, Reload) AND for
    /// pf.conf read failures. Same framing rationale as
    /// `create_firewall_failed`: the verb-level context goes here, the
    /// path/process detail comes from `FirewallError::Display`.
    pub fn destroy_firewall_failed(&mut self, name: &str, err: &FirewallError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to tear down firewall for '{name}': {err}"
        );
    }

    pub fn shell_failed(&mut self, name: &str, err: &AccountError) {
        let _ = writeln!(self.stderr, "tenant: failed to shell into '{name}': {err}");
    }

    /// Cycle-4 shell-narrow profile arm — read or parse of the on-disk
    /// profile failed during the auto-narrow that runs before `login`.
    /// Distinct from `mode_profile_failed`'s wording because the
    /// operator typed `tenant shell <name>`, not `tenant mode`; the
    /// frame names the narrow as a step within the shell verb so the
    /// recovery hint ("fix the profile, retry `tenant shell`") reads
    /// in context. Path-naming convention mirrors `mode_profile_failed`.
    pub fn shell_narrow_profile_failed(&mut self, name: &str, err: &ProfileError) {
        let path = display_path_for(name);
        let _ = writeln!(
            self.stderr,
            "tenant: failed to read profile '{path}' for '{name}' before shell entry: {err}"
        );
    }

    /// Cycle-4 shell-narrow firewall arm — InstallAnchor or Reload
    /// tripped during the auto-narrow. Same parallel as
    /// `shell_narrow_profile_failed`: distinct verb framing
    /// ("before shell entry") so the operator sees the narrow as a
    /// shell-verb step, not a mode-verb invocation they didn't make.
    pub fn shell_narrow_failed(&mut self, name: &str, err: &FirewallError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to narrow firewall for '{name}' before shell entry: {err}"
        );
    }

    /// Failure shape for the `mode` verb's profile arm — read or parse
    /// of the on-disk profile failed before any firewall step ran.
    /// Parallels `destroy_profile_failed` / `create_profile_failed`'s
    /// path-naming frame.
    pub fn mode_profile_failed(&mut self, name: &str, err: &ProfileError) {
        let path = display_path_for(name);
        let _ = writeln!(
            self.stderr,
            "tenant: failed to read profile '{path}' for '{name}': {err}"
        );
    }

    /// Failure shape for the `mode` verb's firewall arm — any of the
    /// reapply ops (InstallAnchor, Reload) tripped. The Display impl
    /// on `FirewallError` carries the path or pfctl exit context;
    /// the frame here names the verb intent.
    pub fn mode_failed(&mut self, name: &str, err: &FirewallError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to apply firewall mode for '{name}': {err}"
        );
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
