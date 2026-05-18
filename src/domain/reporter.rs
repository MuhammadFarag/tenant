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
//! `Reporter` holds a reference to the active `HostMachine` so it can
//! render plan + echo lines lazily from `AccountOp` / `ProfileOp` values
//! via the `Op::describe_via` ADT method. Plan rendering walks
//! `&[(Op<'_>, Option<&'static str>)]` tuples — `Op` for domain dispatch,
//! the `Option<&'static str>` slot for per-step annotations like
//! `# on rollback`.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use super::accounts::{ConflictError, NameError, ShareError, tenant_share_group_name};
use super::{
    AccessMode, AccountError, AclError, FirewallError, GroupId, HostMachine, HostUserName, Op,
    ProbeError, TenantUserName, UserId,
};
use crate::ModeLevel;
use crate::ansi::{self, Colors};
use crate::doctor::{Category, Finding, Severity};
use crate::profile::{ProfileError, display_path_for};

/// Outcome of the pre-execution confirmation prompt. `Proceed` covers
/// all non-aborted paths (user said yes, dry-run skip, `--yes` flag,
/// non-TTY auto-proceed). `Abort` covers explicit `n`, default-N
/// (destroy), and EOF / read errors.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConfirmOutcome {
    Proceed,
    Abort,
}

pub(crate) struct Reporter<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
    verbose: bool,
    dry_run: bool,
    machine: &'a dyn HostMachine,
    colors: Colors,
}

impl<'a> Reporter<'a> {
    pub fn new(
        stdout: &'a mut dyn Write,
        stderr: &'a mut dyn Write,
        verbose: bool,
        dry_run: bool,
        machine: &'a dyn HostMachine,
        colors: Colors,
    ) -> Self {
        Self {
            stdout,
            stderr,
            verbose,
            dry_run,
            machine,
            colors,
        }
    }

    // ============================================================
    // Semantic vocabulary actually exercised by the shipped surface:
    // `ok` (substrate ✓) and `section` (─── rule ─). The wider
    // util.py-style vocabulary (`info` cyan •, `warn` yellow !,
    // `err` red ✗, `panel`) is scoped but deferred — tenant's
    // failures are almost all one-liners, so the 3+-line panel
    // heuristic rarely applies. A future surface that introduces
    // structured multi-line failure bodies reintroduces this layer.
    // ============================================================

    /// `✓ <msg>` — substrate success line (green ✓). To stdout.
    pub fn ok(&mut self, msg: &str) {
        let check = self.paint_stdout("✓", ansi::green);
        let _ = writeln!(self.stdout, "{check} {msg}");
    }

    /// `─── <title> ────...` — section divider, bold title. To stdout.
    pub fn section(&mut self, title: &str) {
        if self.colors.stdout {
            // Compose `─── ` + bold(title) + ` ` + dashes-padded-to-80
            // by hand; `ansi::rule` counts chars including escape
            // sequences when given a bolded title, which would
            // over-truncate the trailing dashes.
            let bolded = ansi::bold(title);
            let prefix = "─── ";
            let suffix = " ";
            let raw_core = prefix.chars().count() + title.chars().count() + suffix.chars().count();
            let pad = 80_usize.saturating_sub(raw_core);
            let dashes: String = "─".repeat(pad);
            let _ = writeln!(self.stdout, "{prefix}{bolded}{suffix}{dashes}");
        } else {
            let line = ansi::rule(title, 80);
            let _ = writeln!(self.stdout, "{line}");
        }
    }

    fn paint_stdout<F: FnOnce(&str) -> String>(&self, s: &str, paint: F) -> String {
        if self.colors.stdout {
            paint(s)
        } else {
            s.to_string()
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
        let line = op.describe_via(self.machine);
        let _ = writeln!(self.stdout, "$ {line}");
    }

    /// Per-step business-level progress line: `✓ <label>` after a
    /// substrate op completes successfully. Emits in real mode (both
    /// standard and verbose). Silent in dry-run — nothing actually
    /// happened. Label comes from `Op::business_label`, the
    /// substrate-agnostic past-tense capability summary.
    pub fn progress(&mut self, op: Op<'_>) {
        if self.dry_run {
            return;
        }
        let label = op.business_label();
        self.ok(&label);
    }

    // ============================================================
    // Pre-execution confirmation
    // ============================================================

    /// Pre-execution confirmation. Emits `Proceed? [Y/n]` (or `[y/N]`
    /// when `default_yes=false`), reads a line from `stdin`, parses,
    /// and returns the outcome. Skip-conditions (auto-Proceed without
    /// prompting):
    ///
    /// - dry-run mode (confirm would be a lie — nothing happens)
    /// - `yes_flag` true (operator passed `--yes`)
    /// - stdin not a TTY (scripted caller)
    ///
    /// Re-prompts on unrecognized input.
    pub fn confirm(
        &mut self,
        default_yes: bool,
        stdin: &mut dyn BufRead,
        stdin_is_tty: bool,
        yes_flag: bool,
    ) -> ConfirmOutcome {
        if self.dry_run {
            // Emit a parenthetical preview so the operator sees what
            // the real run would have asked.
            let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
            let _ = writeln!(self.stdout, "(Real run would prompt: Proceed? {hint})");
            return ConfirmOutcome::Proceed;
        }
        if yes_flag {
            return ConfirmOutcome::Proceed;
        }
        if !stdin_is_tty {
            return ConfirmOutcome::Proceed;
        }
        let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
        loop {
            let _ = write!(self.stdout, "Proceed? {hint} ");
            let _ = self.stdout.flush();
            let mut line = String::new();
            match stdin.read_line(&mut line) {
                Ok(0) => return ConfirmOutcome::Abort, // EOF
                Ok(_) => {}
                Err(_) => return ConfirmOutcome::Abort,
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return if default_yes {
                    ConfirmOutcome::Proceed
                } else {
                    ConfirmOutcome::Abort
                };
            }
            match trimmed.to_ascii_lowercase().as_str() {
                "y" | "yes" => return ConfirmOutcome::Proceed,
                "n" | "no" => return ConfirmOutcome::Abort,
                _ => {
                    let _ = writeln!(self.stdout, "Please answer y or n.");
                }
            }
        }
    }

    /// "Aborted by operator. No changes made." — emits when the
    /// operator answered `n` (or default-N for destroy) to a confirm
    /// prompt. The verb returned without invoking any substrate.
    pub fn aborted(&mut self) {
        let _ = writeln!(self.stdout, "Aborted by operator. No changes made.");
    }

    // ============================================================
    // Per-verb pre-execution business summaries
    // ============================================================

    /// Pre-execution summary for `create`. Emits the headline +
    /// capability bullets + (verbose, when `plan` is Some) plan block +
    /// sudo-needed-for line. Caller follows with `confirm(true, …)` for
    /// real mode; dry-run's confirm emits the preview parenthetical.
    /// The verbose plan block lives in the summary so the operator
    /// sees the literal commands BEFORE the prompt.
    pub fn create_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        uid: UserId,
        gid: GroupId,
        plan: Option<&[(Op<'_>, Option<&'static str>)]>,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.stdout,
            "About to create tenant '{name}' \u{2014} an isolated macOS account with restricted network egress."
        );
        let _ = writeln!(self.stdout);
        let _ = writeln!(self.stdout, "This will:");
        let _ = writeln!(
            self.stdout,
            "  \u{2022} create user account '{name}' (UID {uid}) and group '{group}' (GID {gid})"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} add host '{host}' to '{group}' so files the tenant creates in RW shares stay host-writable"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} install a per-tenant firewall anchor (egress blocked by default; allowlist hosts declared in the profile)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} write profile config at {}",
            display_path_for(name.as_str())
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} enable pf host-wide if not already enabled"
        );
        let _ = writeln!(self.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(
            self.stdout,
            "Sudo needed for: user provisioning, firewall install."
        );
        let _ = writeln!(self.stdout);
    }

    /// Pre-execution summary for `destroy`. Includes the irreversibility
    /// framing on the home-directory move (recoverable until Deleted
    /// Users is emptied). Caller follows with `confirm(false, …)` —
    /// destroy defaults to N so muscle-memory ENTER never deletes.
    pub fn destroy_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        uid: UserId,
        plan: Option<&[(Op<'_>, Option<&'static str>)]>,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(self.stdout, "About to destroy tenant '{name}' (UID {uid}).");
        let _ = writeln!(self.stdout);
        let _ = writeln!(self.stdout, "This will:");
        let _ = writeln!(self.stdout, "  \u{2022} remove the user account");
        let _ = writeln!(
            self.stdout,
            "  \u{2022} move /Users/{name} \u{2192} /Users/Deleted Users/{name} (recoverable until /Users/Deleted Users is emptied or the host is rebuilt)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} remove host '{host}' from '{group}'"
        );
        let _ = writeln!(self.stdout, "  \u{2022} remove group '{group}'");
        let _ = writeln!(
            self.stdout,
            "  \u{2022} remove the firewall anchor and flush its kernel rules"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} remove profile config at {}",
            display_path_for(name.as_str())
        );
        let _ = writeln!(self.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(
            self.stdout,
            "Sudo needed for: user removal, firewall teardown."
        );
        let _ = writeln!(self.stdout);
    }

    /// Pre-execution summary for the orphan-group convergence path of
    /// `destroy`. No user present, but the suffixed group + any
    /// firewall + profile residue remain. Same default-N posture as
    /// the full destroy summary.
    pub fn destroy_orphan_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        plan: Option<&[(Op<'_>, Option<&'static str>)]>,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.stdout,
            "About to destroy orphan group '{group}' for tenant '{name}'."
        );
        let _ = writeln!(self.stdout);
        let _ = writeln!(self.stdout, "This will:");
        let _ = writeln!(
            self.stdout,
            "  \u{2022} remove host '{host}' from '{group}' (idempotent if not a member)"
        );
        let _ = writeln!(self.stdout, "  \u{2022} remove group '{group}'");
        let _ = writeln!(
            self.stdout,
            "  \u{2022} remove the firewall anchor and flush its kernel rules"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} remove profile config at {}",
            display_path_for(name.as_str())
        );
        let _ = writeln!(self.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(
            self.stdout,
            "Sudo needed for: group removal, firewall teardown."
        );
        let _ = writeln!(self.stdout);
    }

    /// Pre-execution summary for `mode`. Same shape as create/destroy
    /// — headline + bullets + sudo. Names the tier the operator chose.
    pub fn mode_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        level: ModeLevel,
        plan: Option<&[(Op<'_>, Option<&'static str>)]>,
    ) {
        let level_str = level.as_str();
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.stdout,
            "About to apply mode '{level_str}' to tenant '{name}'."
        );
        let _ = writeln!(self.stdout);
        let _ = writeln!(self.stdout, "This will:");
        if matches!(level, ModeLevel::Install) {
            let _ = writeln!(
                self.stdout,
                "  \u{2022} re-render the firewall anchor with install-tier hosts added to the allowlist"
            );
        } else {
            let _ = writeln!(
                self.stdout,
                "  \u{2022} re-render the firewall anchor at runtime tier"
            );
        }
        let _ = writeln!(self.stdout, "  \u{2022} reload pf");
        let _ = writeln!(
            self.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} re-apply declared shares from the profile (idempotent)"
        );
        if matches!(level, ModeLevel::Install) {
            let _ = writeln!(self.stdout);
            let _ = writeln!(
                self.stdout,
                "The widened allowlist persists until 'tenant mode {name} runtime' (narrow) or 'tenant shell {name}' (auto-narrow on entry)."
            );
        }
        let _ = writeln!(self.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(self.stdout, "Sudo needed for: firewall install.");
        let _ = writeln!(self.stdout);
    }

    /// Pre-execution summary for single-tenant `reload <name>`.
    pub fn reload_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        plan: Option<&[(Op<'_>, Option<&'static str>)]>,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(self.stdout, "About to reload tenant '{name}' from profile.");
        let _ = writeln!(self.stdout);
        let _ = writeln!(self.stdout, "This will:");
        let _ = writeln!(
            self.stdout,
            "  \u{2022} re-render and reload the firewall anchor (runtime tier)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} re-apply each declared share from [[shares]] in the profile"
        );
        let _ = writeln!(self.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(self.stdout, "Sudo needed for: firewall install.");
        let _ = writeln!(self.stdout);
    }

    /// Pre-execution summary for `shell`. Unlike the other mutating
    /// verbs, shell has no confirm prompt — interactive entry; the
    /// operator becomes the shell after `login` returns. The summary
    /// exists so the pre-exec doctor audit (cycle-16) has visual
    /// context above it (otherwise the operator sees a bare warning
    /// line before the section divider and `$ sudo -iu` echo). Ends
    /// with a blank line; no `(Real run would prompt: …)` parenthetical
    /// because no prompt fires. Same gating as the other summaries —
    /// only emits when `show_summary` (TTY OR dry-run) is true in
    /// dispatch.
    pub fn shell_summary(&mut self, name: &TenantUserName, host: &HostUserName) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(self.stdout, "About to enter tenant '{name}'.");
        let _ = writeln!(self.stdout);
        let _ = writeln!(self.stdout, "This will:");
        let _ = writeln!(
            self.stdout,
            "  \u{2022} narrow the firewall to runtime tier (auto-narrow)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} re-apply each declared share from [[shares]] in the profile"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} launch an interactive login shell as '{name}'"
        );
        let _ = writeln!(self.stdout);
        let _ = writeln!(
            self.stdout,
            "Sudo needed for: firewall narrow, share reapply, login."
        );
        let _ = writeln!(self.stdout);
    }

    /// Pre-execution summary for no-arg `tenant reload` (walks all
    /// tenants). Names the count + comma-separated list so the operator
    /// can confirm the scope before any substrate fires.
    pub fn reload_all_summary(&mut self, host: &HostUserName, names: &[TenantUserName]) {
        let count = names.len();
        let list = names
            .iter()
            .map(|n| n.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            self.stdout,
            "About to reload {count} tenant(s) from their profiles: {list}."
        );
        let _ = writeln!(self.stdout);
        let _ = writeln!(self.stdout, "For each tenant this will:");
        let _ = writeln!(
            self.stdout,
            "  \u{2022} re-render and reload the firewall anchor (runtime tier)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} ensure host '{host}' is a member of the tenant's share group (idempotent catch-up)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} re-apply declared shares from [[shares]] in the profile"
        );
        let _ = writeln!(self.stdout);
        let _ = writeln!(
            self.stdout,
            "Per-tenant failures continue the walk; a final summary names any failed tenants."
        );
        let _ = writeln!(self.stdout);
        let _ = writeln!(
            self.stdout,
            "Sudo needed for: firewall install (per tenant)."
        );
        let _ = writeln!(self.stdout);
    }

    // ============================================================
    // Create verb
    // ============================================================

    /// Pre-exec disclosure for `create`. Real mode emits a
    /// `─── Creating tenant 'X' ───` section divider — operator-visible
    /// "the verb is now running". Dry-run skips the divider; the
    /// pre-exec `create_summary` already framed the verb.
    pub fn create_starting(&mut self, name: &TenantUserName) {
        if !self.dry_run {
            self.section(&format!("Creating tenant '{name}'"));
        }
    }

    /// Post-exec confirmation for `create`. Silent in dry-run (would be
    /// a lie). Real mode: emits a `─── Done ───` closing section, then
    /// a single enriched line naming UID, GID, and the anchor name —
    /// the pre-exec summary already structured the facts; the closing
    /// line confirms completion without duplicating bullets.
    pub fn create_done(&mut self, name: &TenantUserName, uid: UserId, gid: GroupId) {
        if self.dry_run {
            return;
        }
        let anchor = crate::firewall::tenant_anchor_name(name.as_str());
        self.section("Done");
        let _ = writeln!(
            self.stdout,
            "Tenant '{name}' ready (UID {uid}, GID {gid}, anchor '{anchor}')."
        );
    }

    // ============================================================
    // Destroy verb (full path)
    // ============================================================

    /// Pre-exec disclosure for `destroy`. Real mode emits the
    /// `─── Destroying tenant 'X' ───` section divider. Dry-run skips
    /// the divider; the pre-exec `destroy_summary` already framed
    /// the verb.
    pub fn destroy_starting(&mut self, name: &TenantUserName) {
        if !self.dry_run {
            self.section(&format!("Destroying tenant '{name}'"));
        }
    }

    /// Post-exec confirmation for `destroy`. Silent in dry-run. Real
    /// mode: `─── Done ───` closing section + one terminal line.
    pub fn destroy_done(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        self.section("Done");
        let _ = writeln!(self.stdout, "Tenant '{name}' destroyed.");
    }

    // ============================================================
    // Destroy verb (orphan-group convergence path)
    // ============================================================

    /// Pre-exec disclosure for the orphan-group convergence path.
    /// Real mode emits the section divider; dry-run is silent
    /// (`destroy_orphan_summary` covers the framing).
    pub fn orphan_group_starting(&mut self, name: &TenantUserName) {
        if !self.dry_run {
            let group = tenant_share_group_name(name.as_str());
            self.section(&format!(
                "Destroying orphan group '{group}' for tenant '{name}'"
            ));
        }
    }

    /// Post-exec confirmation for the orphan-group convergence path.
    pub fn orphan_group_done(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        let group = tenant_share_group_name(name.as_str());
        self.section("Done");
        let _ = writeln!(
            self.stdout,
            "Orphan group '{group}' for tenant '{name}' destroyed."
        );
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
    /// Emit just the shell intent line (no plan). Called BEFORE the
    /// reapply plan is built so the operator sees the verb context
    /// even if the pre-flight profile read fails — intent is emitted
    /// before any narrow. The plan-render half lives in `shell_plan`,
    /// called after the plan is built.
    pub fn shell_intent(&mut self, name: &TenantUserName) {
        if self.dry_run {
            let _ = writeln!(self.stdout, "Would shell into '{name}'.");
        } else {
            self.section(&format!("Entering tenant '{name}'"));
        }
    }

    /// Render the shell verb's plan block in real+verbose mode.
    /// Called after `shell_intent` and after the plan has been built
    /// from the profile + share entries. Shell has no pre-exec
    /// confirmation (the operator becomes the shell after `login`
    /// returns), so the plan stays here rather than moving into a
    /// summary — only prompt-having verbs relocate plan emission
    /// into their summary. Layout matches the intent-leads-shell-
    /// follows rendering used by the prompt-having verbs' summaries.
    pub fn shell_plan(&mut self, plan: &[(Op<'_>, Option<&'static str>)]) {
        if self.verbose {
            let _ = writeln!(self.stdout, "Plan (commands to execute):");
            let _ = writeln!(self.stdout);
            self.render_plan_block(plan);
            let _ = writeln!(self.stdout);
        }
    }

    /// Command-form shell intent — section divider naming the tier in
    /// real mode, dry-run preamble line in dry-run. Emitted BEFORE the
    /// reapply plan is built so verb context survives a profile-read
    /// failure (mirrors `shell_intent` for the interactive form). Real
    /// shape and bytes finalize in SC3; this stub keeps the compile
    /// quiet during SC2 wiring.
    pub fn shell_command_intent(&mut self, name: &TenantUserName, mode: ModeLevel) {
        if self.dry_run {
            let _ = writeln!(
                self.stdout,
                "Would run command as tenant '{name}' ({} tier).",
                mode.as_str()
            );
        } else if mode == ModeLevel::Runtime {
            self.section(&format!("Running command as tenant '{name}'"));
        } else {
            self.section(&format!(
                "Running command as tenant '{name}' ({} tier)",
                mode.as_str()
            ));
        }
    }

    /// Pre-execution summary for the command form. Real shape finalizes
    /// in SC3; this stub keeps the SC2 compile clean. Same `show_summary`
    /// gating as the interactive form's `shell_summary`.
    pub fn shell_command_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        mode: ModeLevel,
        argv: &[String],
    ) {
        let group = tenant_share_group_name(name.as_str());
        let joined = argv.join(" ");
        if mode == ModeLevel::Runtime {
            let _ = writeln!(self.stdout, "About to run a command as tenant '{name}'.");
        } else {
            let _ = writeln!(
                self.stdout,
                "About to run a command as tenant '{name}' (mode: {}).",
                mode.as_str()
            );
        }
        let _ = writeln!(self.stdout);
        let _ = writeln!(self.stdout, "This will:");
        if mode == ModeLevel::Runtime {
            let _ = writeln!(
                self.stdout,
                "  \u{2022} ensure the firewall is at runtime tier (auto-narrow; idempotent if already there)"
            );
        } else {
            let _ = writeln!(
                self.stdout,
                "  \u{2022} widen the firewall to install tier (narrows back to runtime on completion)"
            );
        }
        let _ = writeln!(
            self.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.stdout,
            "  \u{2022} re-apply each declared share from [[shares]] in the profile"
        );
        let _ = writeln!(self.stdout, "  \u{2022} run as '{name}': {joined}");
        if mode != ModeLevel::Runtime {
            let _ = writeln!(
                self.stdout,
                "  \u{2022} narrow the firewall to runtime tier (always — even if the command fails)"
            );
        }
        let _ = writeln!(self.stdout);
        if mode == ModeLevel::Runtime {
            let _ = writeln!(
                self.stdout,
                "Sudo needed for: firewall install, share reapply, exec."
            );
        } else {
            let _ = writeln!(
                self.stdout,
                "Sudo needed for: firewall install, share reapply, exec, firewall narrow."
            );
        }
        let _ = writeln!(self.stdout);
    }

    /// Yellow `⚠` stderr one-liner when narrow-on-finally failed after
    /// a child-ran case (command form only). Cycle 18 retrofits to a
    /// multi-line panel; cycle 17 ships the one-liner stub. Visual
    /// vocabulary follows cycle-16's `doctor_summary_pending`. Does NOT
    /// override the child's exit code — dispatcher returns the child's
    /// exit alongside this stderr signal.
    pub fn shell_narrow_failed(
        &mut self,
        name: &TenantUserName,
        _err: &super::accounts::ModeError,
    ) {
        let prefix = if self.colors.stderr {
            "\x1b[33m\u{26a0}\x1b[0m"
        } else {
            "\u{26a0}"
        };
        let _ = writeln!(
            self.stderr,
            "{prefix} tenant '{name}': firewall not narrowed after command — install-tier widening still in effect; run `tenant mode {name} runtime` to recover"
        );
    }

    /// Closing surface for the command form: `─── Done ───` separator
    /// followed by `Command exited with code N.` (runtime mode) or
    /// `Command exited with code N (firewall narrowed back to runtime
    /// tier).` (install mode). The narrow-back parenthetical fires
    /// only when the entry widened, as a narrative cue that on-disk
    /// state returned to runtime tier. Matches the prime's Flow 1
    /// (runtime, bare) and Flow 2/3 (install, suffixed) shapes.
    ///
    /// Real-mode only — dry-run skips the closing. The operator-facing
    /// signal that the verb finished is load-bearing for the install
    /// case especially (otherwise the operator only sees ✓ lines and
    /// has no confirmation the narrow-on-finally succeeded).
    pub fn shell_command_done(&mut self, child_exit: i32, mode: ModeLevel) {
        if self.dry_run {
            return;
        }
        self.section("Done");
        if mode == ModeLevel::Install {
            let _ = writeln!(
                self.stdout,
                "Command exited with code {child_exit} (firewall narrowed back to runtime tier)."
            );
        } else {
            let _ = writeln!(self.stdout, "Command exited with code {child_exit}.");
        }
    }

    // ============================================================
    // Mode verb
    // ============================================================

    /// Emit the mode intent line (section divider; real mode only).
    /// The verbose plan lives in `mode_summary` (rendered before the
    /// prompt), so this method doesn't render plan.
    pub fn mode_intent(&mut self, name: &TenantUserName, level: ModeLevel) {
        if !self.dry_run {
            let level_str = level.as_str();
            self.section(&format!("Applying mode '{level_str}' to tenant '{name}'"));
        }
    }

    /// Post-exec confirmation for `mode`. Silent in dry-run. Real mode:
    /// `─── Done ───` closing section + one terminal line naming the
    /// tier.
    pub fn mode_done(&mut self, name: &TenantUserName, level: ModeLevel) {
        if self.dry_run {
            return;
        }
        let level_str = level.as_str();
        self.section("Done");
        let _ = writeln!(self.stdout, "Tenant '{name}' is at {level_str} tier.");
    }

    // ============================================================
    // Convergent noop (destroy on absent tenant)
    // ============================================================

    /// Convergent-noop message: the named tenant doesn't exist; destroy
    /// is a successful no-op. Tense-neutral, emits in both real and
    /// dry-run modes (the verb is idempotent so "would" / "did" is the
    /// same answer).
    pub fn destroy_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.stdout,
            "tenant '{name}' does not exist; nothing to do."
        );
    }

    // ============================================================
    // Refusals (stderr, EX_USAGE)
    // ============================================================

    pub fn refuse_invalid_name(&mut self, name: &TenantUserName, err: &NameError) {
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

    pub fn refuse_name_conflict(&mut self, name: &TenantUserName, err: &ConflictError) {
        let group = tenant_share_group_name(name.as_str());
        let msg = match err {
            ConflictError::UserExists => format!("tenant: user '{name}' already exists"),
            ConflictError::GroupExists => format!("tenant: group '{group}' already exists"),
            ConflictError::Both => {
                format!("tenant: user '{name}' and group '{group}' already exist")
            }
        };
        let _ = writeln!(self.stderr, "{msg}");
    }

    pub fn refuse_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to destroy '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to destroy '{name}': system account (no tenant-range UID)"
        );
    }

    pub fn refuse_shell_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.stderr,
            "tenant: cannot shell into '{name}': does not exist"
        );
    }

    pub fn refuse_shell_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to shell into '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_shell_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to shell into '{name}': system account (no tenant-range UID)"
        );
    }

    /// Mode-side absent refusal. Like `refuse_shell_absent`, this
    /// collapses `Eligibility::NotPresent` and `Eligibility::OrphanGroup`
    /// — the operator wants to switch a tenant's mode; a lingering
    /// `<name>-tenant-share` group doesn't host one.
    pub fn refuse_mode_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.stderr,
            "tenant: cannot apply mode to '{name}': does not exist"
        );
    }

    pub fn refuse_mode_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to apply mode to '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_mode_system_account(&mut self, name: &TenantUserName) {
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
    pub fn refuse_doctor_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.stderr,
            "tenant: cannot run doctor on '{name}': does not exist"
        );
    }

    pub fn refuse_doctor_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to run doctor on '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_doctor_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to run doctor on '{name}': system account (no tenant-range UID)"
        );
    }

    // ============================================================
    // Doctor verb
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
    pub fn doctor_starting(
        &mut self,
        name: &TenantUserName,
        curated: &[(Category, AccessMode, PathBuf)],
    ) {
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
    /// In verbose mode, each finding's one-liner is followed by the
    /// structured-guidance block from `Finding::guidance()`, indented
    /// 2 spaces under the finding line. `FilesystemExposure` returns
    /// `None` for guidance and renders the one-liner alone even in
    /// verbose mode — per-path-category guidance belongs to the future
    /// remediation surface, not the detection surface.
    pub fn doctor_finding(&mut self, finding: &Finding) {
        self.doctor_finding_one_liner(finding);
        if self.verbose
            && let Some(guidance) = finding.guidance()
        {
            for line in guidance.lines() {
                if line.is_empty() {
                    let _ = writeln!(self.stdout);
                } else {
                    let styled = self.style_guidance_line(line);
                    let _ = writeln!(self.stdout, "  {styled}");
                }
            }
        }
    }

    /// Emit just the colored one-liner — the guidance body is skipped
    /// regardless of verbose. Used by cycle-16 `pre_exec_doctor_summary`
    /// for inline critical findings on mutating verbs: the operator
    /// sees the danger, but the full multi-paragraph body lives behind
    /// `tenant doctor -v` (Q4 lock — verb output is about what the
    /// verb is doing; the audit's full guidance is doctor's job).
    pub fn doctor_finding_one_liner(&mut self, finding: &Finding) {
        let rendered = self.color_finding_prefix(finding);
        let _ = writeln!(self.stdout, "{rendered}");
    }

    /// Severity coloring on the finding's leading prefix. Critical →
    /// red+bold; warning → yellow; info → dim. Color-off fallthrough
    /// preserves the plain byte-form contract for tests.
    fn color_finding_prefix(&self, finding: &Finding) -> String {
        let text = finding.to_string();
        if !self.colors.stdout {
            return text;
        }
        match finding.severity() {
            Severity::Critical => {
                if let Some(rest) = text.strip_prefix("critical:") {
                    return format!("{}{rest}", ansi::red(&ansi::bold("critical:")));
                }
            }
            Severity::Warning => {
                if let Some(rest) = text.strip_prefix("warning:") {
                    return format!("{}{rest}", ansi::yellow("warning:"));
                }
            }
            Severity::Info => {
                if let Some(rest) = text.strip_prefix("info:") {
                    return format!("{}{rest}", ansi::dim("info:"));
                }
            }
        }
        text
    }

    /// Guidance-line styling for `doctor --verbose`. Headers (no
    /// leading whitespace in the original guidance text) get bold;
    /// body lines (indented) get dim. Visual subordination keeps the
    /// finding one-liner the scannable focus and the body as context.
    fn style_guidance_line(&self, line: &str) -> String {
        if !self.colors.stdout {
            return line.to_string();
        }
        if line.starts_with(' ') {
            ansi::dim(line)
        } else {
            ansi::bold(line)
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
    pub fn doctor_done_summary(&mut self, name: &TenantUserName, finding_count: usize) {
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

    /// Noop frame for the bare `tenant doctor` (all-tenants) form
    /// when no tenants exist on the host.
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
    pub fn doctor_host_file_failed(&mut self, err: &super::HostFileError) {
        let _ = writeln!(self.stderr, "tenant: failed to read host config: {err}");
    }

    /// Firewall-read failure for `doctor`. The substrate could not
    /// read pf state via `pfctl` (`read_kernel_pf_rules` /
    /// `read_pf_status`). Most likely cause: sudo session isn't
    /// cached (`sudo -v` recovers). Distinct from
    /// `doctor_host_file_failed` (config-file substrate) so the
    /// operator sees which machinery tripped.
    pub fn doctor_firewall_failed(&mut self, err: &FirewallError) {
        let _ = writeln!(self.stderr, "tenant: failed to read pf state: {err}");
    }

    /// Aggregate hint line for non-critical findings the mutating-verb
    /// inline pre-exec audit collected. Emits one yellow ⚠ line naming
    /// the count + the `tenant doctor` command the operator can run for
    /// detail. `target` is `Some(name)` for per-tenant verbs (shell /
    /// mode / reload) and `None` for the create flow (no tenant yet).
    /// Singular/plural agreement on the count. Skipped entirely when
    /// `count == 0` so a healthy host stays silent. Output goes to
    /// stdout next to the critical inline lines, not stderr — these
    /// are advisory, not failures.
    pub fn doctor_summary_pending(&mut self, count: usize, target: Option<&TenantUserName>) {
        if count == 0 {
            return;
        }
        let noun = if count == 1 { "warning" } else { "warnings" };
        let (scope, command) = match target {
            Some(name) => (
                format!(" for tenant '{name}'"),
                format!("tenant doctor {name}"),
            ),
            None => (String::new(), "tenant doctor".to_string()),
        };
        let line =
            format!("\u{26a0} Doctor: {count} {noun}{scope} \u{2014} run `{command}` for details");
        let painted = self.paint_stdout(&line, ansi::yellow);
        let _ = writeln!(self.stdout, "{painted}");
    }

    // ============================================================
    // Failures (stderr, EX_IOERR)
    // ============================================================

    pub fn create_group_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.stderr,
            "tenant: failed to create group '{group}' for '{name}': {err}"
        );
    }

    /// `AddHostToShareGroup` failed after `CreateShareGroup` succeeded
    /// but before `CreateTenantUser` ran. Host now carries an orphan
    /// share group with no host membership. Recovery is `tenant
    /// destroy <name>` (orphan-group convergence path is idempotent
    /// at the substrate; the next destroy converges).
    pub fn create_host_membership_failed(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        err: &AccountError,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.stderr,
            "tenant: failed to add host '{host}' to group '{group}': {err} \
             \u{2014} host now has an orphan group; next 'tenant destroy {name}' will converge"
        );
    }

    pub fn create_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(self.stderr, "tenant: failed to create '{name}': {err}");
    }

    /// Em-dash-suffixed recovery hint. Emitted as a SECOND stderr line
    /// after `create_failed` when the rollback itself failed. The
    /// trailing clause points the operator at `tenant destroy` for
    /// convergence (the OrphanGroup eligibility arm).
    pub fn create_rollback_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.stderr,
            "tenant: rollback of group '{group}' also failed: {err} \
             \u{2014} host now has an orphan group; next 'tenant destroy {name}' will converge"
        );
    }

    pub fn create_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
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
    pub fn create_firewall_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to install firewall for '{name}': {err}"
        );
    }

    pub fn destroy_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(self.stderr, "tenant: failed to destroy '{name}': {err}");
    }

    pub fn destroy_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
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
    pub fn destroy_firewall_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to tear down firewall for '{name}': {err}"
        );
    }

    pub fn shell_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(self.stderr, "tenant: failed to shell into '{name}': {err}");
    }

    /// Shell-narrow profile arm — read or parse of the on-disk
    /// profile failed during the auto-narrow that runs before `login`.
    /// Distinct from `mode_profile_failed`'s wording because the
    /// operator typed `tenant shell <name>`, not `tenant mode`; the
    /// frame names the narrow as a step within the shell verb so the
    /// recovery hint ("fix the profile, retry `tenant shell`") reads
    /// in context. Path-naming convention mirrors `mode_profile_failed`.
    pub fn shell_narrow_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
        let _ = writeln!(
            self.stderr,
            "tenant: failed to read profile '{path}' for '{name}' before shell entry: {err}"
        );
    }

    /// Shell-narrow firewall arm — InstallAnchor or Reload tripped
    /// during the auto-narrow. Same parallel as
    /// `shell_narrow_profile_failed`: distinct verb framing
    /// ("before shell entry") so the operator sees the narrow as a
    /// shell-verb step, not a mode-verb invocation they didn't make.
    pub fn shell_narrow_firewall_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to narrow firewall for '{name}' before shell entry: {err}"
        );
    }

    /// Failure shape for the `mode` verb's profile arm — read or parse
    /// of the on-disk profile failed before any firewall step ran.
    /// Parallels `destroy_profile_failed` / `create_profile_failed`'s
    /// path-naming frame.
    pub fn mode_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
        let _ = writeln!(
            self.stderr,
            "tenant: failed to read profile '{path}' for '{name}': {err}"
        );
    }

    /// Failure shape for the `mode` verb's firewall arm — any of the
    /// reapply ops (InstallAnchor, Reload) tripped. The Display impl
    /// on `FirewallError` carries the path or pfctl exit context;
    /// the frame here names the verb intent.
    pub fn mode_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to apply firewall mode for '{name}': {err}"
        );
    }

    // ============================================================
    // Share-reapply failure framing
    // ============================================================
    //
    // The share substrate fires from `mode` / `shell` / `reload` /
    // `create`'s post-provision step. Each verb gets its own context
    // phrase ("while applying mode", "before shell entry", "during
    // reload", "after provisioning") so the operator's recovery
    // guidance reads in context. Per-arm Reporter methods rather than
    // a single switch — mirrors the existing destroy_*_failed
    // pattern; the dispatch helper in commands.rs picks the right one.

    /// `mode` verb — ACL grant/revoke substrate failed (chmod +a/-a).
    pub fn mode_acl_failed(&mut self, name: &TenantUserName, err: &AclError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to apply ACL for '{name}': {err}"
        );
    }

    /// `mode` verb — tenant-side filesystem state failed (sudo-u
    /// mkdir/ln). Frame names tenant-side state so the operator
    /// distinguishes from the host-side ACL substrate.
    pub fn mode_account_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to install tenant-side filesystem state for '{name}': {err}"
        );
    }

    /// `mode` verb — tenant_path_kind probe machinery failed (sudo
    /// auth cache miss, fork). Operator's recovery is `sudo -v` to
    /// refresh the cache, then retry.
    pub fn mode_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to probe tenant filesystem state for '{name}': {err}"
        );
    }

    /// `mode` verb — pre-flight share refusal (HostPathMissing /
    /// TenantPathOccupied). `refuse_*` framing because the operator
    /// authored the conflict; the substrate never ran. ShareError's
    /// Display surfaces the specific case.
    pub fn refuse_mode_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(self.stderr, "tenant: cannot apply mode for '{name}': {err}");
    }

    /// `shell` verb — ACL grant substrate failed during auto-reapply.
    pub fn shell_narrow_acl_failed(&mut self, name: &TenantUserName, err: &AclError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to apply ACL for '{name}' before shell entry: {err}"
        );
    }

    /// `shell` verb — sudo-u mkdir/ln substrate failed during
    /// auto-reapply.
    pub fn shell_narrow_account_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to install tenant-side filesystem state for '{name}' before shell entry: {err}"
        );
    }

    /// `shell` verb — tenant_path_kind probe failed during
    /// auto-reapply.
    pub fn shell_narrow_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to probe tenant filesystem state for '{name}' before shell entry: {err}"
        );
    }

    /// `shell` verb — pre-flight share refusal during auto-reapply.
    pub fn refuse_shell_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(
            self.stderr,
            "tenant: cannot enter shell for '{name}': {err}"
        );
    }

    // ----- create verb's post-provision arms -----
    //
    // Production: default profile has no `[[shares]]` so these never
    // fire. Tests using `with_create_profile_content` with shares
    // exercise them. Framing emphasizes "tenant was provisioned, but
    // the post-provision share step failed" so the operator knows the
    // user/group/profile/PF are already in place — recovery is
    // `tenant reload <name>` (idempotent retry) rather than `tenant
    // create` again (which would refuse on name-conflict).

    /// `create` verb — ACL substrate failed during post-provision.
    pub fn create_post_provision_acl_failed(&mut self, name: &TenantUserName, err: &AclError) {
        let _ = writeln!(
            self.stderr,
            "tenant: '{name}' provisioned but ACL reapply failed: {err}; \
             recover with `tenant reload {name}`"
        );
    }

    /// `create` verb — sudo-u mkdir/ln substrate failed during
    /// post-provision.
    pub fn create_post_provision_account_failed(
        &mut self,
        name: &TenantUserName,
        err: &AccountError,
    ) {
        let _ = writeln!(
            self.stderr,
            "tenant: '{name}' provisioned but tenant-side filesystem state failed: {err}; \
             recover with `tenant reload {name}`"
        );
    }

    /// `create` verb — tenant_path_kind probe failed during
    /// post-provision.
    pub fn create_post_provision_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.stderr,
            "tenant: '{name}' provisioned but tenant-path probe failed: {err}; \
             recover with `tenant reload {name}`"
        );
    }

    /// `create` verb — pre-flight share refusal during post-provision.
    pub fn refuse_create_post_provision_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(
            self.stderr,
            "tenant: '{name}' provisioned but share entry is invalid: {err}; \
             edit the profile and rerun `tenant reload {name}`"
        );
    }

    // ============================================================
    // Reload verb
    // ============================================================
    //
    // The operator-facing "I edited the profile, apply it" verb.
    // Per-tenant: emit intent + plan + per-share echo + done.
    // No-arg form: emit all-starting + per-tenant inline failure
    // framing + all-done-summary. The single-tenant arms are
    // identical to the mode-verb arms in shape; the firewall + share
    // arms get reload-specific wording where "mode" would mislead.

    /// Emit the reload intent line (section divider; real mode only).
    /// The verbose plan lives in `reload_summary` (rendered before
    /// the prompt), so this method doesn't render plan.
    pub fn reload_intent(&mut self, name: &TenantUserName) {
        if !self.dry_run {
            self.section(&format!("Reloading tenant '{name}'"));
        }
    }

    /// Post-exec confirmation for `reload <name>`. Silent in dry-run.
    pub fn reload_done(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        self.section("Done");
        let _ = writeln!(self.stdout, "Tenant '{name}' reloaded.");
    }

    /// Pre-exec disclosure for the no-arg `tenant reload` walk.
    /// Names the walk scope so the operator's output framing matches
    /// what they typed. Silent when `count == 0` (no tenants on the
    /// host); the `reload_all_done_summary` arm covers that case too.
    pub fn reload_all_starting(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        if !self.dry_run {
            self.section(&format!("Reloading {count} tenant(s)"));
        }
    }

    /// End-of-walk summary for `tenant reload` no-arg form. Emits a
    /// single line so an operator scanning the tail of the output sees
    /// the aggregate result. The no-tenant case ("nothing on this
    /// host to reload") emits a distinct line so the operator gets
    /// feedback instead of empty output.
    pub fn reload_all_done_summary(&mut self, succeeded: usize, failed: usize) {
        if self.dry_run {
            return;
        }
        if succeeded == 0 && failed == 0 {
            let _ = writeln!(self.stdout, "No tenants on this host to reload.");
            return;
        }
        let total = succeeded + failed;
        let line = if failed == 0 {
            format!("Reloaded {total} tenant(s).")
        } else {
            format!("Reloaded {succeeded} of {total} tenant(s); {failed} failed.")
        };
        self.section("Done");
        let _ = writeln!(self.stdout, "{line}");
    }

    /// `reload` verb — profile read/parse failure. Same path-naming
    /// frame as the other *_profile_failed methods.
    pub fn reload_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
        let _ = writeln!(
            self.stderr,
            "tenant: failed to read profile '{path}' for '{name}': {err}"
        );
    }

    /// `reload` verb — InstallAnchor or Reload pfctl failure.
    /// Distinct from `mode_failed` which has "firewall mode" wording
    /// implying a tier-swap — reload doesn't swap tiers.
    pub fn reload_firewall_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.stderr,
            "tenant: failed to reload firewall for '{name}': {err}"
        );
    }

    /// `reload` verb — pre-flight share refusal. Distinct from
    /// `refuse_mode_share` whose wording mentions "mode".
    pub fn refuse_reload_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(self.stderr, "tenant: cannot reload '{name}': {err}");
    }

    /// Eligibility-refusal framing for `reload <name>` (mirrors the
    /// mode / shell / doctor patterns). NotPresent / OrphanGroup
    /// collapse to "does not exist" — a lingering group with no user
    /// can't have its profile reapplied.
    pub fn refuse_reload_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.stderr,
            "tenant: cannot reload '{name}': does not exist"
        );
    }

    /// Eligibility-refusal framing — UID exists but is below the
    /// tenant floor. Mirrors `refuse_mode_not_a_tenant`.
    pub fn refuse_reload_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to reload '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    /// Eligibility-refusal framing — system account (no positive
    /// UID, e.g. `nobody`). Mirrors `refuse_mode_system_account`.
    pub fn refuse_reload_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.stderr,
            "tenant: refusing to reload '{name}': system account (no tenant-range UID)"
        );
    }

    // ============================================================
    // Plan rendering helper (private)
    // ============================================================

    /// Emit the verbose "Plan (commands to execute):" section that
    /// lives inside each prompt-having verb's `*_summary`. Silent in
    /// standard mode (verbose-only disclosure). Silent when `plan` is
    /// `None` (no-arg `reload`, where the bulk-summary doesn't
    /// pre-render per-tenant plans).
    fn emit_plan_section(&mut self, plan: Option<&[(Op<'_>, Option<&'static str>)]>) {
        if !self.verbose {
            return;
        }
        let Some(entries) = plan else { return };
        if entries.is_empty() {
            return;
        }
        let _ = writeln!(self.stdout, "Plan (commands to execute):");
        let _ = writeln!(self.stdout);
        self.render_plan_block(entries);
        let _ = writeln!(self.stdout);
    }

    /// Render the upfront plan block in the intent-leads-shell-follows
    /// layout. Each entry emits:
    ///
    /// ```text
    ///   • <intent>[  # <annotation>]
    ///       <shell>
    /// ```
    ///
    /// with NO blank line between entries — the column-2 `•` + column-6
    /// shell indent give enough visual contrast to pair intent and
    /// shell unambiguously; a 14-entry create plan accumulates too
    /// much vertical fatigue otherwise. `intent` comes from
    /// `Op::intent_label()` (future-tense capability headline); `shell`
    /// from `Op::describe_via` (substrate echo line). Conditional
    /// annotations (`# on rollback`, `# on reload failure`) hang off
    /// the END of the intent line, not the shell line — operator reads
    /// WHAT + WHEN at headline level.
    ///
    /// Privilege-aware rendering on the shell line when `colors.stdout`
    /// is on: shell lines starting with `sudo` render as bold `sudo`
    /// followed by a dim remainder (visual cue: privileged + state-
    /// changing); shell lines starting with anything else render fully
    /// dim (visual cue: probe or operator-owned non-privileged). Bold-
    /// not-color for the sudo accent keeps the severity color budget
    /// (red/green/yellow/cyan) reserved for severity signals. Colors
    /// off (tests pass `Colors::default()`): plain text in both arms.
    fn render_plan_block(&mut self, plan: &[(Op<'_>, Option<&'static str>)]) {
        for (op, annotation) in plan {
            let intent = op.intent_label();
            let shell = op.describe_via(self.machine);
            let intent_line = match annotation {
                Some(note) => format!("  \u{2022} {intent}  # {note}"),
                None => format!("  \u{2022} {intent}"),
            };
            let shell_line = self.format_shell_line(&shell);
            let _ = writeln!(self.stdout, "{intent_line}");
            let _ = writeln!(self.stdout, "      {shell_line}");
        }
    }

    /// Apply the privilege-aware accent to a shell line. `sudo` first
    /// token → bold `sudo` + dim rest; anything else → dim whole line.
    /// Colors off short-circuits to the raw line.
    fn format_shell_line(&self, line: &str) -> String {
        if !self.colors.stdout {
            return line.to_string();
        }
        if let Some(rest) = line.strip_prefix("sudo ") {
            format!("{} {}", ansi::bold("sudo"), ansi::dim(rest))
        } else {
            ansi::dim(line)
        }
    }
}
