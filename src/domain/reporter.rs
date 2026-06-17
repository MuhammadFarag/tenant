//! Operator-facing output. Reporter owns verb-specific phrasing and
//! mode/verbosity branching; callers signal lifecycle events
//! (starting / done / refused / failed) without checking flags.

use std::path::PathBuf;

use super::tenants::{ConflictError, NameError, ShareError, tenant_share_group_name};
use super::{
    AccessMode, AccountError, AclError, FirewallError, GroupId, HostMachine, HostUserName,
    KeychainError, Op, ProbeError, TenantUserName, UserDirectoryError, UserId,
};
use crate::ansi::{self};
use crate::doctor::{Category, Finding, Severity};
use crate::profile::{ProfileError, display_path_for};
use crate::terminal::Terminal;
use crate::{InboundLevel, ModeLevel};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConfirmOutcome {
    Proceed,
    Abort,
}

pub(crate) struct Reporter<'t, 'm> {
    terminal: Terminal<'t>,
    verbose: bool,
    dry_run: bool,
    yes_flag: bool,
    machine: &'m dyn HostMachine,
}

impl<'t, 'm> Reporter<'t, 'm> {
    pub fn new(
        terminal: Terminal<'t>,
        verbose: bool,
        dry_run: bool,
        yes_flag: bool,
        machine: &'m dyn HostMachine,
    ) -> Self {
        Self {
            terminal,
            verbose,
            dry_run,
            yes_flag,
            machine,
        }
    }

    /// `--yes` suppresses the prompt, not the summary: an operator on a
    /// TTY still sees context; scripted (non-TTY real-mode) stays silent.
    pub(crate) fn show_summary(&self) -> bool {
        self.dry_run || self.terminal.stdin_is_tty
    }

    pub fn ok(&mut self, msg: &str) {
        let check = self.paint_stdout("✓", ansi::green);
        let _ = writeln!(self.terminal.stdout, "{check} {msg}");
    }

    pub fn section(&mut self, title: &str) {
        if self.terminal.colors.stdout {
            // `ansi::rule` counts escape sequences as chars when given a bolded
            // title, over-truncating the dashes — compose by hand instead.
            let bolded = ansi::bold(title);
            let prefix = "─── ";
            let suffix = " ";
            let raw_core = prefix.chars().count() + title.chars().count() + suffix.chars().count();
            let pad = 80_usize.saturating_sub(raw_core);
            let dashes: String = "─".repeat(pad);
            let _ = writeln!(self.terminal.stdout, "{prefix}{bolded}{suffix}{dashes}");
        } else {
            let line = ansi::rule(title, 80);
            let _ = writeln!(self.terminal.stdout, "{line}");
        }
    }

    fn paint_stdout<F: FnOnce(&str) -> String>(&self, s: &str, paint: F) -> String {
        if self.terminal.colors.stdout {
            paint(s)
        } else {
            s.to_string()
        }
    }

    /// `$ <rendered>` per-step echo. Real+verbose only. Multi-line
    /// describes (e.g. `EnsureCoworkDir`'s four-call sequence) emit
    /// one `$` prefix per substrate call so the operator sees the
    /// complete mechanism rather than a joined blob.
    pub fn step(&mut self, op: Op<'_>) {
        if self.dry_run || !self.verbose {
            return;
        }
        let rendered = op.describe_via(self.machine);
        for line in rendered.lines() {
            let _ = writeln!(self.terminal.stdout, "$ {line}");
        }
    }

    /// `✓ <label>` business-level progress line after a successful op.
    /// Silent in dry-run.
    pub fn progress(&mut self, op: Op<'_>) {
        if self.dry_run {
            return;
        }
        let label = op.business_label();
        self.ok(&label);
    }

    /// Pre-execution confirmation. Auto-proceeds in dry-run, when
    /// `yes_flag` is set, or when stdin is non-TTY. Re-prompts on
    /// unrecognized input.
    pub fn confirm(&mut self, default_yes: bool) -> ConfirmOutcome {
        if self.dry_run {
            // Preview what the real run would have asked.
            let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
            let _ = writeln!(
                self.terminal.stdout,
                "(Real run would prompt: Proceed? {hint})"
            );
            return ConfirmOutcome::Proceed;
        }
        if self.yes_flag {
            return ConfirmOutcome::Proceed;
        }
        if !self.terminal.stdin_is_tty {
            return ConfirmOutcome::Proceed;
        }
        let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
        loop {
            let _ = write!(self.terminal.stdout, "Proceed? {hint} ");
            let _ = self.terminal.stdout.flush();
            let mut line = String::new();
            match self.terminal.stdin.read_line(&mut line) {
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
                    let _ = writeln!(self.terminal.stdout, "Please answer y or n.");
                }
            }
        }
    }

    pub fn aborted(&mut self) {
        let _ = writeln!(
            self.terminal.stdout,
            "Aborted by operator. No changes made."
        );
    }

    /// Dim post-success "next step" hint. Single source of truth for the
    /// breadcrumb shape so every mutating verb's `*_done` reads
    /// uniformly. Skips emission in dry-run (the closing `Done` section
    /// itself is gated out) — keep the hint paired with the closing.
    fn next_step(&mut self, msg: &str) {
        let painted = self.paint_stdout(msg, ansi::dim);
        let _ = writeln!(self.terminal.stdout, "{painted}");
    }

    /// Render a `tenant help <topic>` body to stdout. Body is plain text;
    /// callers compose the exact wording. Bodies that end with `\n` get
    /// no extra trailing newline.
    pub fn help_topic(&mut self, body: &str) {
        let _ = write!(self.terminal.stdout, "{body}");
    }

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
            self.terminal.stdout,
            "About to create tenant '{name}' \u{2014} an isolated macOS account with restricted network egress."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} create user account '{name}' (UID {uid}) and group '{group}' (GID {gid})"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} add host '{host}' to '{group}' so files the tenant creates in RW shares stay host-writable"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} install a per-tenant firewall anchor (egress blocked by default; allowlist hosts declared in the profile)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} write profile config at {}",
            display_path_for(name.as_str())
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} enable pf host-wide if not already enabled"
        );
        let _ = writeln!(self.terminal.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(
            self.terminal.stdout,
            "Sudo needed for: user provisioning, firewall install."
        );
        let _ = writeln!(self.terminal.stdout);
    }

    /// Caller follows with `confirm(false, …)` — destroy defaults to N
    /// so muscle-memory ENTER never deletes.
    pub fn destroy_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        uid: UserId,
        plan: Option<&[(Op<'_>, Option<&'static str>)]>,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.terminal.stdout,
            "About to destroy tenant '{name}' (UID {uid})."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        let _ = writeln!(self.terminal.stdout, "  \u{2022} remove the user account");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} move /Users/{name} \u{2192} /Users/Deleted Users/{name} (recoverable until /Users/Deleted Users is emptied or the host is rebuilt)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} remove host '{host}' from '{group}'"
        );
        let _ = writeln!(self.terminal.stdout, "  \u{2022} remove group '{group}'");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} remove the firewall anchor and flush its kernel rules"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} remove profile config at {}",
            display_path_for(name.as_str())
        );
        let _ = writeln!(self.terminal.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(
            self.terminal.stdout,
            "Sudo needed for: user removal, firewall teardown."
        );
        let _ = writeln!(self.terminal.stdout);
    }

    /// Same default-N posture as `destroy_summary`.
    pub fn destroy_orphan_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        plan: Option<&[(Op<'_>, Option<&'static str>)]>,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.terminal.stdout,
            "About to destroy orphan group '{group}' for tenant '{name}'."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} remove host '{host}' from '{group}' (idempotent if not a member)"
        );
        let _ = writeln!(self.terminal.stdout, "  \u{2022} remove group '{group}'");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} remove the firewall anchor and flush its kernel rules"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} remove profile config at {}",
            display_path_for(name.as_str())
        );
        let _ = writeln!(self.terminal.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(
            self.terminal.stdout,
            "Sudo needed for: group removal, firewall teardown."
        );
        let _ = writeln!(self.terminal.stdout);
    }

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
            self.terminal.stdout,
            "About to apply mode '{level_str}' to tenant '{name}'."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        if matches!(level, ModeLevel::Install) {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} re-render the firewall anchor with install-tier hosts added to the allowlist"
            );
        } else {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} re-render the firewall anchor at runtime tier"
            );
        }
        let _ = writeln!(self.terminal.stdout, "  \u{2022} reload pf");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} refresh tenant-side symlinks for declared shares"
        );
        if matches!(level, ModeLevel::Install) {
            let _ = writeln!(self.terminal.stdout);
            let _ = writeln!(
                self.terminal.stdout,
                "The widened allowlist persists until 'tenant mode {name} runtime' (narrow) or 'tenant shell {name}' (auto-narrow on entry)."
            );
        }
        let _ = writeln!(self.terminal.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(self.terminal.stdout, "Sudo needed for: firewall install.");
        let _ = writeln!(self.terminal.stdout);
    }

    pub fn inbound_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        level: InboundLevel,
        plan: Option<&[(Op<'_>, Option<&'static str>)]>,
    ) {
        let level_str = level.as_str();
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.terminal.stdout,
            "About to apply inbound '{level_str}' to tenant '{name}'."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        if matches!(level, InboundLevel::Permissive) {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} re-render the firewall anchor opening all inbound loopback (TCP) ports"
            );
        } else {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} re-render the firewall anchor restricting inbound loopback to profile-declared ports"
            );
        }
        let _ = writeln!(self.terminal.stdout, "  \u{2022} reload pf");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} refresh tenant-side symlinks for declared shares"
        );
        if matches!(level, InboundLevel::Permissive) {
            let _ = writeln!(self.terminal.stdout);
            let _ = writeln!(
                self.terminal.stdout,
                "The widened inbound posture persists until 'tenant inbound {name} restricted' (narrow) or 'tenant shell {name}' (auto-narrow on entry)."
            );
        }
        let _ = writeln!(self.terminal.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(self.terminal.stdout, "Sudo needed for: firewall install.");
        let _ = writeln!(self.terminal.stdout);
    }

    pub fn reload_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        plan: Option<&[(Op<'_>, Option<&'static str>)]>,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.terminal.stdout,
            "About to reload tenant '{name}' from profile."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} re-render and reload the firewall anchor (runtime tier)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} re-apply each declared share from [[shares]] in the profile"
        );
        let _ = writeln!(self.terminal.stdout);
        self.emit_plan_section(plan);
        let _ = writeln!(self.terminal.stdout, "Sudo needed for: firewall install.");
        let _ = writeln!(self.terminal.stdout);
    }

    /// No confirm prompt — operator becomes the shell directly. The
    /// summary gives the pre-exec doctor audit visual context.
    pub fn shell_summary(&mut self, name: &TenantUserName, host: &HostUserName) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(self.terminal.stdout, "About to enter tenant '{name}'.");
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} narrow the firewall to runtime tier (auto-narrow)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} refresh tenant-side symlinks for declared shares"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} launch an interactive login shell as '{name}'"
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(
            self.terminal.stdout,
            "Sudo needed for: firewall narrow, tenant-side symlinks, login."
        );
        let _ = writeln!(self.terminal.stdout);
    }

    pub fn reload_all_summary(&mut self, host: &HostUserName, names: &[TenantUserName]) {
        let count = names.len();
        let list = names
            .iter()
            .map(|n| n.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            self.terminal.stdout,
            "About to reload {count} tenant(s) from their profiles: {list}."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "For each tenant this will:");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} re-render and reload the firewall anchor (runtime tier)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} ensure host '{host}' is a member of the tenant's share group (idempotent catch-up)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} re-apply declared shares from [[shares]] in the profile"
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(
            self.terminal.stdout,
            "Per-tenant failures continue the walk; a final summary names any failed tenants."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(
            self.terminal.stdout,
            "Sudo needed for: firewall install (per tenant)."
        );
        let _ = writeln!(self.terminal.stdout);
    }

    pub fn create_starting(&mut self, name: &TenantUserName) {
        if !self.dry_run {
            self.section(&format!("Creating tenant '{name}'"));
        }
    }

    pub fn create_done(&mut self, name: &TenantUserName, uid: UserId, gid: GroupId) {
        if self.dry_run {
            return;
        }
        let anchor = crate::firewall::tenant_anchor_name(name.as_str());
        self.section("Done");
        let _ = writeln!(
            self.terminal.stdout,
            "Tenant '{name}' ready (UID {uid}, GID {gid}, anchor '{anchor}')."
        );
        self.next_step(&format!(
            "Next: edit {} and run `tenant reload {name}` to apply changes.",
            display_path_for(name.as_str())
        ));
    }

    pub fn destroy_starting(&mut self, name: &TenantUserName) {
        if !self.dry_run {
            self.section(&format!("Destroying tenant '{name}'"));
        }
    }

    pub fn destroy_done(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        self.section("Done");
        let _ = writeln!(self.terminal.stdout, "Tenant '{name}' destroyed.");
        // No `Next: ...` breadcrumb here: the tenant is gone, so there's no
        // actionable next-step verb to point at — the operator returns to
        // the host prompt. Other `*_done` methods always trail a breadcrumb.
    }

    pub fn orphan_group_starting(&mut self, name: &TenantUserName) {
        if !self.dry_run {
            let group = tenant_share_group_name(name.as_str());
            self.section(&format!(
                "Destroying orphan group '{group}' for tenant '{name}'"
            ));
        }
    }

    pub fn orphan_group_done(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        let group = tenant_share_group_name(name.as_str());
        self.section("Done");
        let _ = writeln!(
            self.terminal.stdout,
            "Orphan group '{group}' for tenant '{name}' destroyed."
        );
    }

    /// Intent line only (no plan). Shell has no post-exec confirmation,
    /// so this emits in standard mode too — without it the operator
    /// would face a bare sudo prompt with no project-side context. Emit
    /// before the reapply plan is built so verb context survives a
    /// profile-read failure; plan rendering lives in `shell_plan`.
    pub fn shell_intent(&mut self, name: &TenantUserName) {
        if self.dry_run {
            let _ = writeln!(self.terminal.stdout, "Would shell into '{name}'.");
        } else {
            self.section(&format!("Entering tenant '{name}'"));
        }
    }

    /// Plan block in real+verbose mode. Shell has no confirm, so plan
    /// stays here rather than moving into a summary — only prompt-having
    /// verbs relocate plan emission into their summary.
    pub fn shell_plan(&mut self, plan: &[(Op<'_>, Option<&'static str>)]) {
        if self.verbose {
            let _ = writeln!(self.terminal.stdout, "Plan (commands to execute):");
            let _ = writeln!(self.terminal.stdout);
            self.render_plan_block(plan);
            let _ = writeln!(self.terminal.stdout);
        }
    }

    pub fn shell_command_intent(&mut self, name: &TenantUserName, mode: ModeLevel) {
        if self.dry_run {
            let _ = writeln!(
                self.terminal.stdout,
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
            let _ = writeln!(
                self.terminal.stdout,
                "About to run a command as tenant '{name}'."
            );
        } else {
            let _ = writeln!(
                self.terminal.stdout,
                "About to run a command as tenant '{name}' (mode: {}).",
                mode.as_str()
            );
        }
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        if mode == ModeLevel::Runtime {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} ensure the firewall is at runtime tier (auto-narrow; idempotent if already there)"
            );
        } else {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} widen the firewall to install tier (narrows back to runtime on completion)"
            );
        }
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} refresh tenant-side symlinks for declared shares"
        );
        let _ = writeln!(self.terminal.stdout, "  \u{2022} run as '{name}': {joined}");
        if mode != ModeLevel::Runtime {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} narrow the firewall to runtime tier (always — even if the command fails)"
            );
        }
        let _ = writeln!(self.terminal.stdout);
        if mode == ModeLevel::Runtime {
            let _ = writeln!(
                self.terminal.stdout,
                "Sudo needed for: firewall install, tenant-side symlinks, exec."
            );
        } else {
            let _ = writeln!(
                self.terminal.stdout,
                "Sudo needed for: firewall install, tenant-side symlinks, exec, firewall narrow."
            );
        }
        let _ = writeln!(self.terminal.stdout);
    }

    /// `✓` line confirming the tenant's `login.keychain-db` was
    /// unlocked. Emitted by the shell verb's pre-spawn keychain pass
    /// (both interactive and command forms) so the operator sees the
    /// unlock landed — a silent regression where the unlock pass
    /// skipped would otherwise be invisible. Real-mode only.
    pub fn shell_keychain_unlocked(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        self.ok(&format!("Tenant '{name}' login keychain unlocked"));
    }

    /// Yellow `⚠` stderr one-liner for narrow-on-finally failure (command
    /// form only). Does NOT override the child's exit code.
    pub fn shell_narrow_failed(&mut self, name: &TenantUserName, _err: &super::tenants::ModeError) {
        let prefix = if self.terminal.colors.stderr {
            "\x1b[33m\u{26a0}\x1b[0m"
        } else {
            "\u{26a0}"
        };
        let _ = writeln!(
            self.terminal.stderr,
            "{prefix} tenant '{name}': firewall not narrowed after command — install-tier widening still in effect; run `tenant mode {name} runtime` to recover"
        );
    }

    /// Closing surface for the command form. The narrow-back
    /// parenthetical fires only when the entry widened — load-bearing
    /// confirmation that on-disk state returned to runtime tier.
    pub fn shell_command_done(&mut self, child_exit: i32, mode: ModeLevel) {
        if self.dry_run {
            return;
        }
        self.section("Done");
        if mode == ModeLevel::Install {
            let _ = writeln!(
                self.terminal.stdout,
                "Command exited with code {child_exit} (firewall narrowed back to runtime tier)."
            );
        } else {
            let _ = writeln!(
                self.terminal.stdout,
                "Command exited with code {child_exit}."
            );
        }
    }

    pub fn mode_intent(&mut self, name: &TenantUserName, level: ModeLevel) {
        if !self.dry_run {
            let level_str = level.as_str();
            self.section(&format!("Applying mode '{level_str}' to tenant '{name}'"));
        }
    }

    pub fn mode_done(&mut self, name: &TenantUserName, level: ModeLevel) {
        if self.dry_run {
            return;
        }
        let level_str = level.as_str();
        self.section("Done");
        let _ = writeln!(
            self.terminal.stdout,
            "Tenant '{name}' is at {level_str} tier."
        );
        self.next_step(&format!(
            "Next: enter the tenant with `tenant shell {name}` \u{2014} the firewall auto-narrows back to runtime tier on entry."
        ));
    }

    pub fn inbound_intent(&mut self, name: &TenantUserName, level: InboundLevel) {
        if !self.dry_run {
            let level_str = level.as_str();
            self.section(&format!(
                "Applying inbound '{level_str}' to tenant '{name}'"
            ));
        }
    }

    pub fn inbound_done(&mut self, name: &TenantUserName, level: InboundLevel) {
        if self.dry_run {
            return;
        }
        let level_str = level.as_str();
        self.section("Done");
        let _ = writeln!(
            self.terminal.stdout,
            "Tenant '{name}' inbound loopback is {level_str}."
        );
        self.next_step(&format!(
            "Next: enter the tenant with `tenant shell {name}` \u{2014} inbound loopback auto-narrows back to restricted on entry."
        ));
    }

    /// Convergent-noop. Tense-neutral; emits in both real and dry-run.
    pub fn destroy_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stdout,
            "tenant '{name}' does not exist; nothing to do."
        );
    }

    // Refusals (stderr, EX_USAGE)

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
        let _ = writeln!(self.terminal.stderr, "{msg}");
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
        let _ = writeln!(self.terminal.stderr, "{msg}");
    }

    pub fn refuse_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to destroy '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to destroy '{name}': system account (no tenant-range UID)"
        );
    }

    pub fn refuse_shell_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot shell into '{name}': does not exist"
        );
    }

    /// Refusal frame for `ShellError::StashAbsent`: the tenant exists
    /// (eligibility passed) but the operator-side keychain stash for
    /// its login password is missing. Legacy tenants created before
    /// the bootstrap-stash landed need a one-time re-bootstrap; the
    /// hint names the exact recovery verbs verbatim.
    pub fn shell_refuse_stash_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to enter '{name}': stashed password absent \
             \u{2014} run `tenant destroy {name} && tenant create {name}` to re-bootstrap"
        );
    }

    /// Stderr frame for `ShellError::UnlockFailed`: substrate failure
    /// on either the operator-stash retrieval or the in-tenant
    /// `security unlock-keychain` call. No recovery hint — substrate
    /// failure is investigative ground, not an operator-action surface
    /// (parallel to `shell_failed` / `shell_narrow_firewall_failed`).
    /// `KeychainError::Display` carries the substrate exit code + stderr.
    pub fn shell_unlock_failed(&mut self, name: &TenantUserName, err: &KeychainError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to unlock login keychain for '{name}': {err}"
        );
    }

    pub fn refuse_shell_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to shell into '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_shell_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to shell into '{name}': system account (no tenant-range UID)"
        );
    }

    pub fn refuse_mode_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot apply mode to '{name}': does not exist"
        );
    }

    pub fn refuse_mode_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to apply mode to '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_mode_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to apply mode to '{name}': system account (no tenant-range UID)"
        );
    }

    pub fn refuse_inbound_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot apply inbound posture to '{name}': does not exist"
        );
    }

    pub fn refuse_inbound_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to apply inbound posture to '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_inbound_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to apply inbound posture to '{name}': system account (no tenant-range UID)"
        );
    }

    pub fn refuse_doctor_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot run doctor on '{name}': does not exist"
        );
    }

    pub fn refuse_doctor_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to run doctor on '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_doctor_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to run doctor on '{name}': system account (no tenant-range UID)"
        );
    }

    /// Verbose lists the audit's bounded scope so a clean result is not
    /// read as a claim about the host's overall security.
    pub fn doctor_starting(
        &mut self,
        name: &TenantUserName,
        curated: &[(Category, AccessMode, PathBuf)],
    ) {
        if self.dry_run {
            let _ = writeln!(self.terminal.stdout, "Would run doctor on tenant '{name}'.");
        }
        if self.verbose {
            let _ = writeln!(
                self.terminal.stdout,
                "Curated sensitive paths checked for tenant '{name}':"
            );
            for (_, mode, path) in curated {
                let verb = match mode {
                    AccessMode::Read => "read",
                    AccessMode::List => "list",
                };
                let _ = writeln!(self.terminal.stdout, "  {verb} {}", path.display());
            }
        }
    }

    /// In verbose, append `Finding::guidance()` indented 2 spaces below
    /// the one-liner. Findings that return `None` render the one-liner
    /// alone.
    pub fn doctor_finding(&mut self, finding: &Finding) {
        self.doctor_finding_one_liner(finding);
        if self.verbose
            && let Some(guidance) = finding.guidance()
        {
            for line in guidance.lines() {
                if line.is_empty() {
                    let _ = writeln!(self.terminal.stdout);
                } else {
                    let styled = self.style_guidance_line(line);
                    let _ = writeln!(self.terminal.stdout, "  {styled}");
                }
            }
        }
    }

    /// Colored one-liner only — guidance body is skipped regardless of
    /// verbose. Verb output names what the verb is doing; full guidance
    /// stays behind `tenant doctor -v`.
    pub fn doctor_finding_one_liner(&mut self, finding: &Finding) {
        let rendered = self.color_finding_prefix(finding);
        let _ = writeln!(self.terminal.stdout, "{rendered}");
    }

    /// Critical → red+bold; warning → yellow; info → dim. Color-off
    /// preserves the plain byte-form contract.
    fn color_finding_prefix(&self, finding: &Finding) -> String {
        let text = finding.to_string();
        if !self.terminal.colors.stdout {
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

    /// Headers (unindented) get bold; body lines (indented) get dim, so
    /// the finding one-liner stays the scannable focus.
    fn style_guidance_line(&self, line: &str) -> String {
        if !self.terminal.colors.stdout {
            return line.to_string();
        }
        if line.starts_with(' ') {
            ansi::dim(line)
        } else {
            ansi::bold(line)
        }
    }

    /// Scoped to per-tenant findings. Wording is explicit ("no
    /// per-tenant findings") so a clean line doesn't read as "doctor
    /// said everything is clean" when host-wide warnings already
    /// surfaced above.
    pub fn doctor_done_summary(&mut self, name: &TenantUserName, finding_count: usize) {
        if self.dry_run {
            return;
        }
        if finding_count == 0 {
            let _ = writeln!(
                self.terminal.stdout,
                "doctor: tenant '{name}' \u{2014} no per-tenant findings."
            );
        }
    }

    pub fn doctor_all_tenants_noop(&mut self) {
        let _ = writeln!(self.terminal.stdout, "doctor: no tenants to audit.");
    }

    pub fn doctor_failed(&mut self, err: &ProbeError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe doctor: {err}"
        );
    }

    pub fn doctor_host_file_failed(&mut self, err: &super::HostFileError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to read host config: {err}"
        );
    }

    pub fn doctor_firewall_failed(&mut self, err: &FirewallError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to read pf state: {err}"
        );
    }

    /// Stderr frame for substrate failures on the tenant-keychain
    /// presence probe. Doctor continues the walk after emitting; the
    /// audit is a courtesy, never an abort gate.
    pub fn doctor_keychain_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe tenant '{name}' keychain presence: {err}"
        );
    }

    /// Stderr frame for substrate failures on the operator-stash
    /// presence probe. Doctor continues the walk after emitting.
    pub fn doctor_stash_probe_failed(&mut self, name: &TenantUserName, err: &KeychainError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe stash presence for tenant '{name}': {err}"
        );
    }

    // HostUserDirectory (dscl) failure frames, one per call site. The five
    // `*_eligibility_probe_failed` frames carry near-identical Display
    // strings; they stay split per verb to match the sibling pattern
    // already paid for by `mode_failed` / `reload_firewall_failed` /
    // `shell_narrow_firewall_failed` — verb-named frames let log-grep
    // bind to the verb without parsing the message body.

    pub fn create_conflict_probe_failed(
        &mut self,
        name: &TenantUserName,
        err: &UserDirectoryError,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to check existing accounts for '{name}': {err}"
        );
    }

    pub fn create_uid_allocation_failed(&mut self, err: &UserDirectoryError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to allocate UID: {err}"
        );
    }

    pub fn create_gid_allocation_failed(&mut self, err: &UserDirectoryError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to allocate GID: {err}"
        );
    }

    pub fn destroy_eligibility_probe_failed(
        &mut self,
        name: &TenantUserName,
        err: &UserDirectoryError,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to check destroy eligibility for '{name}': {err}"
        );
    }

    pub fn destroy_uid_lookup_failed(&mut self, name: &TenantUserName, err: &UserDirectoryError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to look up UID for '{name}': {err}"
        );
    }

    pub fn shell_eligibility_probe_failed(
        &mut self,
        name: &TenantUserName,
        err: &UserDirectoryError,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to check shell eligibility for '{name}': {err}"
        );
    }

    pub fn mode_eligibility_probe_failed(
        &mut self,
        name: &TenantUserName,
        err: &UserDirectoryError,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to check mode eligibility for '{name}': {err}"
        );
    }

    pub fn inbound_eligibility_probe_failed(
        &mut self,
        name: &TenantUserName,
        err: &UserDirectoryError,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to check inbound eligibility for '{name}': {err}"
        );
    }

    pub fn doctor_eligibility_probe_failed(
        &mut self,
        name: &TenantUserName,
        err: &UserDirectoryError,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to check doctor eligibility for '{name}': {err}"
        );
    }

    pub fn reload_eligibility_probe_failed(
        &mut self,
        name: &TenantUserName,
        err: &UserDirectoryError,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to check reload eligibility for '{name}': {err}"
        );
    }

    pub fn reload_all_enumeration_failed(&mut self, err: &UserDirectoryError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to enumerate tenants for reload: {err}"
        );
    }

    pub fn doctor_enumeration_failed(&mut self, err: &UserDirectoryError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to enumerate tenants for doctor: {err}"
        );
    }

    /// Yellow ⚠ aggregate for non-critical pre-exec findings. `target`
    /// is `None` for create (no tenant yet). Silent on `count == 0`.
    /// Goes to stdout — advisory, not failure.
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
        let _ = writeln!(self.terminal.stdout, "{painted}");
    }

    /// Calibrated shell-entry inbound posture line (cycle 24). Locked
    /// (no declared ports, anchor not permissive) is quiet — `posture`
    /// is `None`, nothing emits. `InboundExposure` (restricted with
    /// ports) gets a dim info-flavored line naming the ports; the loud
    /// `InboundPermissive` gets a yellow ⚠ warning plus a narrow hint.
    /// Distinct from `doctor_summary_pending`'s warning aggregate: the
    /// posture line is a calibrated heads-up, not a "run doctor" nag.
    pub fn doctor_inbound_posture(&mut self, posture: Option<&Finding>) {
        let Some(finding) = posture else {
            return;
        };
        match finding {
            Finding::InboundExposure { ports, .. } => {
                let ports_spec = ports
                    .iter()
                    .map(|p| format!(":{p}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let line = format!(
                    "inbound: restricted \u{2014} {ports_spec} open to host + peer tenants"
                );
                let painted = self.paint_stdout(&line, ansi::dim);
                let _ = writeln!(self.terminal.stdout, "{painted}");
            }
            Finding::InboundPermissive { .. } => {
                let line = "\u{26a0} inbound: PERMISSIVE \u{2014} all ports open to host + peer tenants; \
                            narrows back to restricted on entry";
                let painted = self.paint_stdout(line, ansi::yellow);
                let _ = writeln!(self.terminal.stdout, "{painted}");
            }
            _ => {}
        }
    }

    // Failures (stderr, EX_IOERR)

    pub fn create_group_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to create group '{group}' for '{name}': {err}"
        );
    }

    pub fn create_host_membership_failed(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        err: &AccountError,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to add host '{host}' to group '{group}': {err} \
             \u{2014} host now has an orphan group; next 'tenant destroy {name}' will converge"
        );
    }

    pub fn create_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to create '{name}': {err}"
        );
    }

    /// SECOND stderr line after `create_failed` when the rollback
    /// itself failed.
    pub fn create_rollback_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: rollback of group '{group}' also failed: {err} \
             \u{2014} host now has an orphan group; next 'tenant destroy {name}' will converge"
        );
    }

    pub fn create_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to write profile '{path}' for '{name}': {err}"
        );
    }

    pub fn create_firewall_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to install firewall for '{name}': {err}"
        );
    }

    pub fn destroy_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to destroy '{name}': {err}"
        );
    }

    pub fn destroy_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to remove profile '{path}' for '{name}': {err}"
        );
    }

    pub fn destroy_firewall_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to tear down firewall for '{name}': {err}"
        );
    }

    /// Stdout one-liner emitted at the tail of both destroy paths
    /// (full + orphan-group convergence) when the cowork dir at
    /// `/Users/Shared/tenants/<name>` is still present. The dir is
    /// intentionally preserved — it holds operator-authored work and
    /// auto-deleting it is the failure mode we're avoiding. Naming
    /// the tenant disambiguates back-to-back destroys; naming the
    /// path tells the operator exactly what to clean up.
    pub fn destroy_cowork_dir_intact(&mut self, name: &TenantUserName, path: &std::path::Path) {
        if self.dry_run {
            return;
        }
        let display = path.display();
        let _ = writeln!(
            self.terminal.stdout,
            "Co-working directory for tenant '{name}' left intact at {display}."
        );
    }

    /// Yellow `⚠` stderr warning when the upfront cowork-dir probe
    /// fails. Mirrors the doctor-pass posture (substrate-machinery
    /// failures surface as warnings; the verb proceeds). Naming the
    /// path lets the operator verify manually.
    pub fn destroy_cowork_probe_failed(
        &mut self,
        name: &TenantUserName,
        path: &std::path::Path,
        err: &ProbeError,
    ) {
        let prefix = if self.terminal.colors.stderr {
            "\x1b[33m\u{26a0}\x1b[0m"
        } else {
            "\u{26a0}"
        };
        let display = path.display();
        let _ = writeln!(
            self.terminal.stderr,
            "{prefix} Co-working directory check for tenant '{name}' failed: {err} \u{2014} manually verify {display}"
        );
    }

    /// Warning frame for the destroy-side stash-delete: the rest of
    /// destroy already removed the user + group + firewall, but
    /// scrubbing the operator-side stash failed for a non-NotFound
    /// reason. Em-dash hint names the manual recovery.
    pub fn destroy_keychain_delete_warning(&mut self, name: &TenantUserName, err: &KeychainError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: warning: could not remove stashed password for '{name}': {err} \
             \u{2014} run `security delete-generic-password -a {name} -s tenant-{name}` to scrub manually"
        );
    }

    /// Stderr frame for `CreateError::CoworkDir`. Tenant user + group
    /// already exist; recovery is `tenant destroy <name>`.
    pub fn create_cowork_dir_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to provision co-working directory for '{name}': {err} \
             \u{2014} run `tenant destroy {name}` to clean up"
        );
    }

    /// Stderr frame for `CreateError::KeychainProvision`. Tenant user
    /// + group already exist; recovery is `tenant destroy <name>`.
    pub fn create_keychain_provision_failed(&mut self, name: &TenantUserName, err: &KeychainError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to provision login keychain for '{name}': {err} \
             \u{2014} run `tenant destroy {name}` to clean up"
        );
    }

    /// Stderr frame for `CreateError::KeychainStash`. Tenant user +
    /// group + keychain provisioned but the operator-side stash
    /// failed; recovery is `tenant destroy <name>`.
    pub fn create_keychain_stash_failed(&mut self, name: &TenantUserName, err: &KeychainError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to stash '{name}' password in operator keychain: {err} \
             \u{2014} run `tenant destroy {name}` to clean up"
        );
    }

    pub fn shell_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to shell into '{name}': {err}"
        );
    }

    pub fn shell_narrow_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to read profile '{path}' for '{name}' before shell entry: {err}"
        );
    }

    pub fn shell_narrow_firewall_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to narrow firewall for '{name}' before shell entry: {err}"
        );
    }

    pub fn mode_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to read profile '{path}' for '{name}': {err}"
        );
    }

    pub fn mode_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to apply firewall mode for '{name}': {err}"
        );
    }

    pub fn inbound_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to apply inbound posture for '{name}': {err}"
        );
    }

    // Share-reapply failure framing — per-verb context phrases so the
    // operator's recovery guidance reads in the verb they invoked.

    pub fn mode_acl_failed(&mut self, name: &TenantUserName, err: &AclError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to apply ACL for '{name}': {err}"
        );
    }

    pub fn mode_account_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to install tenant-side filesystem state for '{name}': {err}"
        );
    }

    pub fn mode_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe tenant filesystem state for '{name}': {err}"
        );
    }

    /// `refuse_*` framing because the operator authored the conflict;
    /// the substrate never ran.
    pub fn refuse_mode_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot apply mode for '{name}': {err}"
        );
    }

    pub fn refuse_inbound_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot apply inbound posture for '{name}': {err}"
        );
    }

    pub fn shell_narrow_acl_failed(&mut self, name: &TenantUserName, err: &AclError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to apply ACL for '{name}' before shell entry: {err}"
        );
    }

    pub fn shell_narrow_account_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to install tenant-side filesystem state for '{name}' before shell entry: {err}"
        );
    }

    pub fn shell_narrow_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe tenant filesystem state for '{name}' before shell entry: {err}"
        );
    }

    pub fn refuse_shell_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot enter shell for '{name}': {err}"
        );
    }

    // Create's post-provision arms. Recovery is `tenant reload <name>`
    // rather than `tenant create` (which would refuse on name-conflict).

    pub fn create_post_provision_acl_failed(&mut self, name: &TenantUserName, err: &AclError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: '{name}' provisioned but ACL reapply failed: {err}; \
             recover with `tenant reload {name}`"
        );
    }

    pub fn create_post_provision_account_failed(
        &mut self,
        name: &TenantUserName,
        err: &AccountError,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: '{name}' provisioned but tenant-side filesystem state failed: {err}; \
             recover with `tenant reload {name}`"
        );
    }

    pub fn create_post_provision_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: '{name}' provisioned but tenant-path probe failed: {err}; \
             recover with `tenant reload {name}`"
        );
    }

    pub fn refuse_create_post_provision_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: '{name}' provisioned but share entry is invalid: {err}; \
             edit the profile and rerun `tenant reload {name}`"
        );
    }

    pub fn reload_intent(&mut self, name: &TenantUserName) {
        if !self.dry_run {
            self.section(&format!("Reloading tenant '{name}'"));
        }
    }

    pub fn reload_done(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        self.section("Done");
        let _ = writeln!(self.terminal.stdout, "Tenant '{name}' reloaded.");
        self.next_step(&format!("Next: audit with `tenant doctor {name}`."));
    }

    /// Silent when `count == 0`; `reload_all_done_summary` handles that.
    pub fn reload_all_starting(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        if !self.dry_run {
            self.section(&format!("Reloading {count} tenant(s)"));
        }
    }

    /// The no-tenant case emits a distinct line so the operator gets
    /// feedback instead of empty output.
    pub fn reload_all_done_summary(&mut self, succeeded: usize, failed: usize) {
        if self.dry_run {
            return;
        }
        if succeeded == 0 && failed == 0 {
            let _ = writeln!(self.terminal.stdout, "No tenants on this host to reload.");
            return;
        }
        let total = succeeded + failed;
        let line = if failed == 0 {
            format!("Reloaded {total} tenant(s).")
        } else {
            format!("Reloaded {succeeded} of {total} tenant(s); {failed} failed.")
        };
        self.section("Done");
        let _ = writeln!(self.terminal.stdout, "{line}");
    }

    pub fn reload_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to read profile '{path}' for '{name}': {err}"
        );
    }

    /// Distinct from `mode_failed`; "firewall mode" wording would imply
    /// a tier-swap, and reload doesn't swap tiers.
    pub fn reload_firewall_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to reload firewall for '{name}': {err}"
        );
    }

    pub fn refuse_reload_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot reload '{name}': {err}"
        );
    }

    pub fn refuse_reload_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot reload '{name}': does not exist"
        );
    }

    pub fn refuse_reload_not_a_tenant(&mut self, name: &TenantUserName, uid: UserId, floor: u32) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to reload '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_reload_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to reload '{name}': system account (no tenant-range UID)"
        );
    }

    fn emit_plan_section(&mut self, plan: Option<&[(Op<'_>, Option<&'static str>)]>) {
        if !self.verbose {
            return;
        }
        let Some(entries) = plan else { return };
        if entries.is_empty() {
            return;
        }
        let _ = writeln!(self.terminal.stdout, "Plan (commands to execute):");
        let _ = writeln!(self.terminal.stdout);
        self.render_plan_block(entries);
        let _ = writeln!(self.terminal.stdout);
    }

    /// Intent-leads-shell-follows layout, NO blank line between entries
    /// — a 14-entry create plan would accumulate too much vertical
    /// fatigue otherwise. Annotations hang off the intent line, not the
    /// shell line, so the operator reads WHAT + WHEN at headline level.
    /// Privilege-aware shell rendering uses bold `sudo` + dim rest;
    /// bold-not-color reserves the severity color budget for severity.
    fn render_plan_block(&mut self, plan: &[(Op<'_>, Option<&'static str>)]) {
        for (op, annotation) in plan {
            let intent = op.intent_label();
            let shell = op.describe_via(self.machine);
            let intent_line = match annotation {
                Some(note) => format!("  \u{2022} {intent}  # {note}"),
                None => format!("  \u{2022} {intent}"),
            };
            let _ = writeln!(self.terminal.stdout, "{intent_line}");
            // Multi-line describes (e.g. `EnsureCoworkDir`'s four-call
            // sequence) get one indented shell line per substrate call
            // under the same intent bullet.
            for line in shell.lines() {
                let shell_line = self.format_shell_line(line);
                let _ = writeln!(self.terminal.stdout, "      {shell_line}");
            }
        }
    }

    fn format_shell_line(&self, line: &str) -> String {
        if !self.terminal.colors.stdout {
            return line.to_string();
        }
        if let Some(rest) = line.strip_prefix("sudo ") {
            format!("{} {}", ansi::bold("sudo"), ansi::dim(rest))
        } else {
            ansi::dim(line)
        }
    }
}
