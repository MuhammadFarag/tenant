use std::path::PathBuf;

use super::tenants::{ConflictError, NameError, ShareError, tenant_share_group_name};
use super::{
    AccessMode, AccountError, AclError, FirewallError, GroupId, HostFileError, HostMachine,
    HostUserName, KeychainError, Op, ProbeError, TenantUserName, UserDirectoryError, UserId,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryGate {
    Enter,
    Declined,
    Refused,
}

/// Which inbound line, if any, a shell summary owes the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellInbound {
    Restricted,
    PermissiveByProfile,
    WidenedForCommand,
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

    pub fn step(&mut self, op: Op<'_>) {
        if self.dry_run || !self.verbose {
            return;
        }
        let rendered = op.describe_via(self.machine);
        for line in rendered.lines() {
            let _ = writeln!(self.terminal.stdout, "$ {line}");
        }
    }

    pub fn progress(&mut self, op: Op<'_>) {
        if self.dry_run {
            return;
        }
        let label = op.business_label();
        self.ok(&label);
    }

    /// Auto-proceeds under dry-run, `--yes`, or a non-TTY stdin.
    pub fn confirm(&mut self, default_yes: bool) -> ConfirmOutcome {
        if self.dry_run {
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
        self.ask("Proceed?", default_yes)
    }

    /// EOF or a read error declines; an empty answer takes the default.
    fn ask(&mut self, question: &str, default_yes: bool) -> ConfirmOutcome {
        let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
        loop {
            self.prompt(&format!("{question} {hint} "));
            let mut line = String::new();
            match self.terminal.stdin.read_line(&mut line) {
                Ok(0) | Err(_) => return ConfirmOutcome::Abort,
                Ok(_) => {}
            }
            match line.trim().to_ascii_lowercase().as_str() {
                "" if default_yes => return ConfirmOutcome::Proceed,
                "" => return ConfirmOutcome::Abort,
                "y" | "yes" => return ConfirmOutcome::Proceed,
                "n" | "no" => return ConfirmOutcome::Abort,
                _ => {
                    let _ = writeln!(self.terminal.stderr, "Please answer y or n.");
                }
            }
        }
    }

    /// Criticals print to stderr. `-y` enters with a note; a terminal gets a default-no
    /// `[y/N]`; with no terminal there's no one to ask, so it refuses.
    pub(crate) fn gate_entry_on_criticals(
        &mut self,
        name: &TenantUserName,
        criticals: &[Finding],
    ) -> EntryGate {
        if criticals.is_empty() {
            return EntryGate::Enter;
        }
        let _ = self.terminal.stdout.flush();
        for finding in criticals {
            let _ = writeln!(self.terminal.stderr, "{finding}");
        }
        let findings = if criticals.len() == 1 {
            "1 critical doctor finding".to_string()
        } else {
            format!("{} critical doctor findings", criticals.len())
        };
        let question = format!("Enter '{name}' anyway?");
        if self.dry_run {
            let _ = writeln!(
                self.terminal.stdout,
                "(Real run would prompt: {question} [y/N])"
            );
            return EntryGate::Enter;
        }
        let prefix = self.stderr_warn_prefix();
        if self.yes_flag {
            let _ = writeln!(
                self.terminal.stderr,
                "{prefix} entering '{name}' despite {findings} (-y)"
            );
            return EntryGate::Enter;
        }
        if !self.terminal.stdin_is_tty {
            let _ = writeln!(
                self.terminal.stderr,
                "tenant: refusing to enter '{name}' with no terminal to confirm: {findings} above \
                 \u{2014} run `tenant doctor {name}`, or pass -y to enter anyway"
            );
            return EntryGate::Refused;
        }
        let _ = writeln!(
            self.terminal.stderr,
            "\n{prefix}  '{name}' has {findings} (above). Its sandbox guarantees may not hold:\n\
             {prefix}  entering now can run code without the isolation you expect.\n\
             {prefix}  Run `tenant doctor {name}` for details and fixes.\n"
        );
        match self.ask(&question, false) {
            ConfirmOutcome::Proceed => EntryGate::Enter,
            ConfirmOutcome::Abort => EntryGate::Declined,
        }
    }

    pub fn shell_entry_declined(&mut self, name: &TenantUserName) {
        let _ = writeln!(self.terminal.stdout, "Not entering '{name}'.");
    }

    /// sudo prompts on the controlling tty even when stdin is piped, so a cold
    /// timestamp in a non-interactive run blocks forever with no output. Call it
    /// before any plan build: share probes `sudo -v` there.
    pub(crate) fn refuse_sudo_without_terminal(&mut self) -> bool {
        if self.dry_run || self.terminal.stdin_is_tty || self.machine.sudo_session_cached() {
            return false;
        }
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: this verb needs sudo and no terminal is attached \u{2014} run it in your \
             terminal, or run 'sudo -v' in this session first"
        );
        true
    }

    pub fn aborted(&mut self) {
        let _ = writeln!(
            self.terminal.stdout,
            "Aborted by operator. No changes made."
        );
    }

    fn next_step(&mut self, msg: &str) {
        let painted = self.paint_stdout(msg, ansi::dim);
        let _ = writeln!(self.terminal.stdout, "{painted}");
    }

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

    /// Destroy's confirm defaults to N so a muscle-memory ENTER never deletes.
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

    pub fn shell_summary(
        &mut self,
        name: &TenantUserName,
        host: &HostUserName,
        directory: Option<&str>,
        posture_permissive: bool,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(self.terminal.stdout, "About to enter tenant '{name}'.");
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} narrow the firewall to runtime tier (auto-narrow)"
        );
        if posture_permissive {
            self.permissive_posture_bullet();
        }
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
        // The `cd` is part of what the operator is consenting to, so it
        // shows in the summary as well as the (verbose-only) plan line.
        if let Some(dir) = directory {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} start in '{dir}' (resolved on {name}'s filesystem)"
            );
        }
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
        // No `Next:` breadcrumb: the tenant is gone, so there's no verb to point at.
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

    /// Emits in standard mode too, before the plan is built: otherwise the operator faces a
    /// bare sudo prompt, and verb context wouldn't survive a profile-read failure.
    pub fn shell_intent(&mut self, name: &TenantUserName) {
        if self.dry_run {
            let _ = writeln!(self.terminal.stdout, "Would shell into '{name}'.");
        } else {
            self.section(&format!("Entering tenant '{name}'"));
        }
    }

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
        inbound: ShellInbound,
        argv: &[String],
        directory: Option<&str>,
    ) {
        let group = tenant_share_group_name(name.as_str());
        let joined = argv.join(" ");
        let inbound_widened = inbound == ShellInbound::WidenedForCommand;
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
        if inbound_widened {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} open ALL inbound loopback ports for the command \u{2014} reachable by \
                 host + peer tenants"
            );
        } else if inbound == ShellInbound::PermissiveByProfile {
            self.permissive_posture_bullet();
        }
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} ensure host '{host}' is a member of '{group}' (idempotent catch-up)"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} refresh tenant-side symlinks for declared shares"
        );
        let _ = match directory {
            Some(dir) => writeln!(
                self.terminal.stdout,
                "  \u{2022} run as '{name}' in '{dir}': {joined}"
            ),
            None => writeln!(self.terminal.stdout, "  \u{2022} run as '{name}': {joined}"),
        };
        if mode != ModeLevel::Runtime {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} narrow the firewall to runtime tier (always — even if the command fails)"
            );
        }
        if inbound_widened {
            let _ = writeln!(
                self.terminal.stdout,
                "  \u{2022} narrow inbound loopback back to the profile's posture (always \u{2014} \
                 even if the command fails)"
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

    /// A visible `✓`, so an unlock pass that silently skipped would show.
    pub fn keychain_unlocked(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        self.ok(&format!("Tenant '{name}' keychain unlocked"));
    }

    /// On stderr so a piped stdout still leaves the question on the operator's terminal; stdout
    /// is flushed first so the summary lands above it.
    fn prompt(&mut self, question: &str) {
        let _ = self.terminal.stdout.flush();
        let _ = write!(self.terminal.stderr, "{question}");
        let _ = self.terminal.stderr.flush();
    }

    fn stderr_warn_prefix(&self) -> &'static str {
        if self.terminal.colors.stderr {
            "\x1b[33m\u{26a0}\x1b[0m"
        } else {
            "\u{26a0}"
        }
    }

    pub fn share_grant_incomplete(
        &mut self,
        name: &TenantUserName,
        path: &std::path::Path,
        chmod_stderr: &str,
    ) {
        let prefix = self.stderr_warn_prefix();
        let _ = writeln!(
            self.terminal.stderr,
            "{prefix} tenant '{name}': ACL grant on {} incomplete \u{2014} {}; the rest of the \
             tree was granted, `tenant doctor {name}` lists what still lacks it",
            path.display(),
            chmod_stderr.trim()
        );
    }

    fn permissive_posture_bullet(&mut self) {
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} keep inbound loopback PERMISSIVE (profile posture) \u{2014} every port the \
             tenant opens is reachable by host + peer tenants"
        );
    }

    pub fn shell_narrow_failed(
        &mut self,
        name: &TenantUserName,
        egress_widened: bool,
        inbound_widened: bool,
    ) {
        let prefix = self.stderr_warn_prefix();
        let leftover = match (egress_widened, inbound_widened) {
            (true, true) => "install-tier widening and all-ports inbound loopback",
            (false, true) => "all-ports inbound loopback",
            _ => "install-tier widening",
        };
        let _ = writeln!(
            self.terminal.stderr,
            "{prefix} tenant '{name}': firewall not narrowed after command \u{2014} {leftover} \
             still in effect; run `tenant mode {name} runtime` to recover"
        );
    }

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

    // ---- setup verb (host-wide, opt-in host prep) ----

    pub fn setup_intent(&mut self) {
        if self.dry_run {
            let _ = writeln!(self.terminal.stdout, "Would set up this host.");
        } else {
            self.section("Setting up host");
        }
    }

    pub fn setup_touch_id_offer(&mut self) -> ConfirmOutcome {
        let _ = writeln!(self.terminal.stdout, "Touch ID for sudo");
        let _ = writeln!(
            self.terminal.stdout,
            "  Let sudo accept your fingerprint \u{2014} faster, and adds a hardware"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  auth factor. Additive: your password still works. Appends"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  `auth sufficient pam_tid.so` to /etc/pam.d/sudo_local."
        );
        let _ = writeln!(self.terminal.stdout);
        self.setup_offer("Enable Touch ID for sudo?")
    }

    /// Declines on a non-TTY without `--yes`, unlike `confirm`: setup items are
    /// security-sensitive opt-ins, not converge-to-declared-state operations.
    fn setup_offer(&mut self, question: &str) -> ConfirmOutcome {
        if self.dry_run {
            let _ = writeln!(
                self.terminal.stdout,
                "(Real run would prompt: {question} [y/N])"
            );
            return ConfirmOutcome::Proceed;
        }
        if self.yes_flag {
            return ConfirmOutcome::Proceed;
        }
        if !self.terminal.stdin_is_tty {
            return ConfirmOutcome::Abort;
        }
        // Enabling Touch ID needs sudo, which isn't fingerprint-gated yet, so this
        // one prompts for a typed password.
        let _ = writeln!(
            self.terminal.stdout,
            "  You'll be asked for your password once to apply this."
        );
        self.ask(question, false)
    }

    pub fn setup_touch_id_done(&mut self) {
        if self.dry_run {
            return;
        }
        self.next_step(
            "Touch ID takes effect on your next sudo \u{2014} run `sudo -k` or open a new terminal.",
        );
    }

    pub fn setup_touch_id_skipped(&mut self) {
        if self.dry_run {
            return;
        }
        let _ = writeln!(self.terminal.stdout, "Skipped Touch ID for sudo.");
    }

    pub fn setup_done(&mut self) {
        if self.dry_run {
            return;
        }
        self.section("Done");
        let _ = writeln!(self.terminal.stdout, "Host setup complete.");
    }

    /// Names the backup: there's no auto-restore for a PAM file.
    pub fn setup_pam_failed(&mut self, err: &HostFileError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to enable Touch ID for sudo: {err} \
             \u{2014} if /etc/pam.d/sudo_local looks wrong, restore it from \
             /etc/pam.d/sudo_local.tenant-backup (written before the change, if one existed)"
        );
    }

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

    pub fn shell_refuse_stash_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to enter '{name}': stashed password absent \
             \u{2014} run `tenant destroy {name} && tenant create {name}` to re-bootstrap"
        );
    }

    /// Names `-d`, not `tenant_path`: the mistake is on the command line, not in the profile.
    pub fn refuse_shell_directory_invalid(&mut self, raw: &str, reason: &str) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to enter: --directory {raw:?} {reason}"
        );
    }

    /// Names the RESOLVED path (the fix is obvious only then). One message for absent /
    /// not-a-directory / unreadable: a single `test -d` can't tell which.
    pub fn refuse_shell_directory_unavailable(
        &mut self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to enter '{name}': {} is not a directory '{name}' can enter",
            path.display()
        );
    }

    pub fn shell_directory_probe_failed(&mut self, path: &std::path::Path, err: &ProbeError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe directory {}: {err}",
            path.display()
        );
    }

    pub fn keychain_unlock_failed(&mut self, name: &TenantUserName, err: &KeychainError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to unlock keychain for '{name}': {err}"
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

    pub fn refuse_restricted_on_permissive_profile(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot narrow '{name}' to restricted inbound: its profile declares \
             [inbound] posture = \"permissive\" \u{2014} set it to \"restricted\" (or remove it) in \
             {} or the include that sets it, then run `tenant reload {name}`",
            display_path_for(name.as_str())
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

    /// Never guidance, even under `-v`: full guidance stays behind `tenant doctor -v`.
    pub fn doctor_finding_one_liner(&mut self, finding: &Finding) {
        let rendered = self.color_finding_prefix(finding);
        let _ = writeln!(self.terminal.stdout, "{rendered}");
    }

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

    /// "No per-tenant findings", not "clean": host-wide warnings may already have
    /// printed above.
    pub(crate) fn doctor_error(&mut self, error: &super::tenants::DoctorError) {
        use super::tenants::DoctorError;
        match error {
            DoctorError::Probe(e) => self.doctor_failed(e),
            DoctorError::HostFile(e) => self.doctor_host_file_failed(e),
            DoctorError::Firewall(e) => self.doctor_firewall_failed(e),
            DoctorError::UserDirectoryLookup(e) => self.doctor_enumeration_failed(e),
        }
    }

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

    pub fn doctor_keychain_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe tenant '{name}' keychain presence: {err}"
        );
    }

    pub fn doctor_primary_group_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe tenant '{name}' primary group: {err}"
        );
    }

    pub fn doctor_stash_probe_failed(&mut self, name: &TenantUserName, err: &KeychainError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe stash presence for tenant '{name}': {err}"
        );
    }

    // TODO(smell): the *_eligibility_probe_failed frames are near-identical, split per verb only for log-grep — parameterize by verb

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

    /// `target` is `None` for create (no tenant yet).
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

    /// `None` means locked (no declared ports, anchor not permissive): nothing emits.
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
            Finding::InboundPermissiveByProfile { .. } => {
                let line =
                    "inbound: permissive (profile) \u{2014} all ports open to host + peer tenants";
                let painted = self.paint_stdout(line, ansi::dim);
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

    pub fn create_rollback_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let group = tenant_share_group_name(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: rollback of group '{group}' also failed: {err} \
             \u{2014} host now has an orphan group; next 'tenant destroy {name}' will converge"
        );
    }

    pub fn create_profile_kept(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        self.ok(&format!(
            "Kept existing profile at {}",
            display_path_for(name.as_str())
        ));
    }

    pub fn refuse_create_profile_invalid(&mut self, name: &TenantUserName, err: &ProfileError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to create '{name}': the existing profile {} can't be applied \
             \u{2014} {err}; fix it, or move it aside to start from the default",
            display_path_for(name.as_str())
        );
    }

    pub fn create_profile_failed(&mut self, name: &TenantUserName, err: &ProfileError) {
        let path = display_path_for(name.as_str());
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to write profile '{path}' for '{name}': {err}"
        );
    }

    /// Everything but the kernel load succeeded, so the tenant exists and needs a way forward.
    pub fn create_anchor_not_loaded(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to install firewall for '{name}': {err}; '{name}' was created but its \
             firewall isn't enforced \u{2014} fix pf, then run `tenant reload {name}` (or \
             `tenant destroy {name}` to start over)"
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

    pub fn destroy_cowork_probe_failed(
        &mut self,
        name: &TenantUserName,
        path: &std::path::Path,
        err: &ProbeError,
    ) {
        let prefix = self.stderr_warn_prefix();
        let display = path.display();
        let _ = writeln!(
            self.terminal.stderr,
            "{prefix} Co-working directory check for tenant '{name}' failed: {err} \u{2014} manually verify {display}"
        );
    }

    pub fn destroy_keychain_delete_warning(&mut self, name: &TenantUserName, err: &KeychainError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: warning: could not remove stashed password for '{name}': {err} \
             \u{2014} run `security delete-generic-password -a {name} -s tenant-{name}` to scrub manually"
        );
    }

    pub fn create_cowork_dir_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to provision co-working directory for '{name}': {err} \
             \u{2014} run `tenant destroy {name}` to clean up"
        );
    }

    pub fn create_keychain_provision_failed(&mut self, name: &TenantUserName, err: &KeychainError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to provision keychain for '{name}': {err} \
             \u{2014} run `tenant destroy {name}` to clean up"
        );
    }

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

    // Share-reapply failures: per-verb phrasing so recovery reads in the invoked verb.

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

    // TODO(smell): mode_{profile,acl,account,probe}_failed also serve inbound/reload/create — rename without the `mode_` prefix
    // "Host state", not "filesystem": also covers `sudo -v` and reload's share-group gid read.
    pub fn mode_probe_failed(&mut self, name: &TenantUserName, err: &ProbeError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to probe host state for '{name}': {err}"
        );
    }

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
            "tenant: failed to probe host state for '{name}' before shell entry: {err}"
        );
    }

    pub fn refuse_shell_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot enter shell for '{name}': {err}"
        );
    }

    // Create's post-provision arms: recovery is `tenant reload`, not `tenant create`.

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

    pub fn reload_all_starting(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        if !self.dry_run {
            self.section(&format!("Reloading {count} tenant(s)"));
        }
    }

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

    // --- bootstrap verb ------------------------------------------------

    pub fn bootstrap_intent(&mut self, name: &TenantUserName) {
        if !self.dry_run {
            self.section(&format!("Bootstrapping tenant '{name}'"));
        }
    }

    pub fn bootstrap_done(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        self.section("Done");
        let _ = writeln!(self.terminal.stdout, "Tenant '{name}' bootstrapped.");
        self.next_step(&format!("Next: audit with `tenant doctor {name}`."));
    }

    pub fn bootstrap_summary(
        &mut self,
        name: &TenantUserName,
        command_entries: &[(Op<'_>, Option<&'static str>)],
        infra_entries: &[(Op<'_>, Option<&'static str>)],
    ) {
        let count = command_entries.len();
        let _ = writeln!(
            self.terminal.stdout,
            "About to run {count} bootstrap command(s) as tenant '{name}'."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "This will:");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} widen egress to the install-tier allowlist for the duration"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} run each command below as '{name}', stopping on the first failure"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} narrow egress back to runtime tier on completion (even if a command fails)"
        );
        let _ = writeln!(self.terminal.stdout);
        if self.verbose && !infra_entries.is_empty() {
            let _ = writeln!(
                self.terminal.stdout,
                "Firewall reapply (widen to install tier):"
            );
            let _ = writeln!(self.terminal.stdout);
            self.render_plan_block(infra_entries);
            let _ = writeln!(self.terminal.stdout);
        }
        // Always-shown command list — the honesty backstop.
        let _ = writeln!(self.terminal.stdout, "Commands to run:");
        let _ = writeln!(self.terminal.stdout);
        self.render_plan_block(command_entries);
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(
            self.terminal.stdout,
            "Sudo needed for: firewall install, exec, firewall narrow."
        );
        let _ = writeln!(self.terminal.stdout);
    }

    pub fn bootstrap_nothing_declared(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stdout,
            "Tenant '{name}' declares no bootstrap commands \u{2014} nothing to run."
        );
    }

    /// Names the command itself; the `ExecAsUser` label would only say `sh`.
    pub fn bootstrap_command_ran(&mut self, name: &TenantUserName, command: &str) {
        if self.dry_run {
            return;
        }
        self.ok(&format!("Ran as '{name}': {command}"));
    }

    pub fn bootstrap_command_failed(&mut self, name: &TenantUserName, command: &str, code: i32) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: bootstrap command failed for '{name}' (exit {code}): {command}"
        );
    }

    pub fn bootstrap_exec_failed(&mut self, name: &TenantUserName, err: &AccountError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to run bootstrap command as '{name}': {err}"
        );
    }

    pub fn bootstrap_narrow_failed(
        &mut self,
        name: &TenantUserName,
        _err: &super::tenants::ModeError,
    ) {
        let prefix = self.stderr_warn_prefix();
        let _ = writeln!(
            self.terminal.stderr,
            "{prefix} tenant '{name}': bootstrap commands ran, but the firewall was not narrowed \u{2014} install-tier widening still in effect; run `tenant mode {name} runtime` to recover"
        );
    }

    pub fn bootstrap_firewall_failed(&mut self, name: &TenantUserName, err: &FirewallError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to apply firewall for bootstrap of '{name}': {err}"
        );
    }

    pub fn refuse_bootstrap_share(&mut self, name: &TenantUserName, err: &ShareError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot bootstrap '{name}': {err}"
        );
    }

    pub fn bootstrap_refuse_stash_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to bootstrap '{name}': stashed password absent \
             \u{2014} run `tenant destroy {name} && tenant create {name}` to re-bootstrap"
        );
    }

    pub fn refuse_bootstrap_absent(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: cannot bootstrap '{name}': does not exist"
        );
    }

    pub fn refuse_bootstrap_not_a_tenant(
        &mut self,
        name: &TenantUserName,
        uid: UserId,
        floor: u32,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to bootstrap '{name}': UID {uid} is below tenant floor {floor}"
        );
    }

    pub fn refuse_bootstrap_system_account(&mut self, name: &TenantUserName) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: refusing to bootstrap '{name}': system account (no tenant-range UID)"
        );
    }

    pub fn bootstrap_eligibility_probe_failed(
        &mut self,
        name: &TenantUserName,
        err: &UserDirectoryError,
    ) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to check bootstrap eligibility for '{name}': {err}"
        );
    }

    pub fn bootstrap_all_summary(&mut self, host: &HostUserName, names: &[TenantUserName]) {
        let count = names.len();
        let list = names
            .iter()
            .map(|n| n.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            self.terminal.stdout,
            "About to bootstrap {count} tenant(s): {list}."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(self.terminal.stdout, "For each tenant this will:");
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} widen egress to install tier, run its declared [bootstrap] commands as the tenant, then narrow back"
        );
        let _ = writeln!(
            self.terminal.stdout,
            "  \u{2022} skip tenants that declare no commands"
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(
            self.terminal.stdout,
            "Per-tenant failures continue the walk; a final summary names the counts. \
             The invoking host is '{host}'."
        );
        let _ = writeln!(self.terminal.stdout);
        let _ = writeln!(
            self.terminal.stdout,
            "Sudo needed for: firewall install, exec, firewall narrow (per tenant)."
        );
        let _ = writeln!(self.terminal.stdout);
    }

    pub fn bootstrap_all_starting(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        if !self.dry_run {
            self.section(&format!("Bootstrapping {count} tenant(s)"));
        }
    }

    pub fn bootstrap_all_done_summary(&mut self, succeeded: usize, failed: usize, skipped: usize) {
        if self.dry_run {
            return;
        }
        if succeeded == 0 && failed == 0 && skipped == 0 {
            let _ = writeln!(
                self.terminal.stdout,
                "No tenants on this host to bootstrap."
            );
            return;
        }
        self.section("Done");
        let mut line = format!("Bootstrapped {succeeded} tenant(s)");
        if skipped > 0 {
            line.push_str(&format!("; {skipped} skipped (no commands)"));
        }
        if failed > 0 {
            line.push_str(&format!("; {failed} failed"));
        }
        line.push('.');
        let _ = writeln!(self.terminal.stdout, "{line}");
    }

    pub fn bootstrap_walk_nothing_declared(&mut self, name: &TenantUserName) {
        if self.dry_run {
            return;
        }
        self.next_step(&format!(
            "{name}: no bootstrap commands declared — skipped."
        ));
    }

    pub fn bootstrap_all_enumeration_failed(&mut self, err: &UserDirectoryError) {
        let _ = writeln!(
            self.terminal.stderr,
            "tenant: failed to enumerate tenants for bootstrap: {err}"
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

    /// No blank lines between entries (a 14-entry create plan gets tall). Bold, not
    /// colored, `sudo`: color is reserved for severity.
    fn render_plan_block(&mut self, plan: &[(Op<'_>, Option<&'static str>)]) {
        for (op, annotation) in plan {
            let intent = op.intent_label();
            let shell = op.describe_via(self.machine);
            let intent_line = match annotation {
                Some(note) => format!("  \u{2022} {intent}  # {note}"),
                None => format!("  \u{2022} {intent}"),
            };
            let _ = writeln!(self.terminal.stdout, "{intent_line}");
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
