// Shared helpers for per-verb integration-test files. Each `tests/cli_*.rs`
// declares `mod common;` and pulls these in via `use common::*;`. Cargo
// treats this `mod.rs` under a directory as a non-binary module (it doesn't
// try to run it as its own test binary). Because individual cli_*.rs files
// only use a subset of these helpers, `#![allow(dead_code)]` keeps the
// per-binary unused-item warnings quiet.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;

use tenant::adapters::stub_host_accounts::StubHostAccounts;
use tenant::adapters::stub_host_machine::StubHostMachine;
use tenant::domain::{
    AccountError, AccountOp, AccountsError, FirewallError, FirewallOp, GroupId, GroupName,
    HostMachine, HostUserName, ProfileOp, TenantUserName, UserId,
};

/// Single-failure queue: returns Err on the first call to the matching
/// `HostAccounts` method, snapshots thereafter. The default fixture for
/// tests that drive Reporter's `*_eligibility_probe_failed` /
/// `*_allocation_failed` / `*_enumeration_failed` / `*_conflict_probe_failed`
/// frames — one call site, one failure.
pub fn accounts_fail_once() -> RefCell<VecDeque<Option<AccountsError>>> {
    let err = AccountsError::Spawn(io::Error::other("synthetic"));
    RefCell::new(VecDeque::from([Some(err)]))
}

/// Pass-then-fail queue: first call succeeds (uses the snapshot), second
/// fails. The fixture for `destroy_uid_lookup_failed` — the dispatch
/// surface where `accounts.uid_for` is called AFTER `destroy_eligibility`
/// already consumed its own `uid_for` call. Without skipping the first
/// call, the failure routes to `destroy_eligibility_probe_failed`.
pub fn accounts_fail_on_second_call() -> RefCell<VecDeque<Option<AccountsError>>> {
    let err = AccountsError::Spawn(io::Error::other("synthetic"));
    RefCell::new(VecDeque::from([None, Some(err)]))
}

/// Default host machine for tests that should not reach the exec stage —
/// validation failures, conflicts, and dry-run paths. Panics on any
/// substrate call, so any accidental invocation from a path that's
/// meant to be no-op surfaces loudly instead of being silently absorbed.
pub struct NeverHostMachine;
impl HostMachine for NeverHostMachine {
    fn describe_account(&self, op: &AccountOp) -> String {
        panic!("host machine unexpectedly invoked (describe_account) with op: {op:?}");
    }
    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        panic!("host machine unexpectedly invoked (execute_account) with op: {op:?}");
    }
    fn login(&self, name: &TenantUserName) -> Result<i32, AccountError> {
        panic!("host machine unexpectedly invoked (login) with name: {name:?}");
    }
    fn exec_as_tenant(&self, name: &TenantUserName, argv: &[String]) -> Result<i32, AccountError> {
        panic!("host machine unexpectedly invoked (exec_as_tenant): name={name:?} argv={argv:?}");
    }
    fn describe_profile(&self, op: &ProfileOp) -> String {
        panic!("host machine unexpectedly invoked (describe_profile) with op: {op:?}");
    }
    fn execute_profile(&self, op: &ProfileOp) -> Result<(), tenant::profile::ProfileError> {
        panic!("host machine unexpectedly invoked (execute_profile) with op: {op:?}");
    }
    fn read_profile(&self, name: &TenantUserName) -> Result<String, tenant::profile::ProfileError> {
        panic!("host machine unexpectedly invoked (read_profile) with name: {name:?}");
    }
    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        panic!("host machine unexpectedly invoked (read_pf_conf)");
    }
    fn describe_firewall(&self, op: &FirewallOp) -> String {
        panic!("host machine unexpectedly invoked (describe_firewall) with op: {op:?}");
    }
    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError> {
        panic!("host machine unexpectedly invoked (execute_firewall) with op: {op:?}");
    }
    fn probe_access_as_tenant(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
        mode: tenant::domain::AccessMode,
    ) -> Result<tenant::domain::AccessOutcome, tenant::domain::ProbeError> {
        panic!(
            "host machine unexpectedly invoked (probe_access_as_tenant): name={name:?} path={path:?} mode={mode:?}"
        );
    }
    fn read_env_policy(&self) -> Result<String, tenant::domain::HostFileError> {
        panic!("host machine unexpectedly invoked (read_env_policy)");
    }
    fn read_kernel_pf_rules(
        &self,
        name: &TenantUserName,
    ) -> Result<String, tenant::domain::FirewallError> {
        panic!("host machine unexpectedly invoked (read_kernel_pf_rules): name={name:?}");
    }
    fn read_pam_sudo(&self) -> Result<String, tenant::domain::HostFileError> {
        panic!("host machine unexpectedly invoked (read_pam_sudo)");
    }
    fn read_pf_status(&self) -> Result<String, tenant::domain::FirewallError> {
        panic!("host machine unexpectedly invoked (read_pf_status)");
    }
    fn read_anchor_body(
        &self,
        name: &TenantUserName,
    ) -> Result<String, tenant::domain::HostFileError> {
        panic!("host machine unexpectedly invoked (read_anchor_body): name={name:?}");
    }
    fn describe_acl(&self, op: &tenant::domain::AclOp) -> String {
        panic!("host machine unexpectedly invoked (describe_acl) with op: {op:?}");
    }
    fn execute_acl(&self, op: &tenant::domain::AclOp) -> Result<(), tenant::domain::AclError> {
        panic!("host machine unexpectedly invoked (execute_acl) with op: {op:?}");
    }
    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<tenant::domain::PathKind, tenant::domain::ProbeError> {
        panic!("host machine unexpectedly invoked (tenant_path_kind): name={name:?} path={path:?}");
    }
    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, tenant::domain::ProbeError> {
        panic!("host machine unexpectedly invoked (read_host_acl): path={path:?}");
    }
    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError> {
        panic!("host machine unexpectedly invoked (host_in_group): host={host:?} group={group:?}");
    }
}

/// Host identity passed to `tenant::run`. Production reads `$USER`; tests
/// use a fixed placeholder so the doctor-verb's curated path expansion
/// (`/Users/<host>/...`) is deterministic across test runs.
pub const TEST_HOST: &str = "operator";

/// Expected `─── <title> ───...` section divider line emitted by
/// `Reporter::section` under colors=off, width 80. Centralized so tests
/// pin the wireframe without re-encoding the padding math at every
/// call site; if Reporter's section width or dash count ever changes,
/// both sides move together via `tenant::ansi::rule`.
pub fn section_line(title: &str) -> String {
    tenant::ansi::rule(title, 80)
}

/// Build the full real-mode-success stdout block: section divider
/// opening, `✓ <label>` for each step, `─── Done ───` section,
/// closing line. Tests pass the ordered list of business labels they
/// expect to see; the helper handles framing. Trailing newline included.
pub fn real_success_stdout(opening_title: &str, checks: &[&str], closing: &str) -> String {
    let mut out = section_line(opening_title);
    out.push('\n');
    for check in checks {
        out.push_str("✓ ");
        out.push_str(check);
        out.push('\n');
    }
    out.push_str(&section_line("Done"));
    out.push('\n');
    out.push_str(closing);
    out.push('\n');
    out
}

/// Real-mode-failure stdout block (no Done section, no closing line
/// — the verb didn't complete). Only the section opening + ✓ lines
/// for steps that actually succeeded before the failure.
pub fn real_failure_stdout(opening_title: &str, checks: &[&str]) -> String {
    let mut out = section_line(opening_title);
    out.push('\n');
    for check in checks {
        out.push_str("✓ ");
        out.push_str(check);
        out.push('\n');
    }
    out
}

/// Render the verbose plan section as it appears inside a summary
/// (after the bullets, before "Sudo needed for:"). Each
/// `(intent, shell, annotation)` entry becomes:
///
/// ```text
///   • <intent>[  # <annotation>]
///       <shell>
/// ```
///
/// with no blank line between entries (the column-2 `•` + column-6
/// shell indent give enough visual contrast). The block is wrapped in
/// `Plan (commands to execute):\n\n<entries>\n` and a trailing newline
/// so the caller can splice it directly between the summary bullets
/// and the "Sudo needed for:" line. Tests pass `Colors::default()` so
/// the privilege-aware dim escapes don't enter the byte form — this
/// helper renders only the colors-off shape.
pub fn verbose_plan_section(entries: &[(&str, &str, Option<&str>)]) -> String {
    let mut out = String::from("Plan (commands to execute):\n\n");
    for (intent, shell, annotation) in entries {
        match annotation {
            Some(note) => out.push_str(&format!("  \u{2022} {intent}  # {note}\n")),
            None => out.push_str(&format!("  \u{2022} {intent}\n")),
        }
        out.push_str(&format!("      {shell}\n"));
    }
    out.push('\n');
    out
}

/// Pre-built plan entries for the `create` verb in the
/// intent-leads-shell-follows layout. Returns the 14-entry list every
/// `tenant create <name> -v` invocation expects (UID/GID substituted),
/// for splicing into a verbose summary via `verbose_plan_section`.
pub fn create_verbose_plan_entries(
    name: &str,
    uid: u32,
    gid: u32,
) -> Vec<(String, String, Option<&'static str>)> {
    vec![
        (
            format!("Create share group '{name}-tenant-share' (GID {gid})"),
            format!("sudo dseditgroup -o create -n . -i {gid} {name}-tenant-share"),
            None,
        ),
        (
            format!("Add host '{TEST_HOST}' to share group '{name}-tenant-share'"),
            format!("sudo dseditgroup -o edit -n . -a {TEST_HOST} -t user {name}-tenant-share"),
            None,
        ),
        (
            format!("Create user account '{name}' (UID {uid}, GID {gid})"),
            format!(
                "sudo sysadminctl -addUser {name} -fullName \"Tenant: {name}\" -shell /bin/zsh -UID {uid} -GID {gid}"
            ),
            None,
        ),
        (
            format!("Remove share group '{name}-tenant-share'"),
            format!("sudo dseditgroup -o delete -n . {name}-tenant-share"),
            Some("on rollback"),
        ),
        (
            format!("Write profile config at ~/.config/tenant/profiles/{name}.toml"),
            format!("tee ~/.config/tenant/profiles/{name}.toml < default.toml"),
            None,
        ),
        (
            "Back up /etc/pf.conf to /etc/pf.conf.tenant-backup".to_string(),
            "sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup".to_string(),
            None,
        ),
        (
            format!("Install firewall anchor at /etc/pf.anchors/tenant-{name}"),
            format!("sudo tee /etc/pf.anchors/tenant-{name} < anchor.body"),
            None,
        ),
        (
            "Update /etc/pf.conf".to_string(),
            "sudo tee /etc/pf.conf < updated.conf".to_string(),
            None,
        ),
        (
            "Reload pf ruleset".to_string(),
            "sudo pfctl -f /etc/pf.conf".to_string(),
            None,
        ),
        (
            "Restore /etc/pf.conf from backup".to_string(),
            "sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf".to_string(),
            Some("on reload failure"),
        ),
        (
            format!("Remove firewall anchor at /etc/pf.anchors/tenant-{name}"),
            format!("sudo rm -f /etc/pf.anchors/tenant-{name}"),
            Some("on reload failure"),
        ),
        (
            "Reload pf ruleset".to_string(),
            "sudo pfctl -f /etc/pf.conf".to_string(),
            Some("on reload failure"),
        ),
        (
            format!("Flush kernel rules under anchor 'tenant-{name}'"),
            format!("sudo pfctl -a tenant-{name} -F all"),
            Some("on reload failure"),
        ),
        (
            "Enable pf host-wide".to_string(),
            "sudo pfctl -e".to_string(),
            None,
        ),
    ]
}

/// Borrow-shape adapter: `verbose_plan_section` takes `&[(&str, &str, Option<&str>)]`
/// for shared use across owned (above) and literal-borrowed call sites.
/// Helper that converts the owned vec from `create_verbose_plan_entries`
/// into the borrowed-slice shape `verbose_plan_section` accepts.
pub fn verbose_plan_section_owned(entries: &[(String, String, Option<&'static str>)]) -> String {
    let borrowed: Vec<(&str, &str, Option<&str>)> = entries
        .iter()
        .map(|(i, s, a)| (i.as_str(), s.as_str(), *a))
        .collect();
    verbose_plan_section(&borrowed)
}

/// Pre-built `create_verbose_plan_entries` already spliced into a
/// `verbose_plan_section` block — convenience for the common case.
pub fn create_verbose_plan_block(name: &str, uid: u32, gid: u32) -> String {
    verbose_plan_section_owned(&create_verbose_plan_entries(name, uid, gid))
}

/// Pre-built plan entries for the `destroy` verb in the
/// intent-leads-shell-follows layout (11 entries).
pub fn destroy_verbose_plan_entries(name: &str) -> Vec<(String, String, Option<&'static str>)> {
    vec![
        (
            format!("Remove user account '{name}' (home moved to /Users/Deleted Users/{name})"),
            format!("sudo sysadminctl -deleteUser {name}"),
            None,
        ),
        (
            format!("Probe for residue user record '{name}'"),
            format!("dscl . -read /Users/{name}"),
            None,
        ),
        (
            format!("Clean up residue user record '{name}'"),
            format!("sudo dscl . -delete /Users/{name}"),
            None,
        ),
        (
            format!("Remove host '{TEST_HOST}' from share group '{name}-tenant-share'"),
            format!("sudo dseditgroup -o edit -n . -d {TEST_HOST} -t user {name}-tenant-share"),
            None,
        ),
        (
            format!("Remove share group '{name}-tenant-share'"),
            format!("sudo dseditgroup -o delete -n . {name}-tenant-share"),
            None,
        ),
        (
            format!("Remove profile config at ~/.config/tenant/profiles/{name}.toml"),
            format!("rm -f ~/.config/tenant/profiles/{name}.toml"),
            None,
        ),
        (
            "Back up /etc/pf.conf to /etc/pf.conf.tenant-backup".to_string(),
            "sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup".to_string(),
            None,
        ),
        (
            format!("Remove firewall anchor at /etc/pf.anchors/tenant-{name}"),
            format!("sudo rm -f /etc/pf.anchors/tenant-{name}"),
            None,
        ),
        (
            "Update /etc/pf.conf".to_string(),
            "sudo tee /etc/pf.conf < updated.conf".to_string(),
            None,
        ),
        (
            "Reload pf ruleset".to_string(),
            "sudo pfctl -f /etc/pf.conf".to_string(),
            None,
        ),
        (
            format!("Flush kernel rules under anchor 'tenant-{name}'"),
            format!("sudo pfctl -a tenant-{name} -F all"),
            None,
        ),
    ]
}

pub fn destroy_verbose_plan_block(name: &str) -> String {
    verbose_plan_section_owned(&destroy_verbose_plan_entries(name))
}

/// Pre-built plan entries for the orphan-group convergence path (8
/// entries; no user-removal steps).
pub fn orphan_verbose_plan_entries(name: &str) -> Vec<(String, String, Option<&'static str>)> {
    vec![
        (
            format!("Remove host '{TEST_HOST}' from share group '{name}-tenant-share'"),
            format!("sudo dseditgroup -o edit -n . -d {TEST_HOST} -t user {name}-tenant-share"),
            None,
        ),
        (
            format!("Remove share group '{name}-tenant-share'"),
            format!("sudo dseditgroup -o delete -n . {name}-tenant-share"),
            None,
        ),
        (
            format!("Remove profile config at ~/.config/tenant/profiles/{name}.toml"),
            format!("rm -f ~/.config/tenant/profiles/{name}.toml"),
            None,
        ),
        (
            "Back up /etc/pf.conf to /etc/pf.conf.tenant-backup".to_string(),
            "sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup".to_string(),
            None,
        ),
        (
            format!("Remove firewall anchor at /etc/pf.anchors/tenant-{name}"),
            format!("sudo rm -f /etc/pf.anchors/tenant-{name}"),
            None,
        ),
        (
            "Update /etc/pf.conf".to_string(),
            "sudo tee /etc/pf.conf < updated.conf".to_string(),
            None,
        ),
        (
            "Reload pf ruleset".to_string(),
            "sudo pfctl -f /etc/pf.conf".to_string(),
            None,
        ),
        (
            format!("Flush kernel rules under anchor 'tenant-{name}'"),
            format!("sudo pfctl -a tenant-{name} -F all"),
            None,
        ),
    ]
}

pub fn orphan_verbose_plan_block(name: &str) -> String {
    verbose_plan_section_owned(&orphan_verbose_plan_entries(name))
}

/// Dry-run summary block for `tenant create <name> --dry-run`.
/// Matches `Reporter::create_summary` byte-for-byte, then appends the
/// "(Real run would prompt: Proceed? [Y/n])" preview line that
/// `Reporter::confirm` emits in dry-run mode.
///
/// `plan_section` splices the verbose "Plan (commands to execute):"
/// block in BEFORE the "Sudo needed for:" line. Pass `None` for the
/// standard-mode dry-run (no plan); pass
/// `Some(verbose_plan_section(&entries))` for the verbose-mode shape.
pub fn create_dry_run_block(name: &str, uid: u32, gid: u32, plan_section: Option<&str>) -> String {
    let plan = plan_section.unwrap_or("");
    format!(
        "About to create tenant '{name}' \u{2014} an isolated macOS account with restricted network egress.\n\
         \n\
         This will:\n  \
         \u{2022} create user account '{name}' (UID {uid}) and group '{name}-tenant-share' (GID {gid})\n  \
         \u{2022} add host '{TEST_HOST}' to '{name}-tenant-share' so files the tenant creates in RW shares stay host-writable\n  \
         \u{2022} install a per-tenant firewall anchor (egress blocked by default; allowlist hosts declared in the profile)\n  \
         \u{2022} write profile config at ~/.config/tenant/profiles/{name}.toml\n  \
         \u{2022} enable pf host-wide if not already enabled\n\
         \n\
         {plan}\
         Sudo needed for: user provisioning, firewall install.\n\
         \n\
         (Real run would prompt: Proceed? [Y/n])\n",
    )
}

/// Dry-run summary block for `tenant destroy <name> --dry-run` (full
/// destroy path, default-N prompt preview). `plan_section` optionally
/// splices the verbose plan block.
pub fn destroy_dry_run_block(name: &str, uid: u32, plan_section: Option<&str>) -> String {
    let plan = plan_section.unwrap_or("");
    format!(
        "About to destroy tenant '{name}' (UID {uid}).\n\
         \n\
         This will:\n  \
         \u{2022} remove the user account\n  \
         \u{2022} move /Users/{name} \u{2192} /Users/Deleted Users/{name} (recoverable until /Users/Deleted Users is emptied or the host is rebuilt)\n  \
         \u{2022} remove host '{TEST_HOST}' from '{name}-tenant-share'\n  \
         \u{2022} remove group '{name}-tenant-share'\n  \
         \u{2022} remove the firewall anchor and flush its kernel rules\n  \
         \u{2022} remove profile config at ~/.config/tenant/profiles/{name}.toml\n\
         \n\
         {plan}\
         Sudo needed for: user removal, firewall teardown.\n\
         \n\
         (Real run would prompt: Proceed? [y/N])\n",
    )
}

/// Dry-run summary block for the orphan-group convergence path.
/// `plan_section` optionally splices the verbose plan block.
pub fn destroy_orphan_dry_run_block(name: &str, plan_section: Option<&str>) -> String {
    let plan = plan_section.unwrap_or("");
    format!(
        "About to destroy orphan group '{name}-tenant-share' for tenant '{name}'.\n\
         \n\
         This will:\n  \
         \u{2022} remove host '{TEST_HOST}' from '{name}-tenant-share' (idempotent if not a member)\n  \
         \u{2022} remove group '{name}-tenant-share'\n  \
         \u{2022} remove the firewall anchor and flush its kernel rules\n  \
         \u{2022} remove profile config at ~/.config/tenant/profiles/{name}.toml\n\
         \n\
         {plan}\
         Sudo needed for: group removal, firewall teardown.\n\
         \n\
         (Real run would prompt: Proceed? [y/N])\n",
    )
}

/// Dry-run summary block for `tenant mode <name> <level> --dry-run`.
/// `plan_section` optionally splices the verbose plan block.
pub fn mode_dry_run_block(name: &str, level: &str, plan_section: Option<&str>) -> String {
    let plan = plan_section.unwrap_or("");
    let re_render = if level == "install" {
        "re-render the firewall anchor with install-tier hosts added to the allowlist"
    } else {
        "re-render the firewall anchor at runtime tier"
    };
    let install_tail = if level == "install" {
        format!(
            "\nThe widened allowlist persists until 'tenant mode {name} runtime' (narrow) or 'tenant shell {name}' (auto-narrow on entry).\n",
        )
    } else {
        String::new()
    };
    format!(
        "About to apply mode '{level}' to tenant '{name}'.\n\
         \n\
         This will:\n  \
         \u{2022} {re_render}\n  \
         \u{2022} reload pf\n  \
         \u{2022} ensure host '{TEST_HOST}' is a member of '{name}-tenant-share' (idempotent catch-up)\n  \
         \u{2022} re-apply declared shares from the profile (idempotent)\n{install_tail}\
         \n\
         {plan}\
         Sudo needed for: firewall install.\n\
         \n\
         (Real run would prompt: Proceed? [Y/n])\n",
    )
}

/// Pre-exec summary block for `tenant shell <name>`. Emitted whenever
/// `show_summary` is true (dry-run OR TTY). Unlike the other verbs'
/// summaries, shell has no prompt, so there's no
/// `(Real run would prompt: …)` parenthetical to append. Tests splice
/// this block in BEFORE the shell-intent line (`Would shell into 'X'.`
/// in dry-run, or the section divider in real mode).
pub fn shell_summary_block(name: &str) -> String {
    format!(
        "About to enter tenant '{name}'.\n\
         \n\
         This will:\n  \
         \u{2022} narrow the firewall to runtime tier (auto-narrow)\n  \
         \u{2022} ensure host '{TEST_HOST}' is a member of '{name}-tenant-share' (idempotent catch-up)\n  \
         \u{2022} re-apply each declared share from [[shares]] in the profile\n  \
         \u{2022} launch an interactive login shell as '{name}'\n\
         \n\
         Sudo needed for: firewall narrow, share reapply, login.\n\
         \n",
    )
}

/// Pre-exec summary block for `tenant shell <name> [--mode <m>] -- <argv>`
/// (cycle-17 command form). Same `show_summary` gating as the
/// interactive form's `shell_summary_block`; no confirm prompt
/// parenthetical (Q3 lock: command form is uniform with interactive
/// shell on prompting).
///
/// `mode` is "runtime" or "install"; `argv` is the joined argv string
/// the operator typed after `--`. Runtime tier collapses the entry
/// bullet to the auto-narrow phrasing; install tier expands to the
/// widen + narrow-on-finally pair. Sudo footer expands one phrase on
/// install.
pub fn shell_command_summary_block(name: &str, mode: &str, argv: &str) -> String {
    let (headline_suffix, entry_bullet, finally_bullet, sudo_line) = if mode == "install" {
        (
            " (mode: install)",
            "widen the firewall to install tier (narrows back to runtime on completion)",
            Some("narrow the firewall to runtime tier (always \u{2014} even if the command fails)"),
            "Sudo needed for: firewall install, share reapply, exec, firewall narrow.",
        )
    } else {
        (
            "",
            "ensure the firewall is at runtime tier (auto-narrow; idempotent if already there)",
            None,
            "Sudo needed for: firewall install, share reapply, exec.",
        )
    };
    let mut s = format!(
        "About to run a command as tenant '{name}'{headline_suffix}.\n\
         \n\
         This will:\n  \
         \u{2022} {entry_bullet}\n  \
         \u{2022} ensure host '{TEST_HOST}' is a member of '{name}-tenant-share' (idempotent catch-up)\n  \
         \u{2022} re-apply each declared share from [[shares]] in the profile\n  \
         \u{2022} run as '{name}': {argv}\n",
    );
    if let Some(finally) = finally_bullet {
        s.push_str(&format!("  \u{2022} {finally}\n"));
    }
    s.push_str(&format!("\n{sudo_line}\n\n"));
    s
}

/// Dry-run summary block for single-tenant `tenant reload <name>`.
/// `plan_section` optionally splices the verbose plan block.
pub fn reload_dry_run_block(name: &str, plan_section: Option<&str>) -> String {
    let plan = plan_section.unwrap_or("");
    format!(
        "About to reload tenant '{name}' from profile.\n\
         \n\
         This will:\n  \
         \u{2022} re-render and reload the firewall anchor (runtime tier)\n  \
         \u{2022} ensure host '{TEST_HOST}' is a member of '{name}-tenant-share' (idempotent catch-up)\n  \
         \u{2022} re-apply each declared share from [[shares]] in the profile\n\
         \n\
         {plan}\
         Sudo needed for: firewall install.\n\
         \n\
         (Real run would prompt: Proceed? [Y/n])\n",
    )
}

pub fn run_with(stub: StubHostAccounts, args: &[&str]) -> (u8, String, String) {
    let machine = NeverHostMachine;
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let host = HostUserName::from(TEST_HOST);
    let terminal = tenant::Terminal {
        stdout: &mut stdout,
        stderr: &mut stderr,
        stdin: &mut stdin,
        stdin_is_tty: false, // stdin not a TTY → confirm auto-proceeds
        colors: tenant::ansi::Colors::default(),
    };
    let code = tenant::run(&args, &stub, &machine, &host, terminal);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

pub fn run_with_exec(
    stub: StubHostAccounts,
    exec: &StubHostMachine,
    args: &[&str],
) -> (u8, String, String) {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let host = HostUserName::from(TEST_HOST);
    let terminal = tenant::Terminal {
        stdout: &mut stdout,
        stderr: &mut stderr,
        stdin: &mut stdin,
        stdin_is_tty: false,
        colors: tenant::ansi::Colors::default(),
    };
    let code = tenant::run(&args, &stub, exec, &host, terminal);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// Confirm-aware test runner. Simulates a TTY stdin so the
/// confirmation prompt fires, with `stdin_content` as the operator's
/// keystrokes (one or more lines, `\n`-terminated). Use for tests that
/// exercise y/N parsing, default-Y vs default-N, and reprompt-on-bad-
/// input behavior. `run_with` / `run_with_exec` keep their auto-proceed
/// posture (stdin=empty, tty=false) so the existing test bank is
/// unaffected.
pub fn run_with_stdin(
    stub: StubHostAccounts,
    exec: &StubHostMachine,
    args: &[&str],
    stdin_content: &[u8],
) -> (u8, String, String) {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut stdin = std::io::Cursor::new(stdin_content.to_vec());
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let host = HostUserName::from(TEST_HOST);
    let terminal = tenant::Terminal {
        stdout: &mut stdout,
        stderr: &mut stderr,
        stdin: &mut stdin,
        stdin_is_tty: true, // simulate TTY so confirm prompts fire
        colors: tenant::ansi::Colors::default(),
    };
    let code = tenant::run(&args, &stub, exec, &host, terminal);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// Stub representing a tenant that exists on the host with a tenant-range
/// UID (for tests that drive the destroy verb's actual-destroy path rather
/// than its noop / refusal paths). UID 600 is the canonical floor; any
/// floor-or-above UID would do.
pub fn stub_with_tenant(name: &str) -> StubHostAccounts {
    StubHostAccounts {
        users: vec![name.to_string()],
        uid_by_name: [(name.to_string(), UserId(600))].into_iter().collect(),
        ..Default::default()
    }
}

/// Helper: profile TOML with the given runtime + install host lists
/// AND a `[[shares]]` block for share-reapply tests. Each share triple
/// is `(host_path, mode, tenant_path)`; mode is "ro" or "rw" verbatim
/// from the schema. Empty `shares` slice produces no `[[shares]]`
/// blocks (backward-compat for profiles authored before shares were
/// added to the schema).
pub fn profile_with_shares(
    runtime: &[&str],
    install: &[&str],
    shares: &[(&str, &str, &str)],
) -> String {
    let base = profile_with_hosts(runtime, install);
    if shares.is_empty() {
        return base;
    }
    let share_blocks: String = shares
        .iter()
        .map(|(host_path, mode, tenant_path)| {
            format!(
                "\n[[shares]]\nhost_path = \"{host_path}\"\nmode = \"{mode}\"\ntenant_path = \"{tenant_path}\"\n"
            )
        })
        .collect();
    format!("{base}{share_blocks}")
}

/// Helper: profile TOML with the given runtime + install host lists.
/// Tests use this to populate `with_existing_profile` content so the
/// writer's read_profile + parse + render path exercises non-empty
/// allowlist tiers without touching real fs state.
pub fn profile_with_hosts(runtime: &[&str], install: &[&str]) -> String {
    let runtime_lines = runtime
        .iter()
        .map(|h| format!("  \"{h}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let install_lines = install
        .iter()
        .map(|h| format!("  \"{h}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let runtime_block = if runtime_lines.is_empty() {
        "hosts = []".to_string()
    } else {
        format!("hosts = [\n{runtime_lines}\n]")
    };
    let install_block = if install_lines.is_empty() {
        "hosts = []".to_string()
    } else {
        format!("hosts = [\n{install_lines}\n]")
    };
    format!(
        "schema_version = 1\n\n\
         [allowlist.runtime]\n{runtime_block}\n\n\
         [allowlist.install]\n{install_block}\n"
    )
}

/// A reader where `name` is present as a Destroyable tenant (UID at floor,
/// group present). Lets dispatch reach `doctor_tenant`.
pub fn make_tenant_stub_reader(name: &str) -> StubHostAccounts {
    StubHostAccounts {
        users: vec![name.to_string()],
        groups: vec![format!("{name}-tenant-share")],
        uid_by_name: [(name.to_string(), UserId(600))].into_iter().collect(),
        gid_by_name: [(format!("{name}-tenant-share"), GroupId(600))]
            .into_iter()
            .collect(),
        ..Default::default()
    }
}

pub fn make_two_tenant_stub_reader() -> StubHostAccounts {
    StubHostAccounts {
        users: vec!["dev".to_string(), "staging".to_string()],
        groups: vec![
            "dev-tenant-share".to_string(),
            "staging-tenant-share".to_string(),
        ],
        uid_by_name: [
            ("dev".to_string(), UserId(600)),
            ("staging".to_string(), UserId(601)),
        ]
        .into_iter()
        .collect(),
        gid_by_name: [
            ("dev-tenant-share".to_string(), GroupId(600)),
            ("staging-tenant-share".to_string(), GroupId(601)),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    }
}
