// Shared helpers for tests/cli_*.rs; each binary uses a subset, hence `allow(dead_code)`.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::io::Write;

use clap::Parser;

use crate::adapters::NeverHostMachine;
use crate::adapters::{StubHostMachine, StubUserDirectory};

use tenant::Cli;
use tenant::domain::{GroupId, UserDirectoryError, UserId};

/// Mirrors clap's routing: help/version → stdout (exit 0), parse errors → stderr (exit 2).
fn parse_cli(args: &[&str], stdout: &mut Vec<u8>, stderr: &mut Vec<u8>) -> Result<Cli, u8> {
    let argv = std::iter::once(OsString::from("tenant")).chain(args.iter().map(OsString::from));
    Cli::try_parse_from(argv).map_err(|e| {
        let to_stderr = e.use_stderr();
        let target: &mut dyn Write = if to_stderr { stderr } else { stdout };
        let _ = write!(target, "{e}");
        e.exit_code() as u8
    })
}

/// First call fails; later calls use the snapshot.
pub fn directory_fail_once() -> RefCell<VecDeque<Option<UserDirectoryError>>> {
    let err = UserDirectoryError::Spawn(io::Error::other("synthetic"));
    RefCell::new(VecDeque::from([Some(err)]))
}

/// First call uses the snapshot, second fails: reaches `destroy_uid_lookup_failed` past
/// `destroy_eligibility`'s own `uid_for` call.
pub fn directory_fail_on_second_call() -> RefCell<VecDeque<Option<UserDirectoryError>>> {
    let err = UserDirectoryError::Spawn(io::Error::other("synthetic"));
    RefCell::new(VecDeque::from([None, Some(err)]))
}

/// Returned by `StubHostMachine::new()` and `NeverHostMachine`; keeps host-derived paths deterministic.
pub const TEST_HOST: &str = "operator";

pub const STOCK_PF_CONF: &str = "scrub-anchor \"com.apple/*\"\n\
nat-anchor \"com.apple/*\"\n\
rdr-anchor \"com.apple/*\"\n\
dummynet-anchor \"com.apple/*\"\n\
anchor \"com.apple/*\"\n\
load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n";

pub fn anchor_ref_lines(name: &str) -> String {
    format!(
        "anchor \"tenant-{name}\"\nload anchor \"tenant-{name}\" from \"/etc/pf.anchors/tenant-{name}\"\n"
    )
}

/// `Reporter::section` divider at colors-off, width 80.
pub fn section_line(title: &str) -> String {
    tenant::ansi::rule(title, 80)
}

/// Section opening, `✓ <label>` per check, `─── Done ───`, closing line.
pub fn real_success_stdout(opening_title: &str, checks: &[&str], closing: &str) -> String {
    real_success_stdout_with_breadcrumb(opening_title, checks, closing, None)
}

pub fn real_success_stdout_with_breadcrumb(
    opening_title: &str,
    checks: &[&str],
    closing: &str,
    breadcrumb: Option<&str>,
) -> String {
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
    if let Some(line) = breadcrumb {
        out.push_str(line);
        out.push('\n');
    }
    out
}

pub fn create_breadcrumb(name: &str) -> String {
    format!(
        "Next: edit ~/.config/tenant/profiles/{name}.toml and run `tenant reload {name}` to apply changes."
    )
}

pub fn mode_breadcrumb(name: &str) -> String {
    format!(
        "Next: enter the tenant with `tenant shell {name}` \u{2014} the firewall auto-narrows back to runtime tier on entry."
    )
}

pub fn inbound_breadcrumb(name: &str) -> String {
    format!(
        "Next: enter the tenant with `tenant shell {name}` \u{2014} inbound loopback auto-narrows back to restricted on entry."
    )
}

pub fn reload_breadcrumb(name: &str) -> String {
    format!("Next: audit with `tenant doctor {name}`.")
}

/// No Done section or closing line: only the ✓ lines that succeeded before the failure.
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

/// Colors-off `Plan (commands to execute):` block, spliced before "Sudo needed for:".
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

/// `EnsureCoworkDir`'s four substrate lines, indented under one plan bullet.
pub fn cowork_dir_shell_lines(name: &str) -> String {
    let path = format!("/Users/Shared/tenants/{name}");
    let group = format!("{name}-tenant-share");
    format!(
        "sudo mkdir -p {path}\n      \
         sudo chown {TEST_HOST}:{group} {path}\n      \
         sudo chmod 2770 {path}\n      \
         sudo chmod -R +a \"group:{group} allow \
         read,write,execute,delete,append,file_inherit,directory_inherit\" {path}",
    )
}

/// The 14 `tenant create <name> -v` plan entries.
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
            format!("Ensure co-working directory at /Users/Shared/tenants/{name}"),
            cowork_dir_shell_lines(name),
            None,
        ),
        (
            format!("Create keychain for tenant '{name}'"),
            format!("sudo -iu {name} security create-keychain -p <password> tenant.keychain-db"),
            None,
        ),
        (
            format!("Set tenant '{name}' default keychain to tenant.keychain-db"),
            format!("sudo -iu {name} security default-keychain -s tenant.keychain-db"),
            None,
        ),
        (
            format!("Add tenant.keychain-db to tenant '{name}' search list"),
            format!("sudo -iu {name} security list-keychains -s tenant.keychain-db"),
            None,
        ),
        (
            format!("Disable auto-lock on tenant '{name}' keychain"),
            format!("sudo -iu {name} security set-keychain-settings tenant.keychain-db"),
            None,
        ),
        (
            format!("Stash tenant '{name}' password in operator keychain"),
            format!("security add-generic-password -U -a {name} -s tenant-{name} -w <password>"),
            None,
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

pub fn verbose_plan_section_owned(entries: &[(String, String, Option<&'static str>)]) -> String {
    let borrowed: Vec<(&str, &str, Option<&str>)> = entries
        .iter()
        .map(|(i, s, a)| (i.as_str(), s.as_str(), *a))
        .collect();
    verbose_plan_section(&borrowed)
}

pub fn create_verbose_plan_block(name: &str, uid: u32, gid: u32) -> String {
    verbose_plan_section_owned(&create_verbose_plan_entries(name, uid, gid))
}

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
            format!("Remove tenant '{name}' password from operator keychain"),
            format!("security delete-generic-password -a {name} -s tenant-{name}"),
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

/// Orphan-group path: no user-removal steps, but the keychain stash is still cleaned.
pub fn orphan_verbose_plan_entries(name: &str) -> Vec<(String, String, Option<&'static str>)> {
    vec![
        (
            format!("Remove host '{TEST_HOST}' from share group '{name}-tenant-share'"),
            format!("sudo dseditgroup -o edit -n . -d {TEST_HOST} -t user {name}-tenant-share"),
            None,
        ),
        (
            format!("Remove tenant '{name}' password from operator keychain"),
            format!("security delete-generic-password -a {name} -s tenant-{name}"),
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

/// `Reporter::create_summary` plus the dry-run confirm preview; `plan_section` splices in
/// before "Sudo needed for:".
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
         \u{2022} refresh tenant-side symlinks for declared shares\n{install_tail}\
         \n\
         {plan}\
         Sudo needed for: firewall install.\n\
         \n\
         (Real run would prompt: Proceed? [Y/n])\n",
    )
}

pub fn inbound_dry_run_block(name: &str, level: &str, plan_section: Option<&str>) -> String {
    let plan = plan_section.unwrap_or("");
    let re_render = if level == "permissive" {
        "re-render the firewall anchor opening all inbound loopback (TCP) ports"
    } else {
        "re-render the firewall anchor restricting inbound loopback to profile-declared ports"
    };
    let permissive_tail = if level == "permissive" {
        format!(
            "\nThe widened inbound posture persists until 'tenant inbound {name} restricted' (narrow) or 'tenant shell {name}' (auto-narrow on entry).\n",
        )
    } else {
        String::new()
    };
    format!(
        "About to apply inbound '{level}' to tenant '{name}'.\n\
         \n\
         This will:\n  \
         \u{2022} {re_render}\n  \
         \u{2022} reload pf\n  \
         \u{2022} ensure host '{TEST_HOST}' is a member of '{name}-tenant-share' (idempotent catch-up)\n  \
         \u{2022} refresh tenant-side symlinks for declared shares\n{permissive_tail}\
         \n\
         {plan}\
         Sudo needed for: firewall install.\n\
         \n\
         (Real run would prompt: Proceed? [Y/n])\n",
    )
}

/// Shell has no prompt, so no `(Real run would prompt: …)` line.
pub fn shell_summary_block(name: &str) -> String {
    format!(
        "About to enter tenant '{name}'.\n\
         \n\
         This will:\n  \
         \u{2022} narrow the firewall to runtime tier (auto-narrow)\n  \
         \u{2022} ensure host '{TEST_HOST}' is a member of '{name}-tenant-share' (idempotent catch-up)\n  \
         \u{2022} refresh tenant-side symlinks for declared shares\n  \
         \u{2022} launch an interactive login shell as '{name}'\n\
         \n\
         Sudo needed for: firewall narrow, tenant-side symlinks, login.\n\
         \n",
    )
}

/// `mode` is "runtime" or "install" (install adds the widen + narrow-on-finally bullets).
pub fn shell_command_summary_block(name: &str, mode: &str, argv: &str) -> String {
    let (headline_suffix, entry_bullet, finally_bullet, sudo_line) = if mode == "install" {
        (
            " (mode: install)",
            "widen the firewall to install tier (narrows back to runtime on completion)",
            Some("narrow the firewall to runtime tier (always \u{2014} even if the command fails)"),
            "Sudo needed for: firewall install, tenant-side symlinks, exec, firewall narrow.",
        )
    } else {
        (
            "",
            "ensure the firewall is at runtime tier (auto-narrow; idempotent if already there)",
            None,
            "Sudo needed for: firewall install, tenant-side symlinks, exec.",
        )
    };
    let mut s = format!(
        "About to run a command as tenant '{name}'{headline_suffix}.\n\
         \n\
         This will:\n  \
         \u{2022} {entry_bullet}\n  \
         \u{2022} ensure host '{TEST_HOST}' is a member of '{name}-tenant-share' (idempotent catch-up)\n  \
         \u{2022} refresh tenant-side symlinks for declared shares\n  \
         \u{2022} run as '{name}': {argv}\n",
    );
    if let Some(finally) = finally_bullet {
        s.push_str(&format!("  \u{2022} {finally}\n"));
    }
    s.push_str(&format!("\n{sudo_line}\n\n"));
    s
}

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

pub fn run_with(stub: StubUserDirectory, args: &[&str]) -> (u8, String, String) {
    let machine = NeverHostMachine;
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
    let cli = match parse_cli(args, &mut stdout, &mut stderr) {
        Ok(cli) => cli,
        Err(code) => {
            return (
                code,
                String::from_utf8_lossy(&stdout).into_owned(),
                String::from_utf8_lossy(&stderr).into_owned(),
            );
        }
    };
    let terminal = tenant::Terminal {
        stdout: &mut stdout,
        stderr: &mut stderr,
        stdin: &mut stdin,
        stdin_is_tty: false, // stdin not a TTY → confirm auto-proceeds
        colors: tenant::ansi::Colors::default(),
    };
    let code = tenant::run(cli, &stub, &machine, terminal);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

pub fn run_with_exec(
    stub: StubUserDirectory,
    exec: &StubHostMachine,
    args: &[&str],
) -> (u8, String, String) {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
    let cli = match parse_cli(args, &mut stdout, &mut stderr) {
        Ok(cli) => cli,
        Err(code) => {
            return (
                code,
                String::from_utf8_lossy(&stdout).into_owned(),
                String::from_utf8_lossy(&stderr).into_owned(),
            );
        }
    };
    let terminal = tenant::Terminal {
        stdout: &mut stdout,
        stderr: &mut stderr,
        stdin: &mut stdin,
        stdin_is_tty: false,
        colors: tenant::ansi::Colors::default(),
    };
    let code = tenant::run(cli, &stub, exec, terminal);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// Simulates a TTY so the confirm prompt fires; `stdin_content` is the operator's keystrokes.
pub fn run_with_stdin(
    stub: StubUserDirectory,
    exec: &StubHostMachine,
    args: &[&str],
    stdin_content: &[u8],
) -> (u8, String, String) {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut stdin = std::io::Cursor::new(stdin_content.to_vec());
    let cli = match parse_cli(args, &mut stdout, &mut stderr) {
        Ok(cli) => cli,
        Err(code) => {
            return (
                code,
                String::from_utf8_lossy(&stdout).into_owned(),
                String::from_utf8_lossy(&stderr).into_owned(),
            );
        }
    };
    let terminal = tenant::Terminal {
        stdout: &mut stdout,
        stderr: &mut stderr,
        stdin: &mut stdin,
        stdin_is_tty: true, // simulate TTY so confirm prompts fire
        colors: tenant::ansi::Colors::default(),
    };
    let code = tenant::run(cli, &stub, exec, terminal);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

// TODO(smell): rename `stub_with_tenant` (user only) / `make_tenant_stub_reader` (user + share group) so names say what differs.
/// Tenant user at UID 600, no share group.
pub fn stub_with_tenant(name: &str) -> StubUserDirectory {
    StubUserDirectory {
        users: vec![name.to_string()],
        uid_by_name: [(name.to_string(), UserId(600))].into_iter().collect(),
        ..Default::default()
    }
}

/// `shares` triples are `(host_path, mode, tenant_path)`; empty emits no `[[shares]]`.
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

/// Empty `commands` emits no `[bootstrap]` block.
pub fn profile_with_bootstrap(runtime: &[&str], install: &[&str], commands: &[&str]) -> String {
    let base = profile_with_hosts(runtime, install);
    if commands.is_empty() {
        return base;
    }
    let lines = commands
        .iter()
        .map(|c| format!("  \"{c}\","))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{base}\n[bootstrap]\ncommands = [\n{lines}\n]\n")
}

pub fn egress(hosts: &[&str]) -> Vec<tenant::firewall::EgressHost> {
    hosts
        .iter()
        .map(|h| tenant::firewall::EgressHost {
            host: h.to_string(),
            ports: vec![443],
        })
        .collect()
}

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

/// Tenant user + share group at the floor (Destroyable).
pub fn make_tenant_stub_reader(name: &str) -> StubUserDirectory {
    StubUserDirectory {
        users: vec![name.to_string()],
        groups: vec![format!("{name}-tenant-share")],
        uid_by_name: [(name.to_string(), UserId(600))].into_iter().collect(),
        gid_by_name: [(format!("{name}-tenant-share"), GroupId(600))]
            .into_iter()
            .collect(),
        ..Default::default()
    }
}

pub fn make_two_tenant_stub_reader() -> StubUserDirectory {
    StubUserDirectory {
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

pub const SUDO_NEEDS_TERMINAL_REFUSAL: &str = "tenant: this verb needs sudo and no terminal is \
     attached \u{2014} run it in your terminal, or run 'sudo -v' in this session first\n";

pub fn profile_with_permissive_posture(runtime: &[&str], install: &[&str]) -> String {
    format!(
        "{}\n[inbound]\nposture = \"permissive\"\n",
        profile_with_hosts(runtime, install)
    )
}

pub fn refuse_restricted_on_permissive_profile(name: &str) -> String {
    format!(
        "tenant: cannot narrow '{name}' to restricted inbound: its profile declares \
         [inbound] posture = \"permissive\" \u{2014} set it to \"restricted\" (or remove it) in \
         ~/.config/tenant/profiles/{name}.toml or the include that sets it, then run \
         `tenant reload {name}`\n"
    )
}
