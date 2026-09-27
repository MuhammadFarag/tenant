use std::path::PathBuf;

use tenant::domain::{
    AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp, KeychainError, PathKind,
    ProbeError, UserId,
};

mod adapters;
mod common;
use adapters::*;
use common::*;

// TODO(smell): DryRunHostMachine::find_stashed_password returns NotFound, so every `shell --dry-run` ends in the StashAbsent refusal (exit 64).
#[test]
fn shell_dry_run_default_shows_intent() {
    let (code, stdout, stderr) = run_with(stub_with_tenant("dev"), &["shell", "dev", "--dry-run"]);
    assert_eq!(code, 64, "exit code = {code}; stderr={stderr:?}");
    let want = format!("{}Would shell into 'dev'.\n", shell_summary_block("dev"));
    assert_eq!(stdout, want);
    assert!(
        stderr.contains("stashed password absent"),
        "expected stash-absent refusal frame; stderr={stderr:?}"
    );
}

#[test]
fn shell_dry_run_verbose_shows_mechanism() {
    // Exit 64 is the dry-run stash refusal (see the TODO(smell) at the top of this file).
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["shell", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 64);
    let want = format!(
        "{}Would shell into 'dev'.\n\
         {}",
        shell_summary_block("dev"),
        verbose_plan_section(&[
            (
                "Install firewall anchor at /etc/pf.anchors/tenant-dev",
                "sudo tee /etc/pf.anchors/tenant-dev < anchor.body",
                None,
            ),
            (
                "Update /etc/pf.conf",
                "sudo tee /etc/pf.conf < updated.conf",
                Some("only when /etc/pf.conf lacks the anchor reference"),
            ),
            ("Reload pf ruleset", "sudo pfctl -f /etc/pf.conf", None),
            (
                "Add host 'operator' to share group 'dev-tenant-share'",
                "sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share",
                None,
            ),
            ("Log in as 'dev'", "sudo -iu dev", None),
        ]),
    );
    assert_eq!(stdout, want);
}

#[test]
fn shell_real_mode_standard_emits_intent_and_invokes_exec_into() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    // No closing line: login hands control to the shell.
    let want = format!(
        "{}\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ Tenant 'dev' keychain unlocked\n",
        section_line("Entering tenant 'dev'"),
    );
    assert_eq!(stdout, want);
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(exec.logins(), vec!["dev".to_string()]);
    assert_eq!(
        exec.account_ops(),
        vec![AccountOp::AddHostToShareGroup {
            group: "dev-tenant-share".into(),
            host: "operator".into(),
        }],
        "shell auto-narrow includes only AddHost under Light scope"
    );
}

#[test]
fn shell_refuses_when_stash_absent() {
    // No `with_default_stash`: the stub's find_stashed_password returns NotFound.
    // The refusal lands after the reapply, so its ✓ lines still print.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 64, "EX_USAGE expected; stderr={stderr:?}");
    let want_stdout = format!(
        "{}\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n",
        section_line("Entering tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: refusing to enter 'dev': stashed password absent \
         \u{2014} run `tenant destroy dev && tenant create dev` to re-bootstrap\n"
    );
    assert!(
        exec.logins().is_empty(),
        "login must NOT fire when the keychain stash is absent: {:?}",
        exec.logins()
    );
    assert!(
        exec.exec_calls().is_empty(),
        "exec_as_tenant must NOT fire when the keychain stash is absent: {:?}",
        exec.exec_calls()
    );
}

#[test]
fn shell_surfaces_substrate_failure_on_unlock_call() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .fail_next_unlock_tenant_keychain(KeychainError::NonZero {
            code: 51,
            stderr: "The user name or passphrase you entered is not correct.".to_string(),
        });
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stderr={stderr:?}");
    let want_stdout = format!(
        "{}\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n",
        section_line("Entering tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to unlock keychain for 'dev': \
         security exited with code 51: \
         The user name or passphrase you entered is not correct.\n"
    );
    assert!(
        exec.logins().is_empty(),
        "login must NOT fire on unlock substrate failure: {:?}",
        exec.logins()
    );
    assert!(
        exec.exec_calls().is_empty(),
        "exec_as_tenant must NOT fire on unlock substrate failure: {:?}",
        exec.exec_calls()
    );
}

#[test]
fn shell_real_mode_verbose_shows_plan_and_echo() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev", "-v"]);
    assert_eq!(code, 0);
    let plan = verbose_plan_section(&[
        (
            "Install firewall anchor at /etc/pf.anchors/tenant-dev",
            "sudo tee /etc/pf.anchors/tenant-dev < anchor.body",
            None,
        ),
        ("Reload pf ruleset", "sudo pfctl -f /etc/pf.conf", None),
        (
            "Add host 'operator' to share group 'dev-tenant-share'",
            "sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share",
            None,
        ),
        ("Log in as 'dev'", "sudo -iu dev", None),
    ]);
    let want = format!(
        "{}\n\
         {plan}\
         $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         $ sudo pfctl -f /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         $ sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ Tenant 'dev' keychain unlocked\n\
         $ sudo -iu dev\n",
        section_line("Entering tenant 'dev'"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn shell_refuses_when_tenant_absent() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["shell", "ghost"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot shell into 'ghost': does not exist\n"
    );
}

#[test]
fn shell_refuses_when_only_orphan_group_present() {
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["shell", "dev"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: cannot shell into 'dev': does not exist\n");
}

#[test]
fn shell_refuses_below_floor() {
    // `legacyusr` sidesteps the reserved-name blocklist, isolating the floor check.
    let stub = StubUserDirectory {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), UserId(0))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["shell", "legacyusr"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to shell into 'legacyusr': UID 0 is below tenant floor 600\n"
    );
}

#[test]
fn shell_refuses_system_account() {
    // `uid_for` None models a service account (negative UIDs are filtered at parse).
    let stub = StubUserDirectory {
        users: vec!["phantom".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["shell", "phantom"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to shell into 'phantom': system account (no tenant-range UID)\n"
    );
}

#[test]
fn shell_refuses_below_floor_verbose() {
    let stub = StubUserDirectory {
        users: vec!["edge".to_string()],
        uid_by_name: [("edge".to_string(), UserId(599))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["shell", "edge", "-v"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to shell into 'edge': UID 599 is below tenant floor 600\n"
    );
}

#[test]
fn shell_rejects_empty_name() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["shell", ""]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn shell_rejects_invalid_start() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["shell", "1dev"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: name '1dev' must start with a lowercase letter (got '1')\n"
    );
}

#[test]
fn shell_rejects_reserved_names() {
    // Lexical rail first: `root` would also fail the floor guard, but the reserved name is the useful reason.
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["shell", name]);
        assert_eq!(code, 64, "want EX_USAGE for {name:?}");
        assert!(
            stdout.is_empty(),
            "stdout should be empty for {name:?}: {stdout:?}"
        );
        let want = format!("tenant: name '{name}' is reserved (matches a system or role name)\n");
        assert_eq!(stderr, want, "stderr mismatch for {name:?}");
    }
}

#[test]
fn shell_dry_run_refuses_missing_tenant() {
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["shell", "ghost", "--dry-run"],
    );
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot shell into 'ghost': does not exist\n"
    );
}

#[test]
fn shell_propagates_child_exit_code() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .login_exit_code(5);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 5, "stderr={stderr:?}");
    let want = format!(
        "{}\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ Tenant 'dev' keychain unlocked\n",
        section_line("Entering tenant 'dev'"),
    );
    assert_eq!(stdout, want);
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(exec.logins().len(), 1);
}

#[test]
fn shell_dry_run_bypasses_injected_host_machine() {
    // Exit 64 is the dry-run stash refusal (see the TODO(smell) at the top of this file).
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--dry-run"],
    );
    assert_eq!(code, 64, "stderr={stderr:?}");
    let want = format!("{}Would shell into 'dev'.\n", shell_summary_block("dev"));
    assert_eq!(stdout, want);
    assert!(
        exec.account_ops().is_empty() && exec.firewall_ops().is_empty() && exec.logins().is_empty(),
        "host machine should not be invoked in dry-run; account_ops={:?}, firewall_ops={:?}, logins={:?}",
        exec.account_ops(),
        exec.firewall_ops(),
        exec.logins()
    );
}

// --- Auto-narrow on shell entry ---

#[test]
fn shell_narrows_to_runtime_before_login() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: expected_body,
            },
            FirewallOp::Reload,
        ],
        "shell should narrow with [InstallAnchor(runtime body), Reload] before login"
    );
    assert_eq!(
        exec.logins(),
        vec!["dev".to_string()],
        "login should fire exactly once after the narrow"
    );
}

#[test]
fn shell_refusal_does_not_invoke_narrow() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["shell", "ghost"]);
    assert_eq!(code, 64, "EX_USAGE expected; stderr={stderr:?}");
    assert!(
        stdout.is_empty(),
        "stdout should be empty on refusal: {stdout:?}"
    );
    assert_eq!(
        stderr,
        "tenant: cannot shell into 'ghost': does not exist\n"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "narrow must NOT run on refused tenants: {:?}",
        exec.firewall_ops()
    );
    assert!(
        exec.logins().is_empty(),
        "login must NOT run on refused tenants: {:?}",
        exec.logins()
    );
}

#[test]
fn shell_does_not_invoke_flush_anchor() {
    // A FlushAnchor here would wipe the rules being installed.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, _stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0);
    for op in exec.firewall_ops() {
        assert!(
            !matches!(
                op,
                FirewallOp::FlushAnchor { .. }
                    | FirewallOp::RestoreConfigFromBackup
                    | FirewallOp::BackupConfig
                    | FirewallOp::RemoveAnchor { .. }
                    | FirewallOp::UpdateConfig { .. }
                    | FirewallOp::Enable
            ),
            "shell narrow should be exactly [InstallAnchor, Reload]; saw {op:?}"
        );
    }
}

#[test]
fn shell_aborts_when_read_profile_fails() {
    // No `with_existing_profile`: read_profile fails.
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stdout,
        format!("{}\n", section_line("Entering tenant 'dev'")),
        "intent emitted before narrow"
    );
    assert_eq!(
        stderr,
        "tenant: failed to read profile '~/.config/tenant/profiles/dev.toml' for 'dev' before shell entry: profile 'dev' not found\n"
    );
    assert!(
        exec.logins().is_empty(),
        "login must NOT fire when narrow fails: {:?}",
        exec.logins()
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "no firewall ops should run after read_profile failed: {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn shell_aborts_when_parse_fails() {
    let exec = StubHostMachine::new().with_existing_profile(
        "dev",
        "schema_version = 99\n[allowlist.runtime]\nhosts = []\n[allowlist.install]\nhosts = []\n",
    );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("before shell entry")
            && stderr.contains("schema_version 99 not understood"),
        "expected shell-narrow framing with schema-version refusal, got: {stderr:?}"
    );
    assert!(
        exec.logins().is_empty(),
        "login must NOT fire when narrow's parse fails"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "no firewall ops should run after parse failed"
    );
}

#[test]
fn shell_aborts_when_install_anchor_fails() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .fail_firewall_op(
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: tenant::firewall::render_anchor(
                    "dev",
                    &[],
                    tenant::firewall::InboundRules::Restricted(vec![]),
                ),
            },
            FirewallError::Fs {
                path: "/etc/pf.anchors/tenant-dev".into(),
                message: "permission denied".into(),
            },
        );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stdout,
        format!("{}\n", section_line("Entering tenant 'dev'")),
    );
    assert_eq!(
        stderr,
        "tenant: failed to narrow firewall for 'dev' before shell entry: \
         filesystem error at /etc/pf.anchors/tenant-dev: permission denied\n"
    );
    assert!(exec.logins().is_empty(), "login must NOT fire");
    assert_eq!(
        exec.firewall_ops().len(),
        1,
        "only InstallAnchor should be recorded"
    );
    assert!(matches!(
        exec.firewall_ops()[0],
        FirewallOp::InstallAnchor { .. }
    ));
}

#[test]
fn shell_aborts_when_reload_fails() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .fail_firewall_op(
            FirewallOp::Reload,
            FirewallError::NonZero {
                code: 1,
                stderr: "pfctl: Syntax error in anchor body\n".into(),
            },
        );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stdout,
        real_failure_stdout(
            "Entering tenant 'dev'",
            &["Firewall anchor installed at /etc/pf.anchors/tenant-dev"],
        ),
    );
    assert!(
        stderr.contains("failed to narrow firewall for 'dev' before shell entry"),
        "stderr should be framed by shell_narrow_failed: {stderr:?}"
    );
    assert!(exec.logins().is_empty(), "login must NOT fire");
    assert_eq!(
        exec.firewall_ops().len(),
        2,
        "expected exactly InstallAnchor + Reload, got {:?}",
        exec.firewall_ops()
    );
    for op in exec.firewall_ops() {
        assert!(
            !matches!(
                op,
                FirewallOp::RestoreConfigFromBackup
                    | FirewallOp::RemoveAnchor { .. }
                    | FirewallOp::FlushAnchor { .. }
                    | FirewallOp::BackupConfig
            ),
            "shell narrow should not emit recovery firewall ops on reload failure, saw: {op:?}"
        );
    }
}

#[test]
fn shell_install_anchor_body_excludes_install_hosts() {
    let profile = profile_with_hosts(
        &["api.example.com"],
        &["nodejs.org", "storage.googleapis.com"],
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev");
    let (code, _stdout, _stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(
                body, &expected_body,
                "shell narrow body must exclude install-tier hosts"
            );
        }
        other => panic!("expected InstallAnchor as first firewall op, got {other:?}"),
    }
}

// --- Auto-reapply includes shares ---

#[test]
fn shell_auto_reapply_emits_tenant_side_symlink_only() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev")
        .login_exit_code(0);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "exit = {code}; stderr={stderr:?}");

    assert!(
        exec.acl_ops().is_empty(),
        "shell (Light scope) emits no AclOp::Grant; got {:?}",
        exec.acl_ops()
    );
    let symlink_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .collect();
    assert_eq!(symlink_ops.len(), 1, "expected single symlink op");
    assert_eq!(
        exec.logins(),
        vec!["dev".to_string()],
        "login must fire after successful light reapply"
    );
}

#[test]
fn shell_on_cold_sudo_authenticates_then_probes_tenant_path() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev")
        .with_sudo_session_cached(false);
    let (code, _stdout, stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0, "stderr={stderr:?}");
    // The stub's tenant_path_kind fails while sudo is uncached (like `sudo -n`),
    // so a recorded probe plus exit 0 proves authenticate ran first.
    assert_eq!(exec.authenticate_sudo_calls(), 1);
    assert_eq!(
        exec.tenant_path_kind_calls(),
        vec![("dev".to_string(), PathBuf::from("/Users/dev/src"))],
        "occupancy probe runs once, after authenticating"
    );
    assert_eq!(exec.logins(), vec!["dev".to_string()]);
}

#[test]
fn shell_install_command_on_cold_sudo_refuses_occupied_tenant_path_before_widening() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev")
        .with_sudo_session_cached(false)
        .with_tenant_path_kind("dev", &PathBuf::from("/Users/dev/src"), PathKind::Other);
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "true"],
        b"",
    );
    assert_eq!(code, 74, "stderr={stderr:?}");
    assert!(
        stderr.contains("cannot enter shell for 'dev'") && stderr.contains("/Users/dev/src"),
        "refuse_shell_share frame expected: {stderr:?}"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "refusal must precede the install-tier widen: {:?}",
        exec.firewall_ops()
    );
    assert!(exec.exec_calls().is_empty());
    assert_eq!(
        exec.tenant_path_kind_calls().len(),
        1,
        "refused at plan build: nothing executed, so no narrow-back re-probe"
    );
}

#[test]
fn shell_command_on_cold_sudo_authentication_failure_exits_74_without_mutation() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev")
        .with_sudo_session_cached(false)
        .fail_next_authenticate_sudo(ProbeError::NonZero {
            code: 1,
            stderr: String::new(),
        });
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "true"],
        b"",
    );
    assert_eq!(code, 74);
    assert_eq!(
        stderr,
        "tenant: failed to probe host state for 'dev' before shell entry: probe exited with code 1\n"
    );
    assert_eq!(
        exec.authenticate_sudo_calls(),
        1,
        "authenticates exactly once"
    );
    assert!(
        exec.firewall_ops().is_empty() && exec.account_ops().is_empty(),
        "plan build failed, so nothing mutated: fw={:?} account={:?}",
        exec.firewall_ops(),
        exec.account_ops()
    );
    assert!(exec.exec_calls().is_empty());
}

#[test]
fn shell_refuses_when_host_path_missing_does_not_launch_login() {
    let toml = profile_with_shares(
        &[],
        &[],
        &[("/nonexistent/missing/shell-sentinel", "rw", "$HOME/src")],
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev");
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(
        stderr.contains("cannot enter shell for 'dev'"),
        "stderr should be framed by refuse_shell_share: {stderr:?}"
    );
    assert!(
        stderr.contains("does not exist on disk"),
        "stderr should name the cause: {stderr:?}"
    );
    assert!(
        exec.logins().is_empty(),
        "login must NOT fire when share refusal aborts before entry"
    );
}

#[test]
fn shell_ignores_acl_grant_failure_injection_under_light_scope() {
    // Light never emits Grant, so the injected ACL failure is unreachable.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev")
        .fail_acl_op(
            AclOp::Grant {
                path: PathBuf::from("/tmp"),
                group: "dev-tenant-share".into(),
                mode: tenant::domain::AclMode::Rw,
            },
            AclError::NonZero {
                code: 1,
                stderr: "chmod: Permission denied".into(),
            },
        );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(
        code, 0,
        "Light-scope shell never emits Grant, so the injected ACL failure is unreachable; stderr={stderr:?}"
    );
    assert!(
        exec.acl_ops().is_empty(),
        "no AclOp should have fired under Light scope; got {:?}",
        exec.acl_ops()
    );
    assert_eq!(
        exec.logins(),
        vec!["dev".to_string()],
        "login should still fire (no ACL pass on shell entry)"
    );
}

#[test]
fn shell_routes_sudo_u_substrate_failure_via_shell_narrow_account_frame() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev")
        .fail_account_op(
            AccountOp::EnsureSymlinkAsUser {
                name: "dev".into(),
                link: PathBuf::from("/Users/dev/src"),
                target: PathBuf::from("/tmp"),
            },
            AccountError::NonZero {
                code: 1,
                stderr: "ln: cannot create symbolic link".into(),
            },
        );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stderr={stderr:?}");
    assert!(
        stderr.contains(
            "failed to install tenant-side filesystem state for 'dev' before shell entry"
        ),
        "stderr should be framed by shell_narrow_account_failed: {stderr:?}"
    );
    assert!(
        exec.logins().is_empty(),
        "login must NOT fire on share-substrate failure"
    );
}

#[test]
fn shell_verbose_plan_block_lists_light_ops_alongside_login() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev")
        .login_exit_code(0);
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--verbose"],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("  sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n"),
        "plan must list InstallAnchor: {stdout:?}"
    );
    assert!(
        stdout.contains("  sudo pfctl -f /etc/pf.conf\n"),
        "plan must list Reload: {stdout:?}"
    );
    assert!(
        !stdout.contains("chmod -R +a"),
        "plan must NOT list recursive Grant under Light: {stdout:?}"
    );
    assert!(
        !stdout.contains("co-working directory"),
        "plan must NOT list cowork-dir provisioning under Light: {stdout:?}"
    );
    assert!(
        stdout.contains("  sudo -n -u dev /bin/ln -sfn /tmp /Users/dev/src\n"),
        "plan must list EnsureSymlinkAsUser: {stdout:?}"
    );
    assert!(
        stdout.contains("  sudo -iu dev\n"),
        "plan must list LoginAsUser: {stdout:?}"
    );
}

#[test]
fn shell_negative_pin_share_substrate_does_not_emit_firewall_recovery_ops() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev")
        .login_exit_code(0);
    let (code, _stdout, _stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0);
    for op in exec.firewall_ops() {
        assert!(
            !matches!(
                op,
                FirewallOp::FlushAnchor { .. }
                    | FirewallOp::RestoreConfigFromBackup
                    | FirewallOp::BackupConfig
                    | FirewallOp::RemoveAnchor { .. }
                    | FirewallOp::UpdateConfig { .. }
                    | FirewallOp::Enable
            ),
            "shell narrow with shares should not emit firewall recovery / setup ops; saw {op:?}"
        );
    }
}

// --- Pre-exec doctor audit ---

#[test]
fn shell_pre_exec_doctor_silent_when_host_is_clean() {
    // `run_with_stdin` (TTY) turns the audit on; dry-run would bypass the stub's reads.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("\u{26a0} Doctor:"),
        "clean host must not emit the aggregate warning line; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("critical:"),
        "clean host must not emit a critical finding; stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_doctor_emits_critical_inline_when_pf_disabled() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_pf_status_content("Status: Disabled\n");
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0);
    assert!(
        stdout.contains("critical: pf is globally disabled"),
        "PfDisabled critical must emit inline; stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_doctor_aggregates_warnings_into_single_line() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_env_policy_content("");
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\u{26a0} Doctor: 1 warning for tenant 'dev' \u{2014} run `tenant doctor dev` for details"),
        "warning aggregate line must name singular count + recovery command; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("warning: env-leak"),
        "individual warning one-liner must NOT emit inline (warnings aggregate); stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_doctor_critical_plus_warnings_emits_both_lines() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_pf_status_content("Status: Disabled\n")
        .with_env_policy_content("")
        .with_host_in_group("operator", "dev-tenant-share", false);
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0);
    assert!(
        stdout.contains("critical: pf is globally disabled"),
        "PfDisabled critical must emit inline; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("\u{26a0} Doctor: 2 warnings for tenant 'dev'"),
        "2 warnings must aggregate with plural noun; stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_doctor_verbose_does_not_emit_guidance_for_inline_critical() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_pf_status_content("Status: Disabled\n");
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev", "-v"], b"");
    assert_eq!(code, 0);
    assert!(
        stdout.contains("critical: pf is globally disabled"),
        "critical inline still emits; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("Why this matters"),
        "verb-verbose must NOT emit doctor's guidance block inline; stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_doctor_silent_in_scripted_mode_no_summary() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_pf_status_content("Status: Disabled\n");
    let (code, stdout, _stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("\u{26a0} Doctor:"),
        "scripted real-mode must not emit audit; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("critical:"),
        "scripted real-mode must not emit critical inline; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("About to enter tenant"),
        "scripted real-mode must not emit summary; stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_doctor_exit_code_unaffected_by_findings() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_pf_status_content("Status: Disabled\n")
        .with_env_policy_content("")
        .login_exit_code(0);
    let (code, _stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(
        code, 0,
        "shell exit must be login child's exit (0), not affected by doctor findings"
    );
}

#[test]
fn shell_pre_exec_inbound_posture_quiet_when_locked() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("inbound:"),
        "locked tenant must emit no inbound posture line; stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_inbound_posture_restricted_with_ports_shows_calibrated_line() {
    // Info, not a ⚠ warning: declared ports are intended exposure.
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&[], &[])
    );
    let synced_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![3000]),
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_anchor_body("dev", &synced_body)
        .with_default_stash("dev");
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0);
    assert!(
        stdout.contains("inbound: restricted — :3000 open to host + peer tenants"),
        "restricted-with-ports entry must show calibrated posture line; stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_inbound_posture_permissive_warns_with_narrow_hint() {
    // A heads-up, not a blocker: interactive entry re-renders restricted anyway.
    let permissive_body =
        tenant::firewall::render_anchor("dev", &[], tenant::firewall::InboundRules::Permissive);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &permissive_body)
        .with_default_stash("dev");
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0);
    assert!(
        stdout.contains("inbound: PERMISSIVE — all ports open to host + peer tenants"),
        "permissive entry must show the loud posture warning; stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_doctor_pf_conf_read_failure_surfaces_and_proceeds() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .fail_next_pf_conf(FirewallError::Fs {
            path: "/etc/pf.conf".into(),
            message: "Permission denied".into(),
        });
    let (code, _stdout, stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stderr,
        "tenant: failed to read pf state: filesystem error at /etc/pf.conf: Permission denied\n"
    );
    assert_eq!(
        exec.kernel_pf_rules_calls(),
        vec!["dev".to_string(), "dev".to_string()],
        "pre-pass probe, then the post-reload verify"
    );
    assert_eq!(exec.logins(), vec!["dev".to_string()]);
}

#[test]
fn shell_pre_exec_doctor_substrate_failure_surfaces_and_proceeds() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .fail_next_pf_status(FirewallError::NonZero {
            code: 1,
            stderr: "sudo: a password is required".into(),
        });
    let (code, _stdout, stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0, "verb proceeds despite audit substrate failure");
    assert!(
        stderr.contains("failed to read pf state"),
        "substrate failure surfaces via doctor_firewall_failed frame; stderr={stderr:?}"
    );
}

// --- Command form (`shell <name> [--mode] -- <cmd>`) ---

#[test]
fn shell_command_form_default_runtime_invokes_exec_as_tenant() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "ls", "/tmp"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: expected_body,
            },
            FirewallOp::Reload,
        ],
        "runtime-mode command form fires ONE reapply round (entry only); no redundant post-child narrow"
    );
    assert_eq!(
        exec.exec_calls(),
        vec![(
            "dev".to_string(),
            vec!["ls".to_string(), "/tmp".to_string()]
        )],
        "command form invokes exec_as_tenant exactly once with the operator's argv"
    );
    assert!(
        exec.logins().is_empty(),
        "command form does NOT invoke the interactive login carve-out: {:?}",
        exec.logins()
    );
}

#[test]
fn shell_command_form_install_mode_widens_then_narrows() {
    // Install hosts make the widen and narrow bodies differ.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &[
            "shell", "dev", "--mode", "install", "--", "bash", "-c", "echo hi",
        ],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let install_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["runtime.example", "install.example"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    let runtime_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["runtime.example"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: install_body,
            },
            FirewallOp::Reload,
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: runtime_body,
            },
            FirewallOp::Reload,
        ],
        "entry widens to install tier; finally narrows to runtime tier"
    );
    assert_eq!(
        exec.exec_calls(),
        vec![(
            "dev".to_string(),
            vec!["bash".into(), "-c".into(), "echo hi".into()],
        )],
    );
}

#[test]
fn shell_command_form_propagates_child_exit_code() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .exec_exit_code(7);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "false"],
    );
    assert_eq!(code, 7, "child's exit propagates; stderr={stderr:?}");
    assert!(stderr.is_empty(), "no warning on clean narrow: {stderr:?}");
    assert_eq!(exec.exec_calls().len(), 1);
}

#[test]
fn shell_command_form_does_not_invoke_login_carveout() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "echo", "hello"],
    );
    assert_eq!(code, 0);
    assert!(
        exec.logins().is_empty(),
        "login carve-out must not fire on command form: {:?}",
        exec.logins()
    );
    assert_eq!(
        exec.exec_calls().len(),
        1,
        "exec carve-out fires exactly once on the command form"
    );
}

#[test]
fn shell_interactive_form_unchanged_when_argv_empty() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .login_exit_code(5);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(
        code, 5,
        "child shell exit code propagates: stderr={stderr:?}"
    );
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: expected_body,
            },
            FirewallOp::Reload,
        ],
        "interactive form fires entry reapply only (no finally narrow)"
    );
    assert_eq!(exec.logins(), vec!["dev".to_string()]);
    assert!(
        exec.exec_calls().is_empty(),
        "interactive form must NOT invoke exec_as_tenant: {:?}",
        exec.exec_calls()
    );
}

#[test]
fn shell_command_form_install_mode_narrow_on_finally_runs_when_child_fails() {
    // Otherwise a failing child would leave the anchor widened.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev")
        .exec_exit_code(42);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "false"],
    );
    assert_eq!(code, 42, "child exit code; stderr={stderr:?}");
    let runtime_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["runtime.example"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    let ops = exec.firewall_ops();
    assert_eq!(
        ops.iter()
            .filter(|o| matches!(o, FirewallOp::Reload))
            .count(),
        2,
        "narrow-on-finally fires even when child failed: {ops:?}"
    );
    let last_install = ops
        .iter()
        .rfind(|op| matches!(op, FirewallOp::InstallAnchor { .. }))
        .unwrap();
    if let FirewallOp::InstallAnchor { body, .. } = last_install {
        assert_eq!(
            body, &runtime_body,
            "finally narrow installs the runtime-tier body, not install-tier"
        );
    }
}

#[test]
fn shell_command_form_runtime_mode_no_post_child_narrow() {
    // The entry reapply already lands at runtime tier.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "true"],
    );
    assert_eq!(code, 0);
    assert_eq!(
        exec.firewall_ops()
            .iter()
            .filter(|o| matches!(o, FirewallOp::Reload))
            .count(),
        1,
        "runtime-mode command form fires ONE Reload (entry only): {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn shell_command_form_narrow_failure_surfaces_warning_and_child_exit_wins() {
    // fail_firewall_op matches the runtime body, so only the finally narrow fails.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let runtime_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["runtime.example"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev")
        .fail_firewall_op(
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: runtime_body,
            },
            FirewallError::NonZero {
                code: 1,
                stderr: "anchor write failed".into(),
            },
        );
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "true"],
    );
    assert_eq!(
        code, 0,
        "child's exit (0) wins over narrow failure; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("firewall not narrowed"),
        "yellow ⚠ warning surfaces narrow-failure on stderr: {stderr:?}"
    );
    assert!(
        stderr.contains("tenant mode dev runtime"),
        "warning names the recovery command: {stderr:?}"
    );
    assert_eq!(exec.exec_calls().len(), 1, "child ran exactly once");
}

#[test]
fn shell_command_form_widen_failure_at_build_skips_narrow() {
    let exec = StubHostMachine::new(); // no profile pre-loaded → read_profile fails
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "ls"],
    );
    assert_eq!(code, 74, "EX_IOERR on Mode error; stderr={stderr:?}");
    assert!(
        exec.firewall_ops().is_empty(),
        "no firewall substrate fires when widen-build failed: {:?}",
        exec.firewall_ops()
    );
    assert!(
        exec.exec_calls().is_empty(),
        "child never spawns when widen-build failed: {:?}",
        exec.exec_calls()
    );
}

#[test]
fn shell_command_form_widen_failure_at_substrate_runs_narrow() {
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev")
        .fail_next_firewall(FirewallError::NonZero {
            code: 1,
            stderr: "pf reload failed".into(),
        });
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "ls"],
    );
    assert_eq!(code, 74, "EX_IOERR on widen-Mode error; stderr={stderr:?}");
    // fail_next_firewall is one-shot, so the narrow's ops land.
    let runtime_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["runtime.example"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    let ops = exec.firewall_ops();
    assert!(
        ops.iter().any(|op| matches!(
            op,
            FirewallOp::InstallAnchor { name, body }
                if name == "dev" && body == &runtime_body
        )),
        "best-effort narrow runtime-body InstallAnchor must fire after widen-execute failure: {ops:?}"
    );
    assert!(
        exec.exec_calls().is_empty(),
        "child must not spawn when widen-execute failed: {:?}",
        exec.exec_calls()
    );
}

#[test]
fn shell_command_form_negative_pin_no_flush_anchor() {
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev");
    let (_code, _stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "ls"],
    );
    assert!(
        !exec
            .firewall_ops()
            .iter()
            .any(|op| matches!(op, FirewallOp::FlushAnchor { .. })),
        "FlushAnchor must not fire on the command form: {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn shell_command_form_share_substrate_reapplies_before_exec() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "ls"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let add_host = AccountOp::AddHostToShareGroup {
        group: "dev-tenant-share".into(),
        host: "operator".into(),
    };
    assert!(
        exec.account_ops().contains(&add_host),
        "AddHostToShareGroup fires as part of the entry reapply: {:?}",
        exec.account_ops()
    );
    assert_eq!(exec.exec_calls().len(), 1);
}

// --- Reporter byte-form pins: command form ---

#[test]
fn shell_command_dry_run_default_shows_intent() {
    // Exit 64 is the dry-run stash refusal (see the TODO(smell) at the top of this file).
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--dry-run", "--", "ls", "/tmp"],
    );
    assert_eq!(code, 64, "stderr={stderr:?}");
    let want = format!(
        "{}Would run command as tenant 'dev' (runtime tier).\n",
        shell_command_summary_block("dev", "runtime", "ls /tmp"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn shell_command_dry_run_install_mode_includes_widen_and_narrow_bullets() {
    // Exit 64 is the dry-run stash refusal (see the TODO(smell) at the top of this file).
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &[
            "shell",
            "dev",
            "--dry-run",
            "--mode",
            "install",
            "--",
            "bash",
            "-c",
            "echo hi",
        ],
    );
    assert_eq!(code, 64, "stderr={stderr:?}");
    let want = format!(
        "{}Would run command as tenant 'dev' (install tier).\n",
        shell_command_summary_block("dev", "install", "bash -c echo hi"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn shell_command_real_mode_section_divider_includes_tier_when_install() {
    let runtime_profile = tenant::profile::default_profile_toml();
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &runtime_profile)
        .with_default_stash("dev");
    let (_code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "true"],
    );
    assert!(
        stdout.contains(&section_line("Running command as tenant 'dev'")),
        "runtime-tier section header missing: {stdout:?}"
    );
    assert!(
        !stdout.contains("(install tier)"),
        "runtime-tier header must NOT carry tier suffix: {stdout:?}"
    );

    let install_profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec2 = StubHostMachine::new()
        .with_existing_profile("dev", &install_profile)
        .with_default_stash("dev");
    let (_code, stdout2, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec2,
        &["shell", "dev", "--mode", "install", "--", "true"],
    );
    assert!(
        stdout2.contains(&section_line(
            "Running command as tenant 'dev' (install tier)"
        )),
        "install-tier section header missing: {stdout2:?}"
    );
}

#[test]
fn shell_command_no_confirm_prompt() {
    // Empty stdin on a TTY: a prompt, if one were added, would change the output.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "true"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("Proceed?"),
        "command form must not emit a confirm prompt on TTY: {stdout:?}"
    );
    assert_eq!(exec.exec_calls().len(), 1, "child runs without prompt gate");
}

#[test]
fn shell_command_narrow_failure_warning_uses_warning_glyph() {
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let runtime_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["runtime.example"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev")
        .fail_firewall_op(
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: runtime_body,
            },
            FirewallError::NonZero {
                code: 1,
                stderr: "anchor write failed".into(),
            },
        );
    let (_code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "true"],
    );
    let want = "\u{26a0} tenant 'dev': firewall not narrowed after command \u{2014} install-tier widening still in effect; run `tenant mode dev runtime` to recover\n";
    assert_eq!(stderr, want);
}

#[test]
fn shell_command_closing_runtime_mode_bare_exit_line() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .exec_exit_code(7);
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "false"],
    );
    assert_eq!(code, 7);
    assert!(
        stdout.contains(&section_line("Done")),
        "closing `─── Done ───` separator missing: {stdout:?}"
    );
    assert!(
        stdout.contains("Command exited with code 7.\n"),
        "runtime-mode closing line must be bare (no narrow-back suffix): {stdout:?}"
    );
    assert!(
        !stdout.contains("(firewall narrowed back to runtime tier)"),
        "runtime-mode closing line must NOT carry the narrow-back suffix: {stdout:?}"
    );
}

#[test]
fn shell_command_closing_install_mode_includes_narrow_back_suffix() {
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev")
        .exec_exit_code(0);
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "true"],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains(&section_line("Done")),
        "closing `─── Done ───` separator missing: {stdout:?}"
    );
    assert!(
        stdout.contains("Command exited with code 0 (firewall narrowed back to runtime tier).\n"),
        "install-mode closing line must carry the narrow-back suffix: {stdout:?}"
    );
}

#[test]
fn shell_command_closing_does_not_emit_on_interactive_form() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .login_exit_code(0);
    let (_code, stdout, _stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert!(
        !stdout.contains(&section_line("Done")),
        "interactive form must NOT emit a closing Done separator: {stdout:?}"
    );
    assert!(
        !stdout.contains("Command exited with code"),
        "interactive form must NOT emit a Command-exited closing line: {stdout:?}"
    );
}

#[test]
fn shell_command_pre_exec_doctor_audit_same_as_interactive_shell() {
    let make_exec = || {
        StubHostMachine::new()
            .with_existing_profile("dev", &tenant::profile::default_profile_toml())
            .with_default_stash("dev")
            .with_pf_status_content("Status: Disabled\n")
    };

    // Interactive form (regression baseline).
    let exec_a = make_exec();
    let (_code, stdout_a, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec_a, &["shell", "dev"], b"");

    // Command form.
    let exec_b = make_exec();
    let (_code, stdout_b, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec_b,
        &["shell", "dev", "--", "true"],
        b"",
    );

    assert!(
        stdout_a.contains("critical: pf is globally disabled"),
        "interactive form's pre-exec audit surfaces PfDisabled: {stdout_a:?}"
    );
    assert!(
        stdout_b.contains("critical: pf is globally disabled"),
        "command form's pre-exec audit surfaces PfDisabled: {stdout_b:?}"
    );
}

#[test]
fn shell_clap_rejects_mode_without_argv() {
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install"],
    );
    assert_ne!(code, 0, "clap rejects parse: stderr={stderr:?}");
    assert!(
        exec.firewall_ops().is_empty()
            && exec.account_ops().is_empty()
            && exec.exec_calls().is_empty()
            && exec.logins().is_empty(),
        "no substrate fires on clap parse rejection"
    );
}

// --- Keychain unlock on shell entry ---

#[test]
fn shell_unlocks_keychain_before_login() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_stash("dev", tenant::domain::KeychainPassword::test_dummy("hexpw"));
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let want = format!(
        "{}\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ Tenant 'dev' keychain unlocked\n",
        section_line("Entering tenant 'dev'"),
    );
    assert_eq!(stdout, want);
    assert_eq!(
        exec.unlock_calls(),
        vec!["dev".to_string()],
        "unlock_tenant_keychain must fire exactly once for the tenant"
    );
    assert_eq!(exec.logins(), vec!["dev".to_string()]);
}

#[test]
fn shell_command_form_also_unlocks() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "echo", "hi"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let want = format!(
        "{}\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ Tenant 'dev' keychain unlocked\n\
         {}\n\
         Command exited with code 0.\n",
        section_line("Running command as tenant 'dev'"),
        section_line("Done"),
    );
    assert_eq!(stdout, want);
    assert_eq!(
        exec.unlock_calls(),
        vec!["dev".to_string()],
        "unlock_tenant_keychain must fire exactly once for the tenant"
    );
    assert_eq!(
        exec.exec_calls(),
        vec![(
            "dev".to_string(),
            vec!["echo".to_string(), "hi".to_string()],
        )],
        "command form invokes exec_as_tenant with the operator's argv"
    );
    assert!(
        exec.logins().is_empty(),
        "command form must NOT invoke the login carve-out: {:?}",
        exec.logins()
    );
}

#[test]
fn shell_surfaces_user_directory_error_when_eligibility_probe_fails() {
    let stub = StubUserDirectory {
        fail_has_user: directory_fail_once(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["shell", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.starts_with("tenant: failed to check shell eligibility for 'dev': "),
        "expected shell_eligibility_probe_failed frame; stderr={stderr:?}"
    );
}

// --- Light reapply (all three forms) ---

#[test]
fn shell_interactive_uses_light_reapply_skipping_recursive_acl_passes() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");

    assert!(
        exec.acl_ops().is_empty(),
        "shell (Light scope) must NOT emit AclOp::Grant; got {:?}",
        exec.acl_ops()
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "shell (Light scope) must NOT emit EnsureCoworkDir; got {cowork_ops:?}"
    );
    assert_eq!(
        exec.logins(),
        vec!["dev".to_string()],
        "login should fire exactly once after the light narrow"
    );
}

#[test]
fn shell_command_runtime_uses_light_reapply_skipping_recursive_acl_passes() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "ls"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");

    assert!(
        exec.acl_ops().is_empty(),
        "shell -- cmd (Light scope) must NOT emit Grant; got {:?}",
        exec.acl_ops()
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "shell -- cmd (Light scope) must NOT emit EnsureCoworkDir; got {cowork_ops:?}"
    );
    assert_eq!(
        exec.exec_calls().len(),
        1,
        "expected single exec_as_tenant call; got {:?}",
        exec.exec_calls()
    );
    assert_eq!(
        exec.firewall_ops().len(),
        2,
        "expected single PF reapply (no narrow) under runtime command form; got {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn shell_command_install_uses_light_reapply_on_both_entry_and_narrow() {
    let toml = profile_with_shares(
        &["github.com"],
        &["pypi.org"],
        &[("/tmp", "rw", "$HOME/src")],
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "pip"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");

    assert!(
        exec.acl_ops().is_empty(),
        "shell --mode install (Light scope) must NOT emit Grant on either pass; got {:?}",
        exec.acl_ops()
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "shell --mode install (Light scope) must NOT emit EnsureCoworkDir on either pass; got {cowork_ops:?}"
    );
    assert_eq!(
        exec.firewall_ops().len(),
        4,
        "expected two PF reapplies (entry-widen + post-child-narrow) = 4 ops; got {:?}",
        exec.firewall_ops()
    );
    assert_eq!(
        exec.exec_calls().len(),
        1,
        "expected single exec_as_tenant call between the two PF reapplies; got {:?}",
        exec.exec_calls()
    );
}

#[test]
fn shell_interactive_silently_succeeds_when_cowork_path_is_symlink_under_light_scope() {
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_host_path_kind(
            &cowork_path,
            PathKind::Symlink(PathBuf::from("/tmp/elsewhere")),
        );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(
        code, 0,
        "shell (Light scope) must not refuse on corrupted cowork path; stderr={stderr:?}"
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "shell must NOT emit EnsureCoworkDir against a symlinked cowork path; got {cowork_ops:?}"
    );
    assert_eq!(
        exec.logins(),
        vec!["dev".to_string()],
        "login must still fire — shell light scope ignores the cowork drift"
    );
}

#[test]
fn shell_command_runtime_silently_succeeds_when_cowork_path_is_absent_under_light_scope() {
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_host_path_kind(&cowork_path, PathKind::Absent);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "ls"],
    );
    assert_eq!(
        code, 0,
        "shell -- cmd (Light scope) must not refuse on absent cowork path; stderr={stderr:?}"
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "shell -- cmd must NOT emit EnsureCoworkDir against an absent cowork path; got {cowork_ops:?}"
    );
    assert_eq!(
        exec.exec_calls().len(),
        1,
        "exec_as_tenant should still fire under absent cowork path; got {:?}",
        exec.exec_calls()
    );
}

#[test]
fn shell_command_install_silently_succeeds_when_cowork_path_is_symlink_under_light_scope() {
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_host_path_kind(
            &cowork_path,
            PathKind::Symlink(PathBuf::from("/tmp/elsewhere")),
        );
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "pip"],
    );
    assert_eq!(
        code, 0,
        "shell --mode install (Light scope) must not refuse on either pass; stderr={stderr:?}"
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "shell --mode install must NOT emit EnsureCoworkDir on either pass; got {cowork_ops:?}"
    );
}

#[test]
fn shell_entry_restores_anchor_reference_missing_from_pf_conf() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_pf_conf(STOCK_PF_CONF);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let ops = exec.firewall_ops();
    assert!(
        matches!(ops[0], FirewallOp::InstallAnchor { .. }),
        "ops={ops:?}"
    );
    assert_eq!(
        ops[1..],
        [
            FirewallOp::UpdateConfig {
                content: format!("{STOCK_PF_CONF}{}", anchor_ref_lines("dev")),
            },
            FirewallOp::Reload,
        ]
    );
    assert_eq!(exec.logins(), vec!["dev".to_string()]);
}

// --- Cowork-dir drift in pre-exec doctor ---

#[test]
fn shell_pre_exec_doctor_surfaces_cowork_acl_drift() {
    // ACL listing missing the share-group ACE → CoworkAclDrift.
    let cowork_path = std::path::PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_host_acl(
            &cowork_path,
            " 0: user:operator allow list,add_file,search\n",
        );
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0);
    assert!(
        stdout.contains(
            "\u{26a0} Doctor: 1 warning for tenant 'dev' \u{2014} run `tenant doctor dev` for details"
        ),
        "cowork ACL drift must surface as a Warning aggregate on shell entry; stdout={stdout:?}"
    );
}

#[test]
fn shell_after_reload_heals_cowork_drift_emits_no_doctor_aggregate() {
    // The stub's default ACL listing is the state a Full reload leaves.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, stdout, stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("\u{26a0} Doctor:"),
        "after a clean reload the next shell entry must emit no doctor aggregate; stdout={stdout:?}"
    );
}

#[test]
fn shell_pre_exec_doctor_surfaces_cowork_dir_absent() {
    let cowork_path = std::path::PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_host_path_kind(&cowork_path, PathKind::Absent);
    let (code, stdout, _stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0);
    assert!(
        stdout.contains(
            "\u{26a0} Doctor: 1 warning for tenant 'dev' \u{2014} run `tenant doctor dev` for details"
        ),
        "cowork dir absence must surface as a Warning aggregate on shell entry; stdout={stdout:?}"
    );
}

// --- Command form `--inbound` ---

#[test]
fn shell_command_inbound_permissive_renders_permissive_entry_then_narrows() {
    // A declared port makes the restricted narrow body distinct from locked.
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&["api.example.com"], &["pypi.org"])
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--inbound", "permissive", "--", "ls"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let permissive_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Permissive,
    );
    let restricted_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Restricted(vec![3000]),
    );
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: permissive_body,
            },
            FirewallOp::Reload,
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: restricted_body,
            },
            FirewallOp::Reload,
        ],
        "entry widens inbound to permissive; finally narrows inbound to restricted"
    );
    assert_eq!(
        exec.exec_calls(),
        vec![("dev".to_string(), vec!["ls".to_string()])],
    );
}

#[test]
fn shell_command_inbound_permissive_narrow_on_finally_runs_when_child_fails() {
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&["api.example.com"], &[])
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev")
        .exec_exit_code(42);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--inbound", "permissive", "--", "false"],
    );
    assert_eq!(code, 42, "child exit code; stderr={stderr:?}");
    let restricted_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Restricted(vec![3000]),
    );
    let ops = exec.firewall_ops();
    assert_eq!(
        ops.iter()
            .filter(|o| matches!(o, FirewallOp::Reload))
            .count(),
        2,
        "narrow-on-finally fires even when child failed: {ops:?}"
    );
    let last_install = ops
        .iter()
        .rfind(|op| matches!(op, FirewallOp::InstallAnchor { .. }))
        .unwrap();
    if let FirewallOp::InstallAnchor { body, .. } = last_install {
        assert_eq!(
            body, &restricted_body,
            "finally narrow installs the restricted-inbound body, not permissive"
        );
    }
}

#[test]
fn shell_command_default_inbound_stays_restricted_no_extra_narrow() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "true"],
    );
    assert_eq!(code, 0);
    assert_eq!(
        exec.firewall_ops()
            .iter()
            .filter(|o| matches!(o, FirewallOp::Reload))
            .count(),
        1,
        "default-inbound (restricted) command form fires ONE Reload (entry only): {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn shell_command_inbound_restricted_explicit_no_extra_narrow() {
    // The narrow gate keys on a widened level, not on the flag's presence.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--inbound", "restricted", "--", "true"],
    );
    assert_eq!(code, 0);
    assert_eq!(
        exec.firewall_ops()
            .iter()
            .filter(|o| matches!(o, FirewallOp::Reload))
            .count(),
        1,
        "explicit --inbound restricted widens nothing → ONE Reload: {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn shell_clap_rejects_inbound_without_argv() {
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--inbound", "permissive"],
    );
    assert_ne!(code, 0, "clap rejects parse: stderr={stderr:?}");
    assert!(
        exec.firewall_ops().is_empty()
            && exec.account_ops().is_empty()
            && exec.exec_calls().is_empty()
            && exec.logins().is_empty(),
        "no substrate fires on clap parse rejection"
    );
}

#[test]
fn shell_command_inbound_and_mode_compose_within_one_call() {
    // Widenings compose within one call; the doctrine forbids it only across commands.
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&["runtime.example"], &["install.example"])
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &[
            "shell",
            "dev",
            "--mode",
            "install",
            "--inbound",
            "permissive",
            "--",
            "ls",
        ],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let entry_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["runtime.example", "install.example"]),
        tenant::firewall::InboundRules::Permissive,
    );
    let narrow_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["runtime.example"]),
        tenant::firewall::InboundRules::Restricted(vec![3000]),
    );
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: entry_body,
            },
            FirewallOp::Reload,
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: narrow_body,
            },
            FirewallOp::Reload,
        ],
        "both axes widen on entry, both narrow on finally"
    );
}

// --- `-d/--directory` ---

#[test]
fn shell_command_form_absolute_directory_reaches_exec_carve_out() {
    let dir = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_tenant_dir_present("dev", &dir);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &[
            "shell",
            "dev",
            "-d",
            "/Users/Shared/tenants/dev",
            "--",
            "ls",
        ],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.exec_calls_with_dir(),
        vec![("dev".to_string(), vec!["ls".to_string()], Some(dir))],
    );
}

#[test]
fn shell_interactive_absolute_directory_reaches_login_carve_out() {
    let dir = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_tenant_dir_present("dev", &dir);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--directory", "/Users/Shared/tenants/dev"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.login_calls(),
        vec![("dev".to_string(), Some(dir))],
        "interactive form threads the resolved dir to the login carve-out"
    );
}

#[test]
fn shell_without_directory_flag_passes_none_to_both_carve_outs() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "ls"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.exec_calls_with_dir(),
        vec![("dev".to_string(), vec!["ls".to_string()], None)],
    );
    assert!(
        exec.tenant_path_kind_calls().is_empty(),
        "no -d ⇒ no pre-flight probe: {:?}",
        exec.tenant_path_kind_calls()
    );

    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, _stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0);
    assert_eq!(exec.login_calls(), vec![("dev".to_string(), None)]);
    assert!(exec.tenant_path_kind_calls().is_empty());
}

#[test]
fn shell_relative_directory_resolves_under_tenant_home() {
    let dir = PathBuf::from("/Users/dev/projects/foo");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_tenant_dir_present("dev", &dir);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "projects/foo", "--", "ls"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.exec_calls_with_dir(),
        vec![("dev".to_string(), vec!["ls".to_string()], Some(dir.clone()))],
    );
    assert_eq!(
        exec.tenant_dir_present_calls(),
        vec![("dev".to_string(), dir)],
        "the pre-flight probes the RESOLVED path, as the tenant"
    );
}

#[test]
fn shell_home_prefixed_directory_resolves_to_tenant_home() {
    let dir = PathBuf::from("/Users/dev/projects/foo");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_tenant_dir_present("dev", &dir);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "$HOME/projects/foo", "--", "ls"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.exec_calls_with_dir(),
        vec![("dev".to_string(), vec!["ls".to_string()], Some(dir))],
    );
}

#[test]
fn shell_refuses_mid_string_home_in_directory() {
    // Lexical refusal: it beats the probe.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "/etc/$HOME/foo", "--", "ls"],
    );
    assert_eq!(code, 64, "EX_USAGE expected; stderr={stderr:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to enter: --directory \"/etc/$HOME/foo\" contains `$HOME` not at \
         the start; `$HOME` expands only as a path prefix\n"
    );
    assert!(
        exec.tenant_path_kind_calls().is_empty(),
        "lexical refusal precedes the probe: {:?}",
        exec.tenant_path_kind_calls()
    );
    assert!(exec.firewall_ops().is_empty(), "nothing may have widened");
    assert!(exec.exec_calls().is_empty());
}

#[test]
fn shell_refuses_absent_directory_before_any_firewall_op() {
    // The message names the resolved path, not the typed `projects/foo`.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "projects/foo", "--", "ls"],
    );
    assert_eq!(code, 64, "EX_USAGE expected; stderr={stderr:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to enter 'dev': /Users/dev/projects/foo is not a directory \
         'dev' can enter\n"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "pre-flight must beat the widen: {:?}",
        exec.firewall_ops()
    );
    assert!(exec.account_ops().is_empty(), "no host-membership catch-up");
    assert!(exec.exec_calls().is_empty());
    assert!(exec.logins().is_empty());
}

#[test]
fn shell_refuses_directory_the_tenant_cannot_enter() {
    // `test -d` answers false for files, unstat-able and absent paths alike: one message.
    let dir = PathBuf::from("/Users/dev/notes.md");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev"); // no with_tenant_dir_present ⇒ probe answers false
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "notes.md"],
    );
    assert_eq!(code, 64, "EX_USAGE expected; stderr={stderr:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to enter 'dev': /Users/dev/notes.md is not a directory 'dev' can enter\n"
    );
    assert_eq!(
        exec.tenant_dir_present_calls(),
        vec![("dev".to_string(), dir)],
        "the pre-flight asks the dir question, NOT tenant_path_kind"
    );
    assert!(
        exec.tenant_path_kind_calls().is_empty(),
        "tenant_path_kind classifies `test -L` FIRST — it cannot answer \
         'is this enterable', so -d must not use it: {:?}",
        exec.tenant_path_kind_calls()
    );
    assert!(exec.logins().is_empty());
}

// TODO(smell): rename tenant_dir_present / tenant_path_kind so the names say which one follows symlinks.
#[test]
fn shell_refuses_dangling_symlink_directory() {
    // A dangling link reads as Symlink(..) to tenant_path_kind; `test -d` follows it and answers false.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_tenant_path_kind(
            "dev",
            &PathBuf::from("/Users/dev/src"),
            PathKind::Symlink(PathBuf::from("/Users/Shared/tenants/dev/gone")),
        );
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &[
            "shell", "dev", "--mode", "install", "-d", "src", "--", "make",
        ],
    );
    assert_eq!(code, 64, "EX_USAGE expected; stderr={stderr:?}");
    assert!(
        stderr.contains("/Users/dev/src is not a directory 'dev' can enter"),
        "stderr={stderr:?}"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "install-tier widen must not fire behind a dangling link: {:?}",
        exec.firewall_ops()
    );
    assert!(exec.exec_calls().is_empty());
}

#[test]
fn shell_accepts_symlinked_directory() {
    // Shares install symlinks, so a live link must be accepted.
    let dir = PathBuf::from("/Users/dev/src");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_tenant_dir_present("dev", &dir);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "src"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(exec.login_calls(), vec![("dev".to_string(), Some(dir))]);
}

#[test]
fn shell_directory_probe_failure_is_substrate_error() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .fail_next_tenant_dir_present(ProbeError::NonZero {
            code: 1,
            stderr: "sudo: a password is required".to_string(),
        });
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "projects/foo"],
    );
    assert_eq!(code, 74, "EX_IOERR expected; stderr={stderr:?}");
    assert!(
        stderr.starts_with("tenant: failed to probe directory /Users/dev/projects/foo: "),
        "stderr={stderr:?}"
    );
    assert!(exec.firewall_ops().is_empty());
    assert!(exec.logins().is_empty());
}

#[test]
fn shell_directory_pre_flight_skipped_when_sudo_uncached() {
    // `sudo -n` fails uncached, so probing would fail every fresh terminal's first command.
    let dir = PathBuf::from("/Users/dev/projects/foo");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_sudo_session_cached(false); // and NO with_tenant_dir_present
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "projects/foo", "--", "ls"],
        b"",
    );
    assert_eq!(
        code, 0,
        "must not refuse on an untrustworthy answer; stderr={stderr:?}"
    );
    assert!(
        exec.tenant_dir_present_calls().is_empty(),
        "uncached sudo ⇒ the probe must not even run: {:?}",
        exec.tenant_dir_present_calls()
    );
    assert_eq!(
        exec.exec_calls_with_dir(),
        vec![("dev".to_string(), vec!["ls".to_string()], Some(dir))],
    );
}

#[test]
fn shell_refuses_directory_containing_a_dollar_sign() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "projects/$scratch", "--", "ls"],
    );
    assert_eq!(code, 64, "EX_USAGE expected; stderr={stderr:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to enter: --directory \"projects/$scratch\" contains `$`, which the \
         tenant's login shell would expand before `cd` runs\n"
    );
    assert!(exec.tenant_dir_present_calls().is_empty());
    assert!(exec.firewall_ops().is_empty());
}

#[test]
fn shell_refuses_dollar_after_a_legal_home_prefix() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_tenant_dir_present("dev", &PathBuf::from("/Users/dev/projects/$scratch"));
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "-d", "$HOME/projects/$scratch", "--", "ls"],
    );
    assert_eq!(code, 64, "EX_USAGE expected; stderr={stderr:?}");
    assert!(
        stderr.contains("contains `$`, which the tenant's login shell would expand"),
        "stderr={stderr:?}"
    );
    assert!(exec.exec_calls().is_empty(), "the child must not run");
    assert!(exec.firewall_ops().is_empty());
}

#[test]
fn shell_directory_composes_with_permissive_inbound() {
    let dir = PathBuf::from("/Users/dev/projects/foo");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_tenant_dir_present("dev", &dir);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &[
            "shell",
            "dev",
            "--inbound",
            "permissive",
            "-d",
            "projects/foo",
            "--",
            "gh",
            "auth",
            "login",
        ],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.exec_calls_with_dir(),
        vec![(
            "dev".to_string(),
            vec!["gh".to_string(), "auth".to_string(), "login".to_string()],
            Some(dir)
        )],
    );
    assert_eq!(
        exec.firewall_ops().len(),
        4,
        "permissive widen + restricted narrow = two rounds: {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn shell_interactive_plan_line_renders_the_cd() {
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["shell", "dev", "-d", "projects/foo", "--dry-run", "-v"],
    );
    assert_eq!(code, 64, "dry-run shell ends at the stash-absent refusal");
    assert!(
        stdout.contains("Log in as 'dev' in /Users/dev/projects/foo"),
        "plan must name the resolved dir: {stdout}"
    );
    assert!(
        stdout
            .contains("sudo -iu dev -- /bin/sh -c 'cd /Users/dev/projects/foo && exec \"$SHELL\"'"),
        "plan's shell line must show the real wrapped argv: {stdout}"
    );
    assert!(
        stdout.contains("start in 'projects/foo' (resolved on dev's filesystem)"),
        "summary must name the directory the operator consented to: {stdout}"
    );
}

#[test]
fn shell_command_summary_names_the_directory() {
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &[
            "shell",
            "dev",
            "-d",
            "projects/foo",
            "--dry-run",
            "--",
            "ls",
        ],
    );
    assert_eq!(code, 64);
    assert!(
        stdout.contains("run as 'dev' in 'projects/foo': ls"),
        "command-form summary must name the directory: {stdout}"
    );
}

#[test]
fn shell_directory_composes_with_install_mode() {
    let dir = PathBuf::from("/Users/dev/projects/foo");
    let exec = StubHostMachine::new()
        .with_existing_profile(
            "dev",
            &profile_with_shares(&["runtime.example"], &["install.example"], &[]),
        )
        .with_default_stash("dev")
        .with_tenant_dir_present("dev", &dir);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &[
            "shell",
            "dev",
            "--mode",
            "install",
            "-d",
            "projects/foo",
            "--",
            "pip",
            "install",
            "foo",
        ],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.exec_calls_with_dir(),
        vec![(
            "dev".to_string(),
            vec!["pip".to_string(), "install".to_string(), "foo".to_string()],
            Some(dir)
        )],
    );
    assert_eq!(
        exec.firewall_ops().len(),
        4,
        "install-mode widen + narrow = two InstallAnchor/Reload rounds: {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn shell_command_without_terminal_on_cold_sudo_refuses_before_entry() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_sudo_session_cached(false);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "true"],
    );
    assert_eq!(code, 64);
    assert_eq!(stderr, SUDO_NEEDS_TERMINAL_REFUSAL);
    assert!(exec.firewall_ops().is_empty() && exec.exec_calls().is_empty());
}

#[test]
fn shell_command_install_on_permissive_profile_keeps_inbound_permissive_both_ways() {
    let exec = StubHostMachine::new()
        .with_existing_profile(
            "dev",
            &profile_with_permissive_posture(&["api.example.com"], &["pypi.org"]),
        )
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "ls"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let body = |hosts: &[&str]| {
        tenant::firewall::render_anchor(
            "dev",
            &common::egress(hosts),
            tenant::firewall::InboundRules::Permissive,
        )
    };
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: body(&["api.example.com", "pypi.org"]),
            },
            FirewallOp::Reload,
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: body(&["api.example.com"]),
            },
            FirewallOp::Reload,
        ],
    );
}

#[test]
fn shell_inbound_restricted_refuses_on_permissive_profile() {
    let exec = StubHostMachine::new()
        .with_existing_profile(
            "dev",
            &profile_with_permissive_posture(&["api.example.com"], &[]),
        )
        .with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--inbound", "restricted", "--", "ls"],
    );
    assert_eq!(code, 64);
    assert_eq!(stderr, refuse_restricted_on_permissive_profile("dev"));
    assert!(exec.firewall_ops().is_empty() && exec.exec_calls().is_empty());
}

fn anchor_install(body: String) -> FirewallOp {
    FirewallOp::InstallAnchor {
        name: "dev".into(),
        body,
    }
}

#[test]
fn shell_command_install_narrows_back_when_keychain_unlock_refuses() {
    let exec = StubHostMachine::new().with_existing_profile(
        "dev",
        &profile_with_hosts(&["api.example.com"], &["pypi.org"]),
    );
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "ls"],
    );
    assert_eq!(code, 64, "stderr={stderr:?}");
    let restricted = |hosts: &[&str]| {
        tenant::firewall::render_anchor(
            "dev",
            &common::egress(hosts),
            tenant::firewall::InboundRules::Restricted(vec![]),
        )
    };
    assert_eq!(
        exec.firewall_ops(),
        vec![
            anchor_install(restricted(&["api.example.com", "pypi.org"])),
            FirewallOp::Reload,
            anchor_install(restricted(&["api.example.com"])),
            FirewallOp::Reload,
        ],
    );
    assert!(exec.exec_calls().is_empty());
}

#[test]
fn shell_command_permissive_inbound_narrows_back_when_keychain_unlock_refuses() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile_with_hosts(&["api.example.com"], &[]));
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--inbound", "permissive", "--", "ls"],
    );
    assert_eq!(code, 64, "stderr={stderr:?}");
    let body = |inbound| {
        tenant::firewall::render_anchor("dev", &common::egress(&["api.example.com"]), inbound)
    };
    assert_eq!(
        exec.firewall_ops(),
        vec![
            anchor_install(body(tenant::firewall::InboundRules::Permissive)),
            FirewallOp::Reload,
            anchor_install(body(tenant::firewall::InboundRules::Restricted(vec![]))),
            FirewallOp::Reload,
        ],
    );
}

#[test]
fn shell_pre_exec_skips_root_only_anchor_reads_on_cold_sudo() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_default_stash("dev")
        .with_sudo_session_cached(false);
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "ls"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(exec.anchor_body_reads(), 0);
}

#[test]
fn shell_command_summary_names_a_permissive_inbound_widen() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile_with_hosts(&["api.example.com"], &[]))
        .with_default_stash("dev");
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--inbound", "permissive", "--", "ls"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains(
            "  \u{2022} open ALL inbound loopback ports for the command \u{2014} reachable by \
             host + peer tenants\n"
        ),
        "stdout={stdout:?}"
    );
    assert!(
        stdout.contains(
            "  \u{2022} narrow inbound loopback back to the profile's posture (always \u{2014} \
             even if the command fails)\n"
        ),
        "stdout={stdout:?}"
    );
}

#[test]
fn shell_summary_names_a_permissive_profile_posture() {
    let exec = StubHostMachine::new()
        .with_existing_profile(
            "dev",
            &profile_with_permissive_posture(&["api.example.com"], &[]),
        )
        .with_default_stash("dev");
    let (code, stdout, stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["shell", "dev"], b"");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains(
            "  \u{2022} keep inbound loopback PERMISSIVE (profile posture) \u{2014} every port the \
             tenant opens is reachable by host + peer tenants\n"
        ),
        "stdout={stdout:?}"
    );
}

#[test]
fn shell_inbound_only_narrow_failure_names_the_inbound_leftover() {
    let restricted = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile_with_hosts(&["api.example.com"], &[]))
        .with_default_stash("dev")
        .fail_firewall_op(
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: restricted,
            },
            FirewallError::NonZero {
                code: 1,
                stderr: String::new(),
            },
        );
    let (_code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--inbound", "permissive", "--", "ls"],
    );
    assert_eq!(
        stderr,
        "\u{26a0} tenant 'dev': firewall not narrowed after command \u{2014} all-ports inbound \
         loopback still in effect; run `tenant mode dev runtime` to recover\n"
    );
}
