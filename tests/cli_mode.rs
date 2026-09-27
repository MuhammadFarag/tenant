use std::path::PathBuf;

use tenant::domain::{AccountOp, FirewallError, FirewallOp, PathKind, UserId};

mod adapters;
mod common;
use adapters::*;
use common::*;

// --- Clap parse + dry-run ---

#[test]
fn mode_runtime_dry_run_default_shows_intent() {
    let (code, stdout, stderr) = run_with(
        stub_with_tenant("dev"),
        &["mode", "dev", "runtime", "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, mode_dry_run_block("dev", "runtime", None));
}

#[test]
fn mode_install_dry_run_default_shows_intent() {
    let (code, stdout, stderr) = run_with(
        stub_with_tenant("dev"),
        &["mode", "dev", "install", "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, mode_dry_run_block("dev", "install", None));
}

#[test]
fn mode_rejects_unknown_level() {
    let (code, stdout, _stderr) = run_with(stub_with_tenant("dev"), &["mode", "dev", "bogus"]);
    assert_eq!(code, 2, "clap should reject unknown level");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
}

#[test]
fn mode_requires_name() {
    let (code, _stdout, _stderr) = run_with(StubUserDirectory::default(), &["mode"]);
    assert_eq!(code, 2, "clap should reject missing name");
}

#[test]
fn mode_requires_level() {
    let (code, _stdout, _stderr) = run_with(StubUserDirectory::default(), &["mode", "dev"]);
    assert_eq!(code, 2, "clap should reject missing level");
}

// --- Validation + eligibility refusals ---

#[test]
fn mode_rejects_empty_name() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["mode", "", "runtime"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn mode_rejects_reserved_names() {
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) =
            run_with(StubUserDirectory::default(), &["mode", name, "runtime"]);
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
fn mode_refuses_when_tenant_absent() {
    let (code, stdout, stderr) =
        run_with(StubUserDirectory::default(), &["mode", "ghost", "runtime"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot apply mode to 'ghost': does not exist\n"
    );
}

#[test]
fn mode_refuses_when_only_orphan_group_present() {
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["mode", "dev", "runtime"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot apply mode to 'dev': does not exist\n"
    );
}

#[test]
fn mode_refuses_below_floor() {
    // `legacyusr` sidesteps the reserved-name blocklist so the state-based refusal is exercised.
    let stub = StubUserDirectory {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), UserId(0))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["mode", "legacyusr", "runtime"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to apply mode to 'legacyusr': UID 0 is below tenant floor 600\n"
    );
}

#[test]
fn mode_refuses_system_account() {
    // Negative UID is filtered by parse_id_line: `has_user` true, `uid_for` None.
    let stub = StubUserDirectory {
        users: vec!["phantom".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["mode", "phantom", "runtime"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to apply mode to 'phantom': system account (no tenant-range UID)\n"
    );
}

#[test]
fn mode_dry_run_refuses_missing_tenant() {
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["mode", "ghost", "runtime", "--dry-run"],
    );
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot apply mode to 'ghost': does not exist\n"
    );
}

// --- Real-mode happy path: runtime ---

#[test]
fn mode_runtime_real_mode_op_shape() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout_with_breadcrumb(
            "Applying mode 'runtime' to tenant 'dev'",
            &[
                "Firewall anchor installed at /etc/pf.anchors/tenant-dev",
                "Firewall ruleset reloaded",
                "Host 'operator' added to share group 'dev-tenant-share'",
            ],
            "Tenant 'dev' is at runtime tier.",
            Some(&mode_breadcrumb("dev")),
        ),
    );
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
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
        "mode runtime should InstallAnchor (runtime-only body) then Reload"
    );
}

#[test]
fn mode_renders_declared_inbound_ports_from_profile() {
    // `mode` doesn't control inbound: it renders the declared ports, not a locked posture.
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&[], &[])
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![3000]),
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(
                body, &expected_body,
                "mode should render the profile's declared inbound ports (steady state), not locked"
            );
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

#[test]
fn mode_only_touches_addhost_account_op_and_no_profile_or_login() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0);
    assert_eq!(
        exec.account_ops(),
        vec![AccountOp::AddHostToShareGroup {
            group: "dev-tenant-share".into(),
            host: "operator".into(),
        }],
        "mode should fire only AddHost under Light scope"
    );
    assert!(
        exec.profile_ops().is_empty(),
        "mode should not invoke profile_ops: {:?}",
        exec.profile_ops()
    );
    assert!(
        exec.logins().is_empty(),
        "mode should not invoke login: {:?}",
        exec.logins()
    );
}

#[test]
fn mode_light_does_not_reassert_primary_group() {
    // Preloaded gid: even with one available, Light neither reads nor reasserts it.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_share_group_gid("dev-tenant-share", 742);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !exec
            .account_ops()
            .iter()
            .any(|op| matches!(op, AccountOp::EnsurePrimaryGroup { .. })),
        "mode (Light) must NOT reassert primary group: {:?}",
        exec.account_ops()
    );
}

#[test]
fn mode_does_not_emit_restore_config_op() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (_code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    for op in exec.firewall_ops() {
        assert!(
            !matches!(
                op,
                FirewallOp::RestoreConfigFromBackup
                    | FirewallOp::BackupConfig
                    | FirewallOp::RemoveAnchor { .. }
                    | FirewallOp::FlushAnchor { .. }
                    | FirewallOp::Enable
                    | FirewallOp::UpdateConfig { .. }
            ),
            "mode should not emit recovery/teardown firewall ops, saw: {op:?}"
        );
    }
}

#[test]
fn mode_uses_centralized_anchor_name() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (_code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { name, .. } => {
            assert_eq!(name, "dev", "anchor name should be bare tenant name");
        }
        other => panic!("expected InstallAnchor as first firewall op, got {other:?}"),
    }
}

// --- Install mode + populated profile ---

#[test]
fn mode_install_with_only_runtime_populated() {
    let profile = profile_with_hosts(&["api.example.com", "deploy.example.com"], &[]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com", "deploy.example.com"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

#[test]
fn mode_install_with_runtime_and_install_populated() {
    let profile = profile_with_hosts(
        &["api.example.com"],
        &["nodejs.org", "storage.googleapis.com"],
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com", "nodejs.org", "storage.googleapis.com"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

#[test]
fn mode_runtime_with_runtime_and_install_populated_excludes_install() {
    // Security-relevant: narrowing back must shrink the host set.
    let profile = profile_with_hosts(
        &["api.example.com"],
        &["nodejs.org", "storage.googleapis.com"],
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

#[test]
fn mode_install_with_empty_runtime_and_populated_install() {
    let profile = profile_with_hosts(&[], &["pypi.org", "npmjs.org"]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["pypi.org", "npmjs.org"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

// --- Display: standard + verbose + dry-run ---

#[test]
fn mode_real_standard_emits_only_post_exec_confirmation() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout_with_breadcrumb(
            "Applying mode 'runtime' to tenant 'dev'",
            &[
                "Firewall anchor installed at /etc/pf.anchors/tenant-dev",
                "Firewall ruleset reloaded",
                "Host 'operator' added to share group 'dev-tenant-share'",
            ],
            "Tenant 'dev' is at runtime tier.",
            Some(&mode_breadcrumb("dev")),
        ),
    );
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn mode_real_verbose_shows_plan_and_echo() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-v"],
    );
    assert_eq!(code, 0);
    // Non-TTY real run drops the verbose plan: divider + `$` echo + ✓ only.
    let want = format!(
        "{}\n\
         $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         $ sudo pfctl -f /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         $ sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         {}\n\
         Tenant 'dev' is at runtime tier.\n\
         {}\n",
        section_line("Applying mode 'runtime' to tenant 'dev'"),
        section_line("Done"),
        mode_breadcrumb("dev"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn mode_install_real_verbose_shows_install_level_text() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "install", "-v"],
    );
    assert_eq!(code, 0);
    let want = format!(
        "{}\n\
         $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         $ sudo pfctl -f /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         $ sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         {}\n\
         Tenant 'dev' is at install tier.\n\
         {}\n",
        section_line("Applying mode 'install' to tenant 'dev'"),
        section_line("Done"),
        mode_breadcrumb("dev"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn mode_dry_run_verbose_shows_plan_no_echo() {
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["mode", "dev", "runtime", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let plan = verbose_plan_section(&[
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
    ]);
    assert_eq!(stdout, mode_dry_run_block("dev", "runtime", Some(&plan)));
}

#[test]
fn mode_dry_run_bypasses_injected_host_machine() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, mode_dry_run_block("dev", "runtime", None));
    assert!(
        exec.firewall_ops().is_empty()
            && exec.account_ops().is_empty()
            && exec.profile_ops().is_empty(),
        "host machine should not be invoked in dry-run; firewall_ops={:?}, account_ops={:?}, profile_ops={:?}",
        exec.firewall_ops(),
        exec.account_ops(),
        exec.profile_ops()
    );
}

// --- Failure paths ---

#[test]
fn mode_read_profile_failure_surfaces() {
    // The plan is built before the section divider, so stdout stays empty.
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "tenant: failed to read profile '~/.config/tenant/profiles/dev.toml' for 'dev': profile 'dev' not found\n"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "no firewall ops should have run; got {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn mode_parse_failure_surfaces_schema_version() {
    let exec = StubHostMachine::new().with_existing_profile(
        "dev",
        "schema_version = 99\n[allowlist.runtime]\nhosts = []\n[allowlist.install]\nhosts = []\n",
    );
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("schema_version 99 not understood"),
        "expected schema-version refusal in stderr, got: {stderr:?}"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "no firewall ops should have run"
    );
}

#[test]
fn mode_install_anchor_failure_surfaces() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stdout,
        format!(
            "{}\n",
            section_line("Applying mode 'runtime' to tenant 'dev'")
        ),
    );
    assert_eq!(
        stderr,
        "tenant: failed to apply firewall mode for 'dev': \
         filesystem error at /etc/pf.anchors/tenant-dev: permission denied\n"
    );
    assert_eq!(exec.firewall_ops().len(), 1);
    assert!(matches!(
        exec.firewall_ops()[0],
        FirewallOp::InstallAnchor { .. }
    ));
}

#[test]
fn mode_reload_failure_surfaces_without_recovery() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_firewall_op(
            FirewallOp::Reload,
            FirewallError::NonZero {
                code: 1,
                stderr: "pfctl: Syntax error in anchor body\n".into(),
            },
        );
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stdout,
        real_failure_stdout(
            "Applying mode 'runtime' to tenant 'dev'",
            &["Firewall anchor installed at /etc/pf.anchors/tenant-dev"],
        ),
    );
    assert!(
        stderr.contains("failed to apply firewall mode for 'dev'"),
        "stderr should be framed by mode_failed: {stderr:?}"
    );
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
            "mode should not emit recovery firewall ops on reload failure, saw: {op:?}"
        );
    }
}

// --- Share reapply ---

#[test]
fn mode_profile_read_failure_surfaces_before_prompt() {
    let exec = StubHostMachine::new(); // no profile preloaded
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "--verbose"],
    );
    assert_eq!(code, 74, "EX_IOERR expected");
    assert_eq!(stdout, "", "no stdout pre-prompt; got {stdout:?}");
    assert!(
        stderr.contains("failed to read profile"),
        "stderr should frame the failure; got {stderr:?}"
    );
    assert!(
        !stdout.contains("Proceed?"),
        "no confirm prompt should be emitted; got {stdout:?}"
    );
}

#[test]
fn mode_runtime_with_shares_emits_per_share_substrate_ops() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");

    assert!(
        exec.acl_ops().is_empty(),
        "mode (Light scope) must NOT emit AclOp::Grant; got {:?}",
        exec.acl_ops()
    );

    // No EnsureDir (parent is /Users/dev, the tenant home).
    let account_ops = exec.account_ops();
    let ensure_dirs: Vec<_> = account_ops
        .iter()
        .filter(|op| matches!(op, AccountOp::EnsureDirAsUser { .. }))
        .collect();
    assert!(
        ensure_dirs.is_empty(),
        "EnsureDir should NOT fire when parent is /Users/<name>: {ensure_dirs:?}"
    );

    let ensure_links: Vec<_> = account_ops
        .iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .collect();
    assert_eq!(
        ensure_links.len(),
        1,
        "expected single EnsureSymlinkAsUser; got {ensure_links:?}"
    );
    let AccountOp::EnsureSymlinkAsUser {
        name: link_name,
        link,
        target,
    } = ensure_links[0]
    else {
        unreachable!()
    };
    assert_eq!(link_name, "dev");
    assert_eq!(link, &PathBuf::from("/Users/dev/src"));
    assert_eq!(target, &PathBuf::from("/tmp"));
}

#[test]
fn mode_runtime_uses_light_reapply_skipping_recursive_acl_passes() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");

    assert!(
        exec.acl_ops().is_empty(),
        "mode reapply must NOT emit AclOp::Grant (light reapply); got {:?}",
        exec.acl_ops()
    );

    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "mode reapply must NOT emit EnsureCoworkDir (light reapply); got {cowork_ops:?}"
    );

    let account_kinds: Vec<&'static str> = exec
        .account_ops()
        .iter()
        .map(|op| match op {
            AccountOp::AddHostToShareGroup { .. } => "AddHostToShareGroup",
            AccountOp::EnsureSymlinkAsUser { .. } => "EnsureSymlinkAsUser",
            AccountOp::EnsureDirAsUser { .. } => "EnsureDirAsUser",
            other => panic!("unexpected account op in light reapply: {other:?}"),
        })
        .collect();
    assert_eq!(
        account_kinds,
        vec!["AddHostToShareGroup", "EnsureSymlinkAsUser"],
        "expected AddHost then per-share EnsureSymlink under light reapply"
    );
}

#[test]
fn mode_install_uses_light_reapply_skipping_recursive_acl_passes() {
    let toml = profile_with_shares(
        &["api.example.com"],
        &["pypi.org"],
        &[("/tmp", "rw", "$HOME/src")],
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");

    assert!(
        exec.acl_ops().is_empty(),
        "mode install reapply must NOT emit AclOp::Grant; got {:?}",
        exec.acl_ops()
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "mode install reapply must NOT emit EnsureCoworkDir; got {cowork_ops:?}"
    );
}

#[test]
fn mode_silently_succeeds_when_cowork_path_is_symlink_under_light_scope() {
    // Inverse of `reload_refuses_when_cowork_path_is_a_symlink`.
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_path_kind(
            &cowork_path,
            PathKind::Symlink(PathBuf::from("/tmp/elsewhere")),
        );
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(
        code, 0,
        "Light scope must not refuse on corrupted cowork path; stderr={stderr:?}"
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "mode must NOT emit EnsureCoworkDir against a symlinked cowork path; got {cowork_ops:?}"
    );
}

#[test]
fn mode_silently_succeeds_when_cowork_path_is_absent_under_light_scope() {
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_path_kind(&cowork_path, PathKind::Absent);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(
        code, 0,
        "Light scope must not provision absent cowork path; stderr={stderr:?}"
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "mode must NOT emit EnsureCoworkDir against an absent cowork path; got {cowork_ops:?}"
    );
}

#[test]
fn mode_runtime_with_shares_verbose_plan_excludes_grant_and_cowork() {
    // TTY stdin forces the real-mode pre-confirm summary; dry-run can't show shares.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-v"],
        b"y\n",
    );
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("Grant"),
        "mode plan must NOT contain Grant ACL op under Light: {stdout:?}"
    );
    assert!(
        !stdout.contains("co-working directory"),
        "mode plan must NOT mention cowork dir under Light: {stdout:?}"
    );
    assert!(
        !stdout.contains("chmod -R +a"),
        "mode plan must NOT include the recursive chmod under Light: {stdout:?}"
    );
    assert!(
        stdout.contains("Install symlink /Users/dev/src \u{2192} /tmp"),
        "mode plan should still install tenant-side symlink: {stdout:?}"
    );
}

#[test]
fn mode_runtime_with_nested_tenant_path_emits_ensure_dir_for_parent() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "ro", "$HOME/.local/share/chezmoi")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");

    let account_ops = exec.account_ops();
    let ensure_dirs: Vec<_> = account_ops
        .iter()
        .filter_map(|op| match op {
            AccountOp::EnsureDirAsUser { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        ensure_dirs,
        vec![PathBuf::from("/Users/dev/.local/share")],
        "expected EnsureDir for the symlink parent"
    );
}

#[test]
fn mode_runtime_preserves_profile_declared_share_order() {
    // Light emits no Grant, so declared order is pinned via the symlink sequence.
    let toml = profile_with_shares(
        &[],
        &[],
        &[("/tmp", "rw", "$HOME/zeta"), ("/var", "ro", "$HOME/alpha")],
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    let symlink_targets: Vec<PathBuf> = exec
        .account_ops()
        .into_iter()
        .filter_map(|op| match op {
            AccountOp::EnsureSymlinkAsUser { target, .. } => Some(target),
            _ => None,
        })
        .collect();
    assert_eq!(
        symlink_targets,
        vec![PathBuf::from("/tmp"), PathBuf::from("/var")],
        "expected declared share order via symlink ops [zeta=/tmp, alpha=/var]"
    );
}

#[test]
fn mode_refuses_when_host_path_does_not_exist() {
    let toml = profile_with_shares(
        &[],
        &[],
        &[("/nonexistent/missing/sentinel", "rw", "$HOME/src")],
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(
        code, 74,
        "expected EX_IOERR on share refusal; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("cannot apply mode for 'dev'"),
        "stderr should be framed by refuse_mode_share: {stderr:?}"
    );
    assert!(
        stderr.contains("/nonexistent/missing/sentinel"),
        "stderr should name the missing host_path: {stderr:?}"
    );
    assert!(
        stderr.contains("does not exist on disk"),
        "stderr should name the cause: {stderr:?}"
    );
    // PF reapply ran (precedes share pass); share substrate didn't.
    assert!(
        exec.acl_ops().is_empty(),
        "AclOp should NOT have fired: {:?}",
        exec.acl_ops()
    );
}

#[test]
fn mode_refuses_when_tenant_path_is_real_directory() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_tenant_path_kind("dev", &PathBuf::from("/Users/dev/src"), PathKind::Other);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(
        code, 74,
        "expected EX_IOERR on share refusal; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("cannot apply mode for 'dev'"),
        "stderr should be framed by refuse_mode_share: {stderr:?}"
    );
    assert!(
        stderr.contains("/Users/dev/src"),
        "stderr should name the occupied tenant_path: {stderr:?}"
    );
    assert!(
        exec.acl_ops().is_empty(),
        "AclOp should NOT have fired: {:?}",
        exec.acl_ops()
    );
}

#[test]
fn mode_on_cold_sudo_still_refuses_occupied_tenant_path() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_sudo_session_cached(false)
        .with_tenant_path_kind("dev", &PathBuf::from("/Users/dev/src"), PathKind::Other);
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime"],
        b"",
    );
    assert_eq!(code, 74, "stderr={stderr:?}");
    assert!(
        stderr.contains("cannot apply mode for 'dev'") && stderr.contains("/Users/dev/src"),
        "refuse_mode_share frame naming the occupied path expected: {stderr:?}"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "refusal must precede every mutation: {:?}",
        exec.firewall_ops()
    );
    assert!(
        !exec
            .account_ops()
            .iter()
            .any(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. })),
        "the occupied path must never be linked over: {:?}",
        exec.account_ops()
    );
}

#[test]
fn mode_with_cached_sudo_does_not_authenticate() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime"],
        b"y\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(exec.authenticate_sudo_calls(), 0);
}

#[test]
fn mode_without_shares_does_not_authenticate_on_cold_sudo() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_sudo_session_cached(false);
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime"],
        b"y\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(exec.authenticate_sudo_calls(), 0);
}

#[test]
fn mode_declined_on_cold_sudo_authenticated_once_and_mutated_nothing() {
    // Accepted cost of sudo auth at plan build: a decline has already answered the prompt.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_sudo_session_cached(false);
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime"],
        b"n\n",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Aborted by operator. No changes made."),
        "{stdout:?}"
    );
    assert_eq!(exec.authenticate_sudo_calls(), 1);
    assert!(exec.firewall_ops().is_empty() && exec.account_ops().is_empty());
}

#[test]
fn mode_on_cold_sudo_authentication_failure_exits_74_without_mutation() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_sudo_session_cached(false)
        .fail_next_authenticate_sudo(tenant::domain::ProbeError::NonZero {
            code: 1,
            stderr: String::new(),
        });
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime"],
        b"",
    );
    assert_eq!(code, 74, "stderr={stderr:?}");
    assert_eq!(
        stderr,
        "tenant: failed to probe host state for 'dev': probe exited with code 1\n"
    );
    assert!(exec.tenant_path_kind_calls().is_empty());
    assert!(exec.firewall_ops().is_empty() && exec.account_ops().is_empty());
}

#[test]
fn mode_runtime_skips_substrate_with_existing_symlink_at_tenant_path() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_tenant_path_kind(
            "dev",
            &PathBuf::from("/Users/dev/src"),
            PathKind::Symlink(PathBuf::from("/tmp")),
        );
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(
        code, 0,
        "expected success on existing symlink; stderr={stderr:?}"
    );
    assert!(
        exec.acl_ops().is_empty(),
        "mode (Light scope) emits no Grant; got {:?}",
        exec.acl_ops()
    );
    let symlinks: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .collect();
    assert_eq!(
        symlinks.len(),
        1,
        "expected single EnsureSymlinkAsUser despite existing symlink (idempotent re-link); got {symlinks:?}"
    );
}

#[test]
fn mode_install_tier_does_not_change_share_substrate() {
    let toml = profile_with_shares(
        &["github.com"],
        &["nodejs.org"],
        &[("/tmp", "rw", "$HOME/src")],
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert!(
        exec.acl_ops().is_empty(),
        "mode install (Light scope) emits no Grant; got {:?}",
        exec.acl_ops()
    );
    let symlinks: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .collect();
    assert_eq!(
        symlinks.len(),
        1,
        "share-side symlink op should fire at install tier same as runtime"
    );
}

// --- Pre-exec doctor audit ---

#[test]
fn mode_pre_exec_doctor_silent_when_host_is_clean() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("\u{26a0} Doctor:") && !stdout.contains("critical:"),
        "clean host must not emit audit; stdout={stdout:?}"
    );
}

#[test]
fn mode_pre_exec_doctor_emits_primary_group_drift_critical_and_proceeds() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_sudo_session_cached(false)
        .with_user_primary_gid("dev", 20);
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout
            .contains("critical: tenant 'dev' primary group is gid 20, not dev-tenant-share (600)"),
        "stdout={stdout:?}"
    );
    assert!(!stdout.contains("\u{26a0} Doctor:"), "stdout={stdout:?}");
    assert!(
        exec.firewall_ops()
            .iter()
            .any(|op| matches!(op, FirewallOp::Reload)),
        "ops={:?}",
        exec.firewall_ops()
    );
}

#[test]
fn mode_pre_exec_doctor_primary_group_probe_failure_surfaces_and_proceeds() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_next_user_primary_gid(tenant::domain::ProbeError::NonZero {
            code: 56,
            stderr: "eDSRecordNotFound".to_string(),
        });
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stderr,
        "tenant: failed to probe tenant 'dev' primary group: probe exited with code 56: eDSRecordNotFound\n"
    );
    assert!(
        exec.firewall_ops()
            .iter()
            .any(|op| matches!(op, FirewallOp::Reload)),
        "ops={:?}",
        exec.firewall_ops()
    );
}

#[test]
fn mode_pre_exec_doctor_emits_critical_inline_when_pf_disabled() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_pf_status_content("Status: Disabled\n");
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("critical: pf is globally disabled"),
        "PfDisabled critical must emit inline; stdout={stdout:?}"
    );
}

#[test]
fn mode_pre_exec_doctor_aggregates_pf_rule_drift_warning() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_kernel_pf_rules("dev", "");
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\u{26a0} Doctor: 2 warnings for tenant 'dev'"),
        "empty kernel anchor → 2 warnings (missing pass + missing block); stdout={stdout:?}"
    );
}

#[test]
fn mode_pre_exec_doctor_scope_includes_share_drift() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_in_group("operator", "dev-tenant-share", false);
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\u{26a0} Doctor: 1 warning for tenant 'dev'"),
        "HostNotInShareGroup must propagate to mode scope; stdout={stdout:?}"
    );
}

#[test]
fn mode_pre_exec_doctor_substrate_failure_surfaces_and_proceeds() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_next_pf_status(FirewallError::NonZero {
            code: 1,
            stderr: "sudo: a password is required".into(),
        });
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-y"],
        b"",
    );
    assert_eq!(code, 0, "verb proceeds despite audit substrate failure");
    assert!(
        stderr.contains("failed to read pf state"),
        "substrate failure surfaces; stderr={stderr:?}"
    );
}

#[test]
fn mode_surfaces_user_directory_error_when_eligibility_probe_fails() {
    let stub = StubUserDirectory {
        fail_has_user: directory_fail_once(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74);
    assert!(
        stderr.starts_with("tenant: failed to check mode eligibility for 'dev': "),
        "expected mode_eligibility_probe_failed frame; stderr={stderr:?}"
    );
}

// --- Cowork-dir drift in pre-exec doctor ---

#[test]
fn mode_pre_exec_doctor_surfaces_cowork_acl_drift() {
    let cowork_path = std::path::PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_acl(
            &cowork_path,
            " 0: user:operator allow list,add_file,search\n",
        );
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains(
            "\u{26a0} Doctor: 1 warning for tenant 'dev' \u{2014} run `tenant doctor dev` for details"
        ),
        "cowork ACL drift must surface as a Warning aggregate; stdout={stdout:?}"
    );
}

#[test]
fn mode_pre_exec_doctor_surfaces_cowork_dir_absent() {
    let cowork_path = std::path::PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_path_kind(&cowork_path, PathKind::Absent);
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains(
            "\u{26a0} Doctor: 1 warning for tenant 'dev' \u{2014} run `tenant doctor dev` for details"
        ),
        "cowork dir absence must surface as a Warning aggregate; stdout={stdout:?}"
    );
}

// --- pf.conf anchor reference self-heal ---

#[test]
fn mode_restores_anchor_reference_missing_from_pf_conf() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_pf_conf(STOCK_PF_CONF);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
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
}
