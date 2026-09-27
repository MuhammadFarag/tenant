use tenant::domain::{AccountOp, FirewallError, FirewallOp, UserId};

mod adapters;
mod common;
use adapters::*;
use common::*;

// --- Clap parse + dry-run ---

#[test]
fn inbound_restricted_dry_run_default_shows_intent() {
    // DryRunHostMachine::read_profile returns the default profile (no inbound ports).
    let (code, stdout, stderr) = run_with(
        stub_with_tenant("dev"),
        &["inbound", "dev", "restricted", "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, inbound_dry_run_block("dev", "restricted", None));
}

#[test]
fn inbound_permissive_dry_run_default_shows_intent() {
    let (code, stdout, stderr) = run_with(
        stub_with_tenant("dev"),
        &["inbound", "dev", "permissive", "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, inbound_dry_run_block("dev", "permissive", None));
}

#[test]
fn inbound_rejects_unknown_level() {
    let (code, stdout, _stderr) = run_with(stub_with_tenant("dev"), &["inbound", "dev", "bogus"]);
    assert_eq!(code, 2, "clap should reject unknown level");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
}

#[test]
fn inbound_requires_name() {
    let (code, _stdout, _stderr) = run_with(StubUserDirectory::default(), &["inbound"]);
    assert_eq!(code, 2, "clap should reject missing name");
}

#[test]
fn inbound_requires_level() {
    let (code, _stdout, _stderr) = run_with(StubUserDirectory::default(), &["inbound", "dev"]);
    assert_eq!(code, 2, "clap should reject missing level");
}

// --- Validation + eligibility refusals ---

#[test]
fn inbound_rejects_empty_name() {
    let (code, stdout, stderr) =
        run_with(StubUserDirectory::default(), &["inbound", "", "restricted"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn inbound_refuses_when_tenant_absent() {
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["inbound", "ghost", "restricted"],
    );
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot apply inbound posture to 'ghost': does not exist\n"
    );
}

#[test]
fn inbound_refuses_below_floor() {
    let stub = StubUserDirectory {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), UserId(0))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["inbound", "legacyusr", "restricted"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to apply inbound posture to 'legacyusr': UID 0 is below tenant floor 600\n"
    );
}

#[test]
fn inbound_refuses_system_account() {
    let stub = StubUserDirectory {
        users: vec!["phantom".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["inbound", "phantom", "restricted"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to apply inbound posture to 'phantom': system account (no tenant-range UID)\n"
    );
}

#[test]
fn inbound_surfaces_user_directory_error_when_eligibility_probe_fails() {
    let stub = StubUserDirectory {
        fail_has_user: directory_fail_once(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["inbound", "dev", "restricted"]);
    assert_eq!(code, 74);
    assert!(
        stderr.starts_with("tenant: failed to check inbound eligibility for 'dev': "),
        "expected inbound_eligibility_probe_failed frame; stderr={stderr:?}"
    );
}

// --- Op shape: restricted ---

#[test]
fn inbound_restricted_op_shape_renders_profile_ports() {
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&["api.example.com"], &["pypi.org"])
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Restricted(vec![3000]),
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
        "inbound restricted should InstallAnchor (runtime egress + profile inbound ports) then Reload"
    );
}

#[test]
fn inbound_restricted_with_empty_ports_renders_locked() {
    // The default profile declares no inbound ports.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => assert_eq!(body, &expected_body),
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

#[test]
fn inbound_uses_light_reapply_skipping_recursive_acl_passes() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");

    assert!(
        exec.acl_ops().is_empty(),
        "inbound reapply must NOT emit AclOp::Grant (light reapply); got {:?}",
        exec.acl_ops()
    );
    let cowork_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .collect();
    assert!(
        cowork_ops.is_empty(),
        "inbound reapply must NOT emit EnsureCoworkDir (light reapply); got {cowork_ops:?}"
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

// --- Op shape: permissive ---

#[test]
fn inbound_permissive_op_shape_renders_permissive_section() {
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&["api.example.com"], &[])
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "permissive"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Permissive,
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => assert_eq!(
            body, &expected_body,
            "permissive ignores declared ports and opens all inbound loopback"
        ),
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

// --- Display: standard, verbose, dry-run, confirm ---

#[test]
fn inbound_real_standard_emits_only_post_exec_confirmation() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout_with_breadcrumb(
            "Applying inbound 'restricted' to tenant 'dev'",
            &[
                "Firewall anchor installed at /etc/pf.anchors/tenant-dev",
                "Firewall ruleset reloaded",
                "Host 'operator' added to share group 'dev-tenant-share'",
            ],
            "Tenant 'dev' inbound loopback is restricted.",
            Some(&inbound_breadcrumb("dev")),
        ),
    );
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn inbound_permissive_real_standard_done_names_permissive() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "permissive"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout_with_breadcrumb(
            "Applying inbound 'permissive' to tenant 'dev'",
            &[
                "Firewall anchor installed at /etc/pf.anchors/tenant-dev",
                "Firewall ruleset reloaded",
                "Host 'operator' added to share group 'dev-tenant-share'",
            ],
            "Tenant 'dev' inbound loopback is permissive.",
            Some(&inbound_breadcrumb("dev")),
        ),
    );
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn inbound_real_verbose_shows_plan_and_echo() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted", "-v"],
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
         Tenant 'dev' inbound loopback is restricted.\n\
         {}\n",
        section_line("Applying inbound 'restricted' to tenant 'dev'"),
        section_line("Done"),
        inbound_breadcrumb("dev"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn inbound_dry_run_verbose_shows_plan_no_echo() {
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["inbound", "dev", "restricted", "--dry-run", "-v"],
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
    assert_eq!(
        stdout,
        inbound_dry_run_block("dev", "restricted", Some(&plan))
    );
}

#[test]
fn inbound_confirm_y_default_proceeds_on_enter() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted"],
        b"\n",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Proceed? [Y/n]"),
        "inbound prompt should be Y-default; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("Tenant 'dev' inbound loopback is restricted."),
        "ENTER should proceed; stdout={stdout:?}"
    );
}

#[test]
fn inbound_dry_run_bypasses_injected_host_machine() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, inbound_dry_run_block("dev", "restricted", None));
    assert!(
        exec.firewall_ops().is_empty()
            && exec.account_ops().is_empty()
            && exec.profile_ops().is_empty(),
        "host machine should not be invoked in dry-run"
    );
}

// --- Failure paths ---

#[test]
fn inbound_read_profile_failure_surfaces_before_prompt() {
    // No `with_existing_profile`: read_profile fails before the prompt.
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted"],
    );
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
fn inbound_install_anchor_failure_surfaces() {
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
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted"],
    );
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stdout,
        format!(
            "{}\n",
            section_line("Applying inbound 'restricted' to tenant 'dev'")
        ),
    );
    assert_eq!(
        stderr,
        "tenant: failed to apply inbound posture for 'dev': \
         filesystem error at /etc/pf.anchors/tenant-dev: permission denied\n"
    );
    assert_eq!(exec.firewall_ops().len(), 1);
    assert!(matches!(
        exec.firewall_ops()[0],
        FirewallOp::InstallAnchor { .. }
    ));
}

#[test]
fn inbound_reload_failure_surfaces_without_recovery() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_firewall_op(
            FirewallOp::Reload,
            FirewallError::NonZero {
                code: 1,
                stderr: "pfctl: Syntax error in anchor body\n".into(),
            },
        );
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted"],
    );
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stdout,
        real_failure_stdout(
            "Applying inbound 'restricted' to tenant 'dev'",
            &["Firewall anchor installed at /etc/pf.anchors/tenant-dev"],
        ),
    );
    assert!(
        stderr.contains("failed to apply inbound posture for 'dev'"),
        "stderr should be framed by inbound_failed: {stderr:?}"
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
            "inbound should not emit recovery firewall ops on reload failure, saw: {op:?}"
        );
    }
}

#[test]
fn inbound_restricted_refuses_when_profile_declares_permissive_posture() {
    let exec = StubHostMachine::new().with_existing_profile(
        "dev",
        &profile_with_permissive_posture(&["api.example.com"], &[]),
    );
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["inbound", "dev", "restricted"],
    );
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout={stdout:?}");
    assert_eq!(stderr, refuse_restricted_on_permissive_profile("dev"));
    assert!(exec.firewall_ops().is_empty());
}
