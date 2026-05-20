//! E2E coverage for the `tenant reload [<name>]` verb — the
//! operator-facing "I edited the profile, apply it" surface. The
//! verb composes PF reapply (InstallAnchor + Reload at runtime tier)
//! and the share reapply substrate (AclOp::Grant + EnsureDirAsUser
//! parent + EnsureSymlinkAsUser per `[[shares]]` entry).
//!
//! Locked behavior:
//! - Always lands at runtime tier (no tier flag — `tenant mode
//!   <name> install` keeps the tier-swap role)
//! - No-arg form walks every tenant, continues on per-tenant failure,
//!   reports a summary, exits 0 if all clean / 74 if any tripped
//! - Single-tenant form refuses with EX_USAGE on absent / below-floor
//!   / system-account names (mirrors mode + shell + doctor)

use std::path::PathBuf;

use tenant::domain::{
    AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp, PathKind, UserId,
};

mod adapters;
mod common;
use adapters::*;
use common::*;

// ----------------------------------------------------------------
// Clap parse + dry-run vertical slice
// ----------------------------------------------------------------

#[test]
fn reload_single_tenant_dry_run_default_emits_intent_only() {
    // Smallest red→green. DryRunHostMachine returns default_profile_toml
    // (no shares) from read_profile, so the substrate is a no-op
    // share-wise; PF reapply renders empty allowlist. Standard +
    // dry-run emits the intent line only (no plan).
    let (code, stdout, stderr) = run_with(stub_with_tenant("dev"), &["reload", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, reload_dry_run_block("dev", None));
}

#[test]
fn reload_no_arg_form_dry_run_with_no_tenants_emits_summary_only() {
    // Empty HostUserDirectory → tenant_names() empty → no-tenant summary
    // explicitly tells the operator "nothing to do" so the output
    // isn't silent. Real-mode prints the line; dry-run is silent on
    // summaries (would_done is silent).
    let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["reload"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "No tenants on this host to reload.\n");
}

// ----------------------------------------------------------------
// Validation + eligibility refusals
// ----------------------------------------------------------------

#[test]
fn reload_rejects_empty_name() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["reload", ""]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn reload_rejects_reserved_names() {
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["reload", name]);
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
fn reload_refuses_when_tenant_absent() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["reload", "ghost"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: cannot reload 'ghost': does not exist\n");
}

#[test]
fn reload_refuses_when_only_orphan_group_present() {
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["reload", "dev"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert_eq!(stderr, "tenant: cannot reload 'dev': does not exist\n");
}

#[test]
fn reload_refuses_below_floor() {
    let stub = StubUserDirectory {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), UserId(0))].into_iter().collect(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["reload", "legacyusr"]);
    assert_eq!(code, 64);
    assert_eq!(
        stderr,
        "tenant: refusing to reload 'legacyusr': UID 0 is below tenant floor 600\n"
    );
}

#[test]
fn reload_refuses_system_account() {
    let stub = StubUserDirectory {
        users: vec!["phantom".to_string()],
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["reload", "phantom"]);
    assert_eq!(code, 64);
    assert_eq!(
        stderr,
        "tenant: refusing to reload 'phantom': system account (no tenant-range UID)\n"
    );
}

// ----------------------------------------------------------------
// Real-mode happy path + share substrate
// ----------------------------------------------------------------

#[test]
fn reload_single_tenant_runs_pf_and_share_substrate() {
    // Tenant with one rw share. Reload should:
    //   1. PF: InstallAnchor + Reload (at runtime tier)
    //   2. Shares: AclOp::Grant + EnsureSymlinkAsUser
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout_with_breadcrumb(
            "Reloading tenant 'dev'",
            &[
                "Firewall anchor installed at /etc/pf.anchors/tenant-dev",
                "Firewall ruleset reloaded",
                "Host 'operator' added to share group 'dev-tenant-share'",
                "ACL granted to group 'dev-tenant-share' on /tmp",
                "Symlink /Users/dev/src → /tmp installed",
            ],
            "Tenant 'dev' reloaded.",
            Some(&reload_breadcrumb("dev")),
        ),
    );

    // PF: exactly InstallAnchor + Reload (no recovery / setup ops).
    let fw_ops = exec.firewall_ops();
    assert_eq!(fw_ops.len(), 2, "expected 2 firewall ops, got {fw_ops:?}");
    assert!(matches!(fw_ops[0], FirewallOp::InstallAnchor { .. }));
    assert!(matches!(fw_ops[1], FirewallOp::Reload));
    for op in &fw_ops {
        assert!(
            !matches!(
                op,
                FirewallOp::FlushAnchor { .. }
                    | FirewallOp::BackupConfig
                    | FirewallOp::RestoreConfigFromBackup
                    | FirewallOp::RemoveAnchor { .. }
                    | FirewallOp::UpdateConfig { .. }
                    | FirewallOp::Enable
            ),
            "reload must NOT emit create/destroy firewall ops; saw {op:?}"
        );
    }

    // Shares: one Grant on /tmp at rw.
    let acl_ops = exec.acl_ops();
    assert_eq!(
        acl_ops,
        vec![AclOp::Grant {
            path: PathBuf::from("/tmp"),
            group: "dev-tenant-share".into(),
            mode: tenant::domain::AclMode::Rw,
        }]
    );

    // Symlink op (no EnsureDir for $HOME-direct entries).
    let symlinks: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .collect();
    assert_eq!(symlinks.len(), 1, "expected single symlink op");
}

#[test]
fn reload_profile_read_failure_surfaces_before_prompt() {
    // Behavior pin: dispatch builds the reapply plan BEFORE the
    // confirm prompt, so a missing profile surfaces pre-prompt with
    // no stdout output. Don't ask the operator to confirm an action
    // already known to fail.
    let exec = StubHostMachine::new(); // no profile preloaded
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "--verbose"],
    );
    assert_eq!(code, 74);
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
fn reload_verbose_plan_block_includes_share_ops() {
    // The verbose plan block lives in the summary, rendered only
    // when the operator is interactive OR in dry-run. Scripted
    // real-mode drops the plan (solo-Mac scope; cleaner log trace).
    // Dry-run can't be used here because `DryRunHostMachine::read_profile`
    // returns the default empty-shares TOML regardless of the
    // underlying stub's seeded profile, so the plan would render
    // PF-only. Solve by simulating an interactive (TTY=true) operator
    // who answers `y`; the live host machine reads the share-bearing
    // profile, the summary renders the share ops in the intent-leads
    // layout, the prompt is consumed, and execution proceeds.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "--verbose"],
        b"y\n",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Plan (commands to execute):"),
        "verbose interactive should emit the plan section header: {stdout:?}"
    );
    assert!(
        stdout.contains("Install firewall anchor at /etc/pf.anchors/tenant-dev"),
        "plan must list InstallAnchor intent: {stdout:?}"
    );
    assert!(
        stdout.contains("      sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n"),
        "plan must list InstallAnchor shell line: {stdout:?}"
    );
    assert!(
        stdout.contains("Grant 'dev-tenant-share' ACL access to /tmp"),
        "plan must list Grant intent: {stdout:?}"
    );
    assert!(
        stdout.contains("      chmod +a \"group:dev-tenant-share allow"),
        "plan must list Grant shell line: {stdout:?}"
    );
    assert!(
        stdout.contains("Install symlink /Users/dev/src \u{2192} /tmp (as tenant)"),
        "plan must list EnsureSymlinkAsUser intent: {stdout:?}"
    );
    assert!(
        stdout.contains("      sudo -n -u dev /bin/ln -sfn /tmp /Users/dev/src\n"),
        "plan must list EnsureSymlinkAsUser shell line: {stdout:?}"
    );
}

#[test]
fn reload_single_tenant_with_existing_symlink_at_tenant_path_succeeds_idempotently() {
    // PathKind::Symlink coverage on the reload path: the substrate
    // proceeds (existing symlink is the idempotent re-link case).
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_tenant_path_kind(
            "dev",
            &PathBuf::from("/Users/dev/src"),
            tenant::domain::PathKind::Symlink(PathBuf::from("/tmp")),
        );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(exec.acl_ops().len(), 1, "Grant fires (idempotent re-link)");
}

#[test]
fn reload_single_tenant_verbose_emits_per_op_echo() {
    // Scripted-real-verbose drops the upfront plan; section divider
    // opens, `$` echo + ✓ progress lines fire per substrate op, Done
    // section + closing line. PF ops + per-share ops both appear in
    // the echo block.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "--verbose"],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.starts_with(&format!("{}\n", section_line("Reloading tenant 'dev'"))),
        "section divider first: {stdout:?}"
    );
    // Echo: PF ops + per-share ops (AclOp + EnsureSymlinkAsUser).
    assert!(
        stdout.contains("$ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n"),
        "echo should show InstallAnchor: {stdout:?}"
    );
    assert!(
        stdout.contains("$ chmod +a \"group:dev-tenant-share allow"),
        "echo should show chmod +a: {stdout:?}"
    );
    assert!(
        stdout.contains("$ sudo -n -u dev /bin/ln -sfn /tmp /Users/dev/src\n"),
        "echo should show symlink op: {stdout:?}"
    );
    assert!(
        stdout.ends_with(&format!(
            "Tenant 'dev' reloaded.\n{}\n",
            reload_breadcrumb("dev")
        )),
        "post-exec done line + breadcrumb last: {stdout:?}"
    );
}

#[test]
fn reload_with_default_profile_runs_pf_only_no_share_ops() {
    // Default profile has no shares → share substrate is a no-op.
    // PF reapply still fires.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(exec.acl_ops().is_empty(), "no shares → no AclOp");
    let new_account_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| {
            matches!(
                op,
                AccountOp::EnsureDirAsUser { .. } | AccountOp::EnsureSymlinkAsUser { .. }
            )
        })
        .collect();
    assert!(
        new_account_ops.is_empty(),
        "no shares → no EnsureDir / EnsureSymlink: {new_account_ops:?}"
    );
}

// ----------------------------------------------------------------
// Substrate-failure framing
// ----------------------------------------------------------------

#[test]
fn reload_firewall_failure_surfaces_with_reload_specific_wording() {
    // The mode-verb's `mode_failed` says "failed to apply firewall
    // mode" — reload's framing says "failed to reload firewall"
    // (no tier-swap implied).
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .fail_firewall_op(
            FirewallOp::Reload,
            FirewallError::NonZero {
                code: 1,
                stderr: "pfctl: Syntax error in anchor body\n".into(),
            },
        );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("failed to reload firewall for 'dev'"),
        "expected reload_firewall_failed frame: {stderr:?}"
    );
    assert!(
        !stderr.contains("firewall mode"),
        "must NOT use mode-verb wording: {stderr:?}"
    );
}

#[test]
fn reload_refuses_when_host_path_missing() {
    // HostPathMissing refusal applied through reload: frame says
    // "cannot reload" (distinct from mode-verb's "cannot apply
    // mode").
    let toml = profile_with_shares(
        &[],
        &[],
        &[("/nonexistent/missing/reload-sentinel", "rw", "$HOME/src")],
    );
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("cannot reload 'dev'"),
        "expected refuse_reload_share frame: {stderr:?}"
    );
    assert!(
        stderr.contains("/nonexistent/missing/reload-sentinel"),
        "should name the missing host_path: {stderr:?}"
    );
}

#[test]
fn reload_refuses_when_tenant_path_occupied() {
    // TenantPathOccupied refusal applied through reload.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_tenant_path_kind("dev", &PathBuf::from("/Users/dev/src"), PathKind::Other);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("cannot reload 'dev'"),
        "expected refuse_reload_share frame: {stderr:?}"
    );
    assert!(
        stderr.contains("/Users/dev/src"),
        "should name the occupied tenant_path: {stderr:?}"
    );
}

#[test]
fn reload_routes_acl_failure_via_reapply_arms() {
    // Substrate failure on AclOp::Grant surfaces via the shared
    // `mode_acl_failed` framing (no verb-specific wording for ACL
    // arm — reuses the substrate-action phrase).
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
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
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("failed to apply ACL for 'dev'"),
        "expected mode_acl_failed frame (reused for reload): {stderr:?}"
    );
}

#[test]
fn reload_routes_symlink_failure_via_reapply_arms() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
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
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("failed to install tenant-side filesystem state for 'dev'"),
        "expected mode_account_failed frame (reused for reload): {stderr:?}"
    );
}

// ----------------------------------------------------------------
// No-arg form (walk every tenant)
// ----------------------------------------------------------------

#[test]
fn reload_no_arg_walks_all_tenants_in_alphabetical_order() {
    // tenant_names() returns alphabetical order so output is stable
    // across runs. Verify by exit code + summary line shape.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_existing_profile("staging", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) = run_with_exec(make_two_tenant_stub_reader(), &exec, &["reload"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    // Summary line at the tail.
    assert!(
        stdout.contains("Reloaded 2 tenant(s).\n"),
        "expected summary line: {stdout:?}"
    );
}

#[test]
fn reload_no_arg_continues_on_per_tenant_failure() {
    // One tenant fails, the walk continues to the next.
    // Inject a profile-read failure for 'dev' but leave 'staging'
    // healthy. The walk emits per-tenant failure inline + a summary
    // counting 1 failure.
    let exec = StubHostMachine::new()
        .with_existing_profile("staging", &tenant::profile::default_profile_toml());
    // 'dev' has no profile preloaded → read_profile fails for dev.
    let (code, stdout, stderr) = run_with_exec(make_two_tenant_stub_reader(), &exec, &["reload"]);
    assert_eq!(code, 74, "EX_IOERR expected on any per-tenant failure");
    // Failure line for dev appears on stderr.
    assert!(
        stderr.contains("failed to read profile") && stderr.contains("'dev'"),
        "expected per-tenant failure for dev: {stderr:?}"
    );
    // Summary: 1 succeeded, 1 failed.
    assert!(
        stdout.contains("Reloaded 1 of 2 tenant(s); 1 failed.\n"),
        "expected per-failure summary line: {stdout:?}"
    );
}

#[test]
fn reload_no_arg_emits_no_op_summary_when_no_tenants() {
    let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["reload"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "No tenants on this host to reload.\n");
}

#[test]
fn reload_fires_add_host_unconditionally_even_when_host_already_member() {
    // Catch-up posture: every reload runs `AddHostToShareGroup`
    // regardless of whether the host is currently a member. The
    // substrate is idempotent (`dseditgroup -o edit -a` on an existing
    // member is a silent noop in production; the stub records every
    // call as one entry in account_ops). Stub default is `true` for
    // host_in_group; we explicitly set `true` here too to make the
    // intent visible — the test pins "AddHost fires in the plan even
    // when state says member already" so a future regression that
    // tries to optimize the catch-up away via host_in_group pre-check
    // trips this.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_in_group("operator", "dev-tenant-share", true);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0);
    assert_eq!(
        exec.account_ops(),
        vec![AccountOp::AddHostToShareGroup {
            group: "dev-tenant-share".into(),
            host: "operator".into(),
        }],
        "reload fires AddHost unconditionally (substrate is idempotent, not Tenants-side conditional)"
    );
}

#[test]
fn reload_account_ops_position_pins_add_host_after_pf_before_shares() {
    // Reapply ordering lock: AddHost runs INSIDE execute_reapply_plan
    // AFTER the PF reapply (InstallAnchor + Reload) and BEFORE the
    // per-share ops (Acl::Grant + EnsureSymlinkAsUser). Verify by
    // observing the cross-domain order: firewall_ops happen first,
    // then the one account op (AddHost), then the acl op.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0);
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::AddHostToShareGroup {
                group: "dev-tenant-share".into(),
                host: "operator".into(),
            },
            AccountOp::EnsureSymlinkAsUser {
                name: "dev".into(),
                link: PathBuf::from("/Users/dev/src"),
                target: PathBuf::from("/tmp"),
            },
        ],
        "AddHost recorded before the share-substrate ops"
    );
}

// ================================================================
// Pre-exec doctor audit: reload scope
// ================================================================
//
// Reload's audit considers PfDisabled host-wide + the full per-tenant
// drift set (PfRuleDrift, AnchorBodyDrift, AclDrift, SymlinkDrift,
// HostNotInShareGroup) — same per-tenant set as Shell because reload
// is the verb whose job IS share convergence. EnvLeak is OUT
// (shell-specific operator impact; reload's share substrate is
// mkdir/ln/chmod, no ssh-agent reach).

#[test]
fn reload_pre_exec_doctor_silent_when_host_is_clean() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("\u{26a0} Doctor:") && !stdout.contains("critical:"),
        "clean host must not emit audit; stdout={stdout:?}"
    );
}

#[test]
fn reload_pre_exec_doctor_emits_critical_inline_when_pf_disabled() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_pf_status_content("Status: Disabled\n");
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("critical: pf is globally disabled"),
        "PfDisabled critical must emit inline; stdout={stdout:?}"
    );
}

#[test]
fn reload_pre_exec_doctor_aggregates_host_not_in_share_group_warning() {
    // HostNotInShareGroup → 1 warning aggregate. Singular noun.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_in_group("operator", "dev-tenant-share", false);
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\u{26a0} Doctor: 1 warning for tenant 'dev' \u{2014} run `tenant doctor dev` for details"),
        "HostNotInShareGroup → aggregate with singular noun; stdout={stdout:?}"
    );
}

#[test]
fn reload_pre_exec_doctor_scope_excludes_env_leak() {
    // EnvLeak is Shell-only — reload's share substrate doesn't reach
    // for ssh-agent socket. Audit must not aggregate any warning.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_env_policy_content("");
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("\u{26a0} Doctor:"),
        "EnvLeak must NOT propagate to reload scope; stdout={stdout:?}"
    );
}

#[test]
fn reload_pre_exec_doctor_substrate_failure_surfaces_and_proceeds() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_next_pf_status(FirewallError::NonZero {
            code: 1,
            stderr: "sudo: a password is required".into(),
        });
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "verb proceeds despite audit substrate failure");
    assert!(
        stderr.contains("failed to read pf state"),
        "substrate failure surfaces; stderr={stderr:?}"
    );
}

#[test]
fn reload_surfaces_user_directory_error_when_eligibility_probe_fails() {
    // Single-tenant reload re-uses `destroy_eligibility`; a dscl failure
    // routes to `reload_eligibility_probe_failed` with reload-named
    // action wording.
    let stub = StubUserDirectory {
        fail_has_user: directory_fail_once(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["reload", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.starts_with("tenant: failed to check reload eligibility for 'dev': "),
        "expected reload_eligibility_probe_failed frame; stderr={stderr:?}"
    );
}

#[test]
fn reload_all_surfaces_user_directory_error_when_tenant_enumeration_fails() {
    // No-arg `reload` walks `directory.tenant_names()`; a dscl failure
    // surfaces as `reload_all_enumeration_failed` and aborts the walk
    // before any per-tenant work.
    let stub = StubUserDirectory {
        fail_tenant_names: directory_fail_once(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["reload"]);
    assert_eq!(code, 74);
    assert!(
        stderr.starts_with("tenant: failed to enumerate tenants for reload: "),
        "expected reload_all_enumeration_failed frame; stderr={stderr:?}"
    );
}
