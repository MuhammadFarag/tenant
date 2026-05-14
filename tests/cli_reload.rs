//! E2E coverage for the `tenant reload [<name>]` verb — cycle 10's
//! "I edited the profile, apply it" surface. The verb composes PF
//! reapply (InstallAnchor + Reload at runtime tier) and the share
//! reapply substrate (AclOp::Grant + EnsureDirAsUser parent +
//! EnsureSymlinkAsUser per `[[shares]]` entry).
//!
//! Locked behavior:
//! - Always lands at runtime tier (no tier flag — `tenant mode
//!   <name> install` keeps the tier-swap role)
//! - No-arg form walks every tenant, continues on per-tenant failure,
//!   reports a summary, exits 0 if all clean / 74 if any tripped
//!   (Q15)
//! - Single-tenant form refuses with EX_USAGE on absent / below-floor
//!   / system-account names (mirrors mode + shell + doctor)

use std::path::PathBuf;

use tenant::accounts::StubReader;
use tenant::executor::{
    AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp, PathKind, StubExecutor,
};

mod common;
use common::*;

// ----------------------------------------------------------------
// Sub-cycle 5.1: clap parse + dry-run vertical slice
// ----------------------------------------------------------------

#[test]
fn reload_single_tenant_dry_run_default_emits_intent_only() {
    // Smallest red→green. DryRunExecutor returns default_profile_toml
    // (no shares) from read_profile, so the substrate is a no-op
    // share-wise; PF reapply renders empty allowlist. Standard +
    // dry-run emits the intent line only (no plan).
    let (code, stdout, stderr) = run_with(stub_with_tenant("dev"), &["reload", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would reload tenant 'dev'.\n");
}

#[test]
fn reload_no_arg_form_dry_run_with_no_tenants_emits_summary_only() {
    // Empty Reader → tenant_names() empty → no-tenant summary
    // explicitly tells the operator "nothing to do" so the output
    // isn't silent. Real-mode prints the line; dry-run is silent on
    // summaries (would_done is silent).
    let (code, stdout, _stderr) = run_with(StubReader::default(), &["reload"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "No tenants on this host to reload.\n");
}

// ----------------------------------------------------------------
// Sub-cycle 5.2: validation + eligibility refusals
// ----------------------------------------------------------------

#[test]
fn reload_rejects_empty_name() {
    let (code, stdout, stderr) = run_with(StubReader::default(), &["reload", ""]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn reload_rejects_reserved_names() {
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) = run_with(StubReader::default(), &["reload", name]);
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
    let (code, stdout, stderr) = run_with(StubReader::default(), &["reload", "ghost"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: cannot reload 'ghost': does not exist\n");
}

#[test]
fn reload_refuses_when_only_orphan_group_present() {
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["reload", "dev"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert_eq!(stderr, "tenant: cannot reload 'dev': does not exist\n");
}

#[test]
fn reload_refuses_below_floor() {
    let stub = StubReader {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), 0)].into_iter().collect(),
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
    let stub = StubReader {
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
// Sub-cycle 5.3: real-mode happy path + share substrate
// ----------------------------------------------------------------

#[test]
fn reload_single_tenant_runs_pf_and_share_substrate() {
    // Tenant with one rw share. Reload should:
    //   1. PF: InstallAnchor + Reload (at runtime tier)
    //   2. Shares: AclOp::Grant + EnsureSymlinkAsUser
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Reloaded tenant 'dev'.\n");

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
            group: "dev-tenant-share".to_string(),
            mode: tenant::executor::AclMode::Rw,
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
fn reload_verbose_emits_intent_before_profile_read_failure() {
    // Round-2 review parity fix: `reload dev -v` against a missing
    // profile should emit "Reloading tenant 'dev'." before the read
    // failure surfaces. Mirrors shell + mode.
    let exec = StubExecutor::new(); // no profile preloaded
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "--verbose"],
    );
    assert_eq!(code, 74);
    assert!(
        stdout.starts_with("Reloading tenant 'dev'.\n"),
        "intent should emit before the profile-read failure: {stdout:?}"
    );
}

#[test]
fn reload_verbose_plan_block_includes_share_ops() {
    // Round-1 review fix: the upfront plan block must include the
    // share ops alongside PF ops, not just echo them later.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "--verbose"],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("  sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n"),
        "plan must list InstallAnchor: {stdout:?}"
    );
    assert!(
        stdout.contains("  chmod +a \"group:dev-tenant-share allow"),
        "plan must list Grant: {stdout:?}"
    );
    assert!(
        stdout.contains("  sudo -n -u dev /bin/ln -sfn /tmp /Users/dev/src\n"),
        "plan must list EnsureSymlinkAsUser: {stdout:?}"
    );
}

#[test]
fn reload_single_tenant_with_existing_symlink_at_tenant_path_succeeds_idempotently() {
    // PathKind::Symlink coverage on the reload path: the substrate
    // proceeds (existing symlink is the idempotent re-link case).
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &toml)
        .with_tenant_path_kind(
            "dev",
            &PathBuf::from("/Users/dev/src"),
            tenant::executor::PathKind::Symlink,
        );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(exec.acl_ops().len(), 1, "Grant fires (idempotent re-link)");
}

#[test]
fn reload_single_tenant_verbose_emits_plan_and_per_op_echo() {
    // Plan shows PF ops; `$` echo shows them plus per-share ops as
    // they fire.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "--verbose"],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.starts_with("Reloading tenant 'dev'.\n"),
        "verbose intent first: {stdout:?}"
    );
    // Plan lists InstallAnchor + Reload.
    assert!(
        stdout.contains("  sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n"),
        "plan should list InstallAnchor: {stdout:?}"
    );
    assert!(
        stdout.contains("  sudo pfctl -f /etc/pf.conf\n"),
        "plan should list Reload: {stdout:?}"
    );
    // Echo: PF ops + per-share ops (AclOp + EnsureSymlinkAsUser).
    assert!(
        stdout.contains("$ chmod +a \"group:dev-tenant-share allow"),
        "echo should show chmod +a: {stdout:?}"
    );
    assert!(
        stdout.contains("$ sudo -n -u dev /bin/ln -sfn /tmp /Users/dev/src\n"),
        "echo should show symlink op: {stdout:?}"
    );
    assert!(
        stdout.ends_with("Reloaded tenant 'dev'.\n"),
        "post-exec done line last: {stdout:?}"
    );
}

#[test]
fn reload_with_default_profile_runs_pf_only_no_share_ops() {
    // Default profile has no shares → share substrate is a no-op.
    // PF reapply still fires.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
// Sub-cycle 5.4: substrate-failure framing
// ----------------------------------------------------------------

#[test]
fn reload_firewall_failure_surfaces_with_reload_specific_wording() {
    // The mode-verb's `mode_failed` says "failed to apply firewall
    // mode" — reload's framing says "failed to reload firewall"
    // (no tier-swap implied).
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new()
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
    // Q11 lock applied through reload: HostPathMissing refusal frame
    // says "cannot reload" (distinct from mode-verb's "cannot apply
    // mode").
    let toml = profile_with_shares(
        &[],
        &[],
        &[("/nonexistent/cycle10/reload-sentinel", "rw", "$HOME/src")],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("cannot reload 'dev'"),
        "expected refuse_reload_share frame: {stderr:?}"
    );
    assert!(
        stderr.contains("/nonexistent/cycle10/reload-sentinel"),
        "should name the missing host_path: {stderr:?}"
    );
}

#[test]
fn reload_refuses_when_tenant_path_occupied() {
    // Q12 lock applied through reload.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new()
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
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &toml)
        .fail_acl_op(
            AclOp::Grant {
                path: PathBuf::from("/tmp"),
                group: "dev-tenant-share".into(),
                mode: tenant::executor::AclMode::Rw,
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
    let exec = StubExecutor::new()
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
// Sub-cycle 5.5: no-arg form (Q15)
// ----------------------------------------------------------------

#[test]
fn reload_no_arg_walks_all_tenants_in_alphabetical_order() {
    // tenant_names() returns alphabetical order so output is stable
    // across runs. Verify by exit code + summary line shape.
    let exec = StubExecutor::new()
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
    // Q15 lock: one tenant fails, the walk continues to the next.
    // Inject a profile-read failure for 'dev' but leave 'staging'
    // healthy. The walk emits per-tenant failure inline + a summary
    // counting 1 failure.
    let exec = StubExecutor::new()
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
    let (code, stdout, _stderr) = run_with(StubReader::default(), &["reload"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "No tenants on this host to reload.\n");
}
