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
                "Co-working directory ensured at /Users/Shared/tenants/dev",
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
        stdout.contains("      sudo chmod -R +a \"group:dev-tenant-share allow"),
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
        stdout.contains("$ sudo chmod -R +a \"group:dev-tenant-share allow"),
        "echo should show sudo chmod -R +a: {stdout:?}"
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

/// Symlink at the cowork path between sessions (corrupt prior op,
/// hand-edit, leftover) silently steers a subsequent `mkdir -p` to
/// the link target. Reload pre-flight kind-checks the cowork path
/// inside `build_reapply_plan` and refuses BEFORE any substrate op
/// fires — exit 74 + `mode_account_failed` frame, zero substrate
/// invocations.
#[test]
fn reload_refuses_when_cowork_path_is_a_symlink() {
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_path_kind(
            &cowork_path,
            PathKind::Symlink(PathBuf::from("/tmp/elsewhere")),
        );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stderr={stderr:?}");
    assert!(
        stderr.contains("failed to install tenant-side filesystem state for 'dev'"),
        "expected mode_account_failed frame: {stderr:?}"
    );
    assert!(
        stderr.contains("/Users/Shared/tenants/dev"),
        "stderr should name the cowork path: {stderr:?}"
    );
    assert!(
        stderr.contains("a symlink to /tmp/elsewhere"),
        "stderr should name the symlink target: {stderr:?}"
    );
    // Substrate must not have been touched: pre-flight refuses inside
    // build_reapply_plan, so neither the PF reapply nor the AddHost /
    // EnsureCoworkDir / share ops reach the recorder.
    assert!(
        exec.firewall_ops().is_empty(),
        "no firewall ops expected on pre-flight refusal: {:?}",
        exec.firewall_ops()
    );
    assert!(
        exec.account_ops().is_empty(),
        "no account ops expected on pre-flight refusal: {:?}",
        exec.account_ops()
    );
    assert!(
        exec.acl_ops().is_empty(),
        "no ACL ops expected on pre-flight refusal: {:?}",
        exec.acl_ops()
    );
}

/// Regular file at the cowork path (corrupt prior op, leftover from
/// a hand-edit) trips the same pre-flight as the symlink case. Same
/// exit code + frame; covers the `PathKind::Other` branch.
#[test]
fn reload_refuses_when_cowork_path_is_a_regular_file() {
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_path_kind(&cowork_path, PathKind::Other);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stderr={stderr:?}");
    assert!(
        stderr.contains("failed to install tenant-side filesystem state for 'dev'"),
        "expected mode_account_failed frame: {stderr:?}"
    );
    assert!(
        stderr.contains("/Users/Shared/tenants/dev"),
        "stderr should name the cowork path: {stderr:?}"
    );
    assert!(
        stderr.contains("a non-directory entry"),
        "stderr should name the unexpected kind: {stderr:?}"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "no firewall ops expected on pre-flight refusal: {:?}",
        exec.firewall_ops()
    );
    assert!(
        exec.account_ops().is_empty(),
        "no account ops expected on pre-flight refusal: {:?}",
        exec.account_ops()
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
        vec![
            AccountOp::AddHostToShareGroup {
                group: "dev-tenant-share".into(),
                host: "operator".into(),
            },
            AccountOp::EnsureCoworkDir {
                path: PathBuf::from("/Users/Shared/tenants/dev"),
                owner: "operator".into(),
                group: "dev-tenant-share".into(),
                mode: 0o2770,
            },
        ],
        "reload fires AddHost + cowork-dir catch-up unconditionally (substrate is idempotent, not Tenants-side conditional)"
    );
}

#[test]
fn reload_account_ops_position_pins_add_host_after_pf_before_shares() {
    // Reapply ordering lock: AddHost + EnsureCoworkDir run INSIDE
    // execute_reapply_plan AFTER the PF reapply (InstallAnchor +
    // Reload) and BEFORE the per-share ops (Acl::Grant +
    // EnsureSymlinkAsUser). Verify by observing the cross-domain
    // order: firewall_ops happen first, then the account ops
    // (AddHost + EnsureCoworkDir), then the acl op.
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
            AccountOp::EnsureCoworkDir {
                path: PathBuf::from("/Users/Shared/tenants/dev"),
                owner: "operator".into(),
                group: "dev-tenant-share".into(),
                mode: 0o2770,
            },
            AccountOp::EnsureSymlinkAsUser {
                name: "dev".into(),
                link: PathBuf::from("/Users/dev/src"),
                target: PathBuf::from("/tmp"),
            },
        ],
        "AddHost + cowork-dir recorded before the share-substrate ops"
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
fn reload_pre_exec_doctor_quiet_skips_sudo_probes_when_sudo_uncached() {
    // When the operator has no cached sudo timestamp, the pre-exec
    // audit must skip the GENUINE sudo probes
    // and emit ZERO failure frames — even when those probes are rigged
    // to fail. This fixes the fresh-terminal spam (#2/#8/#14) and
    // removes the #8 double-print structurally (uncached ⇒ zero sudo
    // probes ⇒ zero frames). The auth-free probes (host_in_group,
    // cowork, anchor-body) are NOT suppressed by the gate — they run
    // regardless of cache state; this test keeps the host clean on
    // those so the only observable effect of `uncached` is the
    // sudo-probe suppression. The auth-free-findings-still-surface
    // contract is pinned by
    // `reload_pre_exec_doctor_auth_free_probes_surface_when_sudo_uncached`.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_sudo_session_cached(false)
        // Rig every sudo-gated probe to fail: if any were invoked, its
        // failure frame would surface on stderr. The gate must skip
        // them all before they fire.
        .fail_next_pf_status(FirewallError::NonZero {
            code: 1,
            stderr: "sudo: a password is required".into(),
        })
        .fail_next_kernel_pf_rules(FirewallError::NonZero {
            code: 1,
            stderr: "sudo: a password is required".into(),
        });
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "verb proceeds; the pre-pass is a courtesy");
    assert!(
        !stderr.contains("failed to read pf state"),
        "uncached sudo must skip the gated pf probe, not surface its failure; stderr={stderr:?}"
    );
    assert!(
        !stderr.contains("failed to read host config"),
        "uncached sudo must skip the gated host-config reads silently; stderr={stderr:?}"
    );
    assert!(
        !stdout.contains("\u{26a0} Doctor:"),
        "clean auth-free state + suppressed sudo probes emits no aggregate; stdout={stdout:?}"
    );
    // host_in_group (dseditgroup checkmember) is AUTH-FREE, so the
    // tightened gate runs it regardless of cache state. The verb's own
    // execution adds the host via AddHostToShareGroup but never CHECKS
    // membership, so the pre-pass is the only caller — uncached means
    // it MUST still have fired (the inverse of the pre-tightening pin).
    assert!(
        !exec.host_in_group_invocations().is_empty(),
        "auth-free host_in_group must run even when uncached; invocations={:?}",
        exec.host_in_group_invocations()
    );
}

#[test]
fn reload_pre_exec_doctor_auth_free_probes_surface_when_sudo_uncached() {
    // The fully auth-free per-tenant probes — host_in_group
    // (dseditgroup checkmember, no
    // sudo) and the cowork-dir probe (host_path_kind + read_host_acl,
    // both host-side, no sudo) — must run REGARDLESS of sudo cache
    // state. So on an uncached terminal their findings still surface,
    // while the genuine sudo probes (read_pf_status,
    // read_kernel_pf_rules) stay suppressed and emit no failure frames.
    let cowork_path = tenant::domain::tenants::cowork_dir_path("dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_sudo_session_cached(false)
        // Auth-free drift: host not in share group + cowork dir gone.
        .with_host_in_group("operator", "dev-tenant-share", false)
        .with_host_path_kind(&cowork_path, PathKind::Absent)
        // Rig the sudo-gated probes to fail: if the gate let them run,
        // their failure frames would surface on stderr.
        .fail_next_pf_status(FirewallError::NonZero {
            code: 1,
            stderr: "sudo: a password is required".into(),
        })
        .fail_next_kernel_pf_rules(FirewallError::NonZero {
            code: 1,
            stderr: "sudo: a password is required".into(),
        });
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "verb proceeds; the pre-pass is a courtesy");
    // Auth-free probes ran: host_in_group was invoked despite uncached.
    assert!(
        !exec.host_in_group_invocations().is_empty(),
        "auth-free host_in_group must run when uncached; invocations={:?}",
        exec.host_in_group_invocations()
    );
    // Two auth-free warnings (HostNotInShareGroup + CoworkDirAbsent)
    // aggregate into the doctor hint — proving they surfaced.
    assert!(
        stdout.contains(
            "\u{26a0} Doctor: 2 warnings for tenant 'dev' \u{2014} run `tenant doctor dev` for details"
        ),
        "auth-free findings must aggregate even when uncached; stdout={stdout:?}"
    );
    // Sudo-gated probes stay suppressed: no failure frames despite the
    // rigged failures.
    assert!(
        !stderr.contains("failed to read pf state"),
        "uncached sudo must still skip the gated pf probe; stderr={stderr:?}"
    );
}

#[test]
fn reload_pre_exec_doctor_runs_sudo_probes_when_sudo_cached() {
    // Regression guard for the tightened gate: when sudo IS cached
    // (the default), the gate must NOT suppress the sudo-gated
    // probes — the pre-pass runs them exactly as it did before the
    // gate landed. This is the mirror of
    // `reload_pre_exec_doctor_quiet_skips_sudo_probes_when_sudo_uncached`:
    // there, host_in_group must NOT fire; here it MUST. A gate that
    // accidentally skipped in the cached path would zero
    // host_in_group_invocations and trip this pin.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        // Default sudo_session_cached == true; assert the cached path
        // explicitly rather than relying on the implicit default.
        .with_sudo_session_cached(true)
        // Rig a sudo-gated probe to fail: in the cached path its
        // failure frame MUST surface (proving the probe ran), the
        // inverse of the uncached test where it must be silent.
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
    assert_eq!(code, 0, "verb proceeds; the pre-pass is a courtesy");
    assert!(
        stderr.contains("failed to read pf state"),
        "cached sudo must run the gated pf probe and surface its failure; stderr={stderr:?}"
    );
    // host_in_group (dseditgroup checkmember) is AUTH-FREE, so it fires
    // under BOTH cache states — this is the PARALLEL of the uncached
    // test (lines 838-846), not its inverse. The cached path's
    // distinguishing observable is the sudo-GATED pf probe surfacing its
    // failure frame (asserted above), which the uncached path
    // suppresses. host_in_group firing here just confirms the verb's
    // sole caller (the pre-pass) ran it; the pre-pass is the only
    // membership-checker since the verb's AddHostToShareGroup never
    // CHECKS membership.
    assert!(
        !exec.host_in_group_invocations().is_empty(),
        "auth-free host_in_group runs under both cache states; invocations={:?}",
        exec.host_in_group_invocations()
    );
}

#[test]
fn reload_pre_exec_doctor_acl_drift_surfaces_but_symlink_drift_gated_when_uncached() {
    // collect_share_drift is split by auth requirement. The AclDrift
    // check reads `ls -lde` from the operator process (NO
    // sudo) and must run regardless of sudo cache state; the
    // SymlinkDrift check probes `sudo -n -u <tenant>` and must stay
    // gated. Rig BOTH drifts on a single share, run uncached, and
    // assert only AclDrift surfaces.
    //
    // The reload verb's own plan-build invokes tenant_path_kind once
    // on the share path (independent of the pre-pass). So on the
    // uncached path the ONLY tenant_path_kind call is the verb's —
    // the pre-exec doctor adds none, the mechanism by which
    // SymlinkDrift stays silent.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "ro", "$HOME/src")]);
    let tenant_path = PathBuf::from("/Users/dev/src");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_sudo_session_cached(false)
        // AclDrift (auth-free): the share host_path's ACL listing
        // carries no `group:dev-tenant-share` ACE.
        .with_host_acl(
            &PathBuf::from("/tmp"),
            " 0: user:operator allow list,add_file,search\n",
        )
        // SymlinkDrift (sudo): the tenant-side path is absent, which
        // WOULD drift — but the gated probe must not run it.
        .with_tenant_path_kind("dev", &tenant_path, PathKind::Absent);
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "verb proceeds; the pre-pass is a courtesy");
    // Only the auth-free AclDrift surfaces: one warning, not two.
    assert!(
        stdout.contains(
            "\u{26a0} Doctor: 1 warning for tenant 'dev' \u{2014} run `tenant doctor dev` for details"
        ),
        "uncached: only the auth-free AclDrift aggregates (1 warning), \
         SymlinkDrift stays gated; stdout={stdout:?}"
    );
    // No sudo failure frame; the pre-pass stays quiet on the gated half.
    assert!(
        !stderr.contains("failed"),
        "uncached share-drift split emits no failure frame; stderr={stderr:?}"
    );
    // tenant_path_kind on the share path ran exactly once — the verb's
    // own plan-build — proving the pre-exec doctor's SymlinkDrift
    // branch did NOT invoke it.
    let calls: Vec<_> = exec
        .tenant_path_kind_calls()
        .into_iter()
        .filter(|(_, p)| p == &tenant_path)
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "uncached: only the verb's plan-build probes tenant_path_kind; \
         the pre-exec SymlinkDrift check stays gated; calls={calls:?}"
    );
}

#[test]
fn reload_pre_exec_doctor_acl_and_symlink_drift_both_surface_when_cached() {
    // Cached ⇒ no regression. The SymlinkDrift half
    // of collect_share_drift runs alongside the always-on AclDrift
    // half, so BOTH findings surface. tenant_path_kind on the share
    // path fires twice — once for the verb's plan-build, once for the
    // pre-exec doctor's SymlinkDrift probe.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "ro", "$HOME/src")]);
    let tenant_path = PathBuf::from("/Users/dev/src");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_sudo_session_cached(true)
        .with_host_acl(
            &PathBuf::from("/tmp"),
            " 0: user:operator allow list,add_file,search\n",
        )
        .with_tenant_path_kind("dev", &tenant_path, PathKind::Absent);
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "verb proceeds; the pre-pass is a courtesy");
    // Both AclDrift + SymlinkDrift aggregate: two warnings.
    assert!(
        stdout.contains(
            "\u{26a0} Doctor: 2 warnings for tenant 'dev' \u{2014} run `tenant doctor dev` for details"
        ),
        "cached: both AclDrift and SymlinkDrift aggregate (2 warnings); stdout={stdout:?}"
    );
    // tenant_path_kind on the share path fired twice: verb plan-build
    // + the pre-exec doctor's now-ungated SymlinkDrift probe.
    let calls: Vec<_> = exec
        .tenant_path_kind_calls()
        .into_iter()
        .filter(|(_, p)| p == &tenant_path)
        .collect();
    assert_eq!(
        calls.len(),
        2,
        "cached: verb plan-build + pre-exec SymlinkDrift both probe; calls={calls:?}"
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

// ================================================================
// Reload uses Full reapply scope
// ================================================================
//
// Reload is the canonical "apply everything" verb. Mode + shell use
// Light scope; reload + create-post-provision use Full. A
// refactor that accidentally flipped reload's `build_reapply_plan`
// callsite to Light would silently break the convergence guarantee
// operators depend on after editing the profile or healing drift.

#[test]
fn reload_uses_full_reapply_scope_emitting_grant_and_cowork() {
    // Reload with a declared share MUST emit one AclOp::Grant per
    // share + one EnsureCoworkDir. A Full→Light flip on reload's
    // dispatch callsite zeroes both counts and trips this pin.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "reload happy path; stderr={stderr:?}");

    let grant_count = exec
        .acl_ops()
        .into_iter()
        .filter(|op| matches!(op, AclOp::Grant { .. }))
        .count();
    assert_eq!(
        grant_count, 1,
        "reload (Full scope) must emit exactly one AclOp::Grant per declared share"
    );

    let cowork_count = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .count();
    assert_eq!(
        cowork_count, 1,
        "reload (Full scope) must emit exactly one EnsureCoworkDir"
    );
}

#[test]
fn reload_all_uses_full_reapply_scope_per_tenant_emitting_grant_and_cowork() {
    // No-arg reload's per-tenant `build_reapply_plan` callsite
    // lives inside `reload_all`, INDEPENDENT of the single-tenant
    // dispatch callsite. A Full→Light flip on that line alone would
    // slip past the single-tenant pin above. Exercise two tenants
    // with declared shares; assert BOTH receive Full scope.
    let dev_toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let staging_toml = profile_with_shares(&[], &[], &[("/var", "ro", "$HOME/var-mirror")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &dev_toml)
        .with_existing_profile("staging", &staging_toml);
    let (code, _stdout, stderr) = run_with_exec(make_two_tenant_stub_reader(), &exec, &["reload"]);
    assert_eq!(code, 0, "reload-all happy path; stderr={stderr:?}");

    let grant_count = exec
        .acl_ops()
        .into_iter()
        .filter(|op| matches!(op, AclOp::Grant { .. }))
        .count();
    assert_eq!(
        grant_count, 2,
        "reload-all (Full scope) must emit one AclOp::Grant per tenant per declared share (2 total here)"
    );

    let cowork_count = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .count();
    assert_eq!(
        cowork_count, 2,
        "reload-all (Full scope) must emit one EnsureCoworkDir per tenant (2 total here)"
    );
}
