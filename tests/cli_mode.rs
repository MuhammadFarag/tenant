use std::path::PathBuf;

use tenant::accounts::StubReader;
use tenant::executor::{
    AccountOp, AclMode, AclOp, FirewallError, FirewallOp, PathKind, StubExecutor,
};

mod common;
use common::*;

// ================================================================
// Mode verb — cycle 3 of the PF + profile + mode bundle
// ================================================================
//
// Locked design (see CLAUDE.md doctrine):
// - Q1: NO defensive FlushAnchor before InstallAnchor. The parent
//   `load anchor` directive stays in pf.conf across mode reapply,
//   so `pfctl -f` re-reads the anchor file and replaces the
//   in-kernel ruleset. Verified empirically by the cycle-3 smoke.
// - Q2: Implicit current-mode (no state file). The on-disk anchor
//   body is the source of truth.
// - Q3: Auto-narrow on shell entry deferred to cycle 4. Cycle 3
//   ships the `mode` verb only; the operator narrows manually with
//   `tenant mode <name> runtime` after install-tier work.
// - Q4: ModeError { Profile, Firewall } — verb-isolated failure
//   surface paralleling DestroyError's split.

// ----------------------------------------------------------------
// Sub-cycle 3.1: clap parse + dry-run vertical slice
// ----------------------------------------------------------------

#[test]
fn mode_runtime_dry_run_default_shows_intent() {
    // Smallest red→green for the verb. `stub_with_tenant("dev")`
    // gives a tenant-range user so eligibility classifies as
    // Destroyable; dry-run swaps in DryRunExecutor which returns
    // `default_profile_toml()` from read_profile, so the writer's
    // profile-read + parse + render path completes without touching
    // the StubExecutor we (don't) wire here.
    let (code, stdout, stderr) = run_with(
        stub_with_tenant("dev"),
        &["mode", "dev", "runtime", "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would apply mode 'runtime' to tenant 'dev'.\n");
}

#[test]
fn mode_install_dry_run_default_shows_intent() {
    // Symmetric to the runtime test. Install ModeLevel parses too.
    let (code, stdout, stderr) = run_with(
        stub_with_tenant("dev"),
        &["mode", "dev", "install", "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would apply mode 'install' to tenant 'dev'.\n");
}

#[test]
fn mode_rejects_unknown_level() {
    // Clap's ValueEnum derivation accepts only `runtime` and `install`.
    // Anything else fails parse with exit 1 before dispatch runs.
    let (code, stdout, _stderr) = run_with(stub_with_tenant("dev"), &["mode", "dev", "bogus"]);
    assert_eq!(code, 1, "clap should reject unknown level");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
}

#[test]
fn mode_requires_name() {
    // `tenant mode` with no positional → clap parse error.
    let (code, _stdout, _stderr) = run_with(StubReader::default(), &["mode"]);
    assert_eq!(code, 1, "clap should reject missing name");
}

#[test]
fn mode_requires_level() {
    // `tenant mode dev` (no level) → clap parse error. Pins the
    // ValueEnum being a required positional.
    let (code, _stdout, _stderr) = run_with(StubReader::default(), &["mode", "dev"]);
    assert_eq!(code, 1, "clap should reject missing level");
}

// ----------------------------------------------------------------
// Sub-cycle 3.2: validation + eligibility refusals
// ----------------------------------------------------------------

#[test]
fn mode_rejects_empty_name() {
    // Lexical validation runs before eligibility; empty name trips
    // NameError::Empty and never consults the Reader. Same shape and
    // wording as create/destroy/shell.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["mode", "", "runtime"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn mode_rejects_reserved_names() {
    // Reserved-name blocklist applies to mode too. Lexical rail
    // trips before any state-based check.
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) = run_with(StubReader::default(), &["mode", name, "runtime"]);
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
    // Empty StubReader → NotPresent → refuse_mode_absent. Exit 64.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["mode", "ghost", "runtime"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot apply mode to 'ghost': does not exist\n"
    );
}

#[test]
fn mode_refuses_when_only_orphan_group_present() {
    // OrphanGroup collapses to the same refusal as NotPresent for
    // mode purposes — operator wants to apply a mode; the lingering
    // group can't host one. Mirrors shell's collapse from cycle 1
    // shell rollout.
    let stub = StubReader {
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
    // Tenant-floor guard: an account exists with a positive UID below
    // TENANT_UID_FLOOR (600) → refuse. `legacyusr` sidesteps the
    // reserved-name blocklist so this test exercises the state-based
    // refusal path specifically.
    let stub = StubReader {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), 0)].into_iter().collect(),
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
    // System-account refusal: `has_user` true, `uid_for` None (negative
    // UID was filtered by parse_id_line). Same shape as destroy/shell.
    let stub = StubReader {
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
    // Dry-run doesn't bypass eligibility — same answer real-mode
    // would give. Mirrors shell_dry_run_refuses_missing_tenant.
    let (code, stdout, stderr) = run_with(
        StubReader::default(),
        &["mode", "ghost", "runtime", "--dry-run"],
    );
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot apply mode to 'ghost': does not exist\n"
    );
}

// ----------------------------------------------------------------
// Sub-cycle 3.3: real-mode happy path — runtime
// ----------------------------------------------------------------

#[test]
fn mode_runtime_real_mode_op_shape() {
    // Two-op composition: InstallAnchor (with body rendered from
    // profile.allowlist.runtime.hosts — empty in the default profile)
    // + Reload. No defensive FlushAnchor (Q1 lock). Pre-load an
    // existing profile via with_existing_profile so the writer's
    // read_profile finds something.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Applied mode 'runtime' to tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    let expected_body = tenant::firewall::render_anchor("dev", &[]);
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
fn mode_does_not_touch_account_or_profile_ops() {
    // Negative pin: mode operates entirely in the firewall domain.
    // No DeleteUserRecord, no ProfileOp::Create/Delete — those belong
    // to create/destroy. A regression that accidentally wired mode
    // through, say, a ProfileOp::Create would trip this.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0);
    assert!(
        exec.account_ops().is_empty(),
        "mode should not invoke account_ops: {:?}",
        exec.account_ops()
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
fn mode_does_not_emit_restore_config_op() {
    // Negative pin for Q4 lock: no auto-recovery on Reload failure.
    // Cycle 2's create-side restore-on-reload-failure sequence
    // (RestoreConfigFromBackup → RemoveAnchor → Reload → FlushAnchor)
    // does NOT fire for mode. Even on success the op list should be
    // exactly [InstallAnchor, Reload] with no other firewall ops.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // Regression guard against an inline `format!("tenant-{name}")`
    // at the writer call site. The InstallAnchor's `name` field
    // should be the bare tenant name; the substrate constructs the
    // `tenant-<name>` anchor name from `tenant_anchor_name`. Verifies
    // the centralization rail.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (_code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { name, .. } => {
            assert_eq!(name, "dev", "anchor name should be bare tenant name");
        }
        other => panic!("expected InstallAnchor as first firewall op, got {other:?}"),
    }
}

// ----------------------------------------------------------------
// Sub-cycle 3.4: install mode + populated profile
// ----------------------------------------------------------------

#[test]
fn mode_install_with_only_runtime_populated() {
    // Install mode with runtime=[a,b] and install=[] should produce
    // a body with runtime hosts only (the install tier is empty, so
    // the union has no extra entries).
    let profile = profile_with_hosts(&["api.example.com", "deploy.example.com"], &[]);
    let exec = StubExecutor::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &[
            "api.example.com".to_string(),
            "deploy.example.com".to_string(),
        ],
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
    // The cycle-3 happy-path canonical: runtime=[a] + install=[b,c]
    // under install mode → anchor body has [a, b, c] in that order.
    // Order matters for render_anchor's output stability.
    let profile = profile_with_hosts(
        &["api.example.com"],
        &["nodejs.org", "storage.googleapis.com"],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &[
            "api.example.com".to_string(),
            "nodejs.org".to_string(),
            "storage.googleapis.com".to_string(),
        ],
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
    // The cycle-3 narrow path: runtime=[a] + install=[b,c] under
    // runtime mode → anchor body has [a] only. Install hosts are
    // EXCLUDED. This is the security-relevant case — narrowing back
    // must shrink the host set.
    let profile = profile_with_hosts(
        &["api.example.com"],
        &["nodejs.org", "storage.googleapis.com"],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor("dev", &["api.example.com".to_string()]);
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

#[test]
fn mode_install_with_empty_runtime_and_populated_install() {
    // Edge case: runtime=[] + install=[a,b] under install mode →
    // body has [a, b]. The order-preserving union still works when
    // the runtime tier is empty (no awkward leading-empty handling).
    let profile = profile_with_hosts(&[], &["pypi.org", "npmjs.org"]);
    let exec = StubExecutor::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0);
    let expected_body =
        tenant::firewall::render_anchor("dev", &["pypi.org".to_string(), "npmjs.org".to_string()]);
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

// ----------------------------------------------------------------
// Sub-cycle 3.5: display — standard + verbose + dry-run
// ----------------------------------------------------------------

#[test]
fn mode_real_standard_emits_only_post_exec_confirmation() {
    // Standard real mode: silent pre-exec, one summary line post-exec.
    // Matches create/destroy's pattern. The level appears in the
    // confirmation so the operator sees which mode they ended up in.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Applied mode 'runtime' to tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn mode_real_verbose_shows_plan_and_echo() {
    // Real+verbose: intent + 2-line plan + 2 `$` echoes + done.
    // The plan shows the placeholder InstallAnchor + Reload (their
    // describe lines ignore the body/content fields, so the rendered
    // text matches the real-body ops at execution time).
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Applying mode 'runtime' to tenant 'dev'.\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo pfctl -f /etc/pf.conf\n\
                $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
                $ sudo pfctl -f /etc/pf.conf\n\
                Applied mode 'runtime' to tenant 'dev'.\n";
    assert_eq!(stdout, want);
}

#[test]
fn mode_install_real_verbose_shows_install_level_text() {
    // Same plan/echo shape as runtime mode (anchor body content
    // differs but the describe text doesn't include the body).
    // The "install" level appears in the intent + done lines.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "install", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Applying mode 'install' to tenant 'dev'.\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo pfctl -f /etc/pf.conf\n\
                $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
                $ sudo pfctl -f /etc/pf.conf\n\
                Applied mode 'install' to tenant 'dev'.\n";
    assert_eq!(stdout, want);
}

#[test]
fn mode_dry_run_verbose_shows_plan_no_echo() {
    // Dry-run + verbose: "Would apply" intent + plan, but no `$`
    // echo (echo is real+verbose only) and no "Applied" done line.
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["mode", "dev", "runtime", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Would apply mode 'runtime' to tenant 'dev'.\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo pfctl -f /etc/pf.conf\n";
    assert_eq!(stdout, want);
}

#[test]
fn mode_dry_run_bypasses_injected_executor() {
    // Dry-run swap-in of DryRunExecutor means the StubExecutor wired
    // by the test never sees a call. Mirrors create/destroy/shell's
    // dry-run-bypass tests.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Would apply mode 'runtime' to tenant 'dev'.\n");
    assert!(
        exec.firewall_ops().is_empty()
            && exec.account_ops().is_empty()
            && exec.profile_ops().is_empty(),
        "executor should not be invoked in dry-run; firewall_ops={:?}, account_ops={:?}, profile_ops={:?}",
        exec.firewall_ops(),
        exec.account_ops(),
        exec.profile_ops()
    );
}

// ----------------------------------------------------------------
// Sub-cycle 3.6: failure paths
// ----------------------------------------------------------------

#[test]
fn mode_read_profile_failure_surfaces() {
    // No `with_existing_profile` → StubExecutor::read_profile returns
    // a "not found" ProfileError. Mode should surface this through
    // mode_profile_failed with the profile path framed for the operator.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
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
    // Profile loads but schema_version is unsupported → parse
    // returns ProfileError → mode_profile_failed. The operator-readable
    // refusal message ("schema_version N not understood") is preserved
    // through the surface.
    let exec = StubExecutor::new().with_existing_profile(
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
    // InstallAnchor (the first firewall op) fails → mode_failed with
    // the FirewallError display. Reload should NOT run after a failed
    // InstallAnchor.
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_firewall_op(
            FirewallOp::InstallAnchor {
                name: "dev".into(),
                body: tenant::firewall::render_anchor("dev", &[]),
            },
            FirewallError::Fs {
                path: "/etc/pf.anchors/tenant-dev".into(),
                message: "permission denied".into(),
            },
        );
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to apply firewall mode for 'dev': \
         filesystem error at /etc/pf.anchors/tenant-dev: permission denied\n"
    );
    // Only InstallAnchor recorded; Reload should NOT have fired.
    assert_eq!(exec.firewall_ops().len(), 1);
    assert!(matches!(
        exec.firewall_ops()[0],
        FirewallOp::InstallAnchor { .. }
    ));
}

#[test]
fn mode_reload_failure_surfaces_without_recovery() {
    // Reload fails → mode_failed. Critically, NO recovery sequence
    // fires (no RestoreConfigFromBackup, no RemoveAnchor, no second
    // Reload, no FlushAnchor). The verb is idempotent; the operator
    // reruns to retry. Mirrors plugin's reapply_anchor.
    let exec = StubExecutor::new()
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
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert!(
        stderr.contains("failed to apply firewall mode for 'dev'"),
        "stderr should be framed by mode_failed: {stderr:?}"
    );
    // Exactly two firewall ops: InstallAnchor (succeeded) + Reload
    // (failed). No recovery follow-up.
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

// ================================================================
// Cycle 10: share reapply integration with mode verb
// ================================================================
//
// `tenant mode <name> <tier>` reapplies PF anchor AT THE TIER + per-
// share substrate (ACL grant + parent dir ensure + symlink ensure).
// Tests pin op sequences, refusal paths (Q11 host_path missing, Q12
// tenant_path occupied), Q13 declared-order, and $HOME expansion at
// the layer boundary.

#[test]
fn mode_verbose_emits_intent_before_profile_read_failure() {
    // Round-2 review parity fix: `mode dev runtime -v` against a
    // missing profile should emit the "Applying mode 'runtime' to
    // tenant 'dev'." intent line BEFORE the read failure surfaces.
    // Mirrors `shell`'s `shell_intent` posture; `mode_intent` runs
    // first, then `build_reapply_plan` attempts the read.
    let exec = StubExecutor::new(); // no profile preloaded
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "--verbose"],
    );
    assert_eq!(code, 74, "EX_IOERR expected");
    assert!(
        stdout.starts_with("Applying mode 'runtime' to tenant 'dev'.\n"),
        "intent should emit before the profile-read failure surfaces: {stdout:?}"
    );
}

#[test]
fn mode_runtime_with_shares_emits_per_share_substrate_ops() {
    // Single rw share: `/tmp` (real host_path; always exists) →
    // `$HOME/src` (tenant-side). Mode reapply runs:
    //   PF: InstallAnchor + Reload
    //   Shares: AclOp::Grant + AccountOp::EnsureDirAsUser(parent) +
    //           AccountOp::EnsureSymlinkAsUser
    // EnsureDir's parent is `/Users/dev/` (the tenant home dir
    // itself), which the substrate skips per the "home always exists"
    // optimization — so no EnsureDirAsUser fires for `$HOME/src`.
    // Verifies: AclOp recorded with literal group + path; symlink
    // op recorded with expanded tenant_path.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");

    let acl_ops = exec.acl_ops();
    assert_eq!(
        acl_ops,
        vec![AclOp::Grant {
            path: PathBuf::from("/tmp"),
            group: "dev-tenant-share".to_string(),
            mode: AclMode::Rw,
        }],
        "expected single Grant op for /tmp at rw; got {acl_ops:?}"
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
fn mode_runtime_with_nested_tenant_path_emits_ensure_dir_for_parent() {
    // tenant_path under a subdirectory of $HOME: `$HOME/.local/share/chezmoi`.
    // Parent `/Users/dev/.local/share` is NOT the home itself, so
    // EnsureDirAsUser must fire on it (substrate is responsible for
    // mkdir -p). Symlink then points the leaf at host_path.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "ro", "$HOME/.local/share/chezmoi")]);
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
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
    // Q13 lock: shares apply in profile-declared order. Verify by
    // recording the AclOp sequence: zeta first, alpha second.
    let toml = profile_with_shares(
        &[],
        &[],
        &[("/tmp", "rw", "$HOME/zeta"), ("/var", "ro", "$HOME/alpha")],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    let host_paths: Vec<PathBuf> = exec
        .acl_ops()
        .into_iter()
        .filter_map(|op| match op {
            AclOp::Grant { path, .. } => Some(path),
            _ => None,
        })
        .collect();
    assert_eq!(
        host_paths,
        vec![PathBuf::from("/tmp"), PathBuf::from("/var")],
        "expected declared order [zeta=/tmp, alpha=/var]"
    );
}

#[test]
fn mode_refuses_when_host_path_does_not_exist() {
    // Q11 lock: HostPathMissing surfaces as refuse_mode_share before
    // any share substrate op runs. The PF reapply ops still fire
    // (they precede the share pass) — but no AclOp / AccountOp
    // EnsureDir / EnsureSymlink should be recorded.
    let toml = profile_with_shares(
        &[],
        &[],
        &[("/nonexistent/cycle10/sentinel", "rw", "$HOME/src")],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
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
        stderr.contains("/nonexistent/cycle10/sentinel"),
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
    // Q12 lock: TenantPathOccupied surfaces as refuse_mode_share
    // when probe returns PathKind::Other. Stub returns Other for
    // the expanded tenant_path; no substrate op fires after refusal.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new()
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
fn mode_runtime_skips_substrate_with_existing_symlink_at_tenant_path() {
    // PathKind::Symlink is the idempotent re-link case: substrate
    // proceeds (chmod-pre-check is idempotent; ln -sfn replaces an
    // existing symlink). No refusal — share substrate fires
    // normally.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &toml)
        .with_tenant_path_kind("dev", &PathBuf::from("/Users/dev/src"), PathKind::Symlink);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(
        code, 0,
        "expected success on existing symlink; stderr={stderr:?}"
    );
    assert_eq!(
        exec.acl_ops().len(),
        1,
        "expected single Grant despite existing symlink (idempotent reapply)"
    );
}

#[test]
fn mode_install_tier_does_not_change_share_substrate() {
    // Shares are tier-independent: the same host_path/mode/tenant_path
    // applies whether the operator widened the firewall for an install
    // step or narrowed back. Verify by running `mode dev install` on a
    // profile with a share — share substrate fires with the same shape.
    let toml = profile_with_shares(
        &["github.com"],
        &["nodejs.org"],
        &[("/tmp", "rw", "$HOME/src")],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(
        exec.acl_ops().len(),
        1,
        "share substrate should fire at install tier same as runtime"
    );
}
