use tenant::accounts::StubReader;
use tenant::executor::{FirewallError, FirewallOp, StubExecutor};

mod common;
use common::*;

#[test]
fn shell_dry_run_default_shows_intent() {
    // Smallest red→green for the new verb. `stub_with_tenant("dev")` gives
    // us a tenant-range user (UID 600) so eligibility classifies as
    // shellable; dry-run + NeverExecutor guarantees we don't actually
    // shell out.
    let (code, stdout, stderr) = run_with(stub_with_tenant("dev"), &["shell", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would shell into 'dev'.\n");
}

#[test]
fn shell_dry_run_verbose_shows_mechanism() {
    // Dry-run verbose: intent + 3-line plan (cycle 4). The auto-narrow's
    // InstallAnchor + Reload precede the LoginAsUser in the plan. Dry-run
    // doesn't emit `$` echoes (echo is real+verbose only). The plan's
    // InstallAnchor describe line uses the placeholder body — its
    // describe ignores the body field, so the line is stable across the
    // empty-body plan placeholder and the real-body op at execute time.
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["shell", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Would shell into 'dev'.\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo -iu dev\n";
    assert_eq!(stdout, want);
}

#[test]
fn shell_real_mode_standard_emits_intent_and_invokes_exec_into() {
    // Standard real mode: one pre-exec intent line, then narrow + login.
    // Unlike create/destroy, no post-exec confirmation — the operator IS
    // the shell after login returns. The narrow runs silently in standard
    // mode (no `$` echo); only the intent line emits.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Shelling into 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(exec.logins(), vec!["dev".to_string()]);
    assert!(
        exec.account_ops().is_empty(),
        "login should not record account_ops: {:?}",
        exec.account_ops()
    );
}

#[test]
fn shell_real_mode_verbose_shows_plan_and_echo() {
    // Real+verbose: intent + 3-line plan + 3 `$` echoes (cycle 4 narrow's
    // InstallAnchor + Reload precede the LoginAsUser). No post-exec line.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Shelling into 'dev'.\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo -iu dev\n\
                $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
                $ sudo pfctl -f /etc/pf.conf\n\
                $ sudo -iu dev\n";
    assert_eq!(stdout, want);
}

#[test]
fn shell_refuses_when_tenant_absent() {
    // Empty StubReader — no user, no group. Shell must refuse: there's
    // no account to log into. Exit 64 (EX_USAGE; the operator gave us a
    // name we can't resolve). Never reaches the executor (NeverExecutor
    // would panic), so stdout stays empty and the refusal lands on stderr.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["shell", "ghost"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot shell into 'ghost': does not exist\n"
    );
}

#[test]
fn shell_refuses_when_only_orphan_group_present() {
    // Per Q3 design lock: OrphanGroup collapses to NotPresent for shell
    // purposes — the operator wants a shell, and the lingering group
    // doesn't provide one. Same refusal text and exit code as the bare
    // NotPresent case. A regression that special-cased OrphanGroup
    // (e.g. mentioning the group, or routing to a different message)
    // would trip this test.
    let stub = StubReader {
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
    // Tenant-floor guard mirrors destroy: an account exists with a
    // positive UID below TENANT_UID_FLOOR (600) → refuse. `legacyusr`
    // sidesteps the reserved-name blocklist (cycle 3) so this test
    // exercises the state-based refusal path specifically.
    let stub = StubReader {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), 0)].into_iter().collect(),
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
    // System-account refusal (`has_user` true, `uid_for` None — service
    // accounts whose negative UIDs were filtered by `parse_id_line`).
    // Same shape as destroy's `system_account_refusal`.
    let stub = StubReader {
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
    // -v on a refusal path emits nothing on stdout — no "Shelling into"
    // line, no mechanism preview. Mirrors `destroy_refuses_below_floor_verbose`;
    // guards against "we built the argv before the eligibility match"
    // regressions.
    let stub = StubReader {
        users: vec!["edge".to_string()],
        uid_by_name: [("edge".to_string(), 599)].into_iter().collect(),
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
    // Lexical validation runs before eligibility; an empty name trips
    // `NameError::Empty` and never consults the Reader. Same shape and
    // wording as create/destroy.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["shell", ""]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn shell_rejects_invalid_start() {
    // Pins the leading-letter rule for shell. One representative case
    // (a digit) — the full parametric matrix lives on
    // `create_rejects_non_letter_start` / `destroy_rejects_non_letter_start`.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["shell", "1dev"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: name '1dev' must start with a lowercase letter (got '1')\n"
    );
}

#[test]
fn shell_rejects_reserved_names() {
    // Reserved-name blocklist applies to shell too. Lexical rail trips
    // before any state-based check — important because `root` (UID 0) on
    // a real host would also fail the below-floor guard, but the
    // operator-relevant reason is the reserved name, not the floor.
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) = run_with(StubReader::default(), &["shell", name]);
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
    // Dry-run doesn't bypass eligibility — the operator asking "what
    // would happen if I shelled into 'ghost'?" deserves the same answer
    // they'd get in real mode. Refusal lands on stderr; stdout stays
    // empty; no executor invocation.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["shell", "ghost", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot shell into 'ghost': does not exist\n"
    );
}

#[test]
fn shell_propagates_child_exit_code() {
    // Q1=(b) design lock: tenant forwards the child shell's exit code as
    // its own. Stub the executor's login to return 5; tenant exits 5.
    // The "Shelling into" intent line still emits — pre-exec emission
    // happens before login is consulted. Cycle 4: profile must be
    // pre-loaded so the auto-narrow succeeds before login fires.
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .login_exit_code(5);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 5, "stderr={stderr:?}");
    assert_eq!(stdout, "Shelling into 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(exec.logins().len(), 1);
}

#[test]
fn shell_dry_run_bypasses_injected_executor() {
    // Dry-run swap-in of DryRunExecutor means the StubExecutor wired by
    // the test never sees a call. Mirrors `dry_run_bypasses_injected_executor`
    // and `destroy_dry_run_bypasses_injected_executor` for create/destroy.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Would shell into 'dev'.\n");
    assert!(
        exec.account_ops().is_empty() && exec.firewall_ops().is_empty() && exec.logins().is_empty(),
        "executor should not be invoked in dry-run; account_ops={:?}, firewall_ops={:?}, logins={:?}",
        exec.account_ops(),
        exec.firewall_ops(),
        exec.logins()
    );
}

// ================================================================
// Cycle 4: auto-narrow on shell entry
// ================================================================
//
// Locked design (extends CLAUDE.md doctrine):
// - Q1: Unconditional reapply on every `tenant shell <name>`. The
//   on-disk anchor is the source of truth (cycle-3 Q2 lock); reapply
//   is idempotent at the substrate.
// - Q2: Abort-on-narrow-failure with verb-contextual framing. New
//   `ShellError { Account, Mode }` surfaces narrow failures through
//   `shell_narrow_failed` (firewall) and `shell_narrow_profile_failed`
//   (profile read/parse). The shell is NOT launched on narrow failure.
// - Q3: No annotation on the narrow steps. Annotations mark
//   conditional/contingent steps (`# on rollback`, `# on reload
//   failure`); cycle-4 narrow is unconditional.
// - Q4: Reboot bypass acknowledged in CLAUDE.md doctrine; `tenant
//   shell` is the canonical entry point. Operator using `sudo -iu`
//   directly bypasses the narrow.

#[test]
fn shell_narrows_to_runtime_before_login() {
    // Cycle 4: every `tenant shell <name>` reapplies the runtime-tier
    // anchor body before launching the login shell. Unconditional
    // narrow — even if the tenant is already in runtime, the two-op
    // [InstallAnchor, Reload] sequence runs. Idempotent at the
    // substrate; matches Q2's "on-disk anchor is source of truth" lock
    // from cycle 3.
    //
    // Pin: firewall_ops = [InstallAnchor(runtime body), Reload];
    // login fires after the narrow; ordering matters.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
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
    // Eligibility classification fires BEFORE the writer is called, so
    // refused tenants don't trigger the auto-narrow. The existing
    // refusal tests use NeverExecutor (which panics on any substrate
    // call) so they already implicitly assert this — this test makes
    // it explicit with a StubExecutor whose firewall_ops + logins are
    // observable, pinning the contract at the verb-level for cycle 4.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["shell", "ghost"]);
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
    // Negative pin paralleling cycle-3's
    // `mode_does_not_emit_restore_config_op`: the parent `load anchor`
    // directive in /etc/pf.conf stays in place across shell entry, so
    // `pfctl -f` re-reads the anchor file and replaces the in-kernel
    // ruleset on every reload — structurally different from cycle 2's
    // destroy orphan-anchor case where the parent directive is removed
    // and FlushAnchor IS load-bearing. A defensive FlushAnchor here
    // would wipe rules we're simultaneously installing.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // No `with_existing_profile` → StubExecutor::read_profile returns
    // a "not found" ProfileError. The auto-narrow aborts before login.
    // Operator sees the shell-contextual frame ("before shell entry")
    // — distinct from `mode_profile_failed` so they know the failure
    // came from a verb they typed. Login is NOT launched.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stdout, "Shelling into 'dev'.\n",
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
    // Profile loads but schema_version is unsupported → parse returns
    // ProfileError → shell_narrow_profile_failed. Login NOT launched.
    let exec = StubExecutor::new().with_existing_profile(
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
    // InstallAnchor tripping (e.g. permission denied writing the anchor
    // file) → shell_narrow_failed → exit 74 → login NOT launched. Only
    // InstallAnchor in firewall_ops; Reload should NOT have run after
    // a failed InstallAnchor.
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
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(stdout, "Shelling into 'dev'.\n");
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
    // Reload tripping (e.g. pfctl syntax error in anchor body) →
    // shell_narrow_failed → exit 74 → login NOT launched. Critically,
    // NO recovery sequence fires (mirrors cycle-3's
    // `mode_reload_failure_surfaces_without_recovery` lock — the shell
    // narrow shares the same no-auto-recovery posture as the mode verb).
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_firewall_op(
            FirewallOp::Reload,
            FirewallError::NonZero {
                code: 1,
                stderr: "pfctl: Syntax error in anchor body\n".into(),
            },
        );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(stdout, "Shelling into 'dev'.\n");
    assert!(
        stderr.contains("failed to narrow firewall for 'dev' before shell entry"),
        "stderr should be framed by shell_narrow_failed: {stderr:?}"
    );
    assert!(exec.logins().is_empty(), "login must NOT fire");
    // Exactly two firewall ops: InstallAnchor (succeeded) + Reload (failed).
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
    // Security-load-bearing invariant: even if the tenant's profile
    // declares install-tier hosts, the auto-narrow body must include
    // ONLY runtime-tier hosts. Mirrors cycle-3's
    // `mode_runtime_with_runtime_and_install_populated_excludes_install`
    // — same data flow through a different verb. A regression that
    // passed `ModeLevel::Install` to the helper (e.g. typo) would
    // produce a body containing install-tier hosts and trip this pin.
    let profile = profile_with_hosts(
        &["api.example.com"],
        &["nodejs.org", "storage.googleapis.com"],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor("dev", &["api.example.com".to_string()]);
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
