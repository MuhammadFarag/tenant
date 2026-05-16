use std::path::PathBuf;

use tenant::accounts::StubReader;
use tenant::executor::{
    AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp, StubExecutor,
};

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
    // Dry-run verbose: intent + plan. The auto-narrow's InstallAnchor
    // + Reload precede the LoginAsUser in the plan. Dry-run doesn't
    // emit `$` echoes (echo is real+verbose only). The plan's
    // InstallAnchor describe line uses the placeholder body — its
    // describe ignores the body field, so the line is stable across
    // the empty-body plan placeholder and the real-body op at execute
    // time.
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["shell", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    // Shell's verbose plan uses the intent-leads-shell-follows layout
    // (shell has no prompt, so the plan stays in the verb rather than
    // moving into a summary). 4 entries: Install + Reload + AddHost
    // (catch-up) + LoginAsUser.
    let want = format!(
        "Would shell into 'dev'.\n\
         {}",
        verbose_plan_section(&[
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
        ]),
    );
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
    // Section + ✓ for each substrate step before login. No closing
    // line — login transfers control to the shell.
    let want = format!(
        "{}\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n",
        section_line("Entering tenant 'dev'"),
    );
    assert_eq!(stdout, want);
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(exec.logins(), vec!["dev".to_string()]);
    assert_eq!(
        exec.account_ops(),
        vec![AccountOp::AddHostToShareGroup {
            name: "dev".into(),
            host: "operator".into(),
        }],
        "shell auto-narrow includes the AddHost catch-up op"
    );
}

#[test]
fn shell_real_mode_verbose_shows_plan_and_echo() {
    // Real+verbose: intent + plan + `$` echoes (narrow's InstallAnchor
    // + Reload precede the LoginAsUser). No post-exec line.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev", "-v"]);
    assert_eq!(code, 0);
    // Shell's verbose plan uses the intent-leads-shell-follows layout
    // (shell has no prompt, so the plan stays in the verb rather than
    // moving into a summary).
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
         $ sudo -iu dev\n",
        section_line("Entering tenant 'dev'"),
    );
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
    // sidesteps the reserved-name blocklist so this test exercises
    // the state-based refusal path specifically.
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
    // Tenant forwards the child shell's exit code as its own. Stub
    // the executor's login to return 5; tenant exits 5. The
    // "Shelling into" intent line still emits — pre-exec emission
    // happens before login is consulted. Profile must be pre-loaded
    // so the auto-narrow succeeds before login fires.
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .login_exit_code(5);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 5, "stderr={stderr:?}");
    // Section + ✓ stream from the narrow reapply land before login
    // fires.
    let want = format!(
        "{}\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n",
        section_line("Entering tenant 'dev'"),
    );
    assert_eq!(stdout, want);
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
// Auto-narrow on shell entry
// ================================================================
//
// Locked design (extends CLAUDE.md doctrine):
// - Unconditional reapply on every `tenant shell <name>`. The
//   on-disk anchor is the source of truth; reapply is idempotent
//   at the substrate.
// - Abort-on-narrow-failure with verb-contextual framing.
//   `ShellError { Account, Mode }` surfaces narrow failures through
//   `shell_narrow_failed` (firewall) and `shell_narrow_profile_failed`
//   (profile read/parse). The shell is NOT launched on narrow
//   failure.
// - No annotation on the narrow steps. Annotations mark
//   conditional/contingent steps (`# on rollback`, `# on reload
//   failure`); the narrow is unconditional.
// - Reboot bypass acknowledged in CLAUDE.md doctrine; `tenant shell`
//   is the canonical entry point. Operator using `sudo -iu` directly
//   bypasses the narrow.

#[test]
fn shell_narrows_to_runtime_before_login() {
    // Every `tenant shell <name>` reapplies the runtime-tier anchor
    // body before launching the login shell. Unconditional narrow —
    // even if the tenant is already in runtime, the two-op
    // [InstallAnchor, Reload] sequence runs. Idempotent at the
    // substrate.
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
    // observable, pinning the contract at the verb level.
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
    // Negative pin paralleling `mode_does_not_emit_restore_config_op`:
    // the parent `load anchor` directive in /etc/pf.conf stays in
    // place across shell entry, so `pfctl -f` re-reads the anchor
    // file and replaces the in-kernel ruleset on every reload —
    // structurally different from the destroy orphan-anchor case
    // where the parent directive is removed and FlushAnchor IS
    // load-bearing. A defensive FlushAnchor here would wipe rules
    // we're simultaneously installing.
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
    // Section divider lands; InstallAnchor (first substrate) fails —
    // no ✓.
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
    // Reload tripping (e.g. pfctl syntax error in anchor body) →
    // shell_narrow_failed → exit 74 → login NOT launched. Critically,
    // NO recovery sequence fires (the shell narrow shares the same
    // no-auto-recovery posture as the mode verb, per
    // `mode_reload_failure_surfaces_without_recovery`).
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
    // Section + ✓ for InstallAnchor (succeeded), no ✓ for Reload
    // (failed).
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
    // ONLY runtime-tier hosts. Mirrors
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

// ================================================================
// Shell auto-reapply includes shares
// ================================================================
//
// `tenant shell <name>` extends the PF narrow to also reapply shares
// before handing off to login. Tests pin the substrate fires in the
// right order, that share refusals abort login, and that substrate
// failures on the share pass route through the
// `shell_narrow_*_failed` family (distinct from `mode_*_failed`).

#[test]
fn shell_auto_reapply_includes_share_substrate() {
    // Same op shape as mode-share happy-path, but exercised through
    // the shell verb. Login must still fire after the share substrate
    // succeeds.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &toml)
        .login_exit_code(0);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "exit = {code}; stderr={stderr:?}");

    assert_eq!(exec.acl_ops().len(), 1, "expected single Grant op");
    let symlink_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .collect();
    assert_eq!(symlink_ops.len(), 1, "expected single symlink op");
    assert_eq!(
        exec.logins(),
        vec!["dev".to_string()],
        "login must fire after successful share reapply"
    );
}

#[test]
fn shell_refuses_when_host_path_missing_does_not_launch_login() {
    // HostPathMissing refusal aborts BEFORE login launches. Frame
    // names "before shell entry" so the operator sees the shell-verb
    // context.
    let toml = profile_with_shares(
        &[],
        &[],
        &[("/nonexistent/missing/shell-sentinel", "rw", "$HOME/src")],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &toml);
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
fn shell_routes_acl_substrate_failure_via_shell_narrow_acl_frame() {
    // Substrate failure on the host-side ACL grant during shell
    // auto-reapply surfaces with shell-contextual framing (distinct
    // from mode_acl_failed). Login MUST NOT launch.
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
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stderr={stderr:?}");
    assert!(
        stderr.contains("failed to apply ACL for 'dev' before shell entry"),
        "stderr should be framed by shell_narrow_acl_failed: {stderr:?}"
    );
    assert!(
        exec.logins().is_empty(),
        "login must NOT fire on share-substrate failure"
    );
}

#[test]
fn shell_routes_sudo_u_substrate_failure_via_shell_narrow_account_frame() {
    // Substrate failure on the tenant-side `sudo -u <name> ln -sfn`
    // step during shell auto-reapply surfaces with shell-contextual
    // framing (distinct from mode_account_failed). Login MUST NOT launch.
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
fn shell_verbose_plan_block_lists_share_ops_alongside_pf_and_login() {
    // Round-1 review fix: the upfront plan block must list every op
    // that will fire (PF + per-share + LoginAsUser), so the
    // operator's plan/echo asymmetry contract holds when shares are
    // declared. Before the fix, share ops echoed without appearing
    // in the plan.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &toml)
        .login_exit_code(0);
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--verbose"],
    );
    assert_eq!(code, 0);
    // Plan block must contain InstallAnchor, Reload, AclOp::Grant,
    // EnsureSymlinkAsUser, and LoginAsUser — same lines that fire
    // via `$` echo. Two-space indent identifies the plan block.
    assert!(
        stdout.contains("  sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n"),
        "plan must list InstallAnchor: {stdout:?}"
    );
    assert!(
        stdout.contains("  sudo pfctl -f /etc/pf.conf\n"),
        "plan must list Reload: {stdout:?}"
    );
    assert!(
        stdout.contains("  chmod +a \"group:dev-tenant-share allow"),
        "plan must list Grant: {stdout:?}"
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
    // The negative pin holds with shares wired in: shell never emits
    // FlushAnchor / BackupConfig / RestoreConfigFromBackup /
    // RemoveAnchor / UpdateConfig / Enable even when the share
    // substrate is exercising.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &toml)
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
