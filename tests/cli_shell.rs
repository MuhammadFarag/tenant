use std::path::PathBuf;

use tenant::adapters::stub_host_accounts::StubHostAccounts;
use tenant::adapters::stub_host_machine::StubHostMachine;
use tenant::domain::{AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp, UserId};

mod common;
use common::*;

#[test]
fn shell_dry_run_default_shows_intent() {
    // Smallest red→green for the new verb. `stub_with_tenant("dev")` gives
    // us a tenant-range user (UID 600) so eligibility classifies as
    // shellable; dry-run + NeverHostMachine guarantees we don't actually
    // shell out.
    let (code, stdout, stderr) = run_with(stub_with_tenant("dev"), &["shell", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    let want = format!("{}Would shell into 'dev'.\n", shell_summary_block("dev"));
    assert_eq!(stdout, want);
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
        "{}Would shell into 'dev'.\n\
         {}",
        shell_summary_block("dev"),
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
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
            group: "dev-tenant-share".into(),
            host: "operator".into(),
        }],
        "shell auto-narrow includes the AddHost catch-up op"
    );
}

#[test]
fn shell_real_mode_verbose_shows_plan_and_echo() {
    // Real+verbose: intent + plan + `$` echoes (narrow's InstallAnchor
    // + Reload precede the LoginAsUser). No post-exec line.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // Empty StubHostAccounts — no user, no group. Shell must refuse: there's
    // no account to log into. Exit 64 (EX_USAGE; the operator gave us a
    // name we can't resolve). Never reaches the host machine (NeverHostMachine
    // would panic), so stdout stays empty and the refusal lands on stderr.
    let (code, stdout, stderr) = run_with(StubHostAccounts::default(), &["shell", "ghost"]);
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
    let stub = StubHostAccounts {
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
    let stub = StubHostAccounts {
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
    // System-account refusal (`has_user` true, `uid_for` None — service
    // accounts whose negative UIDs were filtered by `parse_id_line`).
    // Same shape as destroy's `system_account_refusal`.
    let stub = StubHostAccounts {
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
    let stub = StubHostAccounts {
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
    // Lexical validation runs before eligibility; an empty name trips
    // `NameError::Empty` and never consults the HostAccounts. Same shape and
    // wording as create/destroy.
    let (code, stdout, stderr) = run_with(StubHostAccounts::default(), &["shell", ""]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn shell_rejects_invalid_start() {
    // Pins the leading-letter rule for shell. One representative case
    // (a digit) — the full parametric matrix lives on
    // `create_rejects_non_letter_start` / `destroy_rejects_non_letter_start`.
    let (code, stdout, stderr) = run_with(StubHostAccounts::default(), &["shell", "1dev"]);
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
        let (code, stdout, stderr) = run_with(StubHostAccounts::default(), &["shell", name]);
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
    // empty; no host-machine invocation.
    let (code, stdout, stderr) = run_with(
        StubHostAccounts::default(),
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
    // Tenant forwards the child shell's exit code as its own. Stub
    // the host machine's login to return 5; tenant exits 5. The
    // "Shelling into" intent line still emits — pre-exec emission
    // happens before login is consulted. Profile must be pre-loaded
    // so the auto-narrow succeeds before login fires.
    let exec = StubHostMachine::new()
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
fn shell_dry_run_bypasses_injected_host_machine() {
    // Dry-run swap-in of DryRunHostMachine means the StubHostMachine wired by
    // the test never sees a call. Mirrors `dry_run_bypasses_injected_host_machine`
    // and `destroy_dry_run_bypasses_injected_host_machine` for create/destroy.
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
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
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // refusal tests use NeverHostMachine (which panics on any substrate
    // call) so they already implicitly assert this — this test makes
    // it explicit with a StubHostMachine whose firewall_ops + logins are
    // observable, pinning the contract at the verb level.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["shell", "ghost"]);
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
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // No `with_existing_profile` → StubHostMachine::read_profile returns
    // a "not found" ProfileError. The auto-narrow aborts before login.
    // Operator sees the shell-contextual frame ("before shell entry")
    // — distinct from `mode_profile_failed` so they know the failure
    // came from a verb they typed. Login is NOT launched.
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
    // Profile loads but schema_version is unsupported → parse returns
    // ProfileError → shell_narrow_profile_failed. Login NOT launched.
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
    // InstallAnchor tripping (e.g. permission denied writing the anchor
    // file) → shell_narrow_failed → exit 74 → login NOT launched. Only
    // InstallAnchor in firewall_ops; Reload should NOT have run after
    // a failed InstallAnchor.
    let exec = StubHostMachine::new()
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
    let exec = StubHostMachine::new()
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
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
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
    let exec = StubHostMachine::new()
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
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
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
    let exec = StubHostMachine::new()
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
    let exec = StubHostMachine::new()
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

// ================================================================
// Pre-exec doctor audit (cycle 16): shell scope
// ================================================================
//
// Shell's audit considers PfDisabled + EnvLeak (host-wide) plus
// per-tenant PfRuleDrift, AnchorBodyDrift, AclDrift, SymlinkDrift,
// HostNotInShareGroup. Critical findings inline (full one-liner);
// warning/info findings aggregate into a single
// `⚠ Doctor: N warning(s) for tenant 'X' — run `tenant doctor X` for details` line.
// Healthy host emits nothing extra. Audit fires between summary and
// confirm (shell has no confirm; the audit lands between summary and
// the shell intent / login). The `show_summary` gate (dry-run OR TTY)
// controls audit emission too — scripted real-mode callers stay silent.

#[test]
fn shell_pre_exec_doctor_silent_when_host_is_clean() {
    // Default stub state is the doctor-passing baseline (SC1):
    // PF enabled, env_delete includes SSH_AUTH_SOCK, kernel anchor
    // has pass + block, anchor body matches profile render, host
    // is in share group. Real-mode TTY emits summary + section + ✓
    // progress; no ⚠ Doctor: line, no inline critical.
    //
    // Uses `run_with_stdin` to simulate a TTY so the audit gating
    // fires (show_summary = TTY OR dry-run; dry-run swaps to
    // DryRunHostMachine whose mocks return clean defaults regardless of
    // stub injection — the audit tests pin behavior through real
    // mode + TTY which exercises the actual StubHostMachine reads).
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // PfDisabled is the only Critical-tier finding today (host-wide).
    // The audit emits it inline as the full one-liner via the existing
    // `doctor_finding` framing — critical: prefix + the finding text.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
    // EnvLeak (shell scope; warning) → one warning. Aggregate line
    // names the count + the per-tenant `tenant doctor dev` command.
    // Inline finding one-liner is NOT emitted for warnings — the
    // operator runs doctor for detail.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
    // PfDisabled (critical) AND EnvLeak (warning) AND
    // HostNotInShareGroup (warning) — expect 1 inline critical + 1
    // aggregate line counting 2 warnings (plural).
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
    // Q4 lock: verb-verbose does NOT enable the doctor-verbose
    // guidance body for inline critical findings. The aggregate line
    // already points the operator at `tenant doctor` for detail; the
    // inline critical stays a one-liner.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
    // Q3 lock: scripted callers (non-TTY, no --dry-run) skip the
    // summary AND the audit. Real-mode-no-TTY emits only the
    // section divider + ✓ progress + nothing extra above.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
    // Mutating verbs' exit codes don't depend on whether doctor
    // findings emit. PfDisabled is critical — but shell still exits 0
    // on successful login. `--strict` stays doctor-only.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
fn shell_pre_exec_doctor_substrate_failure_surfaces_and_proceeds() {
    // Q1 lock: read_pf_status fails → frame the failure on stderr,
    // continue with the verb. The shell verb still proceeds to
    // shell_intent + login.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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

// ================================================================
// Command form (`tenant shell <name> [--mode install|runtime] -- <cmd>`)
//
// Argv presence after `--` flips the verb between today's interactive
// login flow (empty argv) and the new command form (non-empty argv).
// Command form invokes `HostMachine::exec_as_tenant` (sibling carve-out
// to `login`); on the success path it ALWAYS runs a runtime-tier
// reapply on completion (idempotent if entry was Runtime; narrows
// back to runtime if --mode install widened).
//
// Locks (per cycle-17 prime):
// - Q1: `--` separator (clap `last = true`).
// - Q2: `--mode` rejected without argv (clap `requires = "argv"`).
// - Q3: no confirm prompt on either form.
// - Q4: narrow-on-finally gated on widen-execution. If widen failed
//   at `build_reapply_plan` (no substrate fired), no narrow attempt;
//   if widen-execute fired any substrate, best-effort narrow runs
//   inline before the Mode error surfaces.
// - Option (a): child exit code propagates; narrow-failure stderr
//   warning does NOT override it.
// ================================================================

#[test]
fn shell_command_form_default_runtime_invokes_exec_as_tenant() {
    // `tenant shell dev -- ls /tmp`: no --mode (defaults to Runtime).
    // Entry reapply at Runtime; child runs via exec_as_tenant; NO
    // post-child narrow (mode == Runtime → entry reapply IS the
    // runtime posture; the redundant second reapply is gated off
    // per F2 from cycle-17 smoke).
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--", "ls", "/tmp"],
    );
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
    // `tenant shell dev --mode install -- bash -c 'echo hi'`. Entry
    // widens to install tier (install body includes both runtime +
    // install hosts); child runs; finally narrows to runtime tier.
    // The install-tier and runtime-tier InstallAnchor bodies differ
    // when the profile carries install hosts, so the firewall_ops
    // pin captures the asymmetric pair shape.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
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
        &["runtime.example".to_string(), "install.example".to_string()],
    );
    let runtime_body = tenant::firewall::render_anchor("dev", &["runtime.example".to_string()]);
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
    // Option (a) lock: child exit code propagates to the verb's exit.
    // exec_exit_code(7) → verb exits 7. Mirrors today's
    // shell_propagates_child_exit_code (which targets login).
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
    // Negative pin: command form must NOT reach `HostMachine::login`.
    // The two carve-outs serve different forms; routing must split
    // cleanly at the empty-argv check.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // Regression pin: cycle-17 verb signature change must not
    // disturb today's interactive flow. Empty argv routes to
    // shell_interactive which calls HostMachine::login (NOT
    // exec_as_tenant); only the entry reapply fires (no
    // narrow-on-finally for the interactive form).
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .login_exit_code(5);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(
        code, 5,
        "child shell exit code propagates: stderr={stderr:?}"
    );
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
    // Q4 + F2: when --mode install widened the entry, narrow-on-finally
    // is mandatory regardless of child outcome — otherwise on-disk
    // anchor stays at install tier after a non-zero exit (silent
    // persistent widening, the very thing the verb exists to prevent).
    // Verb returns child's exit code per option (a). The narrow installs
    // the runtime-tier body, not a re-widen.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .exec_exit_code(42);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--mode", "install", "--", "false"],
    );
    assert_eq!(code, 42, "child exit code; stderr={stderr:?}");
    let runtime_body = tenant::firewall::render_anchor("dev", &["runtime.example".to_string()]);
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
    // F2 negative pin: runtime-mode command form must NOT fire a
    // redundant post-child reapply. The entry reapply IS the runtime
    // posture; a second reapply would write the same bytes + reload
    // pf to the same ruleset for zero on-disk delta. Pin: exactly
    // ONE Reload op on the runtime-mode path.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // Option (a) + cycle-17 NarrowFailed arm: child runs cleanly
    // (exit 0); narrow-on-finally fails. The verb returns child's
    // exit code (0); stderr carries the yellow ⚠ warning naming
    // `tenant mode dev runtime` for recovery. Without this pin, a
    // future change that returned EX_IOERR on narrow-failure would
    // surface as a silent regression in the operator's $?.
    //
    // Stub setup: with --mode install, entry InstallAnchor body
    // contains runtime + install hosts; finally InstallAnchor body
    // contains only runtime hosts. The two InstallAnchor ops have
    // distinct `body` fields, so `fail_firewall_op` matching on the
    // runtime-body op tags ONLY the finally narrow.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let runtime_body = tenant::firewall::render_anchor("dev", &["runtime.example".to_string()]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
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
    // Q4 lock: widen-build-failure (profile-read fails BEFORE any
    // substrate fires) → no narrow attempt. The Mode error surfaces;
    // firewall_ops stays empty; exec_calls stays empty.
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
    // Q4 lock: InstallAnchor succeeded (on-disk body now diverged);
    // Reload failed. The best-effort narrow runs inline so on-disk
    // state returns to runtime, then ModeError surfaces. We pin that
    // a SECOND InstallAnchor (runtime body) attempt followed the
    // failed entry Reload.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
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
    // After the entry Reload failed (op #2), the best-effort narrow
    // builds + executes a runtime-tier reapply. fail_next_firewall is
    // one-shot, so the narrow's ops should land cleanly. Pin: a
    // runtime-body InstallAnchor appears after the failed Reload.
    let runtime_body = tenant::firewall::render_anchor("dev", &["runtime.example".to_string()]);
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
    // Doctrine pin (mirrors cycle-4's shell negative pin): the command
    // form is convergent like the interactive form; no FlushAnchor
    // ever fires. FlushAnchor is destroy-side load-bearing because the
    // parent `load anchor` directive gets removed there; the command
    // form preserves the parent directive across widen + narrow.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &profile);
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
    // Share substrate (cycle-14 AddHostToShareGroup + cycle-13
    // AclOp::Grant + EnsureDirAsUser + EnsureSymlinkAsUser) runs as
    // part of the entry reapply BEFORE exec_as_tenant. Pin: account
    // ops include AddHost; profile is read.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // AddHost fires twice (entry + finally narrow), and BEFORE exec.
    // Pin: AddHost is in account_ops at least once.
    assert!(
        exec.account_ops().contains(&add_host),
        "AddHostToShareGroup fires as part of the entry reapply: {:?}",
        exec.account_ops()
    );
    assert_eq!(exec.exec_calls().len(), 1);
}

// ================================================================
// SC3 — Reporter byte-form pins for the command form
// ================================================================

#[test]
fn shell_command_dry_run_default_shows_intent() {
    // Flow 1 from the prime (default-runtime command form, standard mode):
    // summary block + dry-run preamble line (`Would run command as
    // tenant 'dev' (runtime tier).`). No plan in standard dry-run.
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["shell", "dev", "--dry-run", "--", "ls", "/tmp"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let want = format!(
        "{}Would run command as tenant 'dev' (runtime tier).\n",
        shell_command_summary_block("dev", "runtime", "ls /tmp"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn shell_command_dry_run_install_mode_includes_widen_and_narrow_bullets() {
    // Flow 2 from the prime (install-mode command form, standard mode):
    // headline carries `(mode: install)`; entry bullet says "widen",
    // extra finally-narrow bullet; sudo line names firewall narrow.
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
    assert_eq!(code, 0, "stderr={stderr:?}");
    let want = format!(
        "{}Would run command as tenant 'dev' (install tier).\n",
        shell_command_summary_block("dev", "install", "bash -c echo hi"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn shell_command_real_mode_section_divider_includes_tier_when_install() {
    // Real-mode section header: runtime → "Running command as tenant 'dev'";
    // install → "Running command as tenant 'dev' (install tier)". Pin the
    // exact header bytes for both via section_line so a future width
    // tweak moves both sides together.
    let runtime_profile = tenant::profile::default_profile_toml();
    let exec = StubHostMachine::new().with_existing_profile("dev", &runtime_profile);
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
    let exec2 = StubHostMachine::new().with_existing_profile("dev", &install_profile);
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
    // Q3 lock: command form does NOT prompt, even on TTY. We simulate
    // a TTY via run_with_stdin with empty stdin content; if the verb
    // ever started prompting, the empty stdin would cause it to abort
    // (default-N for destroy; default-Y elsewhere). Either way, the
    // shape would change. Pin: clean execution + no "Proceed?" in
    // stdout.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    // SC3 byte-form pin for the yellow ⚠ stderr warning. Default
    // Colors (off) renders the glyph plain; the colored shape is
    // verified at the Reporter level. The warning line names the
    // tenant, the failure summary, and the recovery command.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let runtime_body = tenant::firewall::render_anchor("dev", &["runtime.example".to_string()]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
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
    // F1: runtime-mode command form ends with `─── Done ───` + bare
    // `Command exited with code N.` line — no narrow-back suffix
    // because runtime mode doesn't widen and doesn't narrow on
    // finally (per F2). Matches the prime's Flow 1 spec.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
    // F1: install-mode command form ends with `─── Done ───` +
    // `Command exited with code N (firewall narrowed back to runtime
    // tier).` — the suffix names the narrow as the load-bearing
    // operator-visible cue that on-disk state returned to runtime.
    let profile = profile_with_hosts(&["runtime.example"], &["install.example"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
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
    // Doctrine pin: closing surface fires for the command form only.
    // Interactive form returns from `HostMachine::login` after operator
    // typed exit; the parent shell's terminal context is gone (or
    // already showed the closing). Cycle-4 doctrine: no "Shelled into
    // …" line afterwards. Empty argv is the discriminator in dispatch.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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
    // DoctorScope::Shell covers both forms. Same stub (PfDisabled
    // host-wide) → same critical-finding inline emission for both
    // interactive and command forms. The Reporter wiring is shared;
    // dispatch routes through `pre_exec_doctor_summary` with
    // DoctorScope::Shell regardless of argv presence.
    let make_exec = || {
        StubHostMachine::new()
            .with_existing_profile("dev", &tenant::profile::default_profile_toml())
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

    // Both forms surface the same PfDisabled critical via the cycle-16
    // doctor_finding_one_liner inline emission ("critical: pf is
    // globally disabled" — same byte form across both verb shapes).
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
    // Q2 lock: --mode requires argv. `tenant shell dev --mode install`
    // (no `--` separator, no command) → clap parse error at dispatch.
    // Exit code is clap's default (2); no substrate fires.
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
