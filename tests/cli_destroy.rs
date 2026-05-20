use tenant::domain::{
    AccountError, AccountOp, FirewallError, KeychainError, KeychainOp, ProfileOp, UserId,
};

mod adapters;
mod common;
use adapters::*;
use common::*;

#[test]
fn destroy_removes_profile_file_from_store() {
    // Destroy adds a 5th step: profile-rm. After a successful destroy
    // the profile must be gone from the store. The store is pre-loaded
    // with a profile so the test pins "present before, absent after"
    // — defending against a regression that wires destroy without the
    // profile step.
    let exec = StubHostMachine::new().with_existing_profile("dev", "schema_version = 1\n");
    assert!(exec.has_profile("dev"), "pre-condition: profile present");
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout(
            "Destroying tenant 'dev'",
            &[
                "User account 'dev' removed (home moved to /Users/Deleted Users/dev)",
                "Residual user record check for 'dev'",
                "Residual user record 'dev' cleaned up",
                "Tenant 'dev' password removed from operator keychain",
                "Host 'operator' removed from share group 'dev-tenant-share'",
                "Share group 'dev-tenant-share' removed",
                "Profile removed at ~/.config/tenant/profiles/dev.toml",
                "Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup",
                "Firewall anchor removed at /etc/pf.anchors/tenant-dev",
                "Updated /etc/pf.conf",
                "Firewall ruleset reloaded",
                "Kernel rules under anchor 'tenant-dev' flushed",
            ],
            "Tenant 'dev' destroyed.",
        ),
    );
    assert!(
        !exec.has_profile("dev"),
        "profile should be removed after destroy"
    );
}

#[test]
fn destroy_succeeds_when_profile_already_absent() {
    // Idempotent rm: the operator may have manually removed the profile
    // (or a prior destroy failed mid-flight). Destroy must converge to
    // success regardless. Mirrors `XdgProfileStore::remove`'s
    // NotFound-as-Ok semantics — the `StubHostMachine`'s profile-state
    // simulation enforces the same contract by silently dropping a
    // missing-key remove.
    let exec = StubHostMachine::new(); // empty; no profile loaded
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    // Same wireframe as the profile-present case — the profile-rm
    // step is `NotFound → Ok(())` (idempotent rm), so its ✓ still
    // emits.
    assert_eq!(
        stdout,
        real_success_stdout(
            "Destroying tenant 'dev'",
            &[
                "User account 'dev' removed (home moved to /Users/Deleted Users/dev)",
                "Residual user record check for 'dev'",
                "Residual user record 'dev' cleaned up",
                "Tenant 'dev' password removed from operator keychain",
                "Host 'operator' removed from share group 'dev-tenant-share'",
                "Share group 'dev-tenant-share' removed",
                "Profile removed at ~/.config/tenant/profiles/dev.toml",
                "Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup",
                "Firewall anchor removed at /etc/pf.anchors/tenant-dev",
                "Updated /etc/pf.conf",
                "Firewall ruleset reloaded",
                "Kernel rules under anchor 'tenant-dev' flushed",
            ],
            "Tenant 'dev' destroyed.",
        ),
    );
}

#[test]
fn destroy_dry_run_default_shows_intent() {
    let (code, stdout, stderr) =
        run_with(stub_with_tenant("dev"), &["destroy", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, destroy_dry_run_block("dev", 600, None));
}

#[test]
fn destroy_dry_run_verbose_shows_mechanism() {
    // Dry-run verbose lists the full pessimistic plan. The plan runs
    // 4 lines: the trailing `sudo dseditgroup -o delete -n .
    // <name>-tenant-share` is appended because — unlike the
    // sysadminctl-cascade that caught implicit `<name>` groups — the
    // renamed tenant-share group doesn't inherit that cleanup, so the
    // explicit dseditgroup-delete
    // is load-bearing. Shown unconditionally because the dry-run can't
    // know what the dscl-probe will return at runtime; the operator
    // sees the full algorithm.
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["destroy", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    // Verbose plan lives inside the summary (intent-leads-shell-
    // follows layout).
    let plan = destroy_verbose_plan_block("dev");
    assert_eq!(stdout, destroy_dry_run_block("dev", 600, Some(&plan)));
}

#[test]
fn destroy_real_mode_standard_emits_only_post_exec_confirmation() {
    // StubHostMachine::new() returns Ok by default → the LookupUserRecord
    // probe sees the DS record as still present → the conditional
    // DeleteUserRecord cleanup runs. The DeleteShareGroup is
    // unconditional. Four account ops in standard mode; stdout is still
    // the single confirmation line (mechanism is suppressed without -v).
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout(
            "Destroying tenant 'dev'",
            &[
                "User account 'dev' removed (home moved to /Users/Deleted Users/dev)",
                "Residual user record check for 'dev'",
                "Residual user record 'dev' cleaned up",
                "Tenant 'dev' password removed from operator keychain",
                "Host 'operator' removed from share group 'dev-tenant-share'",
                "Share group 'dev-tenant-share' removed",
                "Profile removed at ~/.config/tenant/profiles/dev.toml",
                "Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup",
                "Firewall anchor removed at /etc/pf.anchors/tenant-dev",
                "Updated /etc/pf.conf",
                "Firewall ruleset reloaded",
                "Kernel rules under anchor 'tenant-dev' flushed",
            ],
            "Tenant 'dev' destroyed.",
        ),
    );
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::DeleteTenantUser { name: "dev".into() },
            AccountOp::LookupUserRecord { name: "dev".into() },
            AccountOp::DeleteUserRecord { name: "dev".into() },
            AccountOp::RemoveHostFromShareGroup {
                group: "dev-tenant-share".into(),
                host: "operator".into(),
            },
            AccountOp::DeleteShareGroup {
                group: "dev-tenant-share".into()
            },
        ],
    );
    assert_eq!(
        exec.profile_ops(),
        vec![ProfileOp::Delete { name: "dev".into() }],
    );
}

#[test]
fn destroy_real_mode_verbose_shows_pre_exec_mechanism_and_post_exec() {
    // Real-mode verbose has two sections: (a) the "Destroying" pre-exec
    // intent + the 4-line pessimistic plan (same shape as dry-run
    // verbose), then (b) per-exec echo lines prefixed with "$ " as each
    // command actually runs. Default StubHostMachine → probe says residue
    // → all four commands echo (dseditgroup-delete is the load-bearing
    // 4th step the share-group cleanup adds). The trailing post-exec
    // confirmation closes the block.
    // Scripted-real-verbose (TTY=false) drops the plan block
    // entirely (cleaner log trace; the section + $ echo + ✓ + Done
    // remains the trace surface).
    let exec = StubHostMachine::new();
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = format!(
        "{}\n\
         $ sudo sysadminctl -deleteUser dev\n\
         ✓ User account 'dev' removed (home moved to /Users/Deleted Users/dev)\n\
         $ dscl . -read /Users/dev\n\
         ✓ Residual user record check for 'dev'\n\
         $ sudo dscl . -delete /Users/dev\n\
         ✓ Residual user record 'dev' cleaned up\n\
         $ security delete-generic-password -a dev -s tenant-dev\n\
         ✓ Tenant 'dev' password removed from operator keychain\n\
         $ sudo dseditgroup -o edit -n . -d operator -t user dev-tenant-share\n\
         ✓ Host 'operator' removed from share group 'dev-tenant-share'\n\
         $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
         ✓ Share group 'dev-tenant-share' removed\n\
         $ rm -f ~/.config/tenant/profiles/dev.toml\n\
         ✓ Profile removed at ~/.config/tenant/profiles/dev.toml\n\
         $ sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n\
         ✓ Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup\n\
         $ sudo rm -f /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall anchor removed at /etc/pf.anchors/tenant-dev\n\
         $ sudo tee /etc/pf.conf < updated.conf\n\
         ✓ Updated /etc/pf.conf\n\
         $ sudo pfctl -f /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         $ sudo pfctl -a tenant-dev -F all\n\
         ✓ Kernel rules under anchor 'tenant-dev' flushed\n\
         {}\n\
         Tenant 'dev' destroyed.\n",
        section_line("Destroying tenant 'dev'"),
        section_line("Done"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn destroy_real_mode_skips_dscl_cleanup_when_probe_finds_clean() {
    // The dscl-read probe returns NonZero when the DS record is absent
    // (typically eDSRecordNotFound, code 56). The destroy writer must
    // treat probe-NonZero as "no cleanup needed" and skip the
    // sudo-dscl-delete — but the unconditional dseditgroup-delete for the
    // tenant-share group still runs after, because that group is independent
    // of the user record. So this path has exactly three exec calls:
    // sysadminctl + dscl-read + dseditgroup-delete (no dscl-delete).
    // The plan-vs-echo asymmetry around dscl-delete remains the
    // operator's signal that the dscl path was clean.
    let exec = StubHostMachine::new().fail_account_op(
        AccountOp::LookupUserRecord { name: "dev".into() },
        AccountError::NonZero {
            code: 56,
            stderr: String::new(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    // No ✓ for `LookupUserRecord` (probe Err == "no residue") and
    // consequently no DeleteUserRecord step at all.
    assert_eq!(
        stdout,
        real_success_stdout(
            "Destroying tenant 'dev'",
            &[
                "User account 'dev' removed (home moved to /Users/Deleted Users/dev)",
                "Tenant 'dev' password removed from operator keychain",
                "Host 'operator' removed from share group 'dev-tenant-share'",
                "Share group 'dev-tenant-share' removed",
                "Profile removed at ~/.config/tenant/profiles/dev.toml",
                "Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup",
                "Firewall anchor removed at /etc/pf.anchors/tenant-dev",
                "Updated /etc/pf.conf",
                "Firewall ruleset reloaded",
                "Kernel rules under anchor 'tenant-dev' flushed",
            ],
            "Tenant 'dev' destroyed.",
        ),
    );
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::DeleteTenantUser { name: "dev".into() },
            AccountOp::LookupUserRecord { name: "dev".into() },
            AccountOp::RemoveHostFromShareGroup {
                group: "dev-tenant-share".into(),
                host: "operator".into(),
            },
            AccountOp::DeleteShareGroup {
                group: "dev-tenant-share".into()
            },
        ],
        "expected DeleteTenantUser + LookupUserRecord + RemoveHost + DeleteShareGroup \
         (DeleteUserRecord cleanup skipped because probe found clean)"
    );
}

#[test]
fn destroy_real_mode_dseditgroup_delete_failure_surfaces_as_destroy_failure() {
    // Load-bearing dseditgroup-delete step: if it fails after
    // sysadminctl-deleteUser succeeded and the dscl-cleanup ran (or
    // was skipped as a noop), the host now carries an orphan
    // tenant-share group. The writer must surface this as EX_IOERR
    // so the operator knows to retry — the OrphanGroup eligibility
    // arm converges on retry. The error message reuses the existing
    // `destroy_failed` shape; the captured dseditgroup stderr inside
    // ExecError carries enough detail (the dseditgroup tool prints
    // its own argv-aware context) for the operator to diagnose.
    let exec = StubHostMachine::new().fail_account_op(
        AccountOp::DeleteShareGroup {
            group: "dev-tenant-share".into(),
        },
        AccountError::NonZero {
            code: 78,
            stderr: "dseditgroup: cannot remove group dev-tenant-share: not authorized\n".into(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    // Pre-failure ✓ stream is visible (Delete user, residue probe +
    // cleanup all succeeded). DeleteShareGroup failed — no ✓ for it,
    // no Done section.
    assert_eq!(
        stdout,
        real_failure_stdout(
            "Destroying tenant 'dev'",
            &[
                "User account 'dev' removed (home moved to /Users/Deleted Users/dev)",
                "Residual user record check for 'dev'",
                "Residual user record 'dev' cleaned up",
                "Tenant 'dev' password removed from operator keychain",
                "Host 'operator' removed from share group 'dev-tenant-share'",
            ],
        ),
    );
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78: \
         dseditgroup: cannot remove group dev-tenant-share: not authorized\n"
    );
    // Five account ops attempted — DeleteTenantUser + LookupUserRecord
    // + DeleteUserRecord + RemoveHostFromShareGroup + DeleteShareGroup
    // (which failed).
    assert_eq!(exec.account_ops().len(), 5);
}

#[test]
fn destroy_real_mode_dscl_cleanup_failure_surfaces_as_destroy_failure() {
    // The cleanup is best-effort but not optional: if sysadminctl claims
    // success and the probe says residue is still there, we MUST be able
    // to remove it — otherwise the operator's `tenant destroy` reports
    // success while the host still carries a stale DS record. Treat a
    // dscl-delete NonZero as a destroy failure (EX_IOERR), with the
    // captured stderr surfaced via ExecError::Display.
    let exec = StubHostMachine::new().fail_account_op(
        AccountOp::DeleteUserRecord { name: "dev".into() },
        AccountError::NonZero {
            code: 78,
            stderr: "dscl: cannot remove /Users/dev: not authorized\n".into(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78: \
         dscl: cannot remove /Users/dev: not authorized\n"
    );
    // DeleteTenantUser + LookupUserRecord + DeleteUserRecord attempted
    // — the failure is on the third op, not before.
    assert_eq!(exec.account_ops().len(), 3);
}

#[test]
fn destroy_real_mode_verbose_omits_cleanup_echo_when_probe_finds_clean() {
    // Verbose-mode counterpart: the upfront plan still lists all four
    // commands (the operator sees the algorithm), but the per-exec `$`
    // echo block skips the dscl-delete because the probe cleared the DS
    // state. The dseditgroup-delete echo still appears — that step is
    // unconditional. The asymmetry between plan and echo around
    // dscl-delete is the operator's signal that the dscl path was clean.
    let exec = StubHostMachine::new().fail_account_op(
        AccountOp::LookupUserRecord { name: "dev".into() },
        AccountError::NonZero {
            code: 56,
            stderr: String::new(),
        },
    );
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0);
    // Scripted-real-verbose drops the plan block. The $ echo block
    // still skips dscl-delete because the probe cleared the DS state;
    // that's the operator's signal that the dscl path was clean.
    let want = format!(
        "{}\n\
         $ sudo sysadminctl -deleteUser dev\n\
         ✓ User account 'dev' removed (home moved to /Users/Deleted Users/dev)\n\
         $ dscl . -read /Users/dev\n\
         $ security delete-generic-password -a dev -s tenant-dev\n\
         ✓ Tenant 'dev' password removed from operator keychain\n\
         $ sudo dseditgroup -o edit -n . -d operator -t user dev-tenant-share\n\
         ✓ Host 'operator' removed from share group 'dev-tenant-share'\n\
         $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
         ✓ Share group 'dev-tenant-share' removed\n\
         $ rm -f ~/.config/tenant/profiles/dev.toml\n\
         ✓ Profile removed at ~/.config/tenant/profiles/dev.toml\n\
         $ sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n\
         ✓ Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup\n\
         $ sudo rm -f /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall anchor removed at /etc/pf.anchors/tenant-dev\n\
         $ sudo tee /etc/pf.conf < updated.conf\n\
         ✓ Updated /etc/pf.conf\n\
         $ sudo pfctl -f /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         $ sudo pfctl -a tenant-dev -F all\n\
         ✓ Kernel rules under anchor 'tenant-dev' flushed\n\
         {}\n\
         Tenant 'dev' destroyed.\n",
        section_line("Destroying tenant 'dev'"),
        section_line("Done"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn destroy_rejects_empty_name() {
    let (code, stdout, stderr) =
        run_with(StubUserDirectory::default(), &["destroy", "", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn destroy_rejects_non_letter_start() {
    for (name, offender) in [("1dev", '1'), ("_dev", '_'), ("Dev", 'D')] {
        let (code, stdout, stderr) = run_with(
            StubUserDirectory::default(),
            &["destroy", name, "--dry-run"],
        );
        assert_eq!(code, 64, "want EX_USAGE for {name:?}");
        assert!(
            stdout.is_empty(),
            "stdout should be empty for {name:?}: {stdout:?}"
        );
        let want = format!(
            "tenant: name '{name}' must start with a lowercase letter (got '{offender}')\n"
        );
        assert_eq!(stderr, want, "stderr mismatch for {name:?}");
    }
}

#[test]
fn destroy_rejects_invalid_character() {
    for (name, offender) in [("de v", ' '), ("de@v", '@'), ("dev.", '.')] {
        let (code, stdout, stderr) = run_with(
            StubUserDirectory::default(),
            &["destroy", name, "--dry-run"],
        );
        assert_eq!(code, 64, "want EX_USAGE for {name:?}");
        assert!(
            stdout.is_empty(),
            "stdout should be empty for {name:?}: {stdout:?}"
        );
        let want = format!("tenant: name '{name}' contains invalid character '{offender}'\n");
        assert_eq!(stderr, want, "stderr mismatch for {name:?}");
    }
}

#[test]
fn destroy_noop_when_user_missing() {
    // Empty StubUserDirectory — no users on the host. Destroy should be
    // convergent-toward-absence: report the noop and exit 0 without
    // touching the host machine (NeverHostMachine would panic if reached).
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "tenant 'dev' does not exist; nothing to do.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn destroy_refuses_below_floor() {
    // Name passes validate_name (lowercase, valid charset, NOT in
    // RESERVED_NAMES) but UID is below the tenant floor — i.e. the
    // state-based refusal, not the lexical one. The synthetic name
    // `legacyusr` deliberately sidesteps the blocklist so the floor
    // guard is the actual code path under test. Refuse with EX_USAGE;
    // never reach the host machine.
    let stub = StubUserDirectory {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), UserId(0))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "legacyusr"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to destroy 'legacyusr': UID 0 is below tenant floor 600\n"
    );
}

#[test]
fn destroy_refuses_just_below_floor() {
    // Boundary: UID 599 refuses; UID 600 (the floor itself) accepts —
    // see `destroy_accepts_at_floor` for the matching positive case.
    let stub = StubUserDirectory {
        users: vec!["edge".to_string()],
        uid_by_name: [("edge".to_string(), UserId(599))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "edge"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to destroy 'edge': UID 599 is below tenant floor 600\n"
    );
}

#[test]
fn destroy_accepts_at_floor() {
    // Boundary's positive twin: UID equal to TENANT_UID_FLOOR (600)
    // proceeds to exec. Pins the inequality direction at the floor itself
    // so a future helper edit that bumps `stub_with_tenant`'s UID can't
    // silently erase the boundary contract.
    let exec = StubHostMachine::new();
    let stub = StubUserDirectory {
        users: vec!["edge".to_string()],
        uid_by_name: [("edge".to_string(), UserId(600))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "edge"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout(
            "Destroying tenant 'edge'",
            &[
                "User account 'edge' removed (home moved to /Users/Deleted Users/edge)",
                "Residual user record check for 'edge'",
                "Residual user record 'edge' cleaned up",
                "Tenant 'edge' password removed from operator keychain",
                "Host 'operator' removed from share group 'edge-tenant-share'",
                "Share group 'edge-tenant-share' removed",
                "Profile removed at ~/.config/tenant/profiles/edge.toml",
                "Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup",
                "Firewall anchor removed at /etc/pf.anchors/tenant-edge",
                "Updated /etc/pf.conf",
                "Firewall ruleset reloaded",
                "Kernel rules under anchor 'tenant-edge' flushed",
            ],
            "Tenant 'edge' destroyed.",
        ),
    );
    // Five account ops: DeleteTenantUser + LookupUserRecord (probe
    // defaults to Ok) + DeleteUserRecord cleanup + RemoveHost +
    // DeleteShareGroup.
    assert_eq!(
        exec.account_ops().len(),
        5,
        "DeleteTenantUser + LookupUserRecord + DeleteUserRecord + RemoveHost + DeleteShareGroup"
    );
}

#[test]
fn destroy_refuses_when_uid_unknown_but_user_present() {
    // The canonical real-world case is `nobody` on macOS (UID -2 filtered
    // by `parse_uid_line` out of `uid_by_name`), but `nobody` is now
    // lexically reserved — the blocklist trips first. Synthetic
    // `phantom` reproduces the same HostUserDirectory state (present in `users`,
    // absent from `uid_by_name`) without crossing the reserved-name
    // rail, so the test still pins the `Eligibility::SystemAccount`
    // arm. `has_user` is true, `uid_for` returns None → refuse with
    // EX_USAGE, NOT a noop.
    let stub = StubUserDirectory {
        users: vec!["phantom".to_string()],
        // uid_by_name deliberately empty: simulates the parse_uid_line
        // negative-UID filter.
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "phantom"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to destroy 'phantom': system account (no tenant-range UID)\n"
    );
}

#[test]
fn destroy_refuses_below_floor_verbose() {
    // -v on a refusal path must not emit any mechanism preview to stdout
    // (no "Destroying …" line, no argv). The refusal is the only output,
    // and it goes to stderr. Guards against a class of "we built the argv
    // string before checking the guard" regressions.
    let stub = StubUserDirectory {
        users: vec!["edge".to_string()],
        uid_by_name: [("edge".to_string(), UserId(599))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "edge", "-v"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to destroy 'edge': UID 599 is below tenant floor 600\n"
    );
}

#[test]
fn destroy_noop_when_user_missing_verbose() {
    // -v on the convergent-noop path emits only the noop line — no
    // mechanism preview, no argv — and on stdout (not stderr).
    let (code, stdout, stderr) =
        run_with(StubUserDirectory::default(), &["destroy", "ghost", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "tenant 'ghost' does not exist; nothing to do.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn destroy_noop_emits_in_dry_run_too() {
    // Same noop framing in dry-run mode — the message is tense-neutral
    // because we'd "do nothing" either way.
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["destroy", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "tenant 'dev' does not exist; nothing to do.\n");
}

#[test]
fn destroy_rejects_reserved_names() {
    // Validate_name is shared between create and destroy via the
    // dispatch layer's lexical-then-state-based check order. This test
    // pins that the blocklist applies to destroy too — important because
    // destroy_eligibility's `NotATenant` floor guard would catch most
    // reserved names by UID, but the lexical refusal is the cheaper
    // first failure (no HostUserDirectory call needed) and surfaces the more
    // operator-relevant reason ("you can't name a tenant 'wheel'" vs
    // "UID 0 is below tenant floor 600").
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) = run_with(
            StubUserDirectory::default(),
            &["destroy", name, "--dry-run"],
        );
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
fn destroy_rejects_overlong_name() {
    let name = "a".repeat(32);
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["destroy", &name, "--dry-run"],
    );
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        format!("tenant: name '{name}' is too long (32 characters; maximum is 31)\n"),
    );
}

#[test]
fn destroy_real_mode_propagates_exec_failure() {
    let exec = StubHostMachine::new().fail_account_blanket(78, "");
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    // Section divider lands; the first substrate op (DeleteTenantUser)
    // fails so no ✓ emits.
    assert_eq!(
        stdout,
        format!("{}\n", section_line("Destroying tenant 'dev'")),
    );
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78\n"
    );
    assert_eq!(exec.account_ops().len(), 1);
}

#[test]
fn destroy_real_mode_failure_surfaces_host_machine_stderr() {
    let exec = StubHostMachine::new()
        .fail_account_blanket(78, "sysadminctl: -deleteUser failed: not authorized\n");
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    // Section + no ✓ — first substrate op failed.
    assert_eq!(
        stdout,
        format!("{}\n", section_line("Destroying tenant 'dev'")),
    );
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78: \
         sysadminctl: -deleteUser failed: not authorized\n"
    );
}

#[test]
fn destroy_dry_run_bypasses_injected_host_machine() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["destroy", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, destroy_dry_run_block("dev", 600, None));
    assert!(
        exec.account_ops().is_empty() && exec.profile_ops().is_empty(),
        "host machine should not be invoked in dry-run mode; account_ops={:?}, profile_ops={:?}",
        exec.account_ops(),
        exec.profile_ops()
    );
}

#[test]
fn destroy_converges_orphan_group_when_user_absent_but_tenant_share_group_present() {
    // The convergence path: the user was destroyed earlier (or a
    // previous destroy failed at the dseditgroup-delete step), leaving
    // a `<name>-tenant-share` group with no corresponding user. The
    // destroy verb classifies this as `OrphanGroup` and converges by
    // running just the dseditgroup-delete. Exactly ONE exec call — no
    // sysadminctl, no dscl — and exit 0. Standard-mode stdout names
    // the tenant (not the group) so it stays parallel with the rest
    // of the destroy UX from the operator's perspective.
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout(
            "Destroying orphan group 'dev-tenant-share' for tenant 'dev'",
            &[
                "Host 'operator' removed from share group 'dev-tenant-share'",
                "Tenant 'dev' password removed from operator keychain",
                "Share group 'dev-tenant-share' removed",
                "Profile removed at ~/.config/tenant/profiles/dev.toml",
                "Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup",
                "Firewall anchor removed at /etc/pf.anchors/tenant-dev",
                "Updated /etc/pf.conf",
                "Firewall ruleset reloaded",
                "Kernel rules under anchor 'tenant-dev' flushed",
            ],
            "Orphan group 'dev-tenant-share' for tenant 'dev' destroyed.",
        ),
    );
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::RemoveHostFromShareGroup {
                group: "dev-tenant-share".into(),
                host: "operator".into(),
            },
            AccountOp::DeleteShareGroup {
                group: "dev-tenant-share".into()
            },
        ],
        "expected RemoveHost + DeleteShareGroup (cosmetic remove before group delete)"
    );
}

#[test]
fn destroy_orphan_group_also_removes_profile_if_present() {
    // Convergence contract: after `tenant destroy <name>`, the host
    // should have no trace of `<name>` — including any leftover profile
    // file. The OrphanGroup arm must remove the profile too, idempotent
    // (the profile may or may not be present; either way is success).
    // Pre-load the profile alongside the orphan group to pin the "both
    // gone after" semantics.
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new().with_existing_profile("dev", "schema_version = 1\n");
    assert!(exec.has_profile("dev"), "pre-condition: profile present");
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        real_success_stdout(
            "Destroying orphan group 'dev-tenant-share' for tenant 'dev'",
            &[
                "Host 'operator' removed from share group 'dev-tenant-share'",
                "Tenant 'dev' password removed from operator keychain",
                "Share group 'dev-tenant-share' removed",
                "Profile removed at ~/.config/tenant/profiles/dev.toml",
                "Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup",
                "Firewall anchor removed at /etc/pf.anchors/tenant-dev",
                "Updated /etc/pf.conf",
                "Firewall ruleset reloaded",
                "Kernel rules under anchor 'tenant-dev' flushed",
            ],
            "Orphan group 'dev-tenant-share' for tenant 'dev' destroyed.",
        ),
    );
    assert!(
        !exec.has_profile("dev"),
        "profile should be removed by orphan-group convergence"
    );
}

#[test]
fn destroy_dry_run_for_orphan_group() {
    // Dry-run twin: same convergence framing, "Would" tense. No exec
    // calls (dry-run bypasses the host machine — NeverHostMachine would panic).
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "dev", "--dry-run"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, destroy_orphan_dry_run_block("dev", None));
}

#[test]
fn destroy_dry_run_verbose_for_orphan_group() {
    // Verbose dry-run names the group explicitly (the suffixed group is
    // the literal resource being touched) AND shows the mechanism.
    // Standard-mode framing is tenant-named; verbose adds the group
    // name for grep-friendliness, matching the mechanism-exposure
    // convention used elsewhere in the codebase.
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, _stderr) = run_with(stub, &["destroy", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    // Verbose plan lives inside the orphan-group summary (intent-
    // leads-shell-follows layout; 8 entries since the user is
    // already absent).
    let plan = orphan_verbose_plan_block("dev");
    assert_eq!(stdout, destroy_orphan_dry_run_block("dev", Some(&plan)));
}

#[test]
fn destroy_real_mode_verbose_for_orphan_group() {
    // Real-mode verbose: same three-section shape as the regular destroy
    // (pre-exec intent + plan, `$` echo for each command, post-exec
    // confirmation), just with one argv in each block instead of four.
    // Scripted-real-verbose drops the plan block. Orphan path has
    // 8 steps — no user-removal.
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new();
    let (code, stdout, _stderr) = run_with_exec(stub, &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = format!(
        "{}\n\
         $ sudo dseditgroup -o edit -n . -d operator -t user dev-tenant-share\n\
         ✓ Host 'operator' removed from share group 'dev-tenant-share'\n\
         $ security delete-generic-password -a dev -s tenant-dev\n\
         ✓ Tenant 'dev' password removed from operator keychain\n\
         $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
         ✓ Share group 'dev-tenant-share' removed\n\
         $ rm -f ~/.config/tenant/profiles/dev.toml\n\
         ✓ Profile removed at ~/.config/tenant/profiles/dev.toml\n\
         $ sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n\
         ✓ Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup\n\
         $ sudo rm -f /etc/pf.anchors/tenant-dev\n\
         ✓ Firewall anchor removed at /etc/pf.anchors/tenant-dev\n\
         $ sudo tee /etc/pf.conf < updated.conf\n\
         ✓ Updated /etc/pf.conf\n\
         $ sudo pfctl -f /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         $ sudo pfctl -a tenant-dev -F all\n\
         ✓ Kernel rules under anchor 'tenant-dev' flushed\n\
         {}\n\
         Orphan group 'dev-tenant-share' for tenant 'dev' destroyed.\n",
        section_line("Destroying orphan group 'dev-tenant-share' for tenant 'dev'"),
        section_line("Done"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn destroy_noop_when_neither_user_nor_tenant_share_group_present() {
    // Specificity pin: a bare-name group (left over from legacy
    // creation, or unrelated host state) does NOT classify as
    // OrphanGroup — only the suffixed `<name>-tenant-share` does. Empty
    // users + bare `dev` group → `NotPresent` noop, exit 0, no exec.
    // A regression that loosened the OrphanGroup check to bare-name
    // matching (e.g. dropping the `tenant_share_group_name` call) would
    // trip this test.
    let stub = StubUserDirectory {
        groups: vec!["dev".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "tenant 'dev' does not exist; nothing to do.\n");
}

#[test]
fn destroy_real_mode_dseditgroup_failure_on_orphan_group_surfaces_as_failure() {
    // Convergence-path failure mode: even on the simplified orphan-group
    // path, dseditgroup-delete can still fail (auth, network OD,
    // whatever). Surface as EX_IOERR via the same `destroy_failed` shape
    // as the regular destroy — the operator's remediation is the same
    // (retry; if the issue persists, manual dscl inspection).
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new().fail_account_blanket(78, "dseditgroup: not authorized\n");
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    // Section divider lands; the orphan-group's first substrate op
    // (DeleteShareGroup) fails — no ✓, no Done section.
    assert_eq!(
        stdout,
        format!(
            "{}\n",
            section_line("Destroying orphan group 'dev-tenant-share' for tenant 'dev'"),
        ),
    );
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78: \
         dseditgroup: not authorized\n"
    );
    assert_eq!(exec.account_ops().len(), 1);
}

#[test]
fn destroy_real_mode_invokes_firewall_teardown_in_locked_order() {
    // Destroy PF teardown order: BackupConfig → RemoveAnchor →
    // UpdateConfig → Reload. No Enable on destroy. Pins
    // `firewall_ops()` shape on a clean-host destroy.
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let op_names: Vec<&'static str> = exec
        .firewall_ops()
        .iter()
        .map(|op| match op {
            tenant::domain::FirewallOp::BackupConfig => "BackupConfig",
            tenant::domain::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::domain::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::domain::FirewallOp::Reload => "Reload",
            tenant::domain::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::domain::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::domain::FirewallOp::Enable => "Enable",
            tenant::domain::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
        })
        .collect();
    assert_eq!(
        op_names,
        vec![
            "BackupConfig",
            "RemoveAnchor",
            "UpdateConfig",
            "Reload",
            "FlushAnchor",
        ],
    );
}

#[test]
fn destroy_real_mode_update_conf_drops_tenant_anchor_ref() {
    // remove_anchor_ref must strip the tenant's anchor + load lines
    // from pf.conf. With a pre-loaded conf that references both
    // tenant-dev and tenant-other, the UpdateConfig content should
    // have tenant-dev gone and tenant-other untouched.
    let initial = "anchor \"tenant-other\"\n\
                   anchor \"tenant-dev\"\n\
                   load anchor \"tenant-other\" from \"/etc/pf.anchors/tenant-other\"\n\
                   load anchor \"tenant-dev\" from \"/etc/pf.anchors/tenant-dev\"\n";
    let exec = StubHostMachine::new().with_pf_conf(initial);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let updated = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::domain::FirewallOp::UpdateConfig { content } => Some(content),
            _ => None,
        })
        .expect("UpdateConfig must have been issued");
    assert!(
        !updated.contains("tenant-dev"),
        "tenant-dev lines should be removed; got:\n{updated}"
    );
    assert!(
        updated.contains("anchor \"tenant-other\""),
        "tenant-other lines must remain; got:\n{updated}"
    );
}

#[test]
fn destroy_firewall_reload_failure_surfaces_via_destroy_firewall_failed() {
    // Reload failure during destroy: no recovery (per locked policy
    // — symmetric restore would re-reference the just-deleted anchor
    // file). Surface as destroy_firewall_failed at EX_IOERR.
    let exec = StubHostMachine::new().fail_firewall_op(
        tenant::domain::FirewallOp::Reload,
        FirewallError::NonZero {
            code: 1,
            stderr: "syntax error".to_string(),
        },
    );
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected");
    assert!(
        stderr.starts_with("tenant: failed to tear down firewall for 'dev':"),
        "got: {stderr:?}"
    );
}

#[test]
fn destroy_orphan_group_tears_down_firewall_too() {
    // Convergence-path: a tenant left with orphan group state may also
    // have orphan PF state (e.g. a create that failed mid-firewall
    // before getting to UpdateConfig+Reload). The convergence path
    // includes the full PF teardown to clean both.
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let op_names: Vec<&'static str> = exec
        .firewall_ops()
        .iter()
        .map(|op| match op {
            tenant::domain::FirewallOp::BackupConfig => "BackupConfig",
            tenant::domain::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::domain::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::domain::FirewallOp::Reload => "Reload",
            tenant::domain::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
            tenant::domain::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::domain::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::domain::FirewallOp::Enable => "Enable",
        })
        .collect();
    assert_eq!(
        op_names,
        vec![
            "BackupConfig",
            "RemoveAnchor",
            "UpdateConfig",
            "Reload",
            "FlushAnchor",
        ],
        "orphan-group convergence must include full firewall teardown"
    );
}

#[test]
fn destroy_firewall_idempotent_when_anchor_already_absent() {
    // The anchor file may already be gone (RemoveAnchor returns Ok
    // from the stub regardless of prior state — `rm -f` semantics on
    // the macOS side too). pf.conf may have no tenant ref. The
    // teardown still runs all five ops; UpdateConfig writes the
    // unchanged pf.conf back; FlushAnchor on an unknown anchor is a
    // noop on the macOS side. End state: idempotent success.
    let exec = StubHostMachine::new().with_pf_conf("# host pf.conf, no tenant refs\n");
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    // Still issued the five ops — destroy doesn't short-circuit based
    // on prior state; it just runs idempotent ops.
    assert_eq!(exec.firewall_ops().len(), 5);
}

#[test]
fn destroy_invokes_flush_anchor_as_final_firewall_step() {
    // The load-bearing post-smoke fix: pfctl -f never garbage-collects
    // anchors after their `load anchor` directive is removed, so
    // destroy must explicitly flush the in-kernel rules. Pin this as
    // the LAST firewall op on the destroy path.
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let last = exec
        .firewall_ops()
        .last()
        .cloned()
        .expect("at least one firewall op must run");
    assert_eq!(
        last,
        tenant::domain::FirewallOp::FlushAnchor { name: "dev".into() },
        "FlushAnchor must be the final firewall op on destroy"
    );
}

#[test]
fn destroy_orphan_group_invokes_flush_anchor_as_final_firewall_step() {
    // Same load-bearing flush, on the convergence path.
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let last = exec
        .firewall_ops()
        .last()
        .cloned()
        .expect("at least one firewall op must run");
    assert_eq!(
        last,
        tenant::domain::FirewallOp::FlushAnchor { name: "dev".into() },
        "FlushAnchor must be the final firewall op on orphan-group destroy"
    );
}

#[test]
fn destroy_orphan_group_cleans_stash() {
    // Orphan-group convergence: a tenant whose user account was manually removed
    // (e.g. `sudo sysadminctl -deleteUser dev`) but whose share group
    // survived still has an operator-side keychain stash from its
    // original `tenant create`. The OrphanGroup convergence path must
    // include the keychain delete so the stash doesn't linger after
    // `tenant destroy <name>` reports success — otherwise the operator
    // ends up with orphan passwords accumulating across re-creates
    // with no surface that flags them.
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        exec.keychain_ops()
            .iter()
            .any(|op| matches!(op, KeychainOp::DeleteStashedPassword { name } if name == "dev")),
        "DeleteStashedPassword must fire on orphan-group destroy; got: {:?}",
        exec.keychain_ops()
    );
}

// ================================================================
// Pre-execution confirmation prompt
// ================================================================

#[test]
fn destroy_with_tty_default_n_aborts_on_empty_input() {
    // Destructive verb: default is N so muscle-memory ENTER never
    // deletes. Operator hits ENTER without typing → Abort.
    // Substrate must NOT fire. Exit 0.
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["destroy", "dev"], b"\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Proceed? [y/N] "),
        "default-N hint should appear: {stdout:?}",
    );
    assert!(
        stdout.contains("Aborted by operator. No changes made."),
        "aborted line should emit: {stdout:?}",
    );
    assert!(
        exec.account_ops().is_empty(),
        "substrate must not fire: {:?}",
        exec.account_ops()
    );
}

#[test]
fn destroy_with_tty_proceeds_on_explicit_y() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["destroy", "dev"], b"y\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("About to destroy tenant 'dev' (UID 600)"),
        "summary should emit: {stdout:?}",
    );
    assert!(stdout.ends_with("Tenant 'dev' destroyed.\n"));
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

#[test]
fn destroy_with_yes_flag_skips_prompt() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["destroy", "dev", "--yes"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("Proceed?"),
        "prompt must NOT emit with --yes: {stdout:?}",
    );
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

#[test]
fn destroy_surfaces_user_directory_error_when_eligibility_probe_fails() {
    // `destroy_eligibility` calls has_user / has_group / uid_for; a dscl
    // failure at has_user routes to `destroy_eligibility_probe_failed`
    // and exits 74 before the convergent-noop or Destroyable branches.
    let stub = StubUserDirectory {
        fail_has_user: directory_fail_once(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "dev", "--dry-run"]);
    assert_eq!(code, 74);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert!(
        stderr.starts_with("tenant: failed to check destroy eligibility for 'dev': "),
        "expected destroy_eligibility_probe_failed frame; stderr={stderr:?}"
    );
}

#[test]
fn destroy_surfaces_user_directory_error_when_uid_lookup_fails() {
    // The `destroy_uid_lookup_failed` frame fires on the SECOND
    // `uid_for` call in the dispatch flow: `destroy_eligibility`
    // already consumed the first to classify `Destroyable`, then the
    // pre-summary path calls `uid_for` again. The queued injector's
    // `[None, Some(err)]` shape skips the first call (snapshot) and
    // fails the second. The re-lookup only fires when `show_summary`
    // is true — driven by `--dry-run` here so stdin doesn't have to
    // be a TTY.
    let stub = StubUserDirectory {
        users: vec!["dev".to_string()],
        uid_by_name: [("dev".to_string(), UserId(600))].into_iter().collect(),
        fail_uid_for: directory_fail_on_second_call(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["destroy", "dev", "--dry-run"]);
    assert_eq!(code, 74);
    assert!(
        stderr.starts_with("tenant: failed to look up UID for 'dev': "),
        "expected destroy_uid_lookup_failed frame; stderr={stderr:?}"
    );
}

// ============================================================
// Keychain teardown
// ============================================================

/// destroy's op stream includes `DeleteStashedPassword`
/// AFTER `DeleteUserRecord` (or its skipped probe), BEFORE the host /
/// group / profile cleanup.
#[test]
fn destroy_emits_keychain_delete_after_user_cleanup() {
    let exec = StubHostMachine::new();
    let (code, _, _) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0);
    let keychain_ops = exec.keychain_ops();
    assert_eq!(
        keychain_ops.len(),
        1,
        "expected exactly one keychain op (DeleteStashedPassword)"
    );
    assert!(
        matches!(
            &keychain_ops[0],
            KeychainOp::DeleteStashedPassword { name } if name.as_str() == "dev"
        ),
        "expected DeleteStashedPassword for 'dev'; got: {:?}",
        keychain_ops[0]
    );
}

/// legacy tenant (created before keychain bootstrap landed) has no stash —
/// substrate returns `KeychainError::NotFound` and destroy
/// CONVERGES, exiting 0 with no warning. The keychain ✓ line is
/// silently omitted because nothing was actually removed.
#[test]
fn destroy_succeeds_silently_when_stash_absent() {
    let exec = StubHostMachine::new().fail_next_keychain_delete(KeychainError::NotFound);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("password removed from operator keychain"),
        "expected no keychain ✓ line on NotFound; stdout={stdout:?}"
    );
    assert!(
        !stderr.contains("warning"),
        "expected no warning on NotFound; stderr={stderr:?}"
    );
}

/// a non-NotFound failure on `DeleteStashedPassword`
/// emits a warning to stderr but destroy continues and exits 0. The
/// rest of the teardown (host / group / profile / firewall) still
/// runs.
#[test]
fn destroy_warns_and_continues_when_stash_delete_fails() {
    let exec = StubHostMachine::new().fail_next_keychain_delete(KeychainError::NonZero {
        code: 50,
        stderr: "security: keychain locked\n".into(),
    });
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "expected destroy to converge; stderr={stderr:?}");
    assert!(
        stderr.contains("warning: could not remove stashed password for 'dev'"),
        "expected warning frame; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("`security delete-generic-password -a dev -s tenant-dev`"),
        "expected manual-recovery hint in warning; stderr={stderr:?}"
    );
    // The rest of the teardown ran — firewall ops are the tail end,
    // so their presence is the proof.
    assert!(
        stdout.contains("Kernel rules under anchor 'tenant-dev' flushed"),
        "expected firewall teardown to complete; stdout={stdout:?}"
    );
}

/// Verbose-mode counterpart to the failure pin: when `security
/// delete-generic-password` fails for a non-NotFound reason, the
/// operator must still see the `$` echo for the attempted command
/// (matches the verbose-mode contract used by every other op).
/// The `✓` is omitted (no successful mutation) and the warning lands
/// on stderr — but the substrate command that was warned about is
/// visible on stdout.
#[test]
fn destroy_verbose_emits_step_echo_before_keychain_delete_warning() {
    let exec = StubHostMachine::new().fail_next_keychain_delete(KeychainError::NonZero {
        code: 50,
        stderr: "security: keychain locked\n".into(),
    });
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0, "expected destroy to converge; stderr={stderr:?}");
    assert!(
        stdout.contains("$ security delete-generic-password -a dev -s tenant-dev"),
        "expected `$` echo for the attempted delete command; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("✓ Tenant 'dev' password removed from operator keychain"),
        "expected no ✓ line on failure; stdout={stdout:?}"
    );
    assert!(
        stderr.contains("warning: could not remove stashed password for 'dev'"),
        "expected warning frame on stderr; stderr={stderr:?}"
    );
}
