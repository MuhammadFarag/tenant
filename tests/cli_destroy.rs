use std::path::PathBuf;

use tenant::domain::{
    AccountError, AccountOp, FirewallError, KeychainError, KeychainOp, PathKind, ProbeError,
    ProfileOp, UserId,
};

mod adapters;
mod common;
use adapters::*;
use common::*;

#[test]
fn destroy_removes_profile_file_from_store() {
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
    let exec = StubHostMachine::new(); // empty; no profile loaded
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    // The ✓ still emits: profile rm treats NotFound as success.
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
    // Dry-run can't probe, so the plan lists every step unconditionally.
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["destroy", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let plan = destroy_verbose_plan_block("dev");
    assert_eq!(stdout, destroy_dry_run_block("dev", 600, Some(&plan)));
}

#[test]
fn destroy_real_mode_standard_emits_only_post_exec_confirmation() {
    // Default stub answers Ok to LookupUserRecord (residue present), so DeleteUserRecord runs.
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
    // Non-TTY verbose omits the plan block; only the `$` echoes remain.
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
    // A failing LookupUserRecord means "no residue", so DeleteUserRecord is skipped.
    let exec = StubHostMachine::new().fail_account_op(
        AccountOp::LookupUserRecord { name: "dev".into() },
        AccountError::NonZero {
            code: 56,
            stderr: String::new(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
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
    // DeleteTenantUser, Lookup/DeleteUserRecord, RemoveHostFromShareGroup, DeleteShareGroup.
    assert_eq!(exec.account_ops().len(), 5);
}

#[test]
fn destroy_real_mode_dscl_cleanup_failure_surfaces_as_destroy_failure() {
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
    // Stops at the third op (DeleteUserRecord).
    assert_eq!(exec.account_ops().len(), 3);
}

#[test]
fn destroy_real_mode_verbose_omits_cleanup_echo_when_probe_finds_clean() {
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
    // No plan block (non-TTY) and no dscl-delete echo (probe found no residue).
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
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "tenant 'dev' does not exist; nothing to do.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn destroy_refuses_below_floor() {
    // `legacyusr` avoids the reserved-name blocklist so the UID floor is what refuses.
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
    // Explicit UID 600 rather than `stub_with_tenant`, so a helper change can't move the boundary.
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
    assert_eq!(
        exec.account_ops().len(),
        5,
        "DeleteTenantUser + LookupUserRecord + DeleteUserRecord + RemoveHost + DeleteShareGroup"
    );
}

#[test]
fn destroy_refuses_when_uid_unknown_but_user_present() {
    // Models `nobody` (negative UID, absent from uid_by_name); `nobody` itself is reserved.
    let stub = StubUserDirectory {
        users: vec!["phantom".to_string()],
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
    let (code, stdout, stderr) =
        run_with(StubUserDirectory::default(), &["destroy", "ghost", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "tenant 'ghost' does not exist; nothing to do.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn destroy_noop_emits_in_dry_run_too() {
    // The noop message is tense-neutral, so dry-run prints it unchanged.
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["destroy", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "tenant 'dev' does not exist; nothing to do.\n");
}

#[test]
fn destroy_rejects_reserved_names() {
    // The lexical refusal must win over the UID-floor refusal that would also catch these.
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
    // Stdout names the tenant, not the group, to match the regular destroy UX.
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
    // Verbose names the share group itself; standard mode names only the tenant.
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, _stderr) = run_with(stub, &["destroy", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let plan = orphan_verbose_plan_block("dev");
    assert_eq!(stdout, destroy_orphan_dry_run_block("dev", Some(&plan)));
}

#[test]
fn destroy_real_mode_verbose_for_orphan_group() {
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
    // A bare `dev` group is not a tenant share group, so this is a noop, not OrphanGroup.
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
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new().fail_account_blanket(78, "dseditgroup: not authorized\n");
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
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
    let exec = StubHostMachine::new().with_pf_conf("# host pf.conf, no tenant refs\n");
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(exec.firewall_ops().len(), 5);
}

#[test]
fn destroy_invokes_flush_anchor_as_final_firewall_step() {
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

// --- Pre-execution confirmation prompt ---

#[test]
fn destroy_with_tty_default_n_aborts_on_empty_input() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) =
        run_with_stdin(stub_with_tenant("dev"), &exec, &["destroy", "dev"], b"\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stderr.contains("Proceed? [y/N] "),
        "default-N hint should appear: {stderr:?}",
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
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["destroy", "dev", "--yes"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stderr.contains("Proceed?"),
        "prompt must NOT emit with --yes: {stderr:?}",
    );
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

#[test]
fn destroy_surfaces_user_directory_error_when_eligibility_probe_fails() {
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

// TODO(smell): carry the UID on `Eligibility::Destroyable` so the summary needn't re-query it.
#[test]
fn destroy_surfaces_user_directory_error_when_uid_lookup_fails() {
    // Fails the second `uid_for` (the pre-summary re-lookup, run only with `--dry-run`/TTY).
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

// --- Keychain teardown ---

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
    // Firewall ops run last, so their presence proves the rest of teardown ran.
    assert!(
        stdout.contains("Kernel rules under anchor 'tenant-dev' flushed"),
        "expected firewall teardown to complete; stdout={stdout:?}"
    );
}

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

// --- Co-working directory left-intact notice ---

#[test]
fn destroy_emits_notice_when_cowork_dir_present() {
    let exec = StubHostMachine::new()
        .with_host_path_kind(&PathBuf::from("/Users/Shared/tenants/dev"), PathKind::Dir);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains(
            "Co-working directory for tenant 'dev' left intact at /Users/Shared/tenants/dev."
        ),
        "expected cowork-intact notice; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("Tenant 'dev' destroyed."),
        "expected destroy_done closing; stdout={stdout:?}"
    );
}

#[test]
fn destroy_omits_notice_when_cowork_dir_absent() {
    // The default stub reports every unregistered path as Absent.
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("Co-working directory"),
        "expected no cowork notice when path is absent; stdout={stdout:?}"
    );
}

#[test]
fn destroy_emits_notice_when_cowork_path_is_symlink_or_other() {
    for kind in [
        PathKind::Symlink(PathBuf::from("/some/other/place")),
        PathKind::Other,
    ] {
        let exec = StubHostMachine::new()
            .with_host_path_kind(&PathBuf::from("/Users/Shared/tenants/dev"), kind.clone());
        let (code, stdout, stderr) =
            run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
        assert_eq!(code, 0, "kind={kind:?}, stderr={stderr:?}");
        assert!(
            stdout.contains(
                "Co-working directory for tenant 'dev' left intact at /Users/Shared/tenants/dev."
            ),
            "expected cowork-intact notice for kind={kind:?}; stdout={stdout:?}"
        );
    }
}

#[test]
fn destroy_warns_and_continues_when_cowork_probe_fails() {
    let exec = StubHostMachine::new().fail_next_host_path_kind(ProbeError::Spawn(
        std::io::Error::other("synthetic probe failure"),
    ));
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("Co-working directory"),
        "expected no stdout notice on probe failure; stdout={stdout:?}"
    );
    assert!(
        stderr.contains(
            "\u{26a0} Co-working directory check for tenant 'dev' failed: \
             failed to spawn probe: synthetic probe failure \
             \u{2014} manually verify /Users/Shared/tenants/dev"
        ),
        "expected ⚠ warning on stderr; stderr={stderr:?}"
    );
    assert!(
        stdout.contains("Tenant 'dev' destroyed."),
        "destroy must still complete normally; stdout={stdout:?}"
    );
}

#[test]
fn destroy_orphan_group_emits_notice_when_cowork_dir_present() {
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new()
        .with_host_path_kind(&PathBuf::from("/Users/Shared/tenants/dev"), PathKind::Dir);
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains(
            "Co-working directory for tenant 'dev' left intact at /Users/Shared/tenants/dev."
        ),
        "expected cowork-intact notice on orphan-group path; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("Orphan group 'dev-tenant-share' for tenant 'dev' destroyed."),
        "orphan-group closing must still emit; stdout={stdout:?}"
    );
}

#[test]
fn destroy_orphan_group_omits_notice_when_cowork_dir_absent() {
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("Co-working directory"),
        "expected no cowork notice when path is absent on orphan path; stdout={stdout:?}"
    );
}

#[test]
fn destroy_orphan_group_warns_and_continues_when_cowork_probe_fails() {
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubHostMachine::new().fail_next_host_path_kind(ProbeError::Spawn(
        std::io::Error::other("synthetic probe failure"),
    ));
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stderr.contains(
            "\u{26a0} Co-working directory check for tenant 'dev' failed: \
             failed to spawn probe: synthetic probe failure \
             \u{2014} manually verify /Users/Shared/tenants/dev"
        ),
        "expected ⚠ warning on stderr; stderr={stderr:?}"
    );
    assert!(
        stdout.contains("Orphan group 'dev-tenant-share' for tenant 'dev' destroyed."),
        "orphan-group convergence must still complete; stdout={stdout:?}"
    );
}
