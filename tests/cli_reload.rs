use std::path::PathBuf;

use tenant::domain::{
    AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp, GroupId, PathKind,
    ProbeError, UserId,
};

mod adapters;
mod common;
use adapters::*;
use common::*;

// --- Clap parse + dry-run ---

#[test]
fn reload_single_tenant_dry_run_default_emits_intent_only() {
    let (code, stdout, stderr) = run_with(stub_with_tenant("dev"), &["reload", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, reload_dry_run_block("dev", None));
}

// TODO(smell): rename — this test runs real mode, not --dry-run.
#[test]
fn reload_no_arg_form_dry_run_with_no_tenants_emits_summary_only() {
    let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["reload"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "No tenants on this host to reload.\n");
}

// --- Validation + eligibility refusals ---

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

// --- Real-mode happy path + share substrate ---

#[test]
fn reload_single_tenant_runs_pf_and_share_substrate() {
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
                "Tenant 'dev' primary group set to GID 600",
                "Co-working directory ensured at /Users/Shared/tenants/dev",
                "ACL granted to group 'dev-tenant-share' on /tmp",
                "Symlink /Users/dev/src → /tmp installed",
            ],
            "Tenant 'dev' reloaded.",
            Some(&reload_breadcrumb("dev")),
        ),
    );

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

    let acl_ops = exec.acl_ops();
    assert_eq!(
        acl_ops,
        vec![AclOp::Grant {
            path: PathBuf::from("/tmp"),
            group: "dev-tenant-share".into(),
            mode: tenant::domain::AclMode::Rw,
        }]
    );

    // No EnsureDir for `$HOME`-direct entries.
    let symlinks: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .collect();
    assert_eq!(symlinks.len(), 1, "expected single symlink op");
}

#[test]
fn reload_renders_per_host_egress_ports_into_anchor_body() {
    let toml = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = [\n\
                  \"api.anthropic.com\",\n\
                  { host = \"github.com\", ports = [443, 22] },\n\
                ]\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    let exec = StubHostMachine::new().with_existing_profile("dev", toml);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");

    let fw_ops = exec.firewall_ops();
    let body = match &fw_ops[0] {
        FirewallOp::InstallAnchor { body, .. } => body,
        other => panic!("expected InstallAnchor first, got {other:?}"),
    };
    assert!(
        body.contains("table <allowed> persist { \\\n  api.anthropic.com \\\n}\n"),
        "bare host must render in the default <allowed> table, got body:\n{body}"
    );
    assert!(
        body.contains("table <allowed_443_22> persist { \\\n  github.com \\\n}\n"),
        "expected an <allowed_443_22> table for the ports-declaring host, got body:\n{body}"
    );
    assert!(
        body.contains(
            "pass out quick proto tcp from any to <allowed_443_22> port { 443, 22 } user dev\n"
        ),
        "expected the <allowed_443_22> pass rule, got body:\n{body}"
    );
}

#[test]
fn reload_profile_read_failure_surfaces_before_prompt() {
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
    // A simulated TTY operator answering `y` stands in for --dry-run.
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
        stdout.contains("Set tenant 'dev' primary group to GID 600"),
        "plan must list EnsurePrimaryGroup intent: {stdout:?}"
    );
    assert!(
        stdout.contains("      sudo dscl . -create /Users/dev PrimaryGroupID 600\n"),
        "plan must list EnsurePrimaryGroup shell line: {stdout:?}"
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
    // Non-TTY real run drops the verbose plan: divider + `$` echo + ✓ only.
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

// --- Substrate-failure framing ---

#[test]
fn reload_firewall_failure_surfaces_with_reload_specific_wording() {
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

/// A symlink at the cowork path would steer `mkdir -p` to its target; pre-flight refuses first.
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

// TODO(smell): rename ModeError + Reporter mode_*_failed to reapply_*; reload + shell use them.
#[test]
fn reload_partial_acl_grant_failure_warns_and_continues_with_remaining_shares() {
    // chmod -R applies the ACE to the rest of the tree and exits 1 at the end.
    let toml = profile_with_shares(
        &[],
        &[],
        &[("/tmp", "rw", "$HOME/src"), ("/var", "ro", "$HOME/var")],
    );
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
                stderr:
                    "chmod: Failed to set ACL on file 'mysql.sock': No such file or directory\n"
                        .into(),
            },
        );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stderr,
        "\u{26a0} tenant 'dev': ACL grant on /tmp incomplete \u{2014} chmod: Failed to set ACL on \
         file 'mysql.sock': No such file or directory; the rest of the tree was granted, \
         `tenant doctor dev` lists what still lacks it\n"
    );
    assert_eq!(exec.acl_ops().len(), 2, "second share still granted");
    let symlinks = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .count();
    assert_eq!(symlinks, 2, "both shares' symlinks still installed");
}

#[test]
fn reload_acl_spawn_failure_still_aborts() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .fail_next_acl(AclError::Spawn(std::io::Error::other("no chmod")));
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("failed to apply ACL for 'dev'"),
        "stderr={stderr:?}"
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

// --- No-arg form (walk every tenant) ---

#[test]
fn reload_no_arg_walks_all_tenants_in_alphabetical_order() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_existing_profile("staging", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) = run_with_exec(make_two_tenant_stub_reader(), &exec, &["reload"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Reloaded 2 tenant(s).\n"),
        "expected summary line: {stdout:?}"
    );
}

#[test]
fn reload_no_arg_continues_on_per_tenant_failure() {
    let exec = StubHostMachine::new()
        .with_existing_profile("staging", &tenant::profile::default_profile_toml());
    // 'dev' has no profile preloaded → read_profile fails for dev.
    let (code, stdout, stderr) = run_with_exec(make_two_tenant_stub_reader(), &exec, &["reload"]);
    assert_eq!(code, 74, "EX_IOERR expected on any per-tenant failure");
    assert!(
        stderr.contains("failed to read profile") && stderr.contains("'dev'"),
        "expected per-tenant failure for dev: {stderr:?}"
    );
    assert!(
        stdout.contains("Reloaded 1 of 2 tenant(s); 1 failed.\n"),
        "expected per-failure summary line: {stdout:?}"
    );
}

#[test]
fn reload_all_continues_when_one_tenants_share_group_gid_read_fails() {
    // One-shot gid failure trips the first tenant alphabetically ('dev'); 'staging' still succeeds.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_existing_profile("staging", &tenant::profile::default_profile_toml())
        .fail_next_share_group_gid(ProbeError::NonZero {
            code: 1,
            stderr: "eDSRecordNotFound".to_string(),
        });
    let (code, stdout, stderr) = run_with_exec(make_two_tenant_stub_reader(), &exec, &["reload"]);
    assert_eq!(
        code, 74,
        "EX_IOERR expected when a per-tenant gid read fails"
    );
    assert!(
        stderr.contains("failed to probe host state for 'dev'"),
        "expected dev's gid-read failure frame: {stderr:?}"
    );
    assert!(
        stdout.contains("Reloaded 1 of 2 tenant(s); 1 failed.\n"),
        "walk continues past the gid-read failure: {stdout:?}"
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
            AccountOp::EnsurePrimaryGroup {
                name: "dev".into(),
                gid: GroupId(600),
            },
            AccountOp::EnsureCoworkDir {
                path: PathBuf::from("/Users/Shared/tenants/dev"),
                owner: "operator".into(),
                group: "dev-tenant-share".into(),
                mode: 0o2770,
            },
        ],
        "reload fires AddHost + primary-group reassert + cowork-dir catch-up unconditionally (substrate is idempotent, not Tenants-side conditional)"
    );
}

#[test]
fn reload_account_ops_position_pins_add_host_after_pf_before_shares() {
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
            AccountOp::EnsurePrimaryGroup {
                name: "dev".into(),
                gid: GroupId(600),
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
        "AddHost + primary-group reassert + cowork-dir recorded before the share-substrate ops"
    );
}

// --- Pre-exec doctor audit ---

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

// TODO(smell): HostMachine probe names don't say which need sudo; tests explain the gate instead.
#[test]
fn reload_pre_exec_doctor_quiet_skips_sudo_probes_when_sudo_uncached() {
    // Host kept clean on auth-free probes so uncached's only effect is sudo-probe suppression.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_sudo_session_cached(false)
        // Rigged to fail: any sudo probe that ran would print a failure frame.
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
    // host_in_group is auth-free, so it runs even uncached.
    assert!(
        !exec.host_in_group_invocations().is_empty(),
        "auth-free host_in_group must run even when uncached; invocations={:?}",
        exec.host_in_group_invocations()
    );
}

#[test]
fn reload_pre_exec_doctor_auth_free_probes_surface_when_sudo_uncached() {
    let cowork_path = tenant::domain::tenants::cowork_dir_path("dev");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_sudo_session_cached(false)
        .with_host_in_group("operator", "dev-tenant-share", false)
        .with_host_path_kind(&cowork_path, PathKind::Absent)
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
        !exec.host_in_group_invocations().is_empty(),
        "auth-free host_in_group must run when uncached; invocations={:?}",
        exec.host_in_group_invocations()
    );
    assert!(
        stdout.contains(
            "\u{26a0} Doctor: 2 warnings for tenant 'dev' \u{2014} run `tenant doctor dev` for details"
        ),
        "auth-free findings must aggregate even when uncached; stdout={stdout:?}"
    );
    assert!(
        !stderr.contains("failed to read pf state"),
        "uncached sudo must still skip the gated pf probe; stderr={stderr:?}"
    );
}

#[test]
fn reload_pre_exec_doctor_surfaces_missing_anchor_ref_when_sudo_uncached() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_sudo_session_cached(false)
        .with_pf_conf(STOCK_PF_CONF);
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("critical: tenant 'dev' anchor not referenced from /etc/pf.conf"),
        "stdout={stdout:?}"
    );
}

#[test]
fn reload_pre_exec_doctor_runs_sudo_probes_when_sudo_cached() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_sudo_session_cached(true)
        // Cached: this rigged failure MUST surface, proving the probe ran.
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
    assert!(
        !exec.host_in_group_invocations().is_empty(),
        "auth-free host_in_group runs under both cache states; invocations={:?}",
        exec.host_in_group_invocations()
    );
}

#[test]
fn reload_on_cold_sudo_authenticates_at_plan_build_so_pre_exec_doctor_probes_symlink_drift() {
    // AclDrift is auth-free; SymlinkDrift needs sudo. The share occupancy probe authenticates
    // at plan build, so the cache is warm by the pre-exec doctor and both surface.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "ro", "$HOME/src")]);
    let tenant_path = PathBuf::from("/Users/dev/src");
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_sudo_session_cached(false)
        .with_host_acl(
            &PathBuf::from("/tmp"),
            " 0: user:operator allow list,add_file,search\n",
        )
        .with_tenant_path_kind("dev", &tenant_path, PathKind::Absent);
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "verb proceeds; the pre-pass is a courtesy");
    assert_eq!(exec.authenticate_sudo_calls(), 1, "cold ⇒ one `sudo -v`");
    assert!(
        stdout.contains("\u{26a0} Doctor: 2 warnings for tenant 'dev'"),
        "warm cache after plan build: AclDrift AND SymlinkDrift aggregate; stdout={stdout:?}"
    );
    assert!(
        !stderr.contains("failed"),
        "no probe failure frame; stderr={stderr:?}"
    );
    // Verb plan-build + pre-exec doctor SymlinkDrift check.
    let calls: Vec<_> = exec
        .tenant_path_kind_calls()
        .into_iter()
        .filter(|(_, p)| p == &tenant_path)
        .collect();
    assert_eq!(calls.len(), 2, "calls={calls:?}");
}

#[test]
fn reload_pre_exec_doctor_acl_and_symlink_drift_both_surface_when_cached() {
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
    assert!(
        stdout.contains(
            "\u{26a0} Doctor: 2 warnings for tenant 'dev' \u{2014} run `tenant doctor dev` for details"
        ),
        "cached: both AclDrift and SymlinkDrift aggregate (2 warnings); stdout={stdout:?}"
    );
    // Two calls: verb plan-build + pre-exec doctor's SymlinkDrift probe.
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

// --- Full reapply scope ---

#[test]
fn reload_uses_full_reapply_scope_emitting_grant_and_cowork() {
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
    // reload_all has its own build_reapply_plan callsite, independent of single-tenant dispatch.
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

// --- Primary-group reassertion ---

#[test]
fn reload_ensure_primary_group_carries_resolved_share_group_gid_not_a_constant() {
    // Non-600 gid: it's read from the live group record, not derived from the name.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_share_group_gid("dev-tenant-share", 742);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        exec.account_ops().contains(&AccountOp::EnsurePrimaryGroup {
            name: "dev".into(),
            gid: GroupId(742),
        }),
        "EnsurePrimaryGroup must carry the resolved share-group gid (742), not a constant: {:?}",
        exec.account_ops()
    );
}

#[test]
fn reload_all_reasserts_each_tenants_own_primary_group_gid() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_existing_profile("staging", &tenant::profile::default_profile_toml())
        // staging's 601 differs from the stub default, so only a per-tenant read passes.
        .with_share_group_gid("dev-tenant-share", 600)
        .with_share_group_gid("staging-tenant-share", 601);
    let (code, _stdout, stderr) = run_with_exec(make_two_tenant_stub_reader(), &exec, &["reload"]);
    assert_eq!(code, 0, "reload-all happy path; stderr={stderr:?}");
    let ops = exec.account_ops();
    assert!(
        ops.contains(&AccountOp::EnsurePrimaryGroup {
            name: "dev".into(),
            gid: GroupId(600),
        }),
        "dev reasserts its own gid 600: {ops:?}"
    );
    assert!(
        ops.contains(&AccountOp::EnsurePrimaryGroup {
            name: "staging".into(),
            gid: GroupId(601),
        }),
        "staging reasserts its own gid 601: {ops:?}"
    );
}

#[test]
fn reload_aborts_with_io_error_when_share_group_gid_read_fails() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_next_share_group_gid(ProbeError::NonZero {
            code: 1,
            stderr: "eDSRecordNotFound".to_string(),
        });
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(
        code, 74,
        "gid-read failure maps to EX_IOERR; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("failed to probe host state for 'dev'"),
        "surfaces the host-state probe frame (not a filesystem-worded one): {stderr:?}"
    );
    assert!(
        exec.account_ops().is_empty(),
        "plan-build failure fires no mutation ops: {:?}",
        exec.account_ops()
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "plan-build failure fires no firewall ops: {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn reload_merges_included_fragment_hosts_into_anchor_body() {
    let profile = "schema_version = 1\n\
                   include = [\"base\"]\n\
                   [allowlist.runtime]\n\
                   hosts = [\"prof.example\"]\n\
                   [allowlist.install]\n\
                   hosts = []\n";
    let fragment = "[allowlist.runtime]\n\
                    hosts = [\"frag.example\"]\n";
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", profile)
        .with_profile_fragment("base", fragment);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "exit={code}; stderr={stderr:?}");

    let fw_ops = exec.firewall_ops();
    let body = match &fw_ops[0] {
        FirewallOp::InstallAnchor { body, .. } => body,
        other => panic!("expected InstallAnchor first, got {other:?}"),
    };
    let frag_pos = body
        .find("frag.example")
        .unwrap_or_else(|| panic!("fragment host must render into anchor:\n{body}"));
    let prof_pos = body
        .find("prof.example")
        .unwrap_or_else(|| panic!("profile host must render into anchor:\n{body}"));
    assert!(
        frag_pos < prof_pos,
        "fragment host must render before profile host (fragments first):\n{body}"
    );
}

#[test]
fn reload_missing_fragment_fails_before_prompt() {
    let profile = "schema_version = 1\n\
                   include = [\"base\"]\n\
                   [allowlist.runtime]\n\
                   hosts = []\n\
                   [allowlist.install]\n\
                   hosts = []\n";
    let exec = StubHostMachine::new().with_existing_profile("dev", profile); // no fragment preloaded
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "--verbose"],
    );
    assert_eq!(code, 74, "EX_IOERR expected; stderr={stderr:?}");
    assert_eq!(stdout, "", "no stdout pre-prompt; got {stdout:?}");
    assert!(
        stderr.contains("includes/base.toml"),
        "stderr must name the missing fragment file; got {stderr:?}"
    );
    assert!(
        !stdout.contains("Proceed?"),
        "no confirm prompt should be emitted; got {stdout:?}"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "missing-fragment failure fires no firewall ops: {:?}",
        exec.firewall_ops()
    );
}

// --- pf.conf anchor reference self-heal ---

#[test]
fn reload_restores_anchor_reference_missing_from_pf_conf() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_pf_conf(STOCK_PF_CONF);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let ops = exec.firewall_ops();
    assert!(
        matches!(ops[0], FirewallOp::InstallAnchor { .. }),
        "ops={ops:?}"
    );
    assert_eq!(
        ops[1..],
        [
            FirewallOp::UpdateConfig {
                content: format!("{STOCK_PF_CONF}{}", anchor_ref_lines("dev")),
            },
            FirewallOp::Reload,
        ]
    );
}

#[test]
fn reload_leaves_pf_conf_alone_when_anchor_reference_present() {
    let referenced = format!("{}{STOCK_PF_CONF}", anchor_ref_lines("dev"));
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_pf_conf(&referenced);
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let ops = exec.firewall_ops();
    assert!(
        matches!(
            ops[..],
            [FirewallOp::InstallAnchor { .. }, FirewallOp::Reload]
        ),
        "ops={ops:?}"
    );
}

#[test]
fn reload_all_restores_only_the_tenant_whose_reference_is_missing() {
    let staging_only = format!("{STOCK_PF_CONF}{}", anchor_ref_lines("staging"));
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_existing_profile("staging", &tenant::profile::default_profile_toml())
        .with_pf_conf(&staging_only);
    let (code, _stdout, stderr) = run_with_exec(make_two_tenant_stub_reader(), &exec, &["reload"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let updates: Vec<FirewallOp> = exec
        .firewall_ops()
        .into_iter()
        .filter(|op| matches!(op, FirewallOp::UpdateConfig { .. }))
        .collect();
    assert_eq!(
        updates,
        vec![FirewallOp::UpdateConfig {
            content: format!("{staging_only}{}", anchor_ref_lines("dev")),
        }]
    );
}

#[test]
fn reload_all_restores_every_reference_after_full_reset() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_existing_profile("staging", &tenant::profile::default_profile_toml())
        .with_pf_conf(STOCK_PF_CONF);
    let (code, _stdout, stderr) = run_with_exec(make_two_tenant_stub_reader(), &exec, &["reload"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let updates: Vec<FirewallOp> = exec
        .firewall_ops()
        .into_iter()
        .filter(|op| matches!(op, FirewallOp::UpdateConfig { .. }))
        .collect();
    let with_dev = format!("{STOCK_PF_CONF}{}", anchor_ref_lines("dev"));
    assert_eq!(
        updates,
        vec![
            FirewallOp::UpdateConfig {
                content: with_dev.clone(),
            },
            FirewallOp::UpdateConfig {
                content: format!("{with_dev}{}", anchor_ref_lines("staging")),
            },
        ]
    );
}

#[test]
fn reload_update_conf_failure_aborts_before_reload() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_pf_conf(STOCK_PF_CONF)
        .fail_firewall_op(
            FirewallOp::UpdateConfig {
                content: format!("{STOCK_PF_CONF}{}", anchor_ref_lines("dev")),
            },
            FirewallError::NonZero {
                code: 1,
                stderr: "mv: rename failed\n".into(),
            },
        );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74, "stderr={stderr:?}");
    assert_eq!(
        stderr,
        "tenant: failed to reload firewall for 'dev': process exited with code 1: mv: rename failed\n"
    );
    let ops = exec.firewall_ops();
    assert!(
        matches!(
            ops[..],
            [
                FirewallOp::InstallAnchor { .. },
                FirewallOp::UpdateConfig { .. }
            ]
        ),
        "ops={ops:?}"
    );
    assert!(
        exec.account_ops().is_empty(),
        "account_ops={:?}",
        exec.account_ops()
    );
}

#[test]
fn reload_pf_conf_read_failure_surfaces_before_prompt() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_next_pf_conf(FirewallError::Fs {
            path: "/etc/pf.conf".into(),
            message: "Permission denied".into(),
        });
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74, "stderr={stderr:?}");
    assert_eq!(stdout, "", "no stdout pre-prompt; got {stdout:?}");
    assert!(
        exec.firewall_ops().is_empty(),
        "ops={:?}",
        exec.firewall_ops()
    );
    assert_eq!(
        stderr,
        "tenant: failed to reload firewall for 'dev': filesystem error at /etc/pf.conf: Permission denied\n"
    );
}

#[test]
fn reload_pre_exec_doctor_counts_missing_anchor_ref_as_one_critical_and_proceeds() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_pf_conf(STOCK_PF_CONF)
        .with_kernel_pf_rules("dev", "");
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout
            .matches("critical: tenant 'dev' anchor not referenced from /etc/pf.conf")
            .count(),
        1,
        "stdout={stdout:?}"
    );
    assert!(!stdout.contains("\u{26a0} Doctor:"), "stdout={stdout:?}");
    assert_eq!(
        exec.kernel_pf_rules_calls(),
        vec!["dev".to_string()],
        "the pre-pass skips the kernel check; only the post-reload verify reads it"
    );
    assert!(
        exec.firewall_ops()
            .iter()
            .any(|op| matches!(op, FirewallOp::UpdateConfig { .. })),
        "ops={:?}",
        exec.firewall_ops()
    );
}

#[test]
fn reload_without_terminal_on_cold_sudo_refuses_before_mutation() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &toml)
        .with_sudo_session_cached(false);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout={stdout:?}");
    assert_eq!(stderr, SUDO_NEEDS_TERMINAL_REFUSAL);
    assert_eq!(
        exec.authenticate_sudo_calls(),
        0,
        "sudo -v would block on the prompt"
    );
    assert!(exec.firewall_ops().is_empty() && exec.account_ops().is_empty());
}

#[test]
fn reload_renders_permissive_inbound_when_profile_declares_posture() {
    let exec = StubHostMachine::new().with_existing_profile(
        "dev",
        &profile_with_permissive_posture(&["api.example.com"], &[]),
    );
    let (code, _stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Permissive,
    );
    assert_eq!(
        exec.firewall_ops()[0],
        FirewallOp::InstallAnchor {
            name: "dev".into(),
            body: expected,
        }
    );
}

#[test]
fn reload_fails_when_the_anchor_rules_never_reach_the_kernel() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_kernel_pf_rules_after_reload("dev", "");
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["reload", "dev"]);
    assert_eq!(code, 74, "stdout={stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to reload firewall for 'dev': pf reloaded, but the kernel has no \
         pass/block rules for anchor tenant-dev \u{2014} its egress allowlist is not enforced\n"
    );
    assert!(
        !stdout.contains("Tenant 'dev' reloaded."),
        "stdout={stdout:?}"
    );
}

#[test]
fn reload_dry_run_previews_the_real_profile() {
    let toml = profile_with_shares(&["api.example.com"], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &toml);
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["reload", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Grant 'dev-tenant-share' ACL access to /tmp"),
        "stdout={stdout:?}"
    );
    assert!(exec.firewall_ops().is_empty() && exec.acl_ops().is_empty());
}
