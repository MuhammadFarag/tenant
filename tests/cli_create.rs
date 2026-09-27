use std::path::PathBuf;

use tenant::domain::{
    AccountError, AccountOp, AclMode, AclOp, FirewallError, FirewallOp, GroupId, KeychainError,
    KeychainOp, PathKind, ProfileOp, UserId,
};

mod adapters;
mod common;
use adapters::*;
use common::*;

#[test]
fn create_dry_run_default_shows_intent() {
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
}

#[test]
fn create_accepts_max_length_name() {
    let name = "a".repeat(31);
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["create", &name, "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block(&name, 600, 600, None));
}

#[test]
fn create_accepts_single_letter_name() {
    let (code, stdout, stderr) =
        run_with(StubUserDirectory::default(), &["create", "x", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("x", 600, 600, None));
}

#[test]
fn verbose_shows_floor_uid_and_gid_when_neither_in_use() {
    // The `# on rollback` plan line is absent from the `$` echo block: that asymmetry is how
    // the operator sees whether rollback fired.
    let (code, stdout, _stderr) = run_with(
        StubUserDirectory::default(),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let plan = create_verbose_plan_block("dev", 600, 600);
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, Some(&plan)));
}

/// Stub whose `used_uids()` reports the given UIDs as taken (by synthetic
/// user names that no test asserts about). Used by allocator-driven tests.
fn stub_with_used_uids(uids: &[u32]) -> StubUserDirectory {
    StubUserDirectory {
        uid_by_name: uids
            .iter()
            .enumerate()
            .map(|(i, &u)| (format!("u{i}"), UserId(u)))
            .collect(),
        ..Default::default()
    }
}

#[test]
fn verbose_shows_lowest_free_uid_with_gap_and_gid_at_floor() {
    // stub_with_used_uids leaves the GID space empty, so GID stays at 600 while UID climbs.
    let (code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[600, 601, 603]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let plan = create_verbose_plan_block("dev", 602, 600);
    assert_eq!(stdout, create_dry_run_block("dev", 602, 600, Some(&plan)));
}

#[test]
fn verbose_uid_skips_taken_floor_gid_stays_at_floor() {
    let (_code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[600]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert!(
        stdout.contains("-UID 601 -GID 600"),
        "expected '-UID 601 -GID 600' in stdout, got: {stdout:?}",
    );
}

#[test]
fn verbose_uid_independent_of_input_order() {
    let (_code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[603, 600, 601]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert!(
        stdout.contains("-UID 602 -GID 600"),
        "expected '-UID 602 -GID 600' in stdout, got: {stdout:?}",
    );
}

#[test]
fn verbose_skips_uids_below_floor() {
    let (_code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[500, 599]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert!(
        stdout.contains("-UID 600 -GID 600"),
        "expected '-UID 600 -GID 600' in stdout, got: {stdout:?}",
    );
}

#[test]
fn verbose_gid_skips_taken_floor_uid_stays_at_floor() {
    // `-i` must track the GID allocator; wiring it to uid would slip past UID-only tests.
    let stub = StubUserDirectory {
        groups: vec!["other".to_string()],
        gid_by_name: [("other".to_string(), GroupId(600))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let plan = create_verbose_plan_block("dev", 600, 601);
    assert_eq!(stdout, create_dry_run_block("dev", 600, 601, Some(&plan)));
}

#[test]
fn verbose_uid_and_gid_allocators_cross_over() {
    // `-UID 601 -GID 600` is impossible if the two allocators were fused.
    let stub = StubUserDirectory {
        users: vec!["legacy".to_string()],
        uid_by_name: [("legacy".to_string(), UserId(600))].into_iter().collect(),
        groups: vec!["phantom".to_string()],
        gid_by_name: [("phantom".to_string(), GroupId(601))]
            .into_iter()
            .collect(),
        ..Default::default()
    };
    let (code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let plan = create_verbose_plan_block("dev", 601, 600);
    assert_eq!(stdout, create_dry_run_block("dev", 601, 600, Some(&plan)));
}

#[test]
fn create_rejects_empty_name() {
    let (code, stdout, stderr) =
        run_with(StubUserDirectory::default(), &["create", "", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn create_rejects_non_letter_start() {
    for (name, offender) in [("1dev", '1'), ("_dev", '_'), ("Dev", 'D')] {
        let (code, stdout, stderr) =
            run_with(StubUserDirectory::default(), &["create", name, "--dry-run"]);
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
fn create_rejects_invalid_character() {
    for (name, offender) in [("de v", ' '), ("de@v", '@'), ("dev.", '.')] {
        let (code, stdout, stderr) =
            run_with(StubUserDirectory::default(), &["create", name, "--dry-run"]);
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
fn create_rejects_overlong_name() {
    let name = "a".repeat(32);
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["create", &name, "--dry-run"],
    );
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        format!("tenant: name '{name}' is too long (32 characters; maximum is 31)\n"),
    );
}

#[test]
fn create_rejects_reserved_names() {
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) =
            run_with(StubUserDirectory::default(), &["create", name, "--dry-run"]);
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
fn create_accepts_name_with_reserved_prefix() {
    for name in ["rooty", "wheelman", "admins", "daemonic"] {
        let (code, stdout, stderr) =
            run_with(StubUserDirectory::default(), &["create", name, "--dry-run"]);
        assert_eq!(code, 0, "want success for {name:?}; stderr={stderr:?}");
        assert_eq!(stdout, create_dry_run_block(name, 600, 600, None));
    }
}

#[test]
fn create_rejects_when_user_exists() {
    let stub = StubUserDirectory {
        users: vec!["dev".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: user 'dev' already exists\n");
}

#[test]
fn create_surfaces_user_directory_error_when_conflict_probe_fails() {
    let stub = StubUserDirectory {
        fail_has_user: directory_fail_once(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 74);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert!(
        stderr.starts_with("tenant: failed to check existing accounts for 'dev': "),
        "expected create_conflict_probe_failed frame; stderr={stderr:?}"
    );
}

#[test]
fn create_rejects_when_tenant_share_group_exists() {
    let stub = StubUserDirectory {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: group 'dev-tenant-share' already exists\n");
}

#[test]
fn create_rejects_when_user_and_tenant_share_group_exist() {
    let stub = StubUserDirectory {
        users: vec!["dev".to_string()],
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: user 'dev' and group 'dev-tenant-share' already exist\n"
    );
}

#[test]
fn create_accepts_when_bare_name_group_exists_but_not_suffix() {
    // sysadminctl gets `-GID` of the share group, so a bare `dev` group is harmless.
    let stub = StubUserDirectory {
        groups: vec!["dev".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
}

#[test]
fn create_succeeds_when_unrelated_user_exists() {
    let stub = StubUserDirectory {
        users: vec!["ops".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
}

#[test]
fn create_writes_default_profile_to_store() {
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        exec.has_profile("dev"),
        "expected profile 'dev' to be present after create; state={:?}",
        exec.profile_state()
    );
}

#[test]
fn create_writes_profile_with_correct_toml_shape() {
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let state = exec.profile_state();
    let content = state.get("dev").expect("profile 'dev' should be present");
    let want = "# Per-tenant profile. See `tenant help profile` for the full schema.\n\
                # Apply edits with `tenant reload <name>`.\n\
                \n\
                schema_version = 1\n\
                \n\
                # Optional: share common allowlist / inbound / shares across a fleet by\n\
                # including ordered fragments from\n\
                # ~/.config/tenant/profiles/includes/<name>.toml — each is merged before\n\
                # this file (this file wins last). Uncomment to enable:\n\
                # include = [\"base\"]\n\
                \n\
                [allowlist.runtime]\n\
                # Hosts the tenant can reach during normal use. A bare host opens TCP\n\
                # 443 only; an inline table declares that host's TCP ports (e.g. 22 for\n\
                # git-over-ssh). Uncomment to enable:\n\
                hosts = [\n\
                #   \"api.anthropic.com\",\n\
                #   { host = \"github.com\", ports = [443, 22] },\n\
                ]\n\
                \n\
                [allowlist.install]\n\
                # Additional hosts the tenant can reach under `tenant mode <name> install`\n\
                # or `tenant shell <name> --mode install -- <cmd>`. Uncomment to enable:\n\
                hosts = [\n\
                #   \"registry.npmjs.org\",\n\
                #   \"pypi.org\",\n\
                #   \"files.pythonhosted.org\",\n\
                ]\n\
                \n\
                # Filesystem shares. Each [[shares]] entry grants the tenant's share group\n\
                # access to a host path and (optionally) symlinks it under the tenant's\n\
                # home. `mode` is \"ro\" or \"rw\"; `tenant_path` accepts `$HOME` as a path\n\
                # prefix only. Uncomment and edit:\n\
                #\n\
                # [[shares]]\n\
                # host_path = \"/Users/<host>/projects/foo\"\n\
                # mode = \"ro\"\n\
                # tenant_path = \"$HOME/projects/foo\"\n\
                \n\
                [inbound]\n\
                # TCP loopback (127.0.0.1) ports the tenant exposes under the default\n\
                # `restricted` posture. SURFACE-REDUCTION, NOT isolation: a declared port\n\
                # is reachable by the host AND peer tenants (pf can't see the initiator on\n\
                # shared loopback). UDP loopback is unfiltered (TCP only). Empty == locked.\n\
                # Widen temporarily with `tenant inbound <name> permissive`. Uncomment:\n\
                ports = [\n\
                #   3000,\n\
                ]\n\
                # JVM build tools (Gradle, Maven, sbt, Bazel) fork workers on random\n\
                # loopback ports and need every port open, persistently. Uncomment:\n\
                # posture = \"permissive\"\n\
                \n\
                [bootstrap]\n\
                # Idempotent shell commands `tenant bootstrap <name>` runs AS the tenant\n\
                # (each via `/bin/sh -c`, in order, stopping on the first failure), under\n\
                # a temporary install-tier egress widen. Guard so re-runs no-op\n\
                # (e.g. `command -v x || install x`). Uncomment and edit:\n\
                commands = [\n\
                #   \"test -d ~/projects/foo || git clone https://github.com/you/foo ~/projects/foo\",\n\
                ]\n";
    assert_eq!(content, want, "profile content mismatch");
}

#[test]
fn create_dry_run_does_not_write_profile() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
    assert!(
        !exec.has_profile("dev"),
        "profile should not be written in dry-run; state={:?}",
        exec.profile_state()
    );
}

#[test]
fn create_real_mode_standard_emits_only_post_exec_confirmation() {
    // Group before user: sysadminctl chowns the new home to the `-GID` group at creation.
    // `-GID` sets the primary group once; no separate EnsurePrimaryGroup (reload-only).
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let want = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         ✓ Co-working directory ensured at /Users/Shared/tenants/dev\n\
         ✓ Tenant 'dev' keychain created\n\
         ✓ Tenant 'dev' default keychain set\n\
         ✓ Tenant 'dev' keychain added to search list\n\
         ✓ Tenant 'dev' keychain auto-lock disabled\n\
         ✓ Tenant 'dev' password stashed in operator keychain\n\
         ✓ Profile written to ~/.config/tenant/profiles/dev.toml\n\
         ✓ Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Updated /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Firewall enabled host-wide\n\
         {}\n\
         Tenant 'dev' ready (UID 600, GID 600, anchor 'tenant-dev').\n\
         {}\n",
        section_line("Creating tenant 'dev'"),
        section_line("Done"),
        create_breadcrumb("dev"),
    );
    assert_eq!(stdout, want);
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::CreateShareGroup {
                group: "dev-tenant-share".into(),
                gid: GroupId(600)
            },
            AccountOp::AddHostToShareGroup {
                group: "dev-tenant-share".into(),
                host: "operator".into(),
            },
            AccountOp::CreateTenantUser {
                name: "dev".into(),
                uid: UserId(600),
                gid: GroupId(600)
            },
            AccountOp::EnsureCoworkDir {
                path: PathBuf::from("/Users/Shared/tenants/dev"),
                owner: "operator".into(),
                group: "dev-tenant-share".into(),
                mode: 0o2770,
            },
        ],
    );
    assert_eq!(
        exec.profile_ops(),
        vec![ProfileOp::Create { name: "dev".into() }],
    );
    let keychain_ops = exec.keychain_ops();
    assert_eq!(
        keychain_ops.len(),
        5,
        "expected 4 provision sub-steps + StashPassword, got: {keychain_ops:?}",
    );
}

#[test]
fn create_real_mode_verbose_shows_pre_exec_plan_and_post_exec_uid_gid() {
    // Non-TTY real run drops the verbose plan: divider + `$` echo + ✓ only.
    let exec = StubHostMachine::new();
    let (code, stdout, _stderr) = run_with_exec(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "-v"],
    );
    assert_eq!(code, 0);
    let want = format!(
        "{}\n\
         $ sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         $ sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         $ sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         $ sudo mkdir -p /Users/Shared/tenants/dev\n\
         $ sudo chown operator:dev-tenant-share /Users/Shared/tenants/dev\n\
         $ sudo chmod 2770 /Users/Shared/tenants/dev\n\
         $ sudo chmod -R +a \"group:dev-tenant-share allow \
         read,write,execute,delete,append,file_inherit,directory_inherit\" /Users/Shared/tenants/dev\n\
         ✓ Co-working directory ensured at /Users/Shared/tenants/dev\n\
         $ sudo -iu dev security create-keychain -p <password> tenant.keychain-db\n\
         ✓ Tenant 'dev' keychain created\n\
         $ sudo -iu dev security default-keychain -s tenant.keychain-db\n\
         ✓ Tenant 'dev' default keychain set\n\
         $ sudo -iu dev security list-keychains -s tenant.keychain-db\n\
         ✓ Tenant 'dev' keychain added to search list\n\
         $ sudo -iu dev security set-keychain-settings tenant.keychain-db\n\
         ✓ Tenant 'dev' keychain auto-lock disabled\n\
         $ security add-generic-password -U -a dev -s tenant-dev -w <password>\n\
         ✓ Tenant 'dev' password stashed in operator keychain\n\
         $ tee ~/.config/tenant/profiles/dev.toml < default.toml\n\
         ✓ Profile written to ~/.config/tenant/profiles/dev.toml\n\
         $ sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n\
         ✓ Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup\n\
         $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         $ sudo tee /etc/pf.conf < updated.conf\n\
         ✓ Updated /etc/pf.conf\n\
         $ sudo pfctl -f /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         $ sudo pfctl -e\n\
         ✓ Firewall enabled host-wide\n\
         {}\n\
         Tenant 'dev' ready (UID 600, GID 600, anchor 'tenant-dev').\n\
         {}\n",
        section_line("Creating tenant 'dev'"),
        section_line("Done"),
        create_breadcrumb("dev"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn create_profile_write_failure_surfaces_with_user_and_group_present() {
    // User + group already exist when the profile write fails; no rollback (destroy converges).
    let exec = StubHostMachine::new().fail_next_profile(tenant::profile::ProfileError {
        message: "disk full".into(),
    });
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         ✓ Co-working directory ensured at /Users/Shared/tenants/dev\n\
         ✓ Tenant 'dev' keychain created\n\
         ✓ Tenant 'dev' default keychain set\n\
         ✓ Tenant 'dev' keychain added to search list\n\
         ✓ Tenant 'dev' keychain auto-lock disabled\n\
         ✓ Tenant 'dev' password stashed in operator keychain\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to write profile '~/.config/tenant/profiles/dev.toml' \
         for 'dev': disk full\n"
    );
    assert_eq!(
        exec.account_ops().len(),
        4,
        "expected CreateShareGroup + AddHostToShareGroup + CreateTenantUser + EnsureCoworkDir; no rollback"
    );
    assert!(
        !exec.has_profile("dev"),
        "profile should be absent after write failure"
    );
}

#[test]
fn dry_run_bypasses_injected_host_machine() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
    assert!(
        exec.account_ops().is_empty() && exec.profile_ops().is_empty(),
        "host machine should not be invoked in dry-run mode; account_ops={:?}, profile_ops={:?}",
        exec.account_ops(),
        exec.profile_ops()
    );
}

#[test]
fn create_real_mode_dseditgroup_failure_aborts_before_sysadminctl() {
    // Blanket failure trips the first call (dseditgroup), so there's nothing to roll back.
    let exec = StubHostMachine::new().fail_account_blanket(78, "");
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert_eq!(
        stdout,
        format!("{}\n", section_line("Creating tenant 'dev'")),
    );
    assert_eq!(
        stderr,
        "tenant: failed to create group 'dev-tenant-share' for 'dev': process exited with code 78\n"
    );
    assert_eq!(
        exec.account_ops().len(),
        1,
        "should abort after CreateShareGroup"
    );
}

#[test]
fn create_add_host_failure_aborts_with_orphan_group_recovery_hint() {
    let exec = StubHostMachine::new().fail_account_op(
        AccountOp::AddHostToShareGroup {
            group: "dev-tenant-share".into(),
            host: "operator".into(),
        },
        AccountError::NonZero {
            code: 1,
            stderr: "dseditgroup: not authorized\n".into(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to add host 'operator' to group 'dev-tenant-share': \
         process exited with code 1: dseditgroup: not authorized \
         \u{2014} host now has an orphan group; next 'tenant destroy dev' will converge\n"
    );
    assert_eq!(exec.account_ops().len(), 2);
}

#[test]
fn create_sysadminctl_failure_rolls_back_dseditgroup() {
    // The original user-creation failure surfaces; the successful rollback isn't reported.
    let exec = StubHostMachine::new().fail_account_op(
        AccountOp::CreateTenantUser {
            name: "dev".into(),
            uid: UserId(600),
            gid: GroupId(600),
        },
        AccountError::NonZero {
            code: 78,
            stderr: "sysadminctl: -addUser failed: existing record\n".into(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    // The rollback DeleteShareGroup also drops the host membership; no explicit RemoveHost.
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ Share group 'dev-tenant-share' removed\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to create 'dev': process exited with code 78: \
         sysadminctl: -addUser failed: existing record\n"
    );
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::CreateShareGroup {
                group: "dev-tenant-share".into(),
                gid: GroupId(600)
            },
            AccountOp::AddHostToShareGroup {
                group: "dev-tenant-share".into(),
                host: "operator".into(),
            },
            AccountOp::CreateTenantUser {
                name: "dev".into(),
                uid: UserId(600),
                gid: GroupId(600)
            },
            AccountOp::DeleteShareGroup {
                group: "dev-tenant-share".into()
            },
        ],
    );
}

#[test]
fn create_real_mode_verbose_shows_rollback_echo() {
    let exec = StubHostMachine::new().fail_account_op(
        AccountOp::CreateTenantUser {
            name: "dev".into(),
            uid: UserId(600),
            gid: GroupId(600),
        },
        AccountError::NonZero {
            code: 78,
            stderr: "sysadminctl: -addUser failed: existing record\n".into(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "-v"],
    );
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    let want_stdout = format!(
        "{}\n\
         $ sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         $ sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         $ sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n\
         $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
         ✓ Share group 'dev-tenant-share' removed\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to create 'dev': process exited with code 78: \
         sysadminctl: -addUser failed: existing record\n"
    );
}

#[test]
fn create_sysadminctl_failure_with_rollback_failure_surfaces_both() {
    let exec = StubHostMachine::new()
        .fail_account_op(
            AccountOp::CreateTenantUser {
                name: "dev".into(),
                uid: UserId(600),
                gid: GroupId(600),
            },
            AccountError::NonZero {
                code: 78,
                stderr: "sysadminctl: -addUser failed: existing record\n".into(),
            },
        )
        .fail_account_op(
            AccountOp::DeleteShareGroup {
                group: "dev-tenant-share".into(),
            },
            AccountError::NonZero {
                code: 1,
                stderr: "dseditgroup: not authorized\n".into(),
            },
        );
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR");
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    let want_stderr = "tenant: failed to create 'dev': process exited with code 78: \
                       sysadminctl: -addUser failed: existing record\n\
                       tenant: rollback of group 'dev-tenant-share' also failed: process exited with code 1: \
                       dseditgroup: not authorized \
                       \u{2014} host now has an orphan group; next 'tenant destroy dev' will converge\n";
    assert_eq!(stderr, want_stderr);
    assert_eq!(exec.account_ops().len(), 4);
}

#[test]
fn create_real_mode_invokes_firewall_ops_in_locked_order() {
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let ops = exec.firewall_ops();
    let names: Vec<&'static str> = ops
        .iter()
        .map(|op| match op {
            tenant::domain::FirewallOp::BackupConfig => "BackupConfig",
            tenant::domain::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::domain::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::domain::FirewallOp::Reload => "Reload",
            tenant::domain::FirewallOp::Enable => "Enable",
            tenant::domain::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::domain::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::domain::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
        })
        .collect();
    assert_eq!(
        names,
        vec![
            "BackupConfig",
            "InstallAnchor",
            "UpdateConfig",
            "Reload",
            "Enable",
        ],
    );
}

#[test]
fn create_real_mode_install_anchor_body_reflects_runtime_hosts_from_profile() {
    // Create writes the default profile (no runtime hosts) before reading, so the table is `{ }`.
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let body = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::domain::FirewallOp::InstallAnchor { body, .. } => Some(body),
            _ => None,
        })
        .expect("InstallAnchor op must have been issued");
    assert!(
        body.contains("table <allowed> persist { }"),
        "anchor body must include empty allowlist table; got:\n{body}"
    );
    assert!(
        body.contains("pass out quick on lo0 proto tcp from any to any user dev no state"),
        "anchor body must include loopback egress pass; got:\n{body}"
    );
}

#[test]
fn create_real_mode_install_anchor_body_includes_hosts_when_profile_populated() {
    let populated = "schema_version = 1\n\
                     \n\
                     [allowlist.runtime]\n\
                     hosts = [\"example.com\", \"api.anthropic.com\"]\n\
                     \n\
                     [allowlist.install]\n\
                     hosts = []\n";
    let exec = StubHostMachine::new().with_create_profile_content("dev", populated);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let body = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::domain::FirewallOp::InstallAnchor { body, .. } => Some(body),
            _ => None,
        })
        .expect("InstallAnchor op must have been issued");
    assert!(
        body.contains(
            "table <allowed> persist { \\\n  \
             example.com \\\n  \
             api.anthropic.com \\\n}\n"
        ),
        "anchor body must include populated backslash-continued table \
         with hosts in profile order; got:\n{body}"
    );
    assert!(
        !body.contains("table <allowed> persist { }"),
        "anchor body must NOT include the empty-table form when hosts present; got:\n{body}"
    );
    assert!(
        body.contains("pass out quick on lo0 proto tcp from any to any user dev no state"),
        "anchor body must still include loopback egress pass; got:\n{body}"
    );
    assert!(
        body.contains("block out quick proto { tcp udp } from any to any user dev"),
        "anchor body must still include catchall block; got:\n{body}"
    );
}

#[test]
fn create_real_mode_install_anchor_body_includes_declared_inbound_ports() {
    let populated = "schema_version = 1\n\
                     \n\
                     [allowlist.runtime]\n\
                     hosts = []\n\
                     \n\
                     [allowlist.install]\n\
                     hosts = []\n\
                     \n\
                     [inbound]\n\
                     ports = [3000]\n";
    let exec = StubHostMachine::new().with_create_profile_content("dev", populated);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let body = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::domain::FirewallOp::InstallAnchor { body, .. } => Some(body),
            _ => None,
        })
        .expect("InstallAnchor op must have been issued");
    assert!(
        body.contains("pass in quick on lo0 proto tcp from any to any port 3000 user dev no state"),
        "anchor body must include the declared inbound port pass (steady state); got:\n{body}"
    );
}

#[test]
fn create_real_mode_update_conf_content_reflects_existing_pf_conf() {
    let initial = "# host's existing pf.conf\nset block-policy drop\n";
    let exec = StubHostMachine::new().with_pf_conf(initial);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let updated = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::domain::FirewallOp::UpdateConfig { content } => Some(content),
            _ => None,
        })
        .expect("UpdateConfig op must have been issued");
    assert!(
        updated.starts_with(initial),
        "updated pf.conf must preserve existing content; got:\n{updated}"
    );
    assert!(
        updated.contains("anchor \"tenant-dev\""),
        "updated pf.conf must reference tenant anchor; got:\n{updated}"
    );
    assert!(
        updated.contains("load anchor \"tenant-dev\" from \"/etc/pf.anchors/tenant-dev\""),
        "updated pf.conf must include load-anchor line; got:\n{updated}"
    );
}

#[test]
fn create_firewall_install_anchor_failure_leaves_user_group_profile_present() {
    let exec = StubHostMachine::new().fail_firewall_op(
        tenant::domain::FirewallOp::InstallAnchor {
            name: "dev".into(),
            body: tenant::firewall::render_anchor(
                "dev",
                &[],
                tenant::firewall::InboundRules::Restricted(vec![]),
            ),
        },
        FirewallError::Fs {
            path: "/etc/pf.anchors/tenant-dev".to_string(),
            message: "permission denied".to_string(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         ✓ Co-working directory ensured at /Users/Shared/tenants/dev\n\
         ✓ Tenant 'dev' keychain created\n\
         ✓ Tenant 'dev' default keychain set\n\
         ✓ Tenant 'dev' keychain added to search list\n\
         ✓ Tenant 'dev' keychain auto-lock disabled\n\
         ✓ Tenant 'dev' password stashed in operator keychain\n\
         ✓ Profile written to ~/.config/tenant/profiles/dev.toml\n\
         ✓ Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to install firewall for 'dev': \
         filesystem error at /etc/pf.anchors/tenant-dev: permission denied\n"
    );
    assert_eq!(
        exec.account_ops().len(),
        4,
        "create-share-group + add-host + create-tenant-user + ensure-cowork-dir all ran"
    );
    assert!(
        exec.has_profile("dev"),
        "profile should remain present after firewall failure"
    );
}

#[test]
fn create_reload_failure_triggers_restore_remove_anchor_reload_recovery_sequence() {
    let exec = StubHostMachine::new().fail_firewall_op(
        tenant::domain::FirewallOp::Reload,
        FirewallError::NonZero {
            code: 1,
            stderr: "syntax error".to_string(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    assert!(
        stdout.starts_with(&format!("{}\n", section_line("Creating tenant 'dev'"))),
        "expected section divider opener: {stdout:?}",
    );
    assert!(
        !stdout.contains(&section_line("Done")),
        "Done section must not emit when verb fails: {stdout:?}",
    );
    assert!(
        stderr.starts_with("tenant: failed to install firewall for 'dev':"),
        "expected install-firewall-failed framing; got: {stderr:?}"
    );
    let op_names: Vec<&'static str> = exec
        .firewall_ops()
        .iter()
        .map(|op| match op {
            tenant::domain::FirewallOp::BackupConfig => "BackupConfig",
            tenant::domain::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::domain::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::domain::FirewallOp::Reload => "Reload",
            tenant::domain::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::domain::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::domain::FirewallOp::Enable => "Enable",
            tenant::domain::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
        })
        .collect();
    assert_eq!(
        op_names,
        vec![
            "BackupConfig",
            "InstallAnchor",
            "UpdateConfig",
            "Reload",
            "RestoreConfigFromBackup",
            "RemoveAnchor",
            "Reload",
            "FlushAnchor",
        ],
        "recovery sequence must run after reload failure"
    );
}

#[test]
fn create_reload_failure_with_failed_restore_surfaces_recovery_hint_naming_backup_path() {
    let exec = StubHostMachine::new()
        .fail_firewall_op(
            tenant::domain::FirewallOp::Reload,
            FirewallError::NonZero {
                code: 1,
                stderr: "syntax error".to_string(),
            },
        )
        .fail_firewall_op(
            tenant::domain::FirewallOp::RestoreConfigFromBackup,
            FirewallError::NonZero {
                code: 1,
                stderr: "cp: permission denied".to_string(),
            },
        );
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR");
    assert!(
        stderr.contains("pf.conf restore from /etc/pf.conf.tenant-backup failed"),
        "expected RestoreFailed framing; got: {stderr:?}"
    );
    assert!(
        stderr.contains("sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf to recover"),
        "expected manual recovery hint; got: {stderr:?}"
    );
}

#[test]
fn create_pf_enable_failure_surfaces_via_create_firewall_failed() {
    let exec = StubHostMachine::new().fail_firewall_op(
        tenant::domain::FirewallOp::Enable,
        FirewallError::NonZero {
            code: 1,
            stderr: "pfctl: operation not permitted".to_string(),
        },
    );
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR");
    assert!(
        stderr.starts_with("tenant: failed to install firewall for 'dev':"),
        "got: {stderr:?}"
    );
    assert_eq!(exec.firewall_ops().len(), 5, "5 firewall ops up to Enable");
}

#[test]
fn create_dry_run_bypasses_firewall_host_machine() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
    assert!(
        exec.firewall_ops().is_empty(),
        "firewall host machine should not be invoked in dry-run; got: {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn create_real_mode_dseditgroup_failure_surfaces_host_machine_stderr() {
    let exec = StubHostMachine::new().fail_account_blanket(
        78,
        "dseditgroup: cannot create group dev-tenant-share: not authorized\n",
    );
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert_eq!(
        stdout,
        format!("{}\n", section_line("Creating tenant 'dev'")),
    );
    assert_eq!(
        stderr,
        "tenant: failed to create group 'dev-tenant-share' for 'dev': process exited with code 78: \
         dseditgroup: cannot create group dev-tenant-share: not authorized\n"
    );
}

#[test]
fn create_success_path_does_not_invoke_flush_anchor() {
    // A FlushAnchor on the success path would wipe the rules just installed.
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !exec
            .firewall_ops()
            .iter()
            .any(|op| matches!(op, tenant::domain::FirewallOp::FlushAnchor { .. })),
        "FlushAnchor must NOT appear in create's success-path firewall_ops; got: {:?}",
        exec.firewall_ops()
    );
}

// --- Post-provision share reapply ---

#[test]
fn create_with_pre_populated_shares_runs_post_provision_substrate() {
    let with_share = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_create_profile_content("dev", &with_share);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");

    let acl_ops = exec.acl_ops();
    assert_eq!(
        acl_ops,
        vec![AclOp::Grant {
            path: PathBuf::from("/tmp"),
            group: "dev-tenant-share".into(),
            mode: AclMode::Rw,
        }],
        "expected single Grant op from post-provision substrate; got {acl_ops:?}"
    );
    let symlink_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .collect();
    assert_eq!(
        symlink_ops.len(),
        1,
        "expected single symlink op; got {symlink_ops:?}"
    );
}

#[test]
fn create_with_default_profile_emits_no_post_provision_acl_ops() {
    let exec = StubHostMachine::new();
    let (code, _stdout, _stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0);
    assert!(
        exec.acl_ops().is_empty(),
        "default profile has no shares; AclOp must NOT fire: {:?}",
        exec.acl_ops()
    );
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
        "default profile has no shares; EnsureDir/EnsureSymlink must NOT fire: {new_account_ops:?}"
    );
}

#[test]
fn create_post_provision_refusal_carries_recovery_hint() {
    let bad_share = profile_with_shares(
        &[],
        &[],
        &[("/nonexistent/create-sentinel", "rw", "$HOME/src")],
    );
    let exec = StubHostMachine::new().with_create_profile_content("dev", &bad_share);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "EX_IOERR on share refusal; stderr={stderr:?}");
    assert!(
        stderr.contains("provisioned but share entry is invalid"),
        "stderr should be framed by refuse_create_post_provision_share: {stderr:?}"
    );
    assert!(
        stderr.contains("tenant reload dev"),
        "stderr should name the recovery command: {stderr:?}"
    );
}

// --- Pre-execution confirmation prompt ---

#[test]
fn create_real_verbose_interactive_emits_plan_before_prompt() {
    // The section divider only appears after the answer, so `n` leaves no verb-section output.
    let exec = StubHostMachine::new();
    let (code, stdout, _stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "-v"],
        b"y\n",
    );
    assert_eq!(code, 0);
    let sudo_idx = stdout
        .find("Sudo needed for: user provisioning, firewall install.")
        .expect("summary should emit Sudo line");
    let plan_idx = stdout
        .find("Plan (commands to execute):")
        .expect("verbose plan section should emit");
    let prompt_idx = stdout
        .find("Proceed? [Y/n]")
        .expect("confirm prompt should emit on TTY");
    let section_idx = stdout
        .find(&section_line("Creating tenant 'dev'"))
        .expect("section divider should emit after the operator answers");
    assert!(
        plan_idx < sudo_idx,
        "Plan section should appear before 'Sudo needed for' inside the summary; \
         plan={plan_idx} sudo={sudo_idx} in {stdout:?}"
    );
    assert!(
        sudo_idx < prompt_idx,
        "Proceed? prompt should follow the Sudo line; \
         sudo={sudo_idx} prompt={prompt_idx} in {stdout:?}"
    );
    assert!(
        section_idx > prompt_idx,
        "Section divider should land AFTER the confirm prompt — operator \
         commits to the verb after seeing the plan + prompt, not before; \
         prompt={prompt_idx} section={section_idx} in {stdout:?}"
    );
    assert!(
        stdout.contains("  \u{2022} Create share group 'dev-tenant-share' (GID 600)"),
        "plan should carry the intent bullet for CreateShareGroup: {stdout:?}"
    );
    assert!(
        stdout.contains("      sudo dseditgroup -o create -n . -i 600 dev-tenant-share"),
        "plan should carry the indented shell line under the bullet: {stdout:?}"
    );
}

#[test]
fn create_with_tty_proceeds_on_y() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev"],
        b"y\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("About to create tenant 'dev'"),
        "summary should emit: {stdout:?}",
    );
    assert!(
        stdout.contains("Proceed? [Y/n] "),
        "prompt should emit: {stdout:?}",
    );
    assert!(
        stdout.contains(&section_line("Creating tenant 'dev'")),
        "section divider should emit after Proceed: {stdout:?}",
    );
    assert!(
        stdout.ends_with(&format!(
            "Tenant 'dev' ready (UID 600, GID 600, anchor 'tenant-dev').\n{}\n",
            create_breadcrumb("dev"),
        )),
        "done line + breadcrumb should close: {stdout:?}",
    );
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

#[test]
fn create_with_tty_aborts_on_n() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev"],
        b"n\n",
    );
    assert_eq!(code, 0, "exit 0 on user-initiated abort; stderr={stderr:?}");
    assert!(
        stdout.contains("Aborted by operator. No changes made."),
        "aborted line should emit: {stdout:?}",
    );
    assert!(
        exec.account_ops().is_empty(),
        "no substrate should run: {:?}",
        exec.account_ops()
    );
}

#[test]
fn create_with_tty_empty_input_uses_default_yes() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev"],
        b"\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Proceed? [Y/n] "),
        "default-Y hint should appear in prompt: {stdout:?}",
    );
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

#[test]
fn create_with_yes_flag_skips_prompt_proceeds() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "--yes"],
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
fn create_with_invalid_input_reprompts_then_accepts() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev"],
        b"maybe\ny\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Please answer y or n."),
        "reprompt hint should appear: {stdout:?}",
    );
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

// --- Pre-exec doctor audit ---

#[test]
fn create_pre_exec_doctor_silent_when_host_is_clean() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
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
fn create_pre_exec_doctor_emits_critical_inline_when_pf_disabled() {
    let exec = StubHostMachine::new().with_pf_status_content("Status: Disabled\n");
    let (code, stdout, stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("critical: pf is globally disabled"),
        "PfDisabled critical must emit inline; stdout={stdout:?}"
    );
}

#[test]
fn create_pre_exec_doctor_scope_excludes_env_leak() {
    let exec = StubHostMachine::new().with_env_policy_content("");
    let (code, stdout, stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("\u{26a0} Doctor:"),
        "EnvLeak must NOT propagate to create scope; stdout={stdout:?}"
    );
}

#[test]
fn create_pre_exec_doctor_silent_in_scripted_mode() {
    let exec = StubHostMachine::new().with_pf_status_content("Status: Disabled\n");
    let (code, stdout, _stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("\u{26a0} Doctor:") && !stdout.contains("critical:"),
        "scripted real-mode must not emit audit; stdout={stdout:?}"
    );
}

#[test]
fn create_pre_exec_doctor_substrate_failure_surfaces_and_proceeds() {
    let exec = StubHostMachine::new().fail_next_pf_status(FirewallError::NonZero {
        code: 1,
        stderr: "sudo: a password is required".into(),
    });
    let (code, _stdout, stderr) = run_with_stdin(
        StubUserDirectory::default(),
        &exec,
        &["create", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "verb proceeds despite audit substrate failure");
    assert!(
        stderr.contains("failed to read pf state"),
        "substrate failure surfaces via doctor_firewall_failed frame; stderr={stderr:?}"
    );
}

#[test]
fn create_surfaces_user_directory_error_when_uid_allocation_fails() {
    let stub = StubUserDirectory {
        fail_used_uids: directory_fail_once(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 74);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert!(
        stderr.starts_with("tenant: failed to allocate UID: "),
        "expected create_uid_allocation_failed frame; stderr={stderr:?}"
    );
}

#[test]
fn create_surfaces_user_directory_error_when_gid_allocation_fails() {
    let stub = StubUserDirectory {
        fail_used_gids: directory_fail_once(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 74);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert!(
        stderr.starts_with("tenant: failed to allocate GID: "),
        "expected create_gid_allocation_failed frame; stderr={stderr:?}"
    );
}

// --- Keychain bootstrap ---
// Each invocation generates a fresh password, so tests extract it from the recorded op.

/// Defends against a hard-coded password or a deterministic RNG seed.
#[test]
fn create_uses_fresh_keychain_password_each_invocation() {
    let exec1 = StubHostMachine::new();
    let (code1, _, _) = run_with_exec(StubUserDirectory::default(), &exec1, &["create", "alpha"]);
    assert_eq!(code1, 0);
    let exec2 = StubHostMachine::new();
    let (code2, _, _) = run_with_exec(StubUserDirectory::default(), &exec2, &["create", "beta"]);
    assert_eq!(code2, 0);

    let pw1 = match &exec1.keychain_ops()[0] {
        KeychainOp::CreateTenantKeychain { password, .. } => password.expose_secret().to_string(),
        other => panic!("expected CreateTenantKeychain, got: {other:?}"),
    };
    let pw2 = match &exec2.keychain_ops()[0] {
        KeychainOp::CreateTenantKeychain { password, .. } => password.expose_secret().to_string(),
        other => panic!("expected CreateTenantKeychain, got: {other:?}"),
    };
    assert_ne!(
        pw1, pw2,
        "two consecutive creates must generate distinct keychain passwords"
    );
}

/// Stash must carry the same bytes as CreateTenantKeychain so the shell/bootstrap unlock works.
#[test]
fn create_provision_and_stash_share_the_same_password() {
    let exec = StubHostMachine::new();
    let (code, _, _) = run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0);
    let ops = exec.keychain_ops();
    assert_eq!(
        ops.len(),
        5,
        "expected 4 provision sub-steps + StashPassword (5 ops), got: {ops:?}"
    );
    let create_pw = match &ops[0] {
        KeychainOp::CreateTenantKeychain { name, password } => {
            assert_eq!(name.as_str(), "dev");
            password.expose_secret().to_string()
        }
        other => panic!("expected CreateTenantKeychain first, got: {other:?}"),
    };
    assert!(
        matches!(&ops[1], KeychainOp::SetDefaultKeychain { name } if name.as_str() == "dev"),
        "expected SetDefaultKeychain second, got: {:?}",
        ops[1]
    );
    assert!(
        matches!(&ops[2], KeychainOp::AddKeychainToSearchList { name } if name.as_str() == "dev"),
        "expected AddKeychainToSearchList third, got: {:?}",
        ops[2]
    );
    assert!(
        matches!(&ops[3], KeychainOp::DisableKeychainAutoLock { name } if name.as_str() == "dev"),
        "expected DisableKeychainAutoLock fourth, got: {:?}",
        ops[3]
    );
    let stash_pw = match &ops[4] {
        KeychainOp::StashPassword { name, password } => {
            assert_eq!(name.as_str(), "dev");
            password.expose_secret().to_string()
        }
        other => panic!("expected StashPassword fifth, got: {other:?}"),
    };
    assert_eq!(
        create_pw, stash_pw,
        "create-keychain + stash must carry the same secret"
    );
    assert!(
        !create_pw.is_empty(),
        "generated password must be non-empty"
    );
}

#[test]
fn keychain_password_debug_is_redacted() {
    let pw = tenant::domain::KeychainPassword::test_dummy("super-secret-value");
    let formatted = format!("{pw:?}");
    assert!(
        formatted.contains("<redacted>"),
        "Debug should contain '<redacted>'; got: {formatted}"
    );
    assert!(
        !formatted.contains("super-secret-value"),
        "Debug must not leak the raw password; got: {formatted}"
    );
}

#[test]
fn create_dry_run_plan_redacts_password() {
    let (code, stdout, _) = run_with(
        StubUserDirectory::default(),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("-p <password>"),
        "expected literal '<password>' in dry-run plan; stdout was: {stdout}"
    );
}

#[test]
fn create_keychain_provision_failure_surfaces_with_user_and_group_present() {
    let exec = StubHostMachine::new().fail_next_keychain_create(KeychainError::NonZero {
        code: 51,
        stderr: "security: SecKeychainCreate -25297 The user name or passphrase is incorrect.\n"
            .into(),
    });
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         ✓ Co-working directory ensured at /Users/Shared/tenants/dev\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert!(
        stderr.starts_with("tenant: failed to provision keychain for 'dev':"),
        "expected create_keychain_provision_failed frame; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("run `tenant destroy dev` to clean up"),
        "expected recovery hint; stderr={stderr:?}"
    );
    assert_eq!(exec.account_ops().len(), 4, "account ops not rolled back");
    assert_eq!(exec.keychain_ops().len(), 1);
    assert!(
        matches!(
            exec.keychain_ops()[0],
            KeychainOp::CreateTenantKeychain { .. }
        ),
        "expected CreateTenantKeychain; got: {:?}",
        exec.keychain_ops()[0]
    );
}

#[test]
fn create_partial_keychain_provision_failure_at_step_2_surfaces() {
    let exec = StubHostMachine::new().fail_next_keychain_set_default(KeychainError::NonZero {
        code: 51,
        stderr: "security: default-keychain failed\n".into(),
    });
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         ✓ Co-working directory ensured at /Users/Shared/tenants/dev\n\
         ✓ Tenant 'dev' keychain created\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert!(
        stderr.starts_with("tenant: failed to provision keychain for 'dev':"),
        "expected create_keychain_provision_failed frame; stderr={stderr:?}"
    );
    let ops = exec.keychain_ops();
    assert_eq!(ops.len(), 2, "expected 2 keychain ops, got: {ops:?}");
    assert!(
        matches!(&ops[0], KeychainOp::CreateTenantKeychain { .. }),
        "first op should be CreateTenantKeychain; got: {:?}",
        ops[0]
    );
    assert!(
        matches!(&ops[1], KeychainOp::SetDefaultKeychain { .. }),
        "second op should be SetDefaultKeychain; got: {:?}",
        ops[1]
    );
}

#[test]
fn create_keychain_stash_failure_surfaces_with_keychain_provisioned() {
    let exec = StubHostMachine::new().fail_next_keychain_stash(KeychainError::NonZero {
        code: 45,
        stderr: "security: SecKeychainAddGenericPassword -25299 duplicate.\n".into(),
    });
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         ✓ Co-working directory ensured at /Users/Shared/tenants/dev\n\
         ✓ Tenant 'dev' keychain created\n\
         ✓ Tenant 'dev' default keychain set\n\
         ✓ Tenant 'dev' keychain added to search list\n\
         ✓ Tenant 'dev' keychain auto-lock disabled\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert!(
        stderr.starts_with("tenant: failed to stash 'dev' password in operator keychain:"),
        "expected create_keychain_stash_failed frame; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("run `tenant destroy dev` to clean up"),
        "expected recovery hint; stderr={stderr:?}"
    );
    assert_eq!(exec.keychain_ops().len(), 5);
}

#[test]
fn create_refuses_when_cowork_path_is_a_regular_file() {
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new().with_host_path_kind(&cowork_path, PathKind::Other);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(
        code, 74,
        "EX_IOERR expected on cowork-path occupancy; stderr={stderr:?}"
    );
    assert!(
        stderr.starts_with("tenant: failed to provision co-working directory for 'dev':"),
        "expected create_cowork_dir_failed frame; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("/Users/Shared/tenants/dev"),
        "stderr should name the cowork path: {stderr:?}"
    );
    assert!(
        stderr.contains("a non-directory entry"),
        "stderr should name the unexpected kind: {stderr:?}"
    );
    assert_eq!(
        exec.account_ops().len(),
        3,
        "expected group + host + user only (no cowork op); got: {:?}",
        exec.account_ops()
    );
    assert!(
        !exec
            .account_ops()
            .iter()
            .any(|op| matches!(op, AccountOp::EnsureCoworkDir { .. })),
        "EnsureCoworkDir must not reach the substrate when path is occupied",
    );
}

/// A symlink would steer mkdir/chown/chmod to its target; the refusal names that target.
#[test]
fn create_refuses_when_cowork_path_is_a_symlink() {
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new().with_host_path_kind(
        &cowork_path,
        PathKind::Symlink(PathBuf::from("/tmp/elsewhere")),
    );
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(
        code, 74,
        "EX_IOERR expected on symlink occupancy; stderr={stderr:?}"
    );
    assert!(
        stderr.starts_with("tenant: failed to provision co-working directory for 'dev':"),
        "expected create_cowork_dir_failed frame; stderr={stderr:?}"
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
        !exec
            .account_ops()
            .iter()
            .any(|op| matches!(op, AccountOp::EnsureCoworkDir { .. })),
        "EnsureCoworkDir must not reach the substrate when path is a symlink",
    );
}

#[test]
fn create_accepts_when_cowork_path_is_already_a_directory() {
    let cowork_path = PathBuf::from("/Users/Shared/tenants/dev");
    let exec = StubHostMachine::new().with_host_path_kind(&cowork_path, PathKind::Dir);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(
        code, 0,
        "create should proceed when cowork path is a directory; stderr={stderr:?}"
    );
    assert!(
        exec.account_ops()
            .iter()
            .any(|op| matches!(op, AccountOp::EnsureCoworkDir { .. })),
        "EnsureCoworkDir should run on an existing directory",
    );
}

// --- Full reapply scope on create-post-provision ---

#[test]
fn create_post_provision_share_pass_uses_full_reapply_scope_emitting_grant() {
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_create_profile_content("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "create happy path; stderr={stderr:?}");

    let grant_count = exec
        .acl_ops()
        .into_iter()
        .filter(|op| matches!(op, AclOp::Grant { .. }))
        .count();
    assert_eq!(
        grant_count, 1,
        "create's post-provision share pass (Full scope) must emit exactly one AclOp::Grant per declared share"
    );
}

#[test]
fn create_emits_cowork_dir_during_provisioning() {
    // EnsureCoworkDir originates in Tenants::create, not reapply_shares_post_provision.
    let toml = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubHostMachine::new().with_create_profile_content("dev", &toml);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "create happy path; stderr={stderr:?}");

    let cowork_count = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureCoworkDir { .. }))
        .count();
    assert_eq!(
        cowork_count, 1,
        "create must emit exactly one EnsureCoworkDir during provisioning"
    );
}

#[test]
fn create_merges_included_fragment_hosts_into_anchor_body() {
    let profile = "schema_version = 1\n\
                   include = [\"base\"]\n\
                   [allowlist.runtime]\n\
                   hosts = [\"prof.example\"]\n\
                   [allowlist.install]\n\
                   hosts = []\n";
    let fragment = "[allowlist.runtime]\nhosts = [\"frag.example\"]\n";
    let exec = StubHostMachine::new()
        .with_create_profile_content("dev", profile)
        .with_profile_fragment("base", fragment);
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let body = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::domain::FirewallOp::InstallAnchor { body, .. } => Some(body),
            _ => None,
        })
        .expect("InstallAnchor op must have been issued");
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
fn create_keeps_and_uses_an_existing_hand_written_profile() {
    let authored = profile_with_hosts(&["api.example.com"], &[]);
    let exec = StubHostMachine::new().with_existing_profile("dev", &authored);
    let (code, stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        exec.profile_ops().is_empty(),
        "the profile must not be rewritten"
    );
    assert_eq!(exec.profile_state().get("dev"), Some(&authored));
    assert!(
        stdout.contains("Kept existing profile at ~/.config/tenant/profiles/dev.toml"),
        "stdout={stdout:?}"
    );
    let expected = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["api.example.com"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    assert!(
        exec.firewall_ops().contains(&FirewallOp::InstallAnchor {
            name: "dev".into(),
            body: expected,
        }),
        "anchor renders from the kept profile"
    );
}

#[test]
fn create_refuses_an_existing_profile_that_does_not_parse_before_creating_anything() {
    let exec = StubHostMachine::new().with_existing_profile("dev", "schema_version = 2\n");
    let (code, _stdout, stderr) =
        run_with_exec(StubUserDirectory::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 64);
    assert!(
        stderr.starts_with(
            "tenant: refusing to create 'dev': the existing profile \
             ~/.config/tenant/profiles/dev.toml does not load \u{2014} "
        ),
        "stderr={stderr:?}"
    );
    assert!(
        stderr.ends_with("; fix it, or move it aside to start from the default\n"),
        "stderr={stderr:?}"
    );
    assert!(exec.account_ops().is_empty() && exec.profile_ops().is_empty());
}
