use tenant::accounts::StubReader;
use tenant::executor::{AccountError, AccountOp, FirewallError, ProfileOp, StubExecutor};

mod common;
use common::*;

#[test]
fn create_dry_run_default_shows_intent() {
    let (code, stdout, stderr) = run_with(StubReader::default(), &["create", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would create tenant 'dev'.\n");
}

#[test]
fn create_accepts_max_length_name() {
    let name = "a".repeat(31);
    let (code, stdout, stderr) = run_with(StubReader::default(), &["create", &name, "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, format!("Would create tenant '{name}'.\n"));
}

#[test]
fn create_accepts_single_letter_name() {
    let (code, stdout, stderr) = run_with(StubReader::default(), &["create", "x", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would create tenant 'x'.\n");
}

#[test]
fn verbose_shows_floor_uid_and_gid_when_neither_in_use() {
    // Phase 3 changes the plan from one argv to three: dseditgroup-create
    // (group-first so the user's home directory lands on the tenant-share
    // group, not staff), sysadminctl-addUser (pointing -GID at the just-
    // created group), and an unconditional `# on rollback` line that
    // documents what happens if sysadminctl fails after the group was
    // created. The rollback line is in the plan but not in the `$` echo
    // block — that asymmetry is the operator-visible signal of whether
    // the rollback fired (mirrors the destroy-side dscl-cleanup
    // convention shipped in V1.8). UID and GID allocators are decoupled
    // post-Phase-3 but both happen to bottom-out at TENANT_UID_FLOOR=600
    // when both spaces are empty.
    let (code, stdout, _stderr) =
        run_with(StubReader::default(), &["create", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let want = "Would create tenant 'dev'.\n  \
                sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share  # on rollback\n  \
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf  # on reload failure\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev  # on reload failure\n  \
                sudo pfctl -f /etc/pf.conf  # on reload failure\n  \
                sudo pfctl -a tenant-dev -F all  # on reload failure\n  \
                sudo pfctl -e\n";
    assert_eq!(stdout, want);
}

/// Stub whose `used_uids()` reports the given UIDs as taken (by synthetic
/// user names that no test asserts about). Used by allocator-driven tests.
fn stub_with_used_uids(uids: &[u32]) -> StubReader {
    StubReader {
        uid_by_name: uids
            .iter()
            .enumerate()
            .map(|(i, &u)| (format!("u{i}"), u))
            .collect(),
        ..Default::default()
    }
}

#[test]
fn verbose_shows_lowest_free_uid_with_gap_and_gid_at_floor() {
    // First decoupled-allocation evidence: UID space has a gap so the
    // allocator returns 602, but the GID space is empty (stub_with_used_uids
    // only populates uid_by_name, leaving gid_by_name empty) so the GID
    // allocator returns 600. Phase 3 explicitly does NOT force UID == GID
    // — the two allocators consult their own spaces and may diverge.
    let (code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[600, 601, 603]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Would create tenant 'dev'.\n  \
                sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 602 -GID 600\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share  # on rollback\n  \
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf  # on reload failure\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev  # on reload failure\n  \
                sudo pfctl -f /etc/pf.conf  # on reload failure\n  \
                sudo pfctl -a tenant-dev -F all  # on reload failure\n  \
                sudo pfctl -e\n";
    assert_eq!(stdout, want);
}

#[test]
fn verbose_uid_skips_taken_floor_gid_stays_at_floor() {
    // UID 600 taken, GID space empty → UID 601, GID 600. Pins the new
    // decoupled-allocator semantics on the boundary: a single taken UID
    // doesn't drag the GID allocator with it.
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
    // UIDs 600, 601, 603 taken (any input order) → UID 602; GID space empty → GID 600.
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
    // UIDs below the floor (500, 599) don't constrain the allocator; both
    // allocators bottom-out at the floor.
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
    // Mirror twin of `verbose_uid_skips_taken_floor_gid_stays_at_floor`:
    // empty UID space + GID 600 taken (an unrelated group at the floor) →
    // UID 600, GID 601. The dseditgroup `-i` value tracks the GID
    // allocator, not the UID allocator — the literal argument is the
    // load-bearing thing tenant passes to dseditgroup, so a regression
    // that wires `-i` to `uid` would slip past UID-only tests but trips
    // here.
    let stub = StubReader {
        groups: vec!["other".to_string()],
        gid_by_name: [("other".to_string(), 600)].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let want = "Would create tenant 'dev'.\n  \
                sudo dseditgroup -o create -n . -i 601 dev-tenant-share\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 601\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share  # on rollback\n  \
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf  # on reload failure\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev  # on reload failure\n  \
                sudo pfctl -f /etc/pf.conf  # on reload failure\n  \
                sudo pfctl -a tenant-dev -F all  # on reload failure\n  \
                sudo pfctl -e\n";
    assert_eq!(stdout, want);
}

#[test]
fn verbose_uid_and_gid_allocators_cross_over() {
    // Crossover stub: UID space has the floor (600) taken; GID space has
    // 601 taken. UID allocator climbs to 601 (lowest free above the
    // floor); GID allocator stays at 600 (still free in its space). The
    // resulting argv carries `-UID 601 -GID 600` — a *crossover* between
    // the two spaces that's impossible if the two allocators are fused.
    // The strongest single-test defense against a regression that
    // wires `-i` and `-GID` to `lowest_free_uid` instead of
    // `lowest_free_gid`.
    let stub = StubReader {
        users: vec!["legacy".to_string()],
        uid_by_name: [("legacy".to_string(), 600)].into_iter().collect(),
        groups: vec!["phantom".to_string()],
        gid_by_name: [("phantom".to_string(), 601)].into_iter().collect(),
    };
    let (code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let want = "Would create tenant 'dev'.\n  \
                sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 601 -GID 600\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share  # on rollback\n  \
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf  # on reload failure\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev  # on reload failure\n  \
                sudo pfctl -f /etc/pf.conf  # on reload failure\n  \
                sudo pfctl -a tenant-dev -F all  # on reload failure\n  \
                sudo pfctl -e\n";
    assert_eq!(stdout, want);
}

#[test]
fn create_rejects_empty_name() {
    let (code, stdout, stderr) = run_with(StubReader::default(), &["create", "", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn create_rejects_non_letter_start() {
    for (name, offender) in [("1dev", '1'), ("_dev", '_'), ("Dev", 'D')] {
        let (code, stdout, stderr) =
            run_with(StubReader::default(), &["create", name, "--dry-run"]);
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
            run_with(StubReader::default(), &["create", name, "--dry-run"]);
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
    let (code, stdout, stderr) = run_with(StubReader::default(), &["create", &name, "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        format!("tenant: name '{name}' is too long (32 characters; maximum is 31)\n"),
    );
}

#[test]
fn create_rejects_reserved_names() {
    // Lexical blocklist on top of charset rules: even though these names
    // all pass `[a-z][a-z0-9_-]*`, they're reserved as macOS system /
    // role names and would either alias a real account (`root`, `nobody`)
    // or carry semantics we don't want a tenant to inherit (`wheel`,
    // `staff`, `sudo`). Copied verbatim from the sandbox plugin's
    // `scripts/lib/naming.py` reserved set — see CLAUDE.md cross-reference.
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) =
            run_with(StubReader::default(), &["create", name, "--dry-run"]);
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
    // Pins exact-match semantics on the blocklist: 'rooty' / 'wheelman'
    // contain reserved names as substrings but are not themselves
    // reserved. A future refactor that swaps `contains` for `starts_with`
    // or vice-versa would silently break this — the test guards the
    // intended behavior.
    for name in ["rooty", "wheelman", "admins", "daemonic"] {
        let (code, stdout, stderr) =
            run_with(StubReader::default(), &["create", name, "--dry-run"]);
        assert_eq!(code, 0, "want success for {name:?}; stderr={stderr:?}");
        assert_eq!(stdout, format!("Would create tenant '{name}'.\n"));
    }
}

#[test]
fn create_rejects_when_user_exists() {
    let stub = StubReader {
        users: vec!["dev".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: user 'dev' already exists\n");
}

#[test]
fn create_rejects_when_tenant_share_group_exists() {
    // Phase 3 names the primary group `<name>-tenant-share` (not bare
    // `<name>`). The conflict check now refuses when that suffixed name is
    // already taken, regardless of what the bare-name group looks like.
    let stub = StubReader {
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
    // The `Both` arm — user named `dev` AND the suffixed group `dev-tenant-share`
    // both present. The message names both with the literal group name so
    // the operator can find them with `dscl` directly.
    let stub = StubReader {
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
    // Phase 3 only reserves `<name>-tenant-share` as conflict territory.
    // A pre-existing bare-name group is no longer something tenant creates
    // (sysadminctl is invoked with -GID pointing at the explicit
    // tenant-share group's GID, not asking sysadminctl to mint a new group
    // named after the user) so a bare `dev` group on the host is harmless.
    // Pins the new contract's specificity — a future regression that
    // swaps `has_group("<name>-tenant-share")` for `has_group(name)` (or
    // checks both) would trip this test.
    let stub = StubReader {
        groups: vec!["dev".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would create tenant 'dev'.\n");
}

#[test]
fn create_succeeds_when_unrelated_user_exists() {
    let stub = StubReader {
        users: vec!["ops".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would create tenant 'dev'.\n");
}

#[test]
fn create_writes_default_profile_to_store() {
    // After a successful real-mode create, the substrate's profile state
    // contains an entry keyed by the tenant name. Content-shape
    // assertion lives in the dedicated TOML test below; this test only
    // pins presence via `StubExecutor::has_profile`.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        exec.has_profile("dev"),
        "expected profile 'dev' to be present after create; state={:?}",
        exec.profile_state()
    );
}

#[test]
fn create_writes_profile_with_correct_toml_shape() {
    // Byte-exact pin on the default profile content. Schema-version
    // floor at 1 (future migrations bump this); two empty allowlist
    // sections matching the shape cycle 2's PF anchor will read from.
    // No `[share]` section — that's Claude-Code-specific and out of
    // scope for the generic Rust port.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let state = exec.profile_state();
    let content = state.get("dev").expect("profile 'dev' should be present");
    let want = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = []\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    assert_eq!(content, want, "profile content mismatch");
}

#[test]
fn create_dry_run_does_not_write_profile() {
    // Dry-run swap-in of `DryRunExecutor` means the wired `StubExecutor`
    // never receives an `execute_profile` call. Mirrors the
    // `dry_run_bypasses_injected_executor` test for the executor side.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        StubReader::default(),
        &exec,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Would create tenant 'dev'.\n");
    assert!(
        !exec.has_profile("dev"),
        "profile should not be written in dry-run; state={:?}",
        exec.profile_state()
    );
}

#[test]
fn create_real_mode_standard_emits_only_post_exec_confirmation() {
    // Standard real mode is silent before exec; one confirmation line
    // after. No UID/GID — that's reserved for verbose mode. The op
    // order is load-bearing: CreateShareGroup must precede
    // CreateTenantUser so the new user's home directory chowns to
    // `dev-tenant-share` (sysadminctl chowns the home dir to the group
    // named by `-GID` at creation time); this test pins both the order
    // and the operand values.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Created tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::CreateShareGroup {
                name: "dev".into(),
                gid: 600
            },
            AccountOp::CreateTenantUser {
                name: "dev".into(),
                uid: 600,
                gid: 600
            },
        ],
    );
    assert_eq!(
        exec.profile_ops(),
        vec![ProfileOp::Create { name: "dev".into() }],
    );
}

#[test]
fn create_real_mode_verbose_shows_pre_exec_plan_and_post_exec_uid_gid() {
    // Real+verbose now shows the full 3-line plan upfront (including the
    // `# on rollback` line that documents what fires if sysadminctl
    // fails), then `$ ` echoes for each command that actually ran.
    // Success-path echo is 2 lines, not 3 — the rollback only echoes if
    // sysadminctl failed (covered in cycle 3). The post-exec
    // confirmation now inlines both UID and GID since Phase 3 allocates
    // them independently; either could be non-floor in real-world use.
    let exec = StubExecutor::new();
    let (code, stdout, _stderr) =
        run_with_exec(StubReader::default(), &exec, &["create", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Creating tenant 'dev'.\n  \
                sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share  # on rollback\n  \
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf  # on reload failure\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev  # on reload failure\n  \
                sudo pfctl -f /etc/pf.conf  # on reload failure\n  \
                sudo pfctl -a tenant-dev -F all  # on reload failure\n  \
                sudo pfctl -e\n\
                $ sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n\
                $ sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n\
                $ tee ~/.config/tenant/profiles/dev.toml < default.toml\n\
                $ sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n\
                $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
                $ sudo tee /etc/pf.conf < updated.conf\n\
                $ sudo pfctl -f /etc/pf.conf\n\
                $ sudo pfctl -e\n\
                Created tenant 'dev' (UID 600, GID 600).\n";
    assert_eq!(stdout, want);
}

#[test]
fn create_profile_write_failure_surfaces_with_user_and_group_present() {
    // Per the design lock: CreateShareGroup + CreateTenantUser have
    // both succeeded by the time the profile step fires, so a
    // profile-write failure does NOT roll back the user or group.
    // Operator sees an EX_IOERR with the `create_profile_failed` message
    // that names the profile path (so they don't have to grep source).
    // Their recovery is `tenant destroy <name>` — destroy's Destroyable
    // arm cleans up the user+group, and the missing profile case is a
    // successful noop for the profile-rm step.
    let exec = StubExecutor::new().fail_next_profile(tenant::profile::ProfileError {
        message: "disk full".into(),
    });
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to write profile '~/.config/tenant/profiles/dev.toml' \
         for 'dev': disk full\n"
    );
    // Two account ops (CreateShareGroup + CreateTenantUser) — no
    // rollback, since the locked policy is "leave user+group present on
    // profile failure".
    assert_eq!(
        exec.account_ops().len(),
        2,
        "expected CreateShareGroup + CreateTenantUser; no rollback"
    );
    // Profile is absent from the simulated state (the write failed) —
    // pins the fact that the failure is a real failure, not a silent
    // success.
    assert!(
        !exec.has_profile("dev"),
        "profile should be absent after write failure"
    );
}

#[test]
fn dry_run_bypasses_injected_executor() {
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        StubReader::default(),
        &exec,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Would create tenant 'dev'.\n");
    assert!(
        exec.account_ops().is_empty() && exec.profile_ops().is_empty(),
        "executor should not be invoked in dry-run mode; account_ops={:?}, profile_ops={:?}",
        exec.account_ops(),
        exec.profile_ops()
    );
}

#[test]
fn create_real_mode_dseditgroup_failure_aborts_before_sysadminctl() {
    // Phase 3 issues two exec calls: dseditgroup-create first, sysadminctl
    // second. `StubExecutor::failing(78)` fails ALL calls, so the first
    // call (dseditgroup-create) trips. The expected behavior is: stop
    // immediately (no sysadminctl, no rollback — there's nothing to roll
    // back because dseditgroup-create itself failed), exit EX_IOERR, and
    // emit the new `create_group_failed` shape that names the group
    // explicitly so the operator knows the user wasn't touched.
    let exec = StubExecutor::new().fail_account_blanket(78, "");
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
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
fn create_sysadminctl_failure_rolls_back_dseditgroup() {
    // The partial-failure case Phase 3 was designed for: CreateShareGroup
    // succeeded, but CreateTenantUser failed. Without rollback the host
    // would carry an orphan `<name>-tenant-share` group with no
    // corresponding user. The writer must invoke a DeleteShareGroup op
    // to converge back to the pre-create state, then surface the
    // *original* user-creation failure as the error (the rollback
    // succeeded so it's not separately reportable). Three account ops
    // in total.
    let exec = StubExecutor::new().fail_account_op(
        AccountOp::CreateTenantUser {
            name: "dev".into(),
            uid: 600,
            gid: 600,
        },
        AccountError::NonZero {
            code: 78,
            stderr: "sysadminctl: -addUser failed: existing record\n".into(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to create 'dev': process exited with code 78: \
         sysadminctl: -addUser failed: existing record\n"
    );
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::CreateShareGroup {
                name: "dev".into(),
                gid: 600
            },
            AccountOp::CreateTenantUser {
                name: "dev".into(),
                uid: 600,
                gid: 600
            },
            AccountOp::DeleteShareGroup { name: "dev".into() },
        ],
    );
}

#[test]
fn create_real_mode_verbose_shows_rollback_echo() {
    // Verbose counterpart: the pre-exec plan still shows 3 lines including
    // the `# on rollback` annotation (same plan as the success case — the
    // plan is the algorithm, not the trace). The `$` echo block grows to
    // 3 lines because the rollback actually fires. No post-exec
    // confirmation — the create failed. Stderr carries the original
    // sysadminctl error; the rollback's success is signaled implicitly
    // by the absence of a rollback-failed line.
    let exec = StubExecutor::new().fail_account_op(
        AccountOp::CreateTenantUser {
            name: "dev".into(),
            uid: 600,
            gid: 600,
        },
        AccountError::NonZero {
            code: 78,
            stderr: "sysadminctl: -addUser failed: existing record\n".into(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubReader::default(), &exec, &["create", "dev", "-v"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    // Plan still has 4 lines (the algorithm — profile-write is the
    // success-path 4th step), but the echo block omits the profile-write
    // because sysadminctl failed before profile-write would have been
    // attempted. The asymmetry between plan (line 4 present) and echo
    // (no profile echo) is the operator's signal that profile-write
    // never happened.
    let want_stdout = "Creating tenant 'dev'.\n  \
                       sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n  \
                       sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n  \
                       sudo dseditgroup -o delete -n . dev-tenant-share  # on rollback\n  \
                       tee ~/.config/tenant/profiles/dev.toml < default.toml\n  \
                       sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                       sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                       sudo tee /etc/pf.conf < updated.conf\n  \
                       sudo pfctl -f /etc/pf.conf\n  \
                       sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf  # on reload failure\n  \
                       sudo rm -f /etc/pf.anchors/tenant-dev  # on reload failure\n  \
                       sudo pfctl -f /etc/pf.conf  # on reload failure\n  \
                       sudo pfctl -a tenant-dev -F all  # on reload failure\n  \
                       sudo pfctl -e\n\
                       $ sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n\
                       $ sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n\
                       $ sudo dseditgroup -o delete -n . dev-tenant-share\n";
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to create 'dev': process exited with code 78: \
         sysadminctl: -addUser failed: existing record\n"
    );
}

#[test]
fn create_sysadminctl_failure_with_rollback_failure_surfaces_both() {
    // Worst-case partial failure: dseditgroup-create succeeded (so the
    // group exists), sysadminctl-addUser failed (so no user), and the
    // rollback dseditgroup-delete also failed (so the group is now an
    // orphan with no corresponding user). The operator gets two stderr
    // lines: the original failure (matches the single-failure shape so
    // log-grep regexes don't break), plus a second line naming the
    // rollback failure and pointing the operator at the recovery path.
    // The trailing `— host now has an orphan group; next 'tenant destroy
    // dev' will converge` is the load-bearing piece: the operator
    // shouldn't have to read the source to find out how to clean up.
    let exec = StubExecutor::new()
        .fail_account_op(
            AccountOp::CreateTenantUser {
                name: "dev".into(),
                uid: 600,
                gid: 600,
            },
            AccountError::NonZero {
                code: 78,
                stderr: "sysadminctl: -addUser failed: existing record\n".into(),
            },
        )
        .fail_account_op(
            AccountOp::DeleteShareGroup { name: "dev".into() },
            AccountError::NonZero {
                code: 1,
                stderr: "dseditgroup: not authorized\n".into(),
            },
        );
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    let want_stderr = "tenant: failed to create 'dev': process exited with code 78: \
                       sysadminctl: -addUser failed: existing record\n\
                       tenant: rollback of group 'dev-tenant-share' also failed: process exited with code 1: \
                       dseditgroup: not authorized \
                       \u{2014} host now has an orphan group; next 'tenant destroy dev' will converge\n";
    assert_eq!(stderr, want_stderr);
    assert_eq!(exec.account_ops().len(), 3);
}

#[test]
fn create_real_mode_invokes_firewall_ops_in_locked_order() {
    // Locked PF flow: BackupConfig → InstallAnchor → UpdateConfig →
    // Reload → Enable. Pins the order of `firewall_ops()` recorded by
    // the stub on a clean-host (empty pf.conf) success path.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let ops = exec.firewall_ops();
    let names: Vec<&'static str> = ops
        .iter()
        .map(|op| match op {
            tenant::executor::FirewallOp::BackupConfig => "BackupConfig",
            tenant::executor::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::executor::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::executor::FirewallOp::Reload => "Reload",
            tenant::executor::FirewallOp::Enable => "Enable",
            tenant::executor::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::executor::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::executor::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
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
    // Profile read → parse → render_anchor: the InstallAnchor body
    // should contain the rendered anchor with the runtime allowlist.
    // Cycle 2 writes the default profile (empty runtime hosts) before
    // reading, so the body's table is the empty `{ }` form. Pins the
    // read→parse→render data flow end-to-end.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let body = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::executor::FirewallOp::InstallAnchor { body, .. } => Some(body),
            _ => None,
        })
        .expect("InstallAnchor op must have been issued");
    assert!(
        body.contains("table <allowed> persist { }"),
        "anchor body must include empty allowlist table; got:\n{body}"
    );
    assert!(
        body.contains("pass out quick on lo0 user dev"),
        "anchor body must include loopback pass; got:\n{body}"
    );
}

#[test]
fn create_real_mode_install_anchor_body_includes_hosts_when_profile_populated() {
    // Closes the automated end-to-end gap on the allow path: the
    // sibling test above pins the data flow with the empty default;
    // this test simulates "the scaffolded profile had runtime hosts"
    // via `with_create_profile_content` and pins that the same data
    // flow (read_profile → parse → render_anchor) carries the hosts
    // all the way to `InstallAnchor.body`. The cycle-2 manual smoke
    // (`.features/cycle2-allow-smoke.sh`) verifies the same flow
    // against real pfctl + egress traffic; this is the unit-level
    // counterpart that catches regressions without needing root.
    let populated = "schema_version = 1\n\
                     \n\
                     [allowlist.runtime]\n\
                     hosts = [\"example.com\", \"api.anthropic.com\"]\n\
                     \n\
                     [allowlist.install]\n\
                     hosts = []\n";
    let exec = StubExecutor::new().with_create_profile_content("dev", populated);
    let (code, _stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let body = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::executor::FirewallOp::InstallAnchor { body, .. } => Some(body),
            _ => None,
        })
        .expect("InstallAnchor op must have been issued");
    // Backslash-continued table with both hosts in input order.
    assert!(
        body.contains(
            "table <allowed> persist { \\\n  \
             example.com \\\n  \
             api.anthropic.com \\\n}\n"
        ),
        "anchor body must include populated backslash-continued table \
         with hosts in profile order; got:\n{body}"
    );
    // Empty-table form must NOT appear (cross-check that the populated
    // path replaced the empty path, not appended).
    assert!(
        !body.contains("table <allowed> persist { }"),
        "anchor body must NOT include the empty-table form when hosts present; got:\n{body}"
    );
    // Sanity: the rules + scoping are unchanged.
    assert!(
        body.contains("pass out quick on lo0 user dev"),
        "anchor body must still include loopback pass; got:\n{body}"
    );
    assert!(
        body.contains("block out quick proto { tcp udp } from any to any user dev"),
        "anchor body must still include catchall block; got:\n{body}"
    );
}

#[test]
fn create_real_mode_update_conf_content_reflects_existing_pf_conf() {
    // ensure_anchor_ref runs against the host's current pf.conf — if
    // the host already has unrelated anchors, those stay intact and
    // tenant's lines append. The stub's `with_pf_conf` simulates the
    // existing-host state.
    let initial = "# host's existing pf.conf\nset block-policy drop\n";
    let exec = StubExecutor::new().with_pf_conf(initial);
    let (code, _stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let updated = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::executor::FirewallOp::UpdateConfig { content } => Some(content),
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
    // Locked recovery posture: a firewall step failing after the
    // account+profile ops have succeeded leaves the host with user +
    // group + profile in place. Recovery is `tenant destroy <name>`
    // — the Destroyable arm cleans up all of them. Operator sees a
    // create_firewall_failed message at EX_IOERR.
    let exec = StubExecutor::new().fail_firewall_op(
        tenant::executor::FirewallOp::InstallAnchor {
            name: "dev".into(),
            body: tenant::firewall::render_anchor("dev", &[]),
        },
        FirewallError::Fs {
            path: "/etc/pf.anchors/tenant-dev".to_string(),
            message: "permission denied".to_string(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    assert!(stdout.is_empty());
    assert_eq!(
        stderr,
        "tenant: failed to install firewall for 'dev': \
         filesystem error at /etc/pf.anchors/tenant-dev: permission denied\n"
    );
    // User + group + profile remain on the host.
    assert_eq!(exec.account_ops().len(), 2, "user+group ops both ran");
    assert!(
        exec.has_profile("dev"),
        "profile should remain present after firewall failure"
    );
}

#[test]
fn create_reload_failure_triggers_restore_remove_anchor_reload_recovery_sequence() {
    // When Reload fails the writer must run the locked 4-step recovery:
    // RestoreConfigFromBackup → RemoveAnchor → Reload → FlushAnchor
    // (best-effort post-restore). FlushAnchor clears any in-kernel
    // anchor state from the failed initial Reload. Total firewall_ops:
    // BackupConfig, InstallAnchor, UpdateConfig, Reload (the failure),
    // RestoreConfigFromBackup, RemoveAnchor, Reload (recovery),
    // FlushAnchor (recovery). Eight ops; the original reload failure
    // surfaces as the CreateError after recovery runs.
    let exec = StubExecutor::new().fail_firewall_op(
        tenant::executor::FirewallOp::Reload,
        FirewallError::NonZero {
            code: 1,
            stderr: "syntax error".to_string(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    assert!(stdout.is_empty());
    assert!(
        stderr.starts_with("tenant: failed to install firewall for 'dev':"),
        "expected install-firewall-failed framing; got: {stderr:?}"
    );
    let op_names: Vec<&'static str> = exec
        .firewall_ops()
        .iter()
        .map(|op| match op {
            tenant::executor::FirewallOp::BackupConfig => "BackupConfig",
            tenant::executor::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::executor::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::executor::FirewallOp::Reload => "Reload",
            tenant::executor::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::executor::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::executor::FirewallOp::Enable => "Enable",
            tenant::executor::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
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
    // Recovery-of-recovery: if RestoreConfigFromBackup itself fails,
    // the writer surfaces FirewallError::RestoreFailed which renders
    // with the em-dash-suffixed manual-recovery hint naming the
    // backup path. The host is left in a half-edited state; only the
    // operator (with shell access) can resolve.
    let exec = StubExecutor::new()
        .fail_firewall_op(
            tenant::executor::FirewallOp::Reload,
            FirewallError::NonZero {
                code: 1,
                stderr: "syntax error".to_string(),
            },
        )
        .fail_firewall_op(
            tenant::executor::FirewallOp::RestoreConfigFromBackup,
            FirewallError::NonZero {
                code: 1,
                stderr: "cp: permission denied".to_string(),
            },
        );
    let (code, _stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
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
    // Enable is the last firewall step. Failure here means rules
    // loaded but enforcement is off — surface as create_firewall_failed
    // at EX_IOERR. Recovery posture per locked policy: user + group +
    // profile + anchor remain on host; `tenant destroy` converges.
    let exec = StubExecutor::new().fail_firewall_op(
        tenant::executor::FirewallOp::Enable,
        FirewallError::NonZero {
            code: 1,
            stderr: "pfctl: operation not permitted".to_string(),
        },
    );
    let (code, _stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR");
    assert!(
        stderr.starts_with("tenant: failed to install firewall for 'dev':"),
        "got: {stderr:?}"
    );
    // All preceding firewall steps ran; Enable was the failure.
    assert_eq!(exec.firewall_ops().len(), 5, "5 firewall ops up to Enable");
}

#[test]
fn create_dry_run_bypasses_firewall_executor() {
    // Dry-run swaps in DryRunExecutor; the wired StubExecutor's
    // firewall_ops list stays empty. Mirrors the cycle-1
    // `create_dry_run_does_not_write_profile` discipline for firewall.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        StubReader::default(),
        &exec,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Would create tenant 'dev'.\n");
    assert!(
        exec.firewall_ops().is_empty(),
        "firewall executor should not be invoked in dry-run; got: {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn create_real_mode_dseditgroup_failure_surfaces_executor_stderr() {
    // Companion to the above — when dseditgroup-create has captured stderr,
    // it flows through ExecError::Display unchanged. Pins the error-shape
    // contract end-to-end.
    let exec = StubExecutor::new().fail_account_blanket(
        78,
        "dseditgroup: cannot create group dev-tenant-share: not authorized\n",
    );
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to create group 'dev-tenant-share' for 'dev': process exited with code 78: \
         dseditgroup: cannot create group dev-tenant-share: not authorized\n"
    );
}

#[test]
fn create_success_path_does_not_invoke_flush_anchor() {
    // Negative pin: create's success path INSTALLS the anchor; there's
    // nothing to flush. FlushAnchor only runs on the destroy paths and
    // on create's reload-failure recovery path (covered by a separate
    // test). Without this guard, an accidental wiring of FlushAnchor
    // into the success path would silently wipe the rules we just
    // installed.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !exec
            .firewall_ops()
            .iter()
            .any(|op| matches!(op, tenant::executor::FirewallOp::FlushAnchor { .. })),
        "FlushAnchor must NOT appear in create's success-path firewall_ops; got: {:?}",
        exec.firewall_ops()
    );
}
