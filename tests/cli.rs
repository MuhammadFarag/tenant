#[cfg(target_os = "macos")]
use tenant::accounts::Reader;
use tenant::accounts::StubReader;
use tenant::executor::{ExecError, Executor, StubExecutor};
use tenant::profile::StubProfileStore;

/// Default executor for tests that should not reach the exec stage —
/// validation failures, conflicts, and dry-run paths. Panics on use, so
/// any accidental exec from a path that's meant to be no-op surfaces
/// loudly instead of being silently absorbed.
struct NeverExecutor;
impl Executor for NeverExecutor {
    fn run(&self, argv: &[String]) -> Result<(), ExecError> {
        panic!("executor unexpectedly invoked with argv: {argv:?}");
    }
    fn exec_into(&self, argv: &[String]) -> Result<i32, ExecError> {
        panic!("executor unexpectedly invoked (exec_into) with argv: {argv:?}");
    }
}

fn run_with(stub: StubReader, args: &[&str]) -> (u8, String, String) {
    let exec = NeverExecutor;
    let profiles = StubProfileStore::new();
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let code = tenant::run(&args, &stub, &exec, &profiles, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// Build a `Vec<String>` argv from `&[&str]` — the shape `StubExecutor`
/// records calls in. Used in assertions where reading three or four parallel
/// argv literals is easier than the inline `.iter().map(...).collect()`
/// chain.
fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

fn run_with_exec(stub: StubReader, exec: &StubExecutor, args: &[&str]) -> (u8, String, String) {
    let profiles = StubProfileStore::new();
    run_with_exec_and_profiles(stub, exec, &profiles, args)
}

/// Variant for tests that need to inject a pre-loaded or failure-configured
/// `StubProfileStore` AND/OR assert against its post-run state. The default
/// `run_with_exec` constructs a fresh empty store internally; this helper
/// hands the store back to the caller. Used by cycle-1 profile tests.
fn run_with_exec_and_profiles(
    stub: StubReader,
    exec: &StubExecutor,
    profiles: &StubProfileStore,
    args: &[&str],
) -> (u8, String, String) {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let code = tenant::run(&args, &stub, exec, profiles, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

#[test]
fn help_exits_zero() {
    let (code, _stdout, stderr) = run_with(StubReader::default(), &["--help"]);
    assert_eq!(code, 0, "--help exited with {code}; stderr={stderr:?}");
}

#[test]
fn create_dry_run_default_shows_intent() {
    let (code, stdout, stderr) = run_with(StubReader::default(), &["create", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would create tenant 'dev'.\n");
}

#[test]
fn dry_run_accepted_as_global_flag_before_subcommand() {
    let (code, stdout, stderr) = run_with(StubReader::default(), &["--dry-run", "create", "dev"]);
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
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n";
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
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n";
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
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n";
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
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n";
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
    // Cycle 1's smallest red→green for the profile feature: after a
    // successful real-mode create, the ProfileStore must contain a
    // profile keyed by the tenant name. Content-shape assertion lives
    // in the dedicated TOML test below; this test only pins presence.
    let exec = StubExecutor::new();
    let profiles = StubProfileStore::new();
    let (code, _stdout, stderr) =
        run_with_exec_and_profiles(StubReader::default(), &exec, &profiles, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        profiles.has_profile("dev"),
        "expected profile 'dev' to be present after create; snapshot={:?}",
        profiles.snapshot()
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
    let profiles = StubProfileStore::new();
    let (code, _stdout, stderr) =
        run_with_exec_and_profiles(StubReader::default(), &exec, &profiles, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let snapshot = profiles.snapshot();
    let content = snapshot
        .get("dev")
        .expect("profile 'dev' should be present");
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
    // Dry-run swap-in of `DryRunProfileStore` means the wired
    // `StubProfileStore` never receives a write call. Mirrors the
    // executor-side `dry_run_bypasses_injected_executor` test. Pins
    // the composition-root dry-run plumbing on the new ProfileStore
    // seam.
    let exec = StubExecutor::new();
    let profiles = StubProfileStore::new();
    let (code, stdout, stderr) = run_with_exec_and_profiles(
        StubReader::default(),
        &exec,
        &profiles,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Would create tenant 'dev'.\n");
    assert!(
        !profiles.has_profile("dev"),
        "profile should not be written in dry-run; snapshot={:?}",
        profiles.snapshot()
    );
}

#[test]
fn create_real_mode_standard_emits_only_post_exec_confirmation() {
    // Standard real mode is silent before exec; one confirmation line
    // after. No UID/GID — that's reserved for verbose mode. Phase 3
    // changed the exec count from 1 to 2 (dseditgroup-create first, then
    // sysadminctl-addUser): the group must exist before sysadminctl so
    // the new user's home directory chowns to `dev-tenant-share`, not
    // `staff`. The two-argv order is load-bearing for that reason; this
    // test pins it.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Created tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    let calls = exec.calls();
    assert_eq!(calls.len(), 2, "expected dseditgroup + sysadminctl");
    assert_eq!(
        calls[0],
        argv(&[
            "sudo",
            "dseditgroup",
            "-o",
            "create",
            "-n",
            ".",
            "-i",
            "600",
            "dev-tenant-share",
        ]),
    );
    assert_eq!(
        calls[1],
        argv(&[
            "sudo",
            "sysadminctl",
            "-addUser",
            "dev",
            "-fullName",
            "Tenant: dev",
            "-shell",
            "/bin/zsh",
            "-UID",
            "600",
            "-GID",
            "600",
        ]),
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
                tee ~/.config/tenant/profiles/dev.toml < default.toml\n\
                $ sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n\
                $ sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n\
                $ tee ~/.config/tenant/profiles/dev.toml < default.toml\n\
                Created tenant 'dev' (UID 600, GID 600).\n";
    assert_eq!(stdout, want);
}

#[test]
fn create_profile_write_failure_surfaces_with_user_and_group_present() {
    // Per the design lock: dseditgroup-create + sysadminctl-addUser have
    // both succeeded by the time profile-write fires, so a profile-write
    // failure does NOT roll back the user or group. Operator sees an
    // EX_IOERR with a new `create_profile_failed` message that names the
    // profile path (so they don't have to grep source). Their recovery
    // is `tenant destroy <name>` — destroy's Destroyable arm cleans up
    // the user+group, and the missing profile case is a successful noop
    // for the profile-rm step.
    let exec = StubExecutor::new();
    let profiles = StubProfileStore::new().with_write_failure("disk full");
    let (code, stdout, stderr) =
        run_with_exec_and_profiles(StubReader::default(), &exec, &profiles, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to write profile '~/.config/tenant/profiles/dev.toml' \
         for 'dev': disk full\n"
    );
    // Two exec calls (dseditgroup + sysadminctl) — no rollback, since
    // the locked policy is "leave user+group present on profile failure".
    assert_eq!(
        exec.calls().len(),
        2,
        "expected dseditgroup + sysadminctl; no rollback"
    );
    // Profile is absent from the store (the write failed) — pins the
    // fact that the failure is a real failure, not a silent success.
    assert!(
        !profiles.has_profile("dev"),
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
        exec.calls().is_empty(),
        "executor should not be invoked in dry-run mode; got calls: {:?}",
        exec.calls()
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
    let exec = StubExecutor::failing(78);
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to create group 'dev-tenant-share' for 'dev': process exited with code 78\n"
    );
    assert_eq!(exec.calls().len(), 1, "should abort after dseditgroup");
}

#[test]
fn create_sysadminctl_failure_rolls_back_dseditgroup() {
    // The partial-failure case Phase 3 was designed for: dseditgroup-create
    // succeeded, but sysadminctl-addUser failed. Without rollback the host
    // would carry an orphan `<name>-tenant-share` group with no
    // corresponding user. The writer must invoke
    // `sudo dseditgroup -o delete -n . <name>-tenant-share` to converge
    // back to the pre-create state, then surface the *original*
    // sysadminctl failure as the error (the rollback succeeded so it's
    // not separately reportable). Three exec calls in total.
    let exec = StubExecutor::new().with_response_to_stderr(
        &["sudo", "sysadminctl", "-addUser", "dev"],
        78,
        "sysadminctl: -addUser failed: existing record\n",
    );
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to create 'dev': process exited with code 78: \
         sysadminctl: -addUser failed: existing record\n"
    );
    let calls = exec.calls();
    assert_eq!(
        calls.len(),
        3,
        "expected dseditgroup-create + sysadminctl + dseditgroup-delete (rollback)"
    );
    assert_eq!(
        calls[0],
        argv(&[
            "sudo",
            "dseditgroup",
            "-o",
            "create",
            "-n",
            ".",
            "-i",
            "600",
            "dev-tenant-share",
        ]),
    );
    assert_eq!(
        calls[1][0..4],
        argv(&["sudo", "sysadminctl", "-addUser", "dev"])[..]
    );
    assert_eq!(
        calls[2],
        argv(&[
            "sudo",
            "dseditgroup",
            "-o",
            "delete",
            "-n",
            ".",
            "dev-tenant-share",
        ]),
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
    let exec = StubExecutor::new().with_response_to_stderr(
        &["sudo", "sysadminctl", "-addUser", "dev"],
        78,
        "sysadminctl: -addUser failed: existing record\n",
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
                       tee ~/.config/tenant/profiles/dev.toml < default.toml\n\
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
        .with_response_to_stderr(
            &["sudo", "sysadminctl", "-addUser", "dev"],
            78,
            "sysadminctl: -addUser failed: existing record\n",
        )
        .with_response_to_stderr(
            &[
                "sudo",
                "dseditgroup",
                "-o",
                "delete",
                "-n",
                ".",
                "dev-tenant-share",
            ],
            1,
            "dseditgroup: not authorized\n",
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
    assert_eq!(exec.calls().len(), 3);
}

#[test]
fn create_real_mode_dseditgroup_failure_surfaces_executor_stderr() {
    // Companion to the above — when dseditgroup-create has captured stderr,
    // it flows through ExecError::Display unchanged. Pins the error-shape
    // contract end-to-end.
    let exec = StubExecutor::failing_with(
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

/// Stub representing a tenant that exists on the host with a tenant-range
/// UID (for tests that drive the destroy verb's actual-destroy path rather
/// than its noop / refusal paths). UID 600 is the canonical floor; any
/// floor-or-above UID would do.
fn stub_with_tenant(name: &str) -> StubReader {
    StubReader {
        users: vec![name.to_string()],
        uid_by_name: [(name.to_string(), 600)].into_iter().collect(),
        ..Default::default()
    }
}

#[test]
fn destroy_removes_profile_file_from_store() {
    // Destroy adds a 5th step: profile-rm. After a successful destroy
    // the profile must be gone from the store. The store is pre-loaded
    // with a profile so the test pins "present before, absent after"
    // — defending against a regression that wires destroy without the
    // profile step.
    let exec = StubExecutor::new();
    let profiles = StubProfileStore::new().with_profile("dev", "schema_version = 1\n");
    assert!(
        profiles.has_profile("dev"),
        "pre-condition: profile present"
    );
    let (code, stdout, stderr) = run_with_exec_and_profiles(
        stub_with_tenant("dev"),
        &exec,
        &profiles,
        &["destroy", "dev"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'dev'.\n");
    assert!(
        !profiles.has_profile("dev"),
        "profile should be removed after destroy"
    );
}

#[test]
fn destroy_succeeds_when_profile_already_absent() {
    // Idempotent rm: the operator may have manually removed the profile
    // (or a prior destroy failed mid-flight). Destroy must converge to
    // success regardless. Mirrors `XdgProfileStore::remove`'s
    // NotFound-as-Ok semantics — the StubProfileStore enforces the same
    // contract by silently dropping a missing-key remove.
    let exec = StubExecutor::new();
    let profiles = StubProfileStore::new(); // empty; no profile loaded
    let (code, stdout, stderr) = run_with_exec_and_profiles(
        stub_with_tenant("dev"),
        &exec,
        &profiles,
        &["destroy", "dev"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'dev'.\n");
}

#[test]
fn destroy_dry_run_default_shows_intent() {
    let (code, stdout, stderr) =
        run_with(stub_with_tenant("dev"), &["destroy", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would destroy tenant 'dev'.\n");
}

#[test]
fn destroy_dry_run_verbose_shows_mechanism() {
    // Dry-run verbose lists the full pessimistic plan. Phase 3 grows it
    // to 4 lines by appending `sudo dseditgroup -o delete -n .
    // <name>-tenant-share` — unlike the V1.8 sysadminctl-cascade that
    // caught implicit `<name>` groups, the renamed tenant-share group
    // doesn't inherit that cleanup, so the explicit dseditgroup-delete
    // is load-bearing. Shown unconditionally because the dry-run can't
    // know what the dscl-probe will return at runtime; the operator
    // sees the full algorithm.
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["destroy", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Would destroy tenant 'dev'.\n  \
                sudo sysadminctl -deleteUser dev\n  \
                dscl . -read /Users/dev\n  \
                sudo dscl . -delete /Users/dev\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share\n  \
                rm -f ~/.config/tenant/profiles/dev.toml\n";
    assert_eq!(stdout, want);
}

#[test]
fn destroy_real_mode_standard_emits_only_post_exec_confirmation() {
    // StubExecutor::new() returns Ok by default → the dscl-read probe sees
    // the DS record as still present → the conditional dscl-delete runs.
    // Phase 3 adds an unconditional fourth call (dseditgroup-delete on
    // the tenant-share group). Four exec calls in standard mode; stdout
    // is still the single confirmation line (mechanism is suppressed
    // without -v).
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    let calls = exec.calls();
    assert_eq!(
        calls.len(),
        4,
        "expected sysadminctl + dscl-read + dscl-delete + dseditgroup-delete"
    );
    assert_eq!(
        calls[0],
        argv(&["sudo", "sysadminctl", "-deleteUser", "dev"])
    );
    assert_eq!(calls[1], argv(&["dscl", ".", "-read", "/Users/dev"]));
    assert_eq!(
        calls[2],
        argv(&["sudo", "dscl", ".", "-delete", "/Users/dev"])
    );
    assert_eq!(
        calls[3],
        argv(&[
            "sudo",
            "dseditgroup",
            "-o",
            "delete",
            "-n",
            ".",
            "dev-tenant-share",
        ]),
    );
}

#[test]
fn destroy_real_mode_verbose_shows_pre_exec_mechanism_and_post_exec() {
    // Real-mode verbose has two sections: (a) the "Destroying" pre-exec
    // intent + the 4-line pessimistic plan (same shape as dry-run
    // verbose), then (b) per-exec echo lines prefixed with "$ " as each
    // command actually runs. Default StubExecutor → probe says residue
    // → all four commands echo (dseditgroup-delete is the load-bearing
    // 4th step Phase 3 adds). The trailing post-exec confirmation closes
    // the block.
    let exec = StubExecutor::new();
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Destroying tenant 'dev'.\n  \
                sudo sysadminctl -deleteUser dev\n  \
                dscl . -read /Users/dev\n  \
                sudo dscl . -delete /Users/dev\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share\n  \
                rm -f ~/.config/tenant/profiles/dev.toml\n\
                $ sudo sysadminctl -deleteUser dev\n\
                $ dscl . -read /Users/dev\n\
                $ sudo dscl . -delete /Users/dev\n\
                $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
                $ rm -f ~/.config/tenant/profiles/dev.toml\n\
                Destroyed tenant 'dev'.\n";
    assert_eq!(stdout, want);
}

#[test]
fn destroy_real_mode_skips_dscl_cleanup_when_probe_finds_clean() {
    // The dscl-read probe returns NonZero when the DS record is absent
    // (typically eDSRecordNotFound, code 56). The destroy writer must
    // treat probe-NonZero as "no cleanup needed" and skip the
    // sudo-dscl-delete — but the unconditional Phase-3 dseditgroup-delete
    // still runs after, because the tenant-share group is independent
    // of the user record. So this path has exactly three exec calls:
    // sysadminctl + dscl-read + dseditgroup-delete (no dscl-delete).
    // The plan-vs-echo asymmetry around dscl-delete remains the
    // operator's signal that the dscl path was clean.
    let exec = StubExecutor::new().with_response_to(&["dscl", ".", "-read", "/Users/dev"], 56);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'dev'.\n");
    let calls = exec.calls();
    assert_eq!(
        calls.len(),
        3,
        "expected sysadminctl + dscl-read + dseditgroup-delete (dscl-delete skipped)"
    );
    assert_eq!(
        calls[0],
        argv(&["sudo", "sysadminctl", "-deleteUser", "dev"])
    );
    assert_eq!(calls[1], argv(&["dscl", ".", "-read", "/Users/dev"]));
    assert_eq!(
        calls[2],
        argv(&[
            "sudo",
            "dseditgroup",
            "-o",
            "delete",
            "-n",
            ".",
            "dev-tenant-share",
        ]),
    );
}

#[test]
fn destroy_real_mode_dseditgroup_delete_failure_surfaces_as_destroy_failure() {
    // Phase 3's load-bearing 4th step: if dseditgroup-delete fails after
    // sysadminctl-deleteUser succeeded and the dscl-cleanup ran (or was
    // skipped as a noop), the host now carries an orphan tenant-share
    // group. The writer must surface this as EX_IOERR so the operator
    // knows to retry — and cycle 5's OrphanGroup eligibility arm
    // converges on retry. The error message reuses the existing
    // `destroy_failed` shape; the captured dseditgroup stderr inside
    // ExecError carries enough detail (the dseditgroup tool prints its
    // own argv-aware context) for the operator to diagnose.
    let exec = StubExecutor::new().with_response_to_stderr(
        &[
            "sudo",
            "dseditgroup",
            "-o",
            "delete",
            "-n",
            ".",
            "dev-tenant-share",
        ],
        78,
        "dseditgroup: cannot remove group dev-tenant-share: not authorized\n",
    );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78: \
         dseditgroup: cannot remove group dev-tenant-share: not authorized\n"
    );
    // All four steps attempted — the failure is on the dseditgroup-delete,
    // not before.
    assert_eq!(exec.calls().len(), 4);
}

#[test]
fn destroy_real_mode_dscl_cleanup_failure_surfaces_as_destroy_failure() {
    // The cleanup is best-effort but not optional: if sysadminctl claims
    // success and the probe says residue is still there, we MUST be able
    // to remove it — otherwise the operator's `tenant destroy` reports
    // success while the host still carries a stale DS record. Treat a
    // dscl-delete NonZero as a destroy failure (EX_IOERR), with the
    // captured stderr surfaced via ExecError::Display.
    let exec = StubExecutor::new().with_response_to_stderr(
        &["sudo", "dscl", ".", "-delete", "/Users/dev"],
        78,
        "dscl: cannot remove /Users/dev: not authorized\n",
    );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78: \
         dscl: cannot remove /Users/dev: not authorized\n"
    );
    // Sysadminctl + dscl-read + dscl-delete all attempted — the failure
    // is on the third call, not before.
    assert_eq!(exec.calls().len(), 3);
}

#[test]
fn destroy_real_mode_verbose_omits_cleanup_echo_when_probe_finds_clean() {
    // Verbose-mode counterpart: the upfront plan still lists all four
    // commands (the operator sees the algorithm), but the per-exec `$`
    // echo block skips the dscl-delete because the probe cleared the DS
    // state. The dseditgroup-delete echo still appears — that step is
    // unconditional. The asymmetry between plan and echo around
    // dscl-delete is the operator's signal that the dscl path was clean.
    let exec = StubExecutor::new().with_response_to(&["dscl", ".", "-read", "/Users/dev"], 56);
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Destroying tenant 'dev'.\n  \
                sudo sysadminctl -deleteUser dev\n  \
                dscl . -read /Users/dev\n  \
                sudo dscl . -delete /Users/dev\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share\n  \
                rm -f ~/.config/tenant/profiles/dev.toml\n\
                $ sudo sysadminctl -deleteUser dev\n\
                $ dscl . -read /Users/dev\n\
                $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
                $ rm -f ~/.config/tenant/profiles/dev.toml\n\
                Destroyed tenant 'dev'.\n";
    assert_eq!(stdout, want);
}

#[test]
fn destroy_rejects_empty_name() {
    let (code, stdout, stderr) = run_with(StubReader::default(), &["destroy", "", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn destroy_rejects_non_letter_start() {
    for (name, offender) in [("1dev", '1'), ("_dev", '_'), ("Dev", 'D')] {
        let (code, stdout, stderr) =
            run_with(StubReader::default(), &["destroy", name, "--dry-run"]);
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
        let (code, stdout, stderr) =
            run_with(StubReader::default(), &["destroy", name, "--dry-run"]);
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
    // Empty StubReader — no users on the host. Destroy should be
    // convergent-toward-absence: report the noop and exit 0 without
    // touching the executor (NeverExecutor would panic if reached).
    let (code, stdout, stderr) = run_with(StubReader::default(), &["destroy", "dev"]);
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
    // never reach the executor.
    let stub = StubReader {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), 0)].into_iter().collect(),
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
    let stub = StubReader {
        users: vec!["edge".to_string()],
        uid_by_name: [("edge".to_string(), 599)].into_iter().collect(),
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
    let exec = StubExecutor::new();
    let stub = StubReader {
        users: vec!["edge".to_string()],
        uid_by_name: [("edge".to_string(), 600)].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "edge"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'edge'.\n");
    // Four calls: sysadminctl-deleteUser + dscl-read probe + (probe
    // defaults to Ok with a vanilla StubExecutor) sudo-dscl-delete cleanup
    // + Phase-3's unconditional dseditgroup-delete.
    assert_eq!(
        exec.calls().len(),
        4,
        "sysadminctl + dscl-read + dscl-delete + dseditgroup-delete"
    );
}

#[test]
fn destroy_refuses_when_uid_unknown_but_user_present() {
    // The canonical real-world case is `nobody` on macOS (UID -2 filtered
    // by `parse_uid_line` out of `uid_by_name`), but `nobody` is now
    // lexically reserved — the blocklist trips first. Synthetic
    // `phantom` reproduces the same Reader state (present in `users`,
    // absent from `uid_by_name`) without crossing the reserved-name
    // rail, so the test still pins the `Eligibility::SystemAccount`
    // arm. `has_user` is true, `uid_for` returns None → refuse with
    // EX_USAGE, NOT a noop.
    let stub = StubReader {
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
    let stub = StubReader {
        users: vec!["edge".to_string()],
        uid_by_name: [("edge".to_string(), 599)].into_iter().collect(),
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
    let (code, stdout, stderr) = run_with(StubReader::default(), &["destroy", "ghost", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "tenant 'ghost' does not exist; nothing to do.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn destroy_noop_emits_in_dry_run_too() {
    // Same noop framing in dry-run mode — the message is tense-neutral
    // because we'd "do nothing" either way.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["destroy", "dev", "--dry-run"]);
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
    // first failure (no Reader call needed) and surfaces the more
    // operator-relevant reason ("you can't name a tenant 'wheel'" vs
    // "UID 0 is below tenant floor 600").
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) =
            run_with(StubReader::default(), &["destroy", name, "--dry-run"]);
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
    let (code, stdout, stderr) = run_with(StubReader::default(), &["destroy", &name, "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        format!("tenant: name '{name}' is too long (32 characters; maximum is 31)\n"),
    );
}

#[test]
fn destroy_real_mode_propagates_exec_failure() {
    let exec = StubExecutor::failing(78);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78\n"
    );
    assert_eq!(exec.calls().len(), 1);
}

#[test]
fn destroy_real_mode_failure_surfaces_executor_stderr() {
    let exec = StubExecutor::failing_with(78, "sysadminctl: -deleteUser failed: not authorized\n");
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78: \
         sysadminctl: -deleteUser failed: not authorized\n"
    );
}

#[test]
fn destroy_dry_run_bypasses_injected_executor() {
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["destroy", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Would destroy tenant 'dev'.\n");
    assert!(
        exec.calls().is_empty(),
        "executor should not be invoked in dry-run mode; got calls: {:?}",
        exec.calls()
    );
}

#[test]
fn destroy_converges_orphan_group_when_user_absent_but_tenant_share_group_present() {
    // The cycle-5 convergence path: the user was destroyed earlier (or
    // a previous destroy failed at the dseditgroup-delete step), leaving
    // a `<name>-tenant-share` group with no corresponding user. The
    // destroy verb classifies this as `OrphanGroup` and converges by
    // running just the dseditgroup-delete. Exactly ONE exec call — no
    // sysadminctl, no dscl — and exit 0. Standard-mode stdout names the
    // tenant (not the group) so it stays parallel with the rest of the
    // destroy UX from the operator's perspective.
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed orphan group for tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    let calls = exec.calls();
    assert_eq!(calls.len(), 1, "expected dseditgroup-delete only");
    assert_eq!(
        calls[0],
        argv(&[
            "sudo",
            "dseditgroup",
            "-o",
            "delete",
            "-n",
            ".",
            "dev-tenant-share",
        ]),
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
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubExecutor::new();
    let profiles = StubProfileStore::new().with_profile("dev", "schema_version = 1\n");
    assert!(
        profiles.has_profile("dev"),
        "pre-condition: profile present"
    );
    let (code, stdout, stderr) =
        run_with_exec_and_profiles(stub, &exec, &profiles, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed orphan group for tenant 'dev'.\n");
    assert!(
        !profiles.has_profile("dev"),
        "profile should be removed by orphan-group convergence"
    );
}

#[test]
fn destroy_dry_run_for_orphan_group() {
    // Dry-run twin: same convergence framing, "Would" tense. No exec
    // calls (dry-run bypasses the executor — NeverExecutor would panic).
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "dev", "--dry-run"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Would destroy orphan group for tenant 'dev'.\n");
}

#[test]
fn destroy_dry_run_verbose_for_orphan_group() {
    // Verbose dry-run names the group explicitly (the suffixed group is
    // the literal resource being touched) AND shows the mechanism.
    // Standard-mode framing is tenant-named; verbose adds the group
    // name for grep-friendliness, matching the mechanism-exposure
    // convention used elsewhere in the codebase.
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, _stderr) = run_with(stub, &["destroy", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let want = "Would destroy orphan group 'dev-tenant-share' for tenant 'dev'.\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share\n  \
                rm -f ~/.config/tenant/profiles/dev.toml\n";
    assert_eq!(stdout, want);
}

#[test]
fn destroy_real_mode_verbose_for_orphan_group() {
    // Real-mode verbose: same three-section shape as the regular destroy
    // (pre-exec intent + plan, `$` echo for each command, post-exec
    // confirmation), just with one argv in each block instead of four.
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubExecutor::new();
    let (code, stdout, _stderr) = run_with_exec(stub, &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Destroying orphan group 'dev-tenant-share' for tenant 'dev'.\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share\n  \
                rm -f ~/.config/tenant/profiles/dev.toml\n\
                $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
                $ rm -f ~/.config/tenant/profiles/dev.toml\n\
                Destroyed orphan group 'dev-tenant-share' for tenant 'dev'.\n";
    assert_eq!(stdout, want);
}

#[test]
fn destroy_noop_when_neither_user_nor_tenant_share_group_present() {
    // Specificity pin: a bare-name group (left over from pre-Phase-3
    // creation, or unrelated host state) does NOT classify as
    // OrphanGroup — only the suffixed `<name>-tenant-share` does. Empty
    // users + bare `dev` group → `NotPresent` noop, exit 0, no exec.
    // A regression that loosened the OrphanGroup check to bare-name
    // matching (e.g. dropping the `tenant_share_group_name` call) would
    // trip this test.
    let stub = StubReader {
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
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubExecutor::failing_with(78, "dseditgroup: not authorized\n");
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78: \
         dseditgroup: not authorized\n"
    );
    assert_eq!(exec.calls().len(), 1);
}

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
    // Dry-run verbose adds the planned argv as a `  `-indented detail
    // line. Single-argv plan because shell only issues `sudo -iu <name>`;
    // no fan-out like create's 3 lines.
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["shell", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Would shell into 'dev'.\n  sudo -iu dev\n";
    assert_eq!(stdout, want);
}

#[test]
fn shell_real_mode_standard_emits_intent_and_invokes_exec_into() {
    // Standard real mode: one pre-exec intent line, then exec_into. Unlike
    // create/destroy, no post-exec confirmation — the operator IS the
    // shell after exec_into returns. Single exec call recorded.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Shelling into 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    let calls = exec.calls();
    assert_eq!(calls.len(), 1, "expected one exec_into call");
    assert_eq!(calls[0], argv(&["sudo", "-iu", "dev"]));
}

#[test]
fn shell_real_mode_verbose_shows_plan_and_echo() {
    // Real+verbose: intent + plan + `$` echo. No post-exec line.
    let exec = StubExecutor::new();
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Shelling into 'dev'.\n  \
                sudo -iu dev\n\
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
    // its own. Stub the executor's exec_into to return 5; tenant exits 5.
    // The "Shelling into" intent line still emits — pre-exec emission
    // happens before exec_into is consulted.
    let exec = StubExecutor::new().with_exec_into_code(5);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["shell", "dev"]);
    assert_eq!(code, 5, "stderr={stderr:?}");
    assert_eq!(stdout, "Shelling into 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(exec.calls().len(), 1);
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
        exec.calls().is_empty(),
        "executor should not be invoked in dry-run; got: {:?}",
        exec.calls()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_reader_observes_host_state() {
    // Smoke test that the real `MacosReader` populates correctly from
    // dscl. Was originally an end-to-end `tenant create root --dry-run`
    // assertion, but Phase 2's reserved-name blocklist now refuses
    // `root` at the lexical layer before dispatch reaches the Reader —
    // which means the old test no longer exercises dscl integration.
    // Direct Reader assertions instead: `root` (UID 0) and `wheel`
    // (group) are universally present on macOS, so this is host-stable
    // and proves the dscl → MacosReader translation works end-to-end
    // for both the user listing and the group listing. The dispatch
    // path is already extensively covered via StubReader.
    let reader = tenant::accounts::MacosReader::new().expect("dscl should be available on macOS");
    assert!(
        reader.has_user("root"),
        "MacosReader should see 'root' user"
    );
    assert!(
        reader.has_group("wheel"),
        "MacosReader should see 'wheel' group"
    );
    assert_eq!(
        reader.uid_for("root"),
        Some(0),
        "root's UID should be 0 in the in-memory map"
    );
}
