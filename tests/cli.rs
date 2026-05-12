#[cfg(target_os = "macos")]
use tenant::accounts::Reader;
use tenant::accounts::StubReader;
use tenant::executor::{
    AccountError, AccountOp, Executor, FirewallError, FirewallOp, ProfileOp, StubExecutor,
};

/// Default executor for tests that should not reach the exec stage —
/// validation failures, conflicts, and dry-run paths. Panics on any
/// substrate call, so any accidental invocation from a path that's
/// meant to be no-op surfaces loudly instead of being silently absorbed.
struct NeverExecutor;
impl Executor for NeverExecutor {
    fn describe_account(&self, op: &AccountOp) -> String {
        panic!("executor unexpectedly invoked (describe_account) with op: {op:?}");
    }
    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        panic!("executor unexpectedly invoked (execute_account) with op: {op:?}");
    }
    fn login(&self, name: &str) -> Result<i32, AccountError> {
        panic!("executor unexpectedly invoked (login) with name: {name:?}");
    }
    fn describe_profile(&self, op: &ProfileOp) -> String {
        panic!("executor unexpectedly invoked (describe_profile) with op: {op:?}");
    }
    fn execute_profile(&self, op: &ProfileOp) -> Result<(), tenant::profile::ProfileError> {
        panic!("executor unexpectedly invoked (execute_profile) with op: {op:?}");
    }
    fn read_profile(&self, name: &str) -> Result<String, tenant::profile::ProfileError> {
        panic!("executor unexpectedly invoked (read_profile) with name: {name:?}");
    }
    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        panic!("executor unexpectedly invoked (read_pf_conf)");
    }
    fn describe_firewall(&self, op: &FirewallOp) -> String {
        panic!("executor unexpectedly invoked (describe_firewall) with op: {op:?}");
    }
    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError> {
        panic!("executor unexpectedly invoked (execute_firewall) with op: {op:?}");
    }
}

fn run_with(stub: StubReader, args: &[&str]) -> (u8, String, String) {
    let exec = NeverExecutor;
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let code = tenant::run(&args, &stub, &exec, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

fn run_with_exec(stub: StubReader, exec: &StubExecutor, args: &[&str]) -> (u8, String, String) {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let code = tenant::run(&args, &stub, exec, &mut stdout, &mut stderr);
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
    let exec = StubExecutor::new().with_existing_profile("dev", "schema_version = 1\n");
    assert!(exec.has_profile("dev"), "pre-condition: profile present");
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'dev'.\n");
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
    // NotFound-as-Ok semantics — the `StubExecutor`'s profile-state
    // simulation enforces the same contract by silently dropping a
    // missing-key remove.
    let exec = StubExecutor::new(); // empty; no profile loaded
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
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
                rm -f ~/.config/tenant/profiles/dev.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo pfctl -a tenant-dev -F all\n";
    assert_eq!(stdout, want);
}

#[test]
fn destroy_real_mode_standard_emits_only_post_exec_confirmation() {
    // StubExecutor::new() returns Ok by default → the LookupUserRecord
    // probe sees the DS record as still present → the conditional
    // DeleteUserRecord cleanup runs. The DeleteShareGroup is
    // unconditional. Four account ops in standard mode; stdout is still
    // the single confirmation line (mechanism is suppressed without -v).
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::DeleteTenantUser { name: "dev".into() },
            AccountOp::LookupUserRecord { name: "dev".into() },
            AccountOp::DeleteUserRecord { name: "dev".into() },
            AccountOp::DeleteShareGroup { name: "dev".into() },
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
                rm -f ~/.config/tenant/profiles/dev.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo pfctl -a tenant-dev -F all\n\
                $ sudo sysadminctl -deleteUser dev\n\
                $ dscl . -read /Users/dev\n\
                $ sudo dscl . -delete /Users/dev\n\
                $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
                $ rm -f ~/.config/tenant/profiles/dev.toml\n\
                $ sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n\
                $ sudo rm -f /etc/pf.anchors/tenant-dev\n\
                $ sudo tee /etc/pf.conf < updated.conf\n\
                $ sudo pfctl -f /etc/pf.conf\n\
                $ sudo pfctl -a tenant-dev -F all\n\
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
    let exec = StubExecutor::new().fail_account_op(
        AccountOp::LookupUserRecord { name: "dev".into() },
        AccountError::NonZero {
            code: 56,
            stderr: String::new(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'dev'.\n");
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::DeleteTenantUser { name: "dev".into() },
            AccountOp::LookupUserRecord { name: "dev".into() },
            AccountOp::DeleteShareGroup { name: "dev".into() },
        ],
        "expected DeleteTenantUser + LookupUserRecord + DeleteShareGroup (cleanup skipped)"
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
    let exec = StubExecutor::new().fail_account_op(
        AccountOp::DeleteShareGroup { name: "dev".into() },
        AccountError::NonZero {
            code: 78,
            stderr: "dseditgroup: cannot remove group dev-tenant-share: not authorized\n".into(),
        },
    );
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78: \
         dseditgroup: cannot remove group dev-tenant-share: not authorized\n"
    );
    // All four account ops attempted — the failure is on
    // DeleteShareGroup, not before.
    assert_eq!(exec.account_ops().len(), 4);
}

#[test]
fn destroy_real_mode_dscl_cleanup_failure_surfaces_as_destroy_failure() {
    // The cleanup is best-effort but not optional: if sysadminctl claims
    // success and the probe says residue is still there, we MUST be able
    // to remove it — otherwise the operator's `tenant destroy` reports
    // success while the host still carries a stale DS record. Treat a
    // dscl-delete NonZero as a destroy failure (EX_IOERR), with the
    // captured stderr surfaced via ExecError::Display.
    let exec = StubExecutor::new().fail_account_op(
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
    let exec = StubExecutor::new().fail_account_op(
        AccountOp::LookupUserRecord { name: "dev".into() },
        AccountError::NonZero {
            code: 56,
            stderr: String::new(),
        },
    );
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Destroying tenant 'dev'.\n  \
                sudo sysadminctl -deleteUser dev\n  \
                dscl . -read /Users/dev\n  \
                sudo dscl . -delete /Users/dev\n  \
                sudo dseditgroup -o delete -n . dev-tenant-share\n  \
                rm -f ~/.config/tenant/profiles/dev.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo pfctl -a tenant-dev -F all\n\
                $ sudo sysadminctl -deleteUser dev\n\
                $ dscl . -read /Users/dev\n\
                $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
                $ rm -f ~/.config/tenant/profiles/dev.toml\n\
                $ sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n\
                $ sudo rm -f /etc/pf.anchors/tenant-dev\n\
                $ sudo tee /etc/pf.conf < updated.conf\n\
                $ sudo pfctl -f /etc/pf.conf\n\
                $ sudo pfctl -a tenant-dev -F all\n\
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
    // Four account ops: DeleteTenantUser + LookupUserRecord (probe
    // defaults to Ok) + DeleteUserRecord cleanup + DeleteShareGroup.
    assert_eq!(
        exec.account_ops().len(),
        4,
        "DeleteTenantUser + LookupUserRecord + DeleteUserRecord + DeleteShareGroup"
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
    let exec = StubExecutor::new().fail_account_blanket(78, "");
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to destroy 'dev': process exited with code 78\n"
    );
    assert_eq!(exec.account_ops().len(), 1);
}

#[test]
fn destroy_real_mode_failure_surfaces_executor_stderr() {
    let exec = StubExecutor::new()
        .fail_account_blanket(78, "sysadminctl: -deleteUser failed: not authorized\n");
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
        exec.account_ops().is_empty() && exec.profile_ops().is_empty(),
        "executor should not be invoked in dry-run mode; account_ops={:?}, profile_ops={:?}",
        exec.account_ops(),
        exec.profile_ops()
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
    assert_eq!(
        exec.account_ops(),
        vec![AccountOp::DeleteShareGroup { name: "dev".into() }],
        "expected DeleteShareGroup only"
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
    let exec = StubExecutor::new().with_existing_profile("dev", "schema_version = 1\n");
    assert!(exec.has_profile("dev"), "pre-condition: profile present");
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed orphan group for tenant 'dev'.\n");
    assert!(
        !exec.has_profile("dev"),
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
                rm -f ~/.config/tenant/profiles/dev.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo pfctl -a tenant-dev -F all\n";
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
                rm -f ~/.config/tenant/profiles/dev.toml\n  \
                sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n  \
                sudo rm -f /etc/pf.anchors/tenant-dev\n  \
                sudo tee /etc/pf.conf < updated.conf\n  \
                sudo pfctl -f /etc/pf.conf\n  \
                sudo pfctl -a tenant-dev -F all\n\
                $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
                $ rm -f ~/.config/tenant/profiles/dev.toml\n\
                $ sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n\
                $ sudo rm -f /etc/pf.anchors/tenant-dev\n\
                $ sudo tee /etc/pf.conf < updated.conf\n\
                $ sudo pfctl -f /etc/pf.conf\n\
                $ sudo pfctl -a tenant-dev -F all\n\
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
    let exec = StubExecutor::new().fail_account_blanket(78, "dseditgroup: not authorized\n");
    let (code, stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
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
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let op_names: Vec<&'static str> = exec
        .firewall_ops()
        .iter()
        .map(|op| match op {
            tenant::executor::FirewallOp::BackupConfig => "BackupConfig",
            tenant::executor::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::executor::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::executor::FirewallOp::Reload => "Reload",
            tenant::executor::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::executor::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::executor::FirewallOp::Enable => "Enable",
            tenant::executor::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
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
    let exec = StubExecutor::new().with_pf_conf(initial);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let updated = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::executor::FirewallOp::UpdateConfig { content } => Some(content),
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
    let exec = StubExecutor::new().fail_firewall_op(
        tenant::executor::FirewallOp::Reload,
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
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let op_names: Vec<&'static str> = exec
        .firewall_ops()
        .iter()
        .map(|op| match op {
            tenant::executor::FirewallOp::BackupConfig => "BackupConfig",
            tenant::executor::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::executor::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::executor::FirewallOp::Reload => "Reload",
            tenant::executor::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
            tenant::executor::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::executor::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::executor::FirewallOp::Enable => "Enable",
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
    let exec = StubExecutor::new().with_pf_conf("# host pf.conf, no tenant refs\n");
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
    let exec = StubExecutor::new();
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
        tenant::executor::FirewallOp::FlushAnchor { name: "dev".into() },
        "FlushAnchor must be the final firewall op on destroy"
    );
}

#[test]
fn destroy_orphan_group_invokes_flush_anchor_as_final_firewall_step() {
    // Same load-bearing flush, on the convergence path.
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub, &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let last = exec
        .firewall_ops()
        .last()
        .cloned()
        .expect("at least one firewall op must run");
    assert_eq!(
        last,
        tenant::executor::FirewallOp::FlushAnchor { name: "dev".into() },
        "FlushAnchor must be the final firewall op on orphan-group destroy"
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
    // Standard real mode: one pre-exec intent line, then login. Unlike
    // create/destroy, no post-exec confirmation — the operator IS the
    // shell after login returns. Single login call recorded.
    let exec = StubExecutor::new();
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
    let exec = StubExecutor::new().login_exit_code(5);
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
        exec.account_ops().is_empty() && exec.logins().is_empty(),
        "executor should not be invoked in dry-run; account_ops={:?}, logins={:?}",
        exec.account_ops(),
        exec.logins()
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
