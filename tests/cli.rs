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
    fn probe_access_as_tenant(
        &self,
        name: &str,
        path: &std::path::Path,
        mode: tenant::executor::AccessMode,
    ) -> Result<tenant::executor::AccessOutcome, tenant::executor::ProbeError> {
        panic!(
            "executor unexpectedly invoked (probe_access_as_tenant): name={name:?} path={path:?} mode={mode:?}"
        );
    }
    fn read_env_policy(&self) -> Result<String, tenant::executor::EnvPolicyError> {
        panic!("executor unexpectedly invoked (read_env_policy)");
    }
}

/// Host identity passed to `tenant::run`. Production reads `$USER`; tests
/// use a fixed placeholder so the doctor-verb's curated path expansion
/// (`/Users/<host>/...`) is deterministic across test runs.
const TEST_HOST: &str = "operator";

fn run_with(stub: StubReader, args: &[&str]) -> (u8, String, String) {
    let exec = NeverExecutor;
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let code = tenant::run(&args, &stub, &exec, TEST_HOST, &mut stdout, &mut stderr);
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
    let code = tenant::run(&args, &stub, exec, TEST_HOST, &mut stdout, &mut stderr);
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

// ================================================================
// Mode verb — cycle 3 of the PF + profile + mode bundle
// ================================================================
//
// Locked design (see CLAUDE.md doctrine):
// - Q1: NO defensive FlushAnchor before InstallAnchor. The parent
//   `load anchor` directive stays in pf.conf across mode reapply,
//   so `pfctl -f` re-reads the anchor file and replaces the
//   in-kernel ruleset. Verified empirically by the cycle-3 smoke.
// - Q2: Implicit current-mode (no state file). The on-disk anchor
//   body is the source of truth.
// - Q3: Auto-narrow on shell entry deferred to cycle 4. Cycle 3
//   ships the `mode` verb only; the operator narrows manually with
//   `tenant mode <name> runtime` after install-tier work.
// - Q4: ModeError { Profile, Firewall } — verb-isolated failure
//   surface paralleling DestroyError's split.

// ----------------------------------------------------------------
// Sub-cycle 3.1: clap parse + dry-run vertical slice
// ----------------------------------------------------------------

#[test]
fn mode_runtime_dry_run_default_shows_intent() {
    // Smallest red→green for the verb. `stub_with_tenant("dev")`
    // gives a tenant-range user so eligibility classifies as
    // Destroyable; dry-run swaps in DryRunExecutor which returns
    // `default_profile_toml()` from read_profile, so the writer's
    // profile-read + parse + render path completes without touching
    // the StubExecutor we (don't) wire here.
    let (code, stdout, stderr) = run_with(
        stub_with_tenant("dev"),
        &["mode", "dev", "runtime", "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would apply mode 'runtime' to tenant 'dev'.\n");
}

#[test]
fn mode_install_dry_run_default_shows_intent() {
    // Symmetric to the runtime test. Install ModeLevel parses too.
    let (code, stdout, stderr) = run_with(
        stub_with_tenant("dev"),
        &["mode", "dev", "install", "--dry-run"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would apply mode 'install' to tenant 'dev'.\n");
}

#[test]
fn mode_rejects_unknown_level() {
    // Clap's ValueEnum derivation accepts only `runtime` and `install`.
    // Anything else fails parse with exit 1 before dispatch runs.
    let (code, stdout, _stderr) = run_with(stub_with_tenant("dev"), &["mode", "dev", "bogus"]);
    assert_eq!(code, 1, "clap should reject unknown level");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
}

#[test]
fn mode_requires_name() {
    // `tenant mode` with no positional → clap parse error.
    let (code, _stdout, _stderr) = run_with(StubReader::default(), &["mode"]);
    assert_eq!(code, 1, "clap should reject missing name");
}

#[test]
fn mode_requires_level() {
    // `tenant mode dev` (no level) → clap parse error. Pins the
    // ValueEnum being a required positional.
    let (code, _stdout, _stderr) = run_with(StubReader::default(), &["mode", "dev"]);
    assert_eq!(code, 1, "clap should reject missing level");
}

// ----------------------------------------------------------------
// Sub-cycle 3.2: validation + eligibility refusals
// ----------------------------------------------------------------

#[test]
fn mode_rejects_empty_name() {
    // Lexical validation runs before eligibility; empty name trips
    // NameError::Empty and never consults the Reader. Same shape and
    // wording as create/destroy/shell.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["mode", "", "runtime"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn mode_rejects_reserved_names() {
    // Reserved-name blocklist applies to mode too. Lexical rail
    // trips before any state-based check.
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) = run_with(StubReader::default(), &["mode", name, "runtime"]);
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
fn mode_refuses_when_tenant_absent() {
    // Empty StubReader → NotPresent → refuse_mode_absent. Exit 64.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["mode", "ghost", "runtime"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot apply mode to 'ghost': does not exist\n"
    );
}

#[test]
fn mode_refuses_when_only_orphan_group_present() {
    // OrphanGroup collapses to the same refusal as NotPresent for
    // mode purposes — operator wants to apply a mode; the lingering
    // group can't host one. Mirrors shell's collapse from cycle 1
    // shell rollout.
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["mode", "dev", "runtime"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot apply mode to 'dev': does not exist\n"
    );
}

#[test]
fn mode_refuses_below_floor() {
    // Tenant-floor guard: an account exists with a positive UID below
    // TENANT_UID_FLOOR (600) → refuse. `legacyusr` sidesteps the
    // reserved-name blocklist so this test exercises the state-based
    // refusal path specifically.
    let stub = StubReader {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), 0)].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["mode", "legacyusr", "runtime"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to apply mode to 'legacyusr': UID 0 is below tenant floor 600\n"
    );
}

#[test]
fn mode_refuses_system_account() {
    // System-account refusal: `has_user` true, `uid_for` None (negative
    // UID was filtered by parse_id_line). Same shape as destroy/shell.
    let stub = StubReader {
        users: vec!["phantom".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["mode", "phantom", "runtime"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to apply mode to 'phantom': system account (no tenant-range UID)\n"
    );
}

#[test]
fn mode_dry_run_refuses_missing_tenant() {
    // Dry-run doesn't bypass eligibility — same answer real-mode
    // would give. Mirrors shell_dry_run_refuses_missing_tenant.
    let (code, stdout, stderr) = run_with(
        StubReader::default(),
        &["mode", "ghost", "runtime", "--dry-run"],
    );
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot apply mode to 'ghost': does not exist\n"
    );
}

// ----------------------------------------------------------------
// Sub-cycle 3.3: real-mode happy path — runtime
// ----------------------------------------------------------------

#[test]
fn mode_runtime_real_mode_op_shape() {
    // Two-op composition: InstallAnchor (with body rendered from
    // profile.allowlist.runtime.hosts — empty in the default profile)
    // + Reload. No defensive FlushAnchor (Q1 lock). Pre-load an
    // existing profile via with_existing_profile so the writer's
    // read_profile finds something.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Applied mode 'runtime' to tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
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
        "mode runtime should InstallAnchor (runtime-only body) then Reload"
    );
}

#[test]
fn mode_does_not_touch_account_or_profile_ops() {
    // Negative pin: mode operates entirely in the firewall domain.
    // No DeleteUserRecord, no ProfileOp::Create/Delete — those belong
    // to create/destroy. A regression that accidentally wired mode
    // through, say, a ProfileOp::Create would trip this.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0);
    assert!(
        exec.account_ops().is_empty(),
        "mode should not invoke account_ops: {:?}",
        exec.account_ops()
    );
    assert!(
        exec.profile_ops().is_empty(),
        "mode should not invoke profile_ops: {:?}",
        exec.profile_ops()
    );
    assert!(
        exec.logins().is_empty(),
        "mode should not invoke login: {:?}",
        exec.logins()
    );
}

#[test]
fn mode_does_not_emit_restore_config_op() {
    // Negative pin for Q4 lock: no auto-recovery on Reload failure.
    // Cycle 2's create-side restore-on-reload-failure sequence
    // (RestoreConfigFromBackup → RemoveAnchor → Reload → FlushAnchor)
    // does NOT fire for mode. Even on success the op list should be
    // exactly [InstallAnchor, Reload] with no other firewall ops.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (_code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    for op in exec.firewall_ops() {
        assert!(
            !matches!(
                op,
                FirewallOp::RestoreConfigFromBackup
                    | FirewallOp::BackupConfig
                    | FirewallOp::RemoveAnchor { .. }
                    | FirewallOp::FlushAnchor { .. }
                    | FirewallOp::Enable
                    | FirewallOp::UpdateConfig { .. }
            ),
            "mode should not emit recovery/teardown firewall ops, saw: {op:?}"
        );
    }
}

#[test]
fn mode_uses_centralized_anchor_name() {
    // Regression guard against an inline `format!("tenant-{name}")`
    // at the writer call site. The InstallAnchor's `name` field
    // should be the bare tenant name; the substrate constructs the
    // `tenant-<name>` anchor name from `tenant_anchor_name`. Verifies
    // the centralization rail.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (_code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { name, .. } => {
            assert_eq!(name, "dev", "anchor name should be bare tenant name");
        }
        other => panic!("expected InstallAnchor as first firewall op, got {other:?}"),
    }
}

// ----------------------------------------------------------------
// Sub-cycle 3.4: install mode + populated profile
// ----------------------------------------------------------------

/// Helper: profile TOML with the given runtime + install host lists.
/// Tests use this to populate `with_existing_profile` content so the
/// writer's read_profile + parse + render path exercises non-empty
/// allowlist tiers without touching real fs state.
fn profile_with_hosts(runtime: &[&str], install: &[&str]) -> String {
    let runtime_lines = runtime
        .iter()
        .map(|h| format!("  \"{h}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let install_lines = install
        .iter()
        .map(|h| format!("  \"{h}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let runtime_block = if runtime_lines.is_empty() {
        "hosts = []".to_string()
    } else {
        format!("hosts = [\n{runtime_lines}\n]")
    };
    let install_block = if install_lines.is_empty() {
        "hosts = []".to_string()
    } else {
        format!("hosts = [\n{install_lines}\n]")
    };
    format!(
        "schema_version = 1\n\n\
         [allowlist.runtime]\n{runtime_block}\n\n\
         [allowlist.install]\n{install_block}\n"
    )
}

#[test]
fn mode_install_with_only_runtime_populated() {
    // Install mode with runtime=[a,b] and install=[] should produce
    // a body with runtime hosts only (the install tier is empty, so
    // the union has no extra entries).
    let profile = profile_with_hosts(&["api.example.com", "deploy.example.com"], &[]);
    let exec = StubExecutor::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &[
            "api.example.com".to_string(),
            "deploy.example.com".to_string(),
        ],
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

#[test]
fn mode_install_with_runtime_and_install_populated() {
    // The cycle-3 happy-path canonical: runtime=[a] + install=[b,c]
    // under install mode → anchor body has [a, b, c] in that order.
    // Order matters for render_anchor's output stability.
    let profile = profile_with_hosts(
        &["api.example.com"],
        &["nodejs.org", "storage.googleapis.com"],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor(
        "dev",
        &[
            "api.example.com".to_string(),
            "nodejs.org".to_string(),
            "storage.googleapis.com".to_string(),
        ],
    );
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

#[test]
fn mode_runtime_with_runtime_and_install_populated_excludes_install() {
    // The cycle-3 narrow path: runtime=[a] + install=[b,c] under
    // runtime mode → anchor body has [a] only. Install hosts are
    // EXCLUDED. This is the security-relevant case — narrowing back
    // must shrink the host set.
    let profile = profile_with_hosts(
        &["api.example.com"],
        &["nodejs.org", "storage.googleapis.com"],
    );
    let exec = StubExecutor::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0);
    let expected_body = tenant::firewall::render_anchor("dev", &["api.example.com".to_string()]);
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

#[test]
fn mode_install_with_empty_runtime_and_populated_install() {
    // Edge case: runtime=[] + install=[a,b] under install mode →
    // body has [a, b]. The order-preserving union still works when
    // the runtime tier is empty (no awkward leading-empty handling).
    let profile = profile_with_hosts(&[], &["pypi.org", "npmjs.org"]);
    let exec = StubExecutor::new().with_existing_profile("dev", &profile);
    let (code, _stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "install"]);
    assert_eq!(code, 0);
    let expected_body =
        tenant::firewall::render_anchor("dev", &["pypi.org".to_string(), "npmjs.org".to_string()]);
    match &exec.firewall_ops()[0] {
        FirewallOp::InstallAnchor { body, .. } => {
            assert_eq!(body, &expected_body);
        }
        other => panic!("expected InstallAnchor first, got {other:?}"),
    }
}

// ----------------------------------------------------------------
// Sub-cycle 3.5: display — standard + verbose + dry-run
// ----------------------------------------------------------------

#[test]
fn mode_real_standard_emits_only_post_exec_confirmation() {
    // Standard real mode: silent pre-exec, one summary line post-exec.
    // Matches create/destroy's pattern. The level appears in the
    // confirmation so the operator sees which mode they ended up in.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Applied mode 'runtime' to tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
}

#[test]
fn mode_real_verbose_shows_plan_and_echo() {
    // Real+verbose: intent + 2-line plan + 2 `$` echoes + done.
    // The plan shows the placeholder InstallAnchor + Reload (their
    // describe lines ignore the body/content fields, so the rendered
    // text matches the real-body ops at execution time).
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Applying mode 'runtime' to tenant 'dev'.\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo pfctl -f /etc/pf.conf\n\
                $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
                $ sudo pfctl -f /etc/pf.conf\n\
                Applied mode 'runtime' to tenant 'dev'.\n";
    assert_eq!(stdout, want);
}

#[test]
fn mode_install_real_verbose_shows_install_level_text() {
    // Same plan/echo shape as runtime mode (anchor body content
    // differs but the describe text doesn't include the body).
    // The "install" level appears in the intent + done lines.
    let exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, _stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "install", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Applying mode 'install' to tenant 'dev'.\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo pfctl -f /etc/pf.conf\n\
                $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
                $ sudo pfctl -f /etc/pf.conf\n\
                Applied mode 'install' to tenant 'dev'.\n";
    assert_eq!(stdout, want);
}

#[test]
fn mode_dry_run_verbose_shows_plan_no_echo() {
    // Dry-run + verbose: "Would apply" intent + plan, but no `$`
    // echo (echo is real+verbose only) and no "Applied" done line.
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["mode", "dev", "runtime", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Would apply mode 'runtime' to tenant 'dev'.\n  \
                sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n  \
                sudo pfctl -f /etc/pf.conf\n";
    assert_eq!(stdout, want);
}

#[test]
fn mode_dry_run_bypasses_injected_executor() {
    // Dry-run swap-in of DryRunExecutor means the StubExecutor wired
    // by the test never sees a call. Mirrors create/destroy/shell's
    // dry-run-bypass tests.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["mode", "dev", "runtime", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Would apply mode 'runtime' to tenant 'dev'.\n");
    assert!(
        exec.firewall_ops().is_empty()
            && exec.account_ops().is_empty()
            && exec.profile_ops().is_empty(),
        "executor should not be invoked in dry-run; firewall_ops={:?}, account_ops={:?}, profile_ops={:?}",
        exec.firewall_ops(),
        exec.account_ops(),
        exec.profile_ops()
    );
}

// ----------------------------------------------------------------
// Sub-cycle 3.6: failure paths
// ----------------------------------------------------------------

#[test]
fn mode_read_profile_failure_surfaces() {
    // No `with_existing_profile` → StubExecutor::read_profile returns
    // a "not found" ProfileError. Mode should surface this through
    // mode_profile_failed with the profile path framed for the operator.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to read profile '~/.config/tenant/profiles/dev.toml' for 'dev': profile 'dev' not found\n"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "no firewall ops should have run; got {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn mode_parse_failure_surfaces_schema_version() {
    // Profile loads but schema_version is unsupported → parse
    // returns ProfileError → mode_profile_failed. The operator-readable
    // refusal message ("schema_version N not understood") is preserved
    // through the surface.
    let exec = StubExecutor::new().with_existing_profile(
        "dev",
        "schema_version = 99\n[allowlist.runtime]\nhosts = []\n[allowlist.install]\nhosts = []\n",
    );
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("schema_version 99 not understood"),
        "expected schema-version refusal in stderr, got: {stderr:?}"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "no firewall ops should have run"
    );
}

#[test]
fn mode_install_anchor_failure_surfaces() {
    // InstallAnchor (the first firewall op) fails → mode_failed with
    // the FirewallError display. Reload should NOT run after a failed
    // InstallAnchor.
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
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to apply firewall mode for 'dev': \
         filesystem error at /etc/pf.anchors/tenant-dev: permission denied\n"
    );
    // Only InstallAnchor recorded; Reload should NOT have fired.
    assert_eq!(exec.firewall_ops().len(), 1);
    assert!(matches!(
        exec.firewall_ops()[0],
        FirewallOp::InstallAnchor { .. }
    ));
}

#[test]
fn mode_reload_failure_surfaces_without_recovery() {
    // Reload fails → mode_failed. Critically, NO recovery sequence
    // fires (no RestoreConfigFromBackup, no RemoveAnchor, no second
    // Reload, no FlushAnchor). The verb is idempotent; the operator
    // reruns to retry. Mirrors plugin's reapply_anchor.
    let exec = StubExecutor::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_firewall_op(
            FirewallOp::Reload,
            FirewallError::NonZero {
                code: 1,
                stderr: "pfctl: Syntax error in anchor body\n".into(),
            },
        );
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["mode", "dev", "runtime"]);
    assert_eq!(code, 74, "EX_IOERR expected; stdout={stdout:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert!(
        stderr.contains("failed to apply firewall mode for 'dev'"),
        "stderr should be framed by mode_failed: {stderr:?}"
    );
    // Exactly two firewall ops: InstallAnchor (succeeded) + Reload
    // (failed). No recovery follow-up.
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
            "mode should not emit recovery firewall ops on reload failure, saw: {op:?}"
        );
    }
}

// ============================================================
// Doctor verb — cycle 5 (filesystem-exposure detection)
// ============================================================
//
// Sub-cycle 1 covers refusal paths + help-text disclosure only. Probe
// orchestration + finding emission land in sub-cycle 3; the all-tenants
// walk lands in sub-cycle 5. Refusals reuse `destroy_eligibility`'s
// 5-way classifier (same as shell/mode): NotPresent and OrphanGroup
// collapse into `refuse_doctor_absent` (the operator wants to audit
// a real tenant; an orphan group has no tenant to audit).

#[test]
fn doctor_refuses_when_tenant_absent() {
    // Empty StubReader — no user, no group. Doctor must refuse: there
    // is no tenant to audit. Exit 64 (EX_USAGE; operator gave a name
    // we can't resolve). Never reaches the executor.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["doctor", "ghost"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot run doctor on 'ghost': does not exist\n"
    );
}

#[test]
fn doctor_refuses_when_only_orphan_group_present() {
    // OrphanGroup collapses to NotPresent for doctor purposes (same
    // shape as shell/mode) — the operator wants to audit a tenant,
    // and a lingering `<name>-tenant-share` group with no user behind
    // it doesn't represent one. A regression that surfaced the orphan
    // group as a distinct refusal would trip this test.
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["doctor", "dev"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot run doctor on 'dev': does not exist\n"
    );
}

#[test]
fn doctor_refuses_below_floor() {
    // Tenant-floor guard mirrors shell/mode: an account exists with
    // a positive UID below TENANT_UID_FLOOR (600) → refuse. `legacyusr`
    // sidesteps the reserved-name blocklist so this test exercises
    // the state-based refusal path specifically.
    let stub = StubReader {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), 501)].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["doctor", "legacyusr"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to run doctor on 'legacyusr': UID 501 is below tenant floor 600\n"
    );
}

#[test]
fn doctor_refuses_system_account() {
    // System-account refusal (`has_user` true, `uid_for` None — service
    // accounts whose negative UIDs were filtered by `parse_id_line`).
    // Same shape as shell/mode's system-account refusal.
    let stub = StubReader {
        users: vec!["phantom".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["doctor", "phantom"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to run doctor on 'phantom': system account (no tenant-range UID)\n"
    );
}

#[test]
fn doctor_rejects_invalid_start() {
    // Lexical validation runs before eligibility; an uppercase first
    // character trips `NameError::InvalidStart` and never consults the
    // Reader. Reuses the generic `refuse_invalid_name` Reporter method
    // (no doctor-specific charset wording) — same shape as create /
    // destroy / shell / mode.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["doctor", "BAD"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: name 'BAD' must start with a lowercase letter (got 'B')\n"
    );
}

// ----- Sub-cycle 3: probe orchestration + finding emission -----
//
// The probe carve-out (`Executor::probe_access_as_tenant`) lets the
// Writer ask the substrate "can <tenant> read/list <path>?" without
// the Writer knowing about `sudo -u` or `/usr/bin/test`. Findings are
// derived from `Allowed` outcomes only; `Denied`/`Unknown` produce
// no operator-visible noise. Tests use `TEST_HOST` (the fixed host
// identity threaded through the test helpers) so the curated path
// expansion is deterministic across runs and environments.

fn make_tenant_stub_reader(name: &str) -> StubReader {
    // A reader where `name` is present as a Destroyable tenant (UID at
    // floor, group present). Lets dispatch reach `doctor_tenant`.
    StubReader {
        users: vec![name.to_string()],
        groups: vec![format!("{name}-tenant-share")],
        uid_by_name: [(name.to_string(), 600)].into_iter().collect(),
        gid_by_name: [(format!("{name}-tenant-share"), 600)]
            .into_iter()
            .collect(),
    }
}

#[test]
fn doctor_emits_one_finding_per_accessible_path() {
    // Stub configured to return `Allowed` for one specific
    // (tenant, path, mode) tuple — `/Users/<host>/.ssh/id_rsa` Read.
    // That's a HostSecret + Read, which `classify` maps to Critical.
    // Output must contain the critical finding line, byte-exact.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::Read,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected_line = format!("critical: tenant 'dev' can read /Users/{TEST_HOST}/.ssh/id_rsa\n");
    assert!(
        stdout.contains(&expected_line),
        "expected finding line in stdout; got: {stdout:?}"
    );
}

#[test]
fn doctor_clean_host_emits_no_findings_summary() {
    // No `with_probe_outcome` calls — every probe defaults to
    // `Denied`. A clean host produces no findings; the operator
    // sees the convergent summary line.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "doctor: tenant 'dev' — no findings.\n");
}

#[test]
fn doctor_probes_full_curated_list_per_tenant() {
    // Pin: the recorded probe sequence matches `curated_paths(TEST_HOST,
    // tenant, &[])`. Behavioral assertion on probe identity — a
    // regression that silently dropped one curated path would trip
    // this test. Tuple order is locked.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected: Vec<(String, std::path::PathBuf, tenant::executor::AccessMode)> =
        tenant::doctor::curated_paths(TEST_HOST, "dev", &[])
            .into_iter()
            .map(|(_, mode, path)| ("dev".to_string(), path, mode))
            .collect();
    assert_eq!(
        stub_exec.probes(),
        expected,
        "probe sequence must match curated_paths(TEST_HOST, 'dev', &[])"
    );
}

#[test]
fn doctor_probe_substrate_failure_exits_74() {
    // `ProbeError::Spawn` propagates as a substrate-execution failure.
    // Doctor surfaces via `doctor_failed`; exit 74 (EX_IOERR) parallel
    // to mode / shell / destroy substrate failures.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().fail_next_probe(tenant::executor::ProbeError::Spawn(
        std::io::Error::other("sudo not found"),
    ));
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert!(
        stderr.contains("failed to probe"),
        "stderr should frame as doctor probe failure; got: {stderr:?}"
    );
}

#[test]
fn doctor_dry_run_skips_probes() {
    // `--dry-run` produces an intent line and runs zero probes.
    // Probes have side effects (sudo prompts, kernel access checks)
    // — dry-run is for "what would this do" inspection only.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--dry-run"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stub_exec.probes(),
        Vec::<(String, std::path::PathBuf, tenant::executor::AccessMode)>::new(),
        "dry-run must not invoke probes"
    );
    assert!(
        stdout.starts_with("Would run doctor on tenant 'dev'"),
        "dry-run should emit intent line; got: {stdout:?}"
    );
}

// ----- Sub-cycle 7: verbose curated-list disclosure -----
//
// Bounded-scope transparency: doctor's verbose output names every
// path it probed, before findings. A clean "no findings" verdict
// is not a claim about the operator's whole host — it's about
// THESE PATHS — and verbose makes that explicit.

#[test]
fn doctor_verbose_prepends_curated_path_header() {
    // Verbose real-mode output starts with the header. The header
    // names the tenant and is followed by one indented `<verb>
    // <path>` line per curated entry. Pin the header line +
    // one canonical entry to guard against regressions that drop
    // the disclosure block.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Curated sensitive paths checked for tenant 'dev':\n"),
        "verbose output should include curated-path header; stdout={stdout:?}"
    );
    let canonical_entry = format!("  read /Users/{TEST_HOST}/.ssh/id_rsa\n");
    assert!(
        stdout.contains(&canonical_entry),
        "verbose output should list the canonical HostSecret/Read entry; stdout={stdout:?}"
    );
}

#[test]
fn doctor_verbose_then_findings_ordering() {
    // Pin: in verbose mode, the curated-path block comes FIRST
    // (operator sees scope), then findings, then the summary line.
    // Regression target: a wiring that emitted findings before the
    // header would surprise the operator's eye on a long output.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::Read,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, stdout, _stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0);
    let header_pos = stdout
        .find("Curated sensitive paths checked for tenant 'dev':")
        .expect("header should be present");
    let finding_pos = stdout
        .find("critical: tenant 'dev' can read")
        .expect("critical finding should be present");
    assert!(
        header_pos < finding_pos,
        "curated-path header must precede findings; stdout={stdout:?}"
    );
}

// ----- Sub-cycle 6: sudoers env-leak check -----
//
// Doctor reads `/etc/sudoers` + drop-ins (concatenated via
// `Executor::read_env_policy`) and parses for `env_delete` directives.
// If `SSH_AUTH_SOCK` isn't covered, doctor emits a host-wide
// `Finding::EnvLeak` warning so the operator knows their session env
// (specifically the ssh-agent socket) is propagating into `tenant
// shell` sessions. Cycle 1 hard-codes the SSH_AUTH_SOCK var; future
// cycles may generalize.

#[test]
fn doctor_reports_ssh_auth_sock_leak_when_env_delete_missing() {
    // Empty env policy → `env_delete` missing → leak finding fires.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().with_env_policy_content("");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("SSH_AUTH_SOCK not in env_delete"),
        "expected env-leak warning; stdout={stdout:?}"
    );
}

#[test]
fn doctor_silent_when_env_delete_in_main_sudoers() {
    // Main `/etc/sudoers` contains the directive → no env-leak finding.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec =
        StubExecutor::new().with_env_policy_content("Defaults env_delete += \"SSH_AUTH_SOCK\"\n");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("SSH_AUTH_SOCK"),
        "no env-leak should fire when directive present; stdout={stdout:?}"
    );
}

#[test]
fn doctor_finds_env_delete_in_drop_in_file() {
    // Directive in a drop-in file (concatenated by the substrate
    // into the same text blob) — parser doesn't care which file
    // sourced it. Models `/etc/sudoers.d/tenant` carrying the fix.
    let stub_reader = make_tenant_stub_reader("dev");
    let policy = "Defaults env_keep += \"PATH\"\n\
                  Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    let stub_exec = StubExecutor::new().with_env_policy_content(policy);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("SSH_AUTH_SOCK not in env_delete"),
        "drop-in directive should suppress leak; stdout={stdout:?}"
    );
}

// ----- Sub-cycle 5: all-tenants walk + cross-tenant probes -----
//
// `tenant doctor` without a positional name enumerates every
// tenant-range account via `Reader::tenant_names()` and probes each
// from its own perspective. The `others` list (every other tenant)
// drives cross-tenant + tenant-artifact probe expansion. Single-
// tenant invocation (`tenant doctor dev`) intentionally probes ONLY
// dev's view (others = empty) — the negative pin is the operator
// signal that single-tenant is scoped.

fn make_two_tenant_stub_reader() -> StubReader {
    StubReader {
        users: vec!["dev".to_string(), "staging".to_string()],
        groups: vec![
            "dev-tenant-share".to_string(),
            "staging-tenant-share".to_string(),
        ],
        uid_by_name: [("dev".to_string(), 600), ("staging".to_string(), 601)]
            .into_iter()
            .collect(),
        gid_by_name: [
            ("dev-tenant-share".to_string(), 600),
            ("staging-tenant-share".to_string(), 601),
        ]
        .into_iter()
        .collect(),
    }
}

#[test]
fn doctor_all_tenants_walks_each_tenant() {
    // Bare `tenant doctor` (no positional name) probes both tenants
    // alphabetically. Behavioral pin: the recorded probe sequence
    // contains entries for `dev` AND `staging` as the probed tenant.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let probes = stub_exec.probes();
    assert!(
        probes.iter().any(|(name, _, _)| name == "dev"),
        "bare doctor should probe `dev`; probes={probes:?}"
    );
    assert!(
        probes.iter().any(|(name, _, _)| name == "staging"),
        "bare doctor should probe `staging`; probes={probes:?}"
    );
}

#[test]
fn doctor_all_tenants_emits_cross_tenant_probes() {
    // With two tenants on the host, dev's probe set includes
    // `/Users/staging` (CrossTenant + List) and staging's includes
    // `/Users/dev`. The cross-tenant block is the new ground doctor
    // breaks — the sandbox plugin doesn't audit it.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let probes = stub_exec.probes();
    let dev_probes_staging = probes.iter().any(|(name, path, mode)| {
        name == "dev"
            && path == &std::path::PathBuf::from("/Users/staging")
            && *mode == tenant::executor::AccessMode::List
    });
    let staging_probes_dev = probes.iter().any(|(name, path, mode)| {
        name == "staging"
            && path == &std::path::PathBuf::from("/Users/dev")
            && *mode == tenant::executor::AccessMode::List
    });
    assert!(
        dev_probes_staging,
        "dev should probe /Users/staging (CrossTenant); probes={probes:?}"
    );
    assert!(
        staging_probes_dev,
        "staging should probe /Users/dev (CrossTenant); probes={probes:?}"
    );
}

#[test]
fn doctor_single_tenant_omits_other_tenant_perspectives() {
    // `tenant doctor dev` only probes dev's view; staging's own
    // probes (e.g. staging probing /Users/operator) must not fire.
    // Negative pin against an accidental "audit every tenant
    // anyway" implementation.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let probes = stub_exec.probes();
    assert!(
        !probes.iter().any(|(name, _, _)| name == "staging"),
        "single-tenant `doctor dev` must not emit probes as `staging`; probes={probes:?}"
    );
    // And single-tenant means others list is empty → no cross-tenant
    // probes from dev's view either (dev doesn't probe /Users/staging).
    assert!(
        !probes
            .iter()
            .any(|(_, path, _)| path == &std::path::PathBuf::from("/Users/staging")),
        "single-tenant `doctor dev` should not probe other tenant homes; probes={probes:?}"
    );
}

// ----- Sub-cycle 4: --strict exit codes -----
//
// Without --strict: doctor always exits 0 on a successful walk (findings
// are informational). With --strict: max finding severity drives the
// exit code (0 / 1 / 2 for none-or-info / warning / critical).

#[test]
fn doctor_strict_critical_exits_2() {
    // One Allowed probe on a HostSecret path → critical finding →
    // --strict → exit 2.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::Read,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 2,
        "expected exit 2 on critical+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_strict_warning_only_exits_1() {
    // One Allowed probe on a HostHomeListing path → warning finding →
    // --strict → exit 1. HostHomeListing is the warning-tier category;
    // host-home is `/Users/<host>` with AccessMode::List.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::List,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_strict_no_findings_exits_0() {
    // Clean host — every probe Denied → 0 findings → --strict → exit 0.
    // Pin: --strict doesn't manufacture exit-1 out of nothing.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 0,
        "expected exit 0 on clean+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_non_strict_critical_still_exits_0() {
    // Negative pin: even a critical finding produces exit 0 without
    // --strict. Doctor's default contract is "report exposures and
    // exit successfully so the operator can pipe / chain"; --strict
    // is the opt-in CI-style verdict shape.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::Read,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(
        code, 0,
        "expected exit 0 on critical without --strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_help_text_mentions_sudo_session_and_admin_requirement() {
    // Operator-UX commitment: `tenant doctor --help` documents the two
    // load-bearing operator preconditions — admin-group membership (so
    // `sudo -u <tenant>` is permitted on macOS) and the cached sudo
    // session pattern (one prompt up front, N probes run silently).
    // Pins load-bearing words, not byte-exact wording.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["doctor", "--help"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("sudo"),
        "doctor --help should mention sudo (cached session pattern); stdout={stdout:?}"
    );
    assert!(
        stdout.contains("admin"),
        "doctor --help should mention admin-group requirement; stdout={stdout:?}"
    );
}
