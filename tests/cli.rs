use tenant::accounts::StubReader;
use tenant::executor::{ExecError, Executor, StubExecutor};

/// Default executor for tests that should not reach the exec stage —
/// validation failures, conflicts, and dry-run paths. Panics on use, so
/// any accidental exec from a path that's meant to be no-op surfaces
/// loudly instead of being silently absorbed.
struct NeverExecutor;
impl Executor for NeverExecutor {
    fn run(&self, argv: &[String]) -> Result<(), ExecError> {
        panic!("executor unexpectedly invoked with argv: {argv:?}");
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

/// Build a `Vec<String>` argv from `&[&str]` — the shape `StubExecutor`
/// records calls in. Used in assertions where reading three or four parallel
/// argv literals is easier than the inline `.iter().map(...).collect()`
/// chain.
fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
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
fn verbose_shows_floor_uid_when_no_uids_in_use() {
    let (code, stdout, _stderr) =
        run_with(StubReader::default(), &["create", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let want = "Would create tenant 'dev'.\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n";
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
fn verbose_shows_lowest_free_uid_with_gap() {
    let (code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[600, 601, 603]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Would create tenant 'dev'.\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 602 -GID 602\n";
    assert_eq!(stdout, want);
}

#[test]
fn verbose_skips_taken_floor() {
    let (_code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[600]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert!(
        stdout.contains("-UID 601 -GID 601"),
        "expected UID 601 in stdout, got: {stdout:?}",
    );
}

#[test]
fn verbose_uid_independent_of_input_order() {
    let (_code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[603, 600, 601]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert!(
        stdout.contains("-UID 602 -GID 602"),
        "expected UID 602 in stdout, got: {stdout:?}",
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
        "expected UID 600 in stdout, got: {stdout:?}",
    );
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
fn create_rejects_when_group_exists() {
    let stub = StubReader {
        groups: vec!["dev".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: group 'dev' already exists\n");
}

#[test]
fn create_rejects_when_user_and_group_exist() {
    let stub = StubReader {
        users: vec!["dev".to_string()],
        groups: vec!["dev".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: user and group 'dev' already exist\n");
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
fn create_real_mode_standard_emits_only_post_exec_confirmation() {
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    // Standard real mode is silent before exec; one confirmation line after.
    // No UID — that's reserved for verbose mode.
    assert_eq!(stdout, "Created tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    let calls = exec.calls();
    assert_eq!(calls.len(), 1, "expected exactly one exec call");
    let want_argv: Vec<String> = [
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
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    assert_eq!(calls[0], want_argv);
}

#[test]
fn create_real_mode_verbose_shows_pre_exec_mechanism_and_post_exec_uid() {
    let exec = StubExecutor::new();
    let (code, stdout, _stderr) =
        run_with_exec(StubReader::default(), &exec, &["create", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Creating tenant 'dev'.\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n\
                Created tenant 'dev' (UID 600).\n";
    assert_eq!(stdout, want);
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
fn create_real_mode_propagates_exec_failure() {
    let exec = StubExecutor::failing(78);
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    // Standard mode: no pre-exec output; failure goes to stderr only.
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to create 'dev': process exited with code 78\n"
    );
    assert_eq!(exec.calls().len(), 1);
}

#[test]
fn create_real_mode_failure_surfaces_executor_stderr() {
    let exec =
        StubExecutor::failing_with(78, "sysadminctl: -addUser failed: user already exists\n");
    let (code, stdout, stderr) = run_with_exec(StubReader::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: failed to create 'dev': process exited with code 78: \
         sysadminctl: -addUser failed: user already exists\n"
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
fn destroy_dry_run_default_shows_intent() {
    let (code, stdout, stderr) =
        run_with(stub_with_tenant("dev"), &["destroy", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, "Would destroy tenant 'dev'.\n");
}

#[test]
fn destroy_dry_run_verbose_shows_mechanism() {
    // Dry-run verbose lists the full pessimistic plan: sysadminctl -deleteUser
    // (the canonical destroy), dscl -read (the post-exec residue probe), and
    // sudo dscl -delete (the conditional belt-and-braces cleanup if the probe
    // finds the DS record still present). The dscl-delete is shown
    // unconditionally because the dry-run can't know what the probe would
    // have found at runtime — the operator sees the algorithm.
    let (code, stdout, _stderr) = run_with(
        stub_with_tenant("dev"),
        &["destroy", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let want = "Would destroy tenant 'dev'.\n  \
                sudo sysadminctl -deleteUser dev\n  \
                dscl . -read /Users/dev\n  \
                sudo dscl . -delete /Users/dev\n";
    assert_eq!(stdout, want);
}

#[test]
fn destroy_real_mode_standard_emits_only_post_exec_confirmation() {
    // StubExecutor::new() returns Ok by default → the dscl-read probe sees
    // the DS record as still present → the conditional dscl-delete runs.
    // Three exec calls in standard mode; stdout is still the single
    // confirmation line (mechanism is suppressed without -v).
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'dev'.\n");
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    let calls = exec.calls();
    assert_eq!(
        calls.len(),
        3,
        "expected sysadminctl + dscl-read + dscl-delete"
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
}

#[test]
fn destroy_real_mode_verbose_shows_pre_exec_mechanism_and_post_exec() {
    // Real-mode verbose has two sections: (a) the "Destroying" pre-exec
    // intent + the full pessimistic plan (same shape as dry-run verbose),
    // then (b) per-exec echo lines prefixed with "$ " as each command
    // actually runs. Default StubExecutor → probe says residue → all three
    // commands echo. The trailing post-exec confirmation closes the block.
    let exec = StubExecutor::new();
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Destroying tenant 'dev'.\n  \
                sudo sysadminctl -deleteUser dev\n  \
                dscl . -read /Users/dev\n  \
                sudo dscl . -delete /Users/dev\n\
                $ sudo sysadminctl -deleteUser dev\n\
                $ dscl . -read /Users/dev\n\
                $ sudo dscl . -delete /Users/dev\n\
                Destroyed tenant 'dev'.\n";
    assert_eq!(stdout, want);
}

#[test]
fn destroy_real_mode_skips_dscl_cleanup_when_probe_finds_clean() {
    // The dscl-read probe returns NonZero when the DS record is absent
    // (typically eDSRecordNotFound, code 56). The destroy writer must
    // treat probe-NonZero as "no cleanup needed" and stop after the
    // probe — only two exec calls, no third sudo-dscl-delete. The
    // stdout (standard mode) is the same single confirmation as the
    // residue path; the operator can't tell from non-verbose output
    // whether the cleanup ran. Verbose output's `$ sudo dscl . -delete`
    // line is the operator's signal — covered separately below.
    let exec = StubExecutor::new().with_response_to(&["dscl", ".", "-read", "/Users/dev"], 56);
    let (code, stdout, stderr) = run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "Destroyed tenant 'dev'.\n");
    let calls = exec.calls();
    assert_eq!(calls.len(), 2, "expected sysadminctl + dscl-read only");
    assert_eq!(
        calls[0],
        argv(&["sudo", "sysadminctl", "-deleteUser", "dev"])
    );
    assert_eq!(calls[1], argv(&["dscl", ".", "-read", "/Users/dev"]));
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
    // Verbose-mode counterpart: the upfront plan still lists all three
    // commands (the operator sees the algorithm), but the per-exec `$`
    // echo block stops after the probe — the dscl-delete echo is absent
    // because the cleanup didn't run. The asymmetry between plan and
    // echo is the load-bearing observable that tells the operator the
    // probe cleared the DS state.
    let exec = StubExecutor::new().with_response_to(&["dscl", ".", "-read", "/Users/dev"], 56);
    let (code, stdout, _stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["destroy", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = "Destroying tenant 'dev'.\n  \
                sudo sysadminctl -deleteUser dev\n  \
                dscl . -read /Users/dev\n  \
                sudo dscl . -delete /Users/dev\n\
                $ sudo sysadminctl -deleteUser dev\n\
                $ dscl . -read /Users/dev\n\
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
    // System account masquerading as a destroyable tenant: name passes
    // validate_name (lowercase, no funny chars) but UID is below the
    // tenant floor. Refuse with EX_USAGE; never reach the executor.
    let stub = StubReader {
        users: vec!["wheel".to_string()],
        uid_by_name: [("wheel".to_string(), 0)].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "wheel"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to destroy 'wheel': UID 0 is below tenant floor 600\n"
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
    // Three calls: sysadminctl-deleteUser + dscl-read probe + (probe defaults
    // to Ok with a vanilla StubExecutor) sudo-dscl-delete cleanup.
    assert_eq!(
        exec.calls().len(),
        3,
        "sysadminctl + dscl-read + dscl-delete"
    );
}

#[test]
fn destroy_refuses_when_uid_unknown_but_user_present() {
    // `nobody` on macOS has UID -2, which `parse_uid_line` filters out
    // of `uid_by_name`. The user is still present in the user listing, so
    // `has_user` is true but `uid_for` returns None — that's the
    // `SystemAccount` variant. Refuse with `EX_USAGE`, NOT a noop, so the
    // operator sees the real state ("system account") rather than the
    // misleading "does not exist".
    let stub = StubReader {
        users: vec!["nobody".to_string()],
        // uid_by_name deliberately empty: simulates the parse_uid_line
        // negative-UID filter.
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["destroy", "nobody"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to destroy 'nobody': system account (no tenant-range UID)\n"
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

#[cfg(target_os = "macos")]
#[test]
fn macos_reader_detects_root_conflict() {
    // End-to-end smoke test: build a real MacosReader against the host's
    // dscl, run `tenant create root --dry-run`, expect a conflict.
    // `root` is universally present on macOS, so this is host-stable.
    let reader = tenant::accounts::MacosReader::new().expect("dscl should be available on macOS");
    let exec = NeverExecutor;
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = ["create", "root", "--dry-run"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let code = tenant::run(&args, &reader, &exec, &mut stdout, &mut stderr);
    let stderr_str = String::from_utf8_lossy(&stderr);
    assert_eq!(code, 64, "stderr={stderr_str:?}");
    assert!(
        stderr_str.contains("'root' already exists"),
        "stderr should mention root conflict, got: {stderr_str:?}",
    );
}
