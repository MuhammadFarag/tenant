use tenant::accounts::StubReader;

fn run_with(stub: StubReader, args: &[&str]) -> (u8, String, String) {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let code = tenant::run(&args, &stub, &mut stdout, &mut stderr);
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
    let want = "Would create tenant 'dev'.\n\
                Would run:\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n";
    assert_eq!(stdout, want);
}

#[test]
fn verbose_shows_lowest_free_uid_with_gap() {
    let stub = StubReader {
        uids: vec![600, 601, 603],
        ..Default::default()
    };
    let (code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let want = "Would create tenant 'dev'.\n\
                Would run:\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 602 -GID 602\n";
    assert_eq!(stdout, want);
}

#[test]
fn verbose_skips_taken_floor() {
    let stub = StubReader {
        uids: vec![600],
        ..Default::default()
    };
    let (_code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
    assert!(
        stdout.contains("-UID 601 -GID 601"),
        "expected UID 601 in stdout, got: {stdout:?}",
    );
}

#[test]
fn verbose_uid_independent_of_input_order() {
    let stub = StubReader {
        uids: vec![603, 600, 601],
        ..Default::default()
    };
    let (_code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
    assert!(
        stdout.contains("-UID 602 -GID 602"),
        "expected UID 602 in stdout, got: {stdout:?}",
    );
}

#[test]
fn verbose_skips_uids_below_floor() {
    let stub = StubReader {
        uids: vec![500, 599],
        ..Default::default()
    };
    let (_code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
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

#[cfg(target_os = "macos")]
#[test]
fn macos_reader_detects_root_conflict() {
    // End-to-end smoke test: build a real MacosReader against the host's
    // dscl, run `tenant create root --dry-run`, expect a conflict.
    // `root` is universally present on macOS, so this is host-stable.
    let reader = tenant::accounts::MacosReader::new().expect("dscl should be available on macOS");
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = ["create", "root", "--dry-run"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let code = tenant::run(&args, &reader, &mut stdout, &mut stderr);
    let stderr_str = String::from_utf8_lossy(&stderr);
    assert_eq!(code, 64, "stderr={stderr_str:?}");
    assert!(
        stderr_str.contains("'root' already exists"),
        "stderr should mention root conflict, got: {stderr_str:?}",
    );
}
