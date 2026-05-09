use tenant::accounts::StubReader;

#[test]
fn help_exits_zero() {
    let accounts = StubReader::default();
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args = vec!["--help".to_string()];

    let exit_code = tenant::run(&args, &accounts, &mut stdout, &mut stderr);

    assert_eq!(
        exit_code,
        0,
        "--help exited with {}, want 0; stderr={:?}",
        exit_code,
        String::from_utf8_lossy(&stderr),
    );
}

#[test]
fn create_dry_run_default_shows_intent() {
    let accounts = StubReader::default();
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args = vec![
        "create".to_string(),
        "dev".to_string(),
        "--dry-run".to_string(),
    ];

    let exit_code = tenant::run(&args, &accounts, &mut stdout, &mut stderr);

    assert_eq!(
        exit_code,
        0,
        "exit code = {}, want 0; stderr={:?}",
        exit_code,
        String::from_utf8_lossy(&stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "Would create tenant 'dev'.\n",
    );
}

#[test]
fn create_dry_run_verbose_includes_mechanism() {
    let accounts = StubReader::default();
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args = vec![
        "create".to_string(),
        "dev".to_string(),
        "--dry-run".to_string(),
        "-v".to_string(),
    ];

    let exit_code = tenant::run(&args, &accounts, &mut stdout, &mut stderr);

    assert_eq!(
        exit_code,
        0,
        "exit code = {}, want 0; stderr={:?}",
        exit_code,
        String::from_utf8_lossy(&stderr),
    );
    let want = "Would create tenant 'dev'.\n\
                Would run:\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n";
    assert_eq!(String::from_utf8_lossy(&stdout), want);
}

#[test]
fn create_dry_run_verbose_uses_lowest_free_uid() {
    let accounts = StubReader {
        uids: vec![600, 601, 603],
        ..Default::default()
    };
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args = vec![
        "create".to_string(),
        "dev".to_string(),
        "--dry-run".to_string(),
        "-v".to_string(),
    ];

    let exit_code = tenant::run(&args, &accounts, &mut stdout, &mut stderr);

    assert_eq!(
        exit_code,
        0,
        "exit code = {}, want 0; stderr={:?}",
        exit_code,
        String::from_utf8_lossy(&stderr),
    );
    let want = "Would create tenant 'dev'.\n\
                Would run:\n  \
                sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 602 -GID 602\n";
    assert_eq!(String::from_utf8_lossy(&stdout), want);
}

#[test]
fn create_with_invalid_name_errors_to_stderr() {
    let accounts = StubReader::default();
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args = vec![
        "create".to_string(),
        "1dev".to_string(),
        "--dry-run".to_string(),
    ];

    let exit_code = tenant::run(&args, &accounts, &mut stdout, &mut stderr);

    assert_eq!(
        exit_code,
        64,
        "want EX_USAGE (64); stderr={:?}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        stdout.is_empty(),
        "stdout should be empty on validation failure; got {:?}",
        String::from_utf8_lossy(&stdout),
    );
    assert_eq!(
        String::from_utf8_lossy(&stderr),
        "tenant: name '1dev' must start with a lowercase letter (got '1')\n",
    );
}
