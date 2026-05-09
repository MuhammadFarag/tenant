#[test]
fn help_exits_zero() {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args = vec!["--help".to_string()];

    let exit_code = tenant::run(&args, &mut stdout, &mut stderr);

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
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args = vec![
        "create".to_string(),
        "dev".to_string(),
        "--dry-run".to_string(),
    ];

    let exit_code = tenant::run(&args, &mut stdout, &mut stderr);

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
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args = vec![
        "create".to_string(),
        "dev".to_string(),
        "--dry-run".to_string(),
        "-v".to_string(),
    ];

    let exit_code = tenant::run(&args, &mut stdout, &mut stderr);

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
