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
