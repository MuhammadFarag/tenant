//! Cross-cutting CLI parser tests; per-verb tests live in `tests/cli_<verb>.rs`.

mod adapters;
mod common;
use adapters::*;
use common::*;

#[test]
fn help_exits_zero() {
    let (code, _stdout, stderr) = run_with(StubUserDirectory::default(), &["--help"]);
    assert_eq!(code, 0, "--help exited with {code}; stderr={stderr:?}");
}

#[test]
fn dry_run_accepted_as_global_flag_before_subcommand() {
    let (code, stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["--dry-run", "create", "dev"],
    );
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
}

#[test]
fn top_level_help_includes_long_about_text() {
    // Substring, not byte-exact: clap owns the surrounding layout.
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["--help"]);
    assert_eq!(code, 0, "--help exited with {code}; stderr={stderr:?}");
    assert!(
        stdout.contains("Provision macOS user accounts"),
        "long_about should open with the provisioning sentence: {stdout}"
    );
    assert!(
        stdout.contains(">= 600"),
        "long_about should mention UID floor: {stdout}"
    );
    assert!(
        stdout.contains("~/.config/tenant/profiles/<name>.toml"),
        "long_about should mention profile path: {stdout}"
    );
}

#[test]
fn top_level_short_help_includes_about_one_liner() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["-h"]);
    assert_eq!(code, 0, "-h exited with {code}; stderr={stderr:?}");
    assert!(
        stdout.contains("Provision isolated macOS tenant accounts"),
        "short about one-liner missing: {stdout}"
    );
}

#[test]
fn shell_help_includes_examples_block() {
    let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["shell", "--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Examples:"),
        "shell --help should include Examples block: {stdout}"
    );
    assert!(
        stdout.contains("tenant shell alice --mode install -- pip install foo"),
        "shell --help should show the widened-call example: {stdout}"
    );
}

#[test]
fn shell_help_documents_directory_path_shapes() {
    let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["shell", "--help"]);
    assert_eq!(code, 0);
    for needle in [
        "-d, --directory",
        "relative",
        "absolute",
        "$HOME",
        "OPERATOR's home",
        "tenant shell alice -d projects/foo -- claude",
        "anywhere else refuses",
        "sudo session is active",
    ] {
        assert!(
            stdout.contains(needle),
            "shell --help should mention {needle:?}: {stdout}"
        );
    }
}

#[test]
fn mode_help_includes_examples_block() {
    let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["mode", "--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Examples:"),
        "mode --help should include Examples block: {stdout}"
    );
    assert!(
        stdout.contains("tenant mode alice install"),
        "mode --help should show the install example: {stdout}"
    );
}

#[test]
fn each_verb_help_includes_long_body() {
    let cases = &[
        ("create", "Provision a new tenant"),
        ("destroy", "Convergent"),
        ("reload", "runtime tier"),
        ("mode", "non-persistent"),
        ("shell", "login shell"),
        ("doctor", "ground truth"),
        ("setup", "no pre-exec doctor pass"),
    ];
    for (verb, needle) in cases {
        let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &[verb, "--help"]);
        assert_eq!(code, 0, "{verb} --help exited with {code}");
        assert!(
            stdout.contains(needle),
            "{verb} --help missing {needle:?}: {stdout}"
        );
    }
}

#[test]
fn setup_takes_no_positional_argument() {
    let (code, _stdout, stderr) = run_with(StubUserDirectory::default(), &["setup", "foo"]);
    assert_eq!(
        code, 2,
        "stray positional should be a parse error; stderr={stderr:?}"
    );
}

#[test]
fn global_verbose_help_text_present() {
    let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Plan (commands to execute)"),
        "--verbose help should mention the plan block: {stdout}"
    );
}

#[test]
fn global_dry_run_help_text_present() {
    let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Preview without mutating"),
        "--dry-run help should describe the preview posture: {stdout}"
    );
}

#[test]
fn version_flag_prints_name_and_cargo_pkg_version() {
    let expected = format!("tenant {}\n", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &[flag]);
        assert_eq!(code, 0, "{flag} exited with {code}; stderr={stderr:?}");
        assert_eq!(stdout, expected, "{flag} byte-form pin failed");
    }
}
