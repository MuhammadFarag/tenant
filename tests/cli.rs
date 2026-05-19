//! Cross-cutting CLI parser tests. Per-verb tests live in
//! `tests/cli_<verb>.rs` (cli_create / cli_destroy / cli_shell / cli_mode /
//! cli_doctor); shared helpers — `NeverHostMachine`, `run_with`, `run_with_exec`,
//! `TEST_HOST`, plus stub-builder factories — live in `tests/common/mod.rs`.

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
    // Dry-run: summary + prompt-preview, no substrate.
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
}

#[test]
fn top_level_help_includes_long_about_text() {
    // clap renders `long_about` under `--help` and `about` under `-h`.
    // Pin substrings from the long body: UID floor, per-tenant config
    // path, and a verb-set anchor. Substring-level rather than byte-
    // exact because clap's surrounding layout is its concern.
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
    // `-h` surfaces the short `about` text instead of `long_about`.
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["-h"]);
    assert_eq!(code, 0, "-h exited with {code}; stderr={stderr:?}");
    assert!(
        stdout.contains("Provision isolated macOS tenant accounts"),
        "short about one-liner missing: {stdout}"
    );
}

#[test]
fn shell_help_includes_examples_block() {
    // `after_help` on Shell emits an Examples: block listing the three
    // common invocations. Pin only the section header + one
    // representative example.
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
    // Sanity: every verb's long-body docstring surfaces under
    // `<verb> --help`. Picks a distinctive substring per verb so the
    // test catches "doc rewrite dropped a key concept" regressions.
    let cases = &[
        ("create", "Provision a new tenant"),
        ("destroy", "Convergent"),
        ("reload", "runtime tier"),
        ("mode", "non-persistent"),
        ("shell", "login shell"),
        ("doctor", "ground truth"),
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
