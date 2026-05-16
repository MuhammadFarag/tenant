//! Cross-cutting CLI parser tests. Per-verb tests live in
//! `tests/cli_<verb>.rs` (cli_create / cli_destroy / cli_shell / cli_mode /
//! cli_doctor); shared helpers — `NeverExecutor`, `run_with`, `run_with_exec`,
//! `TEST_HOST`, plus stub-builder factories — live in `tests/common/mod.rs`.

use tenant::accounts::StubReader;

mod common;
use common::*;

#[test]
fn help_exits_zero() {
    let (code, _stdout, stderr) = run_with(StubReader::default(), &["--help"]);
    assert_eq!(code, 0, "--help exited with {code}; stderr={stderr:?}");
}

#[test]
fn dry_run_accepted_as_global_flag_before_subcommand() {
    let (code, stdout, stderr) = run_with(StubReader::default(), &["--dry-run", "create", "dev"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    // Dry-run: summary + prompt-preview, no substrate.
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
}
