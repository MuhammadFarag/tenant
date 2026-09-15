use tenant::domain::PamOp;

mod adapters;
mod common;
use adapters::*;
use common::*;

// `run_with_stdin` simulates a TTY (the offer fires); `run_with_exec` is non-TTY.

fn no_tenants() -> StubUserDirectory {
    StubUserDirectory::default()
}

// ----- Accept path -----

#[test]
fn setup_offer_accepted_enables_touch_id() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(no_tenants(), &exec, &["setup"], b"y\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.pam_ops(),
        vec![PamOp::EnableTouchIdForSudo],
        "accept must execute the Touch-ID op exactly once"
    );
    assert!(
        stdout.contains("Touch ID for sudo enabled"),
        "success line expected; stdout={stdout:?}"
    );
}

// ----- Decline paths -----

#[test]
fn setup_offer_declined_does_nothing() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(no_tenants(), &exec, &["setup"], b"n\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(exec.pam_ops().is_empty(), "decline must execute nothing");
    assert!(
        stdout.contains("Skipped Touch ID"),
        "skip line expected; stdout={stdout:?}"
    );
}

#[test]
fn setup_offer_defaults_to_no_on_empty_input() {
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_stdin(no_tenants(), &exec, &["setup"], b"\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        exec.pam_ops().is_empty(),
        "empty input must default to decline"
    );
}

#[test]
fn setup_eof_on_prompt_declines() {
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_stdin(no_tenants(), &exec, &["setup"], b"");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(exec.pam_ops().is_empty(), "EOF on the prompt must decline");
}

#[test]
fn setup_reprompts_on_unrecognized_then_accepts() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(no_tenants(), &exec, &["setup"], b"maybe\ny\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.pam_ops(),
        vec![PamOp::EnableTouchIdForSudo],
        "reprompt then 'y' must enable"
    );
    assert!(
        stdout.contains("Please answer y or n."),
        "unrecognized input should reprompt; stdout={stdout:?}"
    );
}

// ----- --yes (scripted) -----

#[test]
fn setup_yes_flag_enables_without_prompt() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(no_tenants(), &exec, &["-y", "setup"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.pam_ops(),
        vec![PamOp::EnableTouchIdForSudo],
        "--yes must execute the Touch-ID op"
    );
    assert!(
        !stdout.contains("[y/N]"),
        "--yes must not print a prompt; stdout={stdout:?}"
    );
}

// ----- Non-TTY without --yes: the key divergence -----

#[test]
fn setup_non_tty_without_yes_declines() {
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(no_tenants(), &exec, &["setup"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        exec.pam_ops().is_empty(),
        "non-TTY without --yes must not enable Touch ID"
    );
}

// ----- Dry-run preview -----

#[test]
fn setup_dry_run_previews_without_executing() {
    // The dry-run substrate wraps the stub, so its pam_ops stays empty.
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(no_tenants(), &exec, &["--dry-run", "setup"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        exec.pam_ops().is_empty(),
        "dry-run must not touch the real substrate"
    );
    assert!(
        stdout.contains("(Real run would prompt:"),
        "dry-run should preview the prompt; stdout={stdout:?}"
    );
}

// ----- Verbose mechanism echo -----

#[test]
fn setup_verbose_shows_mechanism() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(no_tenants(), &exec, &["-v", "-y", "setup"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("sudo tee -a /etc/pam.d/sudo_local"),
        "verbose should echo the append mechanism; stdout={stdout:?}"
    );
}

// ----- Substrate failure -----

#[test]
fn setup_pam_failure_surfaces_io_error() {
    let exec = StubHostMachine::new().fail_next_pam(tenant::domain::HostFileError::NonZero {
        code: 1,
        stderr: "tee: permission denied".to_string(),
    });
    let (code, _stdout, stderr) = run_with_exec(no_tenants(), &exec, &["-y", "setup"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(
        stderr.contains("failed to enable Touch ID for sudo"),
        "stderr should carry the setup failure frame; got: {stderr:?}"
    );
}
