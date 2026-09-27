use tenant::domain::{PamOp, SudoersOp};

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
    let (code, _stdout, stderr) = run_with_stdin(no_tenants(), &exec, &["setup"], b"maybe\ny\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.pam_ops(),
        vec![PamOp::EnableTouchIdForSudo],
        "reprompt then 'y' must enable"
    );
    assert!(
        stderr.contains("Please answer y or n."),
        "unrecognized input should reprompt; stdout={stderr:?}"
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

// ----- SSH agent strip (sudoers drop-in) -----

const SSH_AGENT_OFFER: &str = "Keep your ssh-agent out of tenant sessions
  `tenant shell` runs through sudo, which forwards SSH_AUTH_SOCK, so code in a
  tenant can use (not read) your SSH keys while a session is open. Writes
  `Defaults env_delete += \"SSH_AUTH_SOCK\"` to /etc/sudoers.d/tenant, checked
  with `visudo` first. Host-wide: no sudo command gets your agent any more
  (`sudo git ...` included). Inside tenants, git over ssh needs the tenant's own key.
";

#[test]
fn setup_offers_the_ssh_agent_strip_with_its_host_wide_effect_and_applies_on_yes() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(no_tenants(), &exec, &["setup"], b"n\ny\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(stdout.contains(SSH_AGENT_OFFER), "stdout={stdout:?}");
    assert!(exec.pam_ops().is_empty());
    assert_eq!(exec.sudoers_ops(), vec![SudoersOp::DeleteSshAuthSockEnv]);
    assert!(
        stdout.contains("SSH_AUTH_SOCK removed from sudo sessions in /etc/sudoers.d/tenant"),
        "stdout={stdout:?}"
    );
}

#[test]
fn setup_ssh_agent_strip_declined_writes_nothing() {
    let exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_stdin(no_tenants(), &exec, &["setup"], b"y\nn\n");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(exec.sudoers_ops().is_empty());
    assert!(
        stdout.contains("Skipped ssh-agent strip."),
        "stdout={stdout:?}"
    );
}

#[test]
fn setup_yes_applies_both_items_and_non_tty_applies_neither() {
    let exec = StubHostMachine::new();
    let (code, _stdout, _stderr) = run_with_exec(no_tenants(), &exec, &["-y", "setup"]);
    assert_eq!(code, 0);
    assert_eq!(exec.sudoers_ops(), vec![SudoersOp::DeleteSshAuthSockEnv]);

    let exec = StubHostMachine::new();
    let (code, _stdout, _stderr) = run_with_exec(no_tenants(), &exec, &["setup"]);
    assert_eq!(code, 0);
    assert!(exec.sudoers_ops().is_empty());
}

#[test]
fn setup_sudoers_failure_names_the_drop_in_and_exits_74() {
    let exec = StubHostMachine::new().fail_next_sudoers(tenant::domain::HostFileError::NonZero {
        code: 1,
        stderr: "visudo: syntax error".to_string(),
    });
    let (code, _stdout, stderr) = run_with_exec(no_tenants(), &exec, &["-y", "setup"]);
    assert_eq!(code, 74);
    assert_eq!(
        stderr,
        "tenant: failed to update /etc/sudoers.d/tenant: sudo read exited with code 1: visudo: syntax \
         error \u{2014} nothing was installed unless visudo accepted it\n"
    );
}
