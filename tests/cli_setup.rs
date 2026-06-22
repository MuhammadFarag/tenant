use tenant::domain::PamOp;

mod adapters;
mod common;
use adapters::*;
use common::*;

// ================================================================
// Setup verb — host-wide, opt-in host preparation
// ================================================================
//
// `tenant setup` is NOT a per-tenant verb: no name argument, no
// eligibility/name checks, no pre-exec doctor pass. It presents a
// menu of opt-in host-prep items (today exactly one: Touch ID for
// sudo) and offers each. Key divergences from the convergent verbs:
//
// - Per-item offer defaults to NO (`[y/N]`) — it's an auth-stack
//   change and an optional preference, not a converge-to-declared
//   state.
// - Non-TTY without `--yes` DECLINES (no-op), unlike create/destroy
//   which proceed on non-TTY. An auth change must never auto-apply
//   from a pipe.
// - `--yes` accepts every item (scripted host bootstrap).
// - No pre-probe for "already enabled": the item is always offered;
//   `PamOp::EnableTouchIdForSudo` is substrate-idempotent (no-ops if
//   Touch ID is already on in either pam file). This keeps `--dry-run`
//   honest (shows the plan, never gated on placeholder host state).
//
// E2E through `tenant::run`: `run_with_stdin` simulates a TTY (offer
// fires), `run_with_exec` is non-TTY (auto-decision).

fn no_tenants() -> StubUserDirectory {
    StubUserDirectory::default()
}

// ----- Accept path -----

#[test]
fn setup_offer_accepted_enables_touch_id() {
    // TTY, operator answers "y" → the Touch-ID PamOp executes exactly
    // once; exit 0; success surface names the enabled state.
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
    // TTY, "n" → no PamOp, exit 0, a skip line.
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
    // TTY, bare ENTER → default NO (auth change is opt-in). No PamOp.
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
    // TTY but stdin closes immediately (EOF) → decline (the prompt's
    // `read_line` returns Ok(0)). No PamOp, exit 0.
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_stdin(no_tenants(), &exec, &["setup"], b"");
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(exec.pam_ops().is_empty(), "EOF on the prompt must decline");
}

#[test]
fn setup_reprompts_on_unrecognized_then_accepts() {
    // Unrecognized input reprompts (does not decline); a following "y"
    // proceeds. Pins the offer's reprompt loop (distinct from `confirm`).
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
    // `--yes` (non-TTY) accepts the item without prompting.
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
    // run_with_exec is non-TTY. Without `--yes`, setup must DECLINE the
    // auth-stack change rather than auto-proceed (the opposite of
    // create/destroy). No PamOp; exit 0.
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
    // --dry-run swaps in the DryRun substrate (the stub is wrapped, so
    // its pam_ops stays empty) and previews the would-prompt line. No
    // real mutation.
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
    // `-v` exposes the substrate mechanism (the sudo_local append) so
    // the operator can see exactly what enabling Touch ID runs.
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
    // execute_pam fails → EX_IOERR (74) + a stderr failure frame.
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
