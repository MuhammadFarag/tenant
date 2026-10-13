use tenant::domain::{KeychainError, KeychainOp, KeychainPassword, ProbeError, TenantUserName};

mod adapters;
mod common;
use adapters::*;
use common::*;

fn dev() -> TenantUserName {
    TenantUserName::from("dev")
}

fn provision_ops(password: &KeychainPassword) -> Vec<KeychainOp> {
    vec![
        KeychainOp::CreateTenantKeychain {
            name: dev(),
            password: password.clone(),
        },
        KeychainOp::SetDefaultKeychain { name: dev() },
        KeychainOp::AddKeychainToSearchList { name: dev() },
        KeychainOp::DisableKeychainAutoLock { name: dev() },
        KeychainOp::StashPassword {
            name: dev(),
            password: password.clone(),
        },
    ]
}

const PROVISION_CHECKS: [&str; 5] = [
    "Tenant 'dev' keychain created",
    "Tenant 'dev' default keychain set",
    "Tenant 'dev' keychain added to search list",
    "Tenant 'dev' keychain auto-lock disabled",
    "Tenant 'dev' password stashed in operator keychain",
];

const RESET_CLOSING: &str = "Tenant 'dev' keychain reset; apps inside it sign in again once.";
const RESET_BREADCRUMB: &str = "Next: verify with `tenant doctor dev`.";

#[test]
fn reset_moves_the_keychain_aside_and_recreates_it_keyed_to_the_stash() {
    let stash = KeychainPassword::test_dummy("stashed");
    let exec = StubHostMachine::new().with_stash("dev", stash.clone());
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["keychain", "dev", "reset", "-y"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let mut want_ops = vec![KeychainOp::MoveTenantKeychainAside { name: dev() }];
    want_ops.extend(provision_ops(&stash));
    assert_eq!(exec.keychain_ops(), want_ops);
    let mut checks = vec!["Tenant 'dev' old keychain moved aside"];
    checks.extend(PROVISION_CHECKS);
    assert_eq!(
        stdout,
        real_success_stdout_with_breadcrumb(
            "Resetting tenant 'dev' keychain",
            &checks,
            RESET_CLOSING,
            Some(RESET_BREADCRUMB),
        )
    );
}

#[test]
fn reset_with_no_keychain_file_skips_the_move() {
    let stash = KeychainPassword::test_dummy("stashed");
    let exec = StubHostMachine::new()
        .with_stash("dev", stash.clone())
        .with_tenant_keychain_present("dev", false);
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["keychain", "dev", "reset", "-y"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(exec.keychain_ops(), provision_ops(&stash));
}

#[test]
fn reset_without_a_stash_generates_and_stashes_a_fresh_password() {
    let exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["keychain", "dev", "reset", "-y"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    let ops = exec.keychain_ops();
    let (
        KeychainOp::CreateTenantKeychain {
            password: keyed, ..
        },
        KeychainOp::StashPassword {
            password: stashed, ..
        },
    ) = (&ops[1], &ops[5])
    else {
        panic!("unexpected ops: {ops:?}");
    };
    assert_eq!(keyed, stashed, "keychain and stash must share one password");
}

#[test]
fn reset_refuses_an_absent_tenant_without_touching_the_host() {
    let (code, _stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["keychain", "dev", "reset", "-y"],
    );
    assert_eq!(code, 64);
    assert_eq!(
        stderr,
        "tenant: cannot reset keychain for 'dev': does not exist\n"
    );
}

#[test]
fn reset_refuses_an_invalid_name_without_touching_the_host() {
    let (code, _stdout, stderr) = run_with(
        StubUserDirectory::default(),
        &["keychain", "Dev", "reset", "-y"],
    );
    assert_eq!(code, 64, "stderr={stderr:?}");
}

#[test]
fn reset_prompts_default_no_and_aborts_on_enter() {
    let exec = StubHostMachine::new().with_default_stash("dev");
    let (code, stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["keychain", "dev", "reset"],
        b"\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(stderr.contains("Proceed? [y/N] "), "stderr={stderr:?}");
    assert!(
        stdout.starts_with(
            "About to reset tenant 'dev' keychain.\n\
             \n\
             This will:\n  \
             \u{2022} move /Users/dev/Library/Keychains/tenant.keychain-db aside to \
             tenant.keychain-db.replaced-<UTC timestamp> (if present)\n  \
             \u{2022} create an empty tenant.keychain-db keyed to the stashed password \
             (a fresh one if the stash is missing)\n  \
             \u{2022} make it the tenant's default and only keychain, with auto-lock off\n\
             \n\
             Apps inside the tenant sign in again once.\n\
             \n\
             Sudo needed for: keychain reset.\n\
             \n"
        ),
        "stdout={stdout:?}"
    );
    assert!(stdout.ends_with("Aborted by operator. No changes made.\n"));
    assert!(exec.keychain_ops().is_empty());
}

#[test]
fn reset_proceeds_on_explicit_y() {
    let exec = StubHostMachine::new().with_default_stash("dev");
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("dev"),
        &exec,
        &["keychain", "dev", "reset"],
        b"y\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(exec.keychain_ops().len(), 6);
}

#[test]
fn reset_step_failure_exits_74_and_names_the_step() {
    let exec = StubHostMachine::new()
        .with_default_stash("dev")
        .fail_next_keychain_create(KeychainError::NonZero {
            code: 1,
            stderr: "synthetic".to_string(),
        });
    let (code, stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["keychain", "dev", "reset", "-y"],
    );
    assert_eq!(code, 74);
    assert_eq!(
        stdout,
        real_failure_stdout(
            "Resetting tenant 'dev' keychain",
            &["Tenant 'dev' old keychain moved aside"],
        )
    );
    assert_eq!(
        stderr,
        "tenant: failed to reset keychain for 'dev': security exited with code 1: synthetic \
         \u{2014} re-run `tenant keychain dev reset` once the cause is fixed\n"
    );
}

#[test]
fn reset_stash_read_failure_exits_74_before_any_change() {
    let exec = StubHostMachine::new().fail_next_find_stashed_password(KeychainError::NonZero {
        code: 1,
        stderr: "synthetic".to_string(),
    });
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["keychain", "dev", "reset", "-y"],
    );
    assert_eq!(code, 74);
    assert_eq!(
        stderr,
        "tenant: failed to read the stashed password for 'dev': \
         security exited with code 1: synthetic\n"
    );
    assert!(exec.keychain_ops().is_empty());
}

#[test]
fn reset_keychain_probe_failure_exits_74_before_any_change() {
    let exec = StubHostMachine::new()
        .with_default_stash("dev")
        .fail_next_tenant_keychain_probe(ProbeError::Spawn(std::io::Error::other("boom")));
    let (code, _stdout, stderr) = run_with_exec(
        stub_with_tenant("dev"),
        &exec,
        &["keychain", "dev", "reset", "-y"],
    );
    assert_eq!(code, 74);
    assert!(
        stderr.starts_with("tenant: failed to reset keychain for 'dev': "),
        "stderr={stderr:?}"
    );
    assert!(exec.keychain_ops().is_empty());
}

#[test]
fn reset_dry_run_previews_the_plan_without_changes() {
    let (code, stdout, stderr) = run_with(
        stub_with_tenant("dev"),
        &["keychain", "dev", "reset", "--dry-run", "-v"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains(
            "  \u{2022} Move tenant 'dev' keychain aside  # if present\n      \
             sudo -u dev /bin/mv -n /Users/dev/Library/Keychains/tenant.keychain-db \
             /Users/dev/Library/Keychains/tenant.keychain-db.replaced-<UTC timestamp>\n"
        ),
        "stdout={stdout:?}"
    );
    assert!(
        stdout.ends_with("(Real run would prompt: Proceed? [y/N])\n"),
        "stdout={stdout:?}"
    );
}

#[test]
fn keychain_rejects_an_unknown_action() {
    let (code, _stdout, stderr) = run_with(stub_with_tenant("dev"), &["keychain", "dev", "wipe"]);
    assert_eq!(code, 2, "stderr={stderr:?}");
}
