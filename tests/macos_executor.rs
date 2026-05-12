//! Per-variant contract pins on `MacosExecutor::describe_account` and
//! `MacosExecutor::describe_profile`. These tests are the one place
//! where the literal shell-command shape of each op lives — the
//! verb-level E2E tests in `cli.rs` already pin the end-to-end output
//! via byte-exact stdout assertions, but those assertions are
//! distributed; if dseditgroup ever moves to `dscl . -create /Groups/…`
//! exactly one test here moves with the renderer change.
//!
//! These ARE unit tests, which crosses the project's "E2E-only"
//! convention. Justified by the per-variant combinatorial coverage
//! that's awkward via the CLI surface — every AccountOp variant has
//! its own argv shape, and routing each through a verb (some of which
//! aren't even reachable from a single CLI invocation, like
//! `LoginAsUser` which doesn't share a verb with the dscl probes) means
//! N independent E2E tests, all asserting on tiny substrings of a
//! larger stdout block. A focused per-variant test reads cleaner and
//! catches drift more precisely.

use tenant::executor::{AccountOp, Executor, MacosExecutor, ProfileOp};

#[test]
fn macos_describes_create_share_group() {
    let s = MacosExecutor;
    assert_eq!(
        s.describe_account(&AccountOp::CreateShareGroup {
            name: "dev".into(),
            gid: 600
        }),
        "sudo dseditgroup -o create -n . -i 600 dev-tenant-share",
    );
}

#[test]
fn macos_describes_delete_share_group() {
    let s = MacosExecutor;
    assert_eq!(
        s.describe_account(&AccountOp::DeleteShareGroup { name: "dev".into() }),
        "sudo dseditgroup -o delete -n . dev-tenant-share",
    );
}

#[test]
fn macos_describes_create_tenant_user() {
    let s = MacosExecutor;
    assert_eq!(
        s.describe_account(&AccountOp::CreateTenantUser {
            name: "dev".into(),
            uid: 600,
            gid: 600
        }),
        "sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" \
         -shell /bin/zsh -UID 600 -GID 600",
    );
}

#[test]
fn macos_describes_delete_tenant_user() {
    let s = MacosExecutor;
    assert_eq!(
        s.describe_account(&AccountOp::DeleteTenantUser { name: "dev".into() }),
        "sudo sysadminctl -deleteUser dev",
    );
}

#[test]
fn macos_describes_lookup_user_record() {
    let s = MacosExecutor;
    assert_eq!(
        s.describe_account(&AccountOp::LookupUserRecord { name: "dev".into() }),
        "dscl . -read /Users/dev",
    );
}

#[test]
fn macos_describes_delete_user_record() {
    let s = MacosExecutor;
    assert_eq!(
        s.describe_account(&AccountOp::DeleteUserRecord { name: "dev".into() }),
        "sudo dscl . -delete /Users/dev",
    );
}

#[test]
fn macos_describes_login_as_user() {
    let s = MacosExecutor;
    assert_eq!(
        s.describe_account(&AccountOp::LoginAsUser { name: "dev".into() }),
        "sudo -iu dev",
    );
}

#[test]
fn macos_describes_profile_create() {
    let s = MacosExecutor;
    assert_eq!(
        s.describe_profile(&ProfileOp::Create { name: "dev".into() }),
        "tee ~/.config/tenant/profiles/dev.toml < default.toml",
    );
}

#[test]
fn macos_describes_profile_delete() {
    let s = MacosExecutor;
    assert_eq!(
        s.describe_profile(&ProfileOp::Delete { name: "dev".into() }),
        "rm -f ~/.config/tenant/profiles/dev.toml",
    );
}
