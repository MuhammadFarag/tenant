//! `MacosHostAccounts`-vs-dscl integration smoke test. Symmetric with
//! `tests/macos_executor.rs`, which pins the `MacosExecutor::describe_*`
//! argv contract. This file pins that `MacosHostAccounts::new()` translates
//! dscl output into the in-memory snapshot the rest of the codebase
//! expects. Gated on macOS — the rest of the test suite runs on any
//! platform via `StubHostAccounts`.

#[cfg(target_os = "macos")]
use tenant::domain::HostAccounts;
#[cfg(target_os = "macos")]
use tenant::ids::{GroupName, TenantUserName, UserId};

#[cfg(target_os = "macos")]
#[test]
fn macos_reader_observes_host_state() {
    // Smoke test that the real `MacosHostAccounts` populates correctly from
    // dscl. Was originally an end-to-end `tenant create root --dry-run`
    // assertion, but Phase 2's reserved-name blocklist now refuses
    // `root` at the lexical layer before dispatch reaches the HostAccounts —
    // which means the old test no longer exercises dscl integration.
    // Direct HostAccounts assertions instead: `root` (UID 0) and `wheel`
    // (group) are universally present on macOS, so this is host-stable
    // and proves the dscl → MacosHostAccounts translation works end-to-end
    // for both the user listing and the group listing. The dispatch
    // path is already extensively covered via StubHostAccounts.
    let reader = tenant::adapters::macos::MacosHostAccounts::new()
        .expect("dscl should be available on macOS");
    assert!(
        reader.has_user(&TenantUserName::from("root")),
        "MacosHostAccounts should see 'root' user"
    );
    assert!(
        reader.has_group(&GroupName::from("wheel")),
        "MacosHostAccounts should see 'wheel' group"
    );
    assert_eq!(
        reader.uid_for(&TenantUserName::from("root")),
        Some(UserId(0)),
        "root's UID should be 0 in the in-memory map"
    );
}
