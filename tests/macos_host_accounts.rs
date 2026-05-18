//! `MacosHostAccounts`-vs-dscl integration smoke test. Symmetric with
//! `tests/macos_host_machine.rs`, which pins the `MacosHostMachine::describe_*`
//! argv contract. This file pins that the per-call dscl wired into each
//! `HostAccounts` trait method behaves correctly against a real macOS
//! directory service. Gated on macOS — the rest of the test suite runs
//! on any platform via `StubHostAccounts`.

#[cfg(target_os = "macos")]
use tenant::domain::{GroupName, HostAccounts, TenantUserName, UserId};

#[cfg(target_os = "macos")]
#[test]
fn macos_reader_observes_host_state() {
    // Smoke test that the real `MacosHostAccounts` translates dscl
    // output into the trait return shape the rest of the codebase
    // expects. `root` (UID 0) and `wheel` (group) are universally
    // present on macOS, so this is host-stable.
    let reader = tenant::adapters::macos::MacosHostAccounts;
    assert!(
        reader
            .has_user(&TenantUserName::from("root"))
            .expect("dscl lookup should succeed"),
        "MacosHostAccounts should see 'root' user"
    );
    assert!(
        reader
            .has_group(&GroupName::from("wheel"))
            .expect("dscl lookup should succeed"),
        "MacosHostAccounts should see 'wheel' group"
    );
    assert_eq!(
        reader
            .uid_for(&TenantUserName::from("root"))
            .expect("dscl lookup should succeed"),
        Some(UserId(0)),
        "root's UID should be 0"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_reader_returns_false_for_absent_record() {
    // Per-call dscl pattern-matches `eDSRecordNotFound` to distinguish
    // "absent" (Ok(false) / Ok(None)) from real substrate breakage
    // (Err). This pins the absence-detection contract — a regression
    // that swapped the pattern match for "any nonzero ⇒ absent" would
    // still pass `has_user`, but any other dscl failure would silently
    // report absent instead of erroring.
    let reader = tenant::adapters::macos::MacosHostAccounts;
    assert!(
        !reader
            .has_user(&TenantUserName::from("definitely-not-a-user"))
            .expect("absent-record should resolve cleanly, not error"),
        "absent user should map to Ok(false)"
    );
    assert_eq!(
        reader
            .uid_for(&TenantUserName::from("definitely-not-a-user"))
            .expect("absent-record should resolve cleanly, not error"),
        None,
        "absent user should map to Ok(None)"
    );
}
