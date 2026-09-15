//! Smoke tests of `MacosUserDirectory` against the real macOS directory service.

#[cfg(target_os = "macos")]
use tenant::domain::{GroupName, HostUserDirectory, TenantUserName, UserId};

#[cfg(target_os = "macos")]
#[test]
fn macos_reader_observes_host_state() {
    // `root` and `wheel` exist on every macOS host.
    let reader = tenant::adapters::macos::MacosUserDirectory;
    assert!(
        reader
            .has_user(&TenantUserName::from("root"))
            .expect("dscl lookup should succeed"),
        "MacosUserDirectory should see 'root' user"
    );
    assert!(
        reader
            .has_group(&GroupName::from("wheel"))
            .expect("dscl lookup should succeed"),
        "MacosUserDirectory should see 'wheel' group"
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
    // Only `eDSRecordNotFound` may read as absent; any other dscl failure must stay an Err.
    let reader = tenant::adapters::macos::MacosUserDirectory;
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
