//! `tenant list`: read-only enumeration, one name per line for scripts.

mod adapters;
mod common;

use adapters::*;
use common::*;

// `run_with` wires a machine that panics on any host call: listing needs none.
#[test]
fn list_prints_each_tenant_on_its_own_line() {
    let (code, stdout, stderr) = run_with(make_two_tenant_stub_reader(), &["list"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "dev\nstaging\n");
    assert!(stderr.is_empty(), "stderr={stderr:?}");
}

#[test]
fn ls_is_an_alias_for_list() {
    let (code, stdout, _stderr) = run_with(make_two_tenant_stub_reader(), &["ls"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "dev\nstaging\n");
}

#[test]
fn list_with_no_tenants_keeps_stdout_empty_and_says_so_on_stderr() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["list"]);
    assert_eq!(code, 0);
    assert!(stdout.is_empty(), "stdout={stdout:?}");
    assert_eq!(stderr, "No tenants on this host.\n");
}

#[test]
fn list_surfaces_an_enumeration_failure_as_74() {
    let stub = StubUserDirectory::default();
    stub.fail_tenant_names
        .borrow_mut()
        .push_back(Some(tenant::domain::UserDirectoryError::Spawn(
            std::io::Error::other("dscl missing"),
        )));
    let (code, stdout, stderr) = run_with(stub, &["list"]);
    assert_eq!(code, 74);
    assert!(stdout.is_empty());
    assert!(
        stderr.starts_with("tenant: failed to list tenants: "),
        "stderr={stderr:?}"
    );
}
