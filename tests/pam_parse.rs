//! Unit tests for `doctor::has_pam_tid`: combinatorial over pam.d line shapes.

use tenant::doctor::has_pam_tid;

// --- Positive cases ---

#[test]
fn detects_canonical_directive() {
    let pam = "auth       sufficient     pam_tid.so\n";
    assert!(has_pam_tid(pam));
}

#[test]
fn detects_directive_single_space_separated() {
    let pam = "auth sufficient pam_tid.so\n";
    assert!(has_pam_tid(pam));
}

#[test]
fn detects_directive_with_leading_whitespace() {
    let pam = "    auth       sufficient     pam_tid.so\n";
    assert!(has_pam_tid(pam));
}

#[test]
fn detects_directive_in_realistic_pam_d_sudo() {
    let pam = "# sudo: auth account password session\n\
               auth       sufficient     pam_tid.so\n\
               auth       sufficient     pam_smartcard.so\n\
               auth       required       pam_opendirectory.so\n\
               account    required       pam_permit.so\n\
               password   required       pam_deny.so\n\
               session    required       pam_permit.so\n";
    assert!(has_pam_tid(pam));
}

#[test]
fn detects_directive_anywhere_in_stack() {
    let pam = "auth       required       pam_opendirectory.so\n\
               auth       sufficient     pam_tid.so\n";
    assert!(has_pam_tid(pam));
}

// --- Negative cases ---

#[test]
fn empty_input_returns_false() {
    assert!(!has_pam_tid(""));
}

#[test]
fn whitespace_only_returns_false() {
    assert!(!has_pam_tid("   \n\t\n\n"));
}

#[test]
fn commented_directive_returns_false() {
    let pam = "# auth       sufficient     pam_tid.so\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn commented_with_leading_whitespace_returns_false() {
    let pam = "    # auth       sufficient     pam_tid.so\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn wrong_control_field_returns_false() {
    let pam = "auth       required       pam_tid.so\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn wrong_kind_field_returns_false() {
    let pam = "session    sufficient     pam_tid.so\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn different_module_returns_false() {
    let pam = "auth       sufficient     pam_smartcard.so\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn missing_module_field_returns_false() {
    let pam = "auth       sufficient\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn pam_d_without_tid_returns_false() {
    let pam = "# sudo: auth account password session\n\
               auth       sufficient     pam_smartcard.so\n\
               auth       required       pam_opendirectory.so\n\
               account    required       pam_permit.so\n\
               password   required       pam_deny.so\n\
               session    required       pam_permit.so\n";
    assert!(!has_pam_tid(pam));
}
