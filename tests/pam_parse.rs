//! Combinatorial unit tests for `doctor::has_pam_tid` — the
//! `/etc/pam.d/sudo` Touch-ID directive parser.
//!
//! Justification (per CLAUDE.md test discipline): the parser's
//! input space is combinatorial over pam.d shape — comment vs
//! active, `sufficient` vs `required` vs `optional`, leading
//! whitespace, blank lines, multi-line files with the directive at
//! different positions. Per-shape E2E coverage would be redundant.
//! The parser is pure so unit-level testing is the right tool.

use tenant::doctor::has_pam_tid;

// ============================================================
// Positive cases — directive is present and active
// ============================================================

#[test]
fn detects_canonical_directive() {
    let pam = "auth       sufficient     pam_tid.so\n";
    assert!(has_pam_tid(pam));
}

#[test]
fn detects_directive_single_space_separated() {
    // Tab + space tolerance: tokens separated by any whitespace.
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
    // The shape an operator would see after enabling Touch ID per
    // Apple's documentation: `pam_tid` first, then the
    // smartcard / opendirectory fallbacks. Pin that doctor's
    // parser doesn't get confused by the surrounding stack.
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
    // Even if pam_tid is the LAST entry, the parser finds it.
    let pam = "auth       required       pam_opendirectory.so\n\
               auth       sufficient     pam_tid.so\n";
    assert!(has_pam_tid(pam));
}

// ============================================================
// Negative cases — directive absent or inactive
// ============================================================

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
    // Active comment line — pam.d ignores it.
    let pam = "# auth       sufficient     pam_tid.so\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn commented_with_leading_whitespace_returns_false() {
    // Indented commented line — pam.d still ignores it.
    let pam = "    # auth       sufficient     pam_tid.so\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn wrong_control_field_returns_false() {
    // `required` is not `sufficient`. The Q-lock in `has_pam_tid`'s
    // doc-comment justifies the conservative-false posture: a
    // `required` pam_tid doesn't short-circuit, so the UX guarantee
    // doesn't hold. Operator must use `sufficient` to satisfy the
    // check.
    let pam = "auth       required       pam_tid.so\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn wrong_kind_field_returns_false() {
    // `session sufficient pam_tid.so` is nonsensical but
    // syntactically valid pam.d. Parser must reject (kind != auth).
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
    // Truncated line — only two tokens. Parser must not panic
    // and must return false.
    let pam = "auth       sufficient\n";
    assert!(!has_pam_tid(pam));
}

#[test]
fn pam_d_without_tid_returns_false() {
    // The canonical macOS pre-Touch-ID `/etc/pam.d/sudo` shape —
    // no pam_tid directive at all. Parser returns false → operator
    // sees the Touch-ID-missing tip.
    let pam = "# sudo: auth account password session\n\
               auth       sufficient     pam_smartcard.so\n\
               auth       required       pam_opendirectory.so\n\
               account    required       pam_permit.so\n\
               password   required       pam_deny.so\n\
               session    required       pam_permit.so\n";
    assert!(!has_pam_tid(pam));
}
