//! Combinatorial unit tests for `doctor::has_env_delete_for` — the
//! sudoers `env_delete` directive parser.
//!
//! Justification (per CLAUDE.md test discipline): the parser's input
//! space is combinatorial over directive shape (`=` vs `+=`, quoted
//! vs unquoted, single-var vs multi-var list, `Defaults` qualifiers)
//! and per-shape E2E coverage would be redundant. The parser is a
//! pure function so unit-level testing is the right tool.

use tenant::doctor::has_env_delete_for;

// ============================================================
// Positive cases — the directive IS present
// ============================================================

#[test]
fn detects_plus_equals_quoted_single_var() {
    let policy = "Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_equals_quoted_single_var() {
    // `=` (not `+=`) is the bare-assignment form. Less common but
    // still valid sudoers syntax — the operator may have set the
    // whole env_delete list explicitly.
    let policy = "Defaults env_delete = \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_quoted_multi_var_list() {
    // Multiple vars in one directive — parser tokenizes by
    // whitespace inside the quoted value.
    let policy = "Defaults env_delete += \"FOO SSH_AUTH_SOCK BAR\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_unquoted_single_var() {
    // Bare token form, no quotes. Sudoers permits this for a single
    // var with no whitespace.
    let policy = "Defaults env_delete += SSH_AUTH_SOCK\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_with_leading_whitespace() {
    // Indented directive (some sites prefix-indent for readability).
    let policy = "    Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_across_multiple_lines() {
    // The directive lives on a non-first line — parser walks every
    // line, doesn't short-circuit on the first non-matching one.
    let policy = "# Comment line\n\
                  Defaults env_keep += \"PATH\"\n\
                  Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

// Negative pin: qualified `Defaults` forms restrict the directive's
// scope and don't reliably protect tenant invocations, so the parser
// rejects them. The smoke from `2026-05-13` surfaced this exact
// shape — `Defaults>plugin-dev env_delete += "SSH_AUTH_SOCK"` in
// `/etc/sudoers.d/sandbox-access` was wrongly being treated as
// universal, masking the actual leak for tenant sessions.

#[test]
fn rejects_defaults_runas_qualifier() {
    // `Defaults>runas env_delete +=` applies ONLY when sudo's target
    // user (`-u <name>`) matches `runas`. For `sudo -u <tenant>`,
    // this directive doesn't fire — so it doesn't protect the
    // tenant's env from leak. Conservative: parser rejects.
    let policy = "Defaults>plugin-dev env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn rejects_defaults_user_qualifier() {
    // `Defaults:user env_delete +=` applies when invoking user
    // matches `user`. Even if it covers the operator's sudo invocation
    // for this run, it doesn't generalize to other invokers. Parser
    // rejects all qualified forms in cycle 1.
    let policy = "Defaults:alice env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn rejects_defaults_host_qualifier() {
    let policy = "Defaults@somehost env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn rejects_defaults_cmnd_qualifier() {
    let policy = "Defaults!SUDO_EDITOR env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn unqualified_defaults_alongside_qualified_still_detects() {
    // Mixed file: a qualified directive AND an unqualified one. The
    // unqualified one applies universally, so the parser returns
    // true. Pins that qualified rejection doesn't accidentally skip
    // later unqualified lines.
    let policy = "Defaults>plugin-dev env_delete += \"SSH_AUTH_SOCK\"\n\
                  Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

// ============================================================
// Negative cases — directive ABSENT or unrelated
// ============================================================

#[test]
fn empty_policy_returns_false() {
    assert!(!has_env_delete_for("", "SSH_AUTH_SOCK"));
}

#[test]
fn no_env_delete_directive_returns_false() {
    let policy = "Defaults env_keep += \"PATH HOME\"\nDefaults timestamp_timeout = 5\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn env_delete_for_different_var_returns_false() {
    // Parser must token-match, not substring-match — a directive for
    // a DIFFERENT var shouldn't satisfy the query.
    let policy = "Defaults env_delete += \"FOO BAR BAZ\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn substring_in_other_var_not_matched() {
    // `SSH_AUTH_SOCK_BUDDY` contains `SSH_AUTH_SOCK` as a substring;
    // parser must reject. Pin against a naive `policy.contains(var)`
    // implementation.
    let policy = "Defaults env_delete += \"SSH_AUTH_SOCK_BUDDY\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn env_keep_for_target_var_does_not_block_leak() {
    // `env_keep` is the OPPOSITE directive — it keeps the var in
    // the env (the leak case). A `env_keep += "SSH_AUTH_SOCK"`
    // directive must NOT be reported as `has_env_delete_for`.
    let policy = "Defaults env_keep += \"SSH_AUTH_SOCK\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn random_text_returns_false() {
    let policy = "This is a README, not sudoers\nMaybe SSH_AUTH_SOCK appears here\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}
