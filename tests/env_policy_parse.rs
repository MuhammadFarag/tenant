//! Unit tests for `doctor::has_env_delete_for`: combinatorial over sudoers `env_delete` shapes.

use tenant::doctor::has_env_delete_for;

// --- Positive cases ---

#[test]
fn detects_plus_equals_quoted_single_var() {
    let policy = "Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_equals_quoted_single_var() {
    let policy = "Defaults env_delete = \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_quoted_multi_var_list() {
    let policy = "Defaults env_delete += \"FOO SSH_AUTH_SOCK BAR\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_unquoted_single_var() {
    let policy = "Defaults env_delete += SSH_AUTH_SOCK\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_with_leading_whitespace() {
    let policy = "    Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn detects_across_multiple_lines() {
    let policy = "# Comment line\n\
                  Defaults env_keep += \"PATH\"\n\
                  Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

// Qualified `Defaults` forms don't reliably cover `sudo -u <tenant>`, so they don't count.

#[test]
fn rejects_defaults_runas_qualifier() {
    let policy = "Defaults>plugin-dev env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn rejects_defaults_user_qualifier() {
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
    let policy = "Defaults>plugin-dev env_delete += \"SSH_AUTH_SOCK\"\n\
                  Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    assert!(has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

// --- Negative cases ---

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
    let policy = "Defaults env_delete += \"FOO BAR BAZ\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn substring_in_other_var_not_matched() {
    let policy = "Defaults env_delete += \"SSH_AUTH_SOCK_BUDDY\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn env_keep_for_target_var_does_not_block_leak() {
    let policy = "Defaults env_keep += \"SSH_AUTH_SOCK\"\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}

#[test]
fn random_text_returns_false() {
    let policy = "This is a README, not sudoers\nMaybe SSH_AUTH_SOCK appears here\n";
    assert!(!has_env_delete_for(policy, "SSH_AUTH_SOCK"));
}
