//! Unit tests for `doctor::sudo_strips_env_var`: combinatorial over sudoers env-list shapes.

use tenant::doctor::sudo_strips_env_var;

const VAR: &str = "SSH_AUTH_SOCK";

// --- Positive: `env_keep -=` is what removes a var under env_reset (the macOS default) ---

#[test]
fn detects_quoted_single_var() {
    assert!(sudo_strips_env_var(
        "Defaults env_keep -= \"SSH_AUTH_SOCK\"\n",
        VAR
    ));
}

#[test]
fn detects_quoted_multi_var_list() {
    assert!(sudo_strips_env_var(
        "Defaults env_keep -= \"FOO SSH_AUTH_SOCK BAR\"\n",
        VAR
    ));
}

#[test]
fn detects_unquoted_single_var() {
    assert!(sudo_strips_env_var(
        "Defaults env_keep -= SSH_AUTH_SOCK\n",
        VAR
    ));
}

#[test]
fn detects_with_leading_whitespace_across_lines() {
    let policy = "# Comment line\n\
                  Defaults env_keep += \"PATH\"\n\
                  \t  Defaults env_keep -= \"SSH_AUTH_SOCK\"\n";
    assert!(sudo_strips_env_var(policy, VAR));
}

#[test]
fn unqualified_defaults_alongside_qualified_still_detects() {
    let policy = "Defaults>plugin-dev env_keep -= \"SSH_AUTH_SOCK\"\n\
                  Defaults env_keep -= \"SSH_AUTH_SOCK\"\n";
    assert!(sudo_strips_env_var(policy, VAR));
}

// --- Negative ---

// Ignored while env_reset is on, so it strips nothing on a default host.
#[test]
fn env_delete_does_not_count() {
    assert!(!sudo_strips_env_var(
        "Defaults env_delete += \"SSH_AUTH_SOCK\"\n",
        VAR
    ));
}

#[test]
fn env_keep_add_or_replace_keeps_the_var() {
    assert!(!sudo_strips_env_var(
        "Defaults env_keep += \"SSH_AUTH_SOCK\"\n",
        VAR
    ));
    assert!(!sudo_strips_env_var(
        "Defaults env_keep = \"SSH_AUTH_SOCK\"\n",
        VAR
    ));
}

// Qualified `Defaults` forms don't reliably cover `sudo -u <tenant>`, so they don't count.
#[test]
fn rejects_qualified_defaults() {
    for qualifier in [">plugin-dev", ":alice", "@somehost", "!SUDO_EDITOR"] {
        let policy = format!("Defaults{qualifier} env_keep -= \"SSH_AUTH_SOCK\"\n");
        assert!(!sudo_strips_env_var(&policy, VAR), "{qualifier}");
    }
}

#[test]
fn other_vars_substrings_and_prose_do_not_match() {
    for policy in [
        "",
        "Defaults env_keep -= \"FOO BAR\"\n",
        "Defaults env_keep -= \"SSH_AUTH_SOCK_BUDDY\"\n",
        "Defaults env_keep_extra -= \"SSH_AUTH_SOCK\"\n",
        "This is a README, not sudoers\nMaybe SSH_AUTH_SOCK appears here\n",
    ] {
        assert!(!sudo_strips_env_var(policy, VAR), "{policy:?}");
    }
}

// sudo applies Defaults in file order, so a later `+=` re-adds what an earlier `-=` removed.
#[test]
fn a_later_add_back_wins() {
    let policy = "Defaults env_keep -= \"SSH_AUTH_SOCK\"\n\
                  Defaults env_keep += \"SSH_AUTH_SOCK\"\n";
    assert!(!sudo_strips_env_var(policy, VAR));
    let policy = "Defaults env_keep += \"SSH_AUTH_SOCK\"\n\
                  Defaults env_keep -= \"SSH_AUTH_SOCK\"\n";
    assert!(sudo_strips_env_var(policy, VAR));
}

#[test]
fn comma_joined_defaults_are_read_per_entry() {
    let policy = "Defaults env_reset, env_keep -= \"SSH_AUTH_SOCK\"\n";
    assert!(sudo_strips_env_var(policy, VAR));
}
