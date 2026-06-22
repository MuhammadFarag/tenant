//! Per-variant byte-form pins on `Op::intent_label()` — the future-tense
//! capability label that leads each step in the verbose pre-prompt plan
//! block. Sibling to `Op::business_label()` (past-tense; drives the
//! `✓ <label>` progress lines).
//!
//! These ARE unit tests, which crosses the project's "E2E-only"
//! convention. Justified by the per-variant combinatorial coverage on a
//! pure rendering function — same pattern as `tests/macos_host_machine.rs`
//! (argv per variant). Per-variant rendering bugs are awkward to catch
//! through the verb-level CLI surface because (a) some variants
//! (`LookupUserRecord`, `DeleteUserRecord`, `LoginAsUser`) don't appear
//! in every verb's plan, and (b) the verb-level assertions test the
//! WHOLE plan block, where a single-arm regression is hard to localize.

use std::path::PathBuf;

use tenant::domain::{
    AccountOp, AclMode, AclOp, FirewallOp, GroupId, Op, PamOp, ProfileOp, UserId,
};

#[test]
fn intent_enable_touch_id_for_sudo() {
    let op = PamOp::EnableTouchIdForSudo;
    assert_eq!(
        Op::Pam(&op).intent_label(),
        "Enable Touch ID for sudo in /etc/pam.d/sudo_local"
    );
}

// ============================================================
// Account-domain variants
// ============================================================

#[test]
fn intent_create_share_group() {
    let op = AccountOp::CreateShareGroup {
        group: "dev-tenant-share".into(),
        gid: GroupId(600),
    };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Create share group 'dev-tenant-share' (GID 600)"
    );
}

#[test]
fn intent_delete_share_group() {
    let op = AccountOp::DeleteShareGroup {
        group: "dev-tenant-share".into(),
    };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Remove share group 'dev-tenant-share'"
    );
}

#[test]
fn intent_create_tenant_user() {
    let op = AccountOp::CreateTenantUser {
        name: "dev".into(),
        uid: UserId(600),
        gid: GroupId(600),
    };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Create user account 'dev' (UID 600, GID 600)"
    );
}

#[test]
fn intent_delete_tenant_user() {
    let op = AccountOp::DeleteTenantUser { name: "dev".into() };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Remove user account 'dev' (home moved to /Users/Deleted Users/dev)"
    );
}

#[test]
fn intent_lookup_user_record() {
    let op = AccountOp::LookupUserRecord { name: "dev".into() };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Probe for residue user record 'dev'"
    );
}

#[test]
fn intent_delete_user_record() {
    let op = AccountOp::DeleteUserRecord { name: "dev".into() };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Clean up residue user record 'dev'"
    );
}

#[test]
fn intent_login_as_user() {
    let op = AccountOp::LoginAsUser { name: "dev".into() };
    assert_eq!(Op::Account(&op).intent_label(), "Log in as 'dev'");
}

#[test]
fn intent_exec_as_user() {
    let op = AccountOp::ExecAsUser {
        name: "dev".into(),
        argv: vec!["ls".into(), "/tmp".into()],
    };
    assert_eq!(Op::Account(&op).intent_label(), "Run as 'dev': ls /tmp");
}

#[test]
fn business_exec_as_user_uses_basename() {
    // business_label uses the basename of argv[0] for the ✓ progress
    // line — argv[0] may be an absolute path, but the operator's
    // mental model is "the command 'ls' ran", not "the command
    // '/usr/bin/ls' ran".
    let op = AccountOp::ExecAsUser {
        name: "dev".into(),
        argv: vec!["/usr/local/bin/curl".into(), "https://x".into()],
    };
    assert_eq!(
        Op::Account(&op).business_label(),
        "Command 'curl' executed as 'dev'"
    );
}

#[test]
fn intent_ensure_dir_as_user() {
    let op = AccountOp::EnsureDirAsUser {
        name: "dev".into(),
        path: PathBuf::from("/Users/dev/.local/share"),
    };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Ensure directory /Users/dev/.local/share exists (as tenant)"
    );
}

#[test]
fn intent_ensure_symlink_as_user() {
    let op = AccountOp::EnsureSymlinkAsUser {
        name: "dev".into(),
        link: PathBuf::from("/Users/dev/work"),
        target: PathBuf::from("/Users/operator/projects"),
    };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Install symlink /Users/dev/work \u{2192} /Users/operator/projects (as tenant)"
    );
}

#[test]
fn intent_add_host_to_share_group() {
    let op = AccountOp::AddHostToShareGroup {
        group: "dev-tenant-share".into(),
        host: "operator".into(),
    };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Add host 'operator' to share group 'dev-tenant-share'"
    );
}

#[test]
fn intent_ensure_cowork_dir() {
    let op = AccountOp::EnsureCoworkDir {
        path: PathBuf::from("/Users/Shared/tenants/dev"),
        owner: "operator".into(),
        group: "dev-tenant-share".into(),
        mode: 0o2770,
    };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Ensure co-working directory at /Users/Shared/tenants/dev"
    );
}

#[test]
fn business_ensure_cowork_dir() {
    let op = AccountOp::EnsureCoworkDir {
        path: PathBuf::from("/Users/Shared/tenants/dev"),
        owner: "operator".into(),
        group: "dev-tenant-share".into(),
        mode: 0o2770,
    };
    assert_eq!(
        Op::Account(&op).business_label(),
        "Co-working directory ensured at /Users/Shared/tenants/dev"
    );
}

#[test]
fn intent_remove_host_from_share_group() {
    let op = AccountOp::RemoveHostFromShareGroup {
        group: "dev-tenant-share".into(),
        host: "operator".into(),
    };
    assert_eq!(
        Op::Account(&op).intent_label(),
        "Remove host 'operator' from share group 'dev-tenant-share'"
    );
}

// ============================================================
// Profile-domain variants
// ============================================================

#[test]
fn intent_profile_create() {
    let op = ProfileOp::Create { name: "dev".into() };
    let label = Op::Profile(&op).intent_label();
    // display_path_for renders `~/.config/tenant/profiles/<name>.toml`
    assert_eq!(
        label,
        "Write profile config at ~/.config/tenant/profiles/dev.toml"
    );
}

#[test]
fn intent_profile_delete() {
    let op = ProfileOp::Delete { name: "dev".into() };
    let label = Op::Profile(&op).intent_label();
    assert_eq!(
        label,
        "Remove profile config at ~/.config/tenant/profiles/dev.toml"
    );
}

// ============================================================
// Firewall-domain variants
// ============================================================

#[test]
fn intent_firewall_install_anchor() {
    let op = FirewallOp::InstallAnchor {
        name: "dev".into(),
        body: String::new(),
    };
    assert_eq!(
        Op::Firewall(&op).intent_label(),
        "Install firewall anchor at /etc/pf.anchors/tenant-dev"
    );
}

#[test]
fn intent_firewall_remove_anchor() {
    let op = FirewallOp::RemoveAnchor { name: "dev".into() };
    assert_eq!(
        Op::Firewall(&op).intent_label(),
        "Remove firewall anchor at /etc/pf.anchors/tenant-dev"
    );
}

#[test]
fn intent_firewall_backup_config() {
    let op = FirewallOp::BackupConfig;
    assert_eq!(
        Op::Firewall(&op).intent_label(),
        "Back up /etc/pf.conf to /etc/pf.conf.tenant-backup"
    );
}

#[test]
fn intent_firewall_restore_config_from_backup() {
    let op = FirewallOp::RestoreConfigFromBackup;
    assert_eq!(
        Op::Firewall(&op).intent_label(),
        "Restore /etc/pf.conf from backup"
    );
}

#[test]
fn intent_firewall_update_config() {
    // Content-neutral label: UpdateConfig is used by both create
    // (adds the anchor reference) and destroy (removes it), so the
    // intent stays on the action (`Update /etc/pf.conf`) rather than
    // its directional payload. Matches `business_label`'s shape.
    let op = FirewallOp::UpdateConfig {
        content: String::new(),
    };
    assert_eq!(Op::Firewall(&op).intent_label(), "Update /etc/pf.conf");
}

#[test]
fn intent_firewall_reload() {
    let op = FirewallOp::Reload;
    assert_eq!(Op::Firewall(&op).intent_label(), "Reload pf ruleset");
}

#[test]
fn intent_firewall_flush_anchor() {
    let op = FirewallOp::FlushAnchor { name: "dev".into() };
    assert_eq!(
        Op::Firewall(&op).intent_label(),
        "Flush kernel rules under anchor 'tenant-dev'"
    );
}

#[test]
fn intent_firewall_enable() {
    let op = FirewallOp::Enable;
    assert_eq!(Op::Firewall(&op).intent_label(), "Enable pf host-wide");
}

// ============================================================
// ACL-domain variants
// ============================================================

#[test]
fn intent_acl_grant() {
    let op = AclOp::Grant {
        path: PathBuf::from("/Users/operator/projects/foo"),
        group: "dev-tenant-share".into(),
        mode: AclMode::Rw,
    };
    assert_eq!(
        Op::Acl(&op).intent_label(),
        "Grant 'dev-tenant-share' ACL access to /Users/operator/projects/foo"
    );
}

#[test]
fn intent_acl_revoke() {
    let op = AclOp::Revoke {
        path: PathBuf::from("/Users/operator/projects/foo"),
        group: "dev-tenant-share".into(),
        mode: AclMode::Rw,
    };
    assert_eq!(
        Op::Acl(&op).intent_label(),
        "Revoke 'dev-tenant-share' ACL access from /Users/operator/projects/foo"
    );
}

// ============================================================
// Sharpening pin: intent_label differs from business_label for the
// previously-weak probe variants. LookupUserRecord + DeleteUserRecord
// are cases where the past-tense business_label (`Residual user
// record check for 'dev'`) reads OK after success but doesn't read
// naturally as a future-tense bullet — intent_label uses a sharper
// future-tense headline. This test pins that they actually differ
// so a "let's just alias intent_label to business_label" regression
// trips.
// ============================================================

#[test]
fn intent_label_differs_from_business_label_for_lookup_user_record() {
    let op = AccountOp::LookupUserRecord { name: "dev".into() };
    assert_ne!(
        Op::Account(&op).intent_label(),
        Op::Account(&op).business_label(),
        "intent_label and business_label should be distinct for LookupUserRecord"
    );
}

#[test]
fn intent_label_differs_from_business_label_for_delete_user_record() {
    let op = AccountOp::DeleteUserRecord { name: "dev".into() };
    assert_ne!(
        Op::Account(&op).intent_label(),
        Op::Account(&op).business_label(),
        "intent_label and business_label should be distinct for DeleteUserRecord"
    );
}

#[test]
fn intent_label_differs_from_business_label_for_exec_as_user() {
    // intent_label is the full operator-display ("Run as 'dev': ls /tmp"),
    // business_label is the basename-only past-tense ✓ progress line
    // ("Command 'ls' executed as 'dev'"). The alias-regression pin
    // guards against future refactor that would collapse the two arms.
    let op = AccountOp::ExecAsUser {
        name: "dev".into(),
        argv: vec!["ls".into(), "/tmp".into()],
    };
    assert_ne!(
        Op::Account(&op).intent_label(),
        Op::Account(&op).business_label(),
        "intent_label and business_label should be distinct for ExecAsUser"
    );
}

// ============================================================
// KeychainOp variants
// ============================================================

#[test]
fn intent_create_login_keychain() {
    let op = tenant::domain::KeychainOp::CreateLoginKeychain {
        name: "dev".into(),
        password: tenant::domain::KeychainPassword::test_dummy("ignored"),
    };
    assert_eq!(
        Op::Keychain(&op).intent_label(),
        "Create login keychain for tenant 'dev'"
    );
}

#[test]
fn intent_set_default_keychain() {
    let op = tenant::domain::KeychainOp::SetDefaultKeychain { name: "dev".into() };
    assert_eq!(
        Op::Keychain(&op).intent_label(),
        "Set tenant 'dev' default keychain to login.keychain-db"
    );
}

#[test]
fn intent_add_keychain_to_search_list() {
    let op = tenant::domain::KeychainOp::AddKeychainToSearchList { name: "dev".into() };
    assert_eq!(
        Op::Keychain(&op).intent_label(),
        "Add login.keychain-db to tenant 'dev' search list"
    );
}

#[test]
fn intent_disable_keychain_auto_lock() {
    let op = tenant::domain::KeychainOp::DisableKeychainAutoLock { name: "dev".into() };
    assert_eq!(
        Op::Keychain(&op).intent_label(),
        "Disable auto-lock on tenant 'dev' login keychain"
    );
}

#[test]
fn intent_stash_password() {
    let op = tenant::domain::KeychainOp::StashPassword {
        name: "dev".into(),
        password: tenant::domain::KeychainPassword::test_dummy("ignored"),
    };
    assert_eq!(
        Op::Keychain(&op).intent_label(),
        "Stash tenant 'dev' password in operator keychain"
    );
}

#[test]
fn intent_delete_stashed_password() {
    let op = tenant::domain::KeychainOp::DeleteStashedPassword { name: "dev".into() };
    assert_eq!(
        Op::Keychain(&op).intent_label(),
        "Remove tenant 'dev' password from operator keychain"
    );
}

#[test]
fn business_create_login_keychain() {
    let op = tenant::domain::KeychainOp::CreateLoginKeychain {
        name: "dev".into(),
        password: tenant::domain::KeychainPassword::test_dummy("ignored"),
    };
    assert_eq!(
        Op::Keychain(&op).business_label(),
        "Tenant 'dev' login keychain created"
    );
}

#[test]
fn business_set_default_keychain() {
    let op = tenant::domain::KeychainOp::SetDefaultKeychain { name: "dev".into() };
    assert_eq!(
        Op::Keychain(&op).business_label(),
        "Tenant 'dev' default keychain set"
    );
}

#[test]
fn business_add_keychain_to_search_list() {
    let op = tenant::domain::KeychainOp::AddKeychainToSearchList { name: "dev".into() };
    assert_eq!(
        Op::Keychain(&op).business_label(),
        "Tenant 'dev' keychain added to search list"
    );
}

#[test]
fn business_disable_keychain_auto_lock() {
    let op = tenant::domain::KeychainOp::DisableKeychainAutoLock { name: "dev".into() };
    assert_eq!(
        Op::Keychain(&op).business_label(),
        "Tenant 'dev' keychain auto-lock disabled"
    );
}

#[test]
fn business_stash_password() {
    let op = tenant::domain::KeychainOp::StashPassword {
        name: "dev".into(),
        password: tenant::domain::KeychainPassword::test_dummy("ignored"),
    };
    assert_eq!(
        Op::Keychain(&op).business_label(),
        "Tenant 'dev' password stashed in operator keychain"
    );
}

#[test]
fn business_delete_stashed_password() {
    let op = tenant::domain::KeychainOp::DeleteStashedPassword { name: "dev".into() };
    assert_eq!(
        Op::Keychain(&op).business_label(),
        "Tenant 'dev' password removed from operator keychain"
    );
}
