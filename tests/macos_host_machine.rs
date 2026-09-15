//! Per-variant describe/argv pins: the one place each op's literal shell shape lives. Unit
//! tests because per-variant argv is awkward to isolate in verb-level E2E output.

use std::path::PathBuf;

use tenant::adapters::macos::MacosHostMachine;
use tenant::domain::{
    AccountOp, AclMode, AclOp, FirewallOp, GroupId, HostMachine, PamOp, ProfileOp, UserId,
};

// Only coverage of the no-duplicate + newline guards: `execute_pam` is unreachable from stubs.
use tenant::adapters::macos::host_machine::pam_tid_append_payload;

#[test]
fn pam_payload_none_when_already_in_sudo() {
    assert_eq!(
        pam_tid_append_payload("auth sufficient pam_tid.so\n", ""),
        None
    );
}

#[test]
fn pam_payload_none_when_already_in_sudo_local() {
    assert_eq!(
        pam_tid_append_payload("# sudo stack\n", "auth sufficient pam_tid.so\n"),
        None
    );
}

#[test]
fn pam_payload_for_empty_sudo_local() {
    assert_eq!(
        pam_tid_append_payload("# sudo stack\n", "").as_deref(),
        Some("auth sufficient pam_tid.so\n")
    );
}

#[test]
fn pam_payload_prepends_newline_when_unterminated() {
    assert_eq!(
        pam_tid_append_payload("", "# a hand-written comment").as_deref(),
        Some("\nauth sufficient pam_tid.so\n")
    );
}

#[test]
fn pam_payload_no_extra_newline_when_terminated() {
    assert_eq!(
        pam_tid_append_payload("", "# a hand-written comment\n").as_deref(),
        Some("auth sufficient pam_tid.so\n")
    );
}

#[test]
fn macos_describes_enable_touch_id_for_sudo() {
    // Display is operator-legible; the real `execute_pam` feeds `sudo tee -a` via stdin.
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_pam(&PamOp::EnableTouchIdForSudo),
        "sudo cp /etc/pam.d/sudo_local /etc/pam.d/sudo_local.tenant-backup\n\
         echo 'auth sufficient pam_tid.so' | sudo tee -a /etc/pam.d/sudo_local"
    );
}

#[test]
fn macos_describes_create_share_group() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::CreateShareGroup {
            group: "dev-tenant-share".into(),
            gid: GroupId(600)
        }),
        "sudo dseditgroup -o create -n . -i 600 dev-tenant-share",
    );
}

#[test]
fn macos_describes_delete_share_group() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::DeleteShareGroup {
            group: "dev-tenant-share".into()
        }),
        "sudo dseditgroup -o delete -n . dev-tenant-share",
    );
}

#[test]
fn macos_describes_create_tenant_user() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::CreateTenantUser {
            name: "dev".into(),
            uid: UserId(600),
            gid: GroupId(600)
        }),
        "sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" \
         -shell /bin/zsh -UID 600 -GID 600",
    );
}

#[test]
fn macos_describes_ensure_primary_group() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::EnsurePrimaryGroup {
            name: "dev".into(),
            gid: GroupId(600)
        }),
        "sudo dscl . -create /Users/dev PrimaryGroupID 600",
    );
}

#[test]
fn macos_describes_delete_tenant_user() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::DeleteTenantUser { name: "dev".into() }),
        "sudo sysadminctl -deleteUser dev",
    );
}

#[test]
fn macos_describes_lookup_user_record() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::LookupUserRecord { name: "dev".into() }),
        "dscl . -read /Users/dev",
    );
}

#[test]
fn macos_describes_delete_user_record() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::DeleteUserRecord { name: "dev".into() }),
        "sudo dscl . -delete /Users/dev",
    );
}

#[test]
fn macos_describes_login_as_user() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::LoginAsUser {
            name: "dev".into(),
            dir: None,
        }),
        "sudo -iu dev",
    );
}

#[test]
fn macos_describes_exec_as_user() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::ExecAsUser {
            name: "dev".into(),
            argv: vec!["ls".into(), "/tmp".into()],
            dir: None,
        }),
        "sudo -iu dev -- ls /tmp",
    );
}

#[test]
fn macos_describes_exec_as_user_preserves_quoted_argv_element() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::ExecAsUser {
            name: "dev".into(),
            argv: vec!["bash".into(), "-c".into(), "curl https://x | bash".into(),],
            dir: None,
        }),
        "sudo -iu dev -- bash -c curl https://x | bash",
    );
}

#[test]
fn macos_describes_ensure_dir_as_user() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::EnsureDirAsUser {
            name: "dev".into(),
            path: PathBuf::from("/Users/dev/.local/share"),
        }),
        "sudo -n -u dev /bin/mkdir -p /Users/dev/.local/share",
    );
}

#[test]
fn macos_describes_ensure_symlink_as_user() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::EnsureSymlinkAsUser {
            name: "dev".into(),
            link: PathBuf::from("/Users/dev/src"),
            target: PathBuf::from("/Users/Shared/sandbox/dev"),
        }),
        "sudo -n -u dev /bin/ln -sfn /Users/Shared/sandbox/dev /Users/dev/src",
    );
}

#[test]
fn macos_describes_add_host_to_share_group() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::AddHostToShareGroup {
            group: "dev-tenant-share".into(),
            host: "operator".into(),
        }),
        "sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share",
    );
}

#[test]
fn macos_describes_ensure_cowork_dir_renders_four_substrate_calls() {
    // One op, four substrate calls: describe joins them with `\n`; the reporter splits lines.
    let s = MacosHostMachine;
    let op = AccountOp::EnsureCoworkDir {
        path: PathBuf::from("/Users/Shared/tenants/dev"),
        owner: "operator".into(),
        group: "dev-tenant-share".into(),
        mode: 0o2770,
    };
    assert_eq!(
        s.describe_account(&op),
        "sudo mkdir -p /Users/Shared/tenants/dev\n\
         sudo chown operator:dev-tenant-share /Users/Shared/tenants/dev\n\
         sudo chmod 2770 /Users/Shared/tenants/dev\n\
         sudo chmod -R +a \"group:dev-tenant-share allow \
         read,write,execute,delete,append,file_inherit,directory_inherit\" \
         /Users/Shared/tenants/dev",
    );
}

#[test]
fn macos_describes_remove_host_from_share_group() {
    // The substrate runs `checkmember` first for idempotency; describe shows only the edit.
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::RemoveHostFromShareGroup {
            group: "dev-tenant-share".into(),
            host: "operator".into(),
        }),
        "sudo dseditgroup -o edit -n . -d operator -t user dev-tenant-share",
    );
}

#[test]
fn macos_describes_profile_create() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_profile(&ProfileOp::Create { name: "dev".into() }),
        "tee ~/.config/tenant/profiles/dev.toml < default.toml",
    );
}

#[test]
fn macos_describes_profile_delete() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_profile(&ProfileOp::Delete { name: "dev".into() }),
        "rm -f ~/.config/tenant/profiles/dev.toml",
    );
}

#[test]
fn macos_describes_install_anchor() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_firewall(&FirewallOp::InstallAnchor {
            name: "dev".into(),
            body: "ignored for describe".into(),
        }),
        "sudo tee /etc/pf.anchors/tenant-dev < anchor.body",
    );
}

#[test]
fn macos_describes_remove_anchor() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_firewall(&FirewallOp::RemoveAnchor { name: "dev".into() }),
        "sudo rm -f /etc/pf.anchors/tenant-dev",
    );
}

#[test]
fn macos_describes_backup_config() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_firewall(&FirewallOp::BackupConfig),
        "sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup",
    );
}

#[test]
fn macos_describes_restore_config_from_backup() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_firewall(&FirewallOp::RestoreConfigFromBackup),
        "sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf",
    );
}

#[test]
fn macos_describes_update_config() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_firewall(&FirewallOp::UpdateConfig {
            content: "ignored for describe".into(),
        }),
        "sudo tee /etc/pf.conf < updated.conf",
    );
}

#[test]
fn macos_describes_reload() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_firewall(&FirewallOp::Reload),
        "sudo pfctl -f /etc/pf.conf",
    );
}

#[test]
fn macos_describes_enable() {
    let s = MacosHostMachine;
    assert_eq!(s.describe_firewall(&FirewallOp::Enable), "sudo pfctl -e",);
}

#[test]
fn macos_describes_flush_anchor() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_firewall(&FirewallOp::FlushAnchor { name: "dev".into() }),
        "sudo pfctl -a tenant-dev -F all",
    );
}

// --- AclOp ---
// Grant is `-R` (inherit bits only reach future children); revoke is top-level only because
// `chmod -R -a` fails on any node missing the ACE.

#[test]
fn macos_describes_acl_grant_ro() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_acl(&AclOp::Grant {
            path: PathBuf::from("/Users/Shared/sandbox/dev"),
            group: "dev-tenant-share".into(),
            mode: AclMode::Ro,
        }),
        "sudo chmod -R +a \"group:dev-tenant-share allow read,execute,file_inherit,directory_inherit\" \
         /Users/Shared/sandbox/dev",
    );
}

#[test]
fn macos_describes_acl_grant_rw() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_acl(&AclOp::Grant {
            path: PathBuf::from("/Users/Shared/sandbox/dev"),
            group: "dev-tenant-share".into(),
            mode: AclMode::Rw,
        }),
        "sudo chmod -R +a \"group:dev-tenant-share allow \
         read,write,execute,delete,append,file_inherit,directory_inherit\" \
         /Users/Shared/sandbox/dev",
    );
}

#[test]
fn macos_describes_acl_revoke_ro() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_acl(&AclOp::Revoke {
            path: PathBuf::from("/Users/Shared/sandbox/dev"),
            group: "dev-tenant-share".into(),
            mode: AclMode::Ro,
        }),
        "chmod -a \"group:dev-tenant-share allow read,execute,file_inherit,directory_inherit\" \
         /Users/Shared/sandbox/dev",
    );
}

#[test]
fn macos_describes_acl_revoke_rw() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_acl(&AclOp::Revoke {
            path: PathBuf::from("/Users/Shared/sandbox/dev"),
            group: "dev-tenant-share".into(),
            mode: AclMode::Rw,
        }),
        "chmod -a \"group:dev-tenant-share allow \
         read,write,execute,delete,append,file_inherit,directory_inherit\" \
         /Users/Shared/sandbox/dev",
    );
}

// --- KeychainOp ---

#[test]
fn macos_describes_create_tenant_keychain() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::CreateTenantKeychain {
        name: "dev".into(),
        password: tenant::domain::KeychainPassword::test_dummy("ignored-by-describe"),
    };
    assert_eq!(
        s.describe_keychain(&op),
        "sudo -iu dev security create-keychain -p <password> tenant.keychain-db"
    );
}

#[test]
fn macos_describes_set_default_keychain() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::SetDefaultKeychain { name: "dev".into() };
    assert_eq!(
        s.describe_keychain(&op),
        "sudo -iu dev security default-keychain -s tenant.keychain-db"
    );
}

#[test]
fn macos_describes_add_keychain_to_search_list() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::AddKeychainToSearchList { name: "dev".into() };
    assert_eq!(
        s.describe_keychain(&op),
        "sudo -iu dev security list-keychains -s tenant.keychain-db"
    );
}

#[test]
fn macos_describes_disable_keychain_auto_lock() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::DisableKeychainAutoLock { name: "dev".into() };
    assert_eq!(
        s.describe_keychain(&op),
        "sudo -iu dev security set-keychain-settings tenant.keychain-db"
    );
}

#[test]
fn macos_describes_stash_password_with_argv_redaction_marker() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::StashPassword {
        name: "dev".into(),
        password: tenant::domain::KeychainPassword::test_dummy("ignored-by-describe"),
    };
    assert_eq!(
        s.describe_keychain(&op),
        "security add-generic-password -U -a dev -s tenant-dev -w <password>"
    );
}

#[test]
fn macos_describes_delete_stashed_password() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::DeleteStashedPassword { name: "dev".into() };
    assert_eq!(
        s.describe_keychain(&op),
        "security delete-generic-password -a dev -s tenant-dev"
    );
}

// Unlock-specific tail only; the `sudo -iu <name> security` prefix is pinned elsewhere.
#[test]
fn macos_unlock_keychain_argv_tail() {
    use tenant::adapters::macos::host_machine::unlock_keychain_argv;
    use tenant::domain::KeychainPassword;
    let password = KeychainPassword::test_dummy("test-keychain-pw");
    assert_eq!(
        unlock_keychain_argv(&password),
        vec![
            "unlock-keychain",
            "-p",
            "test-keychain-pw",
            "tenant.keychain-db",
        ],
    );
}

// Library is 0700, so the probe must run as the tenant; an operator-side stat EACCESes.
// Ignored: needs passwordless `sudo -n -u root`.
#[cfg(target_os = "macos")]
#[test]
#[ignore]
fn macos_tenant_keychain_present_returns_false_for_absent_path() {
    use tenant::domain::{HostMachine, TenantUserName};
    let machine = MacosHostMachine;
    // `/Users/root/...` never exists (root's home is `/var/root`): deterministically absent.
    let verdict = machine
        .tenant_keychain_present(&TenantUserName::from("root"))
        .expect("sudo -n -u root /bin/test should yield a kernel verdict");
    assert!(
        !verdict,
        "keychain at /Users/root/Library/Keychains/tenant.keychain-db must not exist"
    );
}

#[test]
fn macos_tenant_keychain_present_argv() {
    use tenant::adapters::macos::host_machine::tenant_keychain_present_argv;
    assert_eq!(
        tenant_keychain_present_argv("dev"),
        vec![
            "sudo",
            "-n",
            "-u",
            "dev",
            "/bin/test",
            "-e",
            "/Users/dev/Library/Keychains/tenant.keychain-db",
        ],
    );
}

#[test]
fn macos_sudo_test_verdict_reads_exit_1_as_no_only_without_stderr() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};
    use tenant::adapters::macos::host_machine::sudo_test_verdict;
    use tenant::domain::ProbeError;
    let output = |code: i32, stderr: &str| Output {
        status: ExitStatus::from_raw(code << 8),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    };
    assert!(matches!(sudo_test_verdict(&output(0, "")), Ok(true)));
    assert!(matches!(
        sudo_test_verdict(&output(0, "warning\n")),
        Ok(true)
    ));
    assert!(matches!(sudo_test_verdict(&output(1, "")), Ok(false)));
    assert!(matches!(
        sudo_test_verdict(&output(1, "sudo: a password is required\n")),
        Err(ProbeError::NonZero { code: 1, .. })
    ));
    assert!(matches!(
        sudo_test_verdict(&output(2, "")),
        Err(ProbeError::NonZero { code: 2, .. })
    ));
    let killed = Output {
        status: ExitStatus::from_raw(9),
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    assert!(matches!(
        sudo_test_verdict(&killed),
        Err(ProbeError::NonZero { code: -1, .. })
    ));
}

// Doctor's host-config reads use BARE sudo (no `-n`): the first prompts and caches, so later
// `sudo -n -u <tenant>` probes ride the cache instead of failing with "a password is required".
#[test]
fn macos_pf_status_argv_is_bare_sudo() {
    use tenant::adapters::macos::host_machine::pf_status_argv;
    let argv = pf_status_argv();
    assert_eq!(argv, vec!["sudo", "pfctl", "-si"]);
    assert!(
        !argv.iter().any(|a| a == "-n"),
        "doctor pf-status read must drop -n for point-of-use prompting; argv={argv:?}"
    );
}

#[test]
fn macos_kernel_pf_rules_argv_is_bare_sudo() {
    use tenant::adapters::macos::host_machine::kernel_pf_rules_argv;
    let argv = kernel_pf_rules_argv("dev");
    assert_eq!(argv, vec!["sudo", "pfctl", "-a", "tenant-dev", "-sr"]);
    assert!(
        !argv.iter().any(|a| a == "-n"),
        "doctor kernel-pf-rules read must drop -n for point-of-use prompting; argv={argv:?}"
    );
}

#[test]
fn macos_privileged_cat_argv_is_bare_sudo() {
    use tenant::adapters::macos::host_machine::privileged_cat_argv;
    let argv = privileged_cat_argv("/etc/sudoers");
    assert_eq!(argv, vec!["sudo", "cat", "/etc/sudoers"]);
    assert!(
        !argv.iter().any(|a| a == "-n"),
        "doctor sudoers read must drop -n for point-of-use prompting; argv={argv:?}"
    );
}

#[test]
fn macos_sudoers_dropins_listing_argv_is_bare_sudo() {
    use tenant::adapters::macos::host_machine::sudoers_dropins_listing_argv;
    let argv = sudoers_dropins_listing_argv();
    assert_eq!(argv, vec!["sudo", "ls", "-1", "/etc/sudoers.d"]);
    assert!(
        !argv.iter().any(|a| a == "-n"),
        "doctor sudoers.d listing must drop -n for point-of-use prompting; argv={argv:?}"
    );
}

#[test]
fn macos_authenticate_sudo_argv_prompts() {
    use tenant::adapters::macos::host_machine::authenticate_sudo_argv;
    assert_eq!(authenticate_sudo_argv(), vec!["sudo", "-v"]);
}

#[test]
fn macos_sudo_session_cached_argv_keeps_dash_n() {
    use tenant::adapters::macos::host_machine::sudo_session_cached_argv;
    assert_eq!(sudo_session_cached_argv(), vec!["sudo", "-n", "-v"]);
}

#[test]
fn macos_describes_login_as_user_with_directory() {
    // `$SHELL` stays single-quoted so it expands tenant-side, after `sudo -i` has set it.
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::LoginAsUser {
            name: "dev".into(),
            dir: Some(PathBuf::from("/Users/dev/projects/foo")),
        }),
        "sudo -iu dev -- /bin/sh -c 'cd /Users/dev/projects/foo && exec \"$SHELL\"'",
    );
}

#[test]
fn macos_describes_exec_as_user_with_directory() {
    // `"$@"` + the `sh` placeholder keep the operator's argv boundaries intact.
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::ExecAsUser {
            name: "dev".into(),
            argv: vec!["ls".into(), "/tmp".into()],
            dir: Some(PathBuf::from("/Users/dev/projects/foo")),
        }),
        "sudo -iu dev -- /bin/sh -c 'cd /Users/dev/projects/foo && exec \"$@\"' sh ls /tmp",
    );
}

#[test]
fn macos_describes_directory_needing_quotes() {
    // The adapter composes this script, so the dir must be shell-quoted (unlike bare argv arms).
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::LoginAsUser {
            name: "dev".into(),
            dir: Some(PathBuf::from("/Users/dev/my work")),
        }),
        "sudo -iu dev -- /bin/sh -c 'cd '\\''/Users/dev/my work'\\'' && exec \"$SHELL\"'",
    );
}

// TODO(smell): derive `describe_account`'s dir-less display from `account_argv` so the two can't diverge.
// Until then this is the only executed-argv coverage of the dir-less arms.
#[test]
fn macos_account_argv_wraps_only_when_directory_present() {
    use tenant::adapters::macos::host_machine::account_argv;
    assert_eq!(
        account_argv(&AccountOp::LoginAsUser {
            name: "dev".into(),
            dir: None,
        }),
        vec!["sudo", "-iu", "dev"],
    );
    assert_eq!(
        account_argv(&AccountOp::ExecAsUser {
            name: "dev".into(),
            argv: vec!["ls".into(), "/tmp".into()],
            dir: None,
        }),
        vec!["sudo", "-iu", "dev", "--", "ls", "/tmp"],
    );
    assert_eq!(
        account_argv(&AccountOp::ExecAsUser {
            name: "dev".into(),
            argv: vec!["bash".into(), "-c".into(), "echo a b".into()],
            dir: Some(PathBuf::from("/w")),
        }),
        vec![
            "sudo",
            "-iu",
            "dev",
            "--",
            "/bin/sh",
            "-c",
            "cd /w && exec \"$@\"",
            "sh",
            "bash",
            "-c",
            "echo a b",
        ],
    );
    assert_eq!(
        account_argv(&AccountOp::LoginAsUser {
            name: "dev".into(),
            dir: Some(PathBuf::from("/Users/dev/my work")),
        }),
        vec![
            "sudo",
            "-iu",
            "dev",
            "--",
            "/bin/sh",
            "-c",
            "cd '/Users/dev/my work' && exec \"$SHELL\"",
        ],
    );
}
