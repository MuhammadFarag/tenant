//! Per-variant contract pins on `MacosHostMachine::describe_account` and
//! `MacosHostMachine::describe_profile`. These tests are the one place
//! where the literal shell-command shape of each op lives — the
//! verb-level E2E tests in `cli.rs` already pin the end-to-end output
//! via byte-exact stdout assertions, but those assertions are
//! distributed; if dseditgroup ever moves to `dscl . -create /Groups/…`
//! exactly one test here moves with the renderer change.
//!
//! These ARE unit tests, which crosses the project's "E2E-only"
//! convention. Justified by the per-variant combinatorial coverage
//! that's awkward via the CLI surface — every AccountOp variant has
//! its own argv shape, and routing each through a verb (some of which
//! aren't even reachable from a single CLI invocation, like
//! `LoginAsUser` which doesn't share a verb with the dscl probes) means
//! N independent E2E tests, all asserting on tiny substrings of a
//! larger stdout block. A focused per-variant test reads cleaner and
//! catches drift more precisely.

use std::path::PathBuf;

use tenant::adapters::macos::MacosHostMachine;
use tenant::domain::{
    AccountOp, AclMode, AclOp, FirewallOp, GroupId, HostMachine, ProfileOp, UserId,
};

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
        s.describe_account(&AccountOp::LoginAsUser { name: "dev".into() }),
        "sudo -iu dev",
    );
}

#[test]
fn macos_describes_exec_as_user() {
    // sudo -iu <name> -- <argv joined with spaces>. `-i` (login shell)
    // sources /etc/zprofile + ~/.zprofile so PATH and tooling env match
    // the interactive `tenant shell <name>` posture. `--` separator
    // ensures sudo doesn't interpret argv[0] as a sudo flag. The display
    // is operator-facing (no shell-quoting); execution argv is the
    // already-tokenized vector so a pipe inside one element survives.
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::ExecAsUser {
            name: "dev".into(),
            argv: vec!["ls".into(), "/tmp".into()],
        }),
        "sudo -iu dev -- ls /tmp",
    );
}

#[test]
fn macos_describes_exec_as_user_preserves_quoted_argv_element() {
    // A single argv element carrying shell metacharacters (here a pipe
    // inside `bash -c '<...>'`) MUST survive intact through the display
    // — operator's mental model: "the command I typed after `--` arrives
    // at the tenant unchanged". Substrate-side, clap collected the
    // element verbatim and `account_argv` passes it through to sudo as
    // one argv entry; sudo's -i then -c-quotes when handing off to the
    // login shell. Display joins with a single space; no per-element
    // shell-escaping (the operator can read what they typed).
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_account(&AccountOp::ExecAsUser {
            name: "dev".into(),
            argv: vec!["bash".into(), "-c".into(), "curl https://x | bash".into(),],
        }),
        "sudo -iu dev -- bash -c curl https://x | bash",
    );
}

#[test]
fn macos_describes_ensure_dir_as_user() {
    // Run-as-tenant `sudo -n -u <name> /bin/mkdir -p <path>`. Mirror
    // of the `LoginAsUser` "run as the tenant" mechanism — Account
    // sub-domain because the substrate is sudo-u (tenant identity),
    // not chmod-on-host (operator identity). Mode bits come from the
    // tenant's umask (default 022 → directories at 755); no explicit
    // mode arg until a real need surfaces.
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
    // Run-as-tenant `sudo -n -u <name> /bin/ln -sfn <target> <link>`.
    // `-sfn`: symlink (s) + force-overwrite-existing-symlink (f) +
    // no-follow-existing-dir-target (n). Idempotent at the substrate:
    // an existing symlink with the same target re-links to the same
    // place (no-op effect); an existing symlink to a different target
    // gets replaced; an existing REAL dir or file at `link` is the
    // `TenantPathOccupied` case the Tenants struct pre-checks for (substrate
    // would error here without that guard; Tenants surfaces
    // `ShareError::TenantPathOccupied` before the substrate runs).
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
    // Secondary group membership for the host operator on every
    // tenant's `<name>-tenant-share` group. Ported verbatim from
    // sandbox's `_add_human_to_group` substrate. `-t user`
    // disambiguates the member type for dseditgroup (the alternative
    // is `-t group` for nested-group memberships, which tenant
    // doesn't use). The operator-facing render names the host
    // literally so a verbose plan line is self-documenting about
    // WHO is being added.
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
fn macos_describes_remove_host_from_share_group() {
    // Destroy-side counter to `AddHostToShareGroup`. The substrate
    // runs `dseditgroup -o checkmember -m <host> <group>` internally
    // before the `-o edit -d` to make removal idempotent on (a)
    // legacy tenants where the host was never a member and (b) the
    // orphan-group destroy path on a partially-created tenant. The
    // describe-side renders the edit form only — checkmember is
    // mechanism the operator doesn't need a line for.
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
    // Body content is intentionally not in the rendered line — the
    // pretend-shell `< anchor.body` marker says "content comes from
    // elsewhere", matching the ProfileOp::Create convention.
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

// --- AclOp ------------------------------------------------------------
//
// ACL strings ported verbatim from the sandbox plugin's
// `scripts/lib/acl.py` (read_exec_inherit_entry / rw_inherit_entry):
//
// - ro: `read,execute,file_inherit,directory_inherit`
// - rw: `read,write,execute,delete,append,file_inherit,directory_inherit`
//
// No `sudo` prefix — `chmod +a` runs as the operator (host user) who
// is expected to own (or have ACL write on) `host_path`. Mirrors the
// plugin's posture exactly. Paths the host can't write to surface as
// `AclError::NonZero` with the chmod stderr embedded; the operator
// frame names the host_path so the cause is locatable.
//
// EntryEnsureKind (Grant/Revoke) maps to the `+a` / `-a` chmod arg.
// The substrate is idempotent: production checks ACL presence via
// `ls -lde <path>` before invoking chmod — sandbox's pattern.

#[test]
fn macos_describes_acl_grant_ro() {
    let s = MacosHostMachine;
    assert_eq!(
        s.describe_acl(&AclOp::Grant {
            path: PathBuf::from("/Users/Shared/sandbox/dev"),
            group: "dev-tenant-share".into(),
            mode: AclMode::Ro,
        }),
        "chmod +a \"group:dev-tenant-share allow read,execute,file_inherit,directory_inherit\" \
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
        "chmod +a \"group:dev-tenant-share allow \
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

// ============================================================
// Keychain describe-string pins
// ============================================================
//
// Provision is four ADT variants, one substrate call each (the split
// landed when the 4-call bundle was broken up so each step is its own
// op-identity assertion target). Each describe-string is its own pin
// here.

#[test]
fn macos_describes_create_login_keychain() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::CreateLoginKeychain {
        name: "dev".into(),
        password: tenant::domain::KeychainPassword::test_dummy("ignored-by-describe"),
    };
    assert_eq!(
        s.describe_keychain(&op),
        "sudo -iu dev security create-keychain -p <password> login.keychain-db"
    );
}

#[test]
fn macos_describes_set_default_keychain() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::SetDefaultKeychain { name: "dev".into() };
    assert_eq!(
        s.describe_keychain(&op),
        "sudo -iu dev security default-keychain -s login.keychain-db"
    );
}

#[test]
fn macos_describes_add_keychain_to_search_list() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::AddKeychainToSearchList { name: "dev".into() };
    assert_eq!(
        s.describe_keychain(&op),
        "sudo -iu dev security list-keychains -s login.keychain-db"
    );
}

#[test]
fn macos_describes_disable_keychain_auto_lock() {
    let s = MacosHostMachine;
    let op = tenant::domain::KeychainOp::DisableKeychainAutoLock { name: "dev".into() };
    assert_eq!(
        s.describe_keychain(&op),
        "sudo -iu dev security set-keychain-settings login.keychain-db"
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

// Argv-tail pin for the shell-entry unlock pass. `unlock_tenant_keychain`
// is a HostMachine carve-out (non-unit-error-shaped probe-style call, no
// `KeychainOp` variant, no `describe_*` surface) that routes through
// `run_security_as_tenant`; the unlock-specific tail is extracted into
// `unlock_keychain_argv` to give this test a byte-exact seam.
// Production + test consume the same helper, so any drift fails here
// exactly once. The `sudo -iu <name> security` prefix is pinned by
// `run_security_as_tenant`'s own sibling coverage.
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
            "login.keychain-db",
        ],
    );
}

// `tenant_keychain_present` smoke. Defends against the EACCES-vs-NotFound
// substrate bug where calling `std::fs::metadata` from the operator
// process against `/Users/<tenant>/Library/...` returns
// PermissionDenied — because Library is mode 0700 — and surfaces as
// ProbeError::Spawn instead of a clean Ok(false). The fix runs the
// existence check AS THE TENANT via `sudo -n -u <name> /bin/test -e
// <path>`; this test exercises that path against `root`, whose
// home (`/var/root/`) doesn't contain a `Library/Keychains/login.keychain-db`
// on a default macOS install — so the probe should return Ok(false).
// `#[ignore]` because the test requires passwordless `sudo -n -u root`,
// which isn't configured in headless CI environments.
#[cfg(target_os = "macos")]
#[test]
#[ignore]
fn macos_tenant_keychain_present_returns_false_for_absent_path() {
    use tenant::domain::{HostMachine, TenantUserName};
    let machine = MacosHostMachine;
    // `root` exists on every macOS host. The keychain path under
    // `/Users/root/...` doesn't (root's home is `/var/root/`); the
    // probe builds the `/Users/<name>/Library/Keychains/login.keychain-db`
    // path literally, so this is a deterministic-absent case that the
    // old `std::fs::metadata` impl would have surfaced as
    // ProbeError::Spawn (EACCES traversing into `/Users/root/`'s
    // absent parent) rather than a clean Ok(false).
    let verdict = machine
        .tenant_keychain_present(&TenantUserName::from("root"))
        .expect("sudo -n -u root /bin/test should yield a kernel verdict");
    assert!(
        !verdict,
        "keychain at /Users/root/Library/Keychains/login.keychain-db must not exist"
    );
}
