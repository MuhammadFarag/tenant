//! Create-verb error type and the `Tenants::create` orchestrator.

use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, FirewallError, FirewallOp, GroupId, HostUserName, KeychainError,
    KeychainOp, KeychainPassword, ProfileOp, TenantUserName, UserId,
};
use crate::firewall::{ensure_anchor_ref, render_anchor};
use crate::profile::{ProfileError, display_path_for, parse};

use super::reapply::steady_inbound_rules;
use super::{ModeError, Tenants, cowork_dir_path, guard_cowork_dir_kind, tenant_share_group_name};

/// Failure surface for create. `UserWithRollback` is the
/// worst case where rollback itself failed and the host is left with
/// an orphan group. `HostMembership` has no automatic rollback —
/// the host-add step is load-bearing for tenant usability.
///
/// `KeychainProvision` / `KeychainStash` follow the same posture as
/// `Profile` / `Firewall`: tenant user + group already exist, no
/// automatic rollback, recovery is `tenant destroy <name>`. The
/// half-provisioned state is convergent under destroy.
#[derive(Debug)]
pub(crate) enum CreateError {
    Group(AccountError),
    User(AccountError),
    UserWithRollback {
        user: AccountError,
        rollback: AccountError,
    },
    HostMembership(AccountError),
    /// Co-working directory provisioning failed. Same posture as
    /// `KeychainProvision` / `Profile` / `Firewall`: tenant user +
    /// group already exist, no automatic rollback, recovery is
    /// `tenant destroy <name>`.
    CoworkDir(AccountError),
    KeychainProvision(KeychainError),
    KeychainStash(KeychainError),
    Profile(ProfileError),
    /// Read/parse failures on the just-written profile also flow here
    /// as `FirewallError::Fs` because they surface during the firewall
    /// composition step.
    Firewall(FirewallError),
    PostProvision(ModeError),
}

impl<'a> Tenants<'a> {
    pub(crate) fn create(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        uid: UserId,
        gid: GroupId,
        reporter: &mut Reporter,
    ) -> Result<(), CreateError> {
        let group = tenant_share_group_name(name.as_str());
        let create_group = AccountOp::CreateShareGroup {
            group: group.clone(),
            gid,
        };
        let add_host = AccountOp::AddHostToShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        let add_user = AccountOp::CreateTenantUser {
            name: name.into(),
            uid,
            gid,
        };
        let rollback_group = AccountOp::DeleteShareGroup {
            group: group.clone(),
        };
        let create_profile = ProfileOp::Create { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let restore = FirewallOp::RestoreConfigFromBackup;
        let reload = FirewallOp::Reload;
        let enable = FirewallOp::Enable;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };

        reporter.create_starting(name);

        self.run(&create_group, reporter)
            .map_err(CreateError::Group)?;
        self.run(&add_host, reporter)
            .map_err(CreateError::HostMembership)?;
        match self.run(&add_user, reporter) {
            Ok(()) => {
                // Provision the per-tenant co-working directory. The
                // four-step substrate (mkdir → chown → chmod 2770 →
                // chmod -R +a) is natively idempotent on macOS, so
                // the same op fires unconditionally on every reapply
                // as catch-up. Failures share the keychain provision's
                // recovery posture — tenant user + group present,
                // `tenant destroy <name>` converges.
                //
                // Pre-flight kind-check refuses when the path already
                // holds a non-directory entry: mkdir -p errors on a
                // regular file (operator typo, stray `touch`) and
                // silently follows a symlink, leaving the subsequent
                // chown/chmod pass mutating the target.
                let cowork_path = cowork_dir_path(name.as_str());
                guard_cowork_dir_kind(self.machine, &cowork_path)
                    .map_err(CreateError::CoworkDir)?;
                let ensure_cowork = AccountOp::EnsureCoworkDir {
                    path: cowork_path,
                    owner: host.into(),
                    group: group.clone(),
                    mode: 0o2770,
                };
                self.run(&ensure_cowork, reporter)
                    .map_err(CreateError::CoworkDir)?;
                // Bootstrap the tenant's login.keychain-db so
                // credential-stashing apps (Claude OAuth, etc.) don't
                // trip the "could not find the keychain" warning, and
                // stash the protecting secret in the operator's
                // keychain so a future shell-entry unlock pass can
                // retrieve it. One password covers both — the
                // keychain is unlockable only by the same secret
                // that's been written into the operator's keychain.
                let keychain_password = KeychainPassword::generate();
                let create_kc = KeychainOp::CreateLoginKeychain {
                    name: name.into(),
                    password: keychain_password.clone(),
                };
                let set_default = KeychainOp::SetDefaultKeychain { name: name.into() };
                let add_to_search = KeychainOp::AddKeychainToSearchList { name: name.into() };
                let disable_lock = KeychainOp::DisableKeychainAutoLock { name: name.into() };
                let stash = KeychainOp::StashPassword {
                    name: name.into(),
                    password: keychain_password,
                };
                // Partial-failure recovery: see execute_keychain
                // comment block in src/adapters/macos/host_machine.rs.
                // All 4 provision sub-steps share one CreateError arm
                // (`KeychainProvision`) — operator-recovery story is
                // `tenant destroy <name>` regardless of which step
                // failed.
                self.run(&create_kc, reporter)
                    .map_err(CreateError::KeychainProvision)?;
                self.run(&set_default, reporter)
                    .map_err(CreateError::KeychainProvision)?;
                self.run(&add_to_search, reporter)
                    .map_err(CreateError::KeychainProvision)?;
                self.run(&disable_lock, reporter)
                    .map_err(CreateError::KeychainProvision)?;
                self.run(&stash, reporter)
                    .map_err(CreateError::KeychainStash)?;
                self.run(&create_profile, reporter)
                    .map_err(CreateError::Profile)?;
                let profile_content = self.machine.read_profile(name).map_err(|e| {
                    CreateError::Firewall(FirewallError::Fs {
                        path: display_path_for(name.as_str()),
                        message: format!("read failed: {e}"),
                    })
                })?;
                let parsed_profile = parse(&profile_content).map_err(|e| {
                    CreateError::Firewall(FirewallError::Fs {
                        path: display_path_for(name.as_str()),
                        message: format!("parse failed: {e}"),
                    })
                })?;
                let pf_conf_current = self.machine.read_pf_conf().map_err(CreateError::Firewall)?;
                let install_anchor = FirewallOp::InstallAnchor {
                    name: name.into(),
                    body: render_anchor(
                        name.as_str(),
                        &parsed_profile.allowlist.runtime.hosts,
                        steady_inbound_rules(&parsed_profile),
                    ),
                };
                let update_conf = FirewallOp::UpdateConfig {
                    content: ensure_anchor_ref(&pf_conf_current, name.as_str()),
                };
                self.run(&backup, reporter).map_err(CreateError::Firewall)?;
                self.run(&install_anchor, reporter)
                    .map_err(CreateError::Firewall)?;
                self.run(&update_conf, reporter)
                    .map_err(CreateError::Firewall)?;
                if let Err(reload_err) = self.run(&reload, reporter) {
                    // FlushAnchor is the symmetric counter to the partial
                    // in-kernel state from the failed Reload — without
                    // it, restoring pf.conf and removing the anchor file
                    // still leaves the partially-loaded rules in kernel
                    // memory under the now-orphaned anchor name.
                    if self.run(&restore, reporter).is_err() {
                        return Err(CreateError::Firewall(FirewallError::RestoreFailed {
                            path: crate::firewall::PF_CONF_BACKUP.to_string(),
                        }));
                    }
                    let _ = self.run(&remove_anchor, reporter);
                    let _ = self.run(&reload, reporter);
                    let _ = self.run(&flush_anchor, reporter);
                    return Err(CreateError::Firewall(reload_err));
                }
                self.run(&enable, reporter).map_err(CreateError::Firewall)?;
                self.reapply_shares_post_provision(name, &parsed_profile, reporter)
                    .map_err(CreateError::PostProvision)?;
                reporter.create_done(name, uid, gid);
                Ok(())
            }
            Err(user_err) => match self.run(&rollback_group, reporter) {
                Ok(()) => Err(CreateError::User(user_err)),
                Err(rollback_err) => Err(CreateError::UserWithRollback {
                    user: user_err,
                    rollback: rollback_err,
                }),
            },
        }
    }
}
