use crate::ModeLevel;
use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, FirewallError, FirewallOp, GroupId, HostUserName, KeychainError,
    KeychainOp, KeychainPassword, ProfileOp, TenantUserName, UserId,
};
use crate::firewall::{ensure_anchor_ref, render_anchor};
use crate::profile::{ProfileError, display_path_for};

use super::reapply::{hosts_for_level, steady_inbound_rules};
use super::{ModeError, Tenants, cowork_dir_path, guard_cowork_dir_kind, tenant_share_group_name};

/// Only `User` rolls back (deletes the group); every other failure leaves partial state
/// that `tenant destroy <name>` converges.
#[derive(Debug)]
pub(crate) enum CreateError {
    Group(AccountError),
    User(AccountError),
    UserWithRollback {
        user: AccountError,
        rollback: AccountError,
    },
    HostMembership(AccountError),
    CoworkDir(AccountError),
    KeychainProvision(KeychainError),
    KeychainStash(KeychainError),
    Profile(ProfileError),
    /// Also carries a failed load of the just-written profile, as `FirewallError::Fs`.
    Firewall(FirewallError),
    PostProvision(ModeError),
}

impl<'a> Tenants<'a> {
    /// `Ok(true)` when a hand-written profile is already in place and loads; create keeps it.
    pub(crate) fn existing_profile_loads(
        &self,
        name: &TenantUserName,
    ) -> Result<bool, ProfileError> {
        if !self.machine.profile_exists(name) {
            return Ok(false);
        }
        self.load_profile(name).map(|_| true)
    }

    pub(crate) fn create(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        uid: UserId,
        gid: GroupId,
        keep_profile: bool,
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
                let keychain_password = KeychainPassword::generate();
                let create_kc = KeychainOp::CreateTenantKeychain {
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
                if keep_profile {
                    reporter.create_profile_kept(name);
                } else {
                    self.run(&create_profile, reporter)
                        .map_err(CreateError::Profile)?;
                }
                let parsed_profile = self.load_profile(name).map_err(|e| {
                    CreateError::Firewall(FirewallError::Fs {
                        path: display_path_for(name.as_str()),
                        message: format!("load failed: {e}"),
                    })
                })?;
                let pf_conf_current = self.machine.read_pf_conf().map_err(CreateError::Firewall)?;
                let install_anchor = FirewallOp::InstallAnchor {
                    name: name.into(),
                    body: render_anchor(
                        name.as_str(),
                        &hosts_for_level(&parsed_profile, ModeLevel::Runtime),
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
                    // Flush too: a failed Reload can leave partially-loaded rules in the kernel under the
                    // orphaned anchor name.
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
