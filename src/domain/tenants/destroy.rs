//! Destroy-verb error type, the eligibility classifier that gates
//! destroy at dispatch, and the `Tenants::destroy` /
//! `Tenants::destroy_orphan_group` orchestrators.

use crate::allocation::TENANT_UID_FLOOR;
use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, FirewallError, FirewallOp, HostUserDirectory, HostUserName, ProfileOp,
    TenantUserName, UserDirectoryError, UserId,
};
use crate::firewall::remove_anchor_ref;
use crate::profile::ProfileError;

use super::{Tenants, tenant_share_group_name};

/// Failure surface for destroy. Unlike create, destroy has
/// no recovery path on Firewall reload failure — the symmetric "restore
/// from backup" would re-introduce a reference to the already-removed
/// anchor file, putting the host in a worse state.
#[derive(Debug)]
pub(crate) enum DestroyError {
    Account(AccountError),
    Profile(ProfileError),
    Firewall(FirewallError),
}

impl From<AccountError> for DestroyError {
    fn from(e: AccountError) -> Self {
        DestroyError::Account(e)
    }
}

/// Destroy-side classification. `OrphanGroup` is the user-absent /
/// suffixed-group-present residue from a prior partial failure.
/// `SystemAccount` is the account-present / no-positive-UID case
/// (filtered out of `uid_by_name` upstream, so the floor predicate
/// can't bind to a value).
#[derive(Debug)]
pub enum Eligibility {
    Destroyable,
    NotPresent,
    OrphanGroup,
    NotATenant { uid: UserId },
    SystemAccount,
}

pub fn destroy_eligibility(
    directory: &dyn HostUserDirectory,
    name: &TenantUserName,
) -> Result<Eligibility, UserDirectoryError> {
    if !directory.has_user(name)? {
        if directory.has_group(&tenant_share_group_name(name.as_str()))? {
            return Ok(Eligibility::OrphanGroup);
        }
        return Ok(Eligibility::NotPresent);
    }
    Ok(match directory.uid_for(name)? {
        Some(uid) if uid.0 >= TENANT_UID_FLOOR => Eligibility::Destroyable,
        Some(uid) => Eligibility::NotATenant { uid },
        None => Eligibility::SystemAccount,
    })
}

impl<'a> Tenants<'a> {
    pub(crate) fn destroy(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        // PF teardown sits after account/profile cleanup so the tenant
        // can't open new sockets while we're tearing down their ruleset.
        // FlushAnchor is load-bearing: without it, the previous tenant's
        // rules persist in kernel memory under the orphaned anchor name
        // and the next tenant getting the same UID inherits them.
        let group = tenant_share_group_name(name.as_str());
        let delete_user = AccountOp::DeleteTenantUser { name: name.into() };
        let probe = AccountOp::LookupUserRecord { name: name.into() };
        let cleanup = AccountOp::DeleteUserRecord { name: name.into() };
        let remove_host = AccountOp::RemoveHostFromShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        let delete_group = AccountOp::DeleteShareGroup { group };
        let delete_profile = ProfileOp::Delete { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let reload = FirewallOp::Reload;
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };

        reporter.destroy_starting(name);

        self.run(&delete_user, reporter)?;
        match self.run(&probe, reporter) {
            Ok(()) => {
                self.run(&cleanup, reporter)?;
            }
            Err(AccountError::NonZero { .. }) => {
                // Probe found directory service clean — no cleanup.
            }
            Err(other) => return Err(DestroyError::Account(other)),
        }

        self.run(&remove_host, reporter)?;
        self.run(&delete_group, reporter)?;
        self.run(&delete_profile, reporter)
            .map_err(DestroyError::Profile)?;

        let pf_conf_current = self
            .machine
            .read_pf_conf()
            .map_err(DestroyError::Firewall)?;
        let update_conf = FirewallOp::UpdateConfig {
            content: remove_anchor_ref(&pf_conf_current, name.as_str()),
        };
        self.run(&backup, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&remove_anchor, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&update_conf, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&reload, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&flush_anchor, reporter)
            .map_err(DestroyError::Firewall)?;

        reporter.destroy_done(name);
        Ok(())
    }

    /// Convergence path when the tenant user is already absent but the
    /// suffixed group (and possibly anchor / pf.conf reference) remain.
    /// Every step is substrate-idempotent so the path is single-pass.
    pub(crate) fn destroy_orphan_group(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        let group = tenant_share_group_name(name.as_str());
        let remove_host = AccountOp::RemoveHostFromShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        let delete_group = AccountOp::DeleteShareGroup { group };
        let delete_profile = ProfileOp::Delete { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let reload = FirewallOp::Reload;
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };

        reporter.orphan_group_starting(name);

        self.run(&remove_host, reporter)?;
        self.run(&delete_group, reporter)?;
        self.run(&delete_profile, reporter)
            .map_err(DestroyError::Profile)?;

        let pf_conf_current = self
            .machine
            .read_pf_conf()
            .map_err(DestroyError::Firewall)?;
        let update_conf = FirewallOp::UpdateConfig {
            content: remove_anchor_ref(&pf_conf_current, name.as_str()),
        };
        self.run(&backup, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&remove_anchor, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&update_conf, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&reload, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&flush_anchor, reporter)
            .map_err(DestroyError::Firewall)?;

        reporter.orphan_group_done(name);
        Ok(())
    }
}
