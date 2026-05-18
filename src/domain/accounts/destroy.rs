//! Destroy-verb error type and the eligibility classifier that gates
//! destroy at dispatch.

use crate::allocation::TENANT_UID_FLOOR;
use crate::domain::{AccountError, FirewallError, HostAccounts, TenantUserName, UserId};
use crate::profile::ProfileError;

use super::tenant_share_group_name;

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

pub fn destroy_eligibility(reader: &dyn HostAccounts, name: &TenantUserName) -> Eligibility {
    if !reader.has_user(name) {
        if reader.has_group(&tenant_share_group_name(name.as_str())) {
            return Eligibility::OrphanGroup;
        }
        return Eligibility::NotPresent;
    }
    match reader.uid_for(name) {
        Some(uid) if uid.0 >= TENANT_UID_FLOOR => Eligibility::Destroyable,
        Some(uid) => Eligibility::NotATenant { uid },
        None => Eligibility::SystemAccount,
    }
}
