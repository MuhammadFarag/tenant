use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use crate::allocation::TENANT_UID_FLOOR;
use crate::domain::{AccountsError, GroupId, GroupName, HostAccounts, TenantUserName, UserId};

/// Test substitute for `HostAccounts`. Each `fail_*` field is a queue
/// of pending per-call outcomes: every call to the matching trait method
/// pops the front of the queue. `Some(err)` returns `Err(err)`,
/// `None` falls through to the snapshot lookup, and an empty queue
/// also falls through. The Some/None queue shape (rather than a flat
/// `Option<AccountsError>`) is load-bearing for dispatch frames that
/// fire on the SECOND call to a method — e.g. `destroy_uid_lookup_failed`
/// fires only after `destroy_eligibility` has already consumed the
/// first `uid_for` call, so the test queues `[None, Some(err)]` to
/// skip the eligibility call and fail the dispatch lookup. Empty
/// default queues keep the existing `..Default::default()` struct
/// literals working unchanged.
#[derive(Default)]
pub struct StubHostAccounts {
    pub uid_by_name: HashMap<String, UserId>,
    pub gid_by_name: HashMap<String, GroupId>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub fail_used_uids: RefCell<VecDeque<Option<AccountsError>>>,
    pub fail_used_gids: RefCell<VecDeque<Option<AccountsError>>>,
    pub fail_has_user: RefCell<VecDeque<Option<AccountsError>>>,
    pub fail_has_group: RefCell<VecDeque<Option<AccountsError>>>,
    pub fail_uid_for: RefCell<VecDeque<Option<AccountsError>>>,
    pub fail_tenant_names: RefCell<VecDeque<Option<AccountsError>>>,
}

impl HostAccounts for StubHostAccounts {
    fn used_uids(&self) -> Result<Vec<UserId>, AccountsError> {
        if let Some(Some(err)) = self.fail_used_uids.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.uid_by_name.values().copied().collect())
    }

    fn used_gids(&self) -> Result<Vec<GroupId>, AccountsError> {
        if let Some(Some(err)) = self.fail_used_gids.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.gid_by_name.values().copied().collect())
    }

    fn has_user(&self, name: &TenantUserName) -> Result<bool, AccountsError> {
        if let Some(Some(err)) = self.fail_has_user.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.users.iter().any(|u| u == name.as_str()))
    }

    fn has_group(&self, group: &GroupName) -> Result<bool, AccountsError> {
        if let Some(Some(err)) = self.fail_has_group.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.groups.iter().any(|g| g == group.as_str()))
    }

    fn uid_for(&self, name: &TenantUserName) -> Result<Option<UserId>, AccountsError> {
        if let Some(Some(err)) = self.fail_uid_for.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.uid_by_name.get(name.as_str()).copied())
    }

    fn tenant_names(&self) -> Result<Vec<TenantUserName>, AccountsError> {
        if let Some(Some(err)) = self.fail_tenant_names.borrow_mut().pop_front() {
            return Err(err);
        }
        let mut out: Vec<TenantUserName> = self
            .uid_by_name
            .iter()
            .filter(|(_, uid)| uid.0 >= TENANT_UID_FLOOR)
            .map(|(name, _)| TenantUserName(name.clone()))
            .collect();
        out.sort();
        Ok(out)
    }
}
