use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use tenant::allocation::TENANT_UID_FLOOR;
use tenant::domain::{
    GroupId, GroupName, HostUserDirectory, TenantUserName, UserDirectoryError, UserId,
};

/// Each `fail_*` queue pops once per call: `Some(err)` fails that call; `None` or an empty
/// queue falls through to the snapshot. `[None, Some(err)]` fails the SECOND call (e.g. a
/// dispatch lookup after eligibility consumed the first).
#[derive(Default)]
pub struct StubUserDirectory {
    pub uid_by_name: HashMap<String, UserId>,
    pub gid_by_name: HashMap<String, GroupId>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub fail_used_uids: RefCell<VecDeque<Option<UserDirectoryError>>>,
    pub fail_used_gids: RefCell<VecDeque<Option<UserDirectoryError>>>,
    pub fail_has_user: RefCell<VecDeque<Option<UserDirectoryError>>>,
    pub fail_has_group: RefCell<VecDeque<Option<UserDirectoryError>>>,
    pub fail_uid_for: RefCell<VecDeque<Option<UserDirectoryError>>>,
    pub fail_tenant_names: RefCell<VecDeque<Option<UserDirectoryError>>>,
}

impl HostUserDirectory for StubUserDirectory {
    fn used_uids(&self) -> Result<Vec<UserId>, UserDirectoryError> {
        if let Some(Some(err)) = self.fail_used_uids.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.uid_by_name.values().copied().collect())
    }

    fn used_gids(&self) -> Result<Vec<GroupId>, UserDirectoryError> {
        if let Some(Some(err)) = self.fail_used_gids.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.gid_by_name.values().copied().collect())
    }

    fn has_user(&self, name: &TenantUserName) -> Result<bool, UserDirectoryError> {
        if let Some(Some(err)) = self.fail_has_user.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.users.iter().any(|u| u == name.as_str()))
    }

    fn has_group(&self, group: &GroupName) -> Result<bool, UserDirectoryError> {
        if let Some(Some(err)) = self.fail_has_group.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.groups.iter().any(|g| g == group.as_str()))
    }

    fn uid_for(&self, name: &TenantUserName) -> Result<Option<UserId>, UserDirectoryError> {
        if let Some(Some(err)) = self.fail_uid_for.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.uid_by_name.get(name.as_str()).copied())
    }

    fn tenant_names(&self) -> Result<Vec<TenantUserName>, UserDirectoryError> {
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
