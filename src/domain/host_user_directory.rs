use super::errors::UserDirectoryError;
use super::ids::{GroupId, GroupName, TenantUserName, UserId};

pub trait HostUserDirectory {
    fn used_uids(&self) -> Result<Vec<UserId>, UserDirectoryError>;
    fn used_gids(&self) -> Result<Vec<GroupId>, UserDirectoryError>;
    fn has_user(&self, name: &TenantUserName) -> Result<bool, UserDirectoryError>;
    fn has_group(&self, group: &GroupName) -> Result<bool, UserDirectoryError>;
    /// `None` also for a present account with a non-positive UID (e.g. `nobody`);
    /// use `has_user` to tell the two apart.
    fn uid_for(&self, name: &TenantUserName) -> Result<Option<UserId>, UserDirectoryError>;
    /// Alphabetical, so doctor's all-tenants output is stable across runs.
    fn tenant_names(&self) -> Result<Vec<TenantUserName>, UserDirectoryError>;
}
