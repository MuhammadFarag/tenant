use super::errors::UserDirectoryError;
use super::ids::{GroupId, GroupName, TenantUserName, UserId};

pub trait HostUserDirectory {
    fn used_uids(&self) -> Result<Vec<UserId>, UserDirectoryError>;
    fn used_gids(&self) -> Result<Vec<GroupId>, UserDirectoryError>;
    fn has_user(&self, name: &TenantUserName) -> Result<bool, UserDirectoryError>;
    fn has_group(&self, group: &GroupName) -> Result<bool, UserDirectoryError>;
    /// Returns the positive UID for `name`, or `None` if either (a) the
    /// account doesn't exist, or (b) the account exists with a non-positive
    /// UID (negative-UID system accounts like `nobody` on macOS). Callers
    /// that need to distinguish "absent" from "present with no positive UID"
    /// must consult `has_user` separately.
    fn uid_for(&self, name: &TenantUserName) -> Result<Option<UserId>, UserDirectoryError>;
    /// All account names with a tenant-range UID (>= `TENANT_UID_FLOOR`),
    /// alphabetical. Stable order keeps doctor's all-tenants diff
    /// meaningful across runs.
    fn tenant_names(&self) -> Result<Vec<TenantUserName>, UserDirectoryError>;
}
