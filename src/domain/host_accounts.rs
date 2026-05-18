use super::errors::AccountsError;
use super::ids::{GroupId, GroupName, TenantUserName, UserId};

pub trait HostAccounts {
    fn used_uids(&self) -> Result<Vec<UserId>, AccountsError>;
    fn used_gids(&self) -> Result<Vec<GroupId>, AccountsError>;
    fn has_user(&self, name: &TenantUserName) -> Result<bool, AccountsError>;
    fn has_group(&self, group: &GroupName) -> Result<bool, AccountsError>;
    /// Returns the positive UID for `name`, or `None` if either (a) the
    /// account doesn't exist, or (b) the account exists with a non-positive
    /// UID (negative-UID system accounts like `nobody` on macOS). Callers
    /// that need to distinguish "absent" from "present with no positive UID"
    /// must consult `has_user` separately.
    fn uid_for(&self, name: &TenantUserName) -> Result<Option<UserId>, AccountsError>;
    /// All account names with a tenant-range UID (>= `TENANT_UID_FLOOR`),
    /// alphabetical. Stable order keeps doctor's all-tenants diff
    /// meaningful across runs.
    fn tenant_names(&self) -> Result<Vec<TenantUserName>, AccountsError>;
}
