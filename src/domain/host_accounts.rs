use super::ids::{GroupId, GroupName, TenantUserName, UserId};

pub trait HostAccounts {
    fn used_uids(&self) -> Vec<UserId>;
    fn used_gids(&self) -> Vec<GroupId>;
    fn has_user(&self, name: &TenantUserName) -> bool;
    fn has_group(&self, group: &GroupName) -> bool;
    /// Returns the positive UID for `name`, or `None` if either (a) the
    /// account doesn't exist, or (b) the account exists with a non-positive
    /// UID (negative-UID system accounts like `nobody` on macOS). Callers
    /// that need to distinguish "absent" from "present with no positive UID"
    /// must consult `has_user` separately.
    fn uid_for(&self, name: &TenantUserName) -> Option<UserId>;
    /// All account names with a tenant-range UID (>= `TENANT_UID_FLOOR`),
    /// alphabetical. Stable order keeps doctor's all-tenants diff
    /// meaningful across runs.
    fn tenant_names(&self) -> Vec<TenantUserName>;
}
