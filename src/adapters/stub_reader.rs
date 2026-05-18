use std::collections::HashMap;

use crate::allocation::TENANT_UID_FLOOR;
use crate::domain::Reader;
use crate::ids::{GroupId, GroupName, TenantUserName, UserId};

#[derive(Default)]
pub struct StubReader {
    pub uid_by_name: HashMap<String, UserId>,
    pub gid_by_name: HashMap<String, GroupId>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
}

impl Reader for StubReader {
    fn used_uids(&self) -> Vec<UserId> {
        self.uid_by_name.values().copied().collect()
    }

    fn used_gids(&self) -> Vec<GroupId> {
        self.gid_by_name.values().copied().collect()
    }

    fn has_user(&self, name: &TenantUserName) -> bool {
        self.users.iter().any(|u| u == name.as_str())
    }

    fn has_group(&self, group: &GroupName) -> bool {
        self.groups.iter().any(|g| g == group.as_str())
    }

    fn uid_for(&self, name: &TenantUserName) -> Option<UserId> {
        self.uid_by_name.get(name.as_str()).copied()
    }

    fn tenant_names(&self) -> Vec<TenantUserName> {
        let mut out: Vec<TenantUserName> = self
            .uid_by_name
            .iter()
            .filter(|(_, uid)| uid.0 >= TENANT_UID_FLOOR)
            .map(|(name, _)| TenantUserName(name.clone()))
            .collect();
        out.sort();
        out
    }
}
