use std::collections::HashSet;

use crate::domain::{AccountsError, GroupId, HostAccounts, UserId};

/// Lower bound for tenant UIDs *and* GIDs — clear of system accounts
/// (0–500) and the regular user range (501+).
pub const TENANT_UID_FLOOR: u32 = 600;

pub struct UidAllocator<'a> {
    reader: &'a dyn HostAccounts,
}

impl<'a> UidAllocator<'a> {
    pub fn new(reader: &'a dyn HostAccounts) -> Self {
        Self { reader }
    }

    pub fn lowest_free_uid(&self) -> Result<UserId, AccountsError> {
        let used: HashSet<UserId> = self.reader.used_uids()?.into_iter().collect();
        let mut candidate = UserId(TENANT_UID_FLOOR);
        loop {
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
            candidate = candidate.next();
        }
    }
}

pub struct GidAllocator<'a> {
    reader: &'a dyn HostAccounts,
}

impl<'a> GidAllocator<'a> {
    pub fn new(reader: &'a dyn HostAccounts) -> Self {
        Self { reader }
    }

    pub fn lowest_free_gid(&self) -> Result<GroupId, AccountsError> {
        let used: HashSet<GroupId> = self.reader.used_gids()?.into_iter().collect();
        let mut candidate = GroupId(TENANT_UID_FLOOR);
        loop {
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
            candidate = candidate.next();
        }
    }
}
