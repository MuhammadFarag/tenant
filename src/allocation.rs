use std::collections::HashSet;

use crate::domain::{GroupId, HostUserDirectory, UserDirectoryError, UserId};

/// Lower bound for tenant UIDs *and* GIDs — clear of system accounts
/// (0–500) and the regular user range (501+).
pub const TENANT_UID_FLOOR: u32 = 600;

pub struct UidAllocator<'a> {
    directory: &'a dyn HostUserDirectory,
}

impl<'a> UidAllocator<'a> {
    pub fn new(directory: &'a dyn HostUserDirectory) -> Self {
        Self { directory }
    }

    pub fn lowest_free_uid(&self) -> Result<UserId, UserDirectoryError> {
        let used: HashSet<UserId> = self.directory.used_uids()?.into_iter().collect();
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
    directory: &'a dyn HostUserDirectory,
}

impl<'a> GidAllocator<'a> {
    pub fn new(directory: &'a dyn HostUserDirectory) -> Self {
        Self { directory }
    }

    pub fn lowest_free_gid(&self) -> Result<GroupId, UserDirectoryError> {
        let used: HashSet<GroupId> = self.directory.used_gids()?.into_iter().collect();
        let mut candidate = GroupId(TENANT_UID_FLOOR);
        loop {
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
            candidate = candidate.next();
        }
    }
}
