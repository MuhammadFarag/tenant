use std::collections::HashSet;

use crate::accounts::Reader;

/// Lower bound for tenant UIDs *and* GIDs — clear of macOS system
/// accounts (0–500) and the human-user range (typically starting at
/// 501). The same floor applies to both spaces: a tenant's primary
/// group lives in the same numeric range as the tenant user, even
/// when the two values themselves diverge.
pub const TENANT_UID_FLOOR: u32 = 600;

pub struct UidAllocator<'a> {
    reader: &'a dyn Reader,
}

impl<'a> UidAllocator<'a> {
    pub fn new(reader: &'a dyn Reader) -> Self {
        Self { reader }
    }

    pub fn lowest_free_uid(&self) -> u32 {
        let used: HashSet<u32> = self.reader.used_uids().into_iter().collect();
        (TENANT_UID_FLOOR..)
            .find(|uid| !used.contains(uid))
            .expect("u32 range exhausted searching for a free UID")
    }
}

/// Mirror of `UidAllocator` for the GID space. The two allocators are
/// deliberately separate: tenant creation doesn't constrain UID == GID,
/// so a tenant created on a host with prior tenants may legitimately
/// land on (UID 613, GID 600). The single-floor convention means
/// both numbers stay clear of macOS system ranges either way.
pub struct GidAllocator<'a> {
    reader: &'a dyn Reader,
}

impl<'a> GidAllocator<'a> {
    pub fn new(reader: &'a dyn Reader) -> Self {
        Self { reader }
    }

    pub fn lowest_free_gid(&self) -> u32 {
        let used: HashSet<u32> = self.reader.used_gids().into_iter().collect();
        (TENANT_UID_FLOOR..)
            .find(|gid| !used.contains(gid))
            .expect("u32 range exhausted searching for a free GID")
    }
}
