use std::collections::HashSet;

use crate::accounts::Reader;

/// Lower bound for tenant UIDs — clear of macOS system accounts (0–500)
/// and the human-user range (typically starting at 501).
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
