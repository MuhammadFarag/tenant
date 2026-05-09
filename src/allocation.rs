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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::StubReader;

    #[test]
    fn lowest_free_uid_empty_returns_floor() {
        let reader = StubReader::default();
        let allocator = UidAllocator::new(&reader);
        assert_eq!(allocator.lowest_free_uid(), 600);
    }

    #[test]
    fn lowest_free_uid_floor_taken_returns_next() {
        let reader = StubReader {
            uids: vec![600],
            ..Default::default()
        };
        let allocator = UidAllocator::new(&reader);
        assert_eq!(allocator.lowest_free_uid(), 601);
    }

    #[test]
    fn lowest_free_uid_skips_to_first_gap() {
        let reader = StubReader {
            uids: vec![600, 601, 603],
            ..Default::default()
        };
        let allocator = UidAllocator::new(&reader);
        assert_eq!(allocator.lowest_free_uid(), 602);
    }

    #[test]
    fn lowest_free_uid_ignores_order() {
        let reader = StubReader {
            uids: vec![603, 600, 601],
            ..Default::default()
        };
        let allocator = UidAllocator::new(&reader);
        assert_eq!(allocator.lowest_free_uid(), 602);
    }

    #[test]
    fn lowest_free_uid_ignores_below_floor() {
        let reader = StubReader {
            uids: vec![500, 599],
            ..Default::default()
        };
        let allocator = UidAllocator::new(&reader);
        assert_eq!(allocator.lowest_free_uid(), 600);
    }
}
