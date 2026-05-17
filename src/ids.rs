//! Newtype wrappers for POSIX user and group identifiers. The two
//! spaces are independently allocated by `UidAllocator` and
//! `GidAllocator`; the newtypes make `UserId` and `GroupId`
//! compile-error-distinct so a position-swap in a multi-argument call
//! (`create_tenant(name, host, uid, gid, ...)` — adjacent same-type
//! params) trips the compiler instead of running silently.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(pub u32);

impl UserId {
    /// Next UID in ascending order. Used by the allocator's "find
    /// lowest free" walk; no overflow check (the search range bottoms
    /// out at `TENANT_UID_FLOOR = 600` and u32::MAX is unreachable in
    /// practice).
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl GroupId {
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// `From<u32>` for cheap construction at parse boundaries (dscl output,
// allocator iteration). No `From<UserId> for u32` — unwrapping is
// explicit (`uid.0`) so it shows in diffs.
impl From<u32> for UserId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<u32> for GroupId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}
