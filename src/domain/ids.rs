//! Newtype wrappers for tenant + operator identifiers, both numeric
//! (`UserId` / `GroupId`) and string-shaped (`TenantUserName` /
//! `HostUserName` / `GroupName`). The numeric pair carries POSIX UIDs /
//! GIDs and protects against UID-vs-GID position swaps. The user-name
//! pair carries macOS short usernames in two distinct roles — the
//! sandboxed tenant user and the host operator — and protects against
//! tenant-name-vs-host-name position swaps in the many
//! `(name, host, ...)` signatures. `GroupName` carries the full
//! macOS short group name (always `<tenant>-tenant-share` today; the
//! suffix is appended at the Writer boundary by
//! `accounts::tenant_share_group_name`) and protects share-group
//! AccountOp variants and the share ACL ops from accidentally
//! receiving a tenant name where a group name belongs.
//!
//! `HostUserName` carries the `User` qualifier deliberately: bare
//! `HostName` is a polyseme with the networking term (DNS hostname,
//! `/etc/hostname`, `uname -n`); the qualifier disambiguates and the
//! symmetric `TenantUserName` keeps the pair parallel.
//!
//! Validation for `TenantUserName` lives outside the constructor —
//! `validate_name` is still the gatekeeper at the dispatch layer.
//! The newtype is a tag, not a validity proof; future work may move
//! validation into a `try_new` constructor. `GroupName` is similarly
//! constructed without validation; today's only producer is
//! `accounts::tenant_share_group_name`, which appends the suffix to an
//! already-validated tenant name.

use std::fmt;
use std::str::FromStr;

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantUserName(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostUserName(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupName(pub String);

impl TenantUserName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl HostUserName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl GroupName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantUserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for HostUserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for GroupName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for TenantUserName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for TenantUserName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for HostUserName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for HostUserName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for GroupName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for GroupName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// `From<&Self>` for cheap `.into()` at substrate ADT construction
// sites — `AccountOp::CreateTenantUser { name: name.into(), ... }` where
// `name: &TenantUserName`. Without this, callers would have to use
// `.clone()` explicitly. Same shape as `String: From<&String>`.
impl From<&TenantUserName> for TenantUserName {
    fn from(s: &TenantUserName) -> Self {
        s.clone()
    }
}

impl From<&HostUserName> for HostUserName {
    fn from(s: &HostUserName) -> Self {
        s.clone()
    }
}

impl From<&GroupName> for GroupName {
    fn from(s: &GroupName) -> Self {
        s.clone()
    }
}

// `PartialEq<str>` / `PartialEq<&str>` for ergonomic test assertions
// (`assert_eq!(name, "dev")`) and `match`/`if`-let comparisons inline
// in dispatch. Mirrors `String`'s PartialEq impls in std.
impl PartialEq<str> for TenantUserName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<TenantUserName> for str {
    fn eq(&self, other: &TenantUserName) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for TenantUserName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<TenantUserName> for &str {
    fn eq(&self, other: &TenantUserName) -> bool {
        *self == other.0
    }
}

impl PartialEq<str> for HostUserName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<HostUserName> for str {
    fn eq(&self, other: &HostUserName) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for HostUserName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<HostUserName> for &str {
    fn eq(&self, other: &HostUserName) -> bool {
        *self == other.0
    }
}

impl PartialEq<str> for GroupName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<GroupName> for str {
    fn eq(&self, other: &GroupName) -> bool {
        self == other.0
    }
}

impl PartialEq<&str> for GroupName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<GroupName> for &str {
    fn eq(&self, other: &GroupName) -> bool {
        *self == other.0
    }
}

// `FromStr` exists so clap's derive macro can parse `TenantUserName`
// directly from CLI input without a custom `value_parser`. Validation
// lives separately (`accounts::validate_name`); the constructor is
// infallible.
impl FromStr for TenantUserName {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}
