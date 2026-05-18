//! `HostUserName` carries the `User` qualifier deliberately: bare
//! `HostName` is a polyseme with the networking term (DNS hostname);
//! the qualifier disambiguates and the symmetric `TenantUserName`
//! keeps the pair parallel.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(pub u32);

impl UserId {
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

// No `From<UserId> for u32` — unwrapping is explicit (`uid.0`) so it
// shows in diffs.
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

// `From<&Self>` mirrors `String: From<&String>` so callers can `.into()`
// from a borrow without an explicit `.clone()`.
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

// Mirrors `String`'s `PartialEq<str>` / `PartialEq<&str>` impls so
// comparisons against string literals work without a `.as_str()`.
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

// Infallible so clap's derive macro can parse `TenantUserName` directly
// from CLI input; validation lives separately at dispatch.
impl FromStr for TenantUserName {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}
