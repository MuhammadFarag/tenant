//! `HostUserName`, not `HostName`: avoids the DNS-hostname polyseme.

use std::fmt;
use std::fs::File;
use std::io::Read;
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

// Mirrors `String: From<&String>` so a borrow can `.into()`.
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

// Mirrors `String`'s `PartialEq<str>` / `PartialEq<&str>` impls.
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

// Infallible so clap can parse it directly; validation runs at dispatch.
impl FromStr for TenantUserName {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

/// Protects the tenant's keychain and is stashed in the operator's keychain
/// so `shell` / `bootstrap` can unlock it non-interactively. Not an account
/// password.
#[derive(Clone, PartialEq, Eq)]
pub struct KeychainPassword(String);

impl KeychainPassword {
    /// Panics on RNG read failure: not operator-actionable, and the
    /// alternative is shipping a weak password.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        let mut f = File::open("/dev/urandom").expect("/dev/urandom must be readable");
        f.read_exact(&mut bytes)
            .expect("/dev/urandom read must succeed");
        let mut hex = String::with_capacity(64);
        for b in bytes {
            hex.push_str(&format!("{b:02x}"));
        }
        Self(hex)
    }

    /// `secrecy`-crate naming so a stray `format!` of it reads as a red flag.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// `describe_keychain` never renders the value. `pub(crate)` so library
    /// consumers can't bypass `generate()`.
    pub(crate) fn for_plan_placeholder() -> Self {
        Self("<plan-placeholder>".to_string())
    }

    /// Value read back from the operator keychain by the macOS adapter.
    pub(crate) fn from_existing(s: String) -> Self {
        Self(s)
    }

    // TODO(smell): gate `test_dummy` behind a test-only cargo feature instead of naming-only enforcement
    /// Test fixtures only; `#[cfg(test)]` doesn't reach `tests/`, so the name
    /// is the guard — a production call site fails review.
    pub fn test_dummy(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// `<redacted>` so accidental log/panic output never leaks the secret.
impl fmt::Debug for KeychainPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeychainPassword")
            .field(&"<redacted>")
            .finish()
    }
}
