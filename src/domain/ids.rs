//! `HostUserName` carries the `User` qualifier deliberately: bare
//! `HostName` is a polyseme with the networking term (DNS hostname);
//! the qualifier disambiguates and the symmetric `TenantUserName`
//! keeps the pair parallel.

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

/// Random secret used to protect the tenant's login keychain AND
/// stashed in the operator's keychain so a future non-interactive
/// unlock pass works. Distinct from any macOS account password.
/// Hex-encoded 32-byte
/// random read from `/dev/urandom`; `Debug` redacts the value so
/// accidental `{:?}` formatting in logs / error trails / panics never
/// leaks the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct KeychainPassword(String);

impl KeychainPassword {
    /// Read 32 bytes from `/dev/urandom`, hex-encode. Macos-only target
    /// → no fallback path. Panics on read failure: the OS RNG being
    /// unreachable is not an actionable error for the operator and the
    /// alternative is silently shipping a weak password.
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

    /// Borrow the password as `&str`. Named after the `secrecy` crate
    /// convention so future log/format misuse looks obviously wrong at
    /// the call site (`format!("{}", pw.expose_secret())` reads as a
    /// red flag in a way that `pw.as_str()` does not). The two
    /// legitimate consumers — the `security create-keychain -p <pw>`
    /// and `security add-generic-password -w <pw>` argv builders in
    /// `adapters/macos/host_machine.rs` — pass the password to argv
    /// briefly and are commented as the platform-limit carve-out.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Plan-rendering placeholder. The verbose plan section renders
    /// keychain ops via `describe_keychain`, which substitutes
    /// `<password>` for the actual bytes regardless of value — but a
    /// `KeychainPassword` still has to be constructed for the
    /// `KeychainOp` variant. `pub(crate)` keeps external library
    /// consumers from threading arbitrary strings into `Tenants::create`
    /// and bypassing `/dev/urandom`-backed `generate()`.
    pub(crate) fn for_plan_placeholder() -> Self {
        Self("<plan-placeholder>".to_string())
    }

    /// Wrap a password value retrieved from the substrate (operator
    /// keychain via `security find-generic-password -w`). `pub(crate)`
    /// so only the macOS adapter can construct one from substrate
    /// output; external library consumers are routed through
    /// `generate()` for fresh provisioning, never through arbitrary
    /// strings. Distinct from `for_plan_placeholder()` (plan-render
    /// only) and `test_dummy()` (test-fixture only).
    pub(crate) fn from_existing(s: String) -> Self {
        Self(s)
    }

    /// Test-fixture constructor. Deliberately named so that any
    /// production-code call site is a visible smell at review: the
    /// only sanctioned way to construct a real password is `generate()`
    /// (which reads `/dev/urandom`). Integration tests in `tests/`
    /// need this to build fixture `KeychainOp` variants whose password
    /// value is never inspected (describe-side substitutes `<password>`,
    /// stub-side ignores the value). `#[cfg(test)]` doesn't reach
    /// integration tests, so naming-enforcement is what we have —
    /// `KeychainPassword::test_dummy("admin")` in a production diff
    /// fails review on sight.
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
