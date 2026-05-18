//! Pre-verb-gate validation: charset rules and state-existence checks
//! that fire before any verb logic touches the substrate.

use crate::domain::{AccountsError, HostAccounts, TenantUserName};

use super::tenant_share_group_name;

const MAX_NAME_LEN: usize = 31;

/// Names that pass the lexical charset rules but alias real accounts
/// or carry privileged semantics. The `_*` service-account namespace
/// is already excluded by the leading-letter rule.
const RESERVED_NAMES: &[&str] = &[
    "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
];

#[derive(Debug)]
pub enum NameError {
    Empty,
    InvalidStart(char),
    InvalidCharacter(char),
    TooLong { len: usize, max: usize },
    Reserved,
}

#[derive(Debug)]
pub enum ConflictError {
    UserExists,
    GroupExists,
    Both,
}

/// Lexical name guard: `[a-z][a-z0-9_-]{0,30}`. The leading-letter rule
/// is load-bearing — it excludes the macOS service-account namespace and
/// any `-…` argv that the substrate would interpret as a flag.
pub fn validate_name(name: &TenantUserName) -> Result<(), NameError> {
    let name = name.as_str();
    let len = name.len();
    if len == 0 {
        return Err(NameError::Empty);
    }
    if len > MAX_NAME_LEN {
        return Err(NameError::TooLong {
            len,
            max: MAX_NAME_LEN,
        });
    }
    let mut chars = name.chars();
    let first = chars.next().expect("len > 0 guarantees at least one char");
    if !first.is_ascii_lowercase() {
        return Err(NameError::InvalidStart(first));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return Err(NameError::InvalidCharacter(c));
        }
    }
    // Reserved check runs last so `Wheel` trips the more-specific
    // `InvalidStart` rather than the blunter `Reserved`.
    if RESERVED_NAMES.contains(&name) {
        return Err(NameError::Reserved);
    }
    Ok(())
}

/// Returns `Ok(None)` when the name is free, `Ok(Some(_))` when an
/// existing user / group / both already occupies the namespace, and
/// `Err(_)` when the directory query itself failed. Splitting the
/// outcomes lets dispatch route lookup failure to a substep-named
/// frame distinct from the conflict-refusal frame.
pub fn check_conflict(
    reader: &dyn HostAccounts,
    name: &TenantUserName,
) -> Result<Option<ConflictError>, AccountsError> {
    let group = tenant_share_group_name(name.as_str());
    Ok(match (reader.has_user(name)?, reader.has_group(&group)?) {
        (false, false) => None,
        (true, false) => Some(ConflictError::UserExists),
        (false, true) => Some(ConflictError::GroupExists),
        (true, true) => Some(ConflictError::Both),
    })
}
