use crate::domain::{HostUserDirectory, TenantUserName, UserDirectoryError};

use super::tenant_share_group_name;

const MAX_NAME_LEN: usize = 31;

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

/// The leading-letter rule is load-bearing: it excludes the macOS `_*` service-account
/// namespace and any `-…` name the substrate would parse as a flag.
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

pub fn check_conflict(
    directory: &dyn HostUserDirectory,
    name: &TenantUserName,
) -> Result<Option<ConflictError>, UserDirectoryError> {
    let group = tenant_share_group_name(name.as_str());
    Ok(
        match (directory.has_user(name)?, directory.has_group(&group)?) {
            (false, false) => None,
            (true, false) => Some(ConflictError::UserExists),
            (false, true) => Some(ConflictError::GroupExists),
            (true, true) => Some(ConflictError::Both),
        },
    )
}
