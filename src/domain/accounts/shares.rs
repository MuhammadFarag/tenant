//! Per-tenant share-validation errors that fire at pre-flight before
//! any ACL or symlink mutation.

use std::fmt;
use std::path::PathBuf;

/// Pre-flight refusals from the share-reapply substrate.
/// `TenantPathOccupied` fires when tenant_path exists as a real
/// directory or file (not a symlink): the substrate would silently
/// fail to replace it.
#[derive(Debug)]
pub(crate) enum ShareError {
    HostPathMissing { path: PathBuf },
    TenantPathOccupied { path: PathBuf },
}

impl fmt::Display for ShareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShareError::HostPathMissing { path } => write!(
                f,
                "host_path {} does not exist on disk; edit the profile or create the path",
                path.display(),
            ),
            ShareError::TenantPathOccupied { path } => write!(
                f,
                "tenant_path {} exists as a real directory or file; \
                 remove it or edit the profile to point elsewhere",
                path.display(),
            ),
        }
    }
}
