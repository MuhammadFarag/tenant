//! Per-tenant share-validation errors that fire at pre-flight before
//! any ACL or symlink mutation.

use std::fmt;
use std::path::PathBuf;

use crate::domain::reporter::Reporter;
use crate::domain::{AccountOp, AclMode, AclOp, PathKind, TenantUserName};
use crate::profile::{Profile, ShareMode, expand_tenant_path};

use super::reapply::ModeError;
use super::{Tenants, tenant_share_group_name};

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

/// One per-share entry's op triple. `ensure_dir` is `None` when the
/// tenant_path's parent is the tenant home itself.
pub(crate) struct ShareOps {
    pub(crate) grant: AclOp,
    pub(crate) ensure_dir: Option<AccountOp>,
    pub(crate) ensure_link: AccountOp,
}

impl ShareOps {
    pub(crate) fn op_count(&self) -> usize {
        2 + if self.ensure_dir.is_some() { 1 } else { 0 }
    }
}

impl<'a> Tenants<'a> {
    pub(crate) fn build_share_ops(
        &self,
        name: &TenantUserName,
        parsed_profile: &Profile,
    ) -> Result<Vec<ShareOps>, ModeError> {
        if parsed_profile.shares.is_empty() {
            return Ok(Vec::new());
        }
        let group = tenant_share_group_name(name.as_str());
        let home_dir = PathBuf::from(format!("/Users/{name}"));
        let mut out = Vec::with_capacity(parsed_profile.shares.len());
        for share in &parsed_profile.shares {
            if !share.host_path.exists() {
                return Err(ModeError::Share(ShareError::HostPathMissing {
                    path: share.host_path.clone(),
                }));
            }
            let tenant_path = expand_tenant_path(name.as_str(), &share.tenant_path);
            let kind = self
                .machine
                .tenant_path_kind(name, &tenant_path)
                .map_err(ModeError::Probe)?;
            if matches!(kind, PathKind::Dir | PathKind::Other) {
                return Err(ModeError::Share(ShareError::TenantPathOccupied {
                    path: tenant_path,
                }));
            }
            let acl_mode = match share.mode {
                ShareMode::Ro => AclMode::Ro,
                ShareMode::Rw => AclMode::Rw,
            };
            let grant = AclOp::Grant {
                path: share.host_path.clone(),
                group: group.clone(),
                mode: acl_mode,
            };
            // Skip parent-dir ensure when the parent is the tenant home itself.
            let ensure_dir = tenant_path.parent().and_then(|parent| {
                if parent == home_dir.as_path() {
                    None
                } else {
                    Some(AccountOp::EnsureDirAsUser {
                        name: name.into(),
                        path: parent.to_path_buf(),
                    })
                }
            });
            let ensure_link = AccountOp::EnsureSymlinkAsUser {
                name: name.into(),
                link: tenant_path,
                target: share.host_path.clone(),
            };
            out.push(ShareOps {
                grant,
                ensure_dir,
                ensure_link,
            });
        }
        Ok(out)
    }

    /// Share-only reapply at create-time. Skips the PF reapply already
    /// done by the create-time firewall sequence.
    pub(crate) fn reapply_shares_post_provision(
        &self,
        name: &TenantUserName,
        parsed_profile: &Profile,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        let share_ops = self.build_share_ops(name, parsed_profile)?;
        self.execute_share_ops(&share_ops, reporter)
    }

    pub(crate) fn execute_share_ops(
        &self,
        share_ops: &[ShareOps],
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        for share in share_ops {
            self.run(&share.grant, reporter).map_err(ModeError::Acl)?;
            if let Some(ensure_dir) = &share.ensure_dir {
                self.run(ensure_dir, reporter).map_err(ModeError::Account)?;
            }
            self.run(&share.ensure_link, reporter)
                .map_err(ModeError::Account)?;
        }
        Ok(())
    }
}
