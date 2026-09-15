use std::fmt;
use std::path::PathBuf;

use crate::domain::reporter::Reporter;
use crate::domain::{AccountOp, AclMode, AclOp, PathKind, TenantUserName};
use crate::profile::{Profile, ShareMode, expand_tenant_path};

use super::reapply::{ModeError, ReapplyScope};
use super::{Tenants, tenant_share_group_name};

/// `TenantPathOccupied`: a real file or directory the symlink substrate can't replace.
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

pub(crate) struct ShareOps {
    pub(crate) grant: Option<AclOp>,
    pub(crate) ensure_dir: Option<AccountOp>,
    pub(crate) ensure_link: AccountOp,
}

impl ShareOps {
    pub(crate) fn op_count(&self) -> usize {
        1 + usize::from(self.grant.is_some()) + usize::from(self.ensure_dir.is_some())
    }
}

impl<'a> Tenants<'a> {
    pub(crate) fn build_share_ops(
        &self,
        name: &TenantUserName,
        parsed_profile: &Profile,
        scope: ReapplyScope,
    ) -> Result<Vec<ShareOps>, ModeError> {
        if parsed_profile.shares.is_empty() {
            return Ok(Vec::new());
        }
        let group = tenant_share_group_name(name.as_str());
        let home_dir = PathBuf::from(format!("/Users/{name}"));
        // `sudo -n` exits 1 on a cold timestamp, the same code `/bin/test` uses for "no", so
        // the occupancy probe needs a warm cache. Authenticate pre-plan so refusals still land
        // ahead of the prompt.
        if !self.machine.sudo_session_cached() {
            self.machine.authenticate_sudo().map_err(ModeError::Probe)?;
        }
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
            let grant = match scope {
                ReapplyScope::Full => Some(AclOp::Grant {
                    path: share.host_path.clone(),
                    group: group.clone(),
                    mode: acl_mode,
                }),
                ReapplyScope::Light => None,
            };
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

    /// Shares only: create's firewall sequence already did the PF half.
    pub(crate) fn reapply_shares_post_provision(
        &self,
        name: &TenantUserName,
        parsed_profile: &Profile,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        let share_ops = self.build_share_ops(name, parsed_profile, ReapplyScope::Full)?;
        self.execute_share_ops(&share_ops, reporter)
    }

    pub(crate) fn execute_share_ops(
        &self,
        share_ops: &[ShareOps],
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        for share in share_ops {
            if let Some(grant) = &share.grant {
                self.run(grant, reporter).map_err(ModeError::Acl)?;
            }
            if let Some(ensure_dir) = &share.ensure_dir {
                self.run(ensure_dir, reporter).map_err(ModeError::Account)?;
            }
            self.run(&share.ensure_link, reporter)
                .map_err(ModeError::Account)?;
        }
        Ok(())
    }
}
