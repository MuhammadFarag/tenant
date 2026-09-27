use std::path::{Path, PathBuf};

use super::host_machine::WritableOp;
use super::reporter::Reporter;
use super::{AccountError, GroupName, HostMachine, PathKind, ProbeError, TenantUserName};
use crate::profile::{
    Profile, ProfileError, ProfileRole, display_fragment_path_for, merge, parse_partial,
};

pub mod bootstrap;
pub mod create;
pub mod destroy;
pub mod doctor;
pub mod reapply;
pub mod setup;
pub mod shares;
pub mod shell;
pub mod validation;

pub(crate) use bootstrap::{BootstrapError, surface_bootstrap_error};
pub(crate) use create::CreateError;
pub(crate) use destroy::{DestroyError, Eligibility, destroy_eligibility};
pub(crate) use doctor::{DoctorError, DoctorOutcome, DoctorScope};
pub(crate) use reapply::{ModeError, ReapplyScope};
pub(crate) use setup::SetupError;
pub(crate) use shares::ShareError;
pub(crate) use shell::ShellError;
pub use validation::{ConflictError, NameError, check_conflict, validate_name};

pub fn tenant_share_group_name(name: &str) -> GroupName {
    GroupName(format!("{name}-tenant-share"))
}

pub const COWORK_DIR_PARENT: &str = "/Users/Shared/tenants";

pub fn cowork_dir_path(name: &str) -> PathBuf {
    PathBuf::from(format!("{COWORK_DIR_PARENT}/{name}"))
}

/// `mkdir -p` over a symlink silently follows it, and the later chown / chmod -R would
/// mutate the link's target. Probes host-side: the tenant user may not exist yet.
pub(super) fn guard_cowork_dir_kind(
    machine: &dyn HostMachine,
    path: &Path,
) -> Result<(), AccountError> {
    let kind = machine.host_path_kind(path).map_err(probe_to_account_err)?;
    match kind {
        PathKind::Absent | PathKind::Dir => Ok(()),
        PathKind::Symlink(_) | PathKind::Other => Err(AccountError::CoworkDirOccupied {
            path: path.to_path_buf(),
            kind,
        }),
    }
}

fn wrap_fragment_error(fragment: &str, err: ProfileError) -> ProfileError {
    ProfileError {
        message: format!(
            "include \"{fragment}\" ({path}): {err}",
            path = display_fragment_path_for(fragment)
        ),
    }
}

fn probe_to_account_err(err: ProbeError) -> AccountError {
    match err {
        ProbeError::Spawn(e) => AccountError::Spawn(e),
        ProbeError::NonZero { code, stderr } => AccountError::NonZero { code, stderr },
    }
}

pub(crate) struct Tenants<'a> {
    pub(super) machine: &'a dyn HostMachine,
}

impl<'a> Tenants<'a> {
    pub(crate) fn new(machine: &'a dyn HostMachine) -> Self {
        Self { machine }
    }

    /// The one profile-load path: fragments merge first, tenant profile last. Doctor's
    /// anchor-body check renders from this merge, so an unreloaded fragment edit surfaces
    /// as `AnchorBodyDrift` on every includer.
    pub(super) fn load_profile(&self, name: &TenantUserName) -> Result<Profile, ProfileError> {
        let content = self.machine.read_profile(name)?;
        let base = parse_partial(&content, ProfileRole::Tenant)?;
        let includes = base.include.clone();
        let mut parts = Vec::with_capacity(includes.len() + 1);
        for fragment in &includes {
            let frag_content = self
                .machine
                .read_profile_fragment(fragment)
                .map_err(|e| wrap_fragment_error(fragment, e))?;
            let part = parse_partial(&frag_content, ProfileRole::Fragment)
                .map_err(|e| wrap_fragment_error(fragment, e))?;
            parts.push(part);
        }
        parts.push(base);
        merge(parts)
    }

    /// Couples narration to execution so no caller can run an op silently.
    pub(super) fn run<O: WritableOp>(
        &self,
        op: &O,
        reporter: &mut Reporter,
    ) -> Result<(), O::Error> {
        reporter.step(op.op_ref());
        op.execute_via(self.machine)?;
        reporter.progress(op.op_ref());
        Ok(())
    }
}
