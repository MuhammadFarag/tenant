use std::path::{Path, PathBuf};

use super::host_machine::WritableOp;
use super::reporter::Reporter;
use super::{AccountError, GroupName, HostMachine, PathKind, ProbeError};

pub mod create;
pub mod destroy;
pub mod doctor;
pub mod reapply;
pub mod shares;
pub mod shell;
pub mod validation;

pub(crate) use create::CreateError;
pub(crate) use destroy::{DestroyError, Eligibility, destroy_eligibility};
pub(crate) use doctor::{DoctorError, DoctorScope};
pub(crate) use reapply::ModeError;
pub(crate) use shares::ShareError;
pub(crate) use shell::ShellError;
pub use validation::{ConflictError, NameError, check_conflict, validate_name};

/// Single source of truth for the `<name>-tenant-share` suffix.
pub fn tenant_share_group_name(name: &str) -> GroupName {
    GroupName(format!("{name}-tenant-share"))
}

/// Single source of truth for the per-tenant co-working directory
/// path: `/Users/Shared/tenants/<name>`. Owned by the host operator
/// with the tenant's share group as primary, mode 2770 + an
/// inheritable rw ACL granting collaborative access to both sides.
pub fn cowork_dir_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/Users/Shared/tenants/{name}"))
}

/// Pre-flight: `mkdir -p` against an existing regular file errors,
/// and against a symlink silently follows the link — the subsequent
/// chown and chmod -R then mutate whatever lives at the link's
/// target. Probe-failure rides the existing `AccountError` shape so
/// it flows through the caller's `CoworkDir` / `Account` arm without
/// new plumbing. Fires on BOTH create AND every reapply (reload /
/// mode / shell): the kind-check prevents the substrate from
/// following a symlink at the cowork path, which is a state-machine
/// concern, not a race window. Probes host-side: the cowork dir is
/// owned by the host operator (the tenant user may not even exist
/// yet at create-time), and its kind doesn't depend on the tenant's
/// perspective.
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

fn probe_to_account_err(err: ProbeError) -> AccountError {
    match err {
        ProbeError::Spawn(e) => AccountError::Spawn(e),
        ProbeError::NonZero { code, stderr } => AccountError::NonZero { code, stderr },
    }
}

/// Composes ops into verb-level flows. Real-vs-dry-run is not the
/// Tenants struct's concern: each method always invokes the substrate,
/// and the Reporter + dry-run substrate handle mode-specific filtering.
pub(crate) struct Tenants<'a> {
    pub(super) machine: &'a dyn HostMachine,
}

impl<'a> Tenants<'a> {
    pub(crate) fn new(machine: &'a dyn HostMachine) -> Self {
        Self { machine }
    }

    /// Narrate, execute, narrate. Coupling the three steps means a
    /// Tenants caller can't execute without narrating either side.
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
