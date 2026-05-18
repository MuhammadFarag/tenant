use super::host_machine::WritableOp;
use super::reporter::Reporter;
use super::{GroupName, HostMachine};

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
