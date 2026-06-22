//! `tenant setup` — host-wide, opt-in host preparation.
//!
//! Unlike the per-tenant verbs, `setup` takes no name and prepares the
//! HOST to run tenants. It presents a menu of opt-in items (today one:
//! Touch ID for sudo) and offers each. Touch ID is an OFFER, not a
//! defect-fix: the per-item prompt defaults to NO, a non-TTY context
//! without `--yes` declines (an auth-stack change must never auto-apply
//! from a pipe), and the item is always offered — `PamOp` is
//! substrate-idempotent, so there's no pre-probe whose dry-run behavior
//! would have to be special-cased.

use crate::domain::HostFileError;
use crate::domain::ops::PamOp;
use crate::domain::reporter::{ConfirmOutcome, Reporter};

use super::Tenants;

/// Verb-boundary failure surface. One arm today; sudoers / pf-prereq
/// host-prep items would extend this as they land. Wraps the shared
/// host-config substrate error.
#[derive(Debug)]
pub(crate) enum SetupError {
    Pam(HostFileError),
}

impl<'a> Tenants<'a> {
    /// Run the host-setup menu. Each item is offered independently;
    /// declining one is a first-class no-op (exit stays 0). A substrate
    /// failure on an accepted item surfaces as `SetupError`.
    pub(crate) fn setup(&self, reporter: &mut Reporter) -> Result<(), SetupError> {
        reporter.setup_intent();
        if reporter.setup_touch_id_offer() == ConfirmOutcome::Proceed {
            self.run(&PamOp::EnableTouchIdForSudo, reporter)
                .map_err(SetupError::Pam)?;
            reporter.setup_touch_id_done();
        } else {
            reporter.setup_touch_id_skipped();
        }
        reporter.setup_done();
        Ok(())
    }
}
