//! Touch ID is always offered, never pre-probed: `PamOp` is substrate-idempotent, so no
//! probe needs dry-run special-casing. A non-TTY run without `--yes` declines: an
//! auth-stack change must never auto-apply from a pipe.

use crate::domain::HostFileError;
use crate::domain::ops::PamOp;
use crate::domain::reporter::{ConfirmOutcome, Reporter};

use super::Tenants;

#[derive(Debug)]
pub(crate) enum SetupError {
    Pam(HostFileError),
}

impl<'a> Tenants<'a> {
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
