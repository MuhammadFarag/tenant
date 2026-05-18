//! Shell-verb error type. Wraps `ModeError` for the auto-narrow path
//! and adds `NarrowFailed` for the command form's post-child reapply.

use crate::domain::AccountError;

use super::ModeError;

/// Failure surface for `shell` (interactive + command forms).
/// `NarrowFailed` is exercised only by the command form when the
/// post-child narrow-on-finally reapply fails; the dispatcher emits
/// a warning and propagates the child's exit code.
#[derive(Debug)]
pub(crate) enum ShellError {
    Account(AccountError),
    Mode(ModeError),
    NarrowFailed {
        child_exit: i32,
        narrow_err: ModeError,
    },
}
