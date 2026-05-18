//! Create-verb error type. The constructor lives in
//! `Writer::create_tenant` (in `accounts.rs`) for now.

use crate::domain::{AccountError, FirewallError};
use crate::profile::ProfileError;

use super::ModeError;

/// Failure surface for the create writer. `UserWithRollback` is the
/// worst case where rollback itself failed and the host is left with
/// an orphan group. `HostMembership` has no automatic rollback —
/// the host-add step is load-bearing for tenant usability.
#[derive(Debug)]
pub(crate) enum CreateError {
    Group(AccountError),
    User(AccountError),
    UserWithRollback {
        user: AccountError,
        rollback: AccountError,
    },
    HostMembership(AccountError),
    Profile(ProfileError),
    /// Read/parse failures on the just-written profile also flow here
    /// as `FirewallError::Fs` because they surface during the firewall
    /// composition step.
    Firewall(FirewallError),
    PostProvision(ModeError),
}
