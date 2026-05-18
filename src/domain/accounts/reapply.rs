//! Mode/reload reapply error type. Used by `mode`, the `shell` command
//! form's auto-narrow, `reload`, and the create-side post-provision
//! share pass.

use crate::domain::{AccountError, AclError, FirewallError, ProbeError};
use crate::profile::ProfileError;

use super::ShareError;

/// Failure surface for `mode` and (by reuse) the `shell` auto-narrow,
/// `reload`, and the create-side post-provision share step.
#[derive(Debug)]
pub(crate) enum ModeError {
    Profile(ProfileError),
    Firewall(FirewallError),
    Acl(AclError),
    Account(AccountError),
    Probe(ProbeError),
    Share(ShareError),
}
