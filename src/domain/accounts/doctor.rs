//! Doctor-verb error type and the dispatch-scope classifier that
//! selects per-verb audit relevance in `pre_exec_doctor_summary`.

use crate::domain::{FirewallError, HostFileError, ProbeError};

/// Per-verb relevance matrix for `pre_exec_doctor_summary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DoctorScope {
    Create,
    Shell,
    Mode,
    Reload,
}

#[derive(Debug)]
pub(crate) enum DoctorError {
    Probe(ProbeError),
    HostFile(HostFileError),
    Firewall(FirewallError),
}

impl From<ProbeError> for DoctorError {
    fn from(e: ProbeError) -> Self {
        DoctorError::Probe(e)
    }
}

impl From<HostFileError> for DoctorError {
    fn from(e: HostFileError) -> Self {
        DoctorError::HostFile(e)
    }
}

impl From<FirewallError> for DoctorError {
    fn from(e: FirewallError) -> Self {
        DoctorError::Firewall(e)
    }
}
