use std::fmt;
use std::io;

#[derive(Debug)]
pub enum AccountError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountError::Spawn(e) => write!(f, "failed to spawn process: {e}"),
            AccountError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "process exited with code {code}")
                } else {
                    write!(f, "process exited with code {code}: {trimmed}")
                }
            }
        }
    }
}

/// Failure surface for `HostAccounts` queries. Mirrors the substrate-
/// shaped convention used by the other domain error types. The macOS
/// adapter runs per-call dscl on every trait method, so any of them
/// can spawn-fail or exit nonzero on a substrate-level error.
#[derive(Debug)]
pub enum AccountsError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
}

impl fmt::Display for AccountsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountsError::Spawn(e) => write!(f, "failed to spawn dscl: {e}"),
            AccountsError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "dscl exited with code {code}")
                } else {
                    write!(f, "dscl exited with code {code}: {trimmed}")
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum HostFileError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
    Fs { path: String, message: String },
}

impl fmt::Display for HostFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostFileError::Spawn(e) => write!(f, "failed to spawn sudo: {e}"),
            HostFileError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "sudo read exited with code {code}")
                } else {
                    write!(f, "sudo read exited with code {code}: {trimmed}")
                }
            }
            HostFileError::Fs { path, message } => {
                write!(f, "filesystem error at {path}: {message}")
            }
        }
    }
}

/// Fires only when the probe couldn't produce a verdict at all. `Denied`
/// and `Unknown` are happy-path `AccessOutcome` variants, not errors.
#[derive(Debug)]
pub enum ProbeError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Spawn(e) => write!(f, "failed to spawn probe: {e}"),
            ProbeError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "probe exited with code {code}")
                } else {
                    write!(f, "probe exited with code {code}: {trimmed}")
                }
            }
        }
    }
}

/// `RestoreFailed` is the recovery-of-recovery case: a reload failure
/// triggered a config-restore that itself failed, leaving the host with a
/// half-edited firewall config. Display names the backup path and the
/// manual recovery command.
#[derive(Debug)]
pub enum FirewallError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
    Fs { path: String, message: String },
    RestoreFailed { path: String },
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirewallError::Spawn(e) => write!(f, "failed to spawn process: {e}"),
            FirewallError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "process exited with code {code}")
                } else {
                    write!(f, "process exited with code {code}: {trimmed}")
                }
            }
            FirewallError::Fs { path, message } => {
                write!(f, "filesystem error at {path}: {message}")
            }
            FirewallError::RestoreFailed { path } => write!(
                f,
                "pf.conf restore from {path} failed \u{2014} \
                 sudo cp {path} /etc/pf.conf to recover"
            ),
        }
    }
}

#[derive(Debug)]
pub enum AclError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
}

impl fmt::Display for AclError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclError::Spawn(e) => write!(f, "failed to spawn chmod: {e}"),
            AclError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "chmod exited with code {code}")
                } else {
                    write!(f, "chmod exited with code {code}: {trimmed}")
                }
            }
        }
    }
}
