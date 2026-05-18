use std::fmt;
use std::io;

/// Account-domain error. Same shape as the pre-refactor `ExecError` — the
/// substrate distinguishes spawn failures (sudo not on PATH, fork failed)
/// from non-zero exits (the tool reported an error). The writer's
/// `LookupUserRecord` flow pattern-matches on `NonZero` specifically to
/// treat probe-non-zero as "no cleanup needed."
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

/// Failure surface for privileged-or-cheap reads of host config files
/// — `/etc/sudoers` + `/etc/sudoers.d/*` (privileged) and
/// `/etc/pam.d/sudo` (mode-0644 direct read). The substrate
/// concatenates the readable text into one blob that doctor's parsers
/// grep through; either the read invocation fails (spawn / non-zero
/// on sudo-gated reads) or a direct filesystem read fails. Mirrors
/// `FirewallError`'s shape with an extra `Fs` variant for the
/// direct-read case.
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

/// Probe-substrate error. Fires when the probe machinery itself failed —
/// `sudo` not on PATH, fork failed, an unexpected non-zero exit pattern
/// that doesn't map cleanly to Allowed / Denied. `Denied` and `Unknown`
/// are NOT errors here — they're `AccessOutcome` variants the probe
/// returns on its happy path. This error type fires only when doctor
/// couldn't get a probe answer at all; the dispatcher routes it to
/// `doctor_failed` and exits 74.
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

/// Firewall-domain error. Same `Spawn` / `NonZero` shape as `AccountError`
/// for pfctl invocations; two additional variants for the fs side of
/// firewall ops:
/// - `Fs` covers tempfile / mv / chmod failures during anchor/pf.conf
///   writes; carries the path so the operator-facing frame can name what
///   failed.
/// - `RestoreFailed` is the recovery-of-recovery case: a `Reload` failure
///   triggered a `RestoreConfigFromBackup`, and the restore itself failed.
///   The host now carries a half-edited pf.conf; the message names the
///   backup path and the manual recovery command.
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

/// ACL-domain error. Mirrors `AccountError`'s shape because the
/// substrate is `chmod` (a tool with the same spawn / non-zero contract
/// as dseditgroup / sysadminctl).
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
