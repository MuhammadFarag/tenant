use crate::accounts::{ConflictError, NameError};
use crate::executor::ExecError;

pub(crate) struct Message {
    /// Default rendering, used in real+standard mode and as ultimate
    /// fallback when no mode-specific override is populated.
    pub summary: Option<String>,
    /// Override used in real+verbose mode (e.g. to inline UID into the
    /// confirmation line). Falls back to `summary` when None.
    pub summary_verbose: Option<String>,
    /// Override used in dry-run mode. Falls back to `summary` when None.
    pub dry_run_summary: Option<String>,
    /// Verbose-only second line, shown in either mode.
    pub detail: Option<String>,
}

/// Pre-exec dry-run message: "Would create tenant 'X'." plus the planned
/// argv as detail. Emitted via `emit_dry_only` — silent in real mode.
pub(crate) fn would_create_tenant(name: &str, argv: &[String]) -> Message {
    Message {
        summary: Some(format!("Would create tenant '{name}'.")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: Some(format!("  {}", shell_join(argv))),
    }
}

/// Pre-exec real-mode message: "Creating tenant 'X'." plus the argv that's
/// about to run. Emitted via `emit_real_only`; the summary lives in
/// `summary_verbose` only, so standard real mode stays silent until the
/// post-exec confirmation.
pub(crate) fn creating_tenant(name: &str, argv: &[String]) -> Message {
    Message {
        summary: None,
        summary_verbose: Some(format!("Creating tenant '{name}'.")),
        dry_run_summary: None,
        detail: Some(format!("  {}", shell_join(argv))),
    }
}

/// Post-exec real-mode confirmation. UID is shown only in verbose
/// (inlined into the summary). Emitted via `emit_real_only` so it doesn't
/// lie about successful creation in dry-run mode.
pub(crate) fn created_tenant(name: &str, uid: u32) -> Message {
    Message {
        summary: Some(format!("Created tenant '{name}'.")),
        summary_verbose: Some(format!("Created tenant '{name}' (UID {uid}).")),
        dry_run_summary: None,
        detail: None,
    }
}

pub(crate) fn create_failed(name: &str, error: &ExecError) -> Message {
    Message {
        summary: Some(format!("tenant: failed to create '{name}': {error}")),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

pub(crate) fn invalid_name(name: &str, error: &NameError) -> Message {
    let summary = match error {
        NameError::Empty => "tenant: name cannot be empty".to_string(),
        NameError::InvalidStart(c) => {
            format!("tenant: name '{name}' must start with a lowercase letter (got '{c}')")
        }
        NameError::InvalidCharacter(c) => {
            format!("tenant: name '{name}' contains invalid character '{c}'")
        }
        NameError::TooLong { len, max } => {
            format!("tenant: name '{name}' is too long ({len} characters; maximum is {max})")
        }
    };
    Message {
        summary: Some(summary),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

pub(crate) fn name_conflict(name: &str, error: &ConflictError) -> Message {
    let summary = match error {
        ConflictError::UserExists => format!("tenant: user '{name}' already exists"),
        ConflictError::GroupExists => format!("tenant: group '{name}' already exists"),
        ConflictError::Both => format!("tenant: user and group '{name}' already exist"),
    };
    Message {
        summary: Some(summary),
        summary_verbose: None,
        dry_run_summary: None,
        detail: None,
    }
}

/// Shell-quote argv for display. Args containing whitespace get wrapped in
/// double quotes so the rendered line is paste-safe; bare args stay bare.
/// Used only for the verbose mechanism line — the executor takes argv
/// directly and never goes through a shell.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.chars().any(char::is_whitespace) {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
