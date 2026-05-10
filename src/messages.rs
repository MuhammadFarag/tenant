use crate::accounts::{ConflictError, NameError};
use crate::executor::ExecError;

pub(crate) struct Message {
    /// Default rendering, used in real mode and as fallback in dry-run mode
    /// when `dry_run_summary` is None. Most messages (errors, conflicts) are
    /// mode-agnostic and only populate this field.
    pub summary: Option<String>,
    /// Override rendering for dry-run mode. Only action messages with a
    /// meaningful "would" framing populate this; others leave it None and
    /// fall back to `summary`.
    pub dry_run_summary: Option<String>,
    pub detail: Option<String>,
}

/// Unified factory for the create-tenant action message. Carries both the
/// real-mode summary ("Creating …") and the dry-run summary ("Would create
/// …") in one Message; Reporter picks based on its mode. Detail (the
/// indented mechanism line) is the same in both modes.
pub(crate) fn create_tenant_action(name: &str, argv: &[String]) -> Message {
    Message {
        summary: Some(format!("Creating tenant '{name}'.")),
        dry_run_summary: Some(format!("Would create tenant '{name}'.")),
        detail: Some(format!("  {}", shell_join(argv))),
    }
}

pub(crate) fn create_failed(name: &str, error: &ExecError) -> Message {
    Message {
        summary: Some(format!("tenant: failed to create '{name}': {error}")),
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
