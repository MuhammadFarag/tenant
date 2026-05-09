use crate::accounts::{ConflictError, NameError};
use crate::executor::ExecError;

pub(crate) struct Message {
    pub summary: Option<String>,
    pub detail: Option<String>,
}

pub(crate) fn would_create_tenant(name: &str, argv: &[String]) -> Message {
    Message {
        summary: Some(format!("Would create tenant '{name}'.")),
        detail: Some(format!("Would run:\n  {}", shell_join(argv))),
    }
}

pub(crate) fn creating_tenant(name: &str, argv: &[String]) -> Message {
    Message {
        summary: Some(format!("Creating tenant '{name}'.")),
        detail: Some(format!("Running:\n  {}", shell_join(argv))),
    }
}

pub(crate) fn create_failed(name: &str, error: &ExecError) -> Message {
    Message {
        summary: Some(format!("tenant: failed to create '{name}': {error}")),
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
