use crate::accounts::{ConflictError, NameError};

pub(crate) struct Message {
    pub summary: Option<String>,
    pub detail: Option<String>,
}

pub(crate) fn would_create_tenant(name: &str, uid: u32) -> Message {
    Message {
        summary: Some(format!("Would create tenant '{name}'.")),
        detail: Some(format!(
            "Would run:\n  sudo sysadminctl -addUser {name} \
             -fullName \"Tenant: {name}\" -shell /bin/zsh -UID {uid} -GID {uid}"
        )),
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
