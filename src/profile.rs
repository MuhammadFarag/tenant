//! Per-tenant profile config — the cycle-1 artifact that cycle 2 (PF
//! anchor) and cycle 3 (`mode` verb) read from. Cycle 1 only writes a
//! default profile at create-time and removes it at destroy-time; reads
//! land in cycle 2 when the PF anchor needs the allowlist.
//!
//! Post-R.2: the substrate for profile operations lives on the unified
//! `Executor` trait (`describe_profile` + `execute_profile`), not a
//! separate `ProfileStore`. This file now holds only the data shapes
//! shared across that interface: the error type, the default TOML
//! content, and the display-form path helper.

use std::fmt;
use std::io;

/// Display path for the tenant's profile, with a literal `~` (not the
/// expanded `$HOME`). Used in user-facing plan/echo lines so the rendered
/// output is host-independent — the operator's `~` is the universally
/// readable form. `Executor::execute_profile` resolves the absolute form
/// internally for the actual fs ops. Single source of truth for the path
/// convention so a future move (XDG_CONFIG_HOME support, schema
/// migration) updates display + writes in one place.
pub fn display_path_for(name: &str) -> String {
    format!("~/.config/tenant/profiles/{name}.toml")
}

/// The default profile content scaffolded at create-time. Schema is
/// minimal on purpose — cycle 2's PF anchor and cycle 3's mode verb
/// will surface what else belongs here. Empty hosts arrays mean "no
/// egress allowlisted yet"; the operator edits this file before
/// `tenant pf-install` (cycle 2). Hand-rolled `format!` rather than
/// going through `toml::ser` because cycle 1 only writes this fixed
/// content — the toml/serde dep earns its keep when cycle 2 starts
/// reading.
pub fn default_profile_toml() -> String {
    "schema_version = 1\n\
     \n\
     [allowlist.runtime]\n\
     hosts = []\n\
     \n\
     [allowlist.install]\n\
     hosts = []\n"
        .to_string()
}

/// Failure shape for the profile domain. Wraps any error surfaced from
/// the substrate's `execute_profile` impl (fs failures in production,
/// caller-injected failures in tests). The dispatcher renders this
/// through `messages::create_profile_failed` / `destroy_profile_failed`
/// so the operator sees the path that failed without having to read
/// source.
#[derive(Debug)]
pub struct ProfileError {
    pub message: String,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<io::Error> for ProfileError {
    fn from(e: io::Error) -> Self {
        ProfileError {
            message: e.to_string(),
        }
    }
}
