//! Per-tenant profile config — the foundation cycle 2 (PF anchor) and
//! cycle 3 (`mode` verb) read from. Cycle 1 only writes a default
//! profile at create-time and removes it at destroy-time; reads land in
//! cycle 2 when the PF anchor needs the allowlist.
//!
//! Mirrors the Reader/Executor composition pattern: `ProfileStore` is
//! the trait, production wires `XdgProfileStore` (writes
//! `~/.config/tenant/profiles/<name>.toml` via `std::fs`), tests wire
//! `StubProfileStore` (in-memory `HashMap`). `DryRunProfileStore` is the
//! no-op swap-in the composition root selects when `cli.dry_run` is set,
//! so domain writers don't need to know about the mode.

use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

/// Display path for the tenant's profile, with a literal `~` (not the
/// expanded `$HOME`). Used in user-facing plan/echo lines so the
/// rendered output is host-independent — the operator's `~` is the
/// universally-readable form. `XdgProfileStore::path_for` returns the
/// expanded version used for actual fs operations. Single source of
/// truth for the path convention so a future move (XDG_CONFIG_HOME
/// support, schema migration) updates display + writes in one place.
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

/// Minimal API surface for cycle 1 — write the default at create-time,
/// remove at destroy-time, idempotent on the destroy side. `read` and
/// `exists` will arrive when cycle 2 needs to load the allowlist before
/// rendering the PF anchor.
pub trait ProfileStore {
    /// Write `contents` for the named tenant. Overwrites if present;
    /// caller is responsible for refusing duplicate-create earlier in
    /// the pipeline (`accounts::check_conflict` already does this for
    /// the user/group; profile-write happens after that gate).
    fn write(&self, name: &str, contents: &str) -> Result<(), ProfileError>;

    /// Remove the named tenant's profile. Idempotent: returns Ok if the
    /// file is already absent (mirrors `rm -f`). Cycle 1 destroy uses
    /// this unconditionally as the 5th step; the orphan-group path also
    /// calls it so convergence covers profile state too.
    fn remove(&self, name: &str) -> Result<(), ProfileError>;
}

/// Failure shape for the profile store. Wraps `io::Error` for the
/// production fs impl; tests inject their own message via
/// `StubProfileStore::with_write_failure`. The dispatcher renders this
/// through `messages::create_profile_failed` so the operator sees the
/// path that failed without having to read source.
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

/// Production impl: writes under `$HOME/.config/tenant/profiles/`.
/// Mirrors the sandbox plugin's profile location convention but
/// per-tenant (the plugin uses named profiles shared across agents;
/// tenant-rust is per-tenant by design — see CLAUDE.md cross-reference
/// for the rationale). `$HOME` is read at construction so a future
/// daemon mode wouldn't drift if the env changed mid-run.
pub struct XdgProfileStore {
    root: PathBuf,
}

impl XdgProfileStore {
    pub fn new() -> io::Result<Self> {
        let home = env::var("HOME")
            .map_err(|_| io::Error::other("HOME environment variable is not set"))?;
        Ok(Self {
            root: PathBuf::from(home).join(".config/tenant/profiles"),
        })
    }

    /// Path the production impl writes to. Public so the dispatch layer
    /// can render it in plan/echo lines without duplicating the
    /// `~/.config/tenant/profiles/<name>.toml` literal.
    pub fn path_for(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.toml"))
    }
}

impl ProfileStore for XdgProfileStore {
    fn write(&self, name: &str, contents: &str) -> Result<(), ProfileError> {
        fs::create_dir_all(&self.root)?;
        fs::write(self.path_for(name), contents)?;
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<(), ProfileError> {
        match fs::remove_file(self.path_for(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Production no-op for `--dry-run`. Composition root swaps this in so
/// domain writers stay mode-agnostic. Mirrors `executor::DryRunExecutor`.
pub struct DryRunProfileStore;

impl ProfileStore for DryRunProfileStore {
    fn write(&self, _name: &str, _contents: &str) -> Result<(), ProfileError> {
        Ok(())
    }

    fn remove(&self, _name: &str) -> Result<(), ProfileError> {
        Ok(())
    }
}

/// In-memory test double. Records writes (assert on contents in tests)
/// and removals (assert on absence after destroy). `with_write_failure`
/// pre-loads a failure for the next write; `with_profile` pre-loads
/// existing content to simulate a host with prior tenants.
#[derive(Default)]
pub struct StubProfileStore {
    profiles: RefCell<HashMap<String, String>>,
    write_failure: RefCell<Option<String>>,
}

impl StubProfileStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the next `write` call to fail with the given message,
    /// regardless of which tenant name. Cleared after the failure fires
    /// so a subsequent write succeeds. Used by the create-failure-path
    /// test (cycle 1.5).
    pub fn with_write_failure(self, message: &str) -> Self {
        *self.write_failure.borrow_mut() = Some(message.to_string());
        self
    }

    /// Pre-load a profile (e.g. for destroy tests that need to assert
    /// "this was here before, gone after"). Also useful for the orphan-
    /// group cycle test where the profile exists alongside the orphan
    /// group.
    pub fn with_profile(self, name: &str, contents: &str) -> Self {
        self.profiles
            .borrow_mut()
            .insert(name.to_string(), contents.to_string());
        self
    }

    /// Snapshot of the in-memory store. Tests use this for byte-exact
    /// content assertions and presence/absence checks.
    pub fn snapshot(&self) -> HashMap<String, String> {
        self.profiles.borrow().clone()
    }

    pub fn has_profile(&self, name: &str) -> bool {
        self.profiles.borrow().contains_key(name)
    }
}

impl ProfileStore for StubProfileStore {
    fn write(&self, name: &str, contents: &str) -> Result<(), ProfileError> {
        if let Some(msg) = self.write_failure.borrow_mut().take() {
            return Err(ProfileError { message: msg });
        }
        self.profiles
            .borrow_mut()
            .insert(name.to_string(), contents.to_string());
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<(), ProfileError> {
        // Idempotent: removing an absent profile is success (mirrors
        // XdgProfileStore's NotFound-as-Ok semantics and the operator's
        // mental model of `rm -f`).
        self.profiles.borrow_mut().remove(name);
        Ok(())
    }
}
