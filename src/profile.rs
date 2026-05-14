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
use std::path::PathBuf;

use serde::Deserialize;

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
/// the substrate's `execute_profile` / `read_profile` impls (fs failures
/// in production, caller-injected failures in tests). The dispatcher
/// renders this through `Reporter::create_profile_failed` /
/// `destroy_profile_failed` so the operator sees the path that failed
/// without having to read source.
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

/// Parsed per-tenant profile. Cycle 2's create-side firewall step reads
/// the on-disk TOML via `Executor::read_profile`, then runs this `parse`
/// on the content to extract the allowlist tiers for `render_anchor`.
///
/// `schema_version` is checked against the supported set (currently just
/// `1`) before structural deserialization so a future schema bump
/// produces an operator-readable refusal rather than a low-level serde
/// error frame. Host order is preserved across parse → render so the
/// anchor file's host order matches the operator's grouping intent in
/// the profile.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub schema_version: u32,
    pub allowlist: Allowlist,
    /// Per-tenant filesystem shares (cycle 10). Each entry declares a
    /// host_path the tenant should be able to access (via `<name>-tenant-share`
    /// ACL grant) and a tenant-side `tenant_path` symlink that points at
    /// it. Absent `[[shares]]` array deserializes to an empty Vec via
    /// `#[serde(default)]`, preserving backward-compat for cycle-9-era
    /// profiles that have no shares section.
    #[serde(default)]
    pub shares: Vec<Share>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Allowlist {
    pub runtime: Tier,
    pub install: Tier,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Tier {
    pub hosts: Vec<String>,
}

/// One per-tenant filesystem share entry. The Writer expands `tenant_path`'s
/// `$HOME` token at op-construction time; the substrate sees a fully
/// absolute path. `host_path` is parsed as `PathBuf` directly (literal
/// absolute path on the host); `tenant_path` stays as `String` because
/// it's a template (`$HOME/...`) that the parser doesn't resolve — keeping
/// the type distinction signals "not yet resolved" at the type level.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
pub struct Share {
    pub host_path: PathBuf,
    pub mode: ShareMode,
    pub tenant_path: String,
}

/// Per-share access intent. Two values, intent-named (`ro` / `rw`) per
/// Q1 lock — POSIX bit-string forms rejected because POSIX bit semantics
/// differ for files vs directories (`r` alone on a directory means "list
/// names but can't open any" which is almost never the operator intent).
/// String discriminator via serde: `mode = "ro"` and `mode = "rw"` are
/// the only accepted TOML forms; anything else is a parse error.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ShareMode {
    Ro,
    Rw,
}

/// Expand a `tenant_path` template into an absolute `PathBuf` for tenant
/// `name`. Q3-locked: `$HOME` is the only supported template variable; it
/// expands to `/Users/<name>` (the macOS tenant home convention) and only
/// when it appears as the prefix. A `tenant_path` like `/etc/$HOME/foo`
/// stays literal so an operator typo doesn't silently become a different
/// path. Literal absolute paths (`/opt/shared`) flow through unchanged.
///
/// Called by `Writer::build_share_ops` at op-construction time so the
/// substrate sees fully-resolved paths; the parser stores the raw
/// template so the type signals "not yet resolved" at the layer
/// boundary.
pub fn expand_tenant_path(name: &str, template: &str) -> PathBuf {
    if template == "$HOME" {
        PathBuf::from(format!("/Users/{name}"))
    } else if let Some(rest) = template.strip_prefix("$HOME/") {
        PathBuf::from(format!("/Users/{name}/{rest}"))
    } else {
        PathBuf::from(template)
    }
}

/// Parse profile TOML content into a typed `Profile`. Pre-checks
/// `schema_version` against the supported set (currently just `1`) so a
/// version bump produces a refusal message that names the version
/// explicitly; structural failures (missing sections, wrong types) fall
/// through to serde's error frame, which the dispatcher rewraps in the
/// path-naming Reporter frame.
///
/// Post-parse, validates each `[[shares]]` entry's `tenant_path` for the
/// `$HOME` template's prefix-only contract: the token only expands when
/// it appears at the start of the path. A `tenant_path` that contains
/// `$HOME` anywhere else (`$HOME$HOME/src`, `/etc/$HOME/foo`) is a
/// profile-authoring mistake — refuse rather than silently produce a
/// surprising literal path.
pub fn parse(content: &str) -> Result<Profile, ProfileError> {
    // Pre-check schema_version separately so the refusal phrasing
    // doesn't depend on serde's error formatting. Falls through silently
    // if the field is absent or the wrong type — the typed deserialize
    // below catches both cases with its own (acceptable) message.
    let raw: toml::Value = toml::from_str(content).map_err(|e: toml::de::Error| ProfileError {
        message: format!("invalid TOML: {e}"),
    })?;
    if let Some(schema) = raw.get("schema_version").and_then(|v| v.as_integer())
        && schema != 1
    {
        return Err(ProfileError {
            message: format!("schema_version {schema} not understood (this tenant supports 1)"),
        });
    }
    let profile: Profile = toml::from_str(content).map_err(|e| ProfileError {
        message: e.to_string(),
    })?;
    for share in &profile.shares {
        validate_tenant_path_template(&share.tenant_path)?;
    }
    Ok(profile)
}

/// Q3 prefix-only `$HOME` contract: token expands only when it appears
/// at position 0 followed by `/` (or as the whole path on its own).
/// Any other occurrence of `$HOME` in `tenant_path` is a likely typo
/// and refused at parse time. Examples refused: `$HOME$HOME/src` (would
/// expand to `/Users/<name>$HOME/src` — confusing literal); `/etc/$HOME/x`
/// (would pass through unchanged, but the operator's intent was almost
/// certainly to use a tenant home subpath).
fn validate_tenant_path_template(template: &str) -> Result<(), ProfileError> {
    if template == "$HOME" || template.starts_with("$HOME/") {
        return Ok(());
    }
    if template.contains("$HOME") {
        return Err(ProfileError {
            message: format!(
                "tenant_path {template:?} contains `$HOME` not at the start; \
                 `$HOME` expands only as a path prefix"
            ),
        });
    }
    Ok(())
}
