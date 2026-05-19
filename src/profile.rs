//! Per-tenant profile config — TOML at `~/.config/tenant/profiles/<name>.toml`.
//! Carries the PF allowlist (runtime / install tiers) and any
//! `[[shares]]` filesystem-share declarations.

use std::fmt;
use std::io;
use std::path::PathBuf;

use serde::Deserialize;

/// Display path with literal `~` for user-facing plan/echo lines —
/// host-independent rendering.
pub fn display_path_for(name: &str) -> String {
    format!("~/.config/tenant/profiles/{name}.toml")
}

/// Default profile content scaffolded at create-time. Empty hosts arrays
/// mean "no egress allowlisted yet"; the operator edits before use.
/// Commented `# ...` examples scaffold the common shape (allowlist
/// entries + a `[[shares]]` block) without committing the operator to
/// any specific entry — they're hints, not defaults.
pub fn default_profile_toml() -> String {
    "# Per-tenant profile. See `tenant help profile` for the full schema.\n\
     # Apply edits with `tenant reload <name>`.\n\
     \n\
     schema_version = 1\n\
     \n\
     [allowlist.runtime]\n\
     # Hosts the tenant can reach during normal use. Uncomment to enable:\n\
     hosts = [\n\
     #   \"github.com\",\n\
     #   \"api.anthropic.com\",\n\
     ]\n\
     \n\
     [allowlist.install]\n\
     # Additional hosts the tenant can reach under `tenant mode <name> install`\n\
     # or `tenant shell <name> --mode install -- <cmd>`. Uncomment to enable:\n\
     hosts = [\n\
     #   \"registry.npmjs.org\",\n\
     #   \"pypi.org\",\n\
     #   \"files.pythonhosted.org\",\n\
     ]\n\
     \n\
     # Filesystem shares. Each [[shares]] entry grants the tenant's share group\n\
     # access to a host path and (optionally) symlinks it under the tenant's\n\
     # home. `mode` is \"ro\" or \"rw\"; `tenant_path` accepts `$HOME` as a path\n\
     # prefix only. Uncomment and edit:\n\
     #\n\
     # [[shares]]\n\
     # host_path = \"/Users/<host>/projects/foo\"\n\
     # mode = \"ro\"\n\
     # tenant_path = \"$HOME/projects/foo\"\n"
        .to_string()
}

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

/// Parsed per-tenant profile.
///
/// `schema_version` is checked against the supported set (currently just
/// `1`) before structural deserialization so a future schema bump
/// produces an operator-readable refusal rather than a low-level serde
/// error frame. Host order is preserved across parse so the anchor
/// file's host order matches the operator's grouping intent.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub schema_version: u32,
    pub allowlist: Allowlist,
    /// Absent `[[shares]]` deserializes to empty via `#[serde(default)]`,
    /// preserving backward-compat with pre-shares profiles.
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

/// `host_path` is a literal absolute path; `tenant_path` is a `$HOME`-
/// templated string that the parser does NOT resolve — the type
/// distinction signals "not yet resolved" at the layer boundary.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
pub struct Share {
    pub host_path: PathBuf,
    pub mode: ShareMode,
    pub tenant_path: String,
}

/// Intent-named only (`ro` / `rw`). POSIX bit-string forms are rejected
/// because POSIX bit semantics diverge for files vs directories (`r`
/// alone on a directory means "list names but can't open any" — almost
/// never the operator intent).
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ShareMode {
    Ro,
    Rw,
}

/// Expand `$HOME` to `/Users/<name>` only when it appears as the path
/// prefix. Mid-string `$HOME` flows through literally — caught by
/// `parse`'s prefix-only validation, so this fallback is only reached
/// for paths that don't contain `$HOME` at all.
pub fn expand_tenant_path(name: &str, template: &str) -> PathBuf {
    if template == "$HOME" {
        PathBuf::from(format!("/Users/{name}"))
    } else if let Some(rest) = template.strip_prefix("$HOME/") {
        PathBuf::from(format!("/Users/{name}/{rest}"))
    } else {
        PathBuf::from(template)
    }
}

/// Pre-checks `schema_version` against the supported set (currently `1`)
/// before structural deserialization so a version bump produces an
/// operator-readable refusal naming the version, not a serde error
/// frame. Post-parse, enforces the `$HOME` prefix-only contract on each
/// `[[shares]]` `tenant_path` — mid-string `$HOME` (`$HOME$HOME/src`,
/// `/etc/$HOME/foo`) is a likely authoring mistake and refused rather
/// than passed through as a surprising literal.
pub fn parse(content: &str) -> Result<Profile, ProfileError> {
    // Pre-check before typed deserialize so the refusal phrasing doesn't
    // depend on serde's error formatting. Falls through silently if the
    // field is absent / wrong type; the typed deserialize catches both.
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

/// Prefix-only `$HOME`: position 0 followed by `/`, or the whole path.
/// Any other occurrence refused as likely typo.
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
