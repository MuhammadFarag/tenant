//! Per-tenant profile config — TOML at `~/.config/tenant/profiles/<name>.toml`.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::path::PathBuf;

use serde::Deserialize;

pub fn display_path_for(name: &str) -> String {
    format!("~/.config/tenant/profiles/{name}.toml")
}

/// Fragments live under `includes/` so a tenant legally named `base`
/// (`profiles/base.toml`) can't collide with a fragment.
pub fn display_fragment_path_for(fragment: &str) -> String {
    format!("~/.config/tenant/profiles/includes/{fragment}.toml")
}

pub fn default_profile_toml() -> String {
    include_str!("resources/default_profile.toml").to_string()
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

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub schema_version: u32,
    pub allowlist: Allowlist,
    #[serde(default)]
    pub shares: Vec<Share>,
    #[serde(default)]
    pub inbound: Inbound,
    #[serde(default)]
    pub bootstrap: Bootstrap,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Allowlist {
    pub runtime: Tier,
    pub install: Tier,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Tier {
    pub hosts: Vec<HostEntry>,
}

/// TCP only. A bare string entry normalizes to `ports = [443]`.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
#[serde(from = "RawHostEntry")]
pub struct HostEntry {
    pub host: String,
    pub ports: Vec<u16>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawHostEntry {
    Bare(String),
    WithPorts { host: String, ports: Vec<u16> },
}

impl From<RawHostEntry> for HostEntry {
    fn from(raw: RawHostEntry) -> Self {
        match raw {
            RawHostEntry::Bare(host) => HostEntry {
                host,
                ports: vec![443],
            },
            RawHostEntry::WithPorts { host, ports } => HostEntry { host, ports },
        }
    }
}

/// TCP only — UDP loopback is unfiltered. Empty is the locked posture.
#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
pub struct Inbound {
    #[serde(default)]
    pub ports: Vec<u16>,
}

/// Each runs as the tenant via `/bin/sh -c`; the operator owns idempotency
/// (guard idioms like `command -v x || install x`).
#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
pub struct Bootstrap {
    #[serde(default)]
    pub commands: Vec<String>,
}

/// Wire shape for both tenant profiles and fragments. Completeness checks
/// live in `merge`, so a fragment carrying only `[allowlist.runtime]` is legal.
#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
pub struct PartialProfile {
    #[serde(default)]
    pub schema_version: Option<u32>,
    /// Merged left-to-right before the tenant profile; refused in a fragment.
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub allowlist: PartialAllowlist,
    #[serde(default)]
    pub shares: Vec<Share>,
    #[serde(default)]
    pub inbound: Inbound,
    #[serde(default)]
    pub bootstrap: Bootstrap,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
pub struct PartialAllowlist {
    #[serde(default)]
    pub runtime: Option<Tier>,
    #[serde(default)]
    pub install: Option<Tier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileRole {
    Tenant,
    Fragment,
}

/// `tenant_path` stays an unresolved `$HOME` template (`String`, not
/// `PathBuf`) until `expand_tenant_path`.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
pub struct Share {
    pub host_path: PathBuf,
    pub mode: ShareMode,
    pub tenant_path: String,
}

/// Intent names, not POSIX bits: `r` alone on a directory lists names but
/// can't open any — almost never what the operator means.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ShareMode {
    Ro,
    Rw,
}

/// Prefix-only; mid-string `$HOME` is refused earlier by `parse_partial`.
pub fn expand_tenant_path(name: &str, template: &str) -> PathBuf {
    if template == "$HOME" {
        PathBuf::from(format!("/Users/{name}"))
    } else if let Some(rest) = template.strip_prefix("$HOME/") {
        PathBuf::from(format!("/Users/{name}/{rest}"))
    } else {
        PathBuf::from(template)
    }
}

/// Does not resolve `include` (no fragment reader here) — use
/// `load_profile` for that; a profile leaning on a fragment fails merge's
/// completeness check.
pub fn parse(content: &str) -> Result<Profile, ProfileError> {
    merge(vec![parse_partial(content, ProfileRole::Tenant)?])
}

/// Validations run per file so a refusal names the file that authored the
/// mistake.
pub fn parse_partial(content: &str, role: ProfileRole) -> Result<PartialProfile, ProfileError> {
    // Schema pre-check before typed deserialize so a version bump refuses
    // readably instead of as a serde error.
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
    let partial: PartialProfile = toml::from_str(content).map_err(|e| ProfileError {
        message: e.to_string(),
    })?;
    // Refuse on key presence, even `include = []`: `partial.include` can't
    // tell absent from empty, and an empty list later filled in shouldn't
    // start refusing only then.
    if role == ProfileRole::Fragment && raw.get("include").is_some() {
        return Err(ProfileError {
            message: "a fragment may not declare `include`; nesting is not supported \
                      (depth one)"
                .to_string(),
        });
    }
    validate_includes(&partial.include)?;
    for entry in partial
        .allowlist
        .runtime
        .iter()
        .chain(&partial.allowlist.install)
        .flat_map(|tier| &tier.hosts)
    {
        validate_host_entry_ports(entry)?;
    }
    for share in &partial.shares {
        validate_tenant_path_template(&share.tenant_path)?;
    }
    for command in &partial.bootstrap.commands {
        validate_bootstrap_command(command)?;
    }
    Ok(partial)
}

/// Parts are fragments first, tenant profile last. Lists concatenate in
/// order with no dedupe — pf tolerates a value rendered twice.
pub fn merge(parts: Vec<PartialProfile>) -> Result<Profile, ProfileError> {
    // Every present value was already validated == 1, so first wins.
    let schema_version = parts
        .iter()
        .find_map(|p| p.schema_version)
        .ok_or(ProfileError {
            message: "no schema_version declared in the profile or any included fragment \
                  (expected schema_version = 1)"
                .to_string(),
        })?;
    if !parts.iter().any(|p| p.allowlist.runtime.is_some()) {
        return Err(ProfileError {
            message: "no [allowlist.runtime] declared in the profile or any included fragment"
                .to_string(),
        });
    }
    if !parts.iter().any(|p| p.allowlist.install.is_some()) {
        return Err(ProfileError {
            message: "no [allowlist.install] declared in the profile or any included fragment"
                .to_string(),
        });
    }
    let runtime = Tier {
        hosts: parts
            .iter()
            .filter_map(|p| p.allowlist.runtime.as_ref())
            .flat_map(|tier| tier.hosts.iter().cloned())
            .collect(),
    };
    let install = Tier {
        hosts: parts
            .iter()
            .filter_map(|p| p.allowlist.install.as_ref())
            .flat_map(|tier| tier.hosts.iter().cloned())
            .collect(),
    };
    let shares: Vec<Share> = parts
        .iter()
        .flat_map(|p| p.shares.iter().cloned())
        .collect();
    let ports: Vec<u16> = parts
        .iter()
        .flat_map(|p| p.inbound.ports.iter().copied())
        .collect();
    let commands: Vec<String> = parts
        .iter()
        .flat_map(|p| p.bootstrap.commands.iter().cloned())
        .collect();
    // Union-only: a single profile with two shares at one tenant_path stays
    // accepted (last symlink wins), and "drop the include" needs an include.
    if parts.len() > 1 {
        let mut seen_paths: HashSet<&str> = HashSet::new();
        for share in &shares {
            if !seen_paths.insert(share.tenant_path.as_str()) {
                return Err(ProfileError {
                    message: format!(
                        "two shares map to the same tenant_path {:?}; drop the include or \
                         inline the share you want",
                        share.tenant_path
                    ),
                });
            }
        }
    }
    Ok(Profile {
        schema_version,
        allowlist: Allowlist { runtime, install },
        shares,
        inbound: Inbound { ports },
        bootstrap: Bootstrap { commands },
    })
}

fn validate_includes(includes: &[String]) -> Result<(), ProfileError> {
    let mut seen: HashSet<&str> = HashSet::new();
    for name in includes {
        validate_fragment_name(name)?;
        if !seen.insert(name.as_str()) {
            return Err(ProfileError {
                message: format!("include lists {name:?} more than once; remove the duplicate"),
            });
        }
    }
    Ok(())
}

// TODO(smell): share one charset check with the tenant-name `validate_name` instead of mirroring it here
/// `[a-z][a-z0-9_-]{0,30}`; the leading-lowercase rule is what forecloses
/// path traversal (`../etc`, `/abs`, `.hidden`).
fn validate_fragment_name(name: &str) -> Result<(), ProfileError> {
    let refuse = |detail: &str| {
        Err(ProfileError {
            message: format!("include name {name:?} {detail}"),
        })
    };
    if name.is_empty() {
        return refuse("is empty");
    }
    if name.len() > 31 {
        return refuse("is too long (max 31 characters)");
    }
    let mut chars = name.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_lowercase() {
        return refuse("must start with a lowercase letter [a-z]");
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return Err(ProfileError {
                message: format!(
                    "include name {name:?} has an invalid character {c:?}; allowed: [a-z0-9_-]"
                ),
            });
        }
    }
    Ok(())
}

fn validate_host_entry_ports(entry: &HostEntry) -> Result<(), ProfileError> {
    if entry.ports.is_empty() {
        return Err(ProfileError {
            message: format!(
                "allowlist host {:?} declares ports = []; a host with no ports is \
                 unreachable \u{2014} remove the entry or declare its ports",
                entry.host
            ),
        });
    }
    Ok(())
}

fn validate_bootstrap_command(command: &str) -> Result<(), ProfileError> {
    if command.trim().is_empty() {
        return Err(ProfileError {
            message: "bootstrap declares an empty (or whitespace-only) command; \
                      a no-op command is an authoring mistake \u{2014} remove it"
                .to_string(),
        });
    }
    Ok(())
}

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
