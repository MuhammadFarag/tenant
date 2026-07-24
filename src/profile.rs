//! Per-tenant profile config — TOML at `~/.config/tenant/profiles/<name>.toml`.
//! Carries the PF allowlist (runtime / install tiers), any
//! `[[shares]]` filesystem-share declarations, and the `[inbound]`
//! TCP-loopback port list (the `restricted` inbound posture).

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::path::PathBuf;

use serde::Deserialize;

/// Display path with literal `~` for user-facing plan/echo lines —
/// host-independent rendering.
pub fn display_path_for(name: &str) -> String {
    format!("~/.config/tenant/profiles/{name}.toml")
}

/// Display path for an `include` fragment, literal `~` form. Fragments
/// live under the `includes/` subdirectory so the tenant/fragment
/// distinction is physical (a tenant legally named `base` writes
/// `profiles/base.toml`, which can't collide with `includes/`).
pub fn display_fragment_path_for(fragment: &str) -> String {
    format!("~/.config/tenant/profiles/includes/{fragment}.toml")
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
     # Optional: share common allowlist / inbound / shares across a fleet by\n\
     # including ordered fragments from\n\
     # ~/.config/tenant/profiles/includes/<name>.toml — each is merged before\n\
     # this file (this file wins last). Uncomment to enable:\n\
     # include = [\"base\"]\n\
     \n\
     [allowlist.runtime]\n\
     # Hosts the tenant can reach during normal use. A bare host opens TCP\n\
     # 443 only; an inline table declares that host's TCP ports (e.g. 22 for\n\
     # git-over-ssh). Uncomment to enable:\n\
     hosts = [\n\
     #   \"api.anthropic.com\",\n\
     #   { host = \"github.com\", ports = [443, 22] },\n\
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
     # tenant_path = \"$HOME/projects/foo\"\n\
     \n\
     [inbound]\n\
     # TCP loopback (127.0.0.1) ports the tenant exposes under the default\n\
     # `restricted` posture. SURFACE-REDUCTION, NOT isolation: a declared port\n\
     # is reachable by the host AND peer tenants (pf can't see the initiator on\n\
     # shared loopback). UDP loopback is unfiltered (TCP only). Empty == locked.\n\
     # Widen temporarily with `tenant inbound <name> permissive`. Uncomment:\n\
     ports = [\n\
     #   3000,\n\
     ]\n\
     \n\
     [bootstrap]\n\
     # Idempotent shell commands `tenant bootstrap <name>` runs AS the tenant\n\
     # (each via `/bin/sh -c`, in order, stopping on the first failure), under\n\
     # a temporary install-tier egress widen. Guard so re-runs no-op\n\
     # (e.g. `command -v x || install x`). Uncomment and edit:\n\
     commands = [\n\
     #   \"test -d ~/projects/foo || git clone https://github.com/you/foo ~/projects/foo\",\n\
     ]\n"
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
    /// Absent `[inbound]` deserializes to empty ports via
    /// `#[serde(default)]`, preserving backward-compat with pre-inbound
    /// profiles. Empty ports is the locked posture.
    #[serde(default)]
    pub inbound: Inbound,
    /// Absent `[bootstrap]` deserializes to empty commands via
    /// `#[serde(default)]`, preserving backward-compat with pre-bootstrap
    /// profiles. Empty commands ⇒ `tenant bootstrap` is a quiet no-op.
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

/// A single allowlist host with the TCP ports it may be reached on.
/// Serde-normalized via `RawHostEntry` so downstream (the renderer's
/// `EgressHost` resolution) never sees the untagged enum: a bare string
/// entry fills `ports = [443]` (backward-compat — every pre-ports profile
/// is bare-only), an inline table declares its own ports. TCP only (no
/// proto field), matching `[inbound]` and the egress catchall.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
#[serde(from = "RawHostEntry")]
pub struct HostEntry {
    pub host: String,
    pub ports: Vec<u16>,
}

/// Wire form of a `hosts` array element: a bare `"host"` string or an
/// inline `{ host = …, ports = [...] }` table. Normalized into `HostEntry`
/// by the `From` impl so the bare-vs-table distinction stops at parse.
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

/// TCP loopback ports the tenant exposes under the default `restricted`
/// inbound posture. Bare port list — no proto field (TCP only; UDP
/// loopback is unfiltered). Empty (or absent section) is the locked
/// posture: no inbound pass is rendered. An absent `ports` key inside a
/// present `[inbound]` section also defaults to empty.
#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
pub struct Inbound {
    #[serde(default)]
    pub ports: Vec<u16>,
}

/// Shell commands the `tenant bootstrap` verb runs AS the tenant, each
/// via `/bin/sh -c <command>`. The operator promises they're idempotent
/// (the design leans on guard idioms like `command -v x || install x`),
/// so the verb is re-runnable anytime. Absent (or empty) ⇒ nothing to
/// run. Bare command list — no proto/tier field; commands are not a
/// tier axis (they run once, when the operator invokes the verb).
#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
pub struct Bootstrap {
    #[serde(default)]
    pub commands: Vec<String>,
}

/// Wire shape for BOTH tenant profiles and `include` fragments: every
/// section optional/defaulted. `Profile` (unchanged) is the merged,
/// validated result; downstream consumers never see a `PartialProfile`.
/// The completeness checks (schema_version present, both tiers declared)
/// live in `merge`, not here — a fragment carrying only
/// `[allowlist.runtime]` is a legal partial.
#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
pub struct PartialProfile {
    #[serde(default)]
    pub schema_version: Option<u32>,
    /// Ordered fragment names resolved from `profiles/includes/<name>.toml`,
    /// merged left-to-right before the tenant profile. Refused in a fragment
    /// (depth one). Serde-default so include-free profiles round-trip.
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

/// Independently-optional allowlist tiers. A fragment may declare one, the
/// other, both, or neither; `merge` requires each present somewhere.
#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
pub struct PartialAllowlist {
    #[serde(default)]
    pub runtime: Option<Tier>,
    #[serde(default)]
    pub install: Option<Tier>,
}

/// Distinguishes the two roles a `PartialProfile` plays at parse. A
/// `Fragment` declaring `include` is refused (depth one); a `Tenant`
/// profile's `include` list drives the load path's fragment resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileRole {
    Tenant,
    Fragment,
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
    // The no-fragments composition: a directly-parsed profile is a single
    // part. `load_profile` (the include-resolving path) is what reads and
    // prepends fragments; `parse` does not resolve `include` (it has no
    // fragment reader), so a profile relying on a fragment for a section
    // surfaces the same completeness refusal it would if the fragment were
    // empty. Value-identical to today for include-free profiles.
    merge(vec![parse_partial(content, ProfileRole::Tenant)?])
}

/// Parse one file (tenant profile or fragment) into a `PartialProfile`.
/// Runs the per-file validations (schema pre-check, `ports = []` refusal,
/// `$HOME` prefix-only, include lexical rail) so a refusal names the
/// mistake in the file that authored it — the load path adds which file.
/// A `Fragment` declaring the `include` key at all is refused (depth one).
pub fn parse_partial(content: &str, role: ProfileRole) -> Result<PartialProfile, ProfileError> {
    // Pre-check before typed deserialize so the refusal phrasing doesn't
    // depend on serde's error formatting. Optional in a partial: absent
    // schema_version falls through (completeness is a merge concern).
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
    // Depth one: refuse the `include` KEY's presence in a fragment — even
    // `include = []`, which "declares include" per the doctrine yet resolves
    // nothing. Failing on presence (not just a non-empty list) fails earlier
    // and truer: an operator who writes `include = []` in a fragment and
    // later fills it in shouldn't be surprised the refusal appears only then.
    // `raw` is already parsed above; `partial.include` can't distinguish an
    // absent key from `[]`.
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

/// Fold ordered parts (fragments first, tenant profile last) into the
/// merged, validated `Profile`. Per-tier host lists, inbound ports, and
/// shares union by concatenation in order (no dedupe — a value appearing
/// twice renders twice, which the renderer/pf already tolerate). Then the
/// merged result is checked for completeness (schema_version present, both
/// allowlist tiers declared somewhere) and the shares `tenant_path`
/// verbatim-collision refusal.
pub fn merge(parts: Vec<PartialProfile>) -> Result<Profile, ProfileError> {
    // schema_version: present somewhere. Every present value is already
    // validated == 1 by `parse_partial`, so the first found is canonical.
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
    // Concatenate fragments-first, no dedupe (same posture as ports /
    // hosts / shares). Empty/whitespace entries are already refused
    // per-file by `parse_partial`, so the merged list has none.
    let commands: Vec<String> = parts
        .iter()
        .flat_map(|p| p.bootstrap.commands.iter().cloned())
        .collect();
    // Verbatim tenant_path collision, only across a genuine union (more
    // than one part). A single include-free profile with two shares at the
    // same tenant_path parsed before this feature (last-symlink-wins
    // downstream), so value-identity forbids a new refusal for it — the
    // collision is a union concern, and the escape hatch ("drop the
    // include") only makes sense when an include is in play.
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

/// Lexical rail on `include` entries — the same charset as tenant names
/// (`[a-z][a-z0-9_-]{0,30}`) plus a duplicate-entry refusal. The charset
/// forecloses path traversal (`../`, `/`, leading dots) without a second
/// vocabulary. Refuses at parse, naming the bad entry.
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

/// `[a-z][a-z0-9_-]{0,30}` — mirrors `validate_name`'s tenant-name charset
/// (kept here to stay a pure-string check with no upward dependency on the
/// domain layer). The leading-lowercase rule excludes `.`/`/`/`-` starts,
/// so `../etc`, `/abs`, and `.hidden` all refuse.
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

/// An allowlist entry with `ports = []` is a contradiction — a host with
/// no ports is unreachable, so listing it is a likely authoring mistake.
/// Refused at parse (a bare string entry can't reach this: it normalizes
/// to `[443]`).
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

/// An empty or whitespace-only `[bootstrap]` command is a no-op in the
/// list — an authoring mistake, same posture as `ports = []`. Refused at
/// parse (per-file, so the refusal names the file that authored it).
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
