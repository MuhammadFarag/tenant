//! Filesystem-exposure detection: pure functions for the curated path
//! list, severity classification, and finding rendering.
//!
//! # Architecture
//!
//! The doctor verb operates in three layers:
//! 1. **Substrate (`Executor::probe_access_as_tenant`)** — invokes
//!    `sudo -n -u <tenant> /usr/bin/test -<mode> <path>` and reports
//!    Allowed / Denied / Unknown. Probe-as-tenant subsumes ACL +
//!    sandbox + TCC semantics at the kernel level; doctor doesn't
//!    re-implement them.
//! 2. **This module (`doctor`)** — curated path list and pure
//!    classification. Knows the project's threat model (which paths
//!    matter, what severity each category produces). No I/O.
//! 3. **Writer (`accounts::Writer::doctor_tenant`)** — orchestrates
//!    probes for one tenant, collects findings, drives the Reporter.
//!    Sub-cycle 5 adds the all-tenants walk on top.
//!
//! Per cycle-5 brief: the curated list is fixed (not configurable);
//! verbose mode surfaces the list to the operator so the bounded scope
//! is operator-visible. Cycle-2 (post-detection remediation) will add
//! mechanism reporting on Denied probes if needed.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::executor::{AccessMode, AccessOutcome};

/// Severity tier of a finding. Order is load-bearing: `--strict` exit
/// code logic (sub-cycle 4) consumes `findings.iter().map(severity).max()`
/// to decide between exit 0 (no findings worse than info), 1 (warning
/// max), or 2 (critical present). Info < Warning < Critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// Threat-category for a curated path. The severity each category
/// produces (when a probe comes back `Allowed`) is locked by
/// `classify` — see the matrix there.
///
/// The brief's Q5 sudoers env-leak finding is rendered separately
/// (sub-cycle 6 adds the `Finding::EnvLeak` variant); it has no
/// curated path and therefore no `Category` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Host-side secret targets — private keys, cloud credentials,
    /// session tokens, command history. Tenant-readability is a
    /// critical exposure (the agent could exfiltrate without any
    /// network access).
    HostSecret,
    /// Top-level `/Users/<host>/` listability — if a tenant can
    /// `ls /Users/host`, they can enumerate file names that might
    /// themselves reveal sensitive activity even if individual
    /// files are protected. Less severe than reading a secret
    /// directly: warning-tier.
    HostHomeListing,
    /// Cross-tenant exposure — tenant A's access to tenant B's home
    /// directory or `.ssh/` directory. Warning-tier rather than
    /// critical because the leakage is between two operator-managed
    /// principals (no third-party data involved), but still a
    /// boundary the design assumes is intact.
    CrossTenant,
    /// Tenant-project artifacts on the host (per-tenant profiles in
    /// the host's `~/.config/tenant/profiles/`, per-tenant PF anchor
    /// files in `/etc/pf.anchors/`). The anchor files specifically
    /// are mode 0644 by design (cycle-2 install flow), so they WILL
    /// surface as `Allowed`; we report as `info` rather than warning
    /// because the exposure is intentional and the operator only
    /// needs to know it exists, not act on it.
    TenantArtifact,
}

/// A doctor-detected exposure.
///
/// `FilesystemExposure` is the per-tenant per-path probe finding from
/// `probe_access_as_tenant` returning Allowed (sub-cycles 3 + 5).
///
/// `EnvLeak` is the host-wide finding from the sudoers env-policy
/// check (sub-cycle 6): if `/etc/sudoers` (plus drop-ins) doesn't
/// `env_delete += "<var>"` an inherited env var, that var propagates
/// from the operator's session into every `sudo -iu <tenant>`. The
/// canonical case is SSH_AUTH_SOCK — macOS ssh-agent's socket gets
/// inherited so the tenant can `ssh` anywhere the host has cached
/// keys for. Warning-tier (not critical) because the leak depends on
/// the operator's session env actually holding the var; recovery is
/// a one-line `/etc/sudoers` edit. The finding line names the
/// directive shape so the operator's fix is mechanical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    FilesystemExposure {
        severity: Severity,
        tenant: String,
        path: PathBuf,
        access: AccessMode,
    },
    EnvLeak {
        var: String,
    },
}

impl Finding {
    pub fn severity(&self) -> Severity {
        match self {
            Finding::FilesystemExposure { severity, .. } => *severity,
            Finding::EnvLeak { .. } => Severity::Warning,
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::FilesystemExposure {
                severity,
                tenant,
                path,
                access,
            } => {
                let verb = match access {
                    AccessMode::Read => "read",
                    AccessMode::List => "list",
                };
                write!(
                    f,
                    "{}: tenant '{}' can {} {}",
                    severity.as_str(),
                    tenant,
                    verb,
                    path.display(),
                )
            }
            Finding::EnvLeak { var } => write!(
                f,
                "warning: {var} not in env_delete \u{2014} host's session env leaks into 'tenant shell' sessions; \
                 add `Defaults env_delete += \"{var}\"` to /etc/sudoers"
            ),
        }
    }
}

/// Does the env policy unconditionally delete `var` from propagation
/// for `sudo -u <tenant>` invocations?
///
/// Greps the concatenated sudoers text for an UNQUALIFIED `Defaults
/// env_delete` directive that includes `var`. Recognized shapes:
/// - `Defaults env_delete += "X"`
/// - `Defaults env_delete = "X Y Z"` (multi-var list, space-separated)
/// - `Defaults env_delete += X` (unquoted single var)
///
/// **Qualified `Defaults` forms are NOT accepted.** Sudo allows
/// `Defaults:user` (invoking-user scoped), `Defaults>runas`
/// (target-user scoped), `Defaults@host` (host scoped), and
/// `Defaults!cmd` (command-tag scoped) — each restricts when the
/// directive applies. A `Defaults>plugin-dev env_delete += "X"`
/// applies only when sudo runs as `plugin-dev`, not when it runs
/// as a tenant — so it doesn't protect the operator's tenant
/// sessions even though the literal text mentions `env_delete`.
/// Cycle-1 brief Q5 lock: better to nag the operator about a leak
/// covered by a per-runas directive (false positive — they can add
/// an unqualified directive to silence) than to silently miss a real
/// leak.
pub fn has_env_delete_for(policy: &str, var: &str) -> bool {
    for raw_line in policy.lines() {
        let line = raw_line.trim();
        // Accept ONLY unqualified `Defaults` followed directly by
        // whitespace. Qualified forms (`Defaults:`, `Defaults>`,
        // `Defaults@`, `Defaults!`) restrict the directive's scope
        // and don't reliably protect tenant invocations.
        let after_defaults = match line.strip_prefix("Defaults") {
            Some(rest) if rest.starts_with(|c: char| c.is_whitespace()) => rest.trim(),
            _ => continue,
        };
        // Now `after_defaults` should start with `env_delete`. Use a
        // word-boundary check so `env_delete_extra` doesn't false-
        // match.
        let after_envdel = match after_defaults.strip_prefix("env_delete") {
            Some(rest) if rest.starts_with(|c: char| c.is_whitespace() || c == '=' || c == '+') => {
                rest.trim()
            }
            _ => continue,
        };
        // Expect `+=` or `=` next.
        let after_op = if let Some(rest) = after_envdel.strip_prefix("+=") {
            rest.trim()
        } else if let Some(rest) = after_envdel.strip_prefix('=') {
            rest.trim()
        } else {
            continue;
        };
        // The value is either a double-quoted space-separated list or
        // a single bare token. Strip surrounding quotes if present.
        let value = after_op
            .trim_start_matches('"')
            .trim_end_matches('"')
            .trim();
        // Tokenize space-separated entries.
        if value.split_whitespace().any(|tok| tok == var) {
            return true;
        }
    }
    false
}

/// Map a (category, probe-outcome) pair to a finding's severity, or
/// `None` if no finding fires. Only `Allowed` ever produces a
/// finding — `Denied` and `Unknown` are the expected case for
/// sensitive paths on a hardened host and should not pollute output.
pub fn classify(category: Category, outcome: AccessOutcome) -> Option<Severity> {
    match (category, outcome) {
        (_, AccessOutcome::Denied) | (_, AccessOutcome::Unknown) => None,
        (Category::HostSecret, AccessOutcome::Allowed) => Some(Severity::Critical),
        (Category::HostHomeListing, AccessOutcome::Allowed) => Some(Severity::Warning),
        (Category::CrossTenant, AccessOutcome::Allowed) => Some(Severity::Warning),
        (Category::TenantArtifact, AccessOutcome::Allowed) => Some(Severity::Info),
    }
}

/// Build the curated list of (category, access, path) tuples to probe
/// for one tenant on one host. The list is:
///
/// - **HostHomeListing**: `/Users/<host>` (List).
/// - **HostSecret (Read)**: SSH private keys, AWS credentials, GnuPG
///   private-key dir, GitHub PAT (`~/.config/gh/hosts.yml`), Claude
///   OAuth token (`~/.claude.json`), zsh history.
/// - **HostSecret (List)**: `.ssh`, `.aws`, `.gnupg`, `.config/gh`,
///   `.claude`, `Library/Keychains`, `Documents`, `Desktop`,
///   `Downloads` — directory listability checks for the same threat
///   model (a tenant who can list `~/.ssh/` may enumerate key names
///   even if individual files are 0600).
/// - **CrossTenant**: for each `other` tenant ≠ `tenant`,
///   `/Users/<other>` (List) and `/Users/<other>/.ssh` (List).
/// - **TenantArtifact**: for each `other`, the host-side profile
///   `~/.config/tenant/profiles/<other>.toml` (Read) and the per-
///   tenant PF anchor `/etc/pf.anchors/tenant-<other>` (Read).
///
/// `others` is permitted to contain the current `tenant` name; that
/// entry is filtered out so callers can pass an unfiltered tenant
/// list. Order is stable across calls so the operator's diff between
/// two `tenant doctor` runs is meaningful.
pub fn curated_paths(
    host: &str,
    tenant: &str,
    others: &[&str],
) -> Vec<(Category, AccessMode, PathBuf)> {
    let mut out: Vec<(Category, AccessMode, PathBuf)> = Vec::new();
    let host_home = format!("/Users/{host}");

    out.push((
        Category::HostHomeListing,
        AccessMode::List,
        PathBuf::from(&host_home),
    ));

    let secret_files: &[&str] = &[
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".aws/credentials",
        ".gnupg/private-keys-v1.d",
        ".config/gh/hosts.yml",
        ".claude.json",
        ".zsh_history",
    ];
    for sub in secret_files {
        out.push((
            Category::HostSecret,
            AccessMode::Read,
            PathBuf::from(format!("{host_home}/{sub}")),
        ));
    }

    let secret_dirs: &[&str] = &[
        ".ssh",
        ".aws",
        ".gnupg",
        ".config/gh",
        ".claude",
        "Library/Keychains",
        "Documents",
        "Desktop",
        "Downloads",
    ];
    for sub in secret_dirs {
        out.push((
            Category::HostSecret,
            AccessMode::List,
            PathBuf::from(format!("{host_home}/{sub}")),
        ));
    }

    for other in others {
        if *other == tenant {
            continue;
        }
        let other_home = format!("/Users/{other}");
        out.push((
            Category::CrossTenant,
            AccessMode::List,
            PathBuf::from(&other_home),
        ));
        out.push((
            Category::CrossTenant,
            AccessMode::List,
            PathBuf::from(format!("{other_home}/.ssh")),
        ));
    }

    for other in others {
        if *other == tenant {
            continue;
        }
        out.push((
            Category::TenantArtifact,
            AccessMode::Read,
            PathBuf::from(format!("{host_home}/.config/tenant/profiles/{other}.toml")),
        ));
        out.push((
            Category::TenantArtifact,
            AccessMode::Read,
            PathBuf::from(format!("/etc/pf.anchors/tenant-{other}")),
        ));
    }

    out
}

/// Render a curated path for the verbose-mode "Curated sensitive paths
/// checked:" disclosure block (sub-cycle 7). Forms one line per path
/// with the access mode suffix so operators can see which capability
/// was probed (Read vs List on the same path produce two lines).
pub fn render_curated_line(access: AccessMode, path: &Path) -> String {
    let verb = match access {
        AccessMode::Read => "read",
        AccessMode::List => "list",
    };
    format!("  {} {}", verb, path.display())
}
