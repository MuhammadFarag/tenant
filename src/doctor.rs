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
///
/// `PfRuleDrift` is the per-tenant finding from cycle 7 SC2: the
/// kernel's anchor for `tenant-<name>` is missing a structural rule
/// (no `pass` rule, no `block return` rule, or both — empty anchor).
/// Warning-tier because the drift is recoverable via `tenant mode
/// <name> runtime` (re-renders + reloads the anchor). `detail`
/// names which structural rule is missing.
///
/// `TouchIdMissing` is the host-wide finding from cycle 7 SC3:
/// `/etc/pam.d/sudo` has no active `pam_tid.so` directive. Info-tier
/// per the cycle-7 brief Q5 lock — it's a recommendation aligned
/// with the project's NOPASSWD-sudoers stance (Touch ID makes sudo
/// faster AND adds an auth factor), not a correctness drift. Info
/// findings do not trip `--strict`'s exit-1, so the operator sees
/// the tip once but isn't nagged on every doctor run.
///
/// `PfDisabled` is the host-wide finding from cycle 7 SC4: pf's
/// global enable state is off (`pfctl -d` was run, or pf never
/// got enabled on this host). Critical-tier — when pf is off, NO
/// tenant's firewall enforces anything; every tenant's anchor is
/// silently inert. Recovery is `sudo pfctl -e` (idempotent at the
/// substrate; the create flow's `FirewallOp::Enable` is the same
/// command).
///
/// `AnchorBodyDrift` is the per-tenant finding from cycle 8: the
/// on-disk anchor file at `/etc/pf.anchors/tenant-<name>` differs
/// byte-for-byte from what `firewall::render_anchor` would produce
/// from the current profile (runtime tier — install widening is
/// session-scoped, so any sustained install-tier on-disk state IS
/// drift). Warning-tier; recovery is `tenant mode <name> runtime`
/// (re-renders + reloads the anchor), same as `PfRuleDrift`.
///
/// Vocabulary note: the variant says "body" (the technical content
/// concept) and the `Display` impl says "anchor file drift" / "on-disk
/// body" (the operator's mental model — they hand-edited the FILE; the
/// detail names what specifically diverged). Same deliberate
/// two-level framing as `PfRuleDrift` ("rule" internally, "pf anchor"
/// in Display).
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
    PfRuleDrift {
        tenant: String,
        detail: &'static str,
    },
    TouchIdMissing,
    PfDisabled,
    AnchorBodyDrift {
        tenant: String,
    },
}

impl Finding {
    pub fn severity(&self) -> Severity {
        match self {
            Finding::FilesystemExposure { severity, .. } => *severity,
            Finding::EnvLeak { .. } => Severity::Warning,
            Finding::PfRuleDrift { .. } => Severity::Warning,
            Finding::TouchIdMissing => Severity::Info,
            Finding::PfDisabled => Severity::Critical,
            Finding::AnchorBodyDrift { .. } => Severity::Warning,
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
            Finding::PfRuleDrift { tenant, detail } => write!(
                f,
                "warning: tenant '{tenant}' pf anchor drift \u{2014} {detail}; \
                 run `tenant mode {tenant} runtime` to re-render and reload"
            ),
            Finding::TouchIdMissing => write!(
                f,
                "info: Touch ID for sudo not detected \u{2014} \
                 add `auth sufficient pam_tid.so` to /etc/pam.d/sudo \
                 to enable fingerprint-gated sudo"
            ),
            Finding::PfDisabled => write!(
                f,
                "critical: pf is globally disabled \u{2014} no tenant firewall \
                 is enforcing; run `sudo pfctl -e` to enable"
            ),
            Finding::AnchorBodyDrift { tenant } => write!(
                f,
                "warning: tenant '{tenant}' anchor file drift \u{2014} \
                 on-disk body differs from profile-derived render; \
                 run `tenant mode {tenant} runtime` to re-render and reload"
            ),
        }
    }
}

/// Does the on-disk anchor body match the profile-derived expected
/// body byte-for-byte? Caller passes the actual file content
/// (`Executor::read_anchor_body`) and the expected render
/// (`firewall::render_anchor` over the runtime-tier hosts).
///
/// Byte-exact per the cycle-8 brief Q2: `render_anchor` is
/// deterministic — same profile + tenant produces identical output
/// across runs — so any difference is real drift, not cosmetic. If
/// trailing-whitespace or comment-edit false positives ever surface,
/// soften the comparator here.
pub fn anchor_body_matches(actual: &str, expected: &str) -> bool {
    actual == expected
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

/// Does `pfctl -si` report pf as enabled? (Cycle 7 SC4.)
///
/// Match shape: a non-comment line whose trimmed form starts with
/// `Status: Enabled`. `pfctl -si`'s canonical first line is e.g.
/// `Status: Enabled for 3 days 04:32:18` (uptime suffix varies);
/// when pf is off, it reports `Status: Disabled`. Prefix match on
/// `Status: Enabled` distinguishes cleanly. Leading whitespace is
/// tolerated.
pub fn pf_status_enabled(status: &str) -> bool {
    for raw_line in status.lines() {
        let line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("Status: Enabled") {
            return true;
        }
    }
    false
}

/// Does `/etc/pam.d/sudo` enable Touch-ID-for-sudo via an active
/// `pam_tid.so` directive? (Cycle 7 SC3.)
///
/// Match shape: a non-comment line whose tokens are `auth sufficient
/// pam_tid.so` (control == `sufficient`, module == `pam_tid.so`).
/// Returns `true` on first hit; `false` if no such line is present.
///
/// Why `sufficient` specifically: pam.d's stack semantics give
/// `sufficient` modules a short-circuit-on-success role — a passing
/// `pam_tid.so sufficient` means sudo authenticates via Touch ID
/// alone (no fallback to password). A `required` or `optional`
/// pam_tid.so doesn't carry the same UX guarantee (Touch ID may
/// run AND then still demand a password). Conservative-false: a
/// non-`sufficient` directive reports as missing, prompting the
/// operator to inspect and confirm.
///
/// Commented (`#`-prefixed) lines do not count. Leading whitespace
/// is tolerated. Inline trailing comments after the module name are
/// not parsed — pam.d doesn't accept them in the canonical sense, so
/// `auth sufficient pam_tid.so # comment` is treated as a real line
/// (the parser sees `auth`, `sufficient`, `pam_tid.so` as the first
/// three tokens).
pub fn has_pam_tid(pam_config: &str) -> bool {
    for raw_line in pam_config.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut toks = line.split_whitespace();
        let kind = toks.next();
        let control = toks.next();
        let module = toks.next();
        if kind == Some("auth") && control == Some("sufficient") && module == Some("pam_tid.so") {
            return true;
        }
    }
    false
}

/// Structural-presence check on the kernel's pf rules for the
/// `tenant-<name>` anchor (cycle 7 SC2). Returns up to two
/// `PfRuleDrift` findings: one if no `pass` rule is present, one if
/// no `block return` rule is present.
///
/// Structural (not exact line-by-line) per the cycle-7 brief Q7 lock:
/// pfctl's output format isn't a stable contract (numerical IPs vs
/// hostnames, table-reference reformatting) so an exact-match check
/// would false-positive on cosmetic drift. The structural shape
/// catches the case that actually matters — "kernel anchor is empty
/// or missing one of the two rule classes the runtime requires".
///
/// Match shape: line begins with `pass ` (any pass rule) and
/// separately a line begins with `block ` (any block rule). Both are
/// case-sensitive lowercase per pfctl's canonical output. Leading
/// whitespace is tolerated; commented-out lines (`#`-prefixed) do
/// not count as a real rule.
pub fn pf_rule_presence_check(rules: &str, tenant: &str) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    let mut has_pass = false;
    let mut has_block = false;
    for raw in rules.lines() {
        let line = raw.trim_start();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with("pass ") {
            has_pass = true;
        }
        if line.starts_with("block ") {
            has_block = true;
        }
    }
    if !has_pass {
        out.push(Finding::PfRuleDrift {
            tenant: tenant.to_string(),
            detail: "no `pass` rule in kernel anchor",
        });
    }
    if !has_block {
        out.push(Finding::PfRuleDrift {
            tenant: tenant.to_string(),
            detail: "no `block` rule in kernel anchor",
        });
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
