//! Combinatorial unit tests for `doctor` module pure functions.
//!
//! Justification (per CLAUDE.md test discipline): `curated_paths`,
//! `classify`, and `Finding::Display` have small combinatorial state
//! spaces (categories × access modes × outcomes) that would require
//! many overlapping E2E tests to cover; per-cell unit testing is the
//! right tool. CLI verb behavior continues to live in `tests/cli.rs`.

use std::path::PathBuf;

use tenant::doctor::{Category, Finding, Severity, classify, curated_paths};
use tenant::executor::{AccessMode, AccessOutcome};

// ============================================================
// Finding display — byte-exact per combination
// ============================================================

#[test]
fn finding_display_critical_read() {
    let f = Finding::FilesystemExposure {
        severity: Severity::Critical,
        tenant: "dev".to_string(),
        path: PathBuf::from("/Users/host/.ssh/id_rsa"),
        access: AccessMode::Read,
    };
    assert_eq!(
        format!("{f}"),
        "critical: tenant 'dev' can read /Users/host/.ssh/id_rsa"
    );
}

#[test]
fn finding_display_warning_list() {
    let f = Finding::FilesystemExposure {
        severity: Severity::Warning,
        tenant: "dev".to_string(),
        path: PathBuf::from("/Users/staging"),
        access: AccessMode::List,
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' can list /Users/staging"
    );
}

#[test]
fn finding_display_info_read() {
    let f = Finding::FilesystemExposure {
        severity: Severity::Info,
        tenant: "dev".to_string(),
        path: PathBuf::from("/etc/pf.anchors/tenant-staging"),
        access: AccessMode::Read,
    };
    assert_eq!(
        format!("{f}"),
        "info: tenant 'dev' can read /etc/pf.anchors/tenant-staging"
    );
}

// ============================================================
// classify — (category × outcome) -> Option<Severity>
// ============================================================
//
// Only the `Allowed` column ever fires a finding. `Denied` and
// `Unknown` collapse to None for every category — the kernel's "no
// access" answer is exactly what we expect on a hardened host and
// should not pollute the operator's output. Negative pins on
// Denied/Unknown live below.

#[test]
fn classify_host_secret_allowed_is_critical() {
    assert_eq!(
        classify(Category::HostSecret, AccessOutcome::Allowed),
        Some(Severity::Critical)
    );
}

#[test]
fn classify_host_home_listing_allowed_is_warning() {
    assert_eq!(
        classify(Category::HostHomeListing, AccessOutcome::Allowed),
        Some(Severity::Warning)
    );
}

#[test]
fn classify_cross_tenant_allowed_is_warning() {
    assert_eq!(
        classify(Category::CrossTenant, AccessOutcome::Allowed),
        Some(Severity::Warning)
    );
}

#[test]
fn classify_tenant_artifact_allowed_is_info() {
    // `/etc/pf.anchors/tenant-<other>` is mode 0644 by design (cycle-2's
    // install flow) — the read IS allowed, and we report it as `info`
    // rather than `critical` because the exposure is intentional and
    // the operator should know without being alarmed.
    assert_eq!(
        classify(Category::TenantArtifact, AccessOutcome::Allowed),
        Some(Severity::Info)
    );
}

#[test]
fn classify_every_category_denied_is_no_finding() {
    for category in [
        Category::HostSecret,
        Category::HostHomeListing,
        Category::CrossTenant,
        Category::TenantArtifact,
    ] {
        assert_eq!(
            classify(category, AccessOutcome::Denied),
            None,
            "category {category:?} + Denied should produce no finding"
        );
    }
}

#[test]
fn classify_every_category_unknown_is_no_finding() {
    for category in [
        Category::HostSecret,
        Category::HostHomeListing,
        Category::CrossTenant,
        Category::TenantArtifact,
    ] {
        assert_eq!(
            classify(category, AccessOutcome::Unknown),
            None,
            "category {category:?} + Unknown should produce no finding"
        );
    }
}

// ============================================================
// curated_paths — coverage of every category
// ============================================================

#[test]
fn curated_paths_covers_host_secret_paths() {
    // For a host with no other tenants, the curated list still includes
    // host-side secret targets. `.ssh/id_rsa` is the canonical Read
    // target; presence pins the category covers the SSH private-key
    // case at minimum.
    let paths = curated_paths("alice", "dev", &[]);
    assert!(
        paths
            .iter()
            .any(|(c, m, p)| matches!(c, Category::HostSecret)
                && matches!(m, AccessMode::Read)
                && p == &PathBuf::from("/Users/alice/.ssh/id_rsa")),
        "curated_paths should include /Users/<host>/.ssh/id_rsa as HostSecret+Read; got: {paths:?}"
    );
}

#[test]
fn curated_paths_covers_host_home_listing() {
    // The top-level read of `/Users/<host>/` is the listability check
    // that detects whether a tenant can enumerate the operator's home.
    let paths = curated_paths("alice", "dev", &[]);
    assert!(
        paths
            .iter()
            .any(|(c, m, p)| matches!(c, Category::HostHomeListing)
                && matches!(m, AccessMode::List)
                && p == &PathBuf::from("/Users/alice")),
        "curated_paths should include /Users/<host> as HostHomeListing+List; got: {paths:?}"
    );
}

#[test]
fn curated_paths_covers_cross_tenant_when_others_present() {
    // Cross-tenant entries are gated on the `others` list — with no
    // others, no cross-tenant probes; with one other tenant, the
    // other's home + .ssh dir are probed for listability.
    let paths = curated_paths("alice", "dev", &["staging"]);
    assert!(
        paths
            .iter()
            .any(|(c, m, p)| matches!(c, Category::CrossTenant)
                && matches!(m, AccessMode::List)
                && p == &PathBuf::from("/Users/staging")),
        "curated_paths should include /Users/<other> as CrossTenant+List when others present; got: {paths:?}"
    );
    assert!(
        paths
            .iter()
            .any(|(c, m, p)| matches!(c, Category::CrossTenant)
                && matches!(m, AccessMode::List)
                && p == &PathBuf::from("/Users/staging/.ssh")),
        "curated_paths should include /Users/<other>/.ssh as CrossTenant+List when others present; got: {paths:?}"
    );
}

#[test]
fn curated_paths_omits_cross_tenant_when_no_others() {
    // Negative pin: a single-tenant host (`others` is empty) emits no
    // cross-tenant entries. Guards against a regression that always
    // appended `/Users/<self>` to the cross-tenant block.
    let paths = curated_paths("alice", "dev", &[]);
    assert!(
        !paths
            .iter()
            .any(|(c, _, _)| matches!(c, Category::CrossTenant)),
        "curated_paths should emit no CrossTenant entries when others is empty; got: {paths:?}"
    );
}

#[test]
fn curated_paths_covers_tenant_artifacts_when_others_present() {
    // Tenant-project artifacts (~/.config/tenant/profiles/<other>.toml,
    // /etc/pf.anchors/tenant-<other>) are info-tier leaks that doctor
    // surfaces so the operator knows other tenants' configs are not
    // strictly private.
    let paths = curated_paths("alice", "dev", &["staging"]);
    assert!(
        paths
            .iter()
            .any(|(c, m, p)| matches!(c, Category::TenantArtifact)
                && matches!(m, AccessMode::Read)
                && p == &PathBuf::from("/Users/alice/.config/tenant/profiles/staging.toml")),
        "curated_paths should include other-tenant profile path as TenantArtifact+Read; got: {paths:?}"
    );
    assert!(
        paths
            .iter()
            .any(|(c, m, p)| matches!(c, Category::TenantArtifact)
                && matches!(m, AccessMode::Read)
                && p == &PathBuf::from("/etc/pf.anchors/tenant-staging")),
        "curated_paths should include other-tenant anchor path as TenantArtifact+Read; got: {paths:?}"
    );
}

#[test]
fn curated_paths_omits_self_from_other_lists() {
    // When `tenant` == `dev` and `others` accidentally includes `dev`,
    // we should not generate cross-tenant or tenant-artifact entries
    // pointing at our own home / config. Pins the contract that
    // callers can pass a tenant list without pre-filtering and doctor
    // does the right thing.
    let paths = curated_paths("alice", "dev", &["dev", "staging"]);
    let self_referential = paths.iter().any(|(_, _, p)| {
        p == &PathBuf::from("/Users/dev")
            || p == &PathBuf::from("/Users/dev/.ssh")
            || p == &PathBuf::from("/Users/alice/.config/tenant/profiles/dev.toml")
            || p == &PathBuf::from("/etc/pf.anchors/tenant-dev")
    });
    assert!(
        !self_referential,
        "curated_paths should not probe self via the others list; got: {paths:?}"
    );
}

// ============================================================
// Severity ordering — load-bearing for --strict (sub-cycle 4)
// ============================================================

#[test]
fn severity_ordering_critical_max() {
    // --strict's exit-code logic uses `max()` across findings. Ord
    // must place Critical at the top so a single critical in a list
    // of warnings produces the exit-2 verdict. Info < Warning <
    // Critical.
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::Critical);
    assert_eq!(
        [Severity::Info, Severity::Warning, Severity::Critical]
            .iter()
            .max(),
        Some(&Severity::Critical)
    );
    assert_eq!(
        [Severity::Info, Severity::Warning].iter().max(),
        Some(&Severity::Warning)
    );
}
