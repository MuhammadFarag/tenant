//! Combinatorial unit tests for `doctor` module pure functions.
//!
//! Justification (per CLAUDE.md test discipline): `curated_paths`,
//! `classify`, and `Finding::Display` have small combinatorial state
//! spaces (categories × access modes × outcomes) that would require
//! many overlapping E2E tests to cover; per-cell unit testing is the
//! right tool. CLI verb behavior continues to live in `tests/cli.rs`.

use std::path::PathBuf;

use tenant::doctor::{
    Category, Finding, Severity, SymlinkActual, anchor_body_matches, classify, curated_paths,
};
use tenant::domain::{AccessMode, AccessOutcome, HostUserName, TenantUserName};

// ============================================================
// Finding display — byte-exact per combination
// ============================================================

#[test]
fn finding_display_critical_read() {
    let f = Finding::FilesystemExposure {
        severity: Severity::Critical,
        tenant: TenantUserName::from("dev"),
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
        tenant: TenantUserName::from("dev"),
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
        tenant: TenantUserName::from("dev"),
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
    // `/etc/pf.anchors/tenant-<other>` is mode 0644 by design (the
    // install flow sets it) — the read IS allowed, and we report it
    // as `info` rather than `critical` because the exposure is
    // intentional and the operator should know without being alarmed.
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
// Severity ordering — load-bearing for --strict
// ============================================================

// ============================================================
// anchor_body_matches — byte-exact equality
// ============================================================
//
// Pure-function comparator for doctor's anchor-body drift check.
// Compares the on-disk anchor body against the profile-derived
// `render_anchor` output. Locked at byte-exact: the render path is
// deterministic, so any difference is real drift. Soften later
// (e.g. trim trailing whitespace) only if false positives surface.

#[test]
fn anchor_body_matches_equal_strings_true() {
    let body = "# PF anchor for tenant 'dev'\nblock return inet from any to any\n";
    assert!(anchor_body_matches(body, body));
}

#[test]
fn anchor_body_matches_extra_trailing_newline_false() {
    // Byte-exact: trailing newline DOES count. Negative pin against
    // a future "normalize trailing whitespace" softening that would
    // also need to update this test deliberately.
    let actual = "block return inet from any to any\n";
    let expected = "block return inet from any to any\n\n";
    assert!(!anchor_body_matches(actual, expected));
}

#[test]
fn anchor_body_matches_empty_strings_true() {
    // Edge case: both empty (e.g. file truncated to zero AND render
    // produced empty — implausible but the function shouldn't choke).
    assert!(anchor_body_matches("", ""));
}

// ============================================================
// Finding::AnchorBodyDrift — Display + severity
// ============================================================

#[test]
fn finding_display_anchor_body_drift() {
    let f = Finding::AnchorBodyDrift {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' anchor file drift \u{2014} on-disk body differs from profile-derived render; \
         run `tenant mode dev runtime` to re-render and reload"
    );
}

#[test]
fn finding_anchor_body_drift_severity_is_warning() {
    let f = Finding::AnchorBodyDrift {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(f.severity(), Severity::Warning);
}

// ============================================================
// Finding::guidance — per-variant multi-section text
// ============================================================
//
// Byte-exact pins on the structured-guidance block each variant emits
// for verbose-mode rendering. Tests both that the locked section
// headers appear in the locked order and that tenant-name / var-name
// substitution lands in every place the text references them. Sentence
// case for headers, imperative voice for fixes, literal tenant name in
// per-tenant variants.

#[test]
fn guidance_filesystem_exposure_returns_none() {
    // FilesystemExposure intentionally has no guidance body — per-path-
    // category text belongs with the future remediation surface, not
    // the detection surface. `guidance()` returns None; Reporter
    // renders the one-liner alone even in verbose mode.
    let f = Finding::FilesystemExposure {
        severity: Severity::Critical,
        tenant: TenantUserName::from("dev"),
        path: std::path::PathBuf::from("/Users/host/.ssh/id_rsa"),
        access: tenant::domain::AccessMode::Read,
    };
    assert_eq!(f.guidance(), None);
}

#[test]
fn guidance_anchor_body_drift_byte_form() {
    let f = Finding::AnchorBodyDrift {
        tenant: TenantUserName::from("dev"),
    };
    let expected = "Why this matters
  The on-disk file at /etc/pf.anchors/tenant-dev is the source of
  truth pf.conf reloads on boot. Its current body diverges from what
  the profile would render \u{2014} so the next reboot or pfctl reload
  will switch the in-kernel ruleset to whatever's on disk, not what
  intent describes. If the divergence is a hand-edit, that edit becomes
  the enforced policy. If it's install-tier widening left behind from a
  prior session, the allowlist stays wide indefinitely.

Recommended fix
  tenant mode dev runtime
  Re-renders the anchor body from the profile (runtime tier) and
  reloads pf, bringing the file and the in-kernel state back in sync
  with intent.

Side-effects to know about
  \u{2022} The pfctl reload causes a sub-millisecond packet-filter disruption.
  \u{2022} Any hand-edits to /etc/pf.anchors/tenant-dev are discarded.
  \u{2022} If install-tier hosts were deliberately on disk, the narrow drops
    them; rerun `tenant mode dev install` after the narrow if
    still needed.

Alternative
  sudo $EDITOR /etc/pf.anchors/tenant-dev && sudo pfctl -f /etc/pf.conf
  Edits the file directly and reloads pf. Preserves operator edits but
  leaves profile and file out of sync \u{2014} the next `tenant mode` or
  `tenant shell` invocation will re-render and overwrite them.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

#[test]
fn guidance_pf_rule_drift_byte_form() {
    let f = Finding::PfRuleDrift {
        tenant: TenantUserName::from("dev"),
        detail: "no `pass` rule in kernel anchor",
    };
    let expected = "Why this matters
  The kernel's pf anchor for tenant 'dev' is missing one of the
  structural rule classes the runtime requires \u{2014} either the `pass`
  rule that allows traffic to the allowlist, the `block` rule that
  drops everything else, or both. Whatever is enforcing right now
  doesn't match the file or the profile; packets the tenant sends may
  be flowing through unintended paths until the next reload reinstates
  the full ruleset.

Recommended fix
  tenant mode dev runtime
  Re-renders the anchor file from the profile (runtime tier) and
  reloads pf, reinstating the full pass + block rule pair in the
  in-kernel anchor.

Side-effects to know about
  \u{2022} The pfctl reload causes a sub-millisecond packet-filter disruption.
  \u{2022} If the on-disk anchor file is also drifted, this fixes both \u{2014}
    file and kernel sync to the profile in one step.
  \u{2022} If install-tier widening was previously applied via `tenant mode
    dev install`, the narrow drops it; rerun mode install
    afterward if the wider allowlist is still needed.

Alternative
  sudo pfctl -f /etc/pf.conf
  Reloads the whole pf.conf, which re-reads the (current) on-disk
  anchor file. Faster than re-rendering but only fixes the kernel-side
  drift if the on-disk file itself isn't drifted; otherwise it just
  reinstalls the drifted body into the kernel.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

#[test]
fn guidance_pf_disabled_byte_form() {
    // PfDisabled is host-wide; no tenant interpolation. "Why this
    // matters" emphasizes the zero-isolation stake. No Alternative
    // section (binary state — pf is either on or off).
    let f = Finding::PfDisabled;
    let expected = "Why this matters
  pf is globally disabled on this host. Every tenant has an anchor
  installed under /etc/pf.anchors/, every anchor is referenced from
  /etc/pf.conf, but pf itself doesn't consult any of them while
  filtering packets \u{2014} so no tenant's egress allowlist is enforcing
  anything. The isolation guarantee tenants depend on is currently
  zero. Any `tenant create` or `tenant mode` that ran while pf was
  disabled installed correct rules into a kernel that's ignoring them.

Recommended fix
  sudo pfctl -e
  Enables pf globally. Idempotent at the substrate \u{2014} this is the same
  command `tenant create` runs on first invocation when pf isn't
  already on.

Side-effects to know about
  \u{2022} Re-enabling pf may surface live issues the operator originally
    disabled it to escape (debugging a flaky rule, working around a
    misconfigured anchor). Verify with `pfctl -sr` before assuming
    the prior issue is resolved.
  \u{2022} Currently-running tenant sessions immediately start being
    filtered by their anchors; in-flight connections the allowlist
    would block may drop.
  \u{2022} System-wide pf rules in /etc/pf.conf also start enforcing again,
    not just tenant anchors.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

#[test]
fn guidance_env_leak_byte_form() {
    // Alternative names the qualified-Defaults case (operators who
    // already have a runas-qualified directive and are confused why
    // doctor still nags). The Recommended fix is the unqualified
    // form per the CLAUDE.md doctrine.
    let f = Finding::EnvLeak {
        var: "SSH_AUTH_SOCK".to_string(),
    };
    let expected = "Why this matters
  /etc/sudoers (with drop-ins) doesn't carry an unqualified
  `Defaults env_delete += \"SSH_AUTH_SOCK\"` directive, so the operator's
  session env propagates verbatim into every `sudo -u <tenant>`
  invocation \u{2014} which is exactly how `tenant shell` enters a tenant.
  The canonical case is SSH_AUTH_SOCK: macOS's ssh-agent socket gets
  inherited, and any tenant the operator shells into can `ssh` to
  every host the operator has cached keys for. The isolation between
  host and tenant is breached at the SSH layer even though pf, the
  filesystem, and the UID/GID are all correct.

Recommended fix
  echo 'Defaults env_delete += \"SSH_AUTH_SOCK\"' | sudo tee -a /etc/sudoers.d/tenant >/dev/null
  Appends to a drop-in file so the main /etc/sudoers stays pristine.
  The directive must be unqualified (no `Defaults:user`, no
  `Defaults>runas`); qualified forms restrict scope and don't protect
  `sudo -u <tenant>` invocations.

Side-effects to know about
  \u{2022} Future `sudo -u <tenant>` sessions won't see SSH_AUTH_SOCK in their env.
    A tenant can still set the var manually (e.g. explicit agent
    forwarding) \u{2014} this closes the unintentional leak path, not all
    paths.
  \u{2022} Other shells that invoke sudo (`sudo bash`, `sudo make`) also
    lose SSH_AUTH_SOCK from their inherited env, regardless of which user sudo
    is running as. Usually fine; flag if a host-side workflow depended
    on the leak.
  \u{2022} Validate the edit with `sudo visudo -c -f /etc/sudoers.d/tenant`
    before relying on it \u{2014} a syntax error in a drop-in can break sudo
    across the host.

Alternative
  Defaults>tenant env_delete += \"SSH_AUTH_SOCK\"
  A `Defaults>runas` form targets only sudo invocations whose -u arg
  matches a tenant by name \u{2014} narrower than the unqualified form but
  doctor will still nag (the parser conservatively rejects qualified
  Defaults per CLAUDE.md's unqualified-directive doctrine). If you
  prefer the qualified form, accept the false-positive warning on
  every doctor run.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

#[test]
fn guidance_touch_id_missing_byte_form() {
    // Info-toned "why" (recommendation, not correctness drift); no
    // Alternative (no meaningful different command exists in this
    // project's threat model — either you want Touch ID or you don't).
    let f = Finding::TouchIdMissing;
    let expected = "Why this matters
  /etc/pam.d/sudo doesn't enable Touch ID for sudo authentication.
  This isn't a correctness drift \u{2014} sudo still works via password \u{2014}
  but it's a recommendation aligned with the project's locked
  no-NOPASSWD-sudoers stance. Touch ID makes sudo prompts faster (a
  fingerprint beats typing a password) AND adds a second auth factor
  (fingerprint plus sudoers membership) instead of just one (sudoers
  membership). Info-tier because absence doesn't compromise isolation;
  it's an ergonomics + defense-in-depth gap.

Recommended fix
  sudo sed -i.bak '/^auth.*pam_opendirectory/i auth       sufficient     pam_tid.so' /etc/pam.d/sudo
  Inserts an `auth sufficient pam_tid.so` line before the existing
  pam_opendirectory module. `sufficient` is the control type the
  threat model expects \u{2014} a Touch ID hit short-circuits the rest of
  the auth stack; a Touch ID miss falls through to password.

Side-effects to know about
  \u{2022} Next sudo invocation pops a Touch ID prompt instead of (or
    before) the password prompt. Touch your sensor on the Touch Bar
    or Magic Keyboard within ~10 seconds.
  \u{2022} If Touch ID hardware isn't available or isn't registered (System
    Settings \u{2192} Touch ID & Password), pam_tid.so falls through to the
    next module \u{2014} sudo still works, just without the short-circuit.
  \u{2022} The /etc/pam.d/sudo.bak backup file is created by sed -i.bak;
    remove it (`sudo rm /etc/pam.d/sudo.bak`) once the new behavior is
    verified.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

// ============================================================
// Severity ordering — load-bearing for --strict
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

// ============================================================
// Finding::AclDrift — Display + severity
// ============================================================

#[test]
fn finding_display_acl_drift() {
    let f = Finding::AclDrift {
        tenant: TenantUserName::from("dev"),
        host_path: std::path::PathBuf::from("/Users/Shared/src"),
        group: "dev-tenant-share".into(),
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' share ACL drift \u{2014} group 'dev-tenant-share' missing on /Users/Shared/src; \
         run `tenant reload dev` to re-apply"
    );
}

#[test]
fn finding_acl_drift_severity_is_warning() {
    let f = Finding::AclDrift {
        tenant: TenantUserName::from("dev"),
        host_path: std::path::PathBuf::from("/Users/Shared/src"),
        group: "dev-tenant-share".into(),
    };
    assert_eq!(f.severity(), Severity::Warning);
}

#[test]
fn guidance_acl_drift_byte_form() {
    let f = Finding::AclDrift {
        tenant: TenantUserName::from("dev"),
        host_path: std::path::PathBuf::from("/Users/Shared/src"),
        group: "dev-tenant-share".into(),
    };
    let expected = "Why this matters
  The host path /Users/Shared/src is declared as a share for tenant 'dev' in
  the profile, but the `dev-tenant-share` group's ACL entry is missing from the
  path's `ls -lde` listing. The tenant currently cannot reach the share
  via group membership \u{2014} any read or write attempt either fails or
  falls back to whatever POSIX bits the path carries. The most common
  causes are a manual `chmod -a` on the operator's side, or a `cp -R`
  that clobbered the entry as a side-effect.

Recommended fix
  tenant reload dev
  Re-applies every declared share in the tenant's profile. macOS
  `chmod +a` is natively idempotent \u{2014} re-applying an existing
  entry is a noop, not a duplicate \u{2014} so this is safe to run
  regardless of the path's current ACL state.

Side-effects to know about
  \u{2022} Every share in the profile is re-applied, not just this one.
    If another share has an unrelated pending refusal (host_path
    missing on disk, tenant_path occupied by a real file), reload
    will abort on it before reaching this entry; address those first.
  \u{2022} The PF anchor is also re-rendered at runtime tier as a side
    effect of `tenant reload`. If install-tier widening was active
    when the operator last ran `tenant mode dev install`, the
    narrow drops it; rerun `mode install` afterward if still needed.

Alternative
  sudo chmod -R +a \"group:dev-tenant-share allow read,write,execute,delete,append,file_inherit,directory_inherit\" /Users/Shared/src
  Re-applies just this one entry. Use when `tenant reload` is blocked
  by an unrelated refusal. The bit list shown is the `rw` default;
  for read-only shares omit `write,delete,append`. `sudo` is required
  because files written by the tenant inside the share (caches, build
  output) are tenant-owned, and POSIX requires owner-or-root to modify
  ACLs.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

// ============================================================
// Finding::CoworkAclDrift — Display + severity + guidance
// ============================================================
//
// Distinct variant from AclDrift: the cowork dir is host-managed,
// not share-declared, so the guidance narrative differs.

#[test]
fn finding_display_cowork_acl_drift() {
    let f = Finding::CoworkAclDrift {
        tenant: TenantUserName::from("dev"),
        path: std::path::PathBuf::from("/Users/Shared/tenants/dev"),
        group: "dev-tenant-share".into(),
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' co-working directory ACL drift \u{2014} group 'dev-tenant-share' missing on /Users/Shared/tenants/dev; \
         run `tenant reload dev` to re-apply"
    );
}

#[test]
fn finding_cowork_acl_drift_severity_is_warning() {
    let f = Finding::CoworkAclDrift {
        tenant: TenantUserName::from("dev"),
        path: std::path::PathBuf::from("/Users/Shared/tenants/dev"),
        group: "dev-tenant-share".into(),
    };
    assert_eq!(f.severity(), Severity::Warning);
}

#[test]
fn guidance_cowork_acl_drift_byte_form() {
    let f = Finding::CoworkAclDrift {
        tenant: TenantUserName::from("dev"),
        path: std::path::PathBuf::from("/Users/Shared/tenants/dev"),
        group: "dev-tenant-share".into(),
    };
    let expected = "Why this matters
  The co-working directory /Users/Shared/tenants/dev is the host\u{2194}tenant collaboration
  surface for tenant 'dev'. Files created on either side inside
  this directory inherit the `dev-tenant-share` group's rw ACE (via
  `file_inherit,directory_inherit`), which is what keeps the operator
  and the tenant mutually reachable. The current `ls -lde` listing is
  missing the group entry on the directory itself \u{2014} new files
  created inside will NOT inherit the rw bits, and existing files
  that previously inherited may become inaccessible from the other
  side. Common causes: a manual `chmod -a` on the cowork-dir root, a
  Time Machine restore that dropped extended ACLs, or a legacy
  tenant whose cowork dir was never provisioned with the ACE.

Recommended fix
  tenant reload dev
  Re-runs the full reapply (PF + shares + cowork dir), which includes
  `EnsureCoworkDir`'s `chmod -R +a` pass on /Users/Shared/tenants/dev. macOS `chmod +a`
  is natively idempotent; safe to run regardless of the current ACL
  state. `tenant mode` and `tenant shell` do NOT touch the cowork dir
  under their light reapply scope \u{2014} reload is the canonical
  remediation.

Side-effects to know about
  \u{2022} The PF anchor is re-rendered at runtime tier as a side effect
    of `tenant reload`. If install-tier widening was active when the
    operator last ran `tenant mode dev install`, the narrow drops
    it; rerun `mode install` afterward if still needed.
  \u{2022} The recursive ACL pass walks every existing child of the
    cowork dir. On a populated workspace this may take a few seconds.

Alternative
  sudo chmod -R +a \"group:dev-tenant-share allow read,write,execute,delete,append,file_inherit,directory_inherit\" /Users/Shared/tenants/dev
  Re-applies just the cowork-dir ACL grant. Same bit list
  `EnsureCoworkDir` uses; `sudo` is required because files inside the
  cowork dir are tenant-owned, and POSIX requires owner-or-root to
  modify ACLs.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

// ============================================================
// Finding::CoworkDirAbsent — Display + severity + guidance
// ============================================================
//
// Sibling variant to CoworkAclDrift covering the dir-doesn't-exist
// case (rm'd externally, never provisioned for an older tenant).
// Distinct variant because there's no ACL to grant if there's no
// directory.

#[test]
fn finding_display_cowork_dir_absent() {
    let f = Finding::CoworkDirAbsent {
        tenant: TenantUserName::from("dev"),
        path: std::path::PathBuf::from("/Users/Shared/tenants/dev"),
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' co-working directory missing at /Users/Shared/tenants/dev; \
         run `tenant reload dev` to re-create"
    );
}

#[test]
fn finding_cowork_dir_absent_severity_is_warning() {
    let f = Finding::CoworkDirAbsent {
        tenant: TenantUserName::from("dev"),
        path: std::path::PathBuf::from("/Users/Shared/tenants/dev"),
    };
    assert_eq!(f.severity(), Severity::Warning);
}

#[test]
fn guidance_cowork_dir_absent_byte_form() {
    let f = Finding::CoworkDirAbsent {
        tenant: TenantUserName::from("dev"),
        path: std::path::PathBuf::from("/Users/Shared/tenants/dev"),
    };
    let expected = "Why this matters
  The co-working directory /Users/Shared/tenants/dev is the per-tenant
  collaboration surface (host operator + tenant share writable access
  via the `dev-tenant-share` group, mode 2770, inheritable rw ACL).
  It's missing from disk \u{2014} `rm -rf` from the host side, a
  Time Machine restore that skipped the path, or a legacy tenant
  whose cowork dir was never provisioned. The tenant has no shared
  workspace until it's re-provisioned.

Recommended fix
  tenant reload dev
  Re-runs the full reapply (PF + shares + cowork dir), which includes
  `EnsureCoworkDir`'s four-call sequence: `mkdir -p` + `chown` +
  `chmod 2770` + `chmod -R +a` for the inheritable rw ACE. All four
  calls are natively idempotent; safe to re-run.

Side-effects to know about
  \u{2022} The PF anchor is re-rendered at runtime tier as a side effect
    of `tenant reload`. If install-tier widening was active when the
    operator last ran `tenant mode dev install`, the narrow drops
    it; rerun `mode install` afterward if still needed.
  \u{2022} The directory is created empty. Any files that previously
    lived inside (if the dir was rm'd, not just lost its ACE) are
    NOT recovered \u{2014} restore from backup separately if needed.

Alternative
  sudo mkdir -p /Users/Shared/tenants/dev && sudo chown $USER:dev-tenant-share /Users/Shared/tenants/dev && sudo chmod 2770 /Users/Shared/tenants/dev && sudo chmod -R +a \"group:dev-tenant-share allow read,write,execute,delete,append,file_inherit,directory_inherit\" /Users/Shared/tenants/dev
  Re-provisions just the cowork dir manually. Same four substrate
  calls `EnsureCoworkDir` runs. `sudo` is required for ownership and
  mode-bit changes outside the operator's home.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

// ============================================================
// Finding::SymlinkDrift — Display + severity + guidance
// ============================================================
//
// Three SymlinkActual sub-cases (Absent / WrongTarget / NotSymlink)
// each get their own byte-form pin for Display + guidance.

#[test]
fn finding_display_symlink_drift_absent() {
    let f = Finding::SymlinkDrift {
        tenant: TenantUserName::from("dev"),
        tenant_path: std::path::PathBuf::from("/Users/dev/src"),
        expected_target: std::path::PathBuf::from("/Users/Shared/src"),
        actual: SymlinkActual::Absent,
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' share symlink drift \u{2014} \
         /Users/dev/src is absent (expected symlink to /Users/Shared/src); \
         run `tenant reload dev` to re-create"
    );
}

#[test]
fn finding_display_symlink_drift_wrong_target() {
    let f = Finding::SymlinkDrift {
        tenant: TenantUserName::from("dev"),
        tenant_path: std::path::PathBuf::from("/Users/dev/src"),
        expected_target: std::path::PathBuf::from("/Users/Shared/src"),
        actual: SymlinkActual::WrongTarget(std::path::PathBuf::from("/tmp/old")),
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' share symlink drift \u{2014} \
         /Users/dev/src points at /tmp/old (expected /Users/Shared/src); \
         run `tenant reload dev` to re-link"
    );
}

#[test]
fn finding_display_symlink_drift_not_symlink() {
    let f = Finding::SymlinkDrift {
        tenant: TenantUserName::from("dev"),
        tenant_path: std::path::PathBuf::from("/Users/dev/src"),
        expected_target: std::path::PathBuf::from("/Users/Shared/src"),
        actual: SymlinkActual::NotSymlink,
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' share symlink drift \u{2014} \
         /Users/dev/src is occupied by a real file or directory (expected symlink to /Users/Shared/src); \
         remove it manually, then run `tenant reload dev`"
    );
}

#[test]
fn finding_symlink_drift_severity_is_warning_all_sub_cases() {
    for actual in [
        SymlinkActual::Absent,
        SymlinkActual::WrongTarget(std::path::PathBuf::from("/tmp")),
        SymlinkActual::NotSymlink,
    ] {
        let f = Finding::SymlinkDrift {
            tenant: TenantUserName::from("dev"),
            tenant_path: std::path::PathBuf::from("/Users/dev/src"),
            expected_target: std::path::PathBuf::from("/Users/Shared/src"),
            actual,
        };
        assert_eq!(f.severity(), Severity::Warning);
    }
}

#[test]
fn guidance_symlink_drift_absent_byte_form() {
    let f = Finding::SymlinkDrift {
        tenant: TenantUserName::from("dev"),
        tenant_path: std::path::PathBuf::from("/Users/dev/src"),
        expected_target: std::path::PathBuf::from("/Users/Shared/src"),
        actual: SymlinkActual::Absent,
    };
    let expected = "Why this matters
  The tenant_path /Users/dev/src is declared in tenant 'dev's profile to
  symlink /Users/Shared/src, but no entry exists at that path \u{2014} the tenant
  `rm`'d the symlink, or it was never installed. The tenant cannot
  reach the declared share through this path until the link is
  restored.

Recommended fix
  tenant reload dev
  Re-runs the share-reapply substrate, which calls `sudo -n -u
  dev /bin/ln -sfn /Users/Shared/src /Users/dev/src`. `ln -sfn` is idempotent
  \u{2014} replaces any existing entry at the same path with the
  declared symlink.

Side-effects to know about
  \u{2022} Every share in the profile is re-applied, not just this one.
    If another share has an unrelated pending refusal, reload aborts
    on it before reaching this entry; address those first.
  \u{2022} The PF anchor is re-rendered at runtime tier as a side effect.
    If install-tier widening was active, the narrow drops it; rerun
    `tenant mode dev install` afterward if still needed.

Alternative
  sudo -n -u dev /bin/ln -sfn /Users/Shared/src /Users/dev/src
  Recreates just this one link. Use when `tenant reload` is blocked
  by an unrelated refusal.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

#[test]
fn guidance_symlink_drift_wrong_target_byte_form() {
    let f = Finding::SymlinkDrift {
        tenant: TenantUserName::from("dev"),
        tenant_path: std::path::PathBuf::from("/Users/dev/src"),
        expected_target: std::path::PathBuf::from("/Users/Shared/src"),
        actual: SymlinkActual::WrongTarget(std::path::PathBuf::from("/tmp/old")),
    };
    let expected = "Why this matters
  The tenant_path /Users/dev/src is declared in tenant 'dev's profile to
  symlink /Users/Shared/src, but the link currently points at /tmp/old. The
  most common cause is an operator edit to the profile's host_path
  without a follow-up `tenant reload`. The tenant is still reaching A
  share through this path, just not the one the profile names.

Recommended fix
  tenant reload dev
  Re-runs the share-reapply substrate, which calls `sudo -n -u
  dev /bin/ln -sfn /Users/Shared/src /Users/dev/src`. `ln -sfn` replaces
  the existing symlink in place; no manual `rm` needed.

Side-effects to know about
  \u{2022} The old target /tmp/old stays on the host filesystem \u{2014} reload
    only updates the link, it doesn't touch what was previously linked.
    Clean up manually if appropriate.
  \u{2022} Every share in the profile is re-applied, not just this one.
    If another share has an unrelated pending refusal, reload aborts
    before reaching this entry; address those first.

Alternative
  sudo -n -u dev /bin/ln -sfn /Users/Shared/src /Users/dev/src
  Updates just this one link. Use when `tenant reload` is blocked by
  an unrelated refusal.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

#[test]
fn guidance_symlink_drift_not_symlink_byte_form() {
    let f = Finding::SymlinkDrift {
        tenant: TenantUserName::from("dev"),
        tenant_path: std::path::PathBuf::from("/Users/dev/src"),
        expected_target: std::path::PathBuf::from("/Users/Shared/src"),
        actual: SymlinkActual::NotSymlink,
    };
    let expected = "Why this matters
  The tenant_path /Users/dev/src is declared in tenant 'dev's profile to
  symlink /Users/Shared/src, but a real file or directory currently occupies
  that path \u{2014} not a symlink. `tenant reload` will refuse with
  `TenantPathOccupied` rather than clobber it (the substrate never
  overwrites real operator data). Until the conflict is removed, the
  declared share isn't reachable through this path.

Recommended fix
  sudo -n -u dev rm -rf /Users/dev/src && tenant reload dev
  Removes the conflict from the tenant's perspective, then re-runs
  the share-reapply substrate to install the declared symlink.
  Verify the conflict's contents BEFORE running `rm -rf` \u{2014} this
  step is destructive.

Side-effects to know about
  \u{2022} `rm -rf` deletes whatever's at /Users/dev/src. If that content matters,
    copy it elsewhere first.
  \u{2022} Reload re-applies every declared share, not just this one.

Alternative
  Edit the profile to point tenant_path elsewhere
  If the current content at /Users/dev/src should be preserved AND the share
  is still needed, change tenant_path in the profile to a free path,
  then run `tenant reload dev`.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

// ============================================================
// Finding::HostNotInShareGroup — Display + severity + guidance
// ============================================================

#[test]
fn finding_display_host_not_in_share_group() {
    let f = Finding::HostNotInShareGroup {
        tenant: TenantUserName::from("dev"),
        host: HostUserName::from("operator"),
        group: "dev-tenant-share".into(),
    };
    assert_eq!(
        format!("{f}"),
        "warning: host 'operator' is not a member of group 'dev-tenant-share' \u{2014} \
         files created by tenant 'dev' inside RW shares are not host-writable; \
         run `tenant reload dev` to fix"
    );
}

#[test]
fn finding_host_not_in_share_group_severity_is_warning() {
    let f = Finding::HostNotInShareGroup {
        tenant: TenantUserName::from("dev"),
        host: HostUserName::from("operator"),
        group: "dev-tenant-share".into(),
    };
    assert_eq!(f.severity(), Severity::Warning);
}

// ============================================================
// Finding::TenantKeychainAbsent — Display + severity + guidance
// ============================================================
//
// Tenant's `login.keychain-db` is absent on disk. Warning-tier
// because the tenant can still function for non-keychain operations;
// the drift signals "OAuth-class apps will break".

#[test]
fn finding_display_tenant_keychain_absent() {
    let f = Finding::TenantKeychainAbsent {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' login keychain absent \u{2014} \
         apps inside the tenant won't be able to persist credentials"
    );
}

#[test]
fn finding_tenant_keychain_absent_severity_is_warning() {
    let f = Finding::TenantKeychainAbsent {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(f.severity(), Severity::Warning);
}

#[test]
fn guidance_tenant_keychain_absent_byte_form() {
    let f = Finding::TenantKeychainAbsent {
        tenant: TenantUserName::from("dev"),
    };
    let expected = "Why this matters
  Tenant 'dev's login keychain at /Users/dev/Library/Keychains/login.keychain-db
  is absent. Claude OAuth and other credential-stashing apps running
  inside the tenant fire `errSecNoSuchKeychain` warnings and have no
  persistent place to write tokens \u{2014} every login interaction
  re-prompts because nothing survives across sessions. The most common
  causes are a manual `rm` against the tenant's Library/Keychains
  directory, or a partial-create that left the file off disk.

Recommended fix
  tenant destroy dev && tenant create dev
  Re-bootstraps the tenant from scratch: the destroy moves the home to
  /Users/Deleted Users/, the create runs the 4-step keychain provision
  sequence cleanly. Idempotent at the substrate (destroy converges on
  absent tenants; create runs `security create-keychain` with the
  duplicate-keychain escape hatch).

Side-effects to know about
  \u{2022} Any tenant-side state in /Users/dev/ moves to
    /Users/Deleted Users/dev/ (recoverable until the host empties
    /Users/Deleted Users or the host is rebuilt).
  \u{2022} A fresh keychain password is generated and stashed in the
    operator's keychain; the prior password (if any) is discarded.
  \u{2022} Any apps the tenant had open with the old keychain attached
    will lose their reference; restart them after the re-create.

Alternative
  sudo -iu dev security create-keychain -p <password> login.keychain-db
  Manually re-create the keychain, then run the 3 follow-up `security`
  sub-steps (`default-keychain -s`, `list-keychains -s`,
  `set-keychain-settings`) and `security add-generic-password -a dev
  -s tenant-dev -w <password>` against the operator's keychain to
  re-stash. Tedious; the full destroy + create path is faster and
  matches the substrate the create flow runs.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

// ============================================================
// Finding::StashAbsent — Display + severity + guidance
// ============================================================

#[test]
fn finding_display_stash_absent() {
    let f = Finding::StashAbsent {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(
        format!("{f}"),
        "warning: stashed password absent for tenant 'dev' \u{2014} \
         a future `tenant shell` unlock pass would have nothing to retrieve; \
         run `tenant destroy dev && tenant create dev` to re-bootstrap"
    );
}

#[test]
fn finding_stash_absent_severity_is_warning() {
    let f = Finding::StashAbsent {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(f.severity(), Severity::Warning);
}

#[test]
fn guidance_stash_absent_byte_form() {
    let f = Finding::StashAbsent {
        tenant: TenantUserName::from("dev"),
    };
    let expected = "Why this matters
  The operator's login keychain doesn't carry a generic-password entry
  under (account=dev, service=tenant-dev). A future shell-
  entry unlock pass would read from that entry to retrieve the
  password that protects the tenant's `login.keychain-db`; without
  the stash, post-reboot the tenant's keychain stays locked and OAuth
  tokens it carries become unreachable. The most common cause is a
  manual `security delete-generic-password` run against the operator's
  keychain, or a partial-create that landed the keychain but missed
  the stash.

Recommended fix
  tenant destroy dev && tenant create dev
  Re-bootstraps both the tenant keychain AND the operator-side stash
  with a fresh shared password. The destroy converges on the
  pre-existing tenant; the create generates a new password, writes it
  to the tenant keychain, and stashes the same bytes in the operator's
  keychain.

Side-effects to know about
  \u{2022} Any tenant-side state in /Users/dev/ moves to
    /Users/Deleted Users/dev/ (recoverable until the host empties
    /Users/Deleted Users or the host is rebuilt).
  \u{2022} The new keychain password is unrelated to any previously-used
    password \u{2014} apps that cached the old one will need re-auth.

Alternative
  In practice, none. The password was never written outside the
  operator's keychain by design, so it can't be recovered after the
  stash is gone. If the tenant's keychain happens to still be unlocked
  and the operator can somehow reproduce the password (e.g. it was
  captured to a password manager out-of-band), they could
  `security add-generic-password -a dev -s tenant-dev -w
  <recovered-password>` to re-stash. Without that, `destroy && create`
  is the only path.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

#[test]
fn guidance_host_not_in_share_group_byte_form() {
    let f = Finding::HostNotInShareGroup {
        tenant: TenantUserName::from("dev"),
        host: HostUserName::from("operator"),
        group: "dev-tenant-share".into(),
    };
    let expected = "Why this matters
  Host 'operator' is not a member of 'dev-tenant-share'. The share substrate
  installs an inheritable ACL on every declared `host_path` granting
  `dev-tenant-share` access \u{2014} the tenant (whose primary group IS `dev-tenant-share`)
  inherits that grant on any new file they create inside an RW share.
  The host inherits it ONLY if also a member of `dev-tenant-share`. Without
  the membership, files the tenant creates inside RW shares are
  world-readable (POSIX 644) but not host-writable: host can `ls`
  and `cat` but `vim` reports `E212: Can't open file for writing`.
  Legacy tenants (created before host membership was wired into the
  create flow) all hit this; manual `dseditgroup -o edit -d operator
  dev-tenant-share` on a newer tenant also surfaces here.

Recommended fix
  tenant reload dev
  The catch-up path runs `dseditgroup -o edit -a operator -t user
  dev-tenant-share` as the first step inside `execute_reapply_plan`.
  Idempotent at the substrate \u{2014} re-applying on an existing
  member is a silent noop.

Side-effects to know about
  \u{2022} 'operator' gains a secondary group membership. `id` and
    `groups` start listing `dev-tenant-share`; processes the host runs inherit
    it on new files and directories they create. On solo-Mac scope
    this is intended; if multiple human users share the host, only
    the operator running `tenant reload` gets added.
  \u{2022} The PF anchor is re-rendered at runtime tier as a side effect.
    If install-tier widening was active, the narrow drops it; rerun
    `tenant mode dev install` afterward if still needed.
  \u{2022} Every declared share is also re-applied. If another share has
    an unrelated pending refusal, reload aborts before reaching this
    step; address those first.

Alternative
  sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share
  Adds just the membership without running the full reload. Use when
  `tenant reload` is blocked by an unrelated refusal.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}
