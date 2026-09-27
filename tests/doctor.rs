//! Unit tests: `doctor`'s pure functions have small combinatorial state spaces.

use std::path::PathBuf;

use tenant::doctor::{
    Category, Finding, Severity, SymlinkActual, anchor_body_matches, classify,
    classify_egress_resolve_drift, classify_inbound_exposure, curated_paths,
    entries_missing_group_ace,
};
use tenant::domain::{AccessMode, AccessOutcome, GroupId, HostUserName, TenantUserName};
use tenant::profile::{Inbound, InboundPosture};

// --- Finding display ---

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

// --- classify: only `Allowed` ever produces a finding ---

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
    // Anchors are 0644 by design: the exposure is intentional, so info rather than critical.
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

// --- curated_paths ---

#[test]
fn curated_paths_covers_host_secret_paths() {
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

// --- anchor_body_matches (byte-exact: the render is deterministic) ---

#[test]
fn anchor_body_matches_equal_strings_true() {
    let body = "# PF anchor for tenant 'dev'\nblock return inet from any to any\n";
    assert!(anchor_body_matches(body, body));
}

#[test]
fn anchor_body_matches_extra_trailing_newline_false() {
    let actual = "block return inet from any to any\n";
    let expected = "block return inet from any to any\n\n";
    assert!(!anchor_body_matches(actual, expected));
}

#[test]
fn anchor_body_matches_empty_strings_true() {
    assert!(anchor_body_matches("", ""));
}

// --- Finding::AnchorBodyDrift ---

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

// --- Finding::InboundExposure / InboundPermissive ---

#[test]
fn finding_display_inbound_exposure_single_port() {
    let f = Finding::InboundExposure {
        tenant: TenantUserName::from("dev"),
        ports: vec![3000],
    };
    assert_eq!(
        format!("{f}"),
        "info: tenant 'dev' inbound loopback open on port 3000 \u{2014} \
         reachable by host + peer tenants"
    );
}

#[test]
fn finding_display_inbound_exposure_multi_port() {
    let f = Finding::InboundExposure {
        tenant: TenantUserName::from("dev"),
        ports: vec![3000, 8080],
    };
    assert_eq!(
        format!("{f}"),
        "info: tenant 'dev' inbound loopback open on ports 3000, 8080 \u{2014} \
         reachable by host + peer tenants"
    );
}

#[test]
fn finding_inbound_exposure_severity_is_info() {
    let f = Finding::InboundExposure {
        tenant: TenantUserName::from("dev"),
        ports: vec![3000],
    };
    assert_eq!(f.severity(), Severity::Info);
}

#[test]
fn finding_display_inbound_permissive() {
    let f = Finding::InboundPermissive {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' inbound loopback is PERMISSIVE \u{2014} \
         all ports open to host + peer tenants; \
         run `tenant inbound dev restricted` to narrow"
    );
}

#[test]
fn finding_inbound_permissive_severity_is_warning() {
    let f = Finding::InboundPermissive {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(f.severity(), Severity::Warning);
}

// --- classify_inbound_exposure: permissive wins, else declared ports → Info, else None ---

#[test]
fn classify_inbound_permissive_wins_over_declared_ports() {
    let f = classify_inbound_exposure(
        &TenantUserName::from("dev"),
        &Inbound {
            ports: vec![3000],
            ..Inbound::default()
        },
        true,
    );
    assert_eq!(
        f,
        Some(Finding::InboundPermissive {
            tenant: TenantUserName::from("dev"),
        })
    );
}

#[test]
fn classify_inbound_permissive_with_no_declared_ports() {
    let f = classify_inbound_exposure(
        &TenantUserName::from("dev"),
        &Inbound {
            ports: vec![],
            ..Inbound::default()
        },
        true,
    );
    assert_eq!(
        f,
        Some(Finding::InboundPermissive {
            tenant: TenantUserName::from("dev"),
        })
    );
}

#[test]
fn classify_inbound_restricted_with_ports_is_info() {
    let f = classify_inbound_exposure(
        &TenantUserName::from("dev"),
        &Inbound {
            ports: vec![3000, 8080],
            ..Inbound::default()
        },
        false,
    );
    assert_eq!(
        f,
        Some(Finding::InboundExposure {
            tenant: TenantUserName::from("dev"),
            ports: vec![3000, 8080],
        })
    );
}

#[test]
fn classify_inbound_locked_is_no_finding() {
    let f = classify_inbound_exposure(
        &TenantUserName::from("dev"),
        &Inbound {
            ports: vec![],
            ..Inbound::default()
        },
        false,
    );
    assert_eq!(f, None);
}

// --- Finding::guidance ---

#[test]
fn guidance_filesystem_exposure_returns_none() {
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
fn guidance_inbound_exposure_byte_form() {
    let f = Finding::InboundExposure {
        tenant: TenantUserName::from("dev"),
        ports: vec![3000, 8080],
    };
    let expected = "Why this matters
  Tenant 'dev's profile declares inbound loopback ports 3000, 8080, so
  the anchor passes loopback TCP to those ports. This is intended
  surface \u{2014} a tenant-local service (a dev web server, an OAuth
  redirect target) needs them open. But restricted is SURFACE-REDUCTION,
  NOT host-vs-peer isolation: a declared port is reachable by the host
  AND by every peer tenant, because pf cannot see the initiator across
  the shared 127.0.0.1 loopback. Treat a declared port as open to the
  whole machine, not just this tenant.

Recommended fix
  Nothing to fix \u{2014} this is informational. If a port no longer needs to
  be reachable, remove it from the `[inbound]` ports list in the profile
  and run `tenant reload dev` to re-render the anchor at the narrowed
  surface.

Side-effects to know about
  \u{2022} Removing a declared port narrows the surface but also blocks the
    tenant from reaching its OWN service on that port \u{2014} a tenant
    cannot reach an undeclared loopback port. Re-declare it if the
    tenant-local flow breaks.
  \u{2022} UDP loopback is unfiltered (TCP only); a UDP service on any port
    stays reachable regardless of this list.

Alternative
  tenant inbound dev permissive
  Temporarily opens ALL loopback ports for an ad-hoc flow (e.g. OAuth on
  a random port). Narrows back on `tenant inbound dev restricted` or on
  `tenant shell dev` entry. Prefer declaring the specific port over a
  blanket widen when the port is known.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

#[test]
fn guidance_inbound_permissive_byte_form() {
    let f = Finding::InboundPermissive {
        tenant: TenantUserName::from("dev"),
    };
    let expected = "Why this matters
  Tenant 'dev's anchor is in the PERMISSIVE inbound posture: every
  loopback TCP port is open, not just the profile-declared ones.
  Permissive is meant to be temporary \u{2014} the OAuth-on-a-random-port
  window \u{2014} and normally narrows back automatically on `tenant shell`
  entry. Finding it permissive outside a live shell session means a
  prior widen was left behind: every loopback port the tenant binds is
  reachable by the host AND by every peer tenant (pf can't see the
  initiator across shared 127.0.0.1).

Recommended fix
  tenant inbound dev restricted
  Re-renders the anchor at the restricted posture (profile-declared
  ports only, or locked if none) and reloads pf, dropping the
  all-ports inbound pass.

Side-effects to know about
  \u{2022} The pfctl reload causes a sub-millisecond packet-filter disruption.
  \u{2022} Any tenant-local service listening on a non-declared loopback port
    stops being reachable once narrowed \u{2014} declare the port in the
    profile's `[inbound]` list if the flow must persist.
  \u{2022} `tenant shell dev` also auto-narrows inbound on entry, so the next
    interactive session would have corrected this on its own.

Alternative
  Re-render via any reapply verb
  `tenant reload dev`, `tenant mode dev runtime`, or entering
  `tenant shell dev` all re-render the anchor at steady inbound
  (restricted), narrowing the same way. Use `tenant inbound` when the
  ONLY change needed is the inbound narrow.";
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
fn finding_display_env_leak() {
    let f = Finding::EnvLeak {
        var: "SSH_AUTH_SOCK".to_string(),
    };
    assert_eq!(
        format!("{f}"),
        "warning: SSH_AUTH_SOCK not in env_delete \u{2014} host's session env leaks into 'tenant shell' sessions; \
         add `Defaults env_delete += \"SSH_AUTH_SOCK\"` to /etc/sudoers.d/tenant \
         (/etc/sudoers is replaced by macOS updates)"
    );
}

#[test]
fn guidance_env_leak_byte_form() {
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
    let f = Finding::TouchIdMissing;
    let expected = "Why this matters
  Neither /etc/pam.d/sudo nor /etc/pam.d/sudo_local enables Touch ID for
  sudo. This isn't a correctness drift \u{2014} sudo still works via password
  \u{2014} it's an optional recommendation aligned with the project's locked
  no-NOPASSWD-sudoers stance. Touch ID makes sudo prompts faster (a
  fingerprint beats typing a password) AND adds a second auth factor
  (fingerprint plus sudoers membership) instead of just one (sudoers
  membership). Info-tier because absence doesn't compromise isolation,
  and declining is a valid choice \u{2014} this is an offer, not a defect.

Recommended fix
  tenant setup
  Offers to append `auth sufficient pam_tid.so` to /etc/pam.d/sudo_local
  \u{2014} the OS-update-safe customization file that /etc/pam.d/sudo
  includes (editing /etc/pam.d/sudo directly is clobbered by macOS
  updates). `sufficient` short-circuits the auth stack on a Touch ID
  hit and falls through to password on a miss. You'll be asked for your
  password once to apply it (Touch ID isn't on yet).

Side-effects to know about
  \u{2022} Next sudo invocation pops a Touch ID prompt instead of (or
    before) the password prompt. Touch your sensor within ~10 seconds.
  \u{2022} If Touch ID hardware isn't available or isn't registered (System
    Settings \u{2192} Touch ID & Password), pam_tid.so falls through to the
    next module \u{2014} sudo still works, just without the short-circuit.
  \u{2022} Inside tmux or screen, the Touch ID prompt won't appear without
    the third-party pam_reattach module.

Alternative
  Ignore this finding if you prefer typing your password. It stays an
  info-tier note, never trips `--strict`, and `tenant setup` will offer
  again whenever you change your mind.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

// --- Severity ordering (load-bearing for --strict) ---

#[test]
fn severity_ordering_critical_max() {
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

// --- Finding::AclDrift ---

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

// --- Finding::CoworkAclDrift ---

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

// --- Finding::CoworkDirAbsent ---

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

// --- Finding::SymlinkDrift ---

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

// --- Finding::HostNotInShareGroup ---

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

// --- Finding::TenantKeychainAbsent ---

#[test]
fn finding_display_tenant_keychain_absent() {
    let f = Finding::TenantKeychainAbsent {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' keychain absent \u{2014} \
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
  Tenant 'dev's keychain at /Users/dev/Library/Keychains/tenant.keychain-db
  is absent. Claude OAuth and other credential-stashing apps running
  inside the tenant fire `errSecNoSuchKeychain` warnings and have no
  persistent place to write tokens \u{2014} every login interaction
  re-prompts because nothing survives across sessions. The most common
  causes are a tenant created before the keychain moved off the
  `login.keychain-db` name (macOS 26.6 binds that name to the user's
  Data Protection keybag and refuses unlocks from the operator's
  session), a manual `rm` against the tenant's Library/Keychains
  directory, or a partial-create that left the file off disk.

Recommended fix
  sudo -iu dev security create-keychain -p \"$(security find-generic-password -a dev -s tenant-dev -w)\" tenant.keychain-db
  sudo -iu dev security default-keychain -s tenant.keychain-db
  sudo -iu dev security list-keychains -s tenant.keychain-db
  sudo -iu dev security set-keychain-settings tenant.keychain-db
  Creates the keychain keyed to the password already stashed in the
  operator's keychain, makes it the tenant's default and sole
  search-list entry, and clears auto-lock \u{2014} the same four steps
  `tenant create` runs, without touching the tenant's home. Step one
  fails if the stash is absent; doctor reports that separately and
  the alternative below covers it.

Side-effects to know about
  \u{2022} The new keychain starts empty: apps inside the tenant
    re-authenticate once. Anything stored in a pre-26.6
    `login.keychain-db` stays in that file, unused.
  \u{2022} The password is on the command line for the duration of step
    one \u{2014} the same exposure `tenant create` has today.

Alternative
  tenant destroy dev && tenant create dev
  Re-bootstraps the tenant from scratch with a fresh password and
  stash. Moves the tenant's home to /Users/Deleted Users/dev/;
  use it when the stash is gone too.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

// --- Finding::StashAbsent ---

#[test]
fn finding_display_stash_absent() {
    let f = Finding::StashAbsent {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(
        format!("{f}"),
        "warning: stashed password absent for tenant 'dev' \u{2014} \
         `tenant shell` and `tenant bootstrap` can't unlock the keychain without it; \
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
  under (account=dev, service=tenant-dev). `tenant shell` and
  `tenant bootstrap` read that entry to retrieve the password that
  protects the tenant's `tenant.keychain-db`; without the stash they
  refuse to enter, and after a reboot the tenant's keychain stays
  locked so OAuth tokens it carries become unreachable. The most
  common cause is a manual `security delete-generic-password` run
  against the operator's keychain, or a partial-create that landed
  the keychain but missed the stash.

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

// --- Finding::PfConfAnchorRefMissing ---

#[test]
fn finding_display_pf_conf_anchor_ref_missing() {
    let f = Finding::PfConfAnchorRefMissing {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(
        format!("{f}"),
        "critical: tenant 'dev' anchor not referenced from /etc/pf.conf \u{2014} \
         its egress allowlist is not loaded; run `tenant reload dev` to restore the reference"
    );
}

#[test]
fn finding_pf_conf_anchor_ref_missing_severity_is_critical() {
    let f = Finding::PfConfAnchorRefMissing {
        tenant: TenantUserName::from("dev"),
    };
    assert_eq!(f.severity(), Severity::Critical);
}

#[test]
fn guidance_pf_conf_anchor_ref_missing_byte_form() {
    let f = Finding::PfConfAnchorRefMissing {
        tenant: TenantUserName::from("dev"),
    };
    let expected = "Why this matters
  /etc/pf.conf carries no `anchor \"tenant-dev\"` / `load anchor` pair,
  so pf never loads /etc/pf.anchors/tenant-dev. The tenant's egress
  allowlist and inbound rules are not enforcing anything \u{2014} the anchor
  file on disk may be perfect and it makes no difference. The usual
  cause is a macOS update: it replaces /etc/pf.conf with Apple's stock
  file, and every tenant loses its reference at once. A reload that ran
  since reported success while loading a file that never named the
  tenant.

Recommended fix
  tenant reload dev
  Re-adds the two lines, re-renders the anchor, and reloads pf. `tenant
  mode` and `tenant shell` do the same on their way in.

Side-effects to know about
  \u{2022} None beyond the reload itself; the added lines are the ones `tenant
    create` writes.
  \u{2022} Do not restore /etc/pf.conf.tenant-backup: it is the rollback
    snapshot from the last create or destroy and omits every tenant
    created since. `tenant reload` rebuilds from the live tenant set.
  \u{2022} While the reference is missing, doctor skips this tenant's
    kernel-rule checks \u{2014} an empty kernel anchor is this finding's
    consequence, not a second problem.

Alternative
  tenant reload
  Without a name, repairs every tenant: after an update it is rarely
  just one. For a scheduled check, `tenant doctor --strict` exits 2 on
  this finding.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

// --- Finding::PrimaryGroupDrift ---

#[test]
fn finding_display_primary_group_drift() {
    let f = Finding::PrimaryGroupDrift {
        tenant: TenantUserName::from("dev"),
        expected: GroupId(612),
        actual: GroupId(601),
    };
    assert_eq!(
        format!("{f}"),
        "critical: tenant 'dev' primary group is gid 601, not dev-tenant-share (612) \u{2014} \
         the tenant has joined another group and left its share group; \
         run `tenant reload dev` to re-assert"
    );
}

#[test]
fn finding_primary_group_drift_severity_is_critical() {
    let f = Finding::PrimaryGroupDrift {
        tenant: TenantUserName::from("dev"),
        expected: GroupId(612),
        actual: GroupId(601),
    };
    assert_eq!(f.severity(), Severity::Critical);
}

#[test]
fn guidance_primary_group_drift_byte_form() {
    let f = Finding::PrimaryGroupDrift {
        tenant: TenantUserName::from("dev"),
        expected: GroupId(612),
        actual: GroupId(601),
    };
    let expected = "Why this matters
  Tenant 'dev' was created with primary group dev-tenant-share (612);
  its record now says 601. When that is 20 (staff) \u{2014} the value macOS
  updates write back \u{2014} the tenant gains group access to every staff-group
  directory on the host, including /Users/<operator> (mode 750, group
  staff), and stops being a member of dev-tenant-share, so every declared share
  denies it. The isolation the tenant depends on is inverted, not just
  weakened. Cause on record: the update's templateMigrator re-creating
  local user records at first boot.

Recommended fix
  tenant reload dev
  Full reapply re-asserts the primary group from the live share-group
  record, then reapplies shares. Processes already running as the tenant
  keep their old group set until they restart.

Side-effects to know about
  \u{2022} Group caches may lag: `sudo dsmemberutil flushcache` if a share still
    denies after the reload.

Alternative
  sudo dscl . -create /Users/dev PrimaryGroupID 612
  The single write reload performs; skips the share reapply.";
    assert_eq!(f.guidance().as_deref(), Some(expected));
}

#[test]
fn classify_permissive_anchor_on_permissive_profile_is_info() {
    let inbound = Inbound {
        ports: vec![],
        posture: InboundPosture::Permissive,
    };
    let f = classify_inbound_exposure(&TenantUserName::from("dev"), &inbound, true).unwrap();
    assert_eq!(
        f,
        Finding::InboundPermissiveByProfile {
            tenant: TenantUserName::from("dev"),
        }
    );
    assert_eq!(f.severity(), Severity::Info);
    assert_eq!(
        format!("{f}"),
        "info: tenant 'dev' inbound posture is permissive (profile) \u{2014} \
         every loopback port the tenant opens is reachable by host + peer tenants"
    );
}

// --- classify_egress_resolve_drift: resolved addresses vs the live `pfctl -T show` table ---

fn ips(list: &[&str]) -> Vec<std::net::IpAddr> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

const LOADED_TABLE: &str = "   142.250.137.93\n   10.0.0.0/8\n   2001:db8::/32\n";

#[test]
fn egress_resolve_drift_none_when_every_address_is_loaded_or_covered() {
    let resolved = ips(&["142.250.137.93", "10.1.2.3", "2001:db8::1"]);
    let f = classify_egress_resolve_drift(
        &TenantUserName::from("dev"),
        "dl.google.com",
        &resolved,
        LOADED_TABLE,
    );
    assert_eq!(f, None);
}

#[test]
fn egress_resolve_drift_names_only_unloaded_addresses() {
    let resolved = ips(&["142.250.137.93", "142.250.139.7", "2001:db9::1"]);
    let f = classify_egress_resolve_drift(
        &TenantUserName::from("dev"),
        "dl.google.com",
        &resolved,
        LOADED_TABLE,
    )
    .unwrap();
    assert_eq!(
        f,
        Finding::EgressResolveDrift {
            tenant: TenantUserName::from("dev"),
            host: "dl.google.com".to_string(),
            unloaded: ips(&["142.250.139.7", "2001:db9::1"]),
        }
    );
    assert_eq!(f.severity(), Severity::Warning);
    assert_eq!(
        format!("{f}"),
        "warning: tenant 'dev' egress host dl.google.com now resolves to 142.250.139.7, \
         2001:db9::1, outside the loaded pf table \u{2014} CDN-backed? pin its CIDR ranges \
         (see `tenant help profile`), or `tenant reload dev` to re-resolve"
    );
}

#[test]
fn egress_resolve_drift_none_when_nothing_resolved() {
    let f = classify_egress_resolve_drift(
        &TenantUserName::from("dev"),
        "gone.example",
        &[],
        LOADED_TABLE,
    );
    assert_eq!(f, None);
}

// --- entries_missing_group_ace: `ls -leRA <root>` → descendants without the share-group ACE ---

const ACL_TREE: &str = "total 0
drwxrwx---+ 3 alice  dev-tenant-share  96 Sep 26 10:00 app
 0: group:dev-tenant-share inherited allow list,add_file,search,file_inherit,directory_inherit
-rw-r--r--  1 dev    staff             0 Sep 26 10:01 moved  in.txt
-rw-rw----+ 1 dev    staff             0 Sep 26 10:01 direct.txt
 0: group:dev-tenant-share allow read,write
lrwxr-xr-x  1 dev    staff             4 Sep 26 10:01 link -> app

/Users/Shared/tenants/dev/app:
total 0
drwxr-xr-x+ 2 dev  staff  64 Sep 26  2025 build
 0: group:other-tenant-share inherited allow list
";

#[test]
fn acl_tree_lists_entries_without_the_group_ace_skipping_symlinks() {
    assert_eq!(
        entries_missing_group_ace(
            ACL_TREE,
            std::path::Path::new("/Users/Shared/tenants/dev"),
            "dev-tenant-share"
        ),
        vec![
            PathBuf::from("/Users/Shared/tenants/dev/moved  in.txt"),
            PathBuf::from("/Users/Shared/tenants/dev/app/build"),
        ]
    );
}

#[test]
fn acl_tree_empty_listing_has_no_drift() {
    assert!(
        entries_missing_group_ace("", std::path::Path::new("/x"), "dev-tenant-share").is_empty()
    );
}
