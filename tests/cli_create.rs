use std::path::PathBuf;

use tenant::adapters::stub_host_accounts::StubHostAccounts;
use tenant::domain::{GroupId, UserId};
use tenant::executor::{
    AccountError, AccountOp, AclMode, AclOp, FirewallError, ProfileOp, StubExecutor,
};

mod common;
use common::*;

#[test]
fn create_dry_run_default_shows_intent() {
    let (code, stdout, stderr) =
        run_with(StubHostAccounts::default(), &["create", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
}

#[test]
fn create_accepts_max_length_name() {
    let name = "a".repeat(31);
    let (code, stdout, stderr) =
        run_with(StubHostAccounts::default(), &["create", &name, "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block(&name, 600, 600, None));
}

#[test]
fn create_accepts_single_letter_name() {
    let (code, stdout, stderr) =
        run_with(StubHostAccounts::default(), &["create", "x", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("x", 600, 600, None));
}

#[test]
fn verbose_shows_floor_uid_and_gid_when_neither_in_use() {
    // Phase 3 changes the plan from one argv to three: dseditgroup-create
    // (group-first so the user's home directory lands on the tenant-share
    // group, not staff), sysadminctl-addUser (pointing -GID at the just-
    // created group), and an unconditional `# on rollback` line that
    // documents what happens if sysadminctl fails after the group was
    // created. The rollback line is in the plan but not in the `$` echo
    // block — that asymmetry is the operator-visible signal of whether
    // the rollback fired (mirrors the destroy-side dscl-cleanup
    // convention shipped in V1.8). UID and GID allocators are decoupled
    // post-Phase-3 but both happen to bottom-out at TENANT_UID_FLOOR=600
    // when both spaces are empty.
    let (code, stdout, _stderr) = run_with(
        StubHostAccounts::default(),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    // The verbose plan section lives inside the summary (between
    // the bullets and "Sudo needed for:"), rendered in
    // intent-leads-shell-follows layout via `create_verbose_plan_block`.
    let plan = create_verbose_plan_block("dev", 600, 600);
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, Some(&plan)));
}

/// Stub whose `used_uids()` reports the given UIDs as taken (by synthetic
/// user names that no test asserts about). Used by allocator-driven tests.
fn stub_with_used_uids(uids: &[u32]) -> StubHostAccounts {
    StubHostAccounts {
        uid_by_name: uids
            .iter()
            .enumerate()
            .map(|(i, &u)| (format!("u{i}"), UserId(u)))
            .collect(),
        ..Default::default()
    }
}

#[test]
fn verbose_shows_lowest_free_uid_with_gap_and_gid_at_floor() {
    // First decoupled-allocation evidence: UID space has a gap so the
    // allocator returns 602, but the GID space is empty (stub_with_used_uids
    // only populates uid_by_name, leaving gid_by_name empty) so the GID
    // allocator returns 600. Phase 3 explicitly does NOT force UID == GID
    // — the two allocators consult their own spaces and may diverge.
    let (code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[600, 601, 603]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert_eq!(code, 0);
    let plan = create_verbose_plan_block("dev", 602, 600);
    assert_eq!(stdout, create_dry_run_block("dev", 602, 600, Some(&plan)));
}

#[test]
fn verbose_uid_skips_taken_floor_gid_stays_at_floor() {
    // UID 600 taken, GID space empty → UID 601, GID 600. Pins the new
    // decoupled-allocator semantics on the boundary: a single taken UID
    // doesn't drag the GID allocator with it.
    let (_code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[600]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert!(
        stdout.contains("-UID 601 -GID 600"),
        "expected '-UID 601 -GID 600' in stdout, got: {stdout:?}",
    );
}

#[test]
fn verbose_uid_independent_of_input_order() {
    // UIDs 600, 601, 603 taken (any input order) → UID 602; GID space empty → GID 600.
    let (_code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[603, 600, 601]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert!(
        stdout.contains("-UID 602 -GID 600"),
        "expected '-UID 602 -GID 600' in stdout, got: {stdout:?}",
    );
}

#[test]
fn verbose_skips_uids_below_floor() {
    // UIDs below the floor (500, 599) don't constrain the allocator; both
    // allocators bottom-out at the floor.
    let (_code, stdout, _stderr) = run_with(
        stub_with_used_uids(&[500, 599]),
        &["create", "dev", "--dry-run", "-v"],
    );
    assert!(
        stdout.contains("-UID 600 -GID 600"),
        "expected '-UID 600 -GID 600' in stdout, got: {stdout:?}",
    );
}

#[test]
fn verbose_gid_skips_taken_floor_uid_stays_at_floor() {
    // Mirror twin of `verbose_uid_skips_taken_floor_gid_stays_at_floor`:
    // empty UID space + GID 600 taken (an unrelated group at the floor) →
    // UID 600, GID 601. The dseditgroup `-i` value tracks the GID
    // allocator, not the UID allocator — the literal argument is the
    // load-bearing thing tenant passes to dseditgroup, so a regression
    // that wires `-i` to `uid` would slip past UID-only tests but trips
    // here.
    let stub = StubHostAccounts {
        groups: vec!["other".to_string()],
        gid_by_name: [("other".to_string(), GroupId(600))].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let plan = create_verbose_plan_block("dev", 600, 601);
    assert_eq!(stdout, create_dry_run_block("dev", 600, 601, Some(&plan)));
}

#[test]
fn verbose_uid_and_gid_allocators_cross_over() {
    // Crossover stub: UID space has the floor (600) taken; GID space has
    // 601 taken. UID allocator climbs to 601 (lowest free above the
    // floor); GID allocator stays at 600 (still free in its space). The
    // resulting argv carries `-UID 601 -GID 600` — a *crossover* between
    // the two spaces that's impossible if the two allocators are fused.
    // The strongest single-test defense against a regression that
    // wires `-i` and `-GID` to `lowest_free_uid` instead of
    // `lowest_free_gid`.
    let stub = StubHostAccounts {
        users: vec!["legacy".to_string()],
        uid_by_name: [("legacy".to_string(), UserId(600))].into_iter().collect(),
        groups: vec!["phantom".to_string()],
        gid_by_name: [("phantom".to_string(), GroupId(601))]
            .into_iter()
            .collect(),
    };
    let (code, stdout, _stderr) = run_with(stub, &["create", "dev", "--dry-run", "-v"]);
    assert_eq!(code, 0);
    let plan = create_verbose_plan_block("dev", 601, 600);
    assert_eq!(stdout, create_dry_run_block("dev", 601, 600, Some(&plan)));
}

#[test]
fn create_rejects_empty_name() {
    let (code, stdout, stderr) =
        run_with(StubHostAccounts::default(), &["create", "", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: name cannot be empty\n");
}

#[test]
fn create_rejects_non_letter_start() {
    for (name, offender) in [("1dev", '1'), ("_dev", '_'), ("Dev", 'D')] {
        let (code, stdout, stderr) =
            run_with(StubHostAccounts::default(), &["create", name, "--dry-run"]);
        assert_eq!(code, 64, "want EX_USAGE for {name:?}");
        assert!(
            stdout.is_empty(),
            "stdout should be empty for {name:?}: {stdout:?}"
        );
        let want = format!(
            "tenant: name '{name}' must start with a lowercase letter (got '{offender}')\n"
        );
        assert_eq!(stderr, want, "stderr mismatch for {name:?}");
    }
}

#[test]
fn create_rejects_invalid_character() {
    for (name, offender) in [("de v", ' '), ("de@v", '@'), ("dev.", '.')] {
        let (code, stdout, stderr) =
            run_with(StubHostAccounts::default(), &["create", name, "--dry-run"]);
        assert_eq!(code, 64, "want EX_USAGE for {name:?}");
        assert!(
            stdout.is_empty(),
            "stdout should be empty for {name:?}: {stdout:?}"
        );
        let want = format!("tenant: name '{name}' contains invalid character '{offender}'\n");
        assert_eq!(stderr, want, "stderr mismatch for {name:?}");
    }
}

#[test]
fn create_rejects_overlong_name() {
    let name = "a".repeat(32);
    let (code, stdout, stderr) =
        run_with(StubHostAccounts::default(), &["create", &name, "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        format!("tenant: name '{name}' is too long (32 characters; maximum is 31)\n"),
    );
}

#[test]
fn create_rejects_reserved_names() {
    // Lexical blocklist on top of charset rules: even though these names
    // all pass `[a-z][a-z0-9_-]*`, they're reserved as macOS system /
    // role names and would either alias a real account (`root`, `nobody`)
    // or carry semantics we don't want a tenant to inherit (`wheel`,
    // `staff`, `sudo`). Copied verbatim from the sandbox plugin's
    // `scripts/lib/naming.py` reserved set — see CLAUDE.md cross-reference.
    for name in [
        "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
    ] {
        let (code, stdout, stderr) =
            run_with(StubHostAccounts::default(), &["create", name, "--dry-run"]);
        assert_eq!(code, 64, "want EX_USAGE for {name:?}");
        assert!(
            stdout.is_empty(),
            "stdout should be empty for {name:?}: {stdout:?}"
        );
        let want = format!("tenant: name '{name}' is reserved (matches a system or role name)\n");
        assert_eq!(stderr, want, "stderr mismatch for {name:?}");
    }
}

#[test]
fn create_accepts_name_with_reserved_prefix() {
    // Pins exact-match semantics on the blocklist: 'rooty' / 'wheelman'
    // contain reserved names as substrings but are not themselves
    // reserved. A future refactor that swaps `contains` for `starts_with`
    // or vice-versa would silently break this — the test guards the
    // intended behavior.
    for name in ["rooty", "wheelman", "admins", "daemonic"] {
        let (code, stdout, stderr) =
            run_with(StubHostAccounts::default(), &["create", name, "--dry-run"]);
        assert_eq!(code, 0, "want success for {name:?}; stderr={stderr:?}");
        assert_eq!(stdout, create_dry_run_block(name, 600, 600, None));
    }
}

#[test]
fn create_rejects_when_user_exists() {
    let stub = StubHostAccounts {
        users: vec!["dev".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: user 'dev' already exists\n");
}

#[test]
fn create_rejects_when_tenant_share_group_exists() {
    // Phase 3 names the primary group `<name>-tenant-share` (not bare
    // `<name>`). The conflict check now refuses when that suffixed name is
    // already taken, regardless of what the bare-name group looks like.
    let stub = StubHostAccounts {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(stderr, "tenant: group 'dev-tenant-share' already exists\n");
}

#[test]
fn create_rejects_when_user_and_tenant_share_group_exist() {
    // The `Both` arm — user named `dev` AND the suffixed group `dev-tenant-share`
    // both present. The message names both with the literal group name so
    // the operator can find them with `dscl` directly.
    let stub = StubHostAccounts {
        users: vec!["dev".to_string()],
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 64);
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: user 'dev' and group 'dev-tenant-share' already exist\n"
    );
}

#[test]
fn create_accepts_when_bare_name_group_exists_but_not_suffix() {
    // Phase 3 only reserves `<name>-tenant-share` as conflict territory.
    // A pre-existing bare-name group is no longer something tenant creates
    // (sysadminctl is invoked with -GID pointing at the explicit
    // tenant-share group's GID, not asking sysadminctl to mint a new group
    // named after the user) so a bare `dev` group on the host is harmless.
    // Pins the new contract's specificity — a future regression that
    // swaps `has_group("<name>-tenant-share")` for `has_group(name)` (or
    // checks both) would trip this test.
    let stub = StubHostAccounts {
        groups: vec!["dev".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
}

#[test]
fn create_succeeds_when_unrelated_user_exists() {
    let stub = StubHostAccounts {
        users: vec!["ops".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["create", "dev", "--dry-run"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
}

#[test]
fn create_writes_default_profile_to_store() {
    // After a successful real-mode create, the substrate's profile state
    // contains an entry keyed by the tenant name. Content-shape
    // assertion lives in the dedicated TOML test below; this test only
    // pins presence via `StubExecutor::has_profile`.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        exec.has_profile("dev"),
        "expected profile 'dev' to be present after create; state={:?}",
        exec.profile_state()
    );
}

#[test]
fn create_writes_profile_with_correct_toml_shape() {
    // Byte-exact pin on the default profile content. Schema-version
    // floor at 1 (future migrations bump this); two empty allowlist
    // sections matching the shape the PF anchor render reads from.
    // No `[share]` section — that's Claude-Code-specific and out of
    // scope for the generic Rust port.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let state = exec.profile_state();
    let content = state.get("dev").expect("profile 'dev' should be present");
    let want = "schema_version = 1\n\
                \n\
                [allowlist.runtime]\n\
                hosts = []\n\
                \n\
                [allowlist.install]\n\
                hosts = []\n";
    assert_eq!(content, want, "profile content mismatch");
}

#[test]
fn create_dry_run_does_not_write_profile() {
    // Dry-run swap-in of `DryRunExecutor` means the wired `StubExecutor`
    // never receives an `execute_profile` call. Mirrors the
    // `dry_run_bypasses_injected_executor` test for the executor side.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
    assert!(
        !exec.has_profile("dev"),
        "profile should not be written in dry-run; state={:?}",
        exec.profile_state()
    );
}

#[test]
fn create_real_mode_standard_emits_only_post_exec_confirmation() {
    // Standard real mode: section divider + ✓ per substrate step
    // + Done section + single enriched closing line naming UID +
    // GID + anchor. The op order is load-bearing:
    // CreateShareGroup must precede CreateTenantUser so the new
    // user's home directory chowns to `dev-tenant-share` (sysadminctl
    // chowns the home dir to the group named by `-GID` at creation
    // time); this test pins both the order and the operand values via
    // the ✓ stream + `account_ops()` assertions below.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let want = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         ✓ Profile written to ~/.config/tenant/profiles/dev.toml\n\
         ✓ Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         ✓ Updated /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Firewall enabled host-wide\n\
         {}\n\
         Tenant 'dev' ready (UID 600, GID 600, anchor 'tenant-dev').\n",
        section_line("Creating tenant 'dev'"),
        section_line("Done"),
    );
    assert_eq!(stdout, want);
    assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::CreateShareGroup {
                group: "dev-tenant-share".into(),
                gid: GroupId(600)
            },
            AccountOp::AddHostToShareGroup {
                group: "dev-tenant-share".into(),
                host: "operator".into(),
            },
            AccountOp::CreateTenantUser {
                name: "dev".into(),
                uid: UserId(600),
                gid: GroupId(600)
            },
        ],
    );
    assert_eq!(
        exec.profile_ops(),
        vec![ProfileOp::Create { name: "dev".into() }],
    );
}

#[test]
fn create_real_mode_verbose_shows_pre_exec_plan_and_post_exec_uid_gid() {
    // Scripted-real-verbose (TTY=false) drops the verbose plan from
    // output entirely — solo-Mac scope, cleaner log trace. The
    // section divider opens the verb, per-substrate $ echo + ✓
    // progress interleave, then Done section + single enriched
    // closing line. The plan-before-prompt move lives on the TTY
    // path; this test pins the scripted-mode shape.
    let exec = StubExecutor::new();
    let (code, stdout, _stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev", "-v"]);
    assert_eq!(code, 0);
    let want = format!(
        "{}\n\
         $ sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         $ sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         $ sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         $ tee ~/.config/tenant/profiles/dev.toml < default.toml\n\
         ✓ Profile written to ~/.config/tenant/profiles/dev.toml\n\
         $ sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup\n\
         ✓ Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup\n\
         $ sudo tee /etc/pf.anchors/tenant-dev < anchor.body\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-dev\n\
         $ sudo tee /etc/pf.conf < updated.conf\n\
         ✓ Updated /etc/pf.conf\n\
         $ sudo pfctl -f /etc/pf.conf\n\
         ✓ Firewall ruleset reloaded\n\
         $ sudo pfctl -e\n\
         ✓ Firewall enabled host-wide\n\
         {}\n\
         Tenant 'dev' ready (UID 600, GID 600, anchor 'tenant-dev').\n",
        section_line("Creating tenant 'dev'"),
        section_line("Done"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn create_profile_write_failure_surfaces_with_user_and_group_present() {
    // Per the design lock: CreateShareGroup + CreateTenantUser have
    // both succeeded by the time the profile step fires, so a
    // profile-write failure does NOT roll back the user or group.
    // Operator sees an EX_IOERR with the `create_profile_failed` message
    // that names the profile path (so they don't have to grep source).
    // Their recovery is `tenant destroy <name>` — destroy's Destroyable
    // arm cleans up the user+group, and the missing profile case is a
    // successful noop for the profile-rm step.
    let exec = StubExecutor::new().fail_next_profile(tenant::profile::ProfileError {
        message: "disk full".into(),
    });
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    // Pre-failure ✓ stream is operator-visible. The two account ops
    // succeeded; the profile-write substrate failed; no Done section
    // closes the verb. Verb-failure signal is "no Done section +
    // closing line, plus stderr frame".
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ User account 'dev' provisioned (UID 600)\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to write profile '~/.config/tenant/profiles/dev.toml' \
         for 'dev': disk full\n"
    );
    // Three account ops (CreateShareGroup + AddHostToShareGroup +
    // CreateTenantUser) — no rollback, since the locked policy is
    // "leave user+group present on profile failure".
    assert_eq!(
        exec.account_ops().len(),
        3,
        "expected CreateShareGroup + AddHostToShareGroup + CreateTenantUser; no rollback"
    );
    // Profile is absent from the simulated state (the write failed) —
    // pins the fact that the failure is a real failure, not a silent
    // success.
    assert!(
        !exec.has_profile("dev"),
        "profile should be absent after write failure"
    );
}

#[test]
fn dry_run_bypasses_injected_executor() {
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
    assert!(
        exec.account_ops().is_empty() && exec.profile_ops().is_empty(),
        "executor should not be invoked in dry-run mode; account_ops={:?}, profile_ops={:?}",
        exec.account_ops(),
        exec.profile_ops()
    );
}

#[test]
fn create_real_mode_dseditgroup_failure_aborts_before_sysadminctl() {
    // Phase 3 issues two exec calls: dseditgroup-create first, sysadminctl
    // second. `StubExecutor::failing(78)` fails ALL calls, so the first
    // call (dseditgroup-create) trips. The expected behavior is: stop
    // immediately (no sysadminctl, no rollback — there's nothing to roll
    // back because dseditgroup-create itself failed), exit EX_IOERR, and
    // emit the new `create_group_failed` shape that names the group
    // explicitly so the operator knows the user wasn't touched.
    let exec = StubExecutor::new().fail_account_blanket(78, "");
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    // Section divider lands before the substrate fires; the first
    // substrate op fails so no ✓ lines emit. Stdout carries the
    // single section line; failure routes to stderr.
    assert_eq!(
        stdout,
        format!("{}\n", section_line("Creating tenant 'dev'")),
    );
    assert_eq!(
        stderr,
        "tenant: failed to create group 'dev-tenant-share' for 'dev': process exited with code 78\n"
    );
    assert_eq!(
        exec.account_ops().len(),
        1,
        "should abort after CreateShareGroup"
    );
}

#[test]
fn create_add_host_failure_aborts_with_orphan_group_recovery_hint() {
    // Partial-failure: CreateShareGroup succeeded, but the
    // AddHostToShareGroup step failed. The host now carries an
    // orphan share group with no host membership AND no tenant user
    // (because CreateTenantUser never ran). No automatic rollback
    // — surface as CreateError::HostMembership;
    // operator runs `tenant destroy <name>` to converge via the
    // OrphanGroup eligibility arm. The stderr frame names the host
    // AND the recovery command.
    let exec = StubExecutor::new().fail_account_op(
        AccountOp::AddHostToShareGroup {
            group: "dev-tenant-share".into(),
            host: "operator".into(),
        },
        AccountError::NonZero {
            code: 1,
            stderr: "dseditgroup: not authorized\n".into(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to add host 'operator' to group 'dev-tenant-share': \
         process exited with code 1: dseditgroup: not authorized \
         \u{2014} host now has an orphan group; next 'tenant destroy dev' will converge\n"
    );
    // Two account ops attempted: CreateShareGroup (ok) +
    // AddHostToShareGroup (failed). CreateTenantUser never ran.
    assert_eq!(exec.account_ops().len(), 2);
}

#[test]
fn create_sysadminctl_failure_rolls_back_dseditgroup() {
    // The partial-failure case Phase 3 was designed for: CreateShareGroup
    // succeeded, but CreateTenantUser failed. Without rollback the host
    // would carry an orphan `<name>-tenant-share` group with no
    // corresponding user. The writer must invoke a DeleteShareGroup op
    // to converge back to the pre-create state, then surface the
    // *original* user-creation failure as the error (the rollback
    // succeeded so it's not separately reportable). Three account ops
    // in total.
    let exec = StubExecutor::new().fail_account_op(
        AccountOp::CreateTenantUser {
            name: "dev".into(),
            uid: UserId(600),
            gid: GroupId(600),
        },
        AccountError::NonZero {
            code: 78,
            stderr: "sysadminctl: -addUser failed: existing record\n".into(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    // Section + ✓ for the successful CreateShareGroup + ✓ for the
    // successful AddHostToShareGroup + ✓ for the successful rollback
    // DeleteShareGroup. The original CreateTenantUser failure is the
    // one that routes to stderr. The rollback DeleteShareGroup also
    // vanishes the just-added host membership implicitly (no explicit
    // RemoveHost fires on this arm — the group's gone, the membership
    // goes with it).
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ Share group 'dev-tenant-share' removed\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to create 'dev': process exited with code 78: \
         sysadminctl: -addUser failed: existing record\n"
    );
    assert_eq!(
        exec.account_ops(),
        vec![
            AccountOp::CreateShareGroup {
                group: "dev-tenant-share".into(),
                gid: GroupId(600)
            },
            AccountOp::AddHostToShareGroup {
                group: "dev-tenant-share".into(),
                host: "operator".into(),
            },
            AccountOp::CreateTenantUser {
                name: "dev".into(),
                uid: UserId(600),
                gid: GroupId(600)
            },
            AccountOp::DeleteShareGroup {
                group: "dev-tenant-share".into()
            },
        ],
    );
}

#[test]
fn create_real_mode_verbose_shows_rollback_echo() {
    // Scripted-real-verbose (TTY=false) drops the verbose plan from
    // output. The section divider opens, the substrate's $ echo + ✓
    // progress lines interleave through the CreateShareGroup +
    // AddHost + CreateTenantUser steps, then the rollback fires.
    // No Done section + closing line because create failed; stderr
    // carries the original sysadminctl error.
    let exec = StubExecutor::new().fail_account_op(
        AccountOp::CreateTenantUser {
            name: "dev".into(),
            uid: UserId(600),
            gid: GroupId(600),
        },
        AccountError::NonZero {
            code: 78,
            stderr: "sysadminctl: -addUser failed: existing record\n".into(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev", "-v"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    let want_stdout = format!(
        "{}\n\
         $ sudo dseditgroup -o create -n . -i 600 dev-tenant-share\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         $ sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         $ sudo sysadminctl -addUser dev -fullName \"Tenant: dev\" -shell /bin/zsh -UID 600 -GID 600\n\
         $ sudo dseditgroup -o delete -n . dev-tenant-share\n\
         ✓ Share group 'dev-tenant-share' removed\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to create 'dev': process exited with code 78: \
         sysadminctl: -addUser failed: existing record\n"
    );
}

#[test]
fn create_sysadminctl_failure_with_rollback_failure_surfaces_both() {
    // Worst-case partial failure: dseditgroup-create succeeded (so the
    // group exists), sysadminctl-addUser failed (so no user), and the
    // rollback dseditgroup-delete also failed (so the group is now an
    // orphan with no corresponding user). The operator gets two stderr
    // lines: the original failure (matches the single-failure shape so
    // log-grep regexes don't break), plus a second line naming the
    // rollback failure and pointing the operator at the recovery path.
    // The trailing `— host now has an orphan group; next 'tenant destroy
    // dev' will converge` is the load-bearing piece: the operator
    // shouldn't have to read the source to find out how to clean up.
    let exec = StubExecutor::new()
        .fail_account_op(
            AccountOp::CreateTenantUser {
                name: "dev".into(),
                uid: UserId(600),
                gid: GroupId(600),
            },
            AccountError::NonZero {
                code: 78,
                stderr: "sysadminctl: -addUser failed: existing record\n".into(),
            },
        )
        .fail_account_op(
            AccountOp::DeleteShareGroup {
                group: "dev-tenant-share".into(),
            },
            AccountError::NonZero {
                code: 1,
                stderr: "dseditgroup: not authorized\n".into(),
            },
        );
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR");
    // Section divider + ✓ for the first two successful steps
    // (CreateShareGroup + AddHostToShareGroup) lands on stdout. The
    // third step (CreateTenantUser) fails — no ✓; rollback also
    // fails — no ✓ for DeleteShareGroup either. Both failure frames
    // go to stderr.
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    let want_stderr = "tenant: failed to create 'dev': process exited with code 78: \
                       sysadminctl: -addUser failed: existing record\n\
                       tenant: rollback of group 'dev-tenant-share' also failed: process exited with code 1: \
                       dseditgroup: not authorized \
                       \u{2014} host now has an orphan group; next 'tenant destroy dev' will converge\n";
    assert_eq!(stderr, want_stderr);
    // Four account ops: CreateShareGroup (ok) + AddHostToShareGroup
    // (ok) + CreateTenantUser (failed) + DeleteShareGroup rollback
    // (failed).
    assert_eq!(exec.account_ops().len(), 4);
}

#[test]
fn create_real_mode_invokes_firewall_ops_in_locked_order() {
    // Locked PF flow: BackupConfig → InstallAnchor → UpdateConfig →
    // Reload → Enable. Pins the order of `firewall_ops()` recorded by
    // the stub on a clean-host (empty pf.conf) success path.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let ops = exec.firewall_ops();
    let names: Vec<&'static str> = ops
        .iter()
        .map(|op| match op {
            tenant::executor::FirewallOp::BackupConfig => "BackupConfig",
            tenant::executor::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::executor::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::executor::FirewallOp::Reload => "Reload",
            tenant::executor::FirewallOp::Enable => "Enable",
            tenant::executor::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::executor::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::executor::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
        })
        .collect();
    assert_eq!(
        names,
        vec![
            "BackupConfig",
            "InstallAnchor",
            "UpdateConfig",
            "Reload",
            "Enable",
        ],
    );
}

#[test]
fn create_real_mode_install_anchor_body_reflects_runtime_hosts_from_profile() {
    // Profile read → parse → render_anchor: the InstallAnchor body
    // should contain the rendered anchor with the runtime allowlist.
    // The create flow writes the default profile (empty runtime
    // hosts) before reading, so the body's table is the empty `{ }`
    // form. Pins the read→parse→render data flow end-to-end.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let body = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::executor::FirewallOp::InstallAnchor { body, .. } => Some(body),
            _ => None,
        })
        .expect("InstallAnchor op must have been issued");
    assert!(
        body.contains("table <allowed> persist { }"),
        "anchor body must include empty allowlist table; got:\n{body}"
    );
    assert!(
        body.contains("pass out quick on lo0 user dev"),
        "anchor body must include loopback pass; got:\n{body}"
    );
}

#[test]
fn create_real_mode_install_anchor_body_includes_hosts_when_profile_populated() {
    // Closes the automated end-to-end gap on the allow path: the
    // sibling test above pins the data flow with the empty default;
    // this test simulates "the scaffolded profile had runtime hosts"
    // via `with_create_profile_content` and pins that the same data
    // flow (read_profile → parse → render_anchor) carries the hosts
    // all the way to `InstallAnchor.body`. The manual smoke verifies
    // the same flow against real pfctl + egress traffic; this is the
    // unit-level counterpart that catches regressions without needing
    // root.
    let populated = "schema_version = 1\n\
                     \n\
                     [allowlist.runtime]\n\
                     hosts = [\"example.com\", \"api.anthropic.com\"]\n\
                     \n\
                     [allowlist.install]\n\
                     hosts = []\n";
    let exec = StubExecutor::new().with_create_profile_content("dev", populated);
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let body = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::executor::FirewallOp::InstallAnchor { body, .. } => Some(body),
            _ => None,
        })
        .expect("InstallAnchor op must have been issued");
    // Backslash-continued table with both hosts in input order.
    assert!(
        body.contains(
            "table <allowed> persist { \\\n  \
             example.com \\\n  \
             api.anthropic.com \\\n}\n"
        ),
        "anchor body must include populated backslash-continued table \
         with hosts in profile order; got:\n{body}"
    );
    // Empty-table form must NOT appear (cross-check that the populated
    // path replaced the empty path, not appended).
    assert!(
        !body.contains("table <allowed> persist { }"),
        "anchor body must NOT include the empty-table form when hosts present; got:\n{body}"
    );
    // Sanity: the rules + scoping are unchanged.
    assert!(
        body.contains("pass out quick on lo0 user dev"),
        "anchor body must still include loopback pass; got:\n{body}"
    );
    assert!(
        body.contains("block out quick proto { tcp udp } from any to any user dev"),
        "anchor body must still include catchall block; got:\n{body}"
    );
}

#[test]
fn create_real_mode_update_conf_content_reflects_existing_pf_conf() {
    // ensure_anchor_ref runs against the host's current pf.conf — if
    // the host already has unrelated anchors, those stay intact and
    // tenant's lines append. The stub's `with_pf_conf` simulates the
    // existing-host state.
    let initial = "# host's existing pf.conf\nset block-policy drop\n";
    let exec = StubExecutor::new().with_pf_conf(initial);
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let updated = exec
        .firewall_ops()
        .into_iter()
        .find_map(|op| match op {
            tenant::executor::FirewallOp::UpdateConfig { content } => Some(content),
            _ => None,
        })
        .expect("UpdateConfig op must have been issued");
    assert!(
        updated.starts_with(initial),
        "updated pf.conf must preserve existing content; got:\n{updated}"
    );
    assert!(
        updated.contains("anchor \"tenant-dev\""),
        "updated pf.conf must reference tenant anchor; got:\n{updated}"
    );
    assert!(
        updated.contains("load anchor \"tenant-dev\" from \"/etc/pf.anchors/tenant-dev\""),
        "updated pf.conf must include load-anchor line; got:\n{updated}"
    );
}

#[test]
fn create_firewall_install_anchor_failure_leaves_user_group_profile_present() {
    // Locked recovery posture: a firewall step failing after the
    // account+profile ops have succeeded leaves the host with user +
    // group + profile in place. Recovery is `tenant destroy <name>`
    // — the Destroyable arm cleans up all of them. Operator sees a
    // create_firewall_failed message at EX_IOERR.
    let exec = StubExecutor::new().fail_firewall_op(
        tenant::executor::FirewallOp::InstallAnchor {
            name: "dev".into(),
            body: tenant::firewall::render_anchor("dev", &[]),
        },
        FirewallError::Fs {
            path: "/etc/pf.anchors/tenant-dev".to_string(),
            message: "permission denied".to_string(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    // Section + ✓ for the successful steps before the firewall
    // InstallAnchor failure (CreateShareGroup, CreateTenantUser,
    // ProfileCreate, BackupConfig). No Done section — the verb
    // failed.
    let want_stdout = format!(
        "{}\n\
         ✓ Share group 'dev-tenant-share' created (GID 600)\n\
         ✓ Host 'operator' added to share group 'dev-tenant-share'\n\
         ✓ User account 'dev' provisioned (UID 600)\n\
         ✓ Profile written to ~/.config/tenant/profiles/dev.toml\n\
         ✓ Backed up /etc/pf.conf to /etc/pf.conf.tenant-backup\n",
        section_line("Creating tenant 'dev'"),
    );
    assert_eq!(stdout, want_stdout);
    assert_eq!(
        stderr,
        "tenant: failed to install firewall for 'dev': \
         filesystem error at /etc/pf.anchors/tenant-dev: permission denied\n"
    );
    // CreateShareGroup + AddHost + CreateTenantUser = 3 account ops.
    assert_eq!(
        exec.account_ops().len(),
        3,
        "create-share-group + add-host + create-tenant-user all ran"
    );
    assert!(
        exec.has_profile("dev"),
        "profile should remain present after firewall failure"
    );
}

#[test]
fn create_reload_failure_triggers_restore_remove_anchor_reload_recovery_sequence() {
    // When Reload fails the writer must run the locked 4-step recovery:
    // RestoreConfigFromBackup → RemoveAnchor → Reload → FlushAnchor
    // (best-effort post-restore). FlushAnchor clears any in-kernel
    // anchor state from the failed initial Reload. Total firewall_ops:
    // BackupConfig, InstallAnchor, UpdateConfig, Reload (the failure),
    // RestoreConfigFromBackup, RemoveAnchor, Reload (recovery),
    // FlushAnchor (recovery). Eight ops; the original reload failure
    // surfaces as the CreateError after recovery runs.
    let exec = StubExecutor::new().fail_firewall_op(
        tenant::executor::FirewallOp::Reload,
        FirewallError::NonZero {
            code: 1,
            stderr: "syntax error".to_string(),
        },
    );
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stdout={stdout:?}");
    // Stdout is non-empty under the ✓ progress narration; we just
    // check it starts with the section divider and never emits the
    // Done section (verb failed).
    assert!(
        stdout.starts_with(&format!("{}\n", section_line("Creating tenant 'dev'"))),
        "expected section divider opener: {stdout:?}",
    );
    assert!(
        !stdout.contains(&section_line("Done")),
        "Done section must not emit when verb fails: {stdout:?}",
    );
    assert!(
        stderr.starts_with("tenant: failed to install firewall for 'dev':"),
        "expected install-firewall-failed framing; got: {stderr:?}"
    );
    let op_names: Vec<&'static str> = exec
        .firewall_ops()
        .iter()
        .map(|op| match op {
            tenant::executor::FirewallOp::BackupConfig => "BackupConfig",
            tenant::executor::FirewallOp::InstallAnchor { .. } => "InstallAnchor",
            tenant::executor::FirewallOp::UpdateConfig { .. } => "UpdateConfig",
            tenant::executor::FirewallOp::Reload => "Reload",
            tenant::executor::FirewallOp::RestoreConfigFromBackup => "RestoreConfigFromBackup",
            tenant::executor::FirewallOp::RemoveAnchor { .. } => "RemoveAnchor",
            tenant::executor::FirewallOp::Enable => "Enable",
            tenant::executor::FirewallOp::FlushAnchor { .. } => "FlushAnchor",
        })
        .collect();
    assert_eq!(
        op_names,
        vec![
            "BackupConfig",
            "InstallAnchor",
            "UpdateConfig",
            "Reload",
            "RestoreConfigFromBackup",
            "RemoveAnchor",
            "Reload",
            "FlushAnchor",
        ],
        "recovery sequence must run after reload failure"
    );
}

#[test]
fn create_reload_failure_with_failed_restore_surfaces_recovery_hint_naming_backup_path() {
    // Recovery-of-recovery: if RestoreConfigFromBackup itself fails,
    // the writer surfaces FirewallError::RestoreFailed which renders
    // with the em-dash-suffixed manual-recovery hint naming the
    // backup path. The host is left in a half-edited state; only the
    // operator (with shell access) can resolve.
    let exec = StubExecutor::new()
        .fail_firewall_op(
            tenant::executor::FirewallOp::Reload,
            FirewallError::NonZero {
                code: 1,
                stderr: "syntax error".to_string(),
            },
        )
        .fail_firewall_op(
            tenant::executor::FirewallOp::RestoreConfigFromBackup,
            FirewallError::NonZero {
                code: 1,
                stderr: "cp: permission denied".to_string(),
            },
        );
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR");
    assert!(
        stderr.contains("pf.conf restore from /etc/pf.conf.tenant-backup failed"),
        "expected RestoreFailed framing; got: {stderr:?}"
    );
    assert!(
        stderr.contains("sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf to recover"),
        "expected manual recovery hint; got: {stderr:?}"
    );
}

#[test]
fn create_pf_enable_failure_surfaces_via_create_firewall_failed() {
    // Enable is the last firewall step. Failure here means rules
    // loaded but enforcement is off — surface as create_firewall_failed
    // at EX_IOERR. Recovery posture per locked policy: user + group +
    // profile + anchor remain on host; `tenant destroy` converges.
    let exec = StubExecutor::new().fail_firewall_op(
        tenant::executor::FirewallOp::Enable,
        FirewallError::NonZero {
            code: 1,
            stderr: "pfctl: operation not permitted".to_string(),
        },
    );
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR");
    assert!(
        stderr.starts_with("tenant: failed to install firewall for 'dev':"),
        "got: {stderr:?}"
    );
    // All preceding firewall steps ran; Enable was the failure.
    assert_eq!(exec.firewall_ops().len(), 5, "5 firewall ops up to Enable");
}

#[test]
fn create_dry_run_bypasses_firewall_executor() {
    // Dry-run swaps in DryRunExecutor; the wired StubExecutor's
    // firewall_ops list stays empty. Mirrors
    // `create_dry_run_does_not_write_profile` for firewall.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev", "--dry-run"],
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, create_dry_run_block("dev", 600, 600, None));
    assert!(
        exec.firewall_ops().is_empty(),
        "firewall executor should not be invoked in dry-run; got: {:?}",
        exec.firewall_ops()
    );
}

#[test]
fn create_real_mode_dseditgroup_failure_surfaces_executor_stderr() {
    // Companion to the above — when dseditgroup-create has captured stderr,
    // it flows through ExecError::Display unchanged. Pins the error-shape
    // contract end-to-end.
    let exec = StubExecutor::new().fail_account_blanket(
        78,
        "dseditgroup: cannot create group dev-tenant-share: not authorized\n",
    );
    let (code, stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    // Section divider lands; the first substrate op fails so no ✓
    // emits; stderr carries the framing.
    assert_eq!(
        stdout,
        format!("{}\n", section_line("Creating tenant 'dev'")),
    );
    assert_eq!(
        stderr,
        "tenant: failed to create group 'dev-tenant-share' for 'dev': process exited with code 78: \
         dseditgroup: cannot create group dev-tenant-share: not authorized\n"
    );
}

#[test]
fn create_success_path_does_not_invoke_flush_anchor() {
    // Negative pin: create's success path INSTALLS the anchor; there's
    // nothing to flush. FlushAnchor only runs on the destroy paths and
    // on create's reload-failure recovery path (covered by a separate
    // test). Without this guard, an accidental wiring of FlushAnchor
    // into the success path would silently wipe the rules we just
    // installed.
    let exec = StubExecutor::new();
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !exec
            .firewall_ops()
            .iter()
            .any(|op| matches!(op, tenant::executor::FirewallOp::FlushAnchor { .. })),
        "FlushAnchor must NOT appear in create's success-path firewall_ops; got: {:?}",
        exec.firewall_ops()
    );
}

// ================================================================
// Post-provision share reapply
// ================================================================
//
// On the standard production path the default profile has no
// `[[shares]]`, so the post-provision substrate is a no-op (covered
// implicitly by every existing create test). Tests here use
// `with_create_profile_content` to inject a profile with shares so
// the post-provision substrate fires.

#[test]
fn create_with_pre_populated_shares_runs_post_provision_substrate() {
    // Operator-supplied (test-injected) profile content with a single
    // `[[shares]]` entry. After user/group/profile/PF land, the
    // post-provision step grants the ACL and installs the symlink.
    let with_share = profile_with_shares(&[], &[], &[("/tmp", "rw", "$HOME/src")]);
    let exec = StubExecutor::new().with_create_profile_content("dev", &with_share);
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0, "exit code = {code}; stderr={stderr:?}");

    let acl_ops = exec.acl_ops();
    assert_eq!(
        acl_ops,
        vec![AclOp::Grant {
            path: PathBuf::from("/tmp"),
            group: "dev-tenant-share".into(),
            mode: AclMode::Rw,
        }],
        "expected single Grant op from post-provision substrate; got {acl_ops:?}"
    );
    let symlink_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| matches!(op, AccountOp::EnsureSymlinkAsUser { .. }))
        .collect();
    assert_eq!(
        symlink_ops.len(),
        1,
        "expected single symlink op; got {symlink_ops:?}"
    );
}

#[test]
fn create_with_default_profile_emits_no_post_provision_acl_ops() {
    // Backward-compat: the default profile has no `[[shares]]`, so
    // create's post-provision substrate is a no-op. Existing create
    // tests rely on this — explicit pin so a future schema change
    // can't silently break the contract.
    let exec = StubExecutor::new();
    let (code, _stdout, _stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0);
    assert!(
        exec.acl_ops().is_empty(),
        "default profile has no shares; AclOp must NOT fire: {:?}",
        exec.acl_ops()
    );
    let new_account_ops: Vec<_> = exec
        .account_ops()
        .into_iter()
        .filter(|op| {
            matches!(
                op,
                AccountOp::EnsureDirAsUser { .. } | AccountOp::EnsureSymlinkAsUser { .. }
            )
        })
        .collect();
    assert!(
        new_account_ops.is_empty(),
        "default profile has no shares; EnsureDir/EnsureSymlink must NOT fire: {new_account_ops:?}"
    );
}

#[test]
fn create_post_provision_refusal_carries_recovery_hint() {
    // Pre-populated profile declares a non-existent host_path; the
    // post-provision share substrate refuses with HostPathMissing.
    // Frame names the existing tenant state and points the operator
    // at `tenant reload` (NOT another `tenant create`).
    let bad_share = profile_with_shares(
        &[],
        &[],
        &[("/nonexistent/cycle10/create-sentinel", "rw", "$HOME/src")],
    );
    let exec = StubExecutor::new().with_create_profile_content("dev", &bad_share);
    let (code, _stdout, stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 74, "EX_IOERR on share refusal; stderr={stderr:?}");
    assert!(
        stderr.contains("provisioned but share entry is invalid"),
        "stderr should be framed by refuse_create_post_provision_share: {stderr:?}"
    );
    assert!(
        stderr.contains("tenant reload dev"),
        "stderr should name the recovery command: {stderr:?}"
    );
}

// ================================================================
// Pre-execution confirmation prompt
// ================================================================

#[test]
fn create_real_verbose_interactive_emits_plan_before_prompt() {
    // Headline behavior pin: under verbose + TTY, the operator sees
    // the plan BEFORE the confirm prompt. The plan
    // section header "Plan (commands to execute):" must appear between
    // the "Sudo needed for:" line and the "Proceed? [Y/n]" prompt;
    // the section divider must only appear AFTER the operator answers
    // (so an n-answer leaves zero verb-section state in the output).
    let exec = StubExecutor::new();
    let (code, stdout, _stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev", "-v"],
        b"y\n",
    );
    assert_eq!(code, 0);
    // Emit order inside the summary: bullets → Plan (commands) →
    // Sudo line → blank → Proceed? prompt → section divider (after
    // operator answers) → $ echo + ✓ progress → Done section.
    let sudo_idx = stdout
        .find("Sudo needed for: user provisioning, firewall install.")
        .expect("summary should emit Sudo line");
    let plan_idx = stdout
        .find("Plan (commands to execute):")
        .expect("verbose plan section should emit");
    let prompt_idx = stdout
        .find("Proceed? [Y/n]")
        .expect("confirm prompt should emit on TTY");
    let section_idx = stdout
        .find(&section_line("Creating tenant 'dev'"))
        .expect("section divider should emit after the operator answers");
    assert!(
        plan_idx < sudo_idx,
        "Plan section should appear before 'Sudo needed for' inside the summary; \
         plan={plan_idx} sudo={sudo_idx} in {stdout:?}"
    );
    assert!(
        sudo_idx < prompt_idx,
        "Proceed? prompt should follow the Sudo line; \
         sudo={sudo_idx} prompt={prompt_idx} in {stdout:?}"
    );
    assert!(
        section_idx > prompt_idx,
        "Section divider should land AFTER the confirm prompt — operator \
         commits to the verb after seeing the plan + prompt, not before; \
         prompt={prompt_idx} section={section_idx} in {stdout:?}"
    );
    // Plan layout uses the intent-leads-shell-follows shape.
    assert!(
        stdout.contains("  \u{2022} Create share group 'dev-tenant-share' (GID 600)"),
        "plan should carry the intent bullet for CreateShareGroup: {stdout:?}"
    );
    assert!(
        stdout.contains("      sudo dseditgroup -o create -n . -i 600 dev-tenant-share"),
        "plan should carry the indented shell line under the bullet: {stdout:?}"
    );
}

#[test]
fn create_with_tty_proceeds_on_y() {
    // Operator at TTY, types `y` + ENTER → confirm returns Proceed →
    // substrate runs. Verifies the summary emits + the prompt line +
    // the post-summary section + ✓ stream + done.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev"],
        b"y\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("About to create tenant 'dev'"),
        "summary should emit: {stdout:?}",
    );
    assert!(
        stdout.contains("Proceed? [Y/n] "),
        "prompt should emit: {stdout:?}",
    );
    assert!(
        stdout.contains(&section_line("Creating tenant 'dev'")),
        "section divider should emit after Proceed: {stdout:?}",
    );
    assert!(
        stdout.ends_with("Tenant 'dev' ready (UID 600, GID 600, anchor 'tenant-dev').\n"),
        "done line should close: {stdout:?}",
    );
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

#[test]
fn create_with_tty_aborts_on_n() {
    // Operator types `n` + ENTER → confirm returns Abort → substrate
    // does NOT run; exit 0 (user-initiated abort is not a failure).
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev"],
        b"n\n",
    );
    assert_eq!(code, 0, "exit 0 on user-initiated abort; stderr={stderr:?}");
    assert!(
        stdout.contains("Aborted by operator. No changes made."),
        "aborted line should emit: {stdout:?}",
    );
    assert!(
        exec.account_ops().is_empty(),
        "no substrate should run: {:?}",
        exec.account_ops()
    );
}

#[test]
fn create_with_tty_empty_input_uses_default_yes() {
    // Operator hits ENTER without typing — default Y for create →
    // Proceed. The prompt hint is `[Y/n]` (Y capitalized) signaling
    // the default.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev"],
        b"\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Proceed? [Y/n] "),
        "default-Y hint should appear in prompt: {stdout:?}",
    );
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

#[test]
fn create_with_yes_flag_skips_prompt_proceeds() {
    // `--yes` (or `-y`) bypasses the prompt without reading stdin.
    // Even with no stdin content, substrate fires.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev", "--yes"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("Proceed?"),
        "prompt must NOT emit with --yes: {stdout:?}",
    );
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

#[test]
fn create_with_invalid_input_reprompts_then_accepts() {
    // Q16 edge case: typing `maybe` (neither y nor n) triggers a
    // reprompt with the "Please answer y or n." hint. Second line
    // `y` proceeds.
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev"],
        b"maybe\ny\n",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Please answer y or n."),
        "reprompt hint should appear: {stdout:?}",
    );
    assert!(!exec.account_ops().is_empty(), "substrate should fire");
}

// ================================================================
// Pre-exec doctor audit (cycle 16): create scope
// ================================================================
//
// Create's audit considers PfDisabled only (host-wide). No tenant
// exists yet, so per-tenant checks are out of scope. EnvLeak is also
// out (shell-specific operator impact).

#[test]
fn create_pre_exec_doctor_silent_when_host_is_clean() {
    let exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("\u{26a0} Doctor:"),
        "clean host must not emit the aggregate warning line; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("critical:"),
        "clean host must not emit a critical finding; stdout={stdout:?}"
    );
}

#[test]
fn create_pre_exec_doctor_emits_critical_inline_when_pf_disabled() {
    let exec = StubExecutor::new().with_pf_status_content("Status: Disabled\n");
    let (code, stdout, stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("critical: pf is globally disabled"),
        "PfDisabled critical must emit inline; stdout={stdout:?}"
    );
}

#[test]
fn create_pre_exec_doctor_scope_excludes_env_leak() {
    // EnvLeak is Shell-only — even with `env_delete` missing,
    // create's audit must NOT emit a warning. The leak doesn't
    // apply to the create flow's substrate (no `sudo -u` happens
    // in create).
    let exec = StubExecutor::new().with_env_policy_content("");
    let (code, stdout, stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("\u{26a0} Doctor:"),
        "EnvLeak must NOT propagate to create scope; stdout={stdout:?}"
    );
}

#[test]
fn create_pre_exec_doctor_silent_in_scripted_mode() {
    // No TTY, no --dry-run → no summary, no audit (Q3 lock).
    let exec = StubExecutor::new().with_pf_status_content("Status: Disabled\n");
    let (code, stdout, _stderr) =
        run_with_exec(StubHostAccounts::default(), &exec, &["create", "dev"]);
    assert_eq!(code, 0);
    assert!(
        !stdout.contains("\u{26a0} Doctor:") && !stdout.contains("critical:"),
        "scripted real-mode must not emit audit; stdout={stdout:?}"
    );
}

#[test]
fn create_pre_exec_doctor_substrate_failure_surfaces_and_proceeds() {
    let exec = StubExecutor::new().fail_next_pf_status(FirewallError::NonZero {
        code: 1,
        stderr: "sudo: a password is required".into(),
    });
    let (code, _stdout, stderr) = run_with_stdin(
        StubHostAccounts::default(),
        &exec,
        &["create", "dev", "-y"],
        b"",
    );
    assert_eq!(code, 0, "verb proceeds despite audit substrate failure");
    assert!(
        stderr.contains("failed to read pf state"),
        "substrate failure surfaces via doctor_firewall_failed frame; stderr={stderr:?}"
    );
}
