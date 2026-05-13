use tenant::accounts::StubReader;
use tenant::executor::StubExecutor;

mod common;
use common::*;

// ============================================================
// Doctor verb — cycle 5 (filesystem-exposure detection)
// ============================================================
//
// Sub-cycle 1 covers refusal paths + help-text disclosure only. Probe
// orchestration + finding emission land in sub-cycle 3; the all-tenants
// walk lands in sub-cycle 5. Refusals reuse `destroy_eligibility`'s
// 5-way classifier (same as shell/mode): NotPresent and OrphanGroup
// collapse into `refuse_doctor_absent` (the operator wants to audit
// a real tenant; an orphan group has no tenant to audit).

#[test]
fn doctor_refuses_when_tenant_absent() {
    // Empty StubReader — no user, no group. Doctor must refuse: there
    // is no tenant to audit. Exit 64 (EX_USAGE; operator gave a name
    // we can't resolve). Never reaches the executor.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["doctor", "ghost"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot run doctor on 'ghost': does not exist\n"
    );
}

#[test]
fn doctor_refuses_when_only_orphan_group_present() {
    // OrphanGroup collapses to NotPresent for doctor purposes (same
    // shape as shell/mode) — the operator wants to audit a tenant,
    // and a lingering `<name>-tenant-share` group with no user behind
    // it doesn't represent one. A regression that surfaced the orphan
    // group as a distinct refusal would trip this test.
    let stub = StubReader {
        groups: vec!["dev-tenant-share".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["doctor", "dev"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot run doctor on 'dev': does not exist\n"
    );
}

#[test]
fn doctor_refuses_below_floor() {
    // Tenant-floor guard mirrors shell/mode: an account exists with
    // a positive UID below TENANT_UID_FLOOR (600) → refuse. `legacyusr`
    // sidesteps the reserved-name blocklist so this test exercises
    // the state-based refusal path specifically.
    let stub = StubReader {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), 501)].into_iter().collect(),
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["doctor", "legacyusr"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to run doctor on 'legacyusr': UID 501 is below tenant floor 600\n"
    );
}

#[test]
fn doctor_refuses_system_account() {
    // System-account refusal (`has_user` true, `uid_for` None — service
    // accounts whose negative UIDs were filtered by `parse_id_line`).
    // Same shape as shell/mode's system-account refusal.
    let stub = StubReader {
        users: vec!["phantom".to_string()],
        ..Default::default()
    };
    let (code, stdout, stderr) = run_with(stub, &["doctor", "phantom"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: refusing to run doctor on 'phantom': system account (no tenant-range UID)\n"
    );
}

#[test]
fn doctor_rejects_invalid_start() {
    // Lexical validation runs before eligibility; an uppercase first
    // character trips `NameError::InvalidStart` and never consults the
    // Reader. Reuses the generic `refuse_invalid_name` Reporter method
    // (no doctor-specific charset wording) — same shape as create /
    // destroy / shell / mode.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["doctor", "BAD"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: name 'BAD' must start with a lowercase letter (got 'B')\n"
    );
}

// ----- Sub-cycle 3: probe orchestration + finding emission -----
//
// The probe carve-out (`Executor::probe_access_as_tenant`) lets the
// Writer ask the substrate "can <tenant> read/list <path>?" without
// the Writer knowing about `sudo -u` or `/usr/bin/test`. Findings are
// derived from `Allowed` outcomes only; `Denied`/`Unknown` produce
// no operator-visible noise. Tests use `TEST_HOST` (the fixed host
// identity threaded through the test helpers) so the curated path
// expansion is deterministic across runs and environments.

#[test]
fn doctor_emits_one_finding_per_accessible_path() {
    // Stub configured to return `Allowed` for one specific
    // (tenant, path, mode) tuple — `/Users/<host>/.ssh/id_rsa` Read.
    // That's a HostSecret + Read, which `classify` maps to Critical.
    // Output must contain the critical finding line, byte-exact.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::Read,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected_line = format!("critical: tenant 'dev' can read /Users/{TEST_HOST}/.ssh/id_rsa\n");
    assert!(
        stdout.contains(&expected_line),
        "expected finding line in stdout; got: {stdout:?}"
    );
}

#[test]
fn doctor_clean_host_emits_no_findings_summary() {
    // No `with_probe_outcome` calls — every probe defaults to
    // `Denied`. A clean host produces no findings; the operator
    // sees the convergent summary line.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "doctor: tenant 'dev' — no findings.\n");
}

#[test]
fn doctor_probes_full_curated_list_per_tenant() {
    // Pin: the recorded probe sequence matches `curated_paths(TEST_HOST,
    // tenant, &[])`. Behavioral assertion on probe identity — a
    // regression that silently dropped one curated path would trip
    // this test. Tuple order is locked.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected: Vec<(String, std::path::PathBuf, tenant::executor::AccessMode)> =
        tenant::doctor::curated_paths(TEST_HOST, "dev", &[])
            .into_iter()
            .map(|(_, mode, path)| ("dev".to_string(), path, mode))
            .collect();
    assert_eq!(
        stub_exec.probes(),
        expected,
        "probe sequence must match curated_paths(TEST_HOST, 'dev', &[])"
    );
}

#[test]
fn doctor_probe_substrate_failure_exits_74() {
    // `ProbeError::Spawn` propagates as a substrate-execution failure.
    // Doctor surfaces via `doctor_failed`; exit 74 (EX_IOERR) parallel
    // to mode / shell / destroy substrate failures.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().fail_next_probe(tenant::executor::ProbeError::Spawn(
        std::io::Error::other("sudo not found"),
    ));
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert!(
        stderr.contains("failed to probe"),
        "stderr should frame as doctor probe failure; got: {stderr:?}"
    );
}

#[test]
fn doctor_dry_run_skips_probes() {
    // `--dry-run` produces an intent line and runs zero probes.
    // Probes have side effects (sudo prompts, kernel access checks)
    // — dry-run is for "what would this do" inspection only.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--dry-run"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stub_exec.probes(),
        Vec::<(String, std::path::PathBuf, tenant::executor::AccessMode)>::new(),
        "dry-run must not invoke probes"
    );
    assert!(
        stdout.starts_with("Would run doctor on tenant 'dev'"),
        "dry-run should emit intent line; got: {stdout:?}"
    );
}

// ----- Sub-cycle 7: verbose curated-list disclosure -----
//
// Bounded-scope transparency: doctor's verbose output names every
// path it probed, before findings. A clean "no findings" verdict
// is not a claim about the operator's whole host — it's about
// THESE PATHS — and verbose makes that explicit.

#[test]
fn doctor_verbose_prepends_curated_path_header() {
    // Verbose real-mode output starts with the header. The header
    // names the tenant and is followed by one indented `<verb>
    // <path>` line per curated entry. Pin the header line +
    // one canonical entry to guard against regressions that drop
    // the disclosure block.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Curated sensitive paths checked for tenant 'dev':\n"),
        "verbose output should include curated-path header; stdout={stdout:?}"
    );
    let canonical_entry = format!("  read /Users/{TEST_HOST}/.ssh/id_rsa\n");
    assert!(
        stdout.contains(&canonical_entry),
        "verbose output should list the canonical HostSecret/Read entry; stdout={stdout:?}"
    );
}

#[test]
fn doctor_verbose_then_findings_ordering() {
    // Pin: in verbose mode, the curated-path block comes FIRST
    // (operator sees scope), then findings, then the summary line.
    // Regression target: a wiring that emitted findings before the
    // header would surprise the operator's eye on a long output.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::Read,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, stdout, _stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0);
    let header_pos = stdout
        .find("Curated sensitive paths checked for tenant 'dev':")
        .expect("header should be present");
    let finding_pos = stdout
        .find("critical: tenant 'dev' can read")
        .expect("critical finding should be present");
    assert!(
        header_pos < finding_pos,
        "curated-path header must precede findings; stdout={stdout:?}"
    );
}

// ----- Sub-cycle 6: sudoers env-leak check -----
//
// Doctor reads `/etc/sudoers` + drop-ins (concatenated via
// `Executor::read_env_policy`) and parses for `env_delete` directives.
// If `SSH_AUTH_SOCK` isn't covered, doctor emits a host-wide
// `Finding::EnvLeak` warning so the operator knows their session env
// (specifically the ssh-agent socket) is propagating into `tenant
// shell` sessions. Cycle 1 hard-codes the SSH_AUTH_SOCK var; future
// cycles may generalize.

#[test]
fn doctor_reports_ssh_auth_sock_leak_when_env_delete_missing() {
    // Empty env policy → `env_delete` missing → leak finding fires.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().with_env_policy_content("");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("SSH_AUTH_SOCK not in env_delete"),
        "expected env-leak warning; stdout={stdout:?}"
    );
}

#[test]
fn doctor_silent_when_env_delete_in_main_sudoers() {
    // Main `/etc/sudoers` contains the directive → no env-leak finding.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec =
        StubExecutor::new().with_env_policy_content("Defaults env_delete += \"SSH_AUTH_SOCK\"\n");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("SSH_AUTH_SOCK"),
        "no env-leak should fire when directive present; stdout={stdout:?}"
    );
}

#[test]
fn doctor_finds_env_delete_in_drop_in_file() {
    // Directive in a drop-in file (concatenated by the substrate
    // into the same text blob) — parser doesn't care which file
    // sourced it. Models `/etc/sudoers.d/tenant` carrying the fix.
    let stub_reader = make_tenant_stub_reader("dev");
    let policy = "Defaults env_keep += \"PATH\"\n\
                  Defaults env_delete += \"SSH_AUTH_SOCK\"\n";
    let stub_exec = StubExecutor::new().with_env_policy_content(policy);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("SSH_AUTH_SOCK not in env_delete"),
        "drop-in directive should suppress leak; stdout={stdout:?}"
    );
}

// ----- Sub-cycle 5: all-tenants walk + cross-tenant probes -----
//
// `tenant doctor` without a positional name enumerates every
// tenant-range account via `Reader::tenant_names()` and probes each
// from its own perspective. The `others` list (every other tenant)
// drives cross-tenant + tenant-artifact probe expansion. Single-
// tenant invocation (`tenant doctor dev`) intentionally probes ONLY
// dev's view (others = empty) — the negative pin is the operator
// signal that single-tenant is scoped.

#[test]
fn doctor_all_tenants_walks_each_tenant() {
    // Bare `tenant doctor` (no positional name) probes both tenants
    // alphabetically. Behavioral pin: the recorded probe sequence
    // contains entries for `dev` AND `staging` as the probed tenant.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let probes = stub_exec.probes();
    assert!(
        probes.iter().any(|(name, _, _)| name == "dev"),
        "bare doctor should probe `dev`; probes={probes:?}"
    );
    assert!(
        probes.iter().any(|(name, _, _)| name == "staging"),
        "bare doctor should probe `staging`; probes={probes:?}"
    );
}

#[test]
fn doctor_all_tenants_emits_cross_tenant_probes() {
    // With two tenants on the host, dev's probe set includes
    // `/Users/staging` (CrossTenant + List) and staging's includes
    // `/Users/dev`. The cross-tenant block is the new ground doctor
    // breaks — the sandbox plugin doesn't audit it.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let probes = stub_exec.probes();
    let dev_probes_staging = probes.iter().any(|(name, path, mode)| {
        name == "dev"
            && path == &std::path::PathBuf::from("/Users/staging")
            && *mode == tenant::executor::AccessMode::List
    });
    let staging_probes_dev = probes.iter().any(|(name, path, mode)| {
        name == "staging"
            && path == &std::path::PathBuf::from("/Users/dev")
            && *mode == tenant::executor::AccessMode::List
    });
    assert!(
        dev_probes_staging,
        "dev should probe /Users/staging (CrossTenant); probes={probes:?}"
    );
    assert!(
        staging_probes_dev,
        "staging should probe /Users/dev (CrossTenant); probes={probes:?}"
    );
}

#[test]
fn doctor_single_tenant_omits_other_tenant_perspectives() {
    // `tenant doctor dev` only probes dev's view; staging's own
    // probes (e.g. staging probing /Users/operator) must not fire.
    // Negative pin against an accidental "audit every tenant
    // anyway" implementation.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let probes = stub_exec.probes();
    assert!(
        !probes.iter().any(|(name, _, _)| name == "staging"),
        "single-tenant `doctor dev` must not emit probes as `staging`; probes={probes:?}"
    );
    // And single-tenant means others list is empty → no cross-tenant
    // probes from dev's view either (dev doesn't probe /Users/staging).
    assert!(
        !probes
            .iter()
            .any(|(_, path, _)| path == &std::path::PathBuf::from("/Users/staging")),
        "single-tenant `doctor dev` should not probe other tenant homes; probes={probes:?}"
    );
}

// ----- Sub-cycle 4: --strict exit codes -----
//
// Without --strict: doctor always exits 0 on a successful walk (findings
// are informational). With --strict: max finding severity drives the
// exit code (0 / 1 / 2 for none-or-info / warning / critical).

#[test]
fn doctor_strict_critical_exits_2() {
    // One Allowed probe on a HostSecret path → critical finding →
    // --strict → exit 2.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::Read,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 2,
        "expected exit 2 on critical+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_strict_warning_only_exits_1() {
    // One Allowed probe on a HostHomeListing path → warning finding →
    // --strict → exit 1. HostHomeListing is the warning-tier category;
    // host-home is `/Users/<host>` with AccessMode::List.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::List,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_strict_no_findings_exits_0() {
    // Clean host — every probe Denied → 0 findings → --strict → exit 0.
    // Pin: --strict doesn't manufacture exit-1 out of nothing.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 0,
        "expected exit 0 on clean+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_non_strict_critical_still_exits_0() {
    // Negative pin: even a critical finding produces exit 0 without
    // --strict. Doctor's default contract is "report exposures and
    // exit successfully so the operator can pipe / chain"; --strict
    // is the opt-in CI-style verdict shape.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubExecutor::new().with_probe_outcome(
        "dev",
        &target,
        tenant::executor::AccessMode::Read,
        tenant::executor::AccessOutcome::Allowed,
    );
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(
        code, 0,
        "expected exit 0 on critical without --strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_help_text_mentions_sudo_session_and_admin_requirement() {
    // Operator-UX commitment: `tenant doctor --help` documents the two
    // load-bearing operator preconditions — admin-group membership (so
    // `sudo -u <tenant>` is permitted on macOS) and the cached sudo
    // session pattern (one prompt up front, N probes run silently).
    // Pins load-bearing words, not byte-exact wording.
    let (code, stdout, stderr) = run_with(StubReader::default(), &["doctor", "--help"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("sudo"),
        "doctor --help should mention sudo (cached session pattern); stdout={stdout:?}"
    );
    assert!(
        stdout.contains("admin"),
        "doctor --help should mention admin-group requirement; stdout={stdout:?}"
    );
}
