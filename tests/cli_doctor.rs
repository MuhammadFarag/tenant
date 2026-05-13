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
    assert_eq!(stdout, "doctor: tenant 'dev' — no per-tenant findings.\n");
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

// ============================================================
// Cycle 7 — doctor cycle 2: host-config drift checks
// ============================================================
//
// Three new checks (SC2 / SC3 / SC4):
//   - SC2: PF rule presence (per-tenant; kernel anchor vs intent)
//   - SC3: Touch-ID-for-sudo (host-wide; /etc/pam.d/sudo)
//   - SC4: pfctl-enabled status (host-wide)
// All checks share doctor's existing severity / --strict / exit-code
// plumbing; new finding variants live in `src/doctor.rs::Finding`.

// ----- Sub-cycle 2: PF rule presence (per-tenant) -----
//
// `Executor::read_kernel_pf_rules(name)` runs `sudo pfctl -a
// tenant-<name> -sr` and returns the raw text; doctor's
// `pf_rule_presence_check` does a structural check (line begins with
// `pass ` AND a line begins with `block `, ignoring comments). The
// structural shape catches "kernel anchor is empty or wrong" without
// false-positiving on pfctl's output formatting cosmetics (Q7-a lock).
// Recovery is `tenant mode <name> runtime` (re-renders + reloads the
// anchor); Warning-tier severity.

#[test]
fn doctor_pf_rules_present_no_finding() {
    // Stub default seeds both `block` + `pass` lines — happy path
    // produces no PfRuleDrift finding. Pin: doctor still exits 0
    // and the operator-visible summary is "no findings".
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("pf anchor drift"),
        "no drift finding expected; stdout={stdout:?}"
    );
    assert_eq!(stdout, "doctor: tenant 'dev' — no per-tenant findings.\n");
}

#[test]
fn doctor_pf_rules_missing_pass_emits_warning() {
    // Kernel anchor has `block` but no `pass` → one PfRuleDrift
    // (warning). Finding line names which rule class is missing
    // and points at the `tenant mode runtime` recovery.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec =
        StubExecutor::new().with_kernel_pf_rules("dev", "block return inet from any to any\n");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' pf anchor drift"),
        "expected pf drift warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("no `pass` rule in kernel anchor"),
        "drift detail should name the missing rule class; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant mode dev runtime"),
        "drift finding should name the recovery command; stdout={stdout:?}"
    );
    // Exactly one drift finding (not two).
    let drift_count = stdout.matches("pf anchor drift").count();
    assert_eq!(
        drift_count, 1,
        "expected exactly one drift line; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pf_rules_missing_block_emits_warning() {
    // Symmetric: kernel anchor has `pass` but no `block` → one
    // PfRuleDrift naming the missing block.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new()
        .with_kernel_pf_rules("dev", "pass inet from 192.0.2.1 to <allowed> keep state\n");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("no `block` rule in kernel anchor"),
        "drift detail should name the missing block; stdout={stdout:?}"
    );
    let drift_count = stdout.matches("pf anchor drift").count();
    assert_eq!(
        drift_count, 1,
        "expected exactly one drift line; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pf_rules_empty_anchor_emits_two_warnings() {
    // Empty kernel anchor → both `pass` AND `block` missing →
    // two PfRuleDrift findings. Captures the "anchor file present
    // but its in-kernel image is empty" case (e.g. pfctl reload
    // partially failed leaving an empty anchor namespace).
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().with_kernel_pf_rules("dev", "");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let drift_count = stdout.matches("pf anchor drift").count();
    assert_eq!(
        drift_count, 2,
        "expected two drift lines; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("no `pass` rule"),
        "first drift detail names missing pass; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("no `block` rule"),
        "second drift detail names missing block; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pf_rules_drift_with_strict_exits_1() {
    // PfRuleDrift is Warning-tier; --strict + warning-only → exit 1
    // (per the severity-ordering contract). Pins the new variant
    // through the --strict exit-code path.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().with_kernel_pf_rules("dev", "");
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_pf_rules_all_tenants_scoped_per_tenant() {
    // Two tenants, only `dev` is drifted (empty kernel anchor);
    // `staging` keeps the stub default (both rules present). Bare
    // `tenant doctor` must emit exactly the dev-scoped drift
    // findings and nothing scoped to staging.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubExecutor::new().with_kernel_pf_rules("dev", "");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("tenant 'dev' pf anchor drift"),
        "dev's drift finding should fire; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("tenant 'staging' pf anchor drift"),
        "staging should NOT show drift (default rules are happy); stdout={stdout:?}"
    );
}

#[test]
fn doctor_pf_rules_substrate_failure_routes_to_firewall_failed_frame() {
    // `FirewallError::Spawn` on `read_kernel_pf_rules` propagates as
    // a substrate-execution failure; doctor surfaces via the new
    // `doctor_firewall_failed` Reporter method (distinct from
    // `doctor_failed` (probe) and `doctor_host_file_failed`
    // (sudoers/pam)). Exit 74 (EX_IOERR).
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().fail_next_kernel_pf_rules(
        tenant::executor::FirewallError::Spawn(std::io::Error::other("pfctl not found")),
    );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    // doctor_starting fires (which writes to stdout) before
    // read_kernel_pf_rules — so stdout MAY have the curated-path
    // intro line. The substrate failure aborts before findings
    // emit, so no finding lines on stdout.
    assert!(
        !stdout.contains("pf anchor drift"),
        "substrate failure must abort before findings; stdout={stdout:?}"
    );
    assert!(
        stderr.contains("failed to read pf state"),
        "stderr should frame as firewall-read failure; got: {stderr:?}"
    );
}

// ----- Sub-cycle 3: Touch-ID-for-sudo (host-wide) -----
//
// `Executor::read_pam_sudo()` reads `/etc/pam.d/sudo` (mode 0644,
// direct fs read). Doctor's `has_pam_tid` parses for an active
// `auth sufficient pam_tid.so` directive; if absent, doctor emits
// one `Finding::TouchIdMissing` (info-tier) per invocation,
// regardless of how many tenants are on the host. Info-tier per
// Q5 lock — Touch ID is a recommendation aligned with the project's
// NOPASSWD-sudoers stance, not a correctness drift.

#[test]
fn doctor_pam_tid_present_no_finding() {
    // Stub default seeds `auth sufficient pam_tid.so` — happy path
    // produces no TouchIdMissing finding.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("Touch ID for sudo not detected"),
        "no Touch-ID finding expected; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pam_tid_absent_emits_info_finding() {
    // Empty pam.d/sudo content → no pam_tid → one TouchIdMissing
    // (info-tier). Operator-visible finding line names the exact
    // edit needed to enable it.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().with_pam_sudo_content("");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("info: Touch ID for sudo not detected"),
        "expected Touch-ID info finding; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("auth sufficient pam_tid.so"),
        "finding should name the directive shape; stdout={stdout:?}"
    );
    // Exactly one Touch-ID line (not duplicated).
    let count = stdout.matches("Touch ID for sudo not detected").count();
    assert_eq!(count, 1, "expected one Touch-ID line; stdout={stdout:?}");
}

#[test]
fn doctor_pam_tid_commented_emits_info_finding() {
    // A `#`-prefixed line with `pam_tid.so` doesn't count as
    // active — pam.d's stack ignores commented directives. Doctor
    // should fire TouchIdMissing exactly as if the line were
    // absent.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().with_pam_sudo_content(
        "# auth       sufficient     pam_tid.so\n\
         auth       required       pam_opendirectory.so\n",
    );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Touch ID for sudo not detected"),
        "commented pam_tid must still trigger finding; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pam_tid_info_does_not_trip_strict() {
    // Cycle 7 SC3 Q5 lock: TouchIdMissing is Info-tier. With
    // --strict + ONLY a TouchIdMissing finding, exit code must be
    // 0 (Info doesn't trip --strict's exit-1). Pin against a
    // regression that bumps TouchIdMissing to Warning by accident.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().with_pam_sudo_content("");
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(code, 0, "Info should not trip --strict; stderr={stderr:?}");
}

#[test]
fn doctor_pam_tid_all_tenants_emits_once() {
    // Touch ID is a host-wide concern (one pam.d/sudo per host).
    // Bare `tenant doctor` (all-tenants walk over two tenants)
    // must emit the finding ONCE, not per-tenant.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubExecutor::new().with_pam_sudo_content("");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let count = stdout.matches("Touch ID for sudo not detected").count();
    assert_eq!(
        count, 1,
        "all-tenants doctor must emit Touch-ID once; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pam_substrate_failure_routes_to_host_file_failed_frame() {
    // `HostFileError::Fs` on read_pam_sudo propagates as a
    // substrate-execution failure. Doctor surfaces via the existing
    // `doctor_host_file_failed` (SC1 generalized it from env-policy
    // to any host-config-file read). Exit 74 (EX_IOERR).
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().fail_next_pam_sudo(tenant::executor::HostFileError::Fs {
        path: "/etc/pam.d/sudo".to_string(),
        message: "permission denied".to_string(),
    });
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(
        stdout.is_empty(),
        "substrate failure aborts before findings; stdout={stdout:?}"
    );
    assert!(
        stderr.contains("failed to read host config"),
        "stderr should frame as host-config-read failure; got: {stderr:?}"
    );
    assert!(
        stderr.contains("/etc/pam.d/sudo"),
        "stderr should name the failed path; got: {stderr:?}"
    );
}

// ----- Sub-cycle 4: pfctl-enabled (host-wide) -----
//
// `Executor::read_pf_status()` runs `sudo pfctl -si` and returns the
// raw text; doctor's `pf_status_enabled` checks for the canonical
// `Status: Enabled` line. If pf is globally disabled, NO tenant
// anchor is enforcing — every tenant's firewall is silently inert
// (Critical severity). One emission per `tenant doctor` invocation
// (host-level, not per-tenant). Recovery: `sudo pfctl -e`.

#[test]
fn doctor_pf_enabled_no_finding() {
    // Stub default has "Status: Enabled" — happy path produces
    // no PfDisabled finding.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("pf is globally disabled"),
        "no pf-disabled finding expected; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pf_disabled_emits_critical_finding() {
    // pfctl -si reports "Status: Disabled" → one PfDisabled
    // critical finding. With --strict, critical → exit 2.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().with_pf_status_content("Status: Disabled\n");
    let (code, stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 2,
        "expected exit 2 on critical+strict; stderr={stderr:?}"
    );
    assert!(
        stdout.contains("critical: pf is globally disabled"),
        "expected pf-disabled critical finding; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("sudo pfctl -e"),
        "finding should name the recovery command; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pf_disabled_all_tenants_emits_once() {
    // pf-enabled is a host-wide state — one pf, one finding,
    // regardless of how many tenants are walked. Pin against a
    // regression that per-tenant-emits the host-wide check.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubExecutor::new().with_pf_status_content("Status: Disabled\n");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    // Critical without --strict still exits 0.
    assert_eq!(code, 0, "stderr={stderr:?}");
    let count = stdout.matches("pf is globally disabled").count();
    assert_eq!(
        count, 1,
        "all-tenants doctor must emit PfDisabled once; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pf_status_substrate_failure_routes_to_firewall_failed_frame() {
    // `FirewallError::Spawn` on read_pf_status surfaces via the
    // existing `doctor_firewall_failed` (SC2 added it); exit 74.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new().fail_next_pf_status(
        tenant::executor::FirewallError::Spawn(std::io::Error::other("pfctl not found")),
    );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(
        stdout.is_empty(),
        "substrate failure aborts before findings; stdout={stdout:?}"
    );
    assert!(
        stderr.contains("failed to read pf state"),
        "stderr should frame as firewall-read failure; got: {stderr:?}"
    );
}

// ----- Sub-cycle 5: anchor-body drift (cycle 8) -----
//
// `Executor::read_anchor_body(name)` reads the on-disk anchor file
// `/etc/pf.anchors/tenant-<name>` (mode 0644, direct fs read).
// Doctor renders the expected body via `firewall::render_anchor`
// over the profile's runtime-tier hosts and compares byte-exact via
// `doctor::anchor_body_matches`. On mismatch, one
// `Finding::AnchorBodyDrift` (Warning) per tenant; recovery is
// `tenant mode <name> runtime`. Q4 lock: a profile that can't be
// read or parsed SKIPS this check (no AnchorBodyDrift fires) and
// the rest of doctor continues.
//
// Q9 lock: comparison is against the RUNTIME tier render only.
// Install-tier widening outside an active shell session is itself
// drift the operator should know about — symmetric with cycle 4's
// shell auto-narrow doctrine.

#[test]
fn doctor_anchor_body_in_sync_no_finding() {
    // Anchor body equals the runtime-tier render of the default
    // profile. Happy path: zero AnchorBodyDrift findings; clean
    // "no per-tenant findings" summary; exit 0.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec =
        StubExecutor::new().with_existing_profile("dev", &tenant::profile::default_profile_toml());
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("anchor file drift"),
        "no anchor-body drift expected; stdout={stdout:?}"
    );
    assert_eq!(stdout, "doctor: tenant 'dev' — no per-tenant findings.\n");
}

#[test]
fn doctor_anchor_body_hand_edit_emits_warning() {
    // Operator hand-edited the anchor file (added a stray comment
    // line). Body diverges from profile-derived render → one
    // AnchorBodyDrift Warning naming the recovery command.
    let stub_reader = make_tenant_stub_reader("dev");
    let edited_body = format!(
        "{}# stray operator edit\n",
        tenant::firewall::render_anchor("dev", &[])
    );
    let stub_exec = StubExecutor::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &edited_body);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' anchor file drift"),
        "expected anchor-body drift warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("on-disk body differs from profile-derived render"),
        "drift finding should name what diverged; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant mode dev runtime"),
        "drift finding should name the recovery command; stdout={stdout:?}"
    );
    let drift_count = stdout.matches("anchor file drift").count();
    assert_eq!(
        drift_count, 1,
        "expected exactly one anchor-body drift line; stdout={stdout:?}"
    );
}

#[test]
fn doctor_anchor_body_profile_drift_emits_warning() {
    // Operator updated the profile (added a runtime host) but
    // didn't re-render. Anchor body == empty-allowlist render;
    // profile now declares one host. Doctor renders expected with
    // the new host → diverges from on-disk body → one drift line.
    let stub_reader = make_tenant_stub_reader("dev");
    let new_profile = profile_with_hosts(&["example.com"], &[]);
    let stale_body = tenant::firewall::render_anchor("dev", &[]);
    let stub_exec = StubExecutor::new()
        .with_existing_profile("dev", &new_profile)
        .with_anchor_body("dev", &stale_body);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' anchor file drift"),
        "expected anchor-body drift warning; stdout={stdout:?}"
    );
}

#[test]
fn doctor_anchor_body_drift_with_strict_exits_1() {
    // AnchorBodyDrift is Warning-tier; --strict + warning-only → exit 1.
    let stub_reader = make_tenant_stub_reader("dev");
    let edited_body = format!("{}# stray\n", tenant::firewall::render_anchor("dev", &[]));
    let stub_exec = StubExecutor::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &edited_body);
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_anchor_body_profile_unreadable_skips_check() {
    // Q4 lock: profile-read failure → SKIP the anchor-body check
    // (no finding emitted from this check). Other checks still run;
    // exit 0; clean summary. Negative pin: AnchorBodyDrift must NOT
    // false-positive on profile-missing state.
    let stub_reader = make_tenant_stub_reader("dev");
    // No `with_existing_profile` → read_profile returns an error.
    // No `with_anchor_body` → default (renders empty-allowlist).
    let stub_exec = StubExecutor::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("anchor file drift"),
        "missing profile should skip the drift check; stdout={stdout:?}"
    );
    assert_eq!(stdout, "doctor: tenant 'dev' — no per-tenant findings.\n");
}

#[test]
fn doctor_anchor_body_substrate_failure_routes_to_host_file_failed_frame() {
    // `HostFileError::Fs` on `read_anchor_body` propagates as a
    // host-config-file read failure; doctor surfaces via the
    // existing `doctor_host_file_failed` Reporter method (same
    // path as pam.d/sudo substrate failures). Exit 74.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubExecutor::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_next_anchor_body(tenant::executor::HostFileError::Fs {
            path: "/etc/pf.anchors/tenant-dev".to_string(),
            message: "Permission denied (os error 13)".to_string(),
        });
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(
        !stdout.contains("anchor file drift"),
        "substrate failure must abort before findings; stdout={stdout:?}"
    );
    assert!(
        stderr.contains("failed to read host config"),
        "stderr should frame as host-config-file read failure; got: {stderr:?}"
    );
}

#[test]
fn doctor_anchor_body_drift_all_tenants_scoped_per_tenant() {
    // Two tenants, only `dev` is drifted; `staging` is in sync.
    // Bare `tenant doctor` must emit exactly the dev-scoped drift
    // finding and nothing scoped to staging.
    let stub_reader = make_two_tenant_stub_reader();
    let default = tenant::profile::default_profile_toml();
    let edited = format!("{}# stray\n", tenant::firewall::render_anchor("dev", &[]));
    let stub_exec = StubExecutor::new()
        .with_existing_profile("dev", &default)
        .with_existing_profile("staging", &default)
        .with_anchor_body("dev", &edited);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("tenant 'dev' anchor file drift"),
        "dev's drift finding should fire; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("tenant 'staging' anchor file drift"),
        "staging should NOT show drift; stdout={stdout:?}"
    );
}

#[test]
fn doctor_anchor_body_drift_suppresses_no_findings_summary() {
    // A per-tenant finding (AnchorBodyDrift) suppresses the
    // "no per-tenant findings" summary line. Pins that the new
    // variant is counted as PER-TENANT (not host-wide).
    let stub_reader = make_tenant_stub_reader("dev");
    let edited = format!("{}# stray\n", tenant::firewall::render_anchor("dev", &[]));
    let stub_exec = StubExecutor::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &edited);
    let (_code, stdout, _stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert!(
        !stdout.contains("no per-tenant findings"),
        "drift finding should suppress clean summary; stdout={stdout:?}"
    );
}

#[test]
fn doctor_anchor_body_install_tier_match_still_drifts() {
    // Q9 negative pin: anchor body matches the INSTALL-tier render
    // (runtime+install hosts) but NOT the runtime-tier render
    // (runtime only). The Q9 lock chose runtime-only comparison —
    // install-tier widening outside a shell session IS drift the
    // operator should know about. Verify drift still fires.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_hosts(&["runtime.example.com"], &["install.example.com"]);
    // Anchor body matches install-tier render (BOTH hosts present).
    let install_tier_body = tenant::firewall::render_anchor(
        "dev",
        &[
            "runtime.example.com".to_string(),
            "install.example.com".to_string(),
        ],
    );
    let stub_exec = StubExecutor::new()
        .with_existing_profile("dev", &profile)
        .with_anchor_body("dev", &install_tier_body);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("tenant 'dev' anchor file drift"),
        "install-tier match must NOT satisfy the runtime-tier check; stdout={stdout:?}"
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
