use tenant::adapters::stub_host_accounts::StubHostAccounts;
use tenant::adapters::stub_host_machine::StubHostMachine;
use tenant::domain::UserId;

mod common;
use common::*;

// ============================================================
// Doctor verb (filesystem-exposure detection)
// ============================================================
//
// Refusals reuse `destroy_eligibility`'s 5-way classifier (same as
// shell/mode): NotPresent and OrphanGroup collapse into
// `refuse_doctor_absent` (the operator wants to audit a real tenant;
// an orphan group has no tenant to audit).

#[test]
fn doctor_refuses_when_tenant_absent() {
    // Empty StubHostAccounts — no user, no group. Doctor must refuse: there
    // is no tenant to audit. Exit 64 (EX_USAGE; operator gave a name
    // we can't resolve). Never reaches the host machine.
    let (code, stdout, stderr) = run_with(StubHostAccounts::default(), &["doctor", "ghost"]);
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
    let stub = StubHostAccounts {
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
    let stub = StubHostAccounts {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), UserId(501))]
            .into_iter()
            .collect(),
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
    let stub = StubHostAccounts {
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
    // HostAccounts. Reuses the generic `refuse_invalid_name` Reporter method
    // (no doctor-specific charset wording) — same shape as create /
    // destroy / shell / mode.
    let (code, stdout, stderr) = run_with(StubHostAccounts::default(), &["doctor", "BAD"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: name 'BAD' must start with a lowercase letter (got 'B')\n"
    );
}

// ----- Probe orchestration + finding emission -----
//
// The probe carve-out (`HostMachine::probe_access_as_tenant`) lets the
// Tenants struct ask the substrate "can <tenant> read/list <path>?" without
// Tenants knowing about `sudo -u` or `/usr/bin/test`. Findings are
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
    let stub_exec = StubHostMachine::new().with_probe_outcome(
        "dev",
        &target,
        tenant::domain::AccessMode::Read,
        tenant::domain::AccessOutcome::Allowed,
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
    let stub_exec = StubHostMachine::new();
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
    let stub_exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected: Vec<(String, std::path::PathBuf, tenant::domain::AccessMode)> =
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
    let stub_exec = StubHostMachine::new().fail_next_probe(tenant::domain::ProbeError::Spawn(
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
    let stub_exec = StubHostMachine::new();
    let (code, stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--dry-run"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stub_exec.probes(),
        Vec::<(String, std::path::PathBuf, tenant::domain::AccessMode)>::new(),
        "dry-run must not invoke probes"
    );
    assert!(
        stdout.starts_with("Would run doctor on tenant 'dev'"),
        "dry-run should emit intent line; got: {stdout:?}"
    );
}

// ----- Verbose curated-list disclosure -----
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
    let stub_exec = StubHostMachine::new();
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
    let stub_exec = StubHostMachine::new().with_probe_outcome(
        "dev",
        &target,
        tenant::domain::AccessMode::Read,
        tenant::domain::AccessOutcome::Allowed,
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

// ----- Sudoers env-leak check -----
//
// Doctor reads `/etc/sudoers` + drop-ins (concatenated via
// `HostMachine::read_env_policy`) and parses for `env_delete` directives.
// If `SSH_AUTH_SOCK` isn't covered, doctor emits a host-wide
// `Finding::EnvLeak` warning so the operator knows their session env
// (specifically the ssh-agent socket) is propagating into `tenant
// shell` sessions. SSH_AUTH_SOCK is hard-coded today; future
// cycles may generalize.

#[test]
fn doctor_reports_ssh_auth_sock_leak_when_env_delete_missing() {
    // Empty env policy → `env_delete` missing → leak finding fires.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().with_env_policy_content("");
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
    let stub_exec = StubHostMachine::new()
        .with_env_policy_content("Defaults env_delete += \"SSH_AUTH_SOCK\"\n");
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
    let stub_exec = StubHostMachine::new().with_env_policy_content(policy);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("SSH_AUTH_SOCK not in env_delete"),
        "drop-in directive should suppress leak; stdout={stdout:?}"
    );
}

// ----- All-tenants walk + cross-tenant probes -----
//
// `tenant doctor` without a positional name enumerates every
// tenant-range account via `HostAccounts::tenant_names()` and probes each
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
    let stub_exec = StubHostMachine::new();
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
    let stub_exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let probes = stub_exec.probes();
    let dev_probes_staging = probes.iter().any(|(name, path, mode)| {
        name == "dev"
            && path == &std::path::PathBuf::from("/Users/staging")
            && *mode == tenant::domain::AccessMode::List
    });
    let staging_probes_dev = probes.iter().any(|(name, path, mode)| {
        name == "staging"
            && path == &std::path::PathBuf::from("/Users/dev")
            && *mode == tenant::domain::AccessMode::List
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
    let stub_exec = StubHostMachine::new();
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

// ----- --strict exit codes -----
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
    let stub_exec = StubHostMachine::new().with_probe_outcome(
        "dev",
        &target,
        tenant::domain::AccessMode::Read,
        tenant::domain::AccessOutcome::Allowed,
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
    let stub_exec = StubHostMachine::new().with_probe_outcome(
        "dev",
        &target,
        tenant::domain::AccessMode::List,
        tenant::domain::AccessOutcome::Allowed,
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
    let stub_exec = StubHostMachine::new();
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
    let stub_exec = StubHostMachine::new().with_probe_outcome(
        "dev",
        &target,
        tenant::domain::AccessMode::Read,
        tenant::domain::AccessOutcome::Allowed,
    );
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(
        code, 0,
        "expected exit 0 on critical without --strict; stderr={stderr:?}"
    );
}

// ============================================================
// Host-config drift checks
// ============================================================
//
// Three checks:
//   - PF rule presence (per-tenant; kernel anchor vs intent)
//   - Touch-ID-for-sudo (host-wide; /etc/pam.d/sudo)
//   - pfctl-enabled status (host-wide)
// All checks share doctor's existing severity / --strict / exit-code
// plumbing; finding variants live in `src/doctor.rs::Finding`.

// ----- PF rule presence (per-tenant) -----
//
// `HostMachine::read_kernel_pf_rules(name)` runs `sudo pfctl -a
// tenant-<name> -sr` and returns the raw text; doctor's
// `pf_rule_presence_check` does a structural check (line begins with
// `pass ` AND a line begins with `block `, ignoring comments). The
// structural shape catches "kernel anchor is empty or wrong" without
// false-positiving on pfctl's output formatting cosmetics. Recovery
// is `tenant mode <name> runtime` (re-renders + reloads the anchor);
// Warning-tier severity.

#[test]
fn doctor_pf_rules_present_no_finding() {
    // Stub default seeds both `block` + `pass` lines — happy path
    // produces no PfRuleDrift finding. Pin: doctor still exits 0
    // and the operator-visible summary is "no findings".
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new();
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
        StubHostMachine::new().with_kernel_pf_rules("dev", "block return inet from any to any\n");
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
    let stub_exec = StubHostMachine::new()
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
    let stub_exec = StubHostMachine::new().with_kernel_pf_rules("dev", "");
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
    let stub_exec = StubHostMachine::new().with_kernel_pf_rules("dev", "");
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
    let stub_exec = StubHostMachine::new().with_kernel_pf_rules("dev", "");
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
    let stub_exec = StubHostMachine::new().fail_next_kernel_pf_rules(
        tenant::domain::FirewallError::Spawn(std::io::Error::other("pfctl not found")),
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

// ----- Touch-ID-for-sudo (host-wide) -----
//
// `HostMachine::read_pam_sudo()` reads `/etc/pam.d/sudo` (mode 0644,
// direct fs read). Doctor's `has_pam_tid` parses for an active
// `auth sufficient pam_tid.so` directive; if absent, doctor emits
// one `Finding::TouchIdMissing` (info-tier) per invocation,
// regardless of how many tenants are on the host. Info-tier —
// Touch ID is a recommendation aligned with the project's
// NOPASSWD-sudoers stance, not a correctness drift.

#[test]
fn doctor_pam_tid_present_no_finding() {
    // Stub default seeds `auth sufficient pam_tid.so` — happy path
    // produces no TouchIdMissing finding.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new();
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
    let stub_exec = StubHostMachine::new().with_pam_sudo_content("");
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
    let stub_exec = StubHostMachine::new().with_pam_sudo_content(
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
    // TouchIdMissing is Info-tier. With --strict + ONLY a
    // TouchIdMissing finding, exit code must be 0 (Info doesn't trip
    // --strict's exit-1). Pin against a regression that bumps
    // TouchIdMissing to Warning by accident.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().with_pam_sudo_content("");
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
    let stub_exec = StubHostMachine::new().with_pam_sudo_content("");
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
    // substrate-execution failure. Doctor surfaces via
    // `doctor_host_file_failed` (the path-agnostic host-config-file
    // read failure frame). Exit 74 (EX_IOERR).
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().fail_next_pam_sudo(tenant::domain::HostFileError::Fs {
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

// ----- pfctl-enabled (host-wide) -----
//
// `HostMachine::read_pf_status()` runs `sudo pfctl -si` and returns the
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
    let stub_exec = StubHostMachine::new();
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
    let stub_exec = StubHostMachine::new().with_pf_status_content("Status: Disabled\n");
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
    let stub_exec = StubHostMachine::new().with_pf_status_content("Status: Disabled\n");
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
    // `FirewallError::Spawn` on read_pf_status surfaces via
    // `doctor_firewall_failed`; exit 74.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().fail_next_pf_status(
        tenant::domain::FirewallError::Spawn(std::io::Error::other("pfctl not found")),
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

// ----- Anchor-body drift -----
//
// `HostMachine::read_anchor_body(name)` reads the on-disk anchor file
// `/etc/pf.anchors/tenant-<name>` (mode 0644, direct fs read).
// Doctor renders the expected body via `firewall::render_anchor`
// over the profile's runtime-tier hosts and compares byte-exact via
// `doctor::anchor_body_matches`. On mismatch, one
// `Finding::AnchorBodyDrift` (Warning) per tenant; recovery is
// `tenant mode <name> runtime`. A profile that can't be read or
// parsed SKIPS this check (no AnchorBodyDrift fires) and the rest
// of doctor continues.
//
// Comparison is against the RUNTIME tier render only. Install-tier
// widening outside an active shell session is itself drift the
// operator should know about — symmetric with the shell auto-narrow
// doctrine.

#[test]
fn doctor_anchor_body_in_sync_no_finding() {
    // Anchor body equals the runtime-tier render of the default
    // profile. Happy path: zero AnchorBodyDrift findings; clean
    // "no per-tenant findings" summary; exit 0.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml());
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
    let stub_exec = StubHostMachine::new()
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
    let stub_exec = StubHostMachine::new()
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
    let stub_exec = StubHostMachine::new()
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
    // Profile-read failure → SKIP the anchor-body check (no finding
    // emitted from this check). Other checks still run; exit 0;
    // clean summary. Negative pin: AnchorBodyDrift must NOT
    // false-positive on profile-missing state.
    let stub_reader = make_tenant_stub_reader("dev");
    // No `with_existing_profile` → read_profile returns an error.
    // No `with_anchor_body` → default (renders empty-allowlist).
    let stub_exec = StubHostMachine::new();
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
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .fail_next_anchor_body(tenant::domain::HostFileError::Fs {
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
    let stub_exec = StubHostMachine::new()
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
    let stub_exec = StubHostMachine::new()
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
    // Negative pin: anchor body matches the INSTALL-tier render
    // (runtime+install hosts) but NOT the runtime-tier render
    // (runtime only). Runtime-only comparison is the chosen
    // semantics — install-tier widening outside a shell session
    // IS drift the operator should know about. Verify drift still
    // fires.
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
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_anchor_body("dev", &install_tier_body);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("tenant 'dev' anchor file drift"),
        "install-tier match must NOT satisfy the runtime-tier check; stdout={stdout:?}"
    );
}

// ============================================================
// Enriched finding guidance (verbose-mode surfacing)
// ============================================================
//
// Each non-FilesystemExposure finding grows a multi-section
// `guidance()` block (Why this matters / Recommended fix /
// Side-effects / Alternative). Standard mode keeps the one-liner
// (skim-the-output usage unchanged); verbose mode emits the block
// indented 2 spaces under each finding line. No new flag, no new
// substrate — `-v` is the existing "tell me more" knob.

#[test]
fn doctor_standard_mode_omits_guidance_block() {
    // Negative pin: a finding fires in standard mode → output is the
    // one-liner ONLY. The "Why this matters" header (load-bearing
    // string of the guidance block) must not appear without -v.
    // Guards skim-the-output usage from sudden multi-screen output.
    let stub_reader = make_tenant_stub_reader("dev");
    let edited = format!("{}# stray\n", tenant::firewall::render_anchor("dev", &[]));
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &edited);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' anchor file drift"),
        "finding one-liner should fire in standard mode; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("Why this matters"),
        "standard mode must NOT emit guidance block; stdout={stdout:?}"
    );
}

#[test]
fn doctor_verbose_emits_indented_guidance_below_finding() {
    // Verbose + one finding → one-liner followed by the indented
    // guidance block. Pin: the "Why this matters" header appears
    // AFTER the finding line, with the locked 2-space indent.
    // AnchorBodyDrift here verifies the full pipeline (variant
    // → guidance() → Reporter prefix → stdout).
    let stub_reader = make_tenant_stub_reader("dev");
    let edited = format!("{}# stray\n", tenant::firewall::render_anchor("dev", &[]));
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &edited);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let finding_pos = stdout
        .find("warning: tenant 'dev' anchor file drift")
        .expect("finding line should be present");
    let guidance_pos = stdout
        .find("  Why this matters\n")
        .expect("indented guidance header should appear");
    assert!(
        finding_pos < guidance_pos,
        "guidance must appear BELOW the finding line; stdout={stdout:?}"
    );
    // Spot-check the section headers are all present with the locked
    // 2-space indent — guards against a regression that drops the
    // Reporter prefix or one of the structured sections.
    for header in [
        "  Why this matters\n",
        "  Recommended fix\n",
        "  Side-effects to know about\n",
        "  Alternative\n",
    ] {
        assert!(
            stdout.contains(header),
            "verbose output should contain `{}`; stdout={:?}",
            header.trim_end(),
            stdout
        );
    }
    // Tenant name should appear inside the indented block (e.g. the
    // recommended fix line) — pins that per-tenant variants name
    // the literal tenant in their guidance.
    assert!(
        stdout.contains("  tenant mode dev runtime\n"),
        "guidance should name the literal tenant 'dev' in the fix command; stdout={stdout:?}"
    );
}

#[test]
fn doctor_verbose_filesystem_exposure_omits_guidance_block() {
    // Pinned at the user-facing surface: FilesystemExposure has no
    // guidance body (guidance belongs with the future remediation
    // surface), so even in verbose mode the one-liner emits alone.
    // Pin: the critical finding fires AND the "Why this matters"
    // guidance header is absent.
    //
    // Set the stub to produce ONLY a FilesystemExposure finding (no
    // env leak, no pf drift, no anchor drift, etc.) so a missing
    // guidance section is unambiguous. AnchorBodyDrift would
    // otherwise fire because the default host machine's anchor body is
    // empty; configure a matching profile + body to suppress it.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &tenant::firewall::render_anchor("dev", &[]))
        .with_probe_outcome(
            "dev",
            &target,
            tenant::domain::AccessMode::Read,
            tenant::domain::AccessOutcome::Allowed,
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let expected_line = format!("critical: tenant 'dev' can read /Users/{TEST_HOST}/.ssh/id_rsa\n");
    assert!(
        stdout.contains(&expected_line),
        "FilesystemExposure one-liner should fire; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("Why this matters"),
        "FilesystemExposure must not emit a guidance block; stdout={stdout:?}"
    );
}

#[test]
fn doctor_verbose_multiple_findings_each_paired_with_own_guidance() {
    // Two findings fire — PfDisabled (host-wide, Critical) and
    // AnchorBodyDrift (per-tenant, Warning). Pin: in verbose mode,
    // EACH finding's one-liner is immediately followed by ITS OWN
    // guidance block. The order is host-wide first (PfDisabled
    // emits before probe_tenant_paths), then per-tenant
    // (AnchorBodyDrift). Verify by relative position of section
    // markers unique to each guidance body.
    let stub_reader = make_tenant_stub_reader("dev");
    let edited = format!("{}# stray\n", tenant::firewall::render_anchor("dev", &[]));
    let stub_exec = StubHostMachine::new()
        .with_pf_status_content("Status: Disabled\n")
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &edited);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let pf_disabled_one_liner = stdout
        .find("critical: pf is globally disabled")
        .expect("PfDisabled one-liner should be present");
    // "Enables pf globally" is a unique phrase from PfDisabled's
    // Recommended fix justification — pins which guidance block
    // sits below the PfDisabled finding.
    let pf_disabled_guidance = stdout
        .find("  Enables pf globally")
        .expect("PfDisabled guidance body should be present");
    let anchor_one_liner = stdout
        .find("warning: tenant 'dev' anchor file drift")
        .expect("AnchorBodyDrift one-liner should be present");
    // "Re-renders the anchor body" is unique to AnchorBodyDrift's
    // recommended-fix justification.
    let anchor_guidance = stdout
        .find("  Re-renders the anchor body")
        .expect("AnchorBodyDrift guidance body should be present");
    assert!(
        pf_disabled_one_liner < pf_disabled_guidance,
        "PfDisabled guidance must follow its one-liner; stdout={stdout:?}"
    );
    assert!(
        pf_disabled_guidance < anchor_one_liner,
        "PfDisabled guidance must finish before AnchorBodyDrift one-liner; stdout={stdout:?}"
    );
    assert!(
        anchor_one_liner < anchor_guidance,
        "AnchorBodyDrift guidance must follow its one-liner; stdout={stdout:?}"
    );
}

#[test]
fn doctor_help_text_mentions_sudo_session_and_admin_requirement() {
    // Operator-UX commitment: `tenant doctor --help` documents the two
    // load-bearing operator preconditions — admin-group membership (so
    // `sudo -u <tenant>` is permitted on macOS) and the cached sudo
    // session pattern (one prompt up front, N probes run silently).
    // Pins load-bearing words, not byte-exact wording.
    let (code, stdout, stderr) = run_with(StubHostAccounts::default(), &["doctor", "--help"]);
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

// ============================================================
// AclDrift on declared shares
// ============================================================
//
// `HostMachine::read_host_acl(path)` reads `ls -lde <path>` and feeds
// `doctor::has_group_acl_entry` to detect missing
// `<tenant>-tenant-share` group entries on each declared share's
// host_path. Warning-tier; recovery is `tenant reload <name>`.
// Bounded scope: set of paths audited is exactly the profile's
// `[[shares]]` array; no filesystem walking for orphan ACLs.

#[test]
fn doctor_share_acl_present_no_finding() {
    // Default-stub `read_host_acl` returns a listing carrying the
    // expected group's entry; symlink_kind is configured to point at
    // the declared host_path. Happy path: zero drift findings; clean
    // per-tenant summary.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/Users/Shared/src")),
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("share ACL drift"),
        "no AclDrift expected when ACL is present; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("share symlink drift"),
        "no SymlinkDrift expected when symlink matches; stdout={stdout:?}"
    );
    assert_eq!(stdout, "doctor: tenant 'dev' — no per-tenant findings.\n");
}

#[test]
fn doctor_share_acl_missing_emits_warning() {
    // Operator manually `chmod -a`'d the group ACL from the share's
    // host_path. Listing now lacks the expected entry → one AclDrift
    // Warning naming the host_path, group, and recovery command.
    // SymlinkDrift is silenced by pre-loading the symlink kind so the
    // test isolates the AclDrift signal.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_host_acl(
            std::path::Path::new("/Users/Shared/src"),
            "drwxr-xr-x 5 op staff 160 May  1 12:34 /Users/Shared/src\n",
        )
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/Users/Shared/src")),
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' share ACL drift"),
        "expected AclDrift warning; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("share symlink drift"),
        "SymlinkDrift should NOT fire when symlink is correct; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("dev-tenant-share"),
        "AclDrift should name the expected group; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("/Users/Shared/src"),
        "AclDrift should name the drifted host_path; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant reload dev"),
        "AclDrift should name the recovery command; stdout={stdout:?}"
    );
}

#[test]
fn doctor_share_acl_missing_only_one_of_two_shares() {
    // Two declared shares; only one is drifted. Exactly one AclDrift
    // line; names the right path. SymlinkDrift silenced by pre-loading
    // both symlinks as correct so the test isolates AclDrift signal.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(
        &[],
        &[],
        &[
            ("/Users/Shared/src", "rw", "$HOME/src"),
            ("/Users/Shared/data", "ro", "$HOME/data"),
        ],
    );
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_host_acl(
            std::path::Path::new("/Users/Shared/src"),
            "drwxr-xr-x 5 op staff 160 May  1 12:34 /Users/Shared/src\n",
        )
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/Users/Shared/src")),
        )
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/data"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/Users/Shared/data")),
        );
    // /Users/Shared/data falls through to the stub's default listing,
    // which carries the dev-tenant-share entry → no drift.
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let drift_count = stdout.matches("share ACL drift").count();
    assert_eq!(
        drift_count, 1,
        "expected exactly one AclDrift line; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("missing on /Users/Shared/src"),
        "drift should name /Users/Shared/src; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("missing on /Users/Shared/data"),
        "drift should NOT fire for /Users/Shared/data; stdout={stdout:?}"
    );
}

#[test]
fn doctor_share_acl_drift_with_strict_exits_1() {
    // AclDrift is Warning-tier; --strict + warning-only → exit 1.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_host_acl(
            std::path::Path::new("/Users/Shared/src"),
            "drwxr-xr-x 5 op staff 160 May  1 12:34 /Users/Shared/src\n",
        )
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/Users/Shared/src")),
        );
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_share_drift_dry_run_emits_no_finding() {
    // `--dry-run` swaps in DryRunHostMachine whose `read_profile` returns
    // `default_profile_toml()` (no `[[shares]]`); the share-drift
    // loop never iterates regardless of the underlying stub's profile
    // state. Intent line only; no AclDrift in stdout.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_host_acl(
            std::path::Path::new("/Users/Shared/src"),
            "drwxr-xr-x 5 op staff 160 May  1 12:34 /Users/Shared/src\n",
        );
    let (code, stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--dry-run"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("share ACL drift"),
        "dry-run must not fire AclDrift; stdout={stdout:?}"
    );
    assert!(
        stdout.starts_with("Would run doctor on tenant 'dev'"),
        "dry-run should emit intent line; stdout={stdout:?}"
    );
}

#[test]
fn doctor_share_drift_skips_when_profile_unreadable() {
    // Profile-read failure SKIPS the share-drift check silently —
    // same posture as the anchor-body-drift check. No AclDrift;
    // clean summary; exit 0. A future ProfileMissing finding would
    // surface the profile state separately.
    let stub_reader = make_tenant_stub_reader("dev");
    // No `with_existing_profile` → read_profile returns an error.
    let stub_exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("share ACL drift"),
        "profile-missing should skip share-drift checks; stdout={stdout:?}"
    );
    assert_eq!(stdout, "doctor: tenant 'dev' — no per-tenant findings.\n");
}

#[test]
fn doctor_share_drift_substrate_failure_exits_74() {
    // `ProbeError` on `read_host_acl` propagates as `DoctorError::Probe`;
    // dispatcher routes through `doctor_failed` frame. Exit 74. Symlink
    // kind isn't consulted because read_host_acl runs first per share
    // entry and the failure aborts the whole walk.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .fail_next_host_acl(
            std::path::Path::new("/Users/Shared/src"),
            tenant::domain::ProbeError::NonZero {
                code: 1,
                stderr: "ls: /Users/Shared/src: Permission denied".to_string(),
            },
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(
        !stdout.contains("share ACL drift"),
        "substrate failure must abort before the finding fires; stdout={stdout:?}"
    );
    assert!(
        stderr.contains("doctor probe failed") || stderr.contains("probe exited"),
        "stderr should frame the probe failure; got: {stderr:?}"
    );
}

#[test]
fn doctor_share_drift_all_tenants_scoped_per_tenant() {
    // Two tenants; only `dev`'s share is drifted. Bare `tenant doctor`
    // must scope the AclDrift to dev and leave staging clean. Symlinks
    // pre-loaded as correct so the test isolates AclDrift signal.
    let stub_reader = make_two_tenant_stub_reader();
    let profile_dev = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let profile_staging =
        profile_with_shares(&[], &[], &[("/Users/Shared/data", "ro", "$HOME/data")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile_dev)
        .with_existing_profile("staging", &profile_staging)
        // Only dev's path is drifted; staging's falls through to default
        // listing which contains the staging-tenant-share entry.
        .with_host_acl(
            std::path::Path::new("/Users/Shared/src"),
            "drwxr-xr-x 5 op staff 160 May  1 12:34 /Users/Shared/src\n",
        )
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/Users/Shared/src")),
        )
        .with_tenant_path_kind(
            "staging",
            std::path::Path::new("/Users/staging/data"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/Users/Shared/data")),
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("tenant 'dev' share ACL drift"),
        "dev's drift should fire; stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("tenant 'staging' share ACL drift"),
        "staging should NOT show drift; stdout={stdout:?}"
    );
}

#[test]
fn doctor_share_acl_drift_verbose_emits_guidance_block() {
    // Every Finding variant with a `guidance()` body emits the
    // 4-section block under `-v`. AclDrift's body names the recovery
    // command in the Recommended fix section. Symlink kind pre-loaded
    // as correct so only AclDrift's guidance fires.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_host_acl(
            std::path::Path::new("/Users/Shared/src"),
            "drwxr-xr-x 5 op staff 160 May  1 12:34 /Users/Shared/src\n",
        )
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/Users/Shared/src")),
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Why this matters"),
        "verbose should emit guidance block header; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("Recommended fix"),
        "verbose should emit Recommended-fix section; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant reload dev"),
        "verbose guidance should name recovery; stdout={stdout:?}"
    );
}

// ============================================================
// SymlinkDrift on declared shares
// ============================================================
//
// `HostMachine::tenant_path_kind(name, tenant_path)` returns one of
// PathKind::{Absent, Symlink(target), Other}; doctor compares against
// the declared host_path (string-exact, no canonicalize) and emits
// one of the three SymlinkActual cases.

#[test]
fn doctor_share_symlink_absent_emits_warning() {
    // tenant_path doesn't exist (tenant `rm`'d the symlink, or it
    // never was installed). PathKind::Absent → SymlinkDrift::Absent.
    // ACL silenced via default stub listing carrying the entry.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Absent,
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' share symlink drift"),
        "expected SymlinkDrift warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("/Users/dev/src is absent"),
        "Absent case should name 'is absent'; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("expected symlink to /Users/Shared/src"),
        "drift should name expected target; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant reload dev"),
        "Absent case should name reload recovery; stdout={stdout:?}"
    );
}

#[test]
fn doctor_share_symlink_wrong_target_emits_warning() {
    // tenant_path is a symlink but points at the wrong host path.
    // PathKind::Symlink(actual) → SymlinkDrift::WrongTarget. Doctor's
    // string-exact comparison treats /tmp/old ≠ /Users/Shared/src as
    // drift even though both are reachable from disk.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/tmp/old")),
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' share symlink drift"),
        "expected SymlinkDrift warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("/Users/dev/src points at /tmp/old"),
        "WrongTarget case should name actual target; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("expected /Users/Shared/src"),
        "WrongTarget case should name expected target; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant reload dev"),
        "WrongTarget case should name reload recovery; stdout={stdout:?}"
    );
}

#[test]
fn doctor_share_symlink_not_symlink_emits_warning() {
    // tenant_path is a real file or directory. PathKind::Other →
    // SymlinkDrift::NotSymlink. Recovery requires manual cleanup
    // before reload (reload's TenantPathOccupied pre-flight refuses
    // a real file at tenant_path).
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Other,
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' share symlink drift"),
        "expected SymlinkDrift warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("occupied by a real file or directory"),
        "NotSymlink case should name 'occupied'; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("remove it manually, then run `tenant reload dev`"),
        "NotSymlink case should name manual cleanup + reload recovery; stdout={stdout:?}"
    );
}

#[test]
fn doctor_share_symlink_matching_target_no_finding() {
    // PathKind::Symlink(target) where target == declared host_path
    // → no SymlinkDrift finding. The happy-path equality test on
    // the string-exact comparator.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Symlink(std::path::PathBuf::from("/Users/Shared/src")),
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("share symlink drift"),
        "no SymlinkDrift expected on matching target; stdout={stdout:?}"
    );
    assert_eq!(stdout, "doctor: tenant 'dev' — no per-tenant findings.\n");
}

#[test]
fn doctor_share_symlink_drift_with_strict_exits_1() {
    // SymlinkDrift is Warning-tier; --strict + warning-only → exit 1.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Absent,
        );
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_share_symlink_drift_dry_run_emits_no_finding() {
    // DryRunHostMachine's read_profile returns default_profile_toml()
    // (no `[[shares]]`); share-drift loop never iterates. No
    // SymlinkDrift output; intent line only.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Absent,
        );
    let (code, stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--dry-run"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("share symlink drift"),
        "dry-run must not fire SymlinkDrift; stdout={stdout:?}"
    );
}

#[test]
fn doctor_share_symlink_substrate_failure_exits_74() {
    // ProbeError on tenant_path_kind propagates as DoctorError::Probe;
    // dispatcher routes through doctor_failed frame. Exit 74. Tests
    // the "tenant_path_kind half" of the fail-fast posture (the
    // AclDrift half lives in
    // doctor_share_drift_substrate_failure_exits_74).
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .fail_next_tenant_path_kind(tenant::domain::ProbeError::NonZero {
            code: 1,
            stderr: "sudo: command not found".to_string(),
        });
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    assert!(
        !stdout.contains("share symlink drift"),
        "substrate failure must abort before the finding fires; stdout={stdout:?}"
    );
}

#[test]
fn doctor_share_symlink_drift_verbose_emits_case_tailored_guidance() {
    // Each SymlinkActual sub-case emits its own guidance body.
    // Smoke-test the Absent case names `ln -sfn` in the recovery;
    // the byte-form pins in tests/doctor.rs cover the full bodies.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_tenant_path_kind(
            "dev",
            std::path::Path::new("/Users/dev/src"),
            tenant::domain::PathKind::Absent,
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Why this matters"),
        "verbose should emit guidance block header; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("/bin/ln -sfn /Users/Shared/src /Users/dev/src"),
        "Absent guidance should name the ln -sfn substrate; stdout={stdout:?}"
    );
}

// ============================================================
// HostNotInShareGroup
// ============================================================

#[test]
fn doctor_emits_host_not_in_share_group_when_membership_missing() {
    // Operator simulating a legacy tenant: the share group exists
    // (the create flow ran before host membership was wired in) but
    // the host was never added as a secondary member. Doctor queries
    // the membership via HostMachine::host_in_group, sees `false`, and
    // emits the warning naming the host, the group, and the recovery.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec =
        StubHostMachine::new().with_host_in_group("operator", "dev-tenant-share", false);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: host 'operator' is not a member of group 'dev-tenant-share'"),
        "expected HostNotInShareGroup warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("run `tenant reload dev` to fix"),
        "warning should name the recovery; stdout={stdout:?}"
    );
}

#[test]
fn doctor_clean_when_host_is_member() {
    // Default stub state: host_in_group returns `true` for unmatched
    // lookups, so no finding fires when the membership is intact.
    // Locks the "no spurious finding" baseline so future stub tweaks
    // can't silently regress the default.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new(); // defaults to true
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("is not a member of group"),
        "no HostNotInShareGroup finding expected; stdout={stdout:?}"
    );
}

#[test]
fn doctor_strict_exit_1_on_host_not_in_share_group_alone() {
    // HostNotInShareGroup is Warning-tier; --strict + warning-only
    // → exit 1. Mirrors the AclDrift strict-mode test.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec =
        StubHostMachine::new().with_host_in_group("operator", "dev-tenant-share", false);
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_no_arg_emits_host_not_in_share_group_per_tenant() {
    // Two tenants, both missing the host membership; doctor walks
    // them in alphabetical order and emits one finding per tenant.
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubHostMachine::new()
        .with_host_in_group("operator", "dev-tenant-share", false)
        .with_host_in_group("operator", "staging-tenant-share", false);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: host 'operator' is not a member of group 'dev-tenant-share'"),
        "expected dev finding; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("warning: host 'operator' is not a member of group 'staging-tenant-share'"),
        "expected staging finding; stdout={stdout:?}"
    );
}

#[test]
fn doctor_host_not_in_share_group_verbose_emits_guidance_block() {
    // Verbose mode emits the 4-section guidance body. Smoke-check
    // that the operator sees Why/Fix/Side-effects/Alternative headers
    // and the dseditgroup alternative command. The full byte-form
    // is pinned in tests/doctor.rs.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec =
        StubHostMachine::new().with_host_in_group("operator", "dev-tenant-share", false);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Why this matters"),
        "verbose should emit Why this matters header; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("Recommended fix"),
        "verbose should emit Recommended fix header; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("sudo dseditgroup -o edit -n . -a operator -t user dev-tenant-share"),
        "Alternative should name the manual dseditgroup command; stdout={stdout:?}"
    );
}

#[test]
fn doctor_single_tenant_surfaces_accounts_error_when_eligibility_probe_fails() {
    // Single-tenant doctor uses `destroy_eligibility`; a dscl failure
    // routes to `doctor_eligibility_probe_failed` with doctor-named
    // action wording.
    let stub = StubHostAccounts {
        fail_has_user: accounts_fail_once(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(stub, &["doctor", "dev"]);
    assert_eq!(code, 74);
    assert!(
        stderr.starts_with("tenant: failed to check doctor eligibility for 'dev': "),
        "expected doctor_eligibility_probe_failed frame; stderr={stderr:?}"
    );
}

#[test]
fn doctor_all_surfaces_accounts_error_when_tenant_enumeration_fails() {
    // No-arg `doctor` reaches `accounts.tenant_names()` after host-wide
    // checks. The pre-walk checks need a host machine that doesn't
    // fail, so the test wires an empty `StubHostMachine` and lets the
    // walk reach the enumeration step. A dscl failure surfaces as
    // `doctor_enumeration_failed`.
    let exec = StubHostMachine::new();
    let stub = StubHostAccounts {
        fail_tenant_names: accounts_fail_once(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with_exec(stub, &exec, &["doctor"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("tenant: failed to enumerate tenants for doctor: "),
        "expected doctor_enumeration_failed frame; stderr={stderr:?}"
    );
}
