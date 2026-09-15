use tenant::domain::{PathKind, UserId};

mod adapters;
mod common;
use adapters::*;
use common::*;

// --- Refusals ---

#[test]
fn doctor_refuses_when_tenant_absent() {
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["doctor", "ghost"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: cannot run doctor on 'ghost': does not exist\n"
    );
}

#[test]
fn doctor_refuses_when_only_orphan_group_present() {
    let stub = StubUserDirectory {
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
    // `legacyusr` avoids the reserved-name blocklist so the UID floor is what refuses.
    let stub = StubUserDirectory {
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
    // System account: present in `users` with no UID (negative UIDs are filtered).
    let stub = StubUserDirectory {
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
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["doctor", "BAD"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert!(stdout.is_empty(), "stdout should be empty: {stdout:?}");
    assert_eq!(
        stderr,
        "tenant: name 'BAD' must start with a lowercase letter (got 'B')\n"
    );
}

// --- Probe orchestration + finding emission ---

#[test]
fn doctor_emits_one_finding_per_accessible_path() {
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

// TODO(smell): default StubHostMachine to a present cowork dir so clean-host tests needn't seat it.
#[test]
fn doctor_clean_host_emits_no_findings_summary() {
    // Every probe defaults to Denied.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().with_present_cowork_dir("dev");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(stdout, "doctor: tenant 'dev' — no per-tenant findings.\n");
}

#[test]
fn doctor_probes_full_curated_list_per_tenant() {
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

// --- Verbose curated-list disclosure ---

#[test]
fn doctor_verbose_prepends_curated_path_header() {
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

// --- Sudoers env-leak check ---

#[test]
fn doctor_reports_ssh_auth_sock_leak_when_env_delete_missing() {
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
    // The substrate concatenates drop-ins into the same policy text.
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

// --- All-tenants walk + cross-tenant probes ---

#[test]
fn doctor_all_tenants_walks_each_tenant() {
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
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubHostMachine::new();
    let (code, _stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let probes = stub_exec.probes();
    assert!(
        !probes.iter().any(|(name, _, _)| name == "staging"),
        "single-tenant `doctor dev` must not emit probes as `staging`; probes={probes:?}"
    );
    assert!(
        !probes
            .iter()
            .any(|(_, path, _)| path == &std::path::PathBuf::from("/Users/staging")),
        "single-tenant `doctor dev` should not probe other tenant homes; probes={probes:?}"
    );
}

// --- --strict exit codes ---

#[test]
fn doctor_strict_critical_exits_2() {
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
    // HostHomeListing (`/Users/<host>`, List) is the warning-tier category.
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
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().with_present_cowork_dir("dev");
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 0,
        "expected exit 0 on clean+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_non_strict_critical_still_exits_0() {
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

// --- PF rule presence (per-tenant) ---

#[test]
fn doctor_pf_rules_present_no_finding() {
    // Stub default kernel rules carry both `pass` and `block`.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().with_present_cowork_dir("dev");
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
    let drift_count = stdout.matches("pf anchor drift").count();
    assert_eq!(
        drift_count, 1,
        "expected exactly one drift line; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pf_rules_missing_block_emits_warning() {
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
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().fail_next_kernel_pf_rules(
        tenant::domain::FirewallError::Spawn(std::io::Error::other("pfctl not found")),
    );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 74, "expected EX_IOERR; stderr={stderr:?}");
    // stdout may carry the intro line; only finding lines are ruled out.
    assert!(
        !stdout.contains("pf anchor drift"),
        "substrate failure must abort before findings; stdout={stdout:?}"
    );
    assert!(
        stderr.contains("failed to read pf state"),
        "stderr should frame as firewall-read failure; got: {stderr:?}"
    );
}

// --- Touch-ID-for-sudo (host-wide) ---

#[test]
fn doctor_pam_tid_present_no_finding() {
    // Stub default `/etc/pam.d/sudo` carries `pam_tid.so`.
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
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().with_pam_sudo_content("");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("info: Touch ID for sudo not detected"),
        "expected Touch-ID info finding; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant setup"),
        "finding should point at `tenant setup`; stdout={stdout:?}"
    );
    let count = stdout.matches("Touch ID for sudo not detected").count();
    assert_eq!(count, 1, "expected one Touch-ID line; stdout={stdout:?}");
}

#[test]
fn doctor_pam_tid_in_sudo_local_only_no_finding() {
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new()
        .with_pam_sudo_content("# sudo: auth account password session\n")
        .with_pam_sudo_local_content("auth       sufficient     pam_tid.so\n");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("Touch ID for sudo not detected"),
        "pam_tid in sudo_local must satisfy the check; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pam_tid_in_neither_file_emits_finding() {
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new()
        .with_pam_sudo_content("# sudo: auth account password session\n")
        .with_pam_sudo_local_content("# auth sufficient pam_smartcard.so\n");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("info: Touch ID for sudo not detected"),
        "expected Touch-ID info finding; stdout={stdout:?}"
    );
}

#[test]
fn doctor_empty_sudo_local_is_not_an_error() {
    // Exit 0 (not 74) proves the empty body parsed as "no directive", not a read failure.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new()
        .with_pam_sudo_content("")
        .with_pam_sudo_local_content("");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(
        code, 0,
        "empty sudo_local must not abort; stderr={stderr:?}"
    );
    assert!(
        stdout.contains("info: Touch ID for sudo not detected"),
        "expected Touch-ID info finding; stdout={stdout:?}"
    );
    assert!(
        !stderr.contains("failed to read host config"),
        "empty body is not a read failure; stderr={stderr:?}"
    );
}

#[test]
fn doctor_pam_sudo_local_substrate_failure_routes_to_host_file_failed_frame() {
    // `sudo` lacks pam_tid, so the check falls through to the failing `sudo_local` read.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new()
        .with_pam_sudo_content("")
        .fail_next_pam_sudo_local(tenant::domain::HostFileError::Fs {
            path: "/etc/pam.d/sudo_local".to_string(),
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
        stderr.contains("/etc/pam.d/sudo_local"),
        "stderr should name the failed path; got: {stderr:?}"
    );
}

#[test]
fn doctor_pam_tid_commented_emits_info_finding() {
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
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new()
        .with_pam_sudo_content("")
        .with_present_cowork_dir("dev");
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(code, 0, "Info should not trip --strict; stderr={stderr:?}");
}

#[test]
fn doctor_pam_tid_all_tenants_emits_once() {
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

// --- pfctl-enabled (host-wide) ---

#[test]
fn doctor_pf_enabled_no_finding() {
    // Stub default pf status is "Status: Enabled".
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
    let stub_reader = make_two_tenant_stub_reader();
    let stub_exec = StubHostMachine::new().with_pf_status_content("Status: Disabled\n");
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let count = stdout.matches("pf is globally disabled").count();
    assert_eq!(
        count, 1,
        "all-tenants doctor must emit PfDisabled once; stdout={stdout:?}"
    );
}

#[test]
fn doctor_pf_status_substrate_failure_routes_to_firewall_failed_frame() {
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

// --- Anchor-body drift ---

#[test]
fn doctor_anchor_body_in_sync_no_finding() {
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
    let stub_reader = make_tenant_stub_reader("dev");
    let edited_body = format!(
        "{}# stray operator edit\n",
        tenant::firewall::render_anchor(
            "dev",
            &[],
            tenant::firewall::InboundRules::Restricted(vec![])
        )
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
fn doctor_anchor_body_in_sync_with_declared_inbound_ports_no_finding() {
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&[], &[])
    );
    let synced_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![3000]),
    );
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_anchor_body("dev", &synced_body);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("anchor file drift"),
        "no anchor-body drift expected when on-disk body matches declared ports; stdout={stdout:?}"
    );
    // The inbound-exposure Info finding is the only per-tenant line, so the summary counts one.
    assert!(
        stdout.contains(
            "info: tenant 'dev' inbound loopback open on port 3000 — reachable by host + peer tenants"
        ),
        "declared port should surface as an inbound-exposure info finding; stdout={stdout:?}"
    );
}

// --- Inbound-exposure finding ---

#[test]
fn doctor_inbound_declared_ports_emits_info_finding() {
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&[], &[])
    );
    let synced_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![3000]),
    );
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_anchor_body("dev", &synced_body);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains(
            "info: tenant 'dev' inbound loopback open on port 3000 — reachable by host + peer tenants"
        ),
        "expected inbound-exposure info finding; stdout={stdout:?}"
    );
}

#[test]
fn doctor_inbound_locked_no_finding() {
    // The default profile's empty `[inbound]` is the locked posture.
    let stub_reader = make_tenant_stub_reader("dev");
    let synced_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &synced_body);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("inbound loopback"),
        "locked inbound must emit no finding; stdout={stdout:?}"
    );
    assert_eq!(stdout, "doctor: tenant 'dev' — no per-tenant findings.\n");
}

#[test]
fn doctor_inbound_permissive_anchor_emits_warning() {
    // Profile declares port 3000, but the observed permissive anchor wins.
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = format!(
        "{}\n[inbound]\nports = [\n  3000,\n]\n",
        profile_with_hosts(&[], &[])
    );
    let permissive_body =
        tenant::firewall::render_anchor("dev", &[], tenant::firewall::InboundRules::Permissive);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile)
        .with_anchor_body("dev", &permissive_body);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains(
            "warning: tenant 'dev' inbound loopback is PERMISSIVE — all ports open to host + peer tenants"
        ),
        "expected inbound-permissive warning finding; stdout={stdout:?}"
    );
}

#[test]
fn doctor_inbound_permissive_with_strict_exits_1() {
    let stub_reader = make_tenant_stub_reader("dev");
    let permissive_body =
        tenant::firewall::render_anchor("dev", &[], tenant::firewall::InboundRules::Permissive);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &permissive_body);
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_anchor_body_profile_drift_emits_warning() {
    let stub_reader = make_tenant_stub_reader("dev");
    let new_profile = profile_with_hosts(&["example.com"], &[]);
    let stale_body = tenant::firewall::render_anchor(
        "dev",
        &[],
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
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
fn doctor_flags_drift_when_profile_declares_extra_ports_not_in_anchor() {
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = "schema_version = 1\n\
                   \n\
                   [allowlist.runtime]\n\
                   hosts = [{ host = \"github.com\", ports = [443, 22] }]\n\
                   \n\
                   [allowlist.install]\n\
                   hosts = []\n";
    let stale_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["github.com"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
    );
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", profile)
        .with_anchor_body("dev", &stale_body);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("tenant 'dev' anchor file drift"),
        "extra-port profile edit without reload must surface AnchorBodyDrift; stdout={stdout:?}"
    );
}

#[test]
fn doctor_anchor_body_drift_with_strict_exits_1() {
    let stub_reader = make_tenant_stub_reader("dev");
    let edited_body = format!(
        "{}# stray\n",
        tenant::firewall::render_anchor(
            "dev",
            &[],
            tenant::firewall::InboundRules::Restricted(vec![])
        )
    );
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
    let stub_reader = make_tenant_stub_reader("dev");
    // No `with_existing_profile` → read_profile returns an error.
    let stub_exec = StubHostMachine::new().with_present_cowork_dir("dev");
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
    let stub_reader = make_two_tenant_stub_reader();
    let default = tenant::profile::default_profile_toml();
    let edited = format!(
        "{}# stray\n",
        tenant::firewall::render_anchor(
            "dev",
            &[],
            tenant::firewall::InboundRules::Restricted(vec![])
        )
    );
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
    let stub_reader = make_tenant_stub_reader("dev");
    let edited = format!(
        "{}# stray\n",
        tenant::firewall::render_anchor(
            "dev",
            &[],
            tenant::firewall::InboundRules::Restricted(vec![])
        )
    );
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
    let stub_reader = make_tenant_stub_reader("dev");
    let profile = profile_with_hosts(&["runtime.example.com"], &["install.example.com"]);
    let install_tier_body = tenant::firewall::render_anchor(
        "dev",
        &common::egress(&["runtime.example.com", "install.example.com"]),
        tenant::firewall::InboundRules::Restricted(vec![]),
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

// --- Finding guidance (verbose) ---

#[test]
fn doctor_standard_mode_omits_guidance_block() {
    let stub_reader = make_tenant_stub_reader("dev");
    let edited = format!(
        "{}# stray\n",
        tenant::firewall::render_anchor(
            "dev",
            &[],
            tenant::firewall::InboundRules::Restricted(vec![])
        )
    );
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
    let stub_reader = make_tenant_stub_reader("dev");
    let edited = format!(
        "{}# stray\n",
        tenant::firewall::render_anchor(
            "dev",
            &[],
            tenant::firewall::InboundRules::Restricted(vec![])
        )
    );
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
    assert!(
        stdout.contains("  tenant mode dev runtime\n"),
        "guidance should name the literal tenant 'dev' in the fix command; stdout={stdout:?}"
    );
}

#[test]
fn doctor_verbose_filesystem_exposure_omits_guidance_block() {
    // Profile and anchor body seeded in sync so FilesystemExposure is the only finding.
    let stub_reader = make_tenant_stub_reader("dev");
    let target = std::path::PathBuf::from(format!("/Users/{TEST_HOST}/.ssh/id_rsa"));
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body(
            "dev",
            &tenant::firewall::render_anchor(
                "dev",
                &[],
                tenant::firewall::InboundRules::Restricted(vec![]),
            ),
        )
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
    // Host-wide findings (PfDisabled) emit before per-tenant ones (AnchorBodyDrift).
    let stub_reader = make_tenant_stub_reader("dev");
    let edited = format!(
        "{}# stray\n",
        tenant::firewall::render_anchor(
            "dev",
            &[],
            tenant::firewall::InboundRules::Restricted(vec![])
        )
    );
    let stub_exec = StubHostMachine::new()
        .with_pf_status_content("Status: Disabled\n")
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_anchor_body("dev", &edited);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    let pf_disabled_one_liner = stdout
        .find("critical: pf is globally disabled")
        .expect("PfDisabled one-liner should be present");
    // Phrases unique to each finding's guidance body.
    let pf_disabled_guidance = stdout
        .find("  Enables pf globally")
        .expect("PfDisabled guidance body should be present");
    let anchor_one_liner = stdout
        .find("warning: tenant 'dev' anchor file drift")
        .expect("AnchorBodyDrift one-liner should be present");
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
    // Pins key words, not byte-exact wording.
    let (code, stdout, stderr) = run_with(StubUserDirectory::default(), &["doctor", "--help"]);
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

// --- AclDrift on declared shares (symlink kinds pre-loaded so only AclDrift fires) ---

#[test]
fn doctor_share_acl_present_no_finding() {
    // Default stub ACL listing carries the share-group entry.
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
    // /Users/Shared/data falls through to the default listing, which has the entry.
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
    // DryRunHostMachine's profile has no `[[shares]]`, so this holds regardless of the stub.
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
    let stub_reader = make_tenant_stub_reader("dev");
    // No `with_existing_profile` → read_profile returns an error.
    let stub_exec = StubHostMachine::new().with_present_cowork_dir("dev");
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
    // read_host_acl runs first per share and aborts the walk, so no symlink kind is needed.
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
    let stub_reader = make_two_tenant_stub_reader();
    let profile_dev = profile_with_shares(&[], &[], &[("/Users/Shared/src", "rw", "$HOME/src")]);
    let profile_staging =
        profile_with_shares(&[], &[], &[("/Users/Shared/data", "ro", "$HOME/data")]);
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile_dev)
        .with_existing_profile("staging", &profile_staging)
        // staging's path falls through to the default listing, which has its entry.
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

// --- SymlinkDrift on declared shares (ACL silenced by the default listing) ---

#[test]
fn doctor_share_symlink_absent_emits_warning() {
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
    // DryRunHostMachine's profile has no `[[shares]]`, so this holds regardless of the stub.
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
    // Smoke test; tests/doctor.rs pins the full guidance bodies.
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

// --- HostNotInShareGroup ---

#[test]
fn doctor_emits_host_not_in_share_group_when_membership_missing() {
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
    // Stub default: host_in_group answers true.
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
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new()
        .with_host_in_group("operator", "dev-tenant-share", false)
        .with_present_cowork_dir("dev");
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_no_arg_emits_host_not_in_share_group_per_tenant() {
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
    // Smoke test; tests/doctor.rs pins the full guidance body.
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
fn doctor_single_tenant_surfaces_user_directory_error_when_eligibility_probe_fails() {
    let stub = StubUserDirectory {
        fail_has_user: directory_fail_once(),
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
fn doctor_all_surfaces_user_directory_error_when_tenant_enumeration_fails() {
    // Host-wide checks run before enumeration, so the host machine must not fail.
    let exec = StubHostMachine::new();
    let stub = StubUserDirectory {
        fail_tenant_names: directory_fail_once(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with_exec(stub, &exec, &["doctor"]);
    assert_eq!(code, 74);
    assert!(
        stderr.contains("tenant: failed to enumerate tenants for doctor: "),
        "expected doctor_enumeration_failed frame; stderr={stderr:?}"
    );
}

// --- Tenant keychain + operator stash ---

#[test]
fn doctor_tenant_keychain_absent_emits_warning() {
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().with_tenant_keychain_present("dev", false);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' keychain absent"),
        "expected TenantKeychainAbsent warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("apps inside the tenant won't be able to persist credentials"),
        "warning should name the operator impact; stdout={stdout:?}"
    );
}

#[test]
fn doctor_tenant_keychain_present_emits_no_warning() {
    // Stub default: tenant_keychain_present answers true.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("keychain absent"),
        "no TenantKeychainAbsent finding expected; stdout={stdout:?}"
    );
}

#[test]
fn doctor_stash_absent_emits_warning() {
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().with_stash_present("dev", false);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: stashed password absent for tenant 'dev'"),
        "expected StashAbsent warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant destroy dev && tenant create dev"),
        "warning should name the recovery; stdout={stdout:?}"
    );
}

#[test]
fn doctor_stash_present_emits_no_warning() {
    // Stub default: stash_present answers true.
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new();
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        !stdout.contains("stashed password absent"),
        "no StashAbsent finding expected; stdout={stdout:?}"
    );
}

#[test]
fn doctor_strict_keychain_warning_exits_1() {
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().with_tenant_keychain_present("dev", false);
    let (code, _stdout, stderr) =
        run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "--strict"]);
    assert_eq!(
        code, 1,
        "expected exit 1 on warning+strict; stderr={stderr:?}"
    );
}

#[test]
fn doctor_keychain_findings_carry_guidance_in_verbose() {
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new()
        .with_tenant_keychain_present("dev", false)
        .with_stash_present("dev", false);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev", "-v"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("Why this matters"),
        "verbose should emit guidance block header; stdout={stdout:?}"
    );
    assert!(
        stdout.contains(
            "sudo -iu dev security create-keychain -p \"$(security find-generic-password -a dev -s tenant-dev -w)\" tenant.keychain-db"
        ),
        "keychain-absent guidance should name the recreate recipe; stdout={stdout:?}"
    );
    let recovery_count = stdout
        .matches("tenant destroy dev && tenant create dev")
        .count();
    assert_eq!(
        recovery_count, 3,
        "stash one-liner + stash guidance + keychain-absent alternative; stdout={stdout:?}"
    );
}

#[test]
fn doctor_tenant_keychain_probe_failure_surfaces_and_walk_continues() {
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec = StubHostMachine::new().fail_next_tenant_keychain_probe(
        tenant::domain::ProbeError::Spawn(std::io::Error::other("stat failed")),
    );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "audit-as-courtesy: probe failure does not abort");
    assert!(
        !stdout.contains("keychain absent"),
        "no finding emits when the probe itself failed; stdout={stdout:?}"
    );
    assert!(
        stderr.contains("failed to probe tenant 'dev' keychain presence"),
        "stderr should carry the probe-failed frame; got: {stderr:?}"
    );
}

#[test]
fn doctor_stash_probe_failure_surfaces_and_walk_continues() {
    let stub_reader = make_tenant_stub_reader("dev");
    let stub_exec =
        StubHostMachine::new().fail_next_stash_probe(tenant::domain::KeychainError::NonZero {
            code: 1,
            stderr: "security: argv parse failed".to_string(),
        });
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "audit-as-courtesy: probe failure does not abort");
    assert!(
        !stdout.contains("stashed password absent"),
        "no finding emits when the probe itself failed; stdout={stdout:?}"
    );
    assert!(
        stderr.contains("failed to probe stash presence for tenant 'dev'"),
        "stderr should carry the stash-probe-failed frame; got: {stderr:?}"
    );
}

// --- Cowork-dir drift ---

#[test]
fn doctor_cowork_acl_missing_emits_warning() {
    let stub_reader = make_tenant_stub_reader("dev");
    let cowork_path = std::path::PathBuf::from("/Users/Shared/tenants/dev");
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_acl(
            &cowork_path,
            // Operator ACE only; no group:dev-tenant-share entry.
            " 0: user:operator allow list,add_file,search\n",
        );
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' co-working directory ACL drift"),
        "expected CoworkAclDrift warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("dev-tenant-share"),
        "CoworkAclDrift should name the expected group; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("/Users/Shared/tenants/dev"),
        "CoworkAclDrift should name the drifted cowork path; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant reload dev"),
        "CoworkAclDrift should name the recovery command; stdout={stdout:?}"
    );
}

#[test]
fn doctor_cowork_dir_absent_emits_warning() {
    let stub_reader = make_tenant_stub_reader("dev");
    let cowork_path = std::path::PathBuf::from("/Users/Shared/tenants/dev");
    let stub_exec = StubHostMachine::new()
        .with_existing_profile("dev", &tenant::profile::default_profile_toml())
        .with_host_path_kind(&cowork_path, PathKind::Absent);
    let (code, stdout, stderr) = run_with_exec(stub_reader, &stub_exec, &["doctor", "dev"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stdout.contains("warning: tenant 'dev' co-working directory missing"),
        "expected CoworkDirAbsent warning; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("/Users/Shared/tenants/dev"),
        "CoworkDirAbsent should name the missing cowork path; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("tenant reload dev"),
        "CoworkDirAbsent should name the recovery command; stdout={stdout:?}"
    );
    // Absence short-circuits the ACL probe, so no AclDrift.
    assert!(
        !stdout.contains("co-working directory ACL drift"),
        "absence must short-circuit the ACL probe; stdout={stdout:?}"
    );
}
