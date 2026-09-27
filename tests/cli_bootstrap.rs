use tenant::domain::{AccountError, FirewallError, FirewallOp};
use tenant::firewall::{InboundRules, render_anchor};

mod adapters;
mod common;
use adapters::*;
use common::*;

fn install_tier_body(name: &str, runtime: &[&str], install: &[&str]) -> String {
    let mut hosts = egress(runtime);
    hosts.extend(egress(install));
    render_anchor(name, &hosts, InboundRules::Restricted(vec![]))
}

fn runtime_tier_body(name: &str, runtime: &[&str]) -> String {
    render_anchor(name, &egress(runtime), InboundRules::Restricted(vec![]))
}

fn sh_c(command: &str) -> Vec<String> {
    vec!["/bin/sh".to_string(), "-c".to_string(), command.to_string()]
}

#[test]
fn bootstrap_runs_merged_fragment_and_profile_commands_in_order() {
    let fragment = "[bootstrap]\ncommands = [\"frag-cmd\"]\n[allowlist.runtime]\nhosts = []\n";
    let profile = "schema_version = 1\n\
                   include = [\"base\"]\n\
                   [allowlist.runtime]\n\
                   hosts = []\n\
                   [allowlist.install]\n\
                   hosts = []\n\
                   [bootstrap]\n\
                   commands = [\"prof-cmd\"]\n";
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", profile)
        .with_profile_fragment("base", fragment)
        .with_default_stash("alice");
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.exec_calls(),
        vec![
            ("alice".to_string(), sh_c("frag-cmd")),
            ("alice".to_string(), sh_c("prof-cmd")),
        ],
        "merged commands must run fragment-first, in order, via /bin/sh -c"
    );
}

#[test]
fn bootstrap_widens_to_install_then_narrows_to_runtime_around_commands() {
    let profile = profile_with_bootstrap(&["r.example"], &["i.example"], &["echo hi"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice");
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "alice".into(),
                body: install_tier_body("alice", &["r.example"], &["i.example"]),
            },
            FirewallOp::Reload,
            FirewallOp::InstallAnchor {
                name: "alice".into(),
                body: runtime_tier_body("alice", &["r.example"]),
            },
            FirewallOp::Reload,
        ],
        "bootstrap must widen to install tier, then narrow back to runtime"
    );
    assert_eq!(
        exec.exec_calls(),
        vec![("alice".to_string(), sh_c("echo hi"))],
        "the command runs between widen and narrow"
    );
}

#[test]
fn bootstrap_stops_on_first_failing_command_but_still_narrows() {
    let profile = profile_with_bootstrap(&["r.example"], &["i.example"], &["ok1", "boom", "never"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice")
        .with_exec_exit_codes(&[0, 3]);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(code, 74, "first failing command must exit EX_IOERR");
    assert_eq!(
        exec.exec_calls(),
        vec![
            ("alice".to_string(), sh_c("ok1")),
            ("alice".to_string(), sh_c("boom")),
        ],
        "the loop must stop after the first non-zero exit (third command never runs)"
    );
    let fw = exec.firewall_ops();
    assert_eq!(
        &fw[fw.len() - 2..],
        &[
            FirewallOp::InstallAnchor {
                name: "alice".into(),
                body: runtime_tier_body("alice", &["r.example"]),
            },
            FirewallOp::Reload,
        ],
        "narrow-on-finally must run even after a command fails; ops={fw:?}"
    );
    assert!(
        stderr.contains("boom") && stderr.contains("exit 3"),
        "stderr must name the failing command + code: {stderr:?}"
    );
}

#[test]
fn bootstrap_no_commands_is_quiet_success_with_zero_exec() {
    let profile = profile_with_bootstrap(&["r.example"], &[], &[]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice");
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        stdout,
        "Tenant 'alice' declares no bootstrap commands \u{2014} nothing to run.\n"
    );
    assert!(
        exec.exec_calls().is_empty() && exec.firewall_ops().is_empty(),
        "no-command tenant must not widen/narrow or exec: exec={:?} fw={:?}",
        exec.exec_calls(),
        exec.firewall_ops()
    );
}

#[test]
fn bootstrap_summary_lists_commands_verbatim_and_abort_skips_exec() {
    // Commands render verbatim in the summary even without `-v`.
    let profile = profile_with_bootstrap(
        &[],
        &[],
        &["command -v rg || brew install ripgrep", "echo done"],
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice");
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("alice"),
        &exec,
        &["bootstrap", "alice"],
        b"n\n",
    );
    assert_eq!(code, 0, "abort exits 0");
    assert!(
        stdout.contains("About to run 2 bootstrap command(s) as tenant 'alice'."),
        "summary must state the count: {stdout:?}"
    );
    assert!(
        stdout.contains("command -v rg || brew install ripgrep") && stdout.contains("echo done"),
        "summary must render every command verbatim: {stdout:?}"
    );
    assert!(
        stdout.contains("Aborted by operator. No changes made."),
        "abort line expected: {stdout:?}"
    );
    assert!(
        exec.exec_calls().is_empty() && exec.firewall_ops().is_empty(),
        "abort must skip all substrate work: exec={:?} fw={:?}",
        exec.exec_calls(),
        exec.firewall_ops()
    );
}

#[test]
fn bootstrap_pre_exec_doctor_aggregates_warning_and_never_aborts() {
    let profile = profile_with_bootstrap(&[], &[], &["echo hi"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice")
        .with_host_in_group("operator", "alice-tenant-share", false);
    let (code, stdout, _stderr) = run_with_stdin(
        stub_with_tenant("alice"),
        &exec,
        &["bootstrap", "alice", "-y"],
        b"",
    );
    assert_eq!(code, 0, "the audit must not abort the verb");
    let doctor_line = "\u{26a0} Doctor: 1 warning for tenant 'alice' \u{2014} run `tenant doctor alice` for details";
    assert!(
        stdout.contains(doctor_line),
        "drift must surface the aggregate doctor line: {stdout:?}"
    );
    let summary_at = stdout.find("About to run 1 bootstrap command(s)");
    let doctor_at = stdout.find(doctor_line);
    let exec_at = stdout.find("Bootstrapping tenant 'alice'");
    assert!(
        summary_at < doctor_at && doctor_at < exec_at,
        "doctor line must sit between summary and execution: {stdout:?}"
    );
    assert_eq!(
        exec.exec_calls(),
        vec![("alice".to_string(), sh_c("echo hi"))],
        "the verb proceeds past the audit warning"
    );
}

// TODO(smell): DryRunHostMachine::read_profile returns the default profile, so `bootstrap --dry-run` previews nothing even when commands are declared.
#[test]
fn bootstrap_dry_run_bypasses_injected_host_machine() {
    let profile = profile_with_bootstrap(&["r.example"], &["i.example"], &["echo hi"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice");
    let (code, _stdout, _stderr) = run_with_exec(
        stub_with_tenant("alice"),
        &exec,
        &["bootstrap", "alice", "--dry-run"],
    );
    assert_eq!(code, 0);
    assert!(
        exec.exec_calls().is_empty() && exec.firewall_ops().is_empty() && exec.logins().is_empty(),
        "dry-run must not touch the injected host machine: exec={:?} fw={:?} logins={:?}",
        exec.exec_calls(),
        exec.firewall_ops(),
        exec.logins(),
    );
}

#[test]
fn bootstrap_refuses_when_stash_absent_and_narrows_back() {
    let profile = profile_with_bootstrap(&["r.example"], &["i.example"], &["echo hi"]);
    // NO with_default_stash: find_stashed_password returns NotFound.
    let exec = StubHostMachine::new().with_existing_profile("alice", &profile);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(
        code, 64,
        "stash-absent is operator-action-required (EX_USAGE)"
    );
    assert_eq!(
        stderr,
        "tenant: refusing to bootstrap 'alice': stashed password absent \
         \u{2014} run `tenant destroy alice && tenant create alice` to re-bootstrap\n"
    );
    assert!(
        exec.exec_calls().is_empty(),
        "no command runs when the keychain stash is absent: {:?}",
        exec.exec_calls()
    );
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "alice".into(),
                body: install_tier_body("alice", &["r.example"], &["i.example"]),
            },
            FirewallOp::Reload,
            FirewallOp::InstallAnchor {
                name: "alice".into(),
                body: runtime_tier_body("alice", &["r.example"]),
            },
            FirewallOp::Reload,
        ],
        "widen must narrow back on stash-absent — not strand install tier"
    );
}

#[test]
fn bootstrap_exec_spawn_failure_exits_74_and_narrows() {
    let profile = profile_with_bootstrap(&["r.example"], &["i.example"], &["echo hi"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice")
        .fail_next_exec(AccountError::Spawn(std::io::Error::other("synthetic")));
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(code, 74, "exec spawn failure exits EX_IOERR");
    assert!(
        stderr.contains("failed to run bootstrap command as 'alice'"),
        "spawn-failure frame expected: {stderr:?}"
    );
    let fw = exec.firewall_ops();
    assert_eq!(
        &fw[fw.len() - 2..],
        &[
            FirewallOp::InstallAnchor {
                name: "alice".into(),
                body: runtime_tier_body("alice", &["r.example"]),
            },
            FirewallOp::Reload,
        ],
        "narrow must run after a spawn failure; ops={fw:?}"
    );
}

#[test]
fn bootstrap_widen_execute_failure_exits_74_no_exec() {
    let profile = profile_with_bootstrap(&["r.example"], &["i.example"], &["echo hi"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice")
        .fail_next_firewall(FirewallError::NonZero {
            code: 1,
            stderr: "synthetic".to_string(),
        });
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(code, 74, "widen-execute failure exits EX_IOERR");
    assert!(
        exec.exec_calls().is_empty(),
        "no command runs when the widen fails: {:?}",
        exec.exec_calls()
    );
    assert_eq!(
        exec.firewall_ops(),
        vec![
            FirewallOp::InstallAnchor {
                name: "alice".into(),
                body: install_tier_body("alice", &["r.example"], &["i.example"]),
            },
            FirewallOp::InstallAnchor {
                name: "alice".into(),
                body: runtime_tier_body("alice", &["r.example"]),
            },
            FirewallOp::Reload,
        ],
        "the failed widen is followed by the best-effort narrow"
    );
    assert!(
        stderr.contains("firewall"),
        "widen failure frame should mention firewall: {stderr:?}"
    );
}

#[test]
fn bootstrap_unlocks_keychain_before_commands() {
    let profile = profile_with_bootstrap(&[], &[], &["cmd"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice");
    let (code, stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert_eq!(
        exec.unlock_calls(),
        vec!["alice".to_string()],
        "unlock_tenant_keychain must fire exactly once for the tenant"
    );
    let want = format!(
        "{}\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-alice\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'alice-tenant-share'\n\
         ✓ Tenant 'alice' keychain unlocked\n\
         ✓ Ran as 'alice': cmd\n\
         ✓ Firewall anchor installed at /etc/pf.anchors/tenant-alice\n\
         ✓ Firewall ruleset reloaded\n\
         ✓ Host 'operator' added to share group 'alice-tenant-share'\n\
         {}\n\
         Tenant 'alice' bootstrapped.\n\
         Next: audit with `tenant doctor alice`.\n",
        section_line("Bootstrapping tenant 'alice'"),
        section_line("Done"),
    );
    assert_eq!(stdout, want);
}

#[test]
fn bootstrap_on_cold_sudo_refuses_occupied_tenant_path_before_widening() {
    let profile = profile_with_bootstrap(&[], &[], &["cmd"]);
    let profile = format!(
        "{profile}\n[[shares]]\nhost_path = \"/tmp\"\ntenant_path = \"$HOME/src\"\nmode = \"rw\"\n"
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice")
        .with_sudo_session_cached(false)
        .with_tenant_path_kind(
            "alice",
            &std::path::PathBuf::from("/Users/alice/src"),
            tenant::domain::PathKind::Other,
        );
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("alice"),
        &exec,
        &["bootstrap", "alice"],
        b"",
    );
    assert_eq!(code, 74, "stderr={stderr:?}");
    assert!(
        stderr.contains("cannot bootstrap 'alice'") && stderr.contains("/Users/alice/src"),
        "refuse_bootstrap_share frame expected: {stderr:?}"
    );
    assert!(
        exec.firewall_ops().is_empty(),
        "refusal must precede the install-tier widen: {:?}",
        exec.firewall_ops()
    );
    assert!(exec.exec_calls().is_empty());
    assert_eq!(
        exec.tenant_path_kind_calls().len(),
        1,
        "refused at plan build: nothing executed, so no narrow-back re-probe"
    );
}

#[test]
fn bootstrap_on_cold_sudo_authentication_failure_exits_74_without_mutation() {
    let profile = profile_with_bootstrap(&[], &[], &["cmd"]);
    let profile = format!(
        "{profile}\n[[shares]]\nhost_path = \"/tmp\"\ntenant_path = \"$HOME/src\"\nmode = \"rw\"\n"
    );
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice")
        .with_sudo_session_cached(false)
        .fail_next_authenticate_sudo(tenant::domain::ProbeError::NonZero {
            code: 1,
            stderr: String::new(),
        });
    let (code, _stdout, stderr) = run_with_stdin(
        stub_with_tenant("alice"),
        &exec,
        &["bootstrap", "alice"],
        b"",
    );
    assert_eq!(code, 74);
    assert_eq!(
        stderr,
        "tenant: failed to probe host state for 'alice': probe exited with code 1\n"
    );
    assert_eq!(
        exec.authenticate_sudo_calls(),
        1,
        "authenticates exactly once"
    );
    assert!(exec.tenant_path_kind_calls().is_empty() && exec.exec_calls().is_empty());
    assert!(
        exec.firewall_ops().is_empty() && exec.account_ops().is_empty(),
        "plan build failed, so nothing mutated: fw={:?} account={:?}",
        exec.firewall_ops(),
        exec.account_ops()
    );
}

#[test]
fn bootstrap_unlock_failure_exits_74() {
    // Stash present (find succeeds); the in-tenant unlock itself fails.
    let profile = profile_with_bootstrap(&["r.example"], &["i.example"], &["echo hi"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice")
        .fail_next_unlock_tenant_keychain(tenant::domain::KeychainError::NonZero {
            code: 1,
            stderr: "synthetic".to_string(),
        });
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(code, 74, "unlock substrate failure exits EX_IOERR");
    assert!(
        stderr.contains("failed to unlock keychain for 'alice'"),
        "unlock-failure frame expected: {stderr:?}"
    );
    assert!(
        exec.exec_calls().is_empty(),
        "no command runs when the keychain unlock fails: {:?}",
        exec.exec_calls()
    );
}

#[test]
fn bootstrap_narrow_failure_after_success_warns_and_exits_74() {
    let profile = profile_with_bootstrap(&["r.example"], &["i.example"], &["echo hi"]);
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", &profile)
        .with_default_stash("alice")
        // Matches only the narrow's runtime body; the widen's install body differs.
        .fail_firewall_op(
            FirewallOp::InstallAnchor {
                name: "alice".into(),
                body: runtime_tier_body("alice", &["r.example"]),
            },
            FirewallError::NonZero {
                code: 1,
                stderr: "synthetic".to_string(),
            },
        );
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(code, 74, "narrow failure after success exits EX_IOERR");
    assert_eq!(
        exec.exec_calls(),
        vec![("alice".to_string(), sh_c("echo hi"))],
        "the command DID run before the narrow failed"
    );
    assert!(
        stderr.contains("\u{26a0}")
            && stderr.contains("bootstrap commands ran")
            && stderr.contains("tenant mode alice runtime"),
        "⚠ must confirm commands ran and name the recovery verb: {stderr:?}"
    );
}

#[test]
fn bootstrap_refuses_invalid_name() {
    let (code, _stdout, stderr) =
        run_with(StubUserDirectory::default(), &["bootstrap", "Bad_Name"]);
    assert_eq!(code, 64);
    assert!(stderr.contains("Bad_Name"), "stderr={stderr:?}");
}

#[test]
fn bootstrap_refuses_absent_tenant() {
    let (code, _stdout, stderr) = run_with(StubUserDirectory::default(), &["bootstrap", "ghost"]);
    assert_eq!(code, 64);
    assert_eq!(stderr, "tenant: cannot bootstrap 'ghost': does not exist\n");
}

#[test]
fn bootstrap_refuses_below_floor_uid() {
    use tenant::domain::UserId;
    let reader = StubUserDirectory {
        users: vec!["legacyusr".to_string()],
        uid_by_name: [("legacyusr".to_string(), UserId(0))].into_iter().collect(),
        ..Default::default()
    };
    let (code, _stdout, stderr) = run_with(reader, &["bootstrap", "legacyusr"]);
    assert_eq!(code, 64);
    assert_eq!(
        stderr,
        "tenant: refusing to bootstrap 'legacyusr': UID 0 is below tenant floor 600\n"
    );
}

#[test]
fn bootstrap_missing_fragment_surfaces_pre_prompt() {
    let profile = "schema_version = 1\n\
                   include = [\"ghostfrag\"]\n\
                   [allowlist.runtime]\n\
                   hosts = []\n\
                   [allowlist.install]\n\
                   hosts = []\n\
                   [bootstrap]\n\
                   commands = [\"echo hi\"]\n";
    // No with_profile_fragment("ghostfrag"): the read fails.
    let exec = StubHostMachine::new()
        .with_existing_profile("alice", profile)
        .with_default_stash("alice");
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("alice"), &exec, &["bootstrap", "alice"]);
    assert_eq!(
        code, 74,
        "missing fragment is a substrate failure (EX_IOERR)"
    );
    assert!(
        stderr.contains("ghostfrag"),
        "error must name the missing fragment: {stderr:?}"
    );
    assert!(
        exec.exec_calls().is_empty() && exec.firewall_ops().is_empty(),
        "nothing runs when the plan build fails: exec={:?} fw={:?}",
        exec.exec_calls(),
        exec.firewall_ops()
    );
}

// --- No-arg fleet walk ---

#[test]
fn bootstrap_no_arg_walks_every_tenant() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile_with_bootstrap(&[], &[], &["echo dev"]))
        .with_existing_profile(
            "staging",
            &profile_with_bootstrap(&[], &[], &["echo staging"]),
        )
        .with_default_stash("dev")
        .with_default_stash("staging");
    let (code, stdout, stderr) =
        run_with_exec(make_two_tenant_stub_reader(), &exec, &["bootstrap"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    // Alphabetical order: dev before staging.
    assert_eq!(
        exec.exec_calls(),
        vec![
            ("dev".to_string(), sh_c("echo dev")),
            ("staging".to_string(), sh_c("echo staging")),
        ],
        "the walk runs each tenant's commands"
    );
    assert!(
        stdout.contains("Bootstrapped 2 tenant(s).\n"),
        "expected fleet summary line: {stdout:?}"
    );
}

#[test]
fn bootstrap_no_arg_continues_past_a_failing_tenant() {
    // dev has no profile preloaded, so its plan-build fails.
    let exec = StubHostMachine::new()
        .with_existing_profile(
            "staging",
            &profile_with_bootstrap(&[], &[], &["echo staging"]),
        )
        .with_default_stash("staging");
    let (code, stdout, stderr) =
        run_with_exec(make_two_tenant_stub_reader(), &exec, &["bootstrap"]);
    assert_eq!(code, 74, "any per-tenant failure exits EX_IOERR");
    assert!(
        stderr.contains("'dev'"),
        "dev's failure must surface: {stderr:?}"
    );
    assert_eq!(
        exec.exec_calls(),
        vec![("staging".to_string(), sh_c("echo staging"))],
        "the walk continues to staging after dev fails"
    );
    assert!(
        stdout.contains("Bootstrapped 1 tenant(s); 1 failed.\n"),
        "expected 1-of-2 summary: {stdout:?}"
    );
}

#[test]
fn bootstrap_no_arg_continues_past_a_stash_absent_tenant() {
    // A bootstrap()-level refusal, unlike the sibling test's plan-build failure.
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile_with_bootstrap(&[], &[], &["echo dev"]))
        .with_existing_profile(
            "staging",
            &profile_with_bootstrap(&[], &[], &["echo staging"]),
        )
        // dev: NO stash. staging: stash present.
        .with_default_stash("staging");
    let (code, stdout, stderr) =
        run_with_exec(make_two_tenant_stub_reader(), &exec, &["bootstrap"]);
    assert_eq!(code, 74, "the stash-absent tenant fails the walk");
    assert!(
        stderr.contains("refusing to bootstrap 'dev'"),
        "dev's stash-absent refusal must surface: {stderr:?}"
    );
    assert_eq!(
        exec.exec_calls(),
        vec![("staging".to_string(), sh_c("echo staging"))],
        "the walk continues to staging after dev refuses"
    );
    assert!(
        stdout.contains("Bootstrapped 1 tenant(s); 1 failed.\n"),
        "expected 1-of-2 summary: {stdout:?}"
    );
}

#[test]
fn bootstrap_no_arg_skips_no_command_tenants() {
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", &profile_with_bootstrap(&[], &[], &["echo dev"]))
        .with_existing_profile("staging", &profile_with_bootstrap(&[], &[], &[]))
        .with_default_stash("dev");
    let (code, stdout, stderr) =
        run_with_exec(make_two_tenant_stub_reader(), &exec, &["bootstrap"]);
    assert_eq!(
        code, 0,
        "a no-command tenant is not a failure; stderr={stderr:?}"
    );
    assert_eq!(
        exec.exec_calls(),
        vec![("dev".to_string(), sh_c("echo dev"))],
        "only the command-declaring tenant runs"
    );
    assert!(
        stdout.contains("Bootstrapped 1 tenant(s); 1 skipped (no commands).\n"),
        "summary must count the skip: {stdout:?}"
    );
}

#[test]
fn bootstrap_no_arg_no_tenants_is_quiet_noop() {
    let (code, stdout, _stderr) = run_with(StubUserDirectory::default(), &["bootstrap"]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "No tenants on this host to bootstrap.\n");
}

#[test]
fn bootstrap_without_terminal_on_cold_sudo_refuses_before_widening() {
    let profile = "schema_version = 1\n\
                   [allowlist.runtime]\n\
                   hosts = []\n\
                   [allowlist.install]\n\
                   hosts = []\n\
                   [bootstrap]\n\
                   commands = [\"true\"]\n\
                   [[shares]]\n\
                   host_path = \"/tmp\"\n\
                   mode = \"rw\"\n\
                   tenant_path = \"$HOME/src\"\n";
    let exec = StubHostMachine::new()
        .with_existing_profile("dev", profile)
        .with_default_stash("dev")
        .with_sudo_session_cached(false);
    let (code, _stdout, stderr) =
        run_with_exec(stub_with_tenant("dev"), &exec, &["bootstrap", "dev"]);
    assert_eq!(code, 64, "stderr={stderr:?}");
    assert_eq!(stderr, SUDO_NEEDS_TERMINAL_REFUSAL);
    assert_eq!(
        exec.authenticate_sudo_calls(),
        0,
        "sudo -v would block on the prompt"
    );
    assert!(exec.firewall_ops().is_empty() && exec.exec_calls().is_empty());
}
