// Shared helpers for per-verb integration-test files. Each `tests/cli_*.rs`
// declares `mod common;` and pulls these in via `use common::*;`. Cargo
// treats this `mod.rs` under a directory as a non-binary module (it doesn't
// try to run it as its own test binary). Because individual cli_*.rs files
// only use a subset of these helpers, `#![allow(dead_code)]` keeps the
// per-binary unused-item warnings quiet.

#![allow(dead_code)]

use tenant::accounts::StubReader;
use tenant::executor::{
    AccountError, AccountOp, Executor, FirewallError, FirewallOp, ProfileOp, StubExecutor,
};

/// Default executor for tests that should not reach the exec stage —
/// validation failures, conflicts, and dry-run paths. Panics on any
/// substrate call, so any accidental invocation from a path that's
/// meant to be no-op surfaces loudly instead of being silently absorbed.
pub struct NeverExecutor;
impl Executor for NeverExecutor {
    fn describe_account(&self, op: &AccountOp) -> String {
        panic!("executor unexpectedly invoked (describe_account) with op: {op:?}");
    }
    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        panic!("executor unexpectedly invoked (execute_account) with op: {op:?}");
    }
    fn login(&self, name: &str) -> Result<i32, AccountError> {
        panic!("executor unexpectedly invoked (login) with name: {name:?}");
    }
    fn describe_profile(&self, op: &ProfileOp) -> String {
        panic!("executor unexpectedly invoked (describe_profile) with op: {op:?}");
    }
    fn execute_profile(&self, op: &ProfileOp) -> Result<(), tenant::profile::ProfileError> {
        panic!("executor unexpectedly invoked (execute_profile) with op: {op:?}");
    }
    fn read_profile(&self, name: &str) -> Result<String, tenant::profile::ProfileError> {
        panic!("executor unexpectedly invoked (read_profile) with name: {name:?}");
    }
    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        panic!("executor unexpectedly invoked (read_pf_conf)");
    }
    fn describe_firewall(&self, op: &FirewallOp) -> String {
        panic!("executor unexpectedly invoked (describe_firewall) with op: {op:?}");
    }
    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError> {
        panic!("executor unexpectedly invoked (execute_firewall) with op: {op:?}");
    }
    fn probe_access_as_tenant(
        &self,
        name: &str,
        path: &std::path::Path,
        mode: tenant::executor::AccessMode,
    ) -> Result<tenant::executor::AccessOutcome, tenant::executor::ProbeError> {
        panic!(
            "executor unexpectedly invoked (probe_access_as_tenant): name={name:?} path={path:?} mode={mode:?}"
        );
    }
    fn read_env_policy(&self) -> Result<String, tenant::executor::HostFileError> {
        panic!("executor unexpectedly invoked (read_env_policy)");
    }
    fn read_kernel_pf_rules(&self, name: &str) -> Result<String, tenant::executor::FirewallError> {
        panic!("executor unexpectedly invoked (read_kernel_pf_rules): name={name:?}");
    }
    fn read_pam_sudo(&self) -> Result<String, tenant::executor::HostFileError> {
        panic!("executor unexpectedly invoked (read_pam_sudo)");
    }
    fn read_pf_status(&self) -> Result<String, tenant::executor::FirewallError> {
        panic!("executor unexpectedly invoked (read_pf_status)");
    }
    fn read_anchor_body(&self, name: &str) -> Result<String, tenant::executor::HostFileError> {
        panic!("executor unexpectedly invoked (read_anchor_body): name={name:?}");
    }
    fn describe_acl(&self, op: &tenant::executor::AclOp) -> String {
        panic!("executor unexpectedly invoked (describe_acl) with op: {op:?}");
    }
    fn execute_acl(&self, op: &tenant::executor::AclOp) -> Result<(), tenant::executor::AclError> {
        panic!("executor unexpectedly invoked (execute_acl) with op: {op:?}");
    }
    fn tenant_path_kind(
        &self,
        name: &str,
        path: &std::path::Path,
    ) -> Result<tenant::executor::PathKind, tenant::executor::ProbeError> {
        panic!("executor unexpectedly invoked (tenant_path_kind): name={name:?} path={path:?}");
    }
    fn read_host_acl(
        &self,
        path: &std::path::Path,
    ) -> Result<String, tenant::executor::ProbeError> {
        panic!("executor unexpectedly invoked (read_host_acl): path={path:?}");
    }
}

/// Host identity passed to `tenant::run`. Production reads `$USER`; tests
/// use a fixed placeholder so the doctor-verb's curated path expansion
/// (`/Users/<host>/...`) is deterministic across test runs.
pub const TEST_HOST: &str = "operator";

pub fn run_with(stub: StubReader, args: &[&str]) -> (u8, String, String) {
    let exec = NeverExecutor;
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let code = tenant::run(&args, &stub, &exec, TEST_HOST, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

pub fn run_with_exec(stub: StubReader, exec: &StubExecutor, args: &[&str]) -> (u8, String, String) {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let code = tenant::run(&args, &stub, exec, TEST_HOST, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// Stub representing a tenant that exists on the host with a tenant-range
/// UID (for tests that drive the destroy verb's actual-destroy path rather
/// than its noop / refusal paths). UID 600 is the canonical floor; any
/// floor-or-above UID would do.
pub fn stub_with_tenant(name: &str) -> StubReader {
    StubReader {
        users: vec![name.to_string()],
        uid_by_name: [(name.to_string(), 600)].into_iter().collect(),
        ..Default::default()
    }
}

/// Helper: profile TOML with the given runtime + install host lists
/// AND a `[[shares]]` block for cycle-10 share-reapply tests. Each
/// share triple is `(host_path, mode, tenant_path)`; mode is "ro" or
/// "rw" verbatim from the schema. Empty `shares` slice produces no
/// `[[shares]]` blocks (backward-compat with cycle-9-era profiles).
pub fn profile_with_shares(
    runtime: &[&str],
    install: &[&str],
    shares: &[(&str, &str, &str)],
) -> String {
    let base = profile_with_hosts(runtime, install);
    if shares.is_empty() {
        return base;
    }
    let share_blocks: String = shares
        .iter()
        .map(|(host_path, mode, tenant_path)| {
            format!(
                "\n[[shares]]\nhost_path = \"{host_path}\"\nmode = \"{mode}\"\ntenant_path = \"{tenant_path}\"\n"
            )
        })
        .collect();
    format!("{base}{share_blocks}")
}

/// Helper: profile TOML with the given runtime + install host lists.
/// Tests use this to populate `with_existing_profile` content so the
/// writer's read_profile + parse + render path exercises non-empty
/// allowlist tiers without touching real fs state.
pub fn profile_with_hosts(runtime: &[&str], install: &[&str]) -> String {
    let runtime_lines = runtime
        .iter()
        .map(|h| format!("  \"{h}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let install_lines = install
        .iter()
        .map(|h| format!("  \"{h}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let runtime_block = if runtime_lines.is_empty() {
        "hosts = []".to_string()
    } else {
        format!("hosts = [\n{runtime_lines}\n]")
    };
    let install_block = if install_lines.is_empty() {
        "hosts = []".to_string()
    } else {
        format!("hosts = [\n{install_lines}\n]")
    };
    format!(
        "schema_version = 1\n\n\
         [allowlist.runtime]\n{runtime_block}\n\n\
         [allowlist.install]\n{install_block}\n"
    )
}

/// A reader where `name` is present as a Destroyable tenant (UID at floor,
/// group present). Lets dispatch reach `doctor_tenant`.
pub fn make_tenant_stub_reader(name: &str) -> StubReader {
    StubReader {
        users: vec![name.to_string()],
        groups: vec![format!("{name}-tenant-share")],
        uid_by_name: [(name.to_string(), 600)].into_iter().collect(),
        gid_by_name: [(format!("{name}-tenant-share"), 600)]
            .into_iter()
            .collect(),
    }
}

pub fn make_two_tenant_stub_reader() -> StubReader {
    StubReader {
        users: vec!["dev".to_string(), "staging".to_string()],
        groups: vec![
            "dev-tenant-share".to_string(),
            "staging-tenant-share".to_string(),
        ],
        uid_by_name: [("dev".to_string(), 600), ("staging".to_string(), 601)]
            .into_iter()
            .collect(),
        gid_by_name: [
            ("dev-tenant-share".to_string(), 600),
            ("staging-tenant-share".to_string(), 601),
        ]
        .into_iter()
        .collect(),
    }
}
