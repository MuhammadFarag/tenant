//! Test substitute for `HostMachine`. Records op invocations for
//! behavioral assertions and supports per-op failure injection.
//! Describe delegates to `MacosHostMachine` so production + test
//! render identical bytes.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;

use tenant::adapters::macos::MacosHostMachine;
use tenant::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupName, HostFileError, HostMachine, HostUserName, KeychainError, KeychainOp,
    KeychainPassword, PamOp, PathKind, ProbeError, ProfileOp, TenantUserName,
};
use tenant::profile::{ProfileError, default_profile_toml};

#[derive(Default)]
pub struct StubHostMachine {
    /// Operator identity returned from `current_host_user_name`. Set by
    /// `new()` to `"operator"` (matches `common::TEST_HOST`) so the
    /// canonical `StubHostMachine::new()` lines up with shared test
    /// fixtures without a per-test setter; `with_host` overrides.
    host: RefCell<String>,

    account_ops: RefCell<Vec<AccountOp>>,
    profile_ops: RefCell<Vec<ProfileOp>>,
    firewall_ops: RefCell<Vec<FirewallOp>>,
    logins: RefCell<Vec<String>>,

    exec_calls: RefCell<Vec<(String, Vec<String>)>>,

    exec_exit_code: Cell<i32>,

    exec_failure: RefCell<Option<AccountError>>,

    /// First match (by full equality on the op value) wins.
    account_overrides: RefCell<Vec<(AccountOp, AccountError)>>,

    /// Fires on every call (not one-shot). Spawn-failure injection
    /// isn't supported by the blanket path; use a per-op override.
    account_blanket_failure: RefCell<Option<(i32, String)>>,

    profile_failure: RefCell<Option<ProfileError>>,

    /// First match (by full equality on the op value) wins.
    firewall_overrides: RefCell<Vec<(FirewallOp, FirewallError)>>,

    firewall_failure: RefCell<Option<FirewallError>>,

    login_exit_code: Cell<i32>,

    /// Backs both `execute_profile` mutations and `read_profile` reads.
    profile_state: RefCell<HashMap<String, String>>,

    /// Not mutated by `execute_firewall` — pfctl ops are modeled as
    /// side effects on a real-host fs; tests assert via `firewall_ops()`
    /// rather than re-reading conf state.
    pf_conf_state: RefCell<String>,

    /// Override for what `ProfileOp::Create` writes. Production always
    /// writes `default_profile_toml()`; this lets create-flow tests
    /// exercise the non-empty-allowlist path without rewriting the default.
    create_profile_overrides: RefCell<HashMap<String, String>>,

    probes: RefCell<Vec<(String, PathBuf, AccessMode)>>,

    /// Unmatched probes default to `AccessOutcome::Denied`.
    probe_outcomes: RefCell<HashMap<(String, PathBuf, AccessMode), AccessOutcome>>,

    probe_failure: RefCell<Option<ProbeError>>,

    env_policy_content: RefCell<String>,

    env_policy_failure: RefCell<Option<HostFileError>>,

    /// Missing entry falls back to a "happy" default (both `pass` +
    /// `block` present) so tests that don't care about PF-drift don't
    /// see spurious findings.
    kernel_pf_rules: RefCell<HashMap<String, String>>,

    kernel_pf_rules_failure: RefCell<Option<FirewallError>>,

    /// Defaults to a "Touch-ID-active" placeholder (see `new`) so tests
    /// that don't care about the PAM path don't see spurious
    /// `TouchIdMissing` findings.
    pam_sudo_content: RefCell<String>,

    pam_sudo_failure: RefCell<Option<HostFileError>>,

    /// Defaults to empty (no local customizations) so doctor's
    /// `sudo OR sudo_local` check relies on `pam_sudo_content` alone
    /// unless a test exercises the sudo_local path explicitly.
    pam_sudo_local_content: RefCell<String>,

    pam_sudo_local_failure: RefCell<Option<HostFileError>>,

    /// Defaults to "Status: Enabled" so tests that don't care about
    /// pf-enabled don't see spurious `PfDisabled` findings.
    pf_status_content: RefCell<String>,

    pf_status_failure: RefCell<Option<FirewallError>>,

    /// Missing entry falls back to the runtime-tier render of the
    /// profile in `profile_state` for the same name (or empty-allowlist
    /// render) — matches what doctor computes as "expected" so tests
    /// that don't care about drift don't see spurious findings.
    anchor_body_state: RefCell<HashMap<String, String>>,

    anchor_body_failure: RefCell<Option<HostFileError>>,

    acl_ops: RefCell<Vec<AclOp>>,

    /// First match (by full equality) wins.
    acl_overrides: RefCell<Vec<(AclOp, AclError)>>,

    acl_failure: RefCell<Option<AclError>>,

    /// Unmatched lookups consult `profile_state[name]` and return
    /// `Symlink(host_path)` when the queried path matches a declared
    /// share's expanded tenant_path (the "shares already reapplied"
    /// state); otherwise `Absent`.
    tenant_path_kinds: RefCell<HashMap<(String, PathBuf), PathKind>>,

    tenant_path_kind_failure: RefCell<Option<ProbeError>>,

    /// Records every `(name, path)` looked up via `tenant_path_kind`,
    /// in call order. Lets tests pin which calls the sudo-bearing
    /// tenant-side probe touched — load-bearing for the pre-exec
    /// doctor's "SymlinkDrift check skipped when sudo uncached" pin.
    tenant_path_kind_calls: RefCell<Vec<(String, PathBuf)>>,

    /// Pre-loaded kinds for `host_path_kind`. Unmatched paths default
    /// to `PathKind::Absent` — matches what an untouched host looks
    /// like to the cowork-dir probe.
    host_path_kinds: RefCell<HashMap<PathBuf, PathKind>>,

    /// One-shot failure injection for `host_path_kind`. Consumed by
    /// the next call.
    host_path_kind_failure: RefCell<Option<ProbeError>>,

    /// Records every path looked up via `host_path_kind`, in call
    /// order. Lets tests pin which paths the host-side probe touched.
    host_path_kind_calls: RefCell<Vec<PathBuf>>,

    /// Unmatched lookups default to a synthesized listing satisfying
    /// `doctor::has_group_acl_entry` for every plausibly-named tenant
    /// group, so tests that don't exercise AclDrift don't see spurious
    /// findings.
    host_acl_state: RefCell<HashMap<PathBuf, String>>,

    host_acl_failures: RefCell<HashMap<PathBuf, ProbeError>>,

    /// Unmatched lookups default to `true` so tests that don't exercise
    /// `HostNotInShareGroup` don't see a spurious warning.
    host_in_group_state: RefCell<HashMap<(String, String), bool>>,

    host_in_group_invocations: RefCell<Vec<(String, String)>>,

    host_in_group_failure: RefCell<Option<AccountError>>,

    /// Operator's cached-sudo-timestamp verdict for
    /// `sudo_session_cached`. Defaults to `true` (set in `new`) so the
    /// pre-exec doctor pass runs its full probe set in existing tests;
    /// `with_sudo_session_cached(false)` exercises the quiet-skip gate.
    sudo_session_cached: Cell<bool>,

    /// Records every `PamOp` passed to `execute_pam`, in call order.
    /// Setup tests assert the Touch-ID op fired (or didn't) via `pam_ops()`.
    pam_ops: RefCell<Vec<PamOp>>,

    /// One-shot failure injection for `execute_pam`.
    pam_failure: RefCell<Option<HostFileError>>,

    keychain_ops: RefCell<Vec<KeychainOp>>,

    /// Unmatched lookups default to `true` so tests that don't
    /// exercise `TenantKeychainAbsent` don't see a spurious warning.
    tenant_keychain_state: RefCell<HashMap<String, bool>>,

    tenant_keychain_probe_failure: RefCell<Option<ProbeError>>,

    /// Unmatched lookups default to `true` so tests that don't
    /// exercise `StashAbsent` don't see a spurious warning.
    stash_state: RefCell<HashMap<String, bool>>,

    stash_probe_failure: RefCell<Option<KeychainError>>,

    /// Retrievable stashed passwords for `find_stashed_password`.
    /// Distinct from `stash_state` (bool-valued, doctor probe). An
    /// entry present here lets the unlock pass retrieve the password;
    /// absent ⇒ `KeychainError::NotFound`.
    stash_passwords: RefCell<HashMap<String, KeychainPassword>>,

    /// Per-method failure injection for the unlock pass. Both are
    /// one-shot (consumed by `.take()`) so a single test can pin
    /// "stash retrieval fails" vs "unlock substrate fails" cleanly.
    find_stashed_password_failure: RefCell<Option<KeychainError>>,
    unlock_tenant_keychain_failure: RefCell<Option<KeychainError>>,

    /// Recorder for `unlock_tenant_keychain` invocations — tests pin
    /// "the unlock fired for tenant X exactly once" via `unlock_calls()`.
    unlock_calls: RefCell<Vec<String>>,

    /// Per-variant one-shot failure injection. KeychainOp variants
    /// carry the randomly-generated password so equality-based
    /// overrides can't be authored by tests; per-variant queues
    /// sidestep that. Provision is split into four sub-step queues
    /// so partial-failure tests can pin exactly which leg failed.
    keychain_create_failure: RefCell<Option<KeychainError>>,
    keychain_set_default_failure: RefCell<Option<KeychainError>>,
    keychain_add_to_search_failure: RefCell<Option<KeychainError>>,
    keychain_disable_auto_lock_failure: RefCell<Option<KeychainError>>,
    keychain_stash_failure: RefCell<Option<KeychainError>>,
    keychain_delete_failure: RefCell<Option<KeychainError>>,
}

impl StubHostMachine {
    pub fn new() -> Self {
        let s = Self::default();
        *s.host.borrow_mut() = "operator".to_string();
        *s.env_policy_content.borrow_mut() =
            "Defaults env_delete += \"SSH_AUTH_SOCK\"\n".to_string();
        *s.pam_sudo_content.borrow_mut() = "auth       sufficient     pam_tid.so\n".to_string();
        *s.pf_status_content.borrow_mut() = "Status: Enabled for 0 days 00:00:00\n".to_string();
        s.sudo_session_cached.set(true);
        s
    }

    pub fn with_host(self, host: &str) -> Self {
        *self.host.borrow_mut() = host.to_string();
        self
    }

    pub fn fail_account_op(self, op: AccountOp, err: AccountError) -> Self {
        self.account_overrides.borrow_mut().push((op, err));
        self
    }

    pub fn fail_account_blanket(self, code: i32, stderr: &str) -> Self {
        *self.account_blanket_failure.borrow_mut() = Some((code, stderr.to_string()));
        self
    }

    pub fn fail_next_profile(self, err: ProfileError) -> Self {
        *self.profile_failure.borrow_mut() = Some(err);
        self
    }

    pub fn fail_firewall_op(self, op: FirewallOp, err: FirewallError) -> Self {
        self.firewall_overrides.borrow_mut().push((op, err));
        self
    }

    pub fn fail_next_firewall(self, err: FirewallError) -> Self {
        *self.firewall_failure.borrow_mut() = Some(err);
        self
    }

    pub fn login_exit_code(self, code: i32) -> Self {
        self.login_exit_code.set(code);
        self
    }

    pub fn exec_exit_code(self, code: i32) -> Self {
        self.exec_exit_code.set(code);
        self
    }

    pub fn fail_next_exec(self, err: AccountError) -> Self {
        *self.exec_failure.borrow_mut() = Some(err);
        self
    }

    pub fn account_ops(&self) -> Vec<AccountOp> {
        self.account_ops.borrow().clone()
    }

    pub fn profile_ops(&self) -> Vec<ProfileOp> {
        self.profile_ops.borrow().clone()
    }

    pub fn firewall_ops(&self) -> Vec<FirewallOp> {
        self.firewall_ops.borrow().clone()
    }

    pub fn logins(&self) -> Vec<String> {
        self.logins.borrow().clone()
    }

    pub fn exec_calls(&self) -> Vec<(String, Vec<String>)> {
        self.exec_calls.borrow().clone()
    }

    pub fn with_existing_profile(self, name: &str, content: &str) -> Self {
        self.profile_state
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    pub fn with_pf_conf(self, content: &str) -> Self {
        *self.pf_conf_state.borrow_mut() = content.to_string();
        self
    }

    /// Override what `ProfileOp::Create` writes. Production always
    /// writes `default_profile_toml()` (empty allowlists); this lets
    /// create-flow tests exercise the non-empty-allowlist path via
    /// the downstream `read_profile` + `parse` + `render_anchor` chain.
    pub fn with_create_profile_content(self, name: &str, content: &str) -> Self {
        self.create_profile_overrides
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    pub fn profile_state(&self) -> HashMap<String, String> {
        self.profile_state.borrow().clone()
    }

    pub fn has_profile(&self, name: &str) -> bool {
        self.profile_state.borrow().contains_key(name)
    }

    pub fn with_probe_outcome(
        self,
        name: &str,
        path: &std::path::Path,
        mode: AccessMode,
        outcome: AccessOutcome,
    ) -> Self {
        self.probe_outcomes
            .borrow_mut()
            .insert((name.to_string(), path.to_path_buf(), mode), outcome);
        self
    }

    pub fn fail_next_probe(self, err: ProbeError) -> Self {
        *self.probe_failure.borrow_mut() = Some(err);
        self
    }

    pub fn probes(&self) -> Vec<(String, PathBuf, AccessMode)> {
        self.probes.borrow().clone()
    }

    pub fn with_env_policy_content(self, content: &str) -> Self {
        *self.env_policy_content.borrow_mut() = content.to_string();
        self
    }

    pub fn fail_next_env_policy(self, err: HostFileError) -> Self {
        *self.env_policy_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_kernel_pf_rules(self, name: &str, content: &str) -> Self {
        self.kernel_pf_rules
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    pub fn fail_next_kernel_pf_rules(self, err: FirewallError) -> Self {
        *self.kernel_pf_rules_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_pam_sudo_content(self, content: &str) -> Self {
        *self.pam_sudo_content.borrow_mut() = content.to_string();
        self
    }

    pub fn fail_next_pam_sudo(self, err: HostFileError) -> Self {
        *self.pam_sudo_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_pam_sudo_local_content(self, content: &str) -> Self {
        *self.pam_sudo_local_content.borrow_mut() = content.to_string();
        self
    }

    pub fn fail_next_pam_sudo_local(self, err: HostFileError) -> Self {
        *self.pam_sudo_local_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_pf_status_content(self, content: &str) -> Self {
        *self.pf_status_content.borrow_mut() = content.to_string();
        self
    }

    pub fn fail_next_pf_status(self, err: FirewallError) -> Self {
        *self.pf_status_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_anchor_body(self, name: &str, content: &str) -> Self {
        self.anchor_body_state
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    pub fn fail_next_anchor_body(self, err: HostFileError) -> Self {
        *self.anchor_body_failure.borrow_mut() = Some(err);
        self
    }

    pub fn fail_acl_op(self, op: AclOp, err: AclError) -> Self {
        self.acl_overrides.borrow_mut().push((op, err));
        self
    }

    pub fn fail_next_acl(self, err: AclError) -> Self {
        *self.acl_failure.borrow_mut() = Some(err);
        self
    }

    pub fn acl_ops(&self) -> Vec<AclOp> {
        self.acl_ops.borrow().clone()
    }

    pub fn with_tenant_path_kind(self, name: &str, path: &std::path::Path, kind: PathKind) -> Self {
        self.tenant_path_kinds
            .borrow_mut()
            .insert((name.to_string(), path.to_path_buf()), kind);
        self
    }

    pub fn fail_next_tenant_path_kind(self, err: ProbeError) -> Self {
        *self.tenant_path_kind_failure.borrow_mut() = Some(err);
        self
    }

    /// Pre-load the kind `host_path_kind` returns for a given path.
    /// Mirrors `with_tenant_path_kind`'s shape but keyed on path alone
    /// — the host-side probe doesn't carry a tenant identity.
    pub fn with_host_path_kind(self, path: &std::path::Path, kind: PathKind) -> Self {
        self.host_path_kinds
            .borrow_mut()
            .insert(path.to_path_buf(), kind);
        self
    }

    pub fn fail_next_host_path_kind(self, err: ProbeError) -> Self {
        *self.host_path_kind_failure.borrow_mut() = Some(err);
        self
    }

    /// Cowork dir healthy: pre-load `host_path_kind` → `Dir` AND a
    /// listing carrying the share-group ACE. Use when a test
    /// doesn't load a profile (the gated synthesizers wouldn't kick
    /// in) but still wants neither `CoworkDirAbsent` nor
    /// `CoworkAclDrift` to fire.
    pub fn with_present_cowork_dir(self, name: &str) -> Self {
        let path = tenant::domain::tenants::cowork_dir_path(name);
        self.host_path_kinds
            .borrow_mut()
            .insert(path.clone(), PathKind::Dir);
        self.host_acl_state.borrow_mut().insert(
            path,
            format!(
                " 0: group:{name}-tenant-share allow read,write,execute,delete,append,file_inherit,directory_inherit\n"
            ),
        );
        self
    }

    /// Snapshot of every `host_path_kind` call, in invocation order.
    pub fn host_path_kind_calls(&self) -> Vec<PathBuf> {
        self.host_path_kind_calls.borrow().clone()
    }

    /// Snapshot of every `tenant_path_kind` call, in invocation order.
    pub fn tenant_path_kind_calls(&self) -> Vec<(String, PathBuf)> {
        self.tenant_path_kind_calls.borrow().clone()
    }

    pub fn with_host_acl(self, path: &std::path::Path, listing: &str) -> Self {
        self.host_acl_state
            .borrow_mut()
            .insert(path.to_path_buf(), listing.to_string());
        self
    }

    pub fn fail_next_host_acl(self, path: &std::path::Path, err: ProbeError) -> Self {
        self.host_acl_failures
            .borrow_mut()
            .insert(path.to_path_buf(), err);
        self
    }

    pub fn with_host_in_group(self, host: &str, group: &str, is_member: bool) -> Self {
        self.host_in_group_state
            .borrow_mut()
            .insert((host.to_string(), group.to_string()), is_member);
        self
    }

    pub fn fail_next_host_in_group(self, err: AccountError) -> Self {
        *self.host_in_group_failure.borrow_mut() = Some(err);
        self
    }

    pub fn host_in_group_invocations(&self) -> Vec<(String, String)> {
        self.host_in_group_invocations.borrow().clone()
    }

    /// Override the cached-sudo verdict. `false` exercises the
    /// pre-exec doctor pass's quiet-skip gate (no sudo probes, no
    /// failure frames pre-consent).
    pub fn with_sudo_session_cached(self, cached: bool) -> Self {
        self.sudo_session_cached.set(cached);
        self
    }

    pub fn keychain_ops(&self) -> Vec<KeychainOp> {
        self.keychain_ops.borrow().clone()
    }

    pub fn pam_ops(&self) -> Vec<PamOp> {
        self.pam_ops.borrow().clone()
    }

    pub fn fail_next_pam(self, err: HostFileError) -> Self {
        *self.pam_failure.borrow_mut() = Some(err);
        self
    }

    pub fn fail_next_keychain_create(self, err: KeychainError) -> Self {
        *self.keychain_create_failure.borrow_mut() = Some(err);
        self
    }

    pub fn fail_next_keychain_set_default(self, err: KeychainError) -> Self {
        *self.keychain_set_default_failure.borrow_mut() = Some(err);
        self
    }

    pub fn fail_next_keychain_add_to_search(self, err: KeychainError) -> Self {
        *self.keychain_add_to_search_failure.borrow_mut() = Some(err);
        self
    }

    pub fn fail_next_keychain_disable_auto_lock(self, err: KeychainError) -> Self {
        *self.keychain_disable_auto_lock_failure.borrow_mut() = Some(err);
        self
    }

    pub fn fail_next_keychain_stash(self, err: KeychainError) -> Self {
        *self.keychain_stash_failure.borrow_mut() = Some(err);
        self
    }

    pub fn fail_next_keychain_delete(self, err: KeychainError) -> Self {
        *self.keychain_delete_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_tenant_keychain_present(self, name: &str, present: bool) -> Self {
        self.tenant_keychain_state
            .borrow_mut()
            .insert(name.to_string(), present);
        self
    }

    pub fn fail_next_tenant_keychain_probe(self, err: ProbeError) -> Self {
        *self.tenant_keychain_probe_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_stash_present(self, name: &str, present: bool) -> Self {
        self.stash_state
            .borrow_mut()
            .insert(name.to_string(), present);
        self
    }

    pub fn fail_next_stash_probe(self, err: KeychainError) -> Self {
        *self.stash_probe_failure.borrow_mut() = Some(err);
        self
    }

    /// Pre-load a retrievable stash entry for `find_stashed_password`.
    /// Companion to `with_stash_present` (which only sets the
    /// bool-valued doctor flag); this one stores the actual password
    /// value the unlock pass retrieves.
    pub fn with_stash(self, name: &str, password: KeychainPassword) -> Self {
        self.stash_passwords
            .borrow_mut()
            .insert(name.to_string(), password);
        self
    }

    /// Convenience: pre-load a stash with a fixed test-dummy password.
    /// Most shell happy-path tests don't care about the password value
    /// (Stub's `unlock_tenant_keychain` ignores it); this shorthand
    /// keeps the call sites focused on what the test IS exercising.
    pub fn with_default_stash(self, name: &str) -> Self {
        self.with_stash(name, KeychainPassword::test_dummy("test-stashed-pw"))
    }

    pub fn fail_next_find_stashed_password(self, err: KeychainError) -> Self {
        *self.find_stashed_password_failure.borrow_mut() = Some(err);
        self
    }

    pub fn fail_next_unlock_tenant_keychain(self, err: KeychainError) -> Self {
        *self.unlock_tenant_keychain_failure.borrow_mut() = Some(err);
        self
    }

    pub fn unlock_calls(&self) -> Vec<String> {
        self.unlock_calls.borrow().clone()
    }
}

impl HostMachine for StubHostMachine {
    fn describe_account(&self, op: &AccountOp) -> String {
        MacosHostMachine.describe_account(op)
    }

    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        self.account_ops.borrow_mut().push(op.clone());
        let mut overrides = self.account_overrides.borrow_mut();
        if let Some(idx) = overrides.iter().position(|(target, _)| target == op) {
            let (_, err) = overrides.remove(idx);
            return Err(err);
        }
        drop(overrides);
        if let Some((code, stderr)) = self.account_blanket_failure.borrow().clone() {
            return Err(AccountError::NonZero { code, stderr });
        }
        Ok(())
    }

    fn login(&self, name: &TenantUserName) -> Result<i32, AccountError> {
        self.logins.borrow_mut().push(name.to_string());
        Ok(self.login_exit_code.get())
    }

    fn exec_as_tenant(&self, name: &TenantUserName, argv: &[String]) -> Result<i32, AccountError> {
        self.exec_calls
            .borrow_mut()
            .push((name.to_string(), argv.to_vec()));
        if let Some(err) = self.exec_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self.exec_exit_code.get())
    }

    fn describe_profile(&self, op: &ProfileOp) -> String {
        MacosHostMachine.describe_profile(op)
    }

    fn execute_profile(&self, op: &ProfileOp) -> Result<(), ProfileError> {
        self.profile_ops.borrow_mut().push(op.clone());
        if let Some(err) = self.profile_failure.borrow_mut().take() {
            return Err(err);
        }
        match op {
            ProfileOp::Create { name } => {
                let content = self
                    .create_profile_overrides
                    .borrow()
                    .get(name.as_str())
                    .cloned()
                    .unwrap_or_else(default_profile_toml);
                self.profile_state
                    .borrow_mut()
                    .insert(name.0.clone(), content);
            }
            ProfileOp::Delete { name } => {
                self.profile_state.borrow_mut().remove(name.as_str());
            }
        }
        Ok(())
    }

    fn read_profile(&self, name: &TenantUserName) -> Result<String, ProfileError> {
        match self.profile_state.borrow().get(name.as_str()) {
            Some(content) => Ok(content.clone()),
            None => Err(ProfileError {
                message: format!("profile '{name}' not found"),
            }),
        }
    }

    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        Ok(self.pf_conf_state.borrow().clone())
    }

    fn describe_firewall(&self, op: &FirewallOp) -> String {
        MacosHostMachine.describe_firewall(op)
    }

    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError> {
        self.firewall_ops.borrow_mut().push(op.clone());
        let mut overrides = self.firewall_overrides.borrow_mut();
        if let Some(idx) = overrides.iter().position(|(target, _)| target == op) {
            let (_, err) = overrides.remove(idx);
            return Err(err);
        }
        drop(overrides);
        if let Some(err) = self.firewall_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(())
    }

    fn probe_access_as_tenant(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
        mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError> {
        self.probes
            .borrow_mut()
            .push((name.0.clone(), path.to_path_buf(), mode));
        if let Some(err) = self.probe_failure.borrow_mut().take() {
            return Err(err);
        }
        let outcome = self
            .probe_outcomes
            .borrow()
            .get(&(name.0.clone(), path.to_path_buf(), mode))
            .copied()
            .unwrap_or(AccessOutcome::Denied);
        Ok(outcome)
    }

    fn read_env_policy(&self) -> Result<String, HostFileError> {
        if let Some(err) = self.env_policy_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self.env_policy_content.borrow().clone())
    }

    fn read_kernel_pf_rules(&self, name: &TenantUserName) -> Result<String, FirewallError> {
        if let Some(err) = self.kernel_pf_rules_failure.borrow_mut().take() {
            return Err(err);
        }
        match self.kernel_pf_rules.borrow().get(name.as_str()) {
            Some(content) => Ok(content.clone()),
            None => Ok("block return inet from any to any\n\
                        pass inet from 192.0.2.1 to <allowed> keep state\n"
                .to_string()),
        }
    }

    fn read_pam_sudo(&self) -> Result<String, HostFileError> {
        if let Some(err) = self.pam_sudo_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self.pam_sudo_content.borrow().clone())
    }

    fn read_pam_sudo_local(&self) -> Result<String, HostFileError> {
        if let Some(err) = self.pam_sudo_local_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self.pam_sudo_local_content.borrow().clone())
    }

    fn read_pf_status(&self) -> Result<String, FirewallError> {
        if let Some(err) = self.pf_status_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self.pf_status_content.borrow().clone())
    }

    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        if let Some(err) = self.anchor_body_failure.borrow_mut().take() {
            return Err(err);
        }
        if let Some(content) = self.anchor_body_state.borrow().get(name.as_str()) {
            return Ok(content.clone());
        }
        let hosts: Vec<String> = match self.profile_state.borrow().get(name.as_str()) {
            Some(toml) => match tenant::profile::parse(toml) {
                Ok(profile) => profile.allowlist.runtime.hosts.clone(),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        Ok(tenant::firewall::render_anchor(
            name.as_str(),
            &hosts,
            tenant::firewall::InboundRules::Restricted(vec![]),
        ))
    }

    fn describe_acl(&self, op: &AclOp) -> String {
        MacosHostMachine.describe_acl(op)
    }

    fn execute_acl(&self, op: &AclOp) -> Result<(), AclError> {
        self.acl_ops.borrow_mut().push(op.clone());
        let mut overrides = self.acl_overrides.borrow_mut();
        if let Some(idx) = overrides.iter().position(|(target, _)| target == op) {
            let (_, err) = overrides.remove(idx);
            return Err(err);
        }
        drop(overrides);
        if let Some(err) = self.acl_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(())
    }

    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<PathKind, ProbeError> {
        self.tenant_path_kind_calls
            .borrow_mut()
            .push((name.0.clone(), path.to_path_buf()));
        if let Some(err) = self.tenant_path_kind_failure.borrow_mut().take() {
            return Err(err);
        }
        if let Some(kind) = self
            .tenant_path_kinds
            .borrow()
            .get(&(name.0.clone(), path.to_path_buf()))
            .cloned()
        {
            return Ok(kind);
        }
        if let Some(toml) = self.profile_state.borrow().get(name.as_str())
            && let Ok(profile) = tenant::profile::parse(toml)
        {
            for share in &profile.shares {
                let expanded =
                    tenant::profile::expand_tenant_path(name.as_str(), &share.tenant_path);
                if expanded == path {
                    return Ok(PathKind::Symlink(share.host_path.clone()));
                }
            }
        }
        Ok(PathKind::Absent)
    }

    fn host_path_kind(&self, path: &std::path::Path) -> Result<PathKind, ProbeError> {
        self.host_path_kind_calls
            .borrow_mut()
            .push(path.to_path_buf());
        if let Some(err) = self.host_path_kind_failure.borrow_mut().take() {
            return Err(err);
        }
        if let Some(kind) = self.host_path_kinds.borrow().get(path) {
            return Ok(kind.clone());
        }
        // Cowork paths default to `Dir` only when the tenant has a
        // profile loaded — same gate as the host-ACL synthesizer
        // below. Tests that don't pre-load a profile still see the
        // legacy "missing pre-load = Absent" default (destroy's
        // cowork-notice probe relies on this).
        if let Some(name) = path
            .strip_prefix(tenant::domain::tenants::COWORK_DIR_PARENT)
            .ok()
            .and_then(|p| p.to_str())
            .filter(|s| !s.is_empty() && !s.contains('/'))
            && self.profile_state.borrow().contains_key(name)
        {
            return Ok(PathKind::Dir);
        }
        Ok(PathKind::Absent)
    }

    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError> {
        if let Some(err) = self.host_acl_failures.borrow_mut().remove(path) {
            return Err(err);
        }
        if let Some(listing) = self.host_acl_state.borrow().get(path) {
            return Ok(listing.clone());
        }
        // Synthesize one share-group ACE per known tenant so tests
        // that don't exercise AclDrift see a matching entry. Add a
        // cowork-dir ACE on the canonical path when the tenant has
        // a profile loaded — same gate as `host_path_kind`. Drift
        // tests override via `with_host_acl(cowork_path, …)`.
        let mut listing = String::new();
        let profiles = self.profile_state.borrow();
        for name in profiles.keys() {
            listing.push_str(&format!(
                " 0: group:{name}-tenant-share allow list,add_file,search\n"
            ));
        }
        if let Some(name) = path
            .strip_prefix(tenant::domain::tenants::COWORK_DIR_PARENT)
            .ok()
            .and_then(|p| p.to_str())
            .filter(|s| !s.is_empty() && !s.contains('/'))
            && profiles.contains_key(name)
        {
            let needle = format!("group:{name}-tenant-share allow");
            if !listing.contains(&needle) {
                listing.push_str(&format!(
                    " 0: group:{name}-tenant-share allow read,write,execute,delete,append,file_inherit,directory_inherit\n"
                ));
            }
        }
        Ok(listing)
    }

    fn current_host_user_name(&self) -> HostUserName {
        HostUserName::from(self.host.borrow().clone())
    }

    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError> {
        self.host_in_group_invocations
            .borrow_mut()
            .push((host.to_string(), group.to_string()));
        if let Some(err) = self.host_in_group_failure.borrow_mut().take() {
            return Err(err);
        }
        let key = (host.to_string(), group.to_string());
        Ok(self
            .host_in_group_state
            .borrow()
            .get(&key)
            .copied()
            .unwrap_or(true))
    }

    fn sudo_session_cached(&self) -> bool {
        self.sudo_session_cached.get()
    }

    fn describe_keychain(&self, op: &KeychainOp) -> String {
        MacosHostMachine.describe_keychain(op)
    }

    fn describe_pam(&self, op: &PamOp) -> String {
        MacosHostMachine.describe_pam(op)
    }

    fn execute_pam(&self, op: &PamOp) -> Result<(), HostFileError> {
        self.pam_ops.borrow_mut().push(op.clone());
        if let Some(err) = self.pam_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(())
    }

    fn tenant_keychain_present(&self, name: &TenantUserName) -> Result<bool, ProbeError> {
        if let Some(err) = self.tenant_keychain_probe_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self
            .tenant_keychain_state
            .borrow()
            .get(name.as_str())
            .copied()
            .unwrap_or(true))
    }

    fn stash_present(&self, name: &TenantUserName) -> Result<bool, KeychainError> {
        if let Some(err) = self.stash_probe_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self
            .stash_state
            .borrow()
            .get(name.as_str())
            .copied()
            .unwrap_or(true))
    }

    fn find_stashed_password(
        &self,
        name: &TenantUserName,
    ) -> Result<KeychainPassword, KeychainError> {
        if let Some(err) = self.find_stashed_password_failure.borrow_mut().take() {
            return Err(err);
        }
        self.stash_passwords
            .borrow()
            .get(name.as_str())
            .cloned()
            .ok_or(KeychainError::NotFound)
    }

    fn unlock_tenant_keychain(
        &self,
        name: &TenantUserName,
        _password: &KeychainPassword,
    ) -> Result<(), KeychainError> {
        self.unlock_calls.borrow_mut().push(name.to_string());
        if let Some(err) = self.unlock_tenant_keychain_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(())
    }

    fn execute_keychain(&self, op: &KeychainOp) -> Result<(), KeychainError> {
        self.keychain_ops.borrow_mut().push(op.clone());
        match op {
            KeychainOp::CreateLoginKeychain { .. } => {
                if let Some(err) = self.keychain_create_failure.borrow_mut().take() {
                    return Err(err);
                }
            }
            KeychainOp::SetDefaultKeychain { .. } => {
                if let Some(err) = self.keychain_set_default_failure.borrow_mut().take() {
                    return Err(err);
                }
            }
            KeychainOp::AddKeychainToSearchList { .. } => {
                if let Some(err) = self.keychain_add_to_search_failure.borrow_mut().take() {
                    return Err(err);
                }
            }
            KeychainOp::DisableKeychainAutoLock { .. } => {
                if let Some(err) = self.keychain_disable_auto_lock_failure.borrow_mut().take() {
                    return Err(err);
                }
            }
            KeychainOp::StashPassword { .. } => {
                if let Some(err) = self.keychain_stash_failure.borrow_mut().take() {
                    return Err(err);
                }
            }
            KeychainOp::DeleteStashedPassword { .. } => {
                if let Some(err) = self.keychain_delete_failure.borrow_mut().take() {
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}
