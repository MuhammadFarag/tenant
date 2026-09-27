//! `HostMachine` test double: records ops, injects failures; describe delegates to `MacosHostMachine`.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::PathBuf;

use tenant::adapters::macos::MacosHostMachine;
use tenant::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupId, GroupName, HostFileError, HostMachine, HostUserName, KeychainError, KeychainOp,
    KeychainPassword, PamOp, PathKind, ProbeError, ProfileOp, SudoersOp, TenantUserName,
};
use tenant::profile::{ProfileError, default_profile_toml};

/// One recorded `exec_as_tenant` call: `(tenant, argv, dir)`.
type ExecCall = (String, Vec<String>, Option<PathBuf>);

#[derive(Default)]
pub struct StubHostMachine {
    /// Defaults to `"operator"` (`common::TEST_HOST`).
    host: RefCell<String>,

    account_ops: RefCell<Vec<AccountOp>>,
    profile_ops: RefCell<Vec<ProfileOp>>,
    firewall_ops: RefCell<Vec<FirewallOp>>,
    logins: RefCell<Vec<(String, Option<PathBuf>)>>,

    exec_calls: RefCell<Vec<ExecCall>>,

    exec_exit_code: Cell<i32>,

    /// Popped per `exec_as_tenant` call; falls back to `exec_exit_code` once drained.
    exec_exit_codes: RefCell<VecDeque<i32>>,

    exec_failure: RefCell<Option<AccountError>>,

    /// First match (by full equality on the op value) wins.
    account_overrides: RefCell<Vec<(AccountOp, AccountError)>>,

    /// Fires on every call (not one-shot); spawn failures need a per-op override.
    account_blanket_failure: RefCell<Option<(i32, String)>>,

    profile_failure: RefCell<Option<ProfileError>>,

    /// First match (by full equality on the op value) wins.
    firewall_overrides: RefCell<Vec<(FirewallOp, FirewallError)>>,

    firewall_failure: RefCell<Option<FirewallError>>,

    login_exit_code: Cell<i32>,

    /// Backs both `execute_profile` mutations and `read_profile` reads.
    profile_state: RefCell<HashMap<String, String>>,

    pf_conf_state: RefCell<String>,

    /// Until `with_pf_conf`, every tenant reads as referenced (no spurious `PfConfAnchorRefMissing`).
    pf_conf_supplied: Cell<bool>,

    pf_conf_failure: RefCell<Option<FirewallError>>,

    /// Unmatched groups fall back to `GroupId(600)`.
    share_group_gids: RefCell<HashMap<String, GroupId>>,

    share_group_gid_failure: RefCell<Option<ProbeError>>,

    /// Unmatched tenants default to their share group's gid (no spurious `PrimaryGroupDrift`).
    user_primary_gids: RefCell<HashMap<String, GroupId>>,

    user_primary_gid_failure: RefCell<Option<ProbeError>>,

    /// Overrides what `ProfileOp::Create` writes (production always writes the default).
    create_profile_overrides: RefCell<HashMap<String, String>>,

    /// Unpreloaded fragments read as `ProfileError`.
    profile_fragments: RefCell<HashMap<String, String>>,

    fragment_reads: RefCell<Vec<String>>,

    probes: RefCell<Vec<(String, PathBuf, AccessMode)>>,

    /// Unmatched probes default to `AccessOutcome::Denied`.
    probe_outcomes: RefCell<HashMap<(String, PathBuf, AccessMode), AccessOutcome>>,

    probe_failure: RefCell<Option<ProbeError>>,

    env_policy_content: RefCell<String>,

    env_policy_failure: RefCell<Option<HostFileError>>,

    /// Missing entry defaults to a pass + block body (no spurious PF-drift findings).
    kernel_pf_rules: RefCell<HashMap<String, String>>,

    kernel_pf_rules_failure: RefCell<Option<FirewallError>>,

    kernel_pf_rules_calls: RefCell<Vec<String>>,

    /// Absent ⇒ a reload loads the default healthy rules.
    kernel_pf_rules_after_reload: RefCell<HashMap<String, String>>,

    /// Keyed `(tenant, table)`; absent ⇒ empty table.
    kernel_pf_tables: RefCell<HashMap<(String, String), String>>,

    /// Absent host ⇒ resolves to nothing, so no resolve-drift finding by default.
    resolved_hosts: RefCell<HashMap<String, Vec<std::net::IpAddr>>>,

    resolve_calls: RefCell<Vec<String>>,

    /// Defaults to Touch-ID-active (no spurious `TouchIdMissing`).
    pam_sudo_content: RefCell<String>,

    pam_sudo_failure: RefCell<Option<HostFileError>>,

    /// Defaults to empty, so the sudo_local path is opt-in per test.
    pam_sudo_local_content: RefCell<String>,

    pam_sudo_local_failure: RefCell<Option<HostFileError>>,

    /// Defaults to "Status: Enabled" (no spurious `PfDisabled`).
    pf_status_content: RefCell<String>,

    pf_status_failure: RefCell<Option<FirewallError>>,

    /// Missing entry defaults to the runtime render of `profile_state` (no spurious drift).
    anchor_body_state: RefCell<HashMap<String, String>>,

    anchor_body_failure: RefCell<Option<HostFileError>>,

    anchor_body_reads: Cell<usize>,

    acl_ops: RefCell<Vec<AclOp>>,

    /// First match (by full equality) wins.
    acl_overrides: RefCell<Vec<(AclOp, AclError)>>,

    acl_failure: RefCell<Option<AclError>>,

    /// Unmatched: `Symlink(host_path)` for a declared share's tenant_path, else `Absent`.
    tenant_path_kinds: RefCell<HashMap<(String, PathBuf), PathKind>>,

    tenant_path_kind_failure: RefCell<Option<ProbeError>>,

    /// Call log; pins which sudo-bearing probes ran (e.g. skipped while sudo is uncached).
    tenant_path_kind_calls: RefCell<Vec<(String, PathBuf)>>,

    /// Unmatched paths default to `false`.
    tenant_dirs_present: RefCell<HashMap<(String, PathBuf), bool>>,

    tenant_dir_present_failure: RefCell<Option<ProbeError>>,

    tenant_dir_present_calls: RefCell<Vec<(String, PathBuf)>>,

    // TODO(smell): the cowork `Dir`/ACE defaults silently key off `profile_state`; make them explicit builders.
    /// Unmatched paths default to `Absent`, except cowork dirs of tenants with a loaded profile (`Dir`).
    host_path_kinds: RefCell<HashMap<PathBuf, PathKind>>,

    host_path_kind_failure: RefCell<Option<ProbeError>>,

    host_path_kind_calls: RefCell<Vec<PathBuf>>,

    /// Unmatched lookups synthesize a matching share-group ACE (no spurious AclDrift).
    host_acl_state: RefCell<HashMap<PathBuf, String>>,

    /// Absent ⇒ an empty tree, so no tree-drift finding by default.
    host_acl_trees: RefCell<HashMap<PathBuf, String>>,

    host_acl_failures: RefCell<HashMap<PathBuf, ProbeError>>,

    /// Unmatched lookups default to `true` (no spurious `HostNotInShareGroup`).
    host_in_group_state: RefCell<HashMap<(String, String), bool>>,

    host_in_group_invocations: RefCell<Vec<(String, String)>>,

    host_in_group_failure: RefCell<Option<AccountError>>,

    /// Defaults to `true`. While `false`, `tenant_path_kind` fails like a real `sudo -n`;
    /// `authenticate_sudo` or the first firewall op (bare sudo) caches it.
    sudo_session_cached: Cell<bool>,

    authenticate_sudo_calls: Cell<usize>,
    authenticate_sudo_failure: RefCell<Option<ProbeError>>,

    pam_ops: RefCell<Vec<PamOp>>,

    sudoers_ops: RefCell<Vec<SudoersOp>>,

    sudoers_failure: RefCell<Option<HostFileError>>,

    pam_failure: RefCell<Option<HostFileError>>,

    keychain_ops: RefCell<Vec<KeychainOp>>,

    /// Unmatched lookups default to `true`.
    tenant_keychain_state: RefCell<HashMap<String, bool>>,

    tenant_keychain_probe_failure: RefCell<Option<ProbeError>>,

    // TODO(smell): rename `stash_state`/`with_stash_present` (probe verdict) apart from `stash_passwords`/`with_stash` (secret).
    /// Unmatched lookups default to `true`.
    stash_state: RefCell<HashMap<String, bool>>,

    stash_probe_failure: RefCell<Option<KeychainError>>,

    /// Absent ⇒ `KeychainError::NotFound`, i.e. the shell unlock pass refuses.
    stash_passwords: RefCell<HashMap<String, KeychainPassword>>,

    find_stashed_password_failure: RefCell<Option<KeychainError>>,
    unlock_tenant_keychain_failure: RefCell<Option<KeychainError>>,

    unlock_calls: RefCell<Vec<String>>,

    /// Per-variant queues: KeychainOps carry a random password, so equality overrides can't match.
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

    pub fn with_exec_exit_codes(self, codes: &[i32]) -> Self {
        *self.exec_exit_codes.borrow_mut() = codes.iter().copied().collect();
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

    // TODO(smell): rename `login_calls` → `logins_with_dir` to pair with `exec_calls_with_dir`.
    pub fn logins(&self) -> Vec<String> {
        self.logins
            .borrow()
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    pub fn login_calls(&self) -> Vec<(String, Option<PathBuf>)> {
        self.logins.borrow().clone()
    }

    pub fn exec_calls(&self) -> Vec<(String, Vec<String>)> {
        self.exec_calls
            .borrow()
            .iter()
            .map(|(n, argv, _)| (n.clone(), argv.clone()))
            .collect()
    }

    pub fn exec_calls_with_dir(&self) -> Vec<ExecCall> {
        self.exec_calls.borrow().clone()
    }

    pub fn with_existing_profile(self, name: &str, content: &str) -> Self {
        self.profile_state
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self.pf_conf_state
            .replace_with(|conf| tenant::firewall::ensure_anchor_ref(conf, name));
        self
    }

    pub fn with_share_group_gid(self, group: &str, gid: u32) -> Self {
        self.share_group_gids
            .borrow_mut()
            .insert(group.to_string(), GroupId(gid));
        self
    }

    pub fn fail_next_share_group_gid(self, err: ProbeError) -> Self {
        *self.share_group_gid_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_user_primary_gid(self, name: &str, gid: u32) -> Self {
        self.user_primary_gids
            .borrow_mut()
            .insert(name.to_string(), GroupId(gid));
        self
    }

    pub fn fail_next_user_primary_gid(self, err: ProbeError) -> Self {
        *self.user_primary_gid_failure.borrow_mut() = Some(err);
        self
    }

    /// Replaces the whole file, dropping the references `with_existing_profile` added.
    pub fn with_pf_conf(self, content: &str) -> Self {
        *self.pf_conf_state.borrow_mut() = content.to_string();
        self.pf_conf_supplied.set(true);
        self
    }

    pub fn fail_next_pf_conf(self, err: FirewallError) -> Self {
        *self.pf_conf_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_create_profile_content(self, name: &str, content: &str) -> Self {
        self.create_profile_overrides
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    pub fn with_profile_fragment(self, fragment: &str, content: &str) -> Self {
        self.profile_fragments
            .borrow_mut()
            .insert(fragment.to_string(), content.to_string());
        self
    }

    pub fn fragment_reads(&self) -> Vec<String> {
        self.fragment_reads.borrow().clone()
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

    pub fn with_kernel_pf_rules_after_reload(self, name: &str, content: &str) -> Self {
        self.kernel_pf_rules_after_reload
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    pub fn fail_next_kernel_pf_rules(self, err: FirewallError) -> Self {
        *self.kernel_pf_rules_failure.borrow_mut() = Some(err);
        self
    }

    pub fn with_kernel_pf_table(self, name: &str, table: &str, content: &str) -> Self {
        self.kernel_pf_tables
            .borrow_mut()
            .insert((name.to_string(), table.to_string()), content.to_string());
        self
    }

    pub fn with_resolved_host(self, host: &str, ips: &[&str]) -> Self {
        self.resolved_hosts.borrow_mut().insert(
            host.to_string(),
            ips.iter().map(|ip| ip.parse().unwrap()).collect(),
        );
        self
    }

    pub fn resolved_hosts(&self) -> Vec<String> {
        self.resolve_calls.borrow().clone()
    }

    pub fn with_host_acl_tree(self, path: &std::path::Path, listing: &str) -> Self {
        self.host_acl_trees
            .borrow_mut()
            .insert(path.to_path_buf(), listing.to_string());
        self
    }

    pub fn kernel_pf_rules_calls(&self) -> Vec<String> {
        self.kernel_pf_rules_calls.borrow().clone()
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

    pub fn with_tenant_dir_present(self, name: &str, path: &std::path::Path) -> Self {
        self.tenant_dirs_present
            .borrow_mut()
            .insert((name.to_string(), path.to_path_buf()), true);
        self
    }

    pub fn fail_next_tenant_dir_present(self, err: ProbeError) -> Self {
        *self.tenant_dir_present_failure.borrow_mut() = Some(err);
        self
    }

    pub fn tenant_dir_present_calls(&self) -> Vec<(String, PathBuf)> {
        self.tenant_dir_present_calls.borrow().clone()
    }

    pub fn fail_next_authenticate_sudo(self, err: ProbeError) -> Self {
        *self.authenticate_sudo_failure.borrow_mut() = Some(err);
        self
    }

    pub fn authenticate_sudo_calls(&self) -> usize {
        self.authenticate_sudo_calls.get()
    }

    pub fn fail_next_tenant_path_kind(self, err: ProbeError) -> Self {
        *self.tenant_path_kind_failure.borrow_mut() = Some(err);
        self
    }

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

    /// For profile-less tests, where the profile-gated cowork defaults don't apply.
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

    pub fn host_path_kind_calls(&self) -> Vec<PathBuf> {
        self.host_path_kind_calls.borrow().clone()
    }

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

    pub fn anchor_body_reads(&self) -> usize {
        self.anchor_body_reads.get()
    }

    pub fn sudoers_ops(&self) -> Vec<SudoersOp> {
        self.sudoers_ops.borrow().clone()
    }

    pub fn fail_next_sudoers(self, err: HostFileError) -> Self {
        *self.sudoers_failure.borrow_mut() = Some(err);
        self
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

    pub fn with_stash(self, name: &str, password: KeychainPassword) -> Self {
        self.stash_passwords
            .borrow_mut()
            .insert(name.to_string(), password);
        self
    }

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

    fn share_group_gid(&self, group: &str) -> GroupId {
        self.share_group_gids
            .borrow()
            .get(group)
            .copied()
            .unwrap_or(GroupId(600))
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

    fn login(
        &self,
        name: &TenantUserName,
        dir: Option<&std::path::Path>,
    ) -> Result<i32, AccountError> {
        self.logins
            .borrow_mut()
            .push((name.to_string(), dir.map(std::path::Path::to_path_buf)));
        Ok(self.login_exit_code.get())
    }

    fn exec_as_tenant(
        &self,
        name: &TenantUserName,
        argv: &[String],
        dir: Option<&std::path::Path>,
    ) -> Result<i32, AccountError> {
        self.exec_calls.borrow_mut().push((
            name.to_string(),
            argv.to_vec(),
            dir.map(std::path::Path::to_path_buf),
        ));
        if let Some(err) = self.exec_failure.borrow_mut().take() {
            return Err(err);
        }
        if let Some(code) = self.exec_exit_codes.borrow_mut().pop_front() {
            return Ok(code);
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

    fn read_profile_fragment(&self, fragment: &str) -> Result<String, ProfileError> {
        self.fragment_reads.borrow_mut().push(fragment.to_string());
        match self.profile_fragments.borrow().get(fragment) {
            Some(content) => Ok(content.clone()),
            None => Err(ProfileError {
                message: format!("fragment '{fragment}' not found"),
            }),
        }
    }

    fn read_share_group_gid(&self, group: &GroupName) -> Result<GroupId, ProbeError> {
        if let Some(err) = self.share_group_gid_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self.share_group_gid(group.as_str()))
    }

    fn read_user_primary_gid(&self, name: &TenantUserName) -> Result<GroupId, ProbeError> {
        if let Some(err) = self.user_primary_gid_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self
            .user_primary_gids
            .borrow()
            .get(name.as_str())
            .copied()
            .unwrap_or_else(|| {
                self.share_group_gid(
                    tenant::domain::tenants::tenant_share_group_name(name.as_str()).as_str(),
                )
            }))
    }

    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        if let Some(err) = self.pf_conf_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self.pf_conf_state.borrow().clone())
    }

    fn pf_conf_references_anchor(&self, name: &TenantUserName) -> Result<bool, FirewallError> {
        let conf = self.read_pf_conf()?;
        Ok(!self.pf_conf_supplied.get()
            || tenant::firewall::is_anchor_referenced(&conf, name.as_str()))
    }

    fn describe_firewall(&self, op: &FirewallOp) -> String {
        MacosHostMachine.describe_firewall(op)
    }

    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError> {
        self.sudo_session_cached.set(true);
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
        if let FirewallOp::UpdateConfig { content } = op {
            *self.pf_conf_state.borrow_mut() = content.clone();
        }
        if *op == FirewallOp::Reload {
            // A reload re-reads every anchor, so pre-reload kernel state is gone.
            *self.kernel_pf_rules.borrow_mut() = self.kernel_pf_rules_after_reload.borrow().clone();
            self.kernel_pf_rules_failure.borrow_mut().take();
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
        self.kernel_pf_rules_calls
            .borrow_mut()
            .push(name.to_string());
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

    fn read_kernel_pf_table(
        &self,
        name: &TenantUserName,
        table: &str,
    ) -> Result<String, FirewallError> {
        Ok(self
            .kernel_pf_tables
            .borrow()
            .get(&(name.to_string(), table.to_string()))
            .cloned()
            .unwrap_or_default())
    }

    fn resolve_host(&self, host: &str) -> Result<Vec<std::net::IpAddr>, ProbeError> {
        self.resolve_calls.borrow_mut().push(host.to_string());
        Ok(self
            .resolved_hosts
            .borrow()
            .get(host)
            .cloned()
            .unwrap_or_default())
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
        self.anchor_body_reads.set(self.anchor_body_reads.get() + 1);
        if let Some(err) = self.anchor_body_failure.borrow_mut().take() {
            return Err(err);
        }
        if let Some(content) = self.anchor_body_state.borrow().get(name.as_str()) {
            return Ok(content.clone());
        }
        let hosts: Vec<tenant::firewall::EgressHost> =
            match self.profile_state.borrow().get(name.as_str()) {
                Some(toml) => match tenant::profile::parse(toml) {
                    Ok(profile) => profile
                        .allowlist
                        .runtime
                        .hosts
                        .iter()
                        .map(|e| tenant::firewall::EgressHost {
                            host: e.host.clone(),
                            ports: e.ports.clone(),
                        })
                        .collect(),
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
        if !self.sudo_session_cached.get() {
            return Err(ProbeError::NonZero {
                code: 1,
                stderr: "sudo: a password is required\n".to_string(),
            });
        }
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

    fn tenant_dir_present(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<bool, ProbeError> {
        self.tenant_dir_present_calls
            .borrow_mut()
            .push((name.to_string(), path.to_path_buf()));
        if let Some(err) = self.tenant_dir_present_failure.borrow_mut().take() {
            return Err(err);
        }
        Ok(self
            .tenant_dirs_present
            .borrow()
            .get(&(name.to_string(), path.to_path_buf()))
            .copied()
            .unwrap_or(false))
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
        // Profile-gated: destroy's cowork-notice probe relies on `Absent` without a profile.
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

    fn read_host_acl_tree(&self, path: &std::path::Path) -> Result<String, ProbeError> {
        Ok(self
            .host_acl_trees
            .borrow()
            .get(path)
            .cloned()
            .unwrap_or_default())
    }

    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError> {
        if let Some(err) = self.host_acl_failures.borrow_mut().remove(path) {
            return Err(err);
        }
        if let Some(listing) = self.host_acl_state.borrow().get(path) {
            return Ok(listing.clone());
        }
        // One share-group ACE per known tenant, plus the cowork ACE when a profile is loaded.
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

    fn authenticate_sudo(&self) -> Result<(), ProbeError> {
        self.authenticate_sudo_calls
            .set(self.authenticate_sudo_calls.get() + 1);
        if let Some(err) = self.authenticate_sudo_failure.borrow_mut().take() {
            return Err(err);
        }
        self.sudo_session_cached.set(true);
        Ok(())
    }

    fn describe_keychain(&self, op: &KeychainOp) -> String {
        MacosHostMachine.describe_keychain(op)
    }

    fn describe_pam(&self, op: &PamOp) -> String {
        MacosHostMachine.describe_pam(op)
    }

    fn describe_sudoers(&self, op: &SudoersOp) -> String {
        MacosHostMachine.describe_sudoers(op)
    }

    fn execute_sudoers(&self, op: &SudoersOp) -> Result<(), HostFileError> {
        self.sudoers_ops.borrow_mut().push(op.clone());
        match self.sudoers_failure.borrow_mut().take() {
            Some(err) => Err(err),
            None => Ok(()),
        }
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
            KeychainOp::CreateTenantKeychain { .. } => {
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
