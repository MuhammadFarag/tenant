//! Test substitute for the `HostMachine` substrate. Records every op
//! invocation (for behavioral assertions) and supports per-op failure
//! injection (for partial-failure-path tests like "sysadminctl-addUser
//! fails after dseditgroup-create succeeded"). Describe still works
//! (tests assert on the rendered plan/echo strings via the byte-exact
//! stdout E2E pattern) — delegated to `MacosHostMachine` so production +
//! test render identical bytes.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::adapters::macos::MacosHostMachine;
use crate::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupName, HostFileError, HostMachine, HostUserName, PathKind, ProbeError, ProfileOp,
    TenantUserName,
};
use crate::profile::{ProfileError, default_profile_toml};

/// Test substitute. Records every op invocation (for behavioral assertions)
/// and supports per-op failure injection (for partial-failure-path tests
/// like "sysadminctl-addUser fails after dseditgroup-create succeeded").
/// Describe still works (tests assert on the rendered plan/echo strings via
/// the byte-exact stdout E2E pattern).
#[derive(Default)]
pub struct StubHostMachine {
    account_ops: RefCell<Vec<AccountOp>>,
    profile_ops: RefCell<Vec<ProfileOp>>,
    firewall_ops: RefCell<Vec<FirewallOp>>,
    logins: RefCell<Vec<String>>,

    /// Recorded `exec_as_tenant` invocations. Each entry is `(name,
    /// argv)`. Tests assert on this list to pin the command-form
    /// substrate contract (verb dispatch invokes exec_as_tenant
    /// exactly once with the operator's argv intact).
    exec_calls: RefCell<Vec<(String, Vec<String>)>>,

    /// Exit code returned by `exec_as_tenant`. Default 0; tests set
    /// this to pin the command-form exit-code propagation contract.
    exec_exit_code: Cell<i32>,

    /// Spawn-failure override for `exec_as_tenant`. When `Some`, the
    /// next call returns this error instead of `exec_exit_code`. Lets
    /// tests pin the `ShellError::Account` path on a substrate-spawn
    /// failure (analogous to `with_response_to` for `execute_account`).
    exec_failure: RefCell<Option<AccountError>>,

    /// Per-op failure overrides for `execute_account`. First match (by full
    /// equality on the op value) wins. Replaces the pre-refactor argv-prefix
    /// matcher (`with_response_to`) with a more explicit op-shape matcher.
    account_overrides: RefCell<Vec<(AccountOp, AccountError)>>,

    /// Blanket failure for `execute_account` calls that don't match an
    /// override. Stored as a (code, stderr) pair so it's Clone-able and
    /// fires on every call (mirrors the pre-refactor
    /// `StubHostMachine::failing` infinite-fire shape). Spawn-failure
    /// injection isn't supported by the blanket path; use a per-op
    /// override for Spawn semantics.
    account_blanket_failure: RefCell<Option<(i32, String)>>,

    /// One-shot failure for the next `execute_profile` call. Cleared after
    /// it fires. Mirrors the pre-refactor `StubProfileStore::with_write_failure`.
    profile_failure: RefCell<Option<ProfileError>>,

    /// Per-op failure overrides for `execute_firewall`. First match wins
    /// (by full equality on the op value). Same shape as
    /// `account_overrides` — lets a test pin "the InstallAnchor step fails
    /// but BackupConfig succeeded" without affecting unrelated firewall
    /// ops in the same flow.
    firewall_overrides: RefCell<Vec<(FirewallOp, FirewallError)>>,

    /// One-shot failure for the next `execute_firewall` call that doesn't
    /// match an override. Useful when the test cares about "the next pfctl
    /// invocation fails" without naming which op specifically.
    firewall_failure: RefCell<Option<FirewallError>>,

    /// Exit code returned by `login`. Default 0; tests set this to pin the
    /// shell-verb's exit-code propagation contract.
    login_exit_code: Cell<i32>,

    /// In-memory simulation of the on-disk profile state. `execute_profile`
    /// mutates this — `Create` writes `default_profile_toml()` under the
    /// tenant name, `Delete` removes the entry — so tests can assert on
    /// presence/absence (`has_profile`) and byte-exact content
    /// (`profile_state`). Also serves as the `read_profile` backing store:
    /// reads return the entry under `name` if present, else a "not found"
    /// `ProfileError`. Mirrors the pre-refactor `StubProfileStore`'s
    /// `HashMap<String, String>` backing.
    profile_state: RefCell<HashMap<String, String>>,

    /// In-memory simulation of `/etc/pf.conf` for `read_pf_conf`. Default
    /// empty. Tests with non-empty starting state (e.g. a host with
    /// another tenant already installed) pre-load via `with_pf_conf`.
    /// Not mutated by `execute_firewall` — the substrate models pfctl
    /// ops as side effects on a real-host fs, and tests assert behavior
    /// via `firewall_ops()` rather than by re-reading conf state.
    pf_conf_state: RefCell<String>,

    /// Per-name override for what `ProfileOp::Create` writes. When
    /// present, `execute_profile(Create)` stores this content under
    /// `name` instead of `default_profile_toml()`. Models "as if the
    /// scaffolded default had different runtime/install hosts" —
    /// lets create-flow tests exercise the read_profile + parse +
    /// render_anchor path with non-empty allowlists without
    /// rewriting `default_profile_toml`.
    create_profile_overrides: RefCell<HashMap<String, String>>,

    /// Recorded probe invocations. Each entry is the `(name, path,
    /// mode)` tuple as passed to `probe_access_as_tenant`. Tests
    /// assert on this list to pin the curated probe sequence.
    probes: RefCell<Vec<(String, PathBuf, AccessMode)>>,

    /// Per-(name, path, mode) outcome overrides. First match (by full
    /// equality on the tuple) wins; unmatched probes default to
    /// `AccessOutcome::Denied` (the expected case for sensitive
    /// paths). Mirrors `with_existing_profile` / `with_pf_conf`
    /// builder shape.
    probe_outcomes: RefCell<HashMap<(String, PathBuf, AccessMode), AccessOutcome>>,

    /// One-shot probe failure injection. Fires on the next
    /// `probe_access_as_tenant` call regardless of which tuple
    /// matched; cleared after firing. Mirrors `fail_next_profile` /
    /// `fail_next_firewall`. Used to pin substrate-failure exit-74
    /// behavior.
    probe_failure: RefCell<Option<ProbeError>>,

    /// In-memory simulation of the host's concatenated env policy
    /// (sudoers main + drop-ins). Default empty — production tests
    /// set this via `with_env_policy_content` to model the operator's
    /// real sudoers state.
    env_policy_content: RefCell<String>,

    /// One-shot env-policy read failure. Mirrors `probe_failure`.
    env_policy_failure: RefCell<Option<HostFileError>>,

    /// Per-tenant in-memory simulation of the kernel's pf rules for
    /// the `tenant-<name>` anchor. Lookup keyed by tenant name; a
    /// missing entry falls back to a "happy" default rules string
    /// (both `pass` + `block` present) so doctor tests that don't
    /// care about the PF-rule path don't see spurious `PfRuleDrift`
    /// findings. Tests override with `with_kernel_pf_rules` to
    /// exercise drift cases.
    kernel_pf_rules: RefCell<HashMap<String, String>>,

    /// One-shot kernel-pf-rules read failure. Mirrors `probe_failure`
    /// / `env_policy_failure`. Used to pin substrate-failure exit-74
    /// behavior for the new firewall-read carve-out.
    kernel_pf_rules_failure: RefCell<Option<FirewallError>>,

    /// In-memory simulation of `/etc/pam.d/sudo`. Default is a
    /// "Touch-ID-active" placeholder (see `StubHostMachine::new`) so
    /// doctor tests that don't care about the PAM path don't see
    /// spurious `TouchIdMissing` findings. Tests override with
    /// `with_pam_sudo_content` to exercise the absent / commented
    /// cases.
    pam_sudo_content: RefCell<String>,

    /// One-shot pam.d/sudo read failure. Mirrors `env_policy_failure`.
    pam_sudo_failure: RefCell<Option<HostFileError>>,

    /// In-memory simulation of `pfctl -si` output. Default is
    /// "Status: Enabled" so doctor tests that don't care about
    /// pf-enabled don't see spurious `PfDisabled` findings. Tests
    /// override with `with_pf_status_content`.
    pf_status_content: RefCell<String>,

    /// One-shot pf-status read failure. Mirrors
    /// `kernel_pf_rules_failure`.
    pf_status_failure: RefCell<Option<FirewallError>>,

    /// Per-tenant in-memory simulation of the on-disk anchor body.
    /// Lookup keyed by tenant name; a missing entry falls back to
    /// the runtime-tier render of whatever profile is in
    /// `profile_state` for the same name, OR to
    /// `render_anchor(name, &[])` when no profile is present — both
    /// shapes match what doctor would compute as "expected" so tests
    /// that don't care about anchor-body drift don't see spurious
    /// `AnchorBodyDrift` findings. Tests override with
    /// `with_anchor_body` to exercise hand-edit drift.
    anchor_body_state: RefCell<HashMap<String, String>>,

    /// One-shot anchor-body read failure. Mirrors `pam_sudo_failure`.
    anchor_body_failure: RefCell<Option<HostFileError>>,

    /// Recorded `execute_acl` invocations in call order. Tests assert on
    /// this list to pin the reapply substrate's per-share op sequence
    /// (grant ops in profile-declared order, paired correctly with
    /// host_path / group / mode). Mirrors `account_ops` / `firewall_ops`.
    acl_ops: RefCell<Vec<AclOp>>,

    /// Per-op failure overrides for `execute_acl`. First match (by full
    /// equality) wins. Mirrors `account_overrides` /
    /// `firewall_overrides`.
    acl_overrides: RefCell<Vec<(AclOp, AclError)>>,

    /// One-shot failure for the next `execute_acl` call that doesn't
    /// match an override. Mirrors `fail_next_firewall`.
    acl_failure: RefCell<Option<AclError>>,

    /// Per-(name, path) override for `tenant_path_kind`. First match
    /// wins; unmatched lookups consult `profile_state[name]` and
    /// return `Symlink(host_path)` when the queried path matches a
    /// declared share's expanded tenant_path (the doctor-passing
    /// "shares already reapplied" state); otherwise `PathKind::Absent`
    /// (the unprovisioned-path case where the substrate freely
    /// installs the symlink). Tests use the override to exercise the
    /// Q12 `TenantPathOccupied` refusal path or other drift cases.
    tenant_path_kinds: RefCell<HashMap<(String, PathBuf), PathKind>>,

    /// One-shot `tenant_path_kind` failure. Mirrors `probe_failure`.
    tenant_path_kind_failure: RefCell<Option<ProbeError>>,

    /// Per-path override for `read_host_acl`. First match wins;
    /// unmatched lookups default to a synthesized listing that
    /// satisfies `doctor::has_group_acl_entry` for every plausibly-named
    /// tenant group — so tests that don't exercise AclDrift don't see
    /// spurious findings. Tests that DO exercise AclDrift load a
    /// listing without the expected group via `with_host_acl`.
    host_acl_state: RefCell<HashMap<PathBuf, String>>,

    /// Per-path one-shot failure injection for `read_host_acl`. First
    /// match wins; cleared after firing. Mirrors `tenant_path_kind_failure`.
    host_acl_failures: RefCell<HashMap<PathBuf, ProbeError>>,

    /// Per-(host, group) override for `host_in_group`. First match
    /// wins; unmatched lookups default to `true` so doctor tests that
    /// don't exercise the `HostNotInShareGroup` finding don't see a
    /// spurious warning. Tests that DO exercise the finding set
    /// `false` via `with_host_in_group`.
    host_in_group_state: RefCell<HashMap<(String, String), bool>>,

    /// Recorded `host_in_group` invocations in call order (one entry
    /// per call). Tests use this to pin that the catch-up path inside
    /// `execute_reapply_plan` fires the AddHost op unconditionally
    /// (the recorder shows the op fired regardless of stub state).
    host_in_group_invocations: RefCell<Vec<(String, String)>>,

    /// One-shot `host_in_group` failure. Mirrors `probe_failure`. Used
    /// to pin the doctor-failure exit-74 behavior when
    /// dseditgroup-checkmember can't run.
    host_in_group_failure: RefCell<Option<AccountError>>,
}

impl StubHostMachine {
    pub fn new() -> Self {
        let s = Self::default();
        // Default env policy to "no leak" so doctor tests that don't
        // care about the env-leak path don't see a spurious EnvLeak
        // finding. Tests override with `with_env_policy_content` to
        // exercise the leak case.
        *s.env_policy_content.borrow_mut() =
            "Defaults env_delete += \"SSH_AUTH_SOCK\"\n".to_string();
        // Default pam.d/sudo to "Touch ID active" so doctor tests
        // that don't care about the Touch-ID-for-sudo path don't see
        // a spurious TouchIdMissing finding. Tests override with
        // `with_pam_sudo_content`.
        *s.pam_sudo_content.borrow_mut() = "auth       sufficient     pam_tid.so\n".to_string();
        // Default pf status to "Enabled" so doctor tests that don't
        // care about the pf-enabled path don't see a spurious
        // PfDisabled finding. Tests override with
        // `with_pf_status_content`.
        *s.pf_status_content.borrow_mut() = "Status: Enabled for 0 days 00:00:00\n".to_string();
        s
    }

    /// Configure the next `execute_account` call matching `op` to fail with
    /// `err`. Matches by full equality on the op value. Builder pattern
    /// (chainable, takes `self` by value).
    pub fn fail_account_op(self, op: AccountOp, err: AccountError) -> Self {
        self.account_overrides.borrow_mut().push((op, err));
        self
    }

    /// Configure all `execute_account` calls to fail with `NonZero { code,
    /// stderr }` (overridden by per-op matchers). Mirrors the pre-refactor
    /// `StubHostMachine::failing_with`. Fires on every call (not one-shot).
    pub fn fail_account_blanket(self, code: i32, stderr: &str) -> Self {
        *self.account_blanket_failure.borrow_mut() = Some((code, stderr.to_string()));
        self
    }

    /// Configure the next `execute_profile` call to fail with `err`.
    /// One-shot — cleared after firing. Used by the create-side
    /// profile-write-failure test.
    pub fn fail_next_profile(self, err: ProfileError) -> Self {
        *self.profile_failure.borrow_mut() = Some(err);
        self
    }

    /// Configure the next `execute_firewall` call matching `op` to fail
    /// with `err`. Matches by full equality on the op value. Mirrors
    /// `fail_account_op`.
    pub fn fail_firewall_op(self, op: FirewallOp, err: FirewallError) -> Self {
        self.firewall_overrides.borrow_mut().push((op, err));
        self
    }

    /// Configure the next non-matching `execute_firewall` call to fail
    /// with `err`. One-shot — cleared after firing. Mirrors
    /// `fail_next_profile`.
    pub fn fail_next_firewall(self, err: FirewallError) -> Self {
        *self.firewall_failure.borrow_mut() = Some(err);
        self
    }

    /// Configure the value returned by `login`. Pins the shell-verb's
    /// exit-code propagation contract.
    pub fn login_exit_code(self, code: i32) -> Self {
        self.login_exit_code.set(code);
        self
    }

    /// Configure the value returned by `exec_as_tenant`. Pins the
    /// command-form shell verb's exit-code propagation contract.
    pub fn exec_exit_code(self, code: i32) -> Self {
        self.exec_exit_code.set(code);
        self
    }

    /// Configure the next `exec_as_tenant` call to fail with `err`
    /// instead of returning an exit code. One-shot — cleared after
    /// firing. Mirrors `fail_next_profile` / `fail_next_firewall`.
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

    /// Pre-load a profile (e.g. for destroy tests that need to assert
    /// "this was here before, gone after"). Content is opaque to the
    /// substrate; only the presence/absence semantics matter for the
    /// assertions.
    pub fn with_existing_profile(self, name: &str, content: &str) -> Self {
        self.profile_state
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    /// Pre-load `/etc/pf.conf` content for `read_pf_conf`. Used by
    /// firewall tests that need a host-state with existing anchor refs
    /// (so `ensure_anchor_ref` / `remove_anchor_ref` exercise the
    /// non-empty case).
    pub fn with_pf_conf(self, content: &str) -> Self {
        *self.pf_conf_state.borrow_mut() = content.to_string();
        self
    }

    /// Override the content that `ProfileOp::Create` writes for `name`.
    /// Production always writes `default_profile_toml()` (empty
    /// allowlists); this builder lets a create-flow test simulate
    /// "what if the scaffolded default included some hosts" without
    /// rewriting the default. The downstream `read_profile` then sees
    /// the override, so `parse` + `render_anchor` produce a populated
    /// `InstallAnchor.body` — closing the automated end-to-end loop on
    /// the allow path (manual smoke verifies the same data flow
    /// against real pfctl).
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

    /// Configure the probe outcome for one `(name, path, mode)` tuple.
    /// Subsequent `probe_access_as_tenant(name, path, mode)` calls
    /// return `outcome` instead of the default `Denied`. Used by
    /// doctor tests to inject "this path IS readable from the tenant"
    /// without poking the host's actual filesystem.
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

    /// Configure the next `probe_access_as_tenant` call to fail with
    /// `err`. One-shot — cleared after firing. Mirrors
    /// `fail_next_profile` / `fail_next_firewall`.
    pub fn fail_next_probe(self, err: ProbeError) -> Self {
        *self.probe_failure.borrow_mut() = Some(err);
        self
    }

    /// Recorded probe invocations in call order. Each entry is the
    /// `(name, path, mode)` tuple the writer asked the substrate to
    /// probe.
    pub fn probes(&self) -> Vec<(String, PathBuf, AccessMode)> {
        self.probes.borrow().clone()
    }

    /// Pre-load the host's env policy text for `read_env_policy`. Used
    /// by doctor's env-leak tests to model the operator's `/etc/sudoers`
    /// + `/etc/sudoers.d/*` concatenation without poking the host.
    pub fn with_env_policy_content(self, content: &str) -> Self {
        *self.env_policy_content.borrow_mut() = content.to_string();
        self
    }

    /// Configure the next `read_env_policy` call to fail with `err`.
    /// One-shot — cleared after firing.
    pub fn fail_next_env_policy(self, err: HostFileError) -> Self {
        *self.env_policy_failure.borrow_mut() = Some(err);
        self
    }

    /// Pre-load the kernel pf rules for the `tenant-<name>` anchor.
    /// `read_kernel_pf_rules(name)` returns this text. Used by
    /// PF-rule-drift tests to inject "kernel anchor is empty" or
    /// "kernel anchor is missing a pass rule" cases.
    pub fn with_kernel_pf_rules(self, name: &str, content: &str) -> Self {
        self.kernel_pf_rules
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    /// Configure the next `read_kernel_pf_rules` call to fail with
    /// `err`. One-shot — cleared after firing. Pins
    /// substrate-failure exit-74 behavior for the firewall-read
    /// carve-out.
    pub fn fail_next_kernel_pf_rules(self, err: FirewallError) -> Self {
        *self.kernel_pf_rules_failure.borrow_mut() = Some(err);
        self
    }

    /// Pre-load `/etc/pam.d/sudo` content for `read_pam_sudo`. Used
    /// by Touch-ID-for-sudo tests to model "operator's pam.d has it /
    /// doesn't have it / has it commented out".
    pub fn with_pam_sudo_content(self, content: &str) -> Self {
        *self.pam_sudo_content.borrow_mut() = content.to_string();
        self
    }

    /// Configure the next `read_pam_sudo` call to fail with `err`.
    /// One-shot — cleared after firing.
    pub fn fail_next_pam_sudo(self, err: HostFileError) -> Self {
        *self.pam_sudo_failure.borrow_mut() = Some(err);
        self
    }

    /// Pre-load the `pfctl -si` output for `read_pf_status`. Used
    /// by pf-status tests to model "pf is disabled" vs "pf is enabled"
    /// without poking the host's actual pf state.
    pub fn with_pf_status_content(self, content: &str) -> Self {
        *self.pf_status_content.borrow_mut() = content.to_string();
        self
    }

    /// Configure the next `read_pf_status` call to fail with `err`.
    /// One-shot — cleared after firing.
    pub fn fail_next_pf_status(self, err: FirewallError) -> Self {
        *self.pf_status_failure.borrow_mut() = Some(err);
        self
    }

    /// Pre-load the on-disk anchor body for `name`.
    /// `read_anchor_body(name)` returns this text. Used by anchor-body
    /// drift tests to inject "operator hand-edited the file" or
    /// "anchor matches install-tier render but not runtime-tier"
    /// drift cases. Mirrors `with_kernel_pf_rules` (content-shaped
    /// subject — no `_content` suffix).
    pub fn with_anchor_body(self, name: &str, content: &str) -> Self {
        self.anchor_body_state
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    /// Configure the next `read_anchor_body` call to fail with `err`.
    /// One-shot — cleared after firing. Pins substrate-failure
    /// exit-74 behavior for the anchor-body carve-out.
    pub fn fail_next_anchor_body(self, err: HostFileError) -> Self {
        *self.anchor_body_failure.borrow_mut() = Some(err);
        self
    }

    /// Configure the next `execute_acl` call matching `op` to fail with
    /// `err`. Matches by full equality on the op value. Mirrors
    /// `fail_account_op` / `fail_firewall_op`.
    pub fn fail_acl_op(self, op: AclOp, err: AclError) -> Self {
        self.acl_overrides.borrow_mut().push((op, err));
        self
    }

    /// Configure the next non-matching `execute_acl` call to fail with
    /// `err`. One-shot — cleared after firing.
    pub fn fail_next_acl(self, err: AclError) -> Self {
        *self.acl_failure.borrow_mut() = Some(err);
        self
    }

    /// Recorded `execute_acl` invocations in call order.
    pub fn acl_ops(&self) -> Vec<AclOp> {
        self.acl_ops.borrow().clone()
    }

    /// Pre-load the `PathKind` outcome for `(name, path)`. Used by
    /// share-reapply tests to model "tenant_path is a real directory"
    /// (triggers `ShareError::TenantPathOccupied`) or "tenant_path
    /// is an existing symlink" (idempotent re-link) cases. Unmatched
    /// lookups default to `Absent`.
    pub fn with_tenant_path_kind(self, name: &str, path: &std::path::Path, kind: PathKind) -> Self {
        self.tenant_path_kinds
            .borrow_mut()
            .insert((name.to_string(), path.to_path_buf()), kind);
        self
    }

    /// Configure the next `tenant_path_kind` call to fail with `err`.
    /// One-shot — cleared after firing.
    pub fn fail_next_tenant_path_kind(self, err: ProbeError) -> Self {
        *self.tenant_path_kind_failure.borrow_mut() = Some(err);
        self
    }

    /// Pre-load the `ls -lde` listing returned for `path`. Used by
    /// doctor tests to model "host_path is missing the
    /// `<tenant>-tenant-share` ACL entry" (triggers `Finding::AclDrift`)
    /// or "host_path carries an unrelated group's entry" cases.
    pub fn with_host_acl(self, path: &std::path::Path, listing: &str) -> Self {
        self.host_acl_state
            .borrow_mut()
            .insert(path.to_path_buf(), listing.to_string());
        self
    }

    /// Configure the next `read_host_acl(path)` call to fail with `err`.
    /// One-shot — cleared after firing.
    pub fn fail_next_host_acl(self, path: &std::path::Path, err: ProbeError) -> Self {
        self.host_acl_failures
            .borrow_mut()
            .insert(path.to_path_buf(), err);
        self
    }

    /// Pre-load the membership outcome for `(host, group)`. Used by
    /// doctor tests to model "host is not a member of the tenant's
    /// share group" (triggers `Finding::HostNotInShareGroup`).
    /// Unmatched lookups default to `true` so existing doctor tests
    /// see no spurious finding.
    pub fn with_host_in_group(self, host: &str, group: &str, is_member: bool) -> Self {
        self.host_in_group_state
            .borrow_mut()
            .insert((host.to_string(), group.to_string()), is_member);
        self
    }

    /// Configure the next `host_in_group` call to fail with `err`.
    /// One-shot — cleared after firing.
    pub fn fail_next_host_in_group(self, err: AccountError) -> Self {
        *self.host_in_group_failure.borrow_mut() = Some(err);
        self
    }

    /// Recorded `host_in_group` invocations in call order. Tests use
    /// this to pin the catch-up path fires unconditionally (the
    /// recorder shows the trait-level call regardless of stub state).
    pub fn host_in_group_invocations(&self) -> Vec<(String, String)> {
        self.host_in_group_invocations.borrow().clone()
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
                // Honor a `with_create_profile_content` override if one
                // was registered for this name; otherwise write the
                // production default. Lets create-flow tests exercise
                // the non-empty-allowlist code path.
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
            // Default to a "happy" rules string (both `pass` + `block`
            // present) so tests that don't care about PF-drift don't
            // see spurious findings. Tests that exercise drift inject
            // via `with_kernel_pf_rules`.
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
        // Default: render from the profile state if present, else
        // empty-allowlist render. Both shapes match what doctor would
        // compute as "expected" so tests that don't care about
        // anchor-body drift don't see spurious findings.
        let hosts: Vec<String> = match self.profile_state.borrow().get(name.as_str()) {
            Some(toml) => match crate::profile::parse(toml) {
                Ok(profile) => profile.allowlist.runtime.hosts.clone(),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        Ok(crate::firewall::render_anchor(name.as_str(), &hosts))
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
        // Default: if the profile declares a share whose expanded
        // tenant_path matches `path`, return Symlink(host_path) — the
        // doctor-passing state where shares are already reapplied.
        // Otherwise Absent (the unprovisioned-path case the substrate
        // freely installs into).
        if let Some(toml) = self.profile_state.borrow().get(name.as_str())
            && let Ok(profile) = crate::profile::parse(toml)
        {
            for share in &profile.shares {
                let expanded =
                    crate::profile::expand_tenant_path(name.as_str(), &share.tenant_path);
                if expanded == path {
                    return Ok(PathKind::Symlink(share.host_path.clone()));
                }
            }
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
        // Default listing: emit one synthetic ACL entry per known
        // tenant (via profile_state's keys, which the stub_host_accounts keeps
        // aligned with the test's tenant set). Tests that don't
        // exercise AclDrift see the matching entry for every tenant
        // they audit; tests that DO exercise drift override via
        // `with_host_acl(path, listing-without-entry)`.
        let mut listing = String::new();
        for name in self.profile_state.borrow().keys() {
            listing.push_str(&format!(
                " 0: group:{name}-tenant-share allow list,add_file,search\n"
            ));
        }
        Ok(listing)
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
}
