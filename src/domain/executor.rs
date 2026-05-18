use super::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclOp, FirewallError, FirewallOp,
    GroupName, HostFileError, HostUserName, Op, PathKind, ProbeError, ProfileOp, TenantUserName,
};
use crate::profile::ProfileError;

/// Host-side substrate. Knows how to render ops as operator-facing display
/// lines (`describe_*`) and how to execute them on this host (`execute_*` +
/// `login`). Production wires `MacosExecutor` (knows dseditgroup,
/// sysadminctl, dscl, std::fs for profile files); tests wire `StubExecutor`
/// (records ops, returns configured outcomes); dry-run wires
/// `DryRunExecutor` (no-op execute; describe still works).
///
/// Methods are per-domain so each domain keeps its own error type — no
/// enum-wrapping at call sites and no nested pattern matching in the writer.
pub trait Executor {
    fn describe_account(&self, op: &AccountOp) -> String;
    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError>;

    /// Interactive login. Separate from `execute_account` because the return
    /// type (child exit code) and stdio semantics (inherit, don't capture)
    /// are incompatible with the non-interactive path. Stub records via
    /// `logins()`; production uses `Command::status` so the parent's stdio
    /// passes through.
    fn login(&self, name: &TenantUserName) -> Result<i32, AccountError>;

    /// Run a single command as the tenant inside a login shell. Sibling
    /// carve-out to `login` — same stdio posture (inherit), same return
    /// shape (child exit code), different argv (`sudo -iu <name> -- <argv>`).
    /// Used by `tenant shell <name> -- <cmd>`. `argv` must be non-empty;
    /// callers route empty argv to `login` before reaching this method.
    /// Stub records via `exec_calls()`; production uses `Command::status`.
    fn exec_as_tenant(&self, name: &TenantUserName, argv: &[String]) -> Result<i32, AccountError>;

    fn describe_profile(&self, op: &ProfileOp) -> String;
    fn execute_profile(&self, op: &ProfileOp) -> Result<(), ProfileError>;

    /// Read the on-disk profile TOML content for `name`. Separate from
    /// `execute_profile` because the return type (file content, not unit)
    /// doesn't fit `execute_profile`'s shape — same carve-out rationale
    /// as `login`. Called by the create-side firewall step to feed
    /// the anchor renderer.
    fn read_profile(&self, name: &TenantUserName) -> Result<String, ProfileError>;

    /// Read the current `/etc/pf.conf` content. Used by the Writer to
    /// compute the post-edit conf via `firewall::ensure_anchor_ref` /
    /// `remove_anchor_ref` before issuing `FirewallOp::UpdateConfig`.
    /// Same carve-out rationale as `read_profile`: the return type is
    /// content, not unit. Dry-run returns an empty conf — the plan
    /// focuses on what tenant adds, not what's already there.
    fn read_pf_conf(&self) -> Result<String, FirewallError>;

    fn describe_firewall(&self, op: &FirewallOp) -> String;
    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError>;

    /// Probe the kind of filesystem entry at `path`, as tenant `name`
    /// sees it. Substrate composition: `sudo -n -u <name> /bin/test
    /// -L <path>` (symlink-check) and `-e <path>` (existence-check); the
    /// pair collapses into one of `PathKind { Absent, Symlink, Other }`.
    /// Reuses `ProbeError` (same substrate posture as `probe_access_as_tenant`:
    /// the machinery-failure cases — sudo not on PATH, sudo prompt
    /// cache expired — are errors; the kind-of-entry outcomes are
    /// non-error variants). Carve-out method (same posture as the other
    /// probe-style carve-outs): return type isn't `Result<(), E>` so it
    /// doesn't fit `WritableOp`.
    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<PathKind, ProbeError>;

    /// Render an `AclOp` as an operator-facing `chmod +a/-a` line. The
    /// rendered ACL entry string (`"group:<g> allow <bits>"`) is the
    /// same byte sequence the production substrate uses for its
    /// idempotence pre-check — `AclMode::acl_bits` is the single source
    /// of truth for the bit list so any drift between describe and
    /// execute would break idempotence visibly.
    fn describe_acl(&self, op: &AclOp) -> String;

    /// Apply an `AclOp` to the host. Production pre-checks `ls -lde
    /// <path>` for an existing entry before invoking chmod — sandbox's
    /// idempotence pattern transcribed verbatim. A `Grant` for an
    /// already-present entry is a noop; a `Revoke` for an absent entry
    /// is a noop. The Writer doesn't need to track ACL state separately
    /// — substrate is the source of truth.
    fn execute_acl(&self, op: &AclOp) -> Result<(), AclError>;

    /// Probe whether `name` (a tenant) can access `path` under the
    /// requested `mode`. Implementation invokes `sudo -n -u <name>
    /// /bin/test -<r|x> <path>` and maps the exit code: `0` →
    /// `Allowed`, `1` → `Denied`, anything else → `Unknown`. Probe-
    /// substrate failures (sudo not on PATH, fork failed) surface as
    /// `ProbeError`. Carve-out method (same posture as `read_profile`
    /// / `read_pf_conf` / `login`): the return type isn't `Result<(),
    /// E>` so it doesn't fit the `WritableOp` shape, and probes aren't
    /// the verb's intent — they're how doctor learns — so plan/echo
    /// rendering doesn't apply.
    fn probe_access_as_tenant(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
        mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError>;

    /// Read the host's environment-propagation policy as the substrate
    /// understands it. Concatenates `/etc/sudoers` + every file in
    /// `/etc/sudoers.d/` into one text blob (newline-separated, no
    /// origin attribution — doctor's parser greps for `env_delete`
    /// directives without caring which file declared them). Carve-out
    /// (same posture as `read_profile` / `read_pf_conf`): the return
    /// type is content, not unit; the substrate handles privileged
    /// reads, doctor handles parsing.
    fn read_env_policy(&self) -> Result<String, HostFileError>;

    /// Read the kernel's pf rules for the per-tenant anchor
    /// `tenant-<name>`. Substrate is `sudo pfctl -a tenant-<name> -sr`;
    /// the raw text is fed to `doctor::pf_rule_presence_check` which
    /// looks for `pass` + `block` lines (structural check, not
    /// line-by-line comparison). Reuses `FirewallError` because pfctl
    /// is the substrate. Carve-out: content return, not unit.
    fn read_kernel_pf_rules(&self, name: &TenantUserName) -> Result<String, FirewallError>;

    /// Read `/etc/pam.d/sudo` so doctor can check for an active
    /// `pam_tid.so` line (Touch-ID-for-sudo). The file is mode 0644
    /// on macOS — no sudo required; substrate is `fs::read_to_string`.
    /// Reuses `HostFileError` (same shape as `read_env_policy`'s
    /// privileged reads; the `Spawn` variant just doesn't fire on
    /// this path). Carve-out: content return, not unit.
    fn read_pam_sudo(&self) -> Result<String, HostFileError>;

    /// Read pf's global enabled status. Substrate is `sudo pfctl
    /// -si`; the raw text is fed to `doctor::pf_status_enabled`
    /// which looks for the `Status: Enabled` line. Reuses
    /// `FirewallError` (pfctl substrate). Carve-out: content
    /// return, not unit.
    ///
    /// Why this matters: pf can be globally disabled with `pfctl
    /// -d`. When disabled, NO anchor rules enforce — every tenant's
    /// firewall is silently inert. `Finding::PfDisabled` is the
    /// host-wide critical-tier finding that surfaces this state.
    fn read_pf_status(&self) -> Result<String, FirewallError>;

    /// Read the on-disk per-tenant anchor file
    /// (`firewall::tenant_anchor_path(name.as_str())`). Mode 0644 root-owned
    /// (the install flow sets this) — direct `fs::read_to_string`,
    /// no sudo. Reuses `HostFileError` (same shape and substrate
    /// posture as `read_pam_sudo`). Carve-out: content return, not
    /// unit.
    ///
    /// `Finding::AnchorBodyDrift` consumes this: doctor compares the
    /// on-disk body byte-for-byte against `firewall::render_anchor`
    /// over the runtime-tier hosts. The "file" side complement to
    /// `read_kernel_pf_rules`'s "kernel" side — neither alone is
    /// sufficient, since the two can drift independently (operator
    /// hand-edit on the file, or a `pfctl -f` race on the kernel).
    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError>;

    /// Read the host-side ACL state on `path`. Substrate is `ls -lde
    /// <path>` from the operator process (no sudo — operator owns or
    /// has list-traverse on host_path). Returns the raw output as a
    /// single string for `doctor::has_group_acl_entry` to grep.
    /// Reuses `ProbeError` because the substrate posture mirrors
    /// `probe_access_as_tenant` (machinery-failure cases are errors;
    /// "no matching entry" is a non-error outcome the parser turns
    /// into a no-finding). Carve-out: content return, not unit.
    ///
    /// `Finding::AclDrift` consumes this: doctor walks the profile's
    /// `[[shares]]` array, calls `read_host_acl(host_path)` for each,
    /// and emits AclDrift when the expected `<tenant>-tenant-share`
    /// group ACL entry is absent.
    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError>;

    /// Probe whether `host` is currently a member of `group` in the
    /// local directory service. Substrate is `dseditgroup -o
    /// checkmember -m <host> <group>` (no sudo — read-only DS query).
    /// Exit code 0 maps to `Ok(true)`; non-zero exit (host not a
    /// member OR group absent) maps to `Ok(false)`. Machinery
    /// failures — sudo/dseditgroup not on PATH, fork failed — surface
    /// as `AccountError` (same shape as the account-domain
    /// substrate's other invocations). Carve-out method (return type
    /// is `bool`, not unit, so it doesn't fit `WritableOp`).
    ///
    /// Doctor's `Finding::HostNotInShareGroup` consumes this to
    /// detect drift on legacy tenants (created before host membership
    /// was wired into create) and operator-manual removals. Also
    /// used internally by `MacosExecutor::execute_account` on
    /// `RemoveHostFromShareGroup` to short-circuit the `-d` edit
    /// when the host isn't currently a member (substrate-side
    /// idempotence).
    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError>;
}

/// Bridge from a leaf op to the typed execution path. `Writer::run` uses
/// this to execute an op with its domain-specific error type while still
/// going through `Op::describe_via` for the echo line. Ops that don't
/// fit (notably `AccountOp::LoginAsUser`, which goes through
/// `Executor::login` for its interactive stdio semantics) can still be
/// rendered via `Op::describe_via` without implementing `WritableOp` —
/// they just don't flow through `Writer::run`.
pub trait WritableOp {
    type Error;
    fn execute_via(&self, executor: &dyn Executor) -> Result<(), Self::Error>;
    fn op_ref(&self) -> Op<'_>;
}
