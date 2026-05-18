//! Host-side substrate for the writer's domain operations.
//!
//! # Architecture
//!
//! Earlier iterations fused intent (what the writer wanted to do) with
//! mechanism (the argv that does it on macOS). Writers built argv via a
//! `build_*_argv` family of helpers; the executor only knew how to spawn
//! processes. Adding non-argv operations (profile-write, PF anchor
//! install) forced "synthetic argv" hacks to flow non-shell ops
//! through the same display/test pipeline.
//!
//! Today: the writer expresses *intent* via per-domain `Op` enums
//! (`AccountOp`, `ProfileOp`); the substrate `Executor` knows how to
//! *describe* ops as operator-facing display lines and how to *execute*
//! them on the host. argv knowledge is confined to `MacosExecutor`'s
//! impl (one place per op variant); other substrates (`StubExecutor`,
//! `DryRunExecutor`) reuse `MacosExecutor`'s describe and supply their
//! own execute behaviour.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::firewall::{PF_CONF, PF_CONF_BACKUP, tenant_anchor_path};
use crate::ids::{GroupId, GroupName, HostUserName, TenantUserName, UserId};
use crate::profile::{ProfileError, default_profile_toml, display_path_for};

/// Which filesystem access predicate doctor's probe checks. `Read` maps to
/// `test -r <path>` (POSIX read permission on a file or directory entry);
/// `List` maps to `test -x <path>` against a directory (the POSIX execute
/// bit on a directory grants the ability to list / traverse its entries —
/// the term "list" is the doctor-domain word for that capability, not
/// POSIX's "execute"). The substrate translates one access mode to one
/// probe invocation; doctor's curated path list pairs each path with the
/// access mode that matters for the threat (Read for secret-file
/// contents, List for directory enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    Read,
    List,
}

/// Kind of filesystem entry at a tenant-side path, as the tenant sees
/// it. `Absent` means no entry exists; `Symlink(target)` means an
/// existing symlink (which the share reapply can safely replace via
/// `ln -sfn`) carrying its resolved target so doctor can compare
/// against the declared `host_path`; `Other` means a real file or
/// directory occupies the path — `Other` triggers
/// `ShareError::TenantPathOccupied` so the operator chooses between
/// editing the profile or removing the conflict manually. Substrate
/// never clobbers real operator data.
///
/// Substrate composition: a `sudo -n -u <tenant> /bin/test -L`
/// probe (symlink check) then, on hit, a `sudo -n -u <tenant>
/// /bin/readlink <path>` to capture the target; on miss, a `/bin/test
/// -e` probe distinguishes `Absent` from `Other`. Substrate-machinery
/// failures (sudo prompt cache expired, fork failed) surface as
/// `ProbeError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathKind {
    Absent,
    Symlink(std::path::PathBuf),
    Other,
}

/// Probe verdict. `Allowed` means the tenant CAN access the path under
/// the requested mode (the probe's exit code is zero); `Denied` covers
/// the expected hardened-host case where the kernel refuses (POSIX,
/// ACLs, sandbox, TCC — doctor doesn't distinguish, since
/// mechanism-of-denial belongs with the future remediation surface);
/// `Unknown` is reserved for ambiguous probe outcomes (e.g. probe
/// ran but produced indeterminate stderr). Doctor's `classify`
/// collapses every non-Allowed outcome to no-finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOutcome {
    Allowed,
    Denied,
    Unknown,
}

/// Account-domain operations. The writer expresses *what* to do (create the
/// share group, look up the OD record, log in as the tenant); the substrate
/// knows *how*. macOS-specific tool choices (dseditgroup, sysadminctl, dscl)
/// live in `MacosExecutor`'s impl, not here.
///
/// `LoginAsUser` is included for the display pipeline (the shell verb's
/// "Shelling into…" plan line goes through `Executor::describe_account`),
/// but it is NOT handled by `execute_account` — interactive ops need stdio
/// inheritance and a separate return type (i32 child exit code), which is
/// the dedicated `Executor::login` method. The asymmetry is local to the
/// shell verb and documented at the trait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountOp {
    /// Create the share group with the given GID. `group` is the full
    /// macOS short group name (today always `<tenant>-tenant-share` —
    /// `accounts::tenant_share_group_name` appends the suffix at the
    /// Writer boundary). Maps to `sudo dseditgroup -o create -n . -i
    /// <gid> <group>` on macOS.
    CreateShareGroup { group: GroupName, gid: GroupId },

    /// Delete the share group. Used as the create-side rollback step
    /// and the destroy-side cleanup step. Maps to `sudo dseditgroup
    /// -o delete -n . <group>` on macOS.
    DeleteShareGroup { group: GroupName },

    /// Create the tenant user with the given UID + GID. Maps to `sudo
    /// sysadminctl -addUser <name> -fullName "Tenant: <name>" -shell
    /// /bin/zsh -UID <uid> -GID <gid>` on macOS.
    CreateTenantUser {
        name: TenantUserName,
        uid: UserId,
        gid: GroupId,
    },

    /// Delete the tenant user via the OD-aware tool. Maps to `sudo
    /// sysadminctl -deleteUser <name>` on macOS. Distinct from
    /// `DeleteUserRecord` (low-level dscl cleanup); the doctrine separates
    /// these because sysadminctl handles home-directory move-to-Deleted-Users
    /// while dscl only touches the DS record.
    DeleteTenantUser { name: TenantUserName },

    /// Probe for an OD record's presence. Maps to `dscl . -read /Users/<name>`
    /// on macOS. The substrate's `execute_account` reports `Ok(())` when the
    /// record exists and `Err(AccountError::NonZero{..})` when it doesn't —
    /// the writer uses that result to gate the conditional `DeleteUserRecord`
    /// cleanup. No sudo (reads on the local node don't require it).
    LookupUserRecord { name: TenantUserName },

    /// Low-level cleanup of a stale OD record that `DeleteTenantUser` may
    /// have left behind. Maps to `sudo dscl . -delete /Users/<name>` on
    /// macOS. Belt-and-braces; runs only when `LookupUserRecord` finds the
    /// record present.
    DeleteUserRecord { name: TenantUserName },

    /// Interactive login as the tenant. Used by the `shell` verb. The
    /// describe-side renders `sudo -iu <name>`; execution goes through
    /// `Executor::login` (NOT `execute_account`) because the return type
    /// is the child shell's exit code, and stdio must inherit so sudo can
    /// prompt and the login shell can drive the controlling terminal.
    LoginAsUser { name: TenantUserName },

    /// Run a single command as the tenant inside a login shell. Used by
    /// the `tenant shell <name> -- <cmd>` command form. Sibling to
    /// `LoginAsUser` under the `sudo -iu` mechanism family — same login
    /// shell semantics (sources `/etc/zprofile` + `~/.zprofile` so PATH
    /// and tooling env match the interactive form), same stdio carve-out
    /// (execution goes through `Executor::exec_as_tenant`, not
    /// `execute_account`, because stdio inherits and the return type is
    /// the child's exit code). Substrate: `sudo -iu <name> -- <argv>` —
    /// the `--` separator prevents sudo from interpreting argv[0] as a
    /// sudo flag. `argv` must be non-empty (dispatch routes empty argv
    /// to the interactive branch before any `ExecAsUser` is constructed).
    ExecAsUser {
        name: TenantUserName,
        argv: Vec<String>,
    },

    /// Ensure a directory exists at `path`, created by the tenant `name`.
    /// The shares substrate uses this to pre-create
    /// `parent(tenant_path)` before symlinking — e.g.
    /// `$HOME/.local/share/` so a downstream `$HOME/.local/share/chezmoi`
    /// symlink lands. Maps to `sudo -n -u <name> /bin/mkdir -p <path>`
    /// on macOS; idempotent at the substrate (`mkdir -p` is a noop for
    /// existing directories). Mode bits come from the tenant's umask
    /// (default 022 → directories at 755) which is the right default for
    /// tenant-readable dirs under their home; a future need for explicit
    /// mode adds a `mode: u32` field at the variant.
    EnsureDirAsUser { name: TenantUserName, path: PathBuf },

    /// Ensure a symlink at `link` points at `target`, created by the
    /// tenant `name`. The shares substrate uses this to install the
    /// `tenant_path → host_path` symlink that gives the tenant a
    /// stable filesystem entry point under their home. Maps to
    /// `sudo -n -u <name> /bin/ln -sfn <target> <link>` — `-sfn` is
    /// the idempotent shape (force-overwrite-existing-symlink +
    /// no-follow-existing-dir-target). An existing REAL directory or
    /// file at `link` is the `TenantPathOccupied` case the Writer
    /// guards against before the substrate runs.
    EnsureSymlinkAsUser {
        name: TenantUserName,
        link: PathBuf,
        target: PathBuf,
    },

    /// Add the host operator as a secondary member of the tenant's
    /// share group. Maps to `sudo dseditgroup -o edit -n . -a <host>
    /// -t user <group>` on macOS. Idempotent at the substrate
    /// (`dseditgroup -o edit -a` on an existing member is a silent
    /// noop), so the catch-up path (`execute_reapply_plan` running
    /// this on every reload/mode/shell) costs one dseditgroup
    /// invocation per verb regardless of the tenant's pre-existing
    /// state.
    ///
    /// Ported verbatim from sandbox's `_add_human_to_group` step
    /// (`scripts/lib/phases/phase01_user.py:180-185`); originally
    /// dropped during the initial port, and the symptom —
    /// bidirectional-write asymmetry on RW shares — was caught in
    /// the 2026-05-15 operator setup pass.
    AddHostToShareGroup {
        group: GroupName,
        host: HostUserName,
    },

    /// Symmetric counter to `AddHostToShareGroup`. Maps to `sudo
    /// dseditgroup -o edit -n . -d <host> -t user <group>`. The
    /// describe-side renders only the `-d` edit form; the production
    /// `execute_account` impl invokes `dseditgroup -o checkmember -m
    /// <host> <group>` first and skips the edit when the host is not
    /// a member (idempotence for legacy tenants without host
    /// membership and the orphan-group destroy path on a partially-
    /// created tenant).
    RemoveHostFromShareGroup {
        group: GroupName,
        host: HostUserName,
    },
}

/// Profile-domain operations. The store-backed `~/.config/tenant/profiles/<name>.toml`
/// file is the host-side artifact; the substrate handles the actual fs work
/// (or in-memory recording for tests). The profile read path lives on
/// `Executor::read_profile` (a dedicated method, not a variant here)
/// because the return type — file content, not unit — doesn't fit
/// `execute_profile`'s shape. Parallels `login`'s carve-out from
/// `execute_account` for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOp {
    /// Write the default profile content for `name`. Idempotent overwrite.
    Create { name: TenantUserName },

    /// Remove the profile file. Idempotent: NotFound is success, mirroring
    /// the operator's mental model of `rm -f`.
    Delete { name: TenantUserName },
}

/// Firewall-domain operations. macOS implements per-tenant firewall rules
/// as a named PF anchor (`/etc/pf.anchors/tenant-<name>`) referenced from
/// `/etc/pf.conf` and loaded via `pfctl -f`. The substrate handles the
/// actual file writes (atomic tempfile + sudo mv + sudo chmod) and the
/// pfctl invocations; the writer composes these ops into the create/destroy
/// flows.
///
/// `Anchor` stays in the variant names because it's the project's domain
/// vocabulary for "named per-tenant firewall ruleset"; `Pf` prefixes drop
/// from `Reload` / `Enable` because the tool's name (pfctl) lives in
/// `MacosExecutor`, not here.
/// Per-share access intent at the substrate level — what bits to grant
/// or revoke when invoking `chmod +a` / `chmod -a`. `Ro` maps to the
/// sandbox-plugin `read_exec_inherit_entry` shape (read + execute +
/// directory/file inheritance — execute is needed for directory
/// traversal); `Rw` maps to `rw_inherit_entry` (read + write + execute
/// + delete + append + inheritance — the full operator-writable bundle).
///
/// Substrate-vocab type sibling to `profile::ShareMode` (profile-vocab):
/// the Writer maps `ShareMode → AclMode` at op-construction time. Same
/// two values today, distinct types so the layer boundary is visible —
/// if `ShareMode` grows a profile-only flag (e.g. an "exclude-children"
/// inheritance opt-out), `AclMode` stays binary and the Writer's
/// mapping absorbs the divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMode {
    Ro,
    Rw,
}

impl AclMode {
    /// The bit list embedded in the `chmod +a "group:<g> allow <bits>,..."`
    /// entry string. Centralized here so both `describe_acl` (operator-
    /// facing rendering) and `execute_acl` (idempotence pre-check via
    /// `ls -lde` substring match) reference the same canonical bytes —
    /// any drift between the rendered command and the substring searched
    /// would silently break idempotence.
    pub fn acl_bits(self) -> &'static str {
        match self {
            AclMode::Ro => "read,execute,file_inherit,directory_inherit",
            AclMode::Rw => "read,write,execute,delete,append,file_inherit,directory_inherit",
        }
    }
}

/// ACL-domain operations. `Grant` adds an inheritable ACL entry
/// granting `group` access to `path` at the requested mode; `Revoke`
/// removes the same entry. Both are idempotent at the substrate (macOS
/// `chmod +a` is natively idempotent — re-applying an existing entry
/// is a noop). No `sudo` prefix on the argv — the operator (host
/// user) is expected to own or have ACL-write on `host_path`; if
/// they don't, `chmod` fails with `AclError::NonZero` and the stderr
/// surfaces under `Reporter::*_failed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclOp {
    /// Grant `group` access to `path` at `mode`. ACL entry is inheritable
    /// (`file_inherit,directory_inherit`); descendants automatically pick
    /// up the same grant.
    Grant {
        path: PathBuf,
        group: GroupName,
        mode: AclMode,
    },

    /// Remove the inheritable ACL entry that `Grant` installed. Idempotent:
    /// if the entry isn't present, returns Ok(()) without invoking chmod.
    Revoke {
        path: PathBuf,
        group: GroupName,
        mode: AclMode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallOp {
    /// Write the rendered anchor body to `/etc/pf.anchors/tenant-<name>`.
    /// `name` is the tenant name; the anchor file's full name
    /// (`tenant-<name>`) is constructed by `MacosExecutor` from it. `body`
    /// is the precomputed anchor content (from `firewall::render_anchor`).
    InstallAnchor { name: TenantUserName, body: String },

    /// Remove `/etc/pf.anchors/tenant-<name>`. Idempotent: NotFound is
    /// success on production, mirroring the operator's mental model of
    /// `rm -f`.
    RemoveAnchor { name: TenantUserName },

    /// Copy `/etc/pf.conf` to `/etc/pf.conf.tenant-backup`. Fixed backup
    /// path (no timestamps) — deterministic recovery, overwritten each
    /// invocation.
    BackupConfig,

    /// Copy `/etc/pf.conf.tenant-backup` back to `/etc/pf.conf`. The
    /// recovery half of `BackupConfig`. Runs on `Reload` failure during
    /// create.
    RestoreConfigFromBackup,

    /// Write the precomputed pf.conf content to `/etc/pf.conf`. `content`
    /// is the output of `firewall::ensure_anchor_ref` (create-side) or
    /// `firewall::remove_anchor_ref` (destroy-side).
    UpdateConfig { content: String },

    /// `pfctl -f /etc/pf.conf` — reload the firewall ruleset. Non-zero
    /// exit on syntax or anchor errors triggers the recovery path on
    /// create.
    Reload,

    /// `sudo pfctl -a tenant-<name> -F all` — flush the in-kernel
    /// rules and tables stored under the named anchor. `pfctl -f` only
    /// walks the parent ruleset and never garbage-collects anchors
    /// whose `load anchor` directive has been removed: without this
    /// explicit flush, destroy leaves the previous tenant's rules
    /// loaded under an orphan anchor name, and the next tenant getting
    /// the same UID would silently inherit them. Symmetric counter to
    /// the create-side `InstallAnchor`. Idempotent: flushing an empty
    /// or unknown anchor is a noop on macOS.
    FlushAnchor { name: TenantUserName },

    /// `pfctl -e` — enable the firewall. Treated as idempotent at the
    /// substrate: "already enabled" stderr maps to `Ok(())`.
    Enable,
}

/// Account-domain error. Same shape as the pre-refactor `ExecError` — the
/// substrate distinguishes spawn failures (sudo not on PATH, fork failed)
/// from non-zero exits (the tool reported an error). The writer's
/// `LookupUserRecord` flow pattern-matches on `NonZero` specifically to
/// treat probe-non-zero as "no cleanup needed."
#[derive(Debug)]
pub enum AccountError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountError::Spawn(e) => write!(f, "failed to spawn process: {e}"),
            AccountError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "process exited with code {code}")
                } else {
                    write!(f, "process exited with code {code}: {trimmed}")
                }
            }
        }
    }
}

/// Failure surface for privileged-or-cheap reads of host config files
/// — `/etc/sudoers` + `/etc/sudoers.d/*` (privileged) and
/// `/etc/pam.d/sudo` (mode-0644 direct read). The substrate
/// concatenates the readable text into one blob that doctor's parsers
/// grep through; either the read invocation fails (spawn / non-zero
/// on sudo-gated reads) or a direct filesystem read fails. Mirrors
/// `FirewallError`'s shape with an extra `Fs` variant for the
/// direct-read case.
#[derive(Debug)]
pub enum HostFileError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
    Fs { path: String, message: String },
}

impl fmt::Display for HostFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostFileError::Spawn(e) => write!(f, "failed to spawn sudo: {e}"),
            HostFileError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "sudo read exited with code {code}")
                } else {
                    write!(f, "sudo read exited with code {code}: {trimmed}")
                }
            }
            HostFileError::Fs { path, message } => {
                write!(f, "filesystem error at {path}: {message}")
            }
        }
    }
}

/// Probe-substrate error. Fires when the probe machinery itself failed —
/// `sudo` not on PATH, fork failed, an unexpected non-zero exit pattern
/// that doesn't map cleanly to Allowed / Denied. `Denied` and `Unknown`
/// are NOT errors here — they're `AccessOutcome` variants the probe
/// returns on its happy path. This error type fires only when doctor
/// couldn't get a probe answer at all; the dispatcher routes it to
/// `doctor_failed` and exits 74.
#[derive(Debug)]
pub enum ProbeError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Spawn(e) => write!(f, "failed to spawn probe: {e}"),
            ProbeError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "probe exited with code {code}")
                } else {
                    write!(f, "probe exited with code {code}: {trimmed}")
                }
            }
        }
    }
}

/// Firewall-domain error. Same `Spawn` / `NonZero` shape as `AccountError`
/// for pfctl invocations; two additional variants for the fs side of
/// firewall ops:
/// - `Fs` covers tempfile / mv / chmod failures during anchor/pf.conf
///   writes; carries the path so the operator-facing frame can name what
///   failed.
/// - `RestoreFailed` is the recovery-of-recovery case: a `Reload` failure
///   triggered a `RestoreConfigFromBackup`, and the restore itself failed.
///   The host now carries a half-edited pf.conf; the message names the
///   backup path and the manual recovery command.
#[derive(Debug)]
pub enum FirewallError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
    Fs { path: String, message: String },
    RestoreFailed { path: String },
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirewallError::Spawn(e) => write!(f, "failed to spawn process: {e}"),
            FirewallError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "process exited with code {code}")
                } else {
                    write!(f, "process exited with code {code}: {trimmed}")
                }
            }
            FirewallError::Fs { path, message } => {
                write!(f, "filesystem error at {path}: {message}")
            }
            FirewallError::RestoreFailed { path } => write!(
                f,
                "pf.conf restore from {path} failed \u{2014} \
                 sudo cp {path} /etc/pf.conf to recover"
            ),
        }
    }
}

/// ACL-domain error. Mirrors `AccountError`'s shape because the
/// substrate is `chmod` (a tool with the same spawn / non-zero contract
/// as dseditgroup / sysadminctl).
#[derive(Debug)]
pub enum AclError {
    Spawn(io::Error),
    NonZero { code: i32, stderr: String },
}

impl fmt::Display for AclError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclError::Spawn(e) => write!(f, "failed to spawn chmod: {e}"),
            AclError::NonZero { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "chmod exited with code {code}")
                } else {
                    write!(f, "chmod exited with code {code}: {trimmed}")
                }
            }
        }
    }
}

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

/// Top-level ADT wrapper for "any op, regardless of domain." Used by the
/// Reporter for uniform display dispatch — `Op::describe_via` picks the
/// right substrate method based on which sub-domain the op belongs to.
/// Execution stays on the bare `AccountOp` / `ProfileOp` types (via the
/// `WritableOp` trait) so per-domain error types stay typed and the
/// dispatcher's `CreateError::Group / User / Profile` distinction is
/// preserved end-to-end. The ADT hierarchy is honest: `Op` is the root,
/// `AccountOp` / `ProfileOp` are the leaf ADTs, each with their own
/// variants.
pub enum Op<'a> {
    Account(&'a AccountOp),
    Profile(&'a ProfileOp),
    Firewall(&'a FirewallOp),
    Acl(&'a AclOp),
}

impl<'a> Op<'a> {
    /// Render the op as an operator-facing display line. The match here
    /// is the one place in the codebase that has to know the
    /// account/profile/firewall/acl split for display purposes.
    pub fn describe_via(&self, executor: &dyn Executor) -> String {
        match self {
            Op::Account(op) => executor.describe_account(op),
            Op::Profile(op) => executor.describe_profile(op),
            Op::Firewall(op) => executor.describe_firewall(op),
            Op::Acl(op) => executor.describe_acl(op),
        }
    }

    /// Operator-facing past-tense success label for the op. Drives the
    /// `✓ <label>` lines emitted by `Reporter::progress` after each
    /// substrate step succeeds. Distinct from `describe_via`: describe
    /// is the mechanism-level shell echo (`sudo dseditgroup …`);
    /// business_label is the capability-level summary the operator
    /// reads. Substrate-agnostic — no `dseditgroup` / `sysadminctl`
    /// jargon.
    pub fn business_label(&self) -> String {
        match self {
            Op::Account(op) => account_business_label(op),
            Op::Profile(op) => profile_business_label(op),
            Op::Firewall(op) => firewall_business_label(op),
            Op::Acl(op) => acl_business_label(op),
        }
    }

    /// Operator-facing future-tense capability label for the op. Leads
    /// each step in the verbose pre-prompt plan block as a `• <intent>`
    /// bullet, with the shell line indented underneath. Sibling to
    /// `business_label` (past-tense; drives the `✓` progress lines
    /// emitted post-execution). Substrate-agnostic — no `dseditgroup`
    /// / `sysadminctl` / `pfctl` jargon. The probe variants
    /// (`LookupUserRecord` / `DeleteUserRecord`) are sharpened apart
    /// from their business_label so the future-tense bullet reads
    /// naturally.
    pub fn intent_label(&self) -> String {
        match self {
            Op::Account(op) => account_intent_label(op),
            Op::Profile(op) => profile_intent_label(op),
            Op::Firewall(op) => firewall_intent_label(op),
            Op::Acl(op) => acl_intent_label(op),
        }
    }
}

fn account_business_label(op: &AccountOp) -> String {
    match op {
        AccountOp::CreateShareGroup { group, gid } => {
            format!("Share group '{group}' created (GID {gid})")
        }
        AccountOp::DeleteShareGroup { group } => {
            format!("Share group '{group}' removed")
        }
        AccountOp::CreateTenantUser { name, uid, .. } => {
            format!("User account '{name}' provisioned (UID {uid})")
        }
        AccountOp::DeleteTenantUser { name } => {
            format!("User account '{name}' removed (home moved to /Users/Deleted Users/{name})")
        }
        AccountOp::LookupUserRecord { name } => {
            format!("Residual user record check for '{name}'")
        }
        AccountOp::DeleteUserRecord { name } => {
            format!("Residual user record '{name}' cleaned up")
        }
        AccountOp::LoginAsUser { name } => format!("Entering shell as '{name}'"),
        AccountOp::ExecAsUser { name, argv } => {
            // basename of argv[0] for the ✓ progress line. argv[0]
            // may be an absolute path; the operator's mental model is
            // "the command 'ls' ran", not "the command '/usr/bin/ls' ran".
            let bin = argv
                .first()
                .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
                .unwrap_or("?");
            format!("Command '{bin}' executed as '{name}'")
        }
        AccountOp::EnsureDirAsUser { path, .. } => {
            format!("Parent directory {} ensured", path.display())
        }
        AccountOp::EnsureSymlinkAsUser { link, target, .. } => {
            format!(
                "Symlink {} → {} installed",
                link.display(),
                target.display()
            )
        }
        AccountOp::AddHostToShareGroup { group, host } => {
            format!("Host '{host}' added to share group '{group}'")
        }
        AccountOp::RemoveHostFromShareGroup { group, host } => {
            format!("Host '{host}' removed from share group '{group}'")
        }
    }
}

fn profile_business_label(op: &ProfileOp) -> String {
    match op {
        ProfileOp::Create { name } => {
            format!(
                "Profile written to {}",
                crate::profile::display_path_for(name.as_str())
            )
        }
        ProfileOp::Delete { name } => format!(
            "Profile removed at {}",
            crate::profile::display_path_for(name.as_str())
        ),
    }
}

fn firewall_business_label(op: &FirewallOp) -> String {
    match op {
        FirewallOp::InstallAnchor { name, .. } => format!(
            "Firewall anchor installed at {}",
            crate::firewall::tenant_anchor_path(name.as_str())
        ),
        FirewallOp::RemoveAnchor { name } => format!(
            "Firewall anchor removed at {}",
            crate::firewall::tenant_anchor_path(name.as_str())
        ),
        FirewallOp::BackupConfig => {
            format!(
                "Backed up {} to {}",
                crate::firewall::PF_CONF,
                crate::firewall::PF_CONF_BACKUP
            )
        }
        FirewallOp::RestoreConfigFromBackup => format!(
            "Restored {} from {}",
            crate::firewall::PF_CONF,
            crate::firewall::PF_CONF_BACKUP
        ),
        FirewallOp::UpdateConfig { .. } => format!("Updated {}", crate::firewall::PF_CONF),
        FirewallOp::Reload => "Firewall ruleset reloaded".to_string(),
        FirewallOp::FlushAnchor { name } => format!(
            "Kernel rules under anchor '{}' flushed",
            crate::firewall::tenant_anchor_name(name.as_str())
        ),
        FirewallOp::Enable => "Firewall enabled host-wide".to_string(),
    }
}

fn acl_business_label(op: &AclOp) -> String {
    match op {
        AclOp::Grant { path, group, .. } => {
            format!("ACL granted to group '{group}' on {}", path.display())
        }
        AclOp::Revoke { path, group, .. } => {
            format!("ACL revoked from group '{group}' on {}", path.display())
        }
    }
}

fn account_intent_label(op: &AccountOp) -> String {
    match op {
        AccountOp::CreateShareGroup { group, gid } => {
            format!("Create share group '{group}' (GID {gid})")
        }
        AccountOp::DeleteShareGroup { group } => {
            format!("Remove share group '{group}'")
        }
        AccountOp::CreateTenantUser { name, uid, gid } => {
            format!("Create user account '{name}' (UID {uid}, GID {gid})")
        }
        AccountOp::DeleteTenantUser { name } => {
            format!("Remove user account '{name}' (home moved to /Users/Deleted Users/{name})")
        }
        AccountOp::LookupUserRecord { name } => {
            format!("Probe for residue user record '{name}'")
        }
        AccountOp::DeleteUserRecord { name } => {
            format!("Clean up residue user record '{name}'")
        }
        AccountOp::LoginAsUser { name } => format!("Log in as '{name}'"),
        AccountOp::ExecAsUser { name, argv } => {
            // Full argv joined with single spaces for the operator-display
            // plan bullet. No shell-escaping — the operator typed it; they
            // can read it. Substrate-side, argv is preserved as the
            // already-tokenized vector so a metachar-bearing element
            // arrives at the tenant unchanged.
            format!("Run as '{name}': {}", argv.join(" "))
        }
        AccountOp::EnsureDirAsUser { path, .. } => {
            format!("Ensure directory {} exists (as tenant)", path.display())
        }
        AccountOp::EnsureSymlinkAsUser { link, target, .. } => {
            format!(
                "Install symlink {} \u{2192} {} (as tenant)",
                link.display(),
                target.display()
            )
        }
        AccountOp::AddHostToShareGroup { group, host } => {
            format!("Add host '{host}' to share group '{group}'")
        }
        AccountOp::RemoveHostFromShareGroup { group, host } => {
            format!("Remove host '{host}' from share group '{group}'")
        }
    }
}

fn profile_intent_label(op: &ProfileOp) -> String {
    match op {
        ProfileOp::Create { name } => format!(
            "Write profile config at {}",
            crate::profile::display_path_for(name.as_str())
        ),
        ProfileOp::Delete { name } => format!(
            "Remove profile config at {}",
            crate::profile::display_path_for(name.as_str())
        ),
    }
}

fn firewall_intent_label(op: &FirewallOp) -> String {
    match op {
        FirewallOp::InstallAnchor { name, .. } => format!(
            "Install firewall anchor at {}",
            crate::firewall::tenant_anchor_path(name.as_str())
        ),
        FirewallOp::RemoveAnchor { name } => format!(
            "Remove firewall anchor at {}",
            crate::firewall::tenant_anchor_path(name.as_str())
        ),
        FirewallOp::BackupConfig => format!(
            "Back up {} to {}",
            crate::firewall::PF_CONF,
            crate::firewall::PF_CONF_BACKUP
        ),
        FirewallOp::RestoreConfigFromBackup => {
            format!("Restore {} from backup", crate::firewall::PF_CONF)
        }
        FirewallOp::UpdateConfig { .. } => format!("Update {}", crate::firewall::PF_CONF),
        FirewallOp::Reload => "Reload pf ruleset".to_string(),
        FirewallOp::FlushAnchor { name } => format!(
            "Flush kernel rules under anchor '{}'",
            crate::firewall::tenant_anchor_name(name.as_str())
        ),
        FirewallOp::Enable => "Enable pf host-wide".to_string(),
    }
}

fn acl_intent_label(op: &AclOp) -> String {
    match op {
        AclOp::Grant { path, group, .. } => {
            format!("Grant '{group}' ACL access to {}", path.display())
        }
        AclOp::Revoke { path, group, .. } => {
            format!("Revoke '{group}' ACL access from {}", path.display())
        }
    }
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

impl WritableOp for AccountOp {
    type Error = AccountError;
    fn execute_via(&self, executor: &dyn Executor) -> Result<(), AccountError> {
        executor.execute_account(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Account(self)
    }
}

impl WritableOp for ProfileOp {
    type Error = ProfileError;
    fn execute_via(&self, executor: &dyn Executor) -> Result<(), ProfileError> {
        executor.execute_profile(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Profile(self)
    }
}

impl WritableOp for FirewallOp {
    type Error = FirewallError;
    fn execute_via(&self, executor: &dyn Executor) -> Result<(), FirewallError> {
        executor.execute_firewall(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Firewall(self)
    }
}

impl WritableOp for AclOp {
    type Error = AclError;
    fn execute_via(&self, executor: &dyn Executor) -> Result<(), AclError> {
        executor.execute_acl(self)
    }
    fn op_ref(&self) -> Op<'_> {
        Op::Acl(self)
    }
}

/// Production substrate. Knows the macOS tool argv and the XDG-style profile
/// path convention. The argv-building logic that previously lived in the
/// `build_*_argv` family (and the synthetic-argv hacks for profile ops) is
/// now confined to this struct's methods.
pub struct MacosExecutor;

impl Executor for MacosExecutor {
    fn describe_account(&self, op: &AccountOp) -> String {
        match op {
            AccountOp::CreateShareGroup { group, gid } => {
                format!("sudo dseditgroup -o create -n . -i {gid} {group}")
            }
            AccountOp::DeleteShareGroup { group } => {
                format!("sudo dseditgroup -o delete -n . {group}")
            }
            AccountOp::CreateTenantUser { name, uid, gid } => format!(
                "sudo sysadminctl -addUser {name} -fullName \"Tenant: {name}\" \
                 -shell /bin/zsh -UID {uid} -GID {gid}"
            ),
            AccountOp::DeleteTenantUser { name } => {
                format!("sudo sysadminctl -deleteUser {name}")
            }
            AccountOp::LookupUserRecord { name } => format!("dscl . -read /Users/{name}"),
            AccountOp::DeleteUserRecord { name } => format!("sudo dscl . -delete /Users/{name}"),
            AccountOp::LoginAsUser { name } => format!("sudo -iu {name}"),
            AccountOp::ExecAsUser { name, argv } => {
                format!("sudo -iu {name} -- {}", argv.join(" "))
            }
            AccountOp::EnsureDirAsUser { name, path } => {
                format!("sudo -n -u {name} /bin/mkdir -p {}", path.display())
            }
            AccountOp::EnsureSymlinkAsUser { name, link, target } => format!(
                "sudo -n -u {name} /bin/ln -sfn {} {}",
                target.display(),
                link.display(),
            ),
            AccountOp::AddHostToShareGroup { group, host } => {
                format!("sudo dseditgroup -o edit -n . -a {host} -t user {group}")
            }
            AccountOp::RemoveHostFromShareGroup { group, host } => {
                format!("sudo dseditgroup -o edit -n . -d {host} -t user {group}")
            }
        }
    }

    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        // LoginAsUser is intentionally not handled here — interactive ops go
        // through `login`. Match-arm panics on it so an accidental wiring
        // through `execute_account` fails loudly in dev / tests rather than
        // silently doing the wrong thing in prod.
        if let AccountOp::RemoveHostFromShareGroup { group, host } = op {
            // Idempotence: skip the `-d` edit when host isn't a
            // current member. Covers (a) legacy tenants where the host
            // was never added and (b) destroy_orphan_group on a
            // partial-create tenant where AddHost failed. The substrate
            // is the source of truth — Writer keeps the op in the plan
            // for symmetry; the substrate decides whether to actually
            // fire it.
            if !self.host_in_group(host, group)? {
                return Ok(());
            }
        }
        let argv = match op {
            AccountOp::LoginAsUser { .. } => {
                panic!(
                    "AccountOp::LoginAsUser must go through Executor::login, not execute_account"
                )
            }
            AccountOp::ExecAsUser { .. } => {
                panic!(
                    "AccountOp::ExecAsUser must go through Executor::exec_as_tenant, not execute_account"
                )
            }
            _ => account_argv(op),
        };
        spawn_capturing(&argv)
    }

    fn login(&self, name: &TenantUserName) -> Result<i32, AccountError> {
        // Stdio inherits so sudo can prompt for the host password and the
        // launched login shell can drive the controlling terminal. Mirrors
        // the pre-refactor `Executor::exec_into`.
        let argv = account_argv(&AccountOp::LoginAsUser { name: name.clone() });
        let (program, rest) = argv
            .split_first()
            .ok_or_else(|| AccountError::Spawn(io::Error::other("argv is empty")))?;
        let status = Command::new(program)
            .args(rest)
            .status()
            .map_err(AccountError::Spawn)?;
        Ok(status.code().unwrap_or(1))
    }

    fn exec_as_tenant(&self, name: &TenantUserName, argv: &[String]) -> Result<i32, AccountError> {
        // Same stdio + return-code posture as `login`. argv shape:
        // `sudo -iu <name> -- <argv...>`. The `--` separator is
        // load-bearing — without it, an argv[0] starting with `-`
        // would be interpreted as a sudo flag.
        let full = account_argv(&AccountOp::ExecAsUser {
            name: name.clone(),
            argv: argv.to_vec(),
        });
        let (program, rest) = full
            .split_first()
            .ok_or_else(|| AccountError::Spawn(io::Error::other("argv is empty")))?;
        let status = Command::new(program)
            .args(rest)
            .status()
            .map_err(AccountError::Spawn)?;
        Ok(status.code().unwrap_or(1))
    }

    fn describe_profile(&self, op: &ProfileOp) -> String {
        match op {
            ProfileOp::Create { name } => {
                // Pretend-shell `tee … < default.toml` framing for the
                // operator — there's no actual tee invocation, but the
                // shape signals "a file landed here" and matches today's
                // verbose-mode bytes exactly.
                format!("tee {} < default.toml", display_path_for(name.as_str()))
            }
            ProfileOp::Delete { name } => {
                // `rm -f` reflects the idempotent semantics — NotFound is
                // success on both the production fs side and the stub.
                format!("rm -f {}", display_path_for(name.as_str()))
            }
        }
    }

    fn execute_profile(&self, op: &ProfileOp) -> Result<(), ProfileError> {
        let path = profile_path(op_name(op))?;
        match op {
            ProfileOp::Create { .. } => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|e| ProfileError {
                        message: e.to_string(),
                    })?;
                }
                fs::write(&path, default_profile_toml()).map_err(|e| ProfileError {
                    message: e.to_string(),
                })?;
                Ok(())
            }
            ProfileOp::Delete { .. } => match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(ProfileError {
                    message: e.to_string(),
                }),
            },
        }
    }

    fn read_profile(&self, name: &TenantUserName) -> Result<String, ProfileError> {
        let path = profile_path(name)?;
        fs::read_to_string(&path).map_err(|e| ProfileError {
            message: e.to_string(),
        })
    }

    fn describe_firewall(&self, op: &FirewallOp) -> String {
        match op {
            FirewallOp::InstallAnchor { name, .. } => {
                // Pretend-shell `sudo tee … < anchor.body` framing — the
                // operator sees the file path and a `<` marker for the
                // content; the actual mechanism inside `execute_firewall`
                // is tempfile + sudo mv + sudo chmod. Matches the
                // ProfileOp::Create convention (`tee … < default.toml`),
                // with `sudo` because the target is privileged.
                format!("sudo tee /etc/pf.anchors/tenant-{name} < anchor.body")
            }
            FirewallOp::RemoveAnchor { name } => {
                format!("sudo rm -f /etc/pf.anchors/tenant-{name}")
            }
            FirewallOp::BackupConfig => {
                "sudo cp /etc/pf.conf /etc/pf.conf.tenant-backup".to_string()
            }
            FirewallOp::RestoreConfigFromBackup => {
                "sudo cp /etc/pf.conf.tenant-backup /etc/pf.conf".to_string()
            }
            FirewallOp::UpdateConfig { .. } => "sudo tee /etc/pf.conf < updated.conf".to_string(),
            FirewallOp::Reload => "sudo pfctl -f /etc/pf.conf".to_string(),
            FirewallOp::FlushAnchor { name } => {
                format!("sudo pfctl -a tenant-{name} -F all")
            }
            FirewallOp::Enable => "sudo pfctl -e".to_string(),
        }
    }

    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        fs::read_to_string(PF_CONF).map_err(|e| FirewallError::Fs {
            path: PF_CONF.to_string(),
            message: e.to_string(),
        })
    }

    fn probe_access_as_tenant(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
        mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError> {
        // `/bin/test -<flag> <path>` returns:
        //   0  → predicate true (Allowed)
        //   1  → predicate false (Denied — includes file-doesn't-exist;
        //        we accept the ambiguity here, since mechanism-of-denial
        //        belongs with the future remediation surface).
        //   ≥2 → anything else (Unknown — probe machinery hiccup).
        // `sudo -n` is the non-interactive flag: if the operator's
        // sudo session isn't already cached, sudo fails with non-zero
        // and we surface as `ProbeError::NonZero`. The expected
        // operator workflow is `sudo -v` (or any prior privileged
        // command in the last ~5 min) before `tenant doctor`; the
        // `--help` text documents this.
        let flag = match mode {
            AccessMode::Read => "-r",
            AccessMode::List => "-x",
        };
        let path_str = path.to_string_lossy().into_owned();
        let output = Command::new("sudo")
            .args(["-n", "-u", name.as_str(), "/bin/test", flag, &path_str])
            .output()
            .map_err(ProbeError::Spawn)?;
        match output.status.code() {
            Some(0) => Ok(AccessOutcome::Allowed),
            Some(1) => Ok(AccessOutcome::Denied),
            Some(code) => {
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                // Distinguish "sudo couldn't authenticate" (machinery
                // failure → ProbeError) from "test answered something
                // weird" (kernel state weird → Unknown). A non-cached
                // sudo session is the canonical machinery failure.
                if stderr.contains("sudo: a password is required")
                    || stderr.contains("sudo: a terminal is required")
                {
                    Err(ProbeError::NonZero { code, stderr })
                } else {
                    Ok(AccessOutcome::Unknown)
                }
            }
            None => Err(ProbeError::NonZero {
                code: -1,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
        }
    }

    fn read_env_policy(&self) -> Result<String, HostFileError> {
        // Read /etc/sudoers (sudoers files are mode 0440 root:wheel —
        // not world-readable; sudo is required), then read every file
        // in /etc/sudoers.d/. Concatenate with newlines so the
        // parser's `env_delete` grep doesn't accidentally bridge the
        // last line of one file into the first of the next. Origin
        // attribution is intentionally dropped — doctor's parser
        // doesn't need it, and a future cycle that wants attribution
        // would have to introduce a wrapper type (we lean YAGNI).
        let primary = read_privileged_text("/etc/sudoers")?;
        let mut combined = primary;
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
        let listing_output = Command::new("sudo")
            .args(["-n", "ls", "-1", "/etc/sudoers.d"])
            .output()
            .map_err(HostFileError::Spawn)?;
        // A non-existent or unreadable /etc/sudoers.d/ is treated as
        // "no drop-ins" rather than a hard failure — sudo doesn't
        // require the dir to exist. Only surface as Fs error if sudo
        // itself reported an authentication failure.
        if listing_output.status.success() {
            let listing = String::from_utf8_lossy(&listing_output.stdout).into_owned();
            for entry in listing.lines() {
                let trimmed = entry.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let path = format!("/etc/sudoers.d/{trimmed}");
                let content = read_privileged_text(&path)?;
                combined.push_str(&content);
                if !combined.ends_with('\n') {
                    combined.push('\n');
                }
            }
        }
        Ok(combined)
    }

    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError> {
        match op {
            FirewallOp::InstallAnchor { name, body } => {
                write_privileged(&tenant_anchor_path(name.as_str()), body)
            }
            FirewallOp::RemoveAnchor { name } => {
                // `sudo rm -f <path>` — idempotent on the macOS side
                // (`rm -f` returns 0 on NotFound), so a partial-state
                // destroy doesn't trip here.
                spawn_firewall(&[
                    "sudo".into(),
                    "rm".into(),
                    "-f".into(),
                    tenant_anchor_path(name.as_str()),
                ])
            }
            FirewallOp::BackupConfig => spawn_firewall(&[
                "sudo".into(),
                "cp".into(),
                PF_CONF.into(),
                PF_CONF_BACKUP.into(),
            ]),
            FirewallOp::RestoreConfigFromBackup => {
                // Recovery half: copy the backup back. A failure here
                // means the host carries a half-edited pf.conf with no
                // clean automated path back; surface as `RestoreFailed`
                // so the Reporter message names the backup path and
                // includes the manual recovery command.
                spawn_firewall(&[
                    "sudo".into(),
                    "cp".into(),
                    PF_CONF_BACKUP.into(),
                    PF_CONF.into(),
                ])
                .map_err(|_| FirewallError::RestoreFailed {
                    path: PF_CONF_BACKUP.to_string(),
                })
            }
            FirewallOp::UpdateConfig { content } => write_privileged(PF_CONF, content),
            FirewallOp::Reload => {
                spawn_firewall(&["sudo".into(), "pfctl".into(), "-f".into(), PF_CONF.into()])
            }
            FirewallOp::FlushAnchor { name } => spawn_firewall(&[
                "sudo".into(),
                "pfctl".into(),
                "-a".into(),
                format!("tenant-{name}"),
                "-F".into(),
                "all".into(),
            ]),
            FirewallOp::Enable => {
                // `pfctl -e` exits non-zero with "pf already enabled"
                // when already on. Treat both success and
                // already-enabled as success — the plugin's defensive
                // pattern, transcribed verbatim.
                match spawn_firewall(&["sudo".into(), "pfctl".into(), "-e".into()]) {
                    Ok(()) => Ok(()),
                    Err(FirewallError::NonZero { stderr, .. })
                        if stderr.to_lowercase().contains("already enabled") =>
                    {
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    fn read_kernel_pf_rules(&self, name: &TenantUserName) -> Result<String, FirewallError> {
        let output = Command::new("sudo")
            .args(["-n", "pfctl", "-a", &format!("tenant-{name}"), "-sr"])
            .output()
            .map_err(FirewallError::Spawn)?;
        if !output.status.success() {
            return Err(FirewallError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn read_pam_sudo(&self) -> Result<String, HostFileError> {
        // `/etc/pam.d/sudo` is mode 0644 — direct fs read, no sudo.
        // The `Fs` variant carries the path so the operator-facing
        // frame names what failed.
        fs::read_to_string("/etc/pam.d/sudo").map_err(|e| HostFileError::Fs {
            path: "/etc/pam.d/sudo".to_string(),
            message: e.to_string(),
        })
    }

    fn read_pf_status(&self) -> Result<String, FirewallError> {
        let output = Command::new("sudo")
            .args(["-n", "pfctl", "-si"])
            .output()
            .map_err(FirewallError::Spawn)?;
        if !output.status.success() {
            return Err(FirewallError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        // `pfctl -si` writes to BOTH stdout and stderr — the
        // "Status: Enabled" line lands on stderr in practice. Combine
        // both into one blob for the parser; tolerating the empty
        // case if the user's host ever emits to a single stream.
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(combined)
    }

    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        // Mode 0644 root-owned — direct fs read, no sudo. Same
        // substrate posture as `read_pam_sudo`. Path centralized via
        // `firewall::tenant_anchor_path` so a future anchor-dir move
        // flows through here without inline edits.
        let path = crate::firewall::tenant_anchor_path(name.as_str());
        fs::read_to_string(&path).map_err(|e| HostFileError::Fs {
            path,
            message: e.to_string(),
        })
    }

    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<PathKind, ProbeError> {
        // Probes:
        //   `sudo -n -u <name> /bin/test -L <path>` → exit 0 = symlink
        //   On symlink-hit: `sudo -n -u <name> /usr/bin/readlink <path>`
        //     captures the target string. readlink itself does not
        //     resolve intermediate symlinks; we record what's literally
        //     stored in the link entry. Doctor's SymlinkDrift comparator
        //     is string-exact.
        //   On symlink-miss: `sudo -n -u <name> /bin/test -e <path>`
        //     distinguishes Other vs Absent.
        // sudo-machinery failures (auth cache miss, fork failed) surface
        // as `ProbeError`. Same NonZero pattern as
        // `probe_access_as_tenant`.
        //
        // Note on absolute paths: macOS Tahoe (Darwin 25.x) ships
        // `test` at `/bin/test` (not `/usr/bin/test`); readlink at
        // `/usr/bin/readlink` (not `/bin/readlink`); `ln` at `/bin/ln`.
        // No single bin-directory is canonical on macOS; the right
        // answer is per-utility.
        let path_str = path.to_string_lossy().into_owned();
        let symlink_out = Command::new("sudo")
            .args(["-n", "-u", name.as_str(), "/bin/test", "-L", &path_str])
            .output()
            .map_err(ProbeError::Spawn)?;
        if let Some(code) = symlink_out.status.code() {
            if code == 0 {
                let readlink_out = Command::new("sudo")
                    .args(["-n", "-u", name.as_str(), "/usr/bin/readlink", &path_str])
                    .output()
                    .map_err(ProbeError::Spawn)?;
                match readlink_out.status.code() {
                    Some(0) => {
                        let target = String::from_utf8_lossy(&readlink_out.stdout)
                            .trim_end_matches('\n')
                            .to_string();
                        return Ok(PathKind::Symlink(std::path::PathBuf::from(target)));
                    }
                    Some(code) => {
                        return Err(ProbeError::NonZero {
                            code,
                            stderr: String::from_utf8_lossy(&readlink_out.stderr).into_owned(),
                        });
                    }
                    None => {
                        return Err(ProbeError::NonZero {
                            code: -1,
                            stderr: String::from_utf8_lossy(&readlink_out.stderr).into_owned(),
                        });
                    }
                }
            }
            if code != 1 {
                // Sudo-auth failure surfaces with codes other than 0/1.
                return Err(ProbeError::NonZero {
                    code,
                    stderr: String::from_utf8_lossy(&symlink_out.stderr).into_owned(),
                });
            }
        } else {
            return Err(ProbeError::NonZero {
                code: -1,
                stderr: String::from_utf8_lossy(&symlink_out.stderr).into_owned(),
            });
        }
        let exists_out = Command::new("sudo")
            .args(["-n", "-u", name.as_str(), "/bin/test", "-e", &path_str])
            .output()
            .map_err(ProbeError::Spawn)?;
        match exists_out.status.code() {
            Some(0) => Ok(PathKind::Other),
            Some(1) => Ok(PathKind::Absent),
            Some(code) => Err(ProbeError::NonZero {
                code,
                stderr: String::from_utf8_lossy(&exists_out.stderr).into_owned(),
            }),
            None => Err(ProbeError::NonZero {
                code: -1,
                stderr: String::from_utf8_lossy(&exists_out.stderr).into_owned(),
            }),
        }
    }

    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError> {
        // Operator-process `ls -lde <path>`: host-side ACL is host
        // state, read from the operator process — no sudo, no
        // run-as-tenant. `ls`'s exit code is 0 on success, non-zero
        // when the path is unreadable (which IS a substrate failure
        // for doctor's purposes — operator can't audit a path they
        // can't list). Concatenate stdout+stderr so both `total N +
        // entries` lines and any error blurb feed the parser uniformly.
        let path_str = path.to_string_lossy().into_owned();
        let output = Command::new("ls")
            .args(["-lde", &path_str])
            .output()
            .map_err(ProbeError::Spawn)?;
        if !output.status.success() {
            return Err(ProbeError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn describe_acl(&self, op: &AclOp) -> String {
        // Pretend-shell `chmod +a "<entry>" <path>` framing. Quoted
        // entry preserved with literal double-quotes in the rendered
        // line — matches the form an operator would type at a prompt;
        // also lets the test golden assert on the exact shape.
        let (flag, path, group, mode) = match op {
            AclOp::Grant {
                path, group, mode, ..
            } => ("+a", path, group, mode),
            AclOp::Revoke {
                path, group, mode, ..
            } => ("-a", path, group, mode),
        };
        format!(
            "chmod {flag} \"{}\" {}",
            acl_entry(group.as_str(), *mode),
            path.display(),
        )
    }

    fn execute_acl(&self, op: &AclOp) -> Result<(), AclError> {
        // macOS `chmod +a` is natively idempotent — re-applying the
        // same ACL entry to a path that already carries it doesn't
        // add a duplicate and doesn't error. So Grant runs chmod
        // unconditionally; substrate-side dedup is the contract.
        //
        // An earlier draft tried a substring-match pre-check against
        // `ls -lde` output before calling chmod, but macOS canonicalizes
        // the bit names on storage (we write
        // `read,write,execute,delete,append` and macOS stores
        // `list,add_file,search,delete,add_subdirectory`), so the
        // substring pre-check always failed false-negative and chmod
        // ran every time anyway. Removed the dead pre-check; the
        // operator-visible behavior is unchanged.
        //
        // Revoke (`chmod -a`) on an absent entry currently surfaces
        // as `AclError::NonZero` with "No matching ACL entry" stderr.
        // No production path exercises Revoke today; future
        // ACL-drift remediation will need to tolerate that case
        // (or pre-check via ls).
        let (flag, path, group, mode) = match op {
            AclOp::Grant {
                path, group, mode, ..
            } => ("+a", path, group, mode),
            AclOp::Revoke {
                path, group, mode, ..
            } => ("-a", path, group, mode),
        };
        let entry = acl_entry(group.as_str(), *mode);
        let path_str = path.display().to_string();
        let output = Command::new("chmod")
            .args([flag, &entry, &path_str])
            .output()
            .map_err(AclError::Spawn)?;
        if !output.status.success() {
            return Err(AclError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(())
    }

    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError> {
        // Read-only directory-service membership probe. Exit 0 ⇒ member;
        // any non-zero exit (host absent from group, group absent) ⇒
        // false. Machinery failure (dseditgroup not on PATH, fork
        // failed) surfaces as `AccountError::Spawn`. The non-zero
        // branch deliberately does NOT inspect stderr; the idempotence
        // contract treats any non-zero as "not a member" so the
        // substrate isn't tied to the tool's exact stderr wording.
        let output = Command::new("dseditgroup")
            .args(["-o", "checkmember", "-m", host.as_str(), group.as_str()])
            .output()
            .map_err(AccountError::Spawn)?;
        Ok(output.status.success())
    }
}

/// Read `path` via `sudo -n cat <path>`. Used for privileged-read
/// access to `/etc/sudoers` and `/etc/sudoers.d/*`. Mirrors the
/// `write_privileged` pattern in reverse: confine sudo invocation
/// to one helper so the substrate code that calls it stays
/// readable.
fn read_privileged_text(path: &str) -> Result<String, HostFileError> {
    let output = Command::new("sudo")
        .args(["-n", "cat", path])
        .output()
        .map_err(HostFileError::Spawn)?;
    if !output.status.success() {
        return Err(HostFileError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Write `content` to a privileged absolute `path` via the tempfile +
/// sudo mv + sudo chmod pattern from the plugin's
/// `phase02_pf.py::_write_anchor_file`. Atomic from the operator's
/// viewpoint: either the file lands fully or it doesn't.
fn write_privileged(path: &str, content: &str) -> Result<(), FirewallError> {
    let tmp_path = tempfile_path();
    let mut tmp = fs::File::create(&tmp_path).map_err(|e| FirewallError::Fs {
        path: tmp_path.display().to_string(),
        message: e.to_string(),
    })?;
    tmp.write_all(content.as_bytes())
        .map_err(|e| FirewallError::Fs {
            path: tmp_path.display().to_string(),
            message: e.to_string(),
        })?;
    drop(tmp);

    let tmp_str = tmp_path.display().to_string();
    let result = (|| -> Result<(), FirewallError> {
        spawn_firewall(&["sudo".into(), "mv".into(), tmp_str.clone(), path.into()])?;
        spawn_firewall(&["sudo".into(), "chmod".into(), "0644".into(), path.into()])
    })();
    // Best-effort cleanup — `sudo mv` may have moved it already, which
    // makes remove_file a NotFound that we silently swallow.
    let _ = fs::remove_file(&tmp_path);
    result
}

/// Privately-named tempfile under the OS temp dir. PID + nanos suffix
/// to avoid collision between concurrent tenant invocations (rare in
/// the create/destroy verbs, but cheap to guard against).
fn tempfile_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut path = env::temp_dir();
    path.push(format!("tenant-pf-{pid}-{nanos}.tmp"));
    path
}

fn spawn_firewall(argv: &[String]) -> Result<(), FirewallError> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| FirewallError::Spawn(io::Error::other("argv is empty")))?;
    let output = Command::new(program)
        .args(rest)
        .output()
        .map_err(FirewallError::Spawn)?;
    if !output.status.success() {
        return Err(FirewallError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

/// Extract the tenant name from any `ProfileOp` variant. Centralizes the
/// pattern-match so future variants (e.g. a `Read` op) just slot in.
fn op_name(op: &ProfileOp) -> &TenantUserName {
    match op {
        ProfileOp::Create { name } | ProfileOp::Delete { name } => name,
    }
}

/// Resolve the absolute profile path for `name` on the host.
/// `$HOME/.config/tenant/profiles/<name>.toml`. The display form (with a
/// literal `~`) lives in `profile::display_path_for`; the absolute form
/// is what the fs ops need.
fn profile_path(name: &TenantUserName) -> Result<PathBuf, ProfileError> {
    let home = env::var("HOME").map_err(|_| ProfileError {
        message: "HOME environment variable is not set".to_string(),
    })?;
    Ok(PathBuf::from(home)
        .join(".config/tenant/profiles")
        .join(format!("{name}.toml")))
}

/// Translate an `AccountOp` to its argv. Confined to this module; the writer
/// never sees argv directly. Used by both `MacosExecutor::execute_account`
/// (to spawn the process) and `MacosExecutor::login` (to spawn the
/// interactive login shell). The describe-side renders its own strings to
/// match today's verbose-mode output byte-for-byte; the argv-builder is
/// kept separate so a future change to one form doesn't silently drift the
/// other.
fn account_argv(op: &AccountOp) -> Vec<String> {
    match op {
        AccountOp::CreateShareGroup { group, gid } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "create".into(),
            "-n".into(),
            ".".into(),
            "-i".into(),
            gid.to_string(),
            group.0.clone(),
        ],
        AccountOp::DeleteShareGroup { group } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "delete".into(),
            "-n".into(),
            ".".into(),
            group.0.clone(),
        ],
        AccountOp::CreateTenantUser { name, uid, gid } => vec![
            "sudo".into(),
            "sysadminctl".into(),
            "-addUser".into(),
            name.0.clone(),
            "-fullName".into(),
            format!("Tenant: {name}"),
            "-shell".into(),
            "/bin/zsh".into(),
            "-UID".into(),
            uid.to_string(),
            "-GID".into(),
            gid.to_string(),
        ],
        AccountOp::DeleteTenantUser { name } => vec![
            "sudo".into(),
            "sysadminctl".into(),
            "-deleteUser".into(),
            name.0.clone(),
        ],
        AccountOp::LookupUserRecord { name } => vec![
            "dscl".into(),
            ".".into(),
            "-read".into(),
            format!("/Users/{name}"),
        ],
        AccountOp::DeleteUserRecord { name } => vec![
            "sudo".into(),
            "dscl".into(),
            ".".into(),
            "-delete".into(),
            format!("/Users/{name}"),
        ],
        AccountOp::LoginAsUser { name } => {
            vec!["sudo".into(), "-iu".into(), name.0.clone()]
        }
        AccountOp::ExecAsUser { name, argv } => {
            // sudo -iu <name> -- <argv...>. Each argv element passes
            // through as a separate process-argv entry; shell
            // metacharacters inside a single element survive intact.
            let mut full = vec!["sudo".into(), "-iu".into(), name.0.clone(), "--".into()];
            full.extend(argv.iter().cloned());
            full
        }
        AccountOp::EnsureDirAsUser { name, path } => vec![
            "sudo".into(),
            "-n".into(),
            "-u".into(),
            name.0.clone(),
            "/bin/mkdir".into(),
            "-p".into(),
            path.display().to_string(),
        ],
        AccountOp::EnsureSymlinkAsUser { name, link, target } => vec![
            "sudo".into(),
            "-n".into(),
            "-u".into(),
            name.0.clone(),
            "/bin/ln".into(),
            "-sfn".into(),
            target.display().to_string(),
            link.display().to_string(),
        ],
        AccountOp::AddHostToShareGroup { group, host } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "edit".into(),
            "-n".into(),
            ".".into(),
            "-a".into(),
            host.0.clone(),
            "-t".into(),
            "user".into(),
            group.0.clone(),
        ],
        AccountOp::RemoveHostFromShareGroup { group, host } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "edit".into(),
            "-n".into(),
            ".".into(),
            "-d".into(),
            host.0.clone(),
            "-t".into(),
            "user".into(),
            group.0.clone(),
        ],
    }
}

/// Compose the ACL entry string for `(group, mode)`. The bytes live in
/// `AclMode::acl_bits`; this function adds the `group:<g> allow ` prefix.
/// One source of truth so both `describe_acl` (operator-facing
/// rendering) and `execute_acl` (chmod argv) use the same form.
fn acl_entry(group: &str, mode: AclMode) -> String {
    format!("group:{group} allow {}", mode.acl_bits())
}

fn spawn_capturing(argv: &[String]) -> Result<(), AccountError> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| AccountError::Spawn(io::Error::other("argv is empty")))?;
    let output = Command::new(program)
        .args(rest)
        .output()
        .map_err(AccountError::Spawn)?;
    if !output.status.success() {
        return Err(AccountError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

/// Mode swap-in for `--dry-run`. Composition root selects this when
/// `cli.dry_run` is set; the writer stays mode-agnostic. Describe still
/// renders display lines (the verbose dry-run plan needs them); execute
/// is a no-op.
pub struct DryRunExecutor;

impl Executor for DryRunExecutor {
    fn describe_account(&self, op: &AccountOp) -> String {
        MacosExecutor.describe_account(op)
    }
    fn execute_account(&self, _op: &AccountOp) -> Result<(), AccountError> {
        Ok(())
    }
    fn login(&self, _name: &TenantUserName) -> Result<i32, AccountError> {
        Ok(0)
    }
    fn exec_as_tenant(
        &self,
        _name: &TenantUserName,
        _argv: &[String],
    ) -> Result<i32, AccountError> {
        Ok(0)
    }
    fn describe_profile(&self, op: &ProfileOp) -> String {
        MacosExecutor.describe_profile(op)
    }
    fn execute_profile(&self, _op: &ProfileOp) -> Result<(), ProfileError> {
        Ok(())
    }
    /// Dry-run reads return the default profile content. At create-time
    /// the writer reads the profile after the (simulated) `ProfileOp::Create`
    /// step — the operator's mental model is "the file would now exist with
    /// the scaffolded default", so the dry-run read returns exactly that.
    /// No verb reads the profile outside the create flow, so this default
    /// covers every dry-run path that hits `read_profile`.
    fn read_profile(&self, _name: &TenantUserName) -> Result<String, ProfileError> {
        Ok(default_profile_toml())
    }
    /// Dry-run reads return an empty pf.conf — the plan focuses on what
    /// tenant adds to the file, not what's already there. The Writer's
    /// `ensure_anchor_ref(empty, name)` produces a clean two-line conf
    /// representing tenant's contribution.
    fn read_pf_conf(&self) -> Result<String, FirewallError> {
        Ok(String::new())
    }
    fn describe_firewall(&self, op: &FirewallOp) -> String {
        MacosExecutor.describe_firewall(op)
    }
    fn execute_firewall(&self, _op: &FirewallOp) -> Result<(), FirewallError> {
        Ok(())
    }

    /// Dry-run skips probes entirely. The dispatcher's `Verb::Doctor`
    /// arm short-circuits before calling any executor probe under
    /// `--dry-run`; if anything does reach this impl, return Unknown
    /// rather than fabricating a misleading Allowed/Denied answer.
    fn probe_access_as_tenant(
        &self,
        _name: &TenantUserName,
        _path: &std::path::Path,
        _mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError> {
        Ok(AccessOutcome::Unknown)
    }

    /// Dry-run returns a "no-leak" placeholder env policy so the
    /// dry-run plan output doesn't fire an EnvLeak finding. The
    /// real env policy could go either way; for a "would-do"
    /// preview, we lean against producing an actionable warning the
    /// operator might then chase down outside of a real run.
    fn read_env_policy(&self) -> Result<String, HostFileError> {
        Ok("Defaults env_delete += \"SSH_AUTH_SOCK\"\n".to_string())
    }

    /// Dry-run returns a "no-drift" placeholder so the would-do
    /// preview doesn't fire spurious `PfRuleDrift` findings. Same
    /// posture as `read_env_policy`: the plan is about what tenant
    /// WOULD do, not about flagging unrelated host state.
    fn read_kernel_pf_rules(&self, _name: &TenantUserName) -> Result<String, FirewallError> {
        Ok(
            "block return inet from any to any\npass inet from 192.0.2.1 to <allowed> keep state\n"
                .to_string(),
        )
    }

    /// Dry-run returns a "Touch-ID-present" placeholder so the
    /// would-do preview doesn't fire a spurious `TouchIdMissing`
    /// finding. Real pam.d/sudo may differ; we avoid actionable
    /// warnings in the would-do preview.
    fn read_pam_sudo(&self) -> Result<String, HostFileError> {
        Ok("auth       sufficient     pam_tid.so\n".to_string())
    }

    /// Dry-run returns a "pf enabled" placeholder so the would-do
    /// preview doesn't fire a spurious `PfDisabled` finding. Same
    /// posture as the other read_* carve-outs.
    fn read_pf_status(&self) -> Result<String, FirewallError> {
        Ok("Status: Enabled for 0 days 00:00:00\n".to_string())
    }

    /// Dry-run returns the empty-allowlist render so the would-do
    /// preview never fires a spurious `AnchorBodyDrift` finding —
    /// `read_profile` already returns `default_profile_toml()` (empty
    /// allowlists), so a runtime-tier render of the parsed default
    /// is exactly `render_anchor(name, &[])`. Same posture as the
    /// other read_* carve-outs: avoid actionable warnings in the
    /// would-do preview.
    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        Ok(crate::firewall::render_anchor(name.as_str(), &[]))
    }

    fn describe_acl(&self, op: &AclOp) -> String {
        MacosExecutor.describe_acl(op)
    }

    fn execute_acl(&self, _op: &AclOp) -> Result<(), AclError> {
        Ok(())
    }

    /// Dry-run returns `Absent` so the plan preview never trips the
    /// `TenantPathOccupied` refusal — the operator's "would-do" view
    /// shows what tenant intends to install, not surprise refusals
    /// the real run might encounter on different host state.
    fn tenant_path_kind(
        &self,
        _name: &TenantUserName,
        _path: &std::path::Path,
    ) -> Result<PathKind, ProbeError> {
        Ok(PathKind::Absent)
    }

    /// Dry-run returns an empty listing. Unreachable under production
    /// dry-run because `read_profile` returns `default_profile_toml()`
    /// (no `[[shares]]`), so doctor's per-share-drift loop skips before
    /// reaching this method. Defensive return preserves the
    /// "no actionable warnings in the would-do preview" posture if a
    /// future code path adds a default share.
    fn read_host_acl(&self, _path: &std::path::Path) -> Result<String, ProbeError> {
        Ok(String::new())
    }

    /// Dry-run returns `true` so the would-do preview never trips
    /// doctor's `HostNotInShareGroup` finding — same "no actionable
    /// warnings in dry-run" posture as `read_host_acl` and
    /// `tenant_path_kind`.
    fn host_in_group(
        &self,
        _host: &HostUserName,
        _group: &GroupName,
    ) -> Result<bool, AccountError> {
        Ok(true)
    }
}

/// Test substitute. Records every op invocation (for behavioral assertions)
/// and supports per-op failure injection (for partial-failure-path tests
/// like "sysadminctl-addUser fails after dseditgroup-create succeeded").
/// Describe still works (tests assert on the rendered plan/echo strings via
/// the byte-exact stdout E2E pattern).
#[derive(Default)]
pub struct StubExecutor {
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
    /// `StubExecutor::failing` infinite-fire shape). Spawn-failure
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
    /// "Touch-ID-active" placeholder (see `StubExecutor::new`) so
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

impl StubExecutor {
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
    /// `StubExecutor::failing_with`. Fires on every call (not one-shot).
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

impl Executor for StubExecutor {
    fn describe_account(&self, op: &AccountOp) -> String {
        MacosExecutor.describe_account(op)
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
        MacosExecutor.describe_profile(op)
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
        MacosExecutor.describe_firewall(op)
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
        MacosExecutor.describe_acl(op)
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
        // tenant (via profile_state's keys, which the stub_reader keeps
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
