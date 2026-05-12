//! Host-side substrate for the writer's domain operations.
//!
//! # Architecture
//!
//! Earlier iterations fused intent (what the writer wanted to do) with
//! mechanism (the argv that does it on macOS). Writers built argv via a
//! `build_*_argv` family of helpers; the executor only knew how to spawn
//! processes. Adding non-argv operations (cycle 1's profile-write; cycle
//! 2's PF anchor install) forced "synthetic argv" hacks to flow non-shell
//! ops through the same display/test pipeline.
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
use crate::profile::{ProfileError, default_profile_toml, display_path_for};

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
    /// Create the `<name>-tenant-share` primary group with the given GID.
    /// Maps to `sudo dseditgroup -o create -n . -i <gid> <name>-tenant-share`
    /// on macOS.
    CreateShareGroup { name: String, gid: u32 },

    /// Delete the `<name>-tenant-share` group. Used as the create-side
    /// rollback step and the destroy-side cleanup step. Maps to `sudo
    /// dseditgroup -o delete -n . <name>-tenant-share` on macOS.
    DeleteShareGroup { name: String },

    /// Create the tenant user with the given UID + GID. Maps to `sudo
    /// sysadminctl -addUser <name> -fullName "Tenant: <name>" -shell
    /// /bin/zsh -UID <uid> -GID <gid>` on macOS.
    CreateTenantUser { name: String, uid: u32, gid: u32 },

    /// Delete the tenant user via the OD-aware tool. Maps to `sudo
    /// sysadminctl -deleteUser <name>` on macOS. Distinct from
    /// `DeleteUserRecord` (low-level dscl cleanup); the doctrine separates
    /// these because sysadminctl handles home-directory move-to-Deleted-Users
    /// while dscl only touches the DS record.
    DeleteTenantUser { name: String },

    /// Probe for an OD record's presence. Maps to `dscl . -read /Users/<name>`
    /// on macOS. The substrate's `execute_account` reports `Ok(())` when the
    /// record exists and `Err(AccountError::NonZero{..})` when it doesn't —
    /// the writer uses that result to gate the conditional `DeleteUserRecord`
    /// cleanup. No sudo (reads on the local node don't require it).
    LookupUserRecord { name: String },

    /// Low-level cleanup of a stale OD record that `DeleteTenantUser` may
    /// have left behind. Maps to `sudo dscl . -delete /Users/<name>` on
    /// macOS. Belt-and-braces; runs only when `LookupUserRecord` finds the
    /// record present.
    DeleteUserRecord { name: String },

    /// Interactive login as the tenant. Used by the `shell` verb. The
    /// describe-side renders `sudo -iu <name>`; execution goes through
    /// `Executor::login` (NOT `execute_account`) because the return type
    /// is the child shell's exit code, and stdio must inherit so sudo can
    /// prompt and the login shell can drive the controlling terminal.
    LoginAsUser { name: String },
}

/// Profile-domain operations. The store-backed `~/.config/tenant/profiles/<name>.toml`
/// file is the host-side artifact; the substrate handles the actual fs work
/// (or in-memory recording for tests). Cycle 2's profile read path lives on
/// `Executor::read_profile` (a dedicated method, not a variant here) because
/// the return type — file content, not unit — doesn't fit
/// `execute_profile`'s shape. Parallels `login`'s carve-out from
/// `execute_account` for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOp {
    /// Write the default profile content for `name`. Idempotent overwrite
    /// (matches the cycle-1 contract).
    Create { name: String },

    /// Remove the profile file. Idempotent: NotFound is success, mirroring
    /// the operator's mental model of `rm -f`.
    Delete { name: String },
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallOp {
    /// Write the rendered anchor body to `/etc/pf.anchors/tenant-<name>`.
    /// `name` is the tenant name; the anchor file's full name
    /// (`tenant-<name>`) is constructed by `MacosExecutor` from it. `body`
    /// is the precomputed anchor content (from `firewall::render_anchor`).
    InstallAnchor { name: String, body: String },

    /// Remove `/etc/pf.anchors/tenant-<name>`. Idempotent: NotFound is
    /// success on production, mirroring the operator's mental model of
    /// `rm -f`.
    RemoveAnchor { name: String },

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
    FlushAnchor { name: String },

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
    fn login(&self, name: &str) -> Result<i32, AccountError>;

    fn describe_profile(&self, op: &ProfileOp) -> String;
    fn execute_profile(&self, op: &ProfileOp) -> Result<(), ProfileError>;

    /// Read the on-disk profile TOML content for `name`. Separate from
    /// `execute_profile` because the return type (file content, not unit)
    /// doesn't fit `execute_profile`'s shape — same carve-out rationale
    /// as `login`. Cycle 2's create-side firewall step calls this to feed
    /// the anchor renderer.
    fn read_profile(&self, name: &str) -> Result<String, ProfileError>;

    /// Read the current `/etc/pf.conf` content. Used by the Writer to
    /// compute the post-edit conf via `firewall::ensure_anchor_ref` /
    /// `remove_anchor_ref` before issuing `FirewallOp::UpdateConfig`.
    /// Same carve-out rationale as `read_profile`: the return type is
    /// content, not unit. Dry-run returns an empty conf — the plan
    /// focuses on what tenant adds, not what's already there.
    fn read_pf_conf(&self) -> Result<String, FirewallError>;

    fn describe_firewall(&self, op: &FirewallOp) -> String;
    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError>;
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
}

impl<'a> Op<'a> {
    /// Render the op as an operator-facing display line. The match here
    /// is the one place in the codebase that has to know the
    /// account/profile/firewall split for display purposes.
    pub fn describe_via(&self, executor: &dyn Executor) -> String {
        match self {
            Op::Account(op) => executor.describe_account(op),
            Op::Profile(op) => executor.describe_profile(op),
            Op::Firewall(op) => executor.describe_firewall(op),
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

/// Production substrate. Knows the macOS tool argv and the XDG-style profile
/// path convention. The argv-building logic that previously lived in the
/// `build_*_argv` family (and the synthetic-argv hacks for profile ops) is
/// now confined to this struct's methods.
pub struct MacosExecutor;

impl Executor for MacosExecutor {
    fn describe_account(&self, op: &AccountOp) -> String {
        match op {
            AccountOp::CreateShareGroup { name, gid } => {
                format!("sudo dseditgroup -o create -n . -i {gid} {name}-tenant-share")
            }
            AccountOp::DeleteShareGroup { name } => {
                format!("sudo dseditgroup -o delete -n . {name}-tenant-share")
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
        }
    }

    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        // LoginAsUser is intentionally not handled here — interactive ops go
        // through `login`. Match-arm panics on it so an accidental wiring
        // through `execute_account` fails loudly in dev / tests rather than
        // silently doing the wrong thing in prod.
        let argv = match op {
            AccountOp::LoginAsUser { .. } => {
                panic!(
                    "AccountOp::LoginAsUser must go through Executor::login, not execute_account"
                )
            }
            _ => account_argv(op),
        };
        spawn_capturing(&argv)
    }

    fn login(&self, name: &str) -> Result<i32, AccountError> {
        // Stdio inherits so sudo can prompt for the host password and the
        // launched login shell can drive the controlling terminal. Mirrors
        // the pre-refactor `Executor::exec_into`.
        let argv = account_argv(&AccountOp::LoginAsUser {
            name: name.to_string(),
        });
        let (program, rest) = argv
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
                format!("tee {} < default.toml", display_path_for(name))
            }
            ProfileOp::Delete { name } => {
                // `rm -f` reflects the idempotent semantics — NotFound is
                // success on both the production fs side and the stub.
                format!("rm -f {}", display_path_for(name))
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

    fn read_profile(&self, name: &str) -> Result<String, ProfileError> {
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

    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError> {
        match op {
            FirewallOp::InstallAnchor { name, body } => {
                write_privileged(&tenant_anchor_path(name), body)
            }
            FirewallOp::RemoveAnchor { name } => {
                // `sudo rm -f <path>` — idempotent on the macOS side
                // (`rm -f` returns 0 on NotFound), so a partial-state
                // destroy doesn't trip here.
                spawn_firewall(&[
                    "sudo".into(),
                    "rm".into(),
                    "-f".into(),
                    tenant_anchor_path(name),
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
/// pattern-match so future variants (cycle 2's `Read`) just slot in.
fn op_name(op: &ProfileOp) -> &str {
    match op {
        ProfileOp::Create { name } | ProfileOp::Delete { name } => name,
    }
}

/// Resolve the absolute profile path for `name` on the host.
/// `$HOME/.config/tenant/profiles/<name>.toml`. The display form (with a
/// literal `~`) lives in `profile::display_path_for`; the absolute form
/// is what the fs ops need.
fn profile_path(name: &str) -> Result<PathBuf, ProfileError> {
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
        AccountOp::CreateShareGroup { name, gid } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "create".into(),
            "-n".into(),
            ".".into(),
            "-i".into(),
            gid.to_string(),
            format!("{name}-tenant-share"),
        ],
        AccountOp::DeleteShareGroup { name } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "delete".into(),
            "-n".into(),
            ".".into(),
            format!("{name}-tenant-share"),
        ],
        AccountOp::CreateTenantUser { name, uid, gid } => vec![
            "sudo".into(),
            "sysadminctl".into(),
            "-addUser".into(),
            name.clone(),
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
            name.clone(),
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
            vec!["sudo".into(), "-iu".into(), name.clone()]
        }
    }
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
    fn login(&self, _name: &str) -> Result<i32, AccountError> {
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
    fn read_profile(&self, _name: &str) -> Result<String, ProfileError> {
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
    /// rewriting `default_profile_toml`. The cycle-2 allow-path
    /// manual smoke validates this end-to-end against real pfctl; the
    /// automated counterpart pins the same data flow through the stub.
    create_profile_overrides: RefCell<HashMap<String, String>>,
}

impl StubExecutor {
    pub fn new() -> Self {
        Self::default()
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

    /// Pre-load a profile (e.g. for destroy tests that need to assert
    /// "this was here before, gone after"). Mirrors the pre-refactor
    /// `StubProfileStore::with_profile`. Content is opaque to the
    /// substrate; only the presence/absence semantics matter for
    /// cycle-1 assertions.
    pub fn with_existing_profile(self, name: &str, content: &str) -> Self {
        self.profile_state
            .borrow_mut()
            .insert(name.to_string(), content.to_string());
        self
    }

    /// Pre-load `/etc/pf.conf` content for `read_pf_conf`. Used by
    /// cycle-2 tests that need a host-state with existing anchor refs
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

    fn login(&self, name: &str) -> Result<i32, AccountError> {
        self.logins.borrow_mut().push(name.to_string());
        Ok(self.login_exit_code.get())
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
                    .get(name)
                    .cloned()
                    .unwrap_or_else(default_profile_toml);
                self.profile_state
                    .borrow_mut()
                    .insert(name.clone(), content);
            }
            ProfileOp::Delete { name } => {
                self.profile_state.borrow_mut().remove(name);
            }
        }
        Ok(())
    }

    fn read_profile(&self, name: &str) -> Result<String, ProfileError> {
        match self.profile_state.borrow().get(name) {
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
}
