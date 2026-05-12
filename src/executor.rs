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
use std::path::PathBuf;
use std::process::Command;

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
/// (or in-memory recording for tests). `Read` lands in cycle 2 when the PF
/// anchor renderer needs the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOp {
    /// Write the default profile content for `name`. Idempotent overwrite
    /// (matches the cycle-1 contract).
    Create { name: String },

    /// Remove the profile file. Idempotent: NotFound is success, mirroring
    /// the operator's mental model of `rm -f`.
    Delete { name: String },
    // Cycle 2 adds:
    // Read { name: String },
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

    /// Exit code returned by `login`. Default 0; tests set this to pin the
    /// shell-verb's exit-code propagation contract.
    login_exit_code: Cell<i32>,

    /// In-memory simulation of the on-disk profile state. `execute_profile`
    /// mutates this — `Create` writes `default_profile_toml()` under the
    /// tenant name, `Delete` removes the entry — so tests can assert on
    /// presence/absence (`has_profile`) and byte-exact content
    /// (`profile_state`). Mirrors the pre-refactor `StubProfileStore`'s
    /// `HashMap<String, String>` backing.
    profile_state: RefCell<HashMap<String, String>>,
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
                self.profile_state
                    .borrow_mut()
                    .insert(name.clone(), default_profile_toml());
            }
            ProfileOp::Delete { name } => {
                self.profile_state.borrow_mut().remove(name);
            }
        }
        Ok(())
    }
}
