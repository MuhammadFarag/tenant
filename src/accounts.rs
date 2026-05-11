use std::collections::{HashMap, HashSet};
use std::io;
use std::process::Command;

use crate::allocation::TENANT_UID_FLOOR;
use crate::executor::{ExecError, Executor};
use crate::messages;
use crate::reporter::Reporter;

pub trait Reader {
    fn used_uids(&self) -> Vec<u32>;
    fn has_user(&self, name: &str) -> bool;
    fn has_group(&self, name: &str) -> bool;
    /// Returns the positive UID for `name`, or `None` if either (a) the
    /// account doesn't exist, or (b) the account exists with a non-positive
    /// UID (negative-UID system accounts like `nobody` on macOS). Callers
    /// that need to distinguish "absent" from "present with no positive UID"
    /// must consult `has_user` separately — `destroy_eligibility` is the
    /// canonical example: a `(has_user: true, uid_for: None)` pair is a
    /// system account, classified `Eligibility::SystemAccount`.
    fn uid_for(&self, name: &str) -> Option<u32>;
}

#[derive(Default)]
pub struct StubReader {
    pub uid_by_name: HashMap<String, u32>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
}

impl Reader for StubReader {
    fn used_uids(&self) -> Vec<u32> {
        self.uid_by_name.values().copied().collect()
    }

    fn has_user(&self, name: &str) -> bool {
        self.users.iter().any(|u| u == name)
    }

    fn has_group(&self, name: &str) -> bool {
        self.groups.iter().any(|g| g == name)
    }

    fn uid_for(&self, name: &str) -> Option<u32> {
        self.uid_by_name.get(name).copied()
    }
}

const MAX_NAME_LEN: usize = 31;

/// Lexical-validation outcomes from `validate_name`. Each variant carries
/// just enough information for the matching message factory in
/// `messages.rs` to render an operator-friendly explanation.
#[derive(Debug)]
pub enum NameError {
    Empty,
    InvalidStart(char),
    InvalidCharacter(char),
    TooLong { len: usize, max: usize },
}

/// State-based conflict outcomes from `check_conflict` (the create-side
/// precheck). Each variant maps to a distinct refusal message; all three
/// produce `EX_USAGE` at the dispatch layer.
#[derive(Debug)]
pub enum ConflictError {
    UserExists,
    GroupExists,
    Both,
}

/// Create-side precheck: refuse if the requested name already exists as a
/// user, a group, or both. The `(false, false)` happy path means the name
/// is free for sysadminctl to provision.
pub fn check_conflict(reader: &dyn Reader, name: &str) -> Result<(), ConflictError> {
    match (reader.has_user(name), reader.has_group(name)) {
        (false, false) => Ok(()),
        (true, false) => Err(ConflictError::UserExists),
        (false, true) => Err(ConflictError::GroupExists),
        (true, true) => Err(ConflictError::Both),
    }
}

/// Four-way classification of whether a name is destroyable.
/// `Destroyable` means the dispatcher should call `Writer::destroy_tenant`;
/// `NotPresent` means destroy is a convergent noop (already absent);
/// `NotATenant` means the account exists with a positive UID below the
/// tenant floor (system or human account masquerading as a tenant);
/// `SystemAccount` means the account exists in the user listing but has no
/// positive UID (`nobody` and other negative-UID service accounts) — those
/// are filtered out of `uid_by_name` upstream, so the floor predicate
/// can't bind to a value. Both refusal variants exit with `EX_USAGE`; the
/// split exists so the error message can be honest about the reason.
#[derive(Debug)]
pub enum Eligibility {
    Destroyable,
    NotPresent,
    NotATenant { uid: u32 },
    SystemAccount,
}

/// Classify a name for destroy. Uses `has_user` as the presence gate
/// (so accounts with non-positive UIDs — which are filtered out of
/// `uid_by_name` — are not misclassified as `NotPresent`), then
/// `uid_for` for the floor check. The `(true, None)` case is a system
/// account with a non-positive UID, which we refuse via `SystemAccount`.
pub fn destroy_eligibility(reader: &dyn Reader, name: &str) -> Eligibility {
    if !reader.has_user(name) {
        return Eligibility::NotPresent;
    }
    match reader.uid_for(name) {
        Some(uid) if uid >= TENANT_UID_FLOOR => Eligibility::Destroyable,
        Some(uid) => Eligibility::NotATenant { uid },
        None => Eligibility::SystemAccount,
    }
}

/// Real `Reader` backed by `dscl`. Queries the local Open Directory node
/// once at construction and serves all subsequent lookups from memory.
/// `users` and `uid_by_name` are kept separate for the same reason the
/// stub keeps them separate: macOS service accounts with negative UIDs
/// (`nobody` is the canonical case) are present in the user listing but
/// are filtered out of the UID map (negative-UID accounts can't masquerade
/// as a tenant-range UID and shouldn't influence allocator state).
pub struct MacosReader {
    users: HashSet<String>,
    groups: HashSet<String>,
    uid_by_name: HashMap<String, u32>,
}

impl MacosReader {
    pub fn new() -> io::Result<Self> {
        let users = run_dscl(&[".", "-list", "/Users"])?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let groups = run_dscl(&[".", "-list", "/Groups"])?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        // Fold (rather than .collect()) so a name that appears in multiple
        // UniqueID rows resolves to its *lowest* UID. Standard macOS doesn't
        // emit duplicates from the local node, but malformed or hand-edited
        // OD state could; under destroy's floor check the lowest UID is the
        // safer choice (most likely to be a system-account match, which we
        // refuse). Without this, a `HashMap::collect` would keep the last
        // line seen, which on duplicate rows could let a system account
        // alias a tenant-range UID and slip past `destroy_eligibility`.
        let uid_by_name = run_dscl(&[".", "-list", "/Users", "UniqueID"])?
            .lines()
            .filter_map(parse_uid_line)
            .fold(HashMap::<String, u32>::new(), |mut map, (name, uid)| {
                map.entry(name)
                    .and_modify(|cur| *cur = (*cur).min(uid))
                    .or_insert(uid);
                map
            });
        Ok(MacosReader {
            users,
            groups,
            uid_by_name,
        })
    }
}

impl Reader for MacosReader {
    fn used_uids(&self) -> Vec<u32> {
        self.uid_by_name.values().copied().collect()
    }

    fn has_user(&self, name: &str) -> bool {
        self.users.contains(name)
    }

    fn has_group(&self, name: &str) -> bool {
        self.groups.contains(name)
    }

    fn uid_for(&self, name: &str) -> Option<u32> {
        self.uid_by_name.get(name).copied()
    }
}

fn parse_uid_line(line: &str) -> Option<(String, u32)> {
    // dscl `-list /Users UniqueID` lines are "name<whitespace>uid".
    // Negative UIDs (system accounts like `nobody`) are filtered out — they
    // can't appear in the tenant range, so they're irrelevant to the
    // allocator. Negative-UID users still appear in the `users` set (built
    // from a separate dscl call), so `has_user` still finds them — that's
    // what create's `check_conflict` consults to refuse aliasing, and what
    // destroy's `destroy_eligibility` consults to classify them as
    // `SystemAccount` (refused with `EX_USAGE`) rather than `NotPresent`
    // (which would emit a misleading "does not exist" noop).
    let mut parts = line.split_whitespace();
    let name = parts.next()?;
    let uid = parts.next()?.parse::<i32>().ok()?;
    if uid < 0 {
        None
    } else {
        Some((name.to_string(), uid as u32))
    }
}

fn run_dscl(args: &[&str]) -> io::Result<String> {
    let output = Command::new("dscl").args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "dscl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Side-effecting half of the accounts API. Verbs ask in domain terms;
/// the impl owns argv construction and self-emits intent + (verbose)
/// mechanism via the Reporter handed in. Mode (real vs dry-run) is not
/// the Writer's concern — each method always renders the same three
/// bracketed Messages (`would_<action>` / `<action>ing` / `<action>ed`)
/// and always invokes the executor. The Reporter filters each Message
/// down to the right mode/verbosity; the Executor is a no-op in dry-run.
pub(crate) trait Writer {
    fn create_tenant(&self, name: &str, uid: u32, reporter: &mut Reporter)
    -> Result<(), ExecError>;

    fn destroy_tenant(&self, name: &str, reporter: &mut Reporter) -> Result<(), ExecError>;
}

pub(crate) struct MacosWriter<'a> {
    executor: &'a dyn Executor,
}

impl<'a> MacosWriter<'a> {
    pub(crate) fn new(executor: &'a dyn Executor) -> Self {
        Self { executor }
    }
}

impl<'a> Writer for MacosWriter<'a> {
    fn create_tenant(
        &self,
        name: &str,
        uid: u32,
        reporter: &mut Reporter,
    ) -> Result<(), ExecError> {
        let argv = build_create_argv(name, uid);
        // Three bracketed Reporter calls; each is silent except in its
        // applicable mode/verbosity. Net effect: dry-run shows "Would …"
        // (and mechanism in verbose); real-standard shows only the
        // post-exec "Created …"; real-verbose shows pre-exec intent +
        // mechanism + post-exec confirmation with UID.
        reporter.emit_dry_only(messages::would_create_tenant(name, &argv));
        reporter.emit_real_only(messages::creating_tenant(name, &argv));
        self.executor.run(&argv)?;
        reporter.emit_real_only(messages::created_tenant(name, uid));
        Ok(())
    }

    fn destroy_tenant(&self, name: &str, reporter: &mut Reporter) -> Result<(), ExecError> {
        let argv = build_destroy_argv(name);
        // Same three-message bracket as create: dry-run shows "Would …",
        // real-verbose shows pre-exec intent + mechanism, real-standard
        // shows only the post-exec confirmation.
        reporter.emit_dry_only(messages::would_destroy_tenant(name, &argv));
        reporter.emit_real_only(messages::destroying_tenant(name, &argv));
        self.executor.run(&argv)?;
        reporter.emit_real_only(messages::destroyed_tenant(name));
        Ok(())
    }
}

fn build_create_argv(name: &str, uid: u32) -> Vec<String> {
    vec![
        "sudo".into(),
        "sysadminctl".into(),
        "-addUser".into(),
        name.into(),
        "-fullName".into(),
        format!("Tenant: {name}"),
        "-shell".into(),
        "/bin/zsh".into(),
        "-UID".into(),
        uid.to_string(),
        "-GID".into(),
        uid.to_string(),
    ]
}

fn build_destroy_argv(name: &str) -> Vec<String> {
    vec![
        "sudo".into(),
        "sysadminctl".into(),
        "-deleteUser".into(),
        name.into(),
    ]
}

/// Lexical name guard: `[a-z][a-z0-9_-]{0,30}`. The leading-letter rule
/// is load-bearing — it lexically excludes the macOS `_*` service-account
/// namespace and any `-…` argv that sysadminctl would interpret as a
/// flag. Shared by `create` and `destroy` as the cheapest first failure
/// (no Reader call needed). `len` is byte length, which equals character
/// length for valid input since the charset is ASCII; non-ASCII input
/// trips `InvalidCharacter` after the length check.
pub fn validate_name(name: &str) -> Result<(), NameError> {
    let len = name.len();
    if len == 0 {
        return Err(NameError::Empty);
    }
    if len > MAX_NAME_LEN {
        return Err(NameError::TooLong {
            len,
            max: MAX_NAME_LEN,
        });
    }
    let mut chars = name.chars();
    let first = chars.next().expect("len > 0 guarantees at least one char");
    if !first.is_ascii_lowercase() {
        return Err(NameError::InvalidStart(first));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return Err(NameError::InvalidCharacter(c));
        }
    }
    Ok(())
}
