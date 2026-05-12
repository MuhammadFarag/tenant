use std::collections::{HashMap, HashSet};
use std::io;
use std::process::Command;

use crate::allocation::TENANT_UID_FLOOR;
use crate::executor::{self, AccountError, AccountOp, ProfileOp};
use crate::messages::{self, PlanStep};
use crate::profile::ProfileError;
use crate::reporter::Reporter;

pub trait Reader {
    fn used_uids(&self) -> Vec<u32>;
    /// Mirror of `used_uids` for the GID space. Phase 3 allocates UID and
    /// GID independently — they may converge at the floor in fresh hosts
    /// but diverge as tenants come and go. Feeds `GidAllocator`.
    fn used_gids(&self) -> Vec<u32>;
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
    pub gid_by_name: HashMap<String, u32>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
}

impl Reader for StubReader {
    fn used_uids(&self) -> Vec<u32> {
        self.uid_by_name.values().copied().collect()
    }

    fn used_gids(&self) -> Vec<u32> {
        self.gid_by_name.values().copied().collect()
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

/// macOS system / role names that pass the lexical charset rules
/// (`[a-z][a-z0-9_-]*`) but would either alias a real account
/// (`root`, `nobody`) or carry privileged semantics we don't want a
/// tenant to inherit (`wheel`, `staff`, `sudo`). Refused by `validate_name`
/// with `NameError::Reserved`, mapped to `EX_USAGE` at dispatch. The set
/// is copied verbatim from the sandbox plugin's
/// `scripts/lib/naming.py` — see CLAUDE.md cross-reference. The macOS
/// `_*` service-account namespace is already excluded by the
/// leading-letter rule (`InvalidStart`) so no special handling needed
/// for `_sandbox` etc.
const RESERVED_NAMES: &[&str] = &[
    "root", "admin", "staff", "wheel", "daemon", "nobody", "sudo",
];

/// Lexical-validation outcomes from `validate_name`. Each variant carries
/// just enough information for the matching message factory in
/// `messages.rs` to render an operator-friendly explanation.
#[derive(Debug)]
pub enum NameError {
    Empty,
    InvalidStart(char),
    InvalidCharacter(char),
    TooLong {
        len: usize,
        max: usize,
    },
    /// Lexically valid but appears in `RESERVED_NAMES`. The error message
    /// uses the name itself (already in dispatch context) so this variant
    /// is payload-free.
    Reserved,
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

/// Phase 3 names the primary group `<name>-tenant-share` (not bare
/// `<name>`). Single source of truth for the suffix so `check_conflict`,
/// the create/destroy writers, and the orphan-group convergence path all
/// agree on the literal string. Choosing the convention here also keeps the
/// suffix exactly one grep away from any caller — handy when the operator
/// asks "where does '-tenant-share' come from?".
pub fn tenant_share_group_name(name: &str) -> String {
    format!("{name}-tenant-share")
}

/// Create-side precheck: refuse if the requested name already exists as a
/// user, or if `<name>-tenant-share` already exists as a group, or both.
/// Pre-Phase-3 this checked the bare-name group; that arm was dropped
/// because tenant no longer creates bare-name groups (the suffixed name is
/// the only group identity Phase 3 owns) so a stray bare-name group on
/// the host is no longer in conflict territory.
pub fn check_conflict(reader: &dyn Reader, name: &str) -> Result<(), ConflictError> {
    let group = tenant_share_group_name(name);
    match (reader.has_user(name), reader.has_group(&group)) {
        (false, false) => Ok(()),
        (true, false) => Err(ConflictError::UserExists),
        (false, true) => Err(ConflictError::GroupExists),
        (true, true) => Err(ConflictError::Both),
    }
}

/// Five-way classification of whether a name is destroyable.
/// `Destroyable` means the dispatcher should call `Writer::destroy_tenant`;
/// `NotPresent` means destroy is a convergent noop (user absent AND
/// no `<name>-tenant-share` group residue);
/// `OrphanGroup` means the user is absent but the suffixed group is still
/// present (e.g. a prior destroy that failed at the dseditgroup-delete
/// step) — the dispatcher converges via `Writer::destroy_orphan_group`;
/// `NotATenant` means the account exists with a positive UID below the
/// tenant floor (system or human account masquerading as a tenant);
/// `SystemAccount` means the account exists in the user listing but has no
/// positive UID (`nobody` and other negative-UID service accounts) — those
/// are filtered out of `uid_by_name` upstream, so the floor predicate
/// can't bind to a value. The two refusal variants exit with `EX_USAGE`;
/// the split exists so the error message can be honest about the reason.
#[derive(Debug)]
pub enum Eligibility {
    Destroyable,
    NotPresent,
    /// User absent, `<name>-tenant-share` group present. The host carries
    /// orphan group state from a prior partial failure; destroy
    /// converges by removing the group with `dseditgroup -o delete`.
    OrphanGroup,
    NotATenant {
        uid: u32,
    },
    SystemAccount,
}

/// Classify a name for destroy. Uses `has_user` as the presence gate
/// (so accounts with non-positive UIDs — which are filtered out of
/// `uid_by_name` — are not misclassified as `NotPresent`), then
/// `uid_for` for the floor check. The `(true, None)` case is a system
/// account with a non-positive UID, which we refuse via `SystemAccount`.
/// When the user is absent, the suffixed group's presence determines
/// whether destroy converges through the `OrphanGroup` path or is a true
/// `NotPresent` noop.
pub fn destroy_eligibility(reader: &dyn Reader, name: &str) -> Eligibility {
    if !reader.has_user(name) {
        if reader.has_group(&tenant_share_group_name(name)) {
            return Eligibility::OrphanGroup;
        }
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
/// `gid_by_name` mirrors the UID structure for the GID space, with the
/// same negative-GID filtering rationale.
pub struct MacosReader {
    users: HashSet<String>,
    groups: HashSet<String>,
    uid_by_name: HashMap<String, u32>,
    gid_by_name: HashMap<String, u32>,
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
            .filter_map(parse_id_line)
            .fold(HashMap::<String, u32>::new(), |mut map, (name, uid)| {
                map.entry(name)
                    .and_modify(|cur| *cur = (*cur).min(uid))
                    .or_insert(uid);
                map
            });
        // Same shape for the GID space. `PrimaryGroupID` is the dscl key
        // on `/Groups`. Mirrors the UID parse: negative-GID filter (macOS
        // service groups can have negative GIDs; allocator-irrelevant) and
        // lowest-on-duplicate fold for the same defensive reason.
        let gid_by_name = run_dscl(&[".", "-list", "/Groups", "PrimaryGroupID"])?
            .lines()
            .filter_map(parse_id_line)
            .fold(HashMap::<String, u32>::new(), |mut map, (name, gid)| {
                map.entry(name)
                    .and_modify(|cur| *cur = (*cur).min(gid))
                    .or_insert(gid);
                map
            });
        Ok(MacosReader {
            users,
            groups,
            uid_by_name,
            gid_by_name,
        })
    }
}

impl Reader for MacosReader {
    fn used_uids(&self) -> Vec<u32> {
        self.uid_by_name.values().copied().collect()
    }

    fn used_gids(&self) -> Vec<u32> {
        self.gid_by_name.values().copied().collect()
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

fn parse_id_line(line: &str) -> Option<(String, u32)> {
    // dscl `-list /Users UniqueID` and `-list /Groups PrimaryGroupID`
    // both emit "name<whitespace>id" lines, so a single parser serves
    // both. Negative IDs (system accounts/groups like `nobody`) are
    // filtered out — they can't appear in the tenant range and shouldn't
    // influence allocator state. Negative-ID entries still appear in the
    // `users`/`groups` sets (built from separate dscl calls), so the
    // `has_*` predicates still find them — that's what create's
    // `check_conflict` consults to refuse aliasing, and what destroy's
    // `destroy_eligibility` consults to classify as `SystemAccount`.
    let mut parts = line.split_whitespace();
    let name = parts.next()?;
    let id = parts.next()?.parse::<i32>().ok()?;
    if id < 0 {
        None
    } else {
        Some((name.to_string(), id as u32))
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

/// Granular error type for the create writer. Phase 3 splits the create
/// flow into two account-domain ops (CreateShareGroup +
/// CreateTenantUser), each of which can fail; cycle 1 adds the
/// profile-write step. The dispatcher needs to know which one failed so
/// it can render the right error message: `create_group_failed` if
/// dseditgroup tripped (the user wasn't touched), `create_failed` if
/// sysadminctl tripped (the writer ran a rollback). The third variant
/// covers the worst case where the rollback itself failed — the host is
/// left with an orphan group, which the operator needs to know about so
/// they can re-run destroy to converge.
#[derive(Debug)]
pub(crate) enum CreateError {
    /// CreateShareGroup failed before CreateTenantUser ran. No rollback —
    /// the group was never created. The user is untouched.
    Group(AccountError),
    /// CreateTenantUser failed; the rollback DeleteShareGroup succeeded.
    /// Host is back to its pre-create state.
    User(AccountError),
    /// CreateTenantUser failed AND the rollback DeleteShareGroup also
    /// failed. The host now has an orphan `<name>-tenant-share` group
    /// with no corresponding user. The dispatcher emits two stderr
    /// lines, the second pointing the operator at `tenant destroy` for
    /// convergence (cycle 5's OrphanGroup arm).
    UserWithRollback {
        user: AccountError,
        rollback: AccountError,
    },
    /// CreateShareGroup + CreateTenantUser both succeeded; the
    /// profile-write failed (disk full, permission denied, etc.). Locked
    /// policy: leave the user + group present. The operator's recovery
    /// is `tenant destroy <name>` — the Destroyable arm cleans up the
    /// user + group, and the profile-rm step is a noop when the profile
    /// is absent.
    Profile(ProfileError),
}

/// Granular error type for the destroy writers (both `destroy_tenant`
/// and `destroy_orphan_group`). Distinguishes account-domain failures
/// (sysadminctl-deleteUser, dscl-cleanup, dseditgroup-delete) from
/// profile-domain failures (profile-rm) so the dispatcher can render
/// each with operator-appropriate framing. The `From<AccountError>`
/// impl lets the writers keep `?` propagation on their `execute_account`
/// calls.
#[derive(Debug)]
pub(crate) enum DestroyError {
    Account(AccountError),
    Profile(ProfileError),
}

impl From<AccountError> for DestroyError {
    fn from(e: AccountError) -> Self {
        DestroyError::Account(e)
    }
}

/// Side-effecting half of the accounts API. Verbs ask in domain terms
/// via `AccountOp` and `ProfileOp` values handed to the substrate; the
/// substrate (production: `MacosExecutor`) owns argv construction and
/// the actual subprocess invocation; this writer composes ops into
/// verb-level flows and emits intent + (verbose) mechanism via the
/// Reporter handed in. Mode (real vs dry-run) is not the Writer's
/// concern — each method always renders the same bracketed
/// `would_<action>` / `<action>ing` / `<action>ed` Messages and always
/// invokes the substrate. The Reporter filters each Message down to
/// the right mode/verbosity; the substrate's `DryRunExecutor` impl is
/// a no-op in dry-run.
pub(crate) struct Writer<'a> {
    executor: &'a dyn executor::Executor,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(executor: &'a dyn executor::Executor) -> Self {
        Self { executor }
    }

    pub(crate) fn create_tenant(
        &self,
        name: &str,
        uid: u32,
        gid: u32,
        reporter: &mut Reporter,
    ) -> Result<(), CreateError> {
        // Four-step composition: CreateShareGroup → CreateTenantUser → (on
        // failure) DeleteShareGroup rollback → (on success)
        // ProfileOp::Create. The share-group must exist before
        // CreateTenantUser so the new user's home directory chowns to the
        // tenant-share group rather than staff. The rollback step is
        // shown in the plan unconditionally (the operator sees the
        // algorithm) but echoes only when it fires.
        let create_group = AccountOp::CreateShareGroup {
            name: name.into(),
            gid,
        };
        let add_user = AccountOp::CreateTenantUser {
            name: name.into(),
            uid,
            gid,
        };
        let rollback_group = AccountOp::DeleteShareGroup { name: name.into() };
        let create_profile = ProfileOp::Create { name: name.into() };

        let plan_group_line = self.executor.describe_account(&create_group);
        let plan_user_line = self.executor.describe_account(&add_user);
        let plan_rollback_line = self.executor.describe_account(&rollback_group);
        let plan_profile_line = self.executor.describe_profile(&create_profile);

        let plan = [
            PlanStep::plain(&plan_group_line),
            PlanStep::plain(&plan_user_line),
            PlanStep::annotated(&plan_rollback_line, "on rollback"),
            PlanStep::plain(&plan_profile_line),
        ];

        reporter.emit_dry_only(messages::would_create_tenant(name, &plan));
        reporter.emit_real_only(messages::creating_tenant(name, &plan));

        reporter.emit_real_only(messages::running(&plan_group_line));
        self.executor
            .execute_account(&create_group)
            .map_err(CreateError::Group)?;

        reporter.emit_real_only(messages::running(&plan_user_line));
        match self.executor.execute_account(&add_user) {
            Ok(()) => {
                // Profile-write is the 4th step. Echo goes through the
                // unified `running` factory against the substrate's
                // describe output — no special-case echo factory needed.
                // A profile-write failure doesn't roll back the user or
                // group; recovery is `tenant destroy <name>`.
                reporter.emit_real_only(messages::running(&plan_profile_line));
                self.executor
                    .execute_profile(&create_profile)
                    .map_err(CreateError::Profile)?;
                reporter.emit_real_only(messages::created_tenant(name, uid, gid));
                Ok(())
            }
            Err(user_err) => {
                // CreateTenantUser failed after the group was created.
                // Roll back by deleting the just-created group so the host
                // returns to its pre-create state. The `$` echo for the
                // rollback fires here regardless of whether the rollback
                // itself succeeds — the operator should see what we tried.
                reporter.emit_real_only(messages::running(&plan_rollback_line));
                match self.executor.execute_account(&rollback_group) {
                    Ok(()) => Err(CreateError::User(user_err)),
                    Err(rollback_err) => Err(CreateError::UserWithRollback {
                        user: user_err,
                        rollback: rollback_err,
                    }),
                }
            }
        }
    }

    pub(crate) fn destroy_tenant(
        &self,
        name: &str,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        // Five-step composition:
        //   1. DeleteTenantUser   — the canonical destroy (sysadminctl)
        //   2. LookupUserRecord   — residue probe; success means the DS
        //      record is still present (gates the conditional cleanup)
        //   3. DeleteUserRecord   — belt-and-braces low-level cleanup;
        //      conditional on the probe finding residue
        //   4. DeleteShareGroup   — the Phase-3 group cleanup
        //   5. ProfileOp::Delete  — cycle 1's profile cleanup
        // The probe's exit code drives the conditional. Plan shows all
        // five steps; echo block shows what actually ran (the conditional
        // cleanup line is absent when the probe found clean).
        let delete_user = AccountOp::DeleteTenantUser { name: name.into() };
        let probe = AccountOp::LookupUserRecord { name: name.into() };
        let cleanup = AccountOp::DeleteUserRecord { name: name.into() };
        let delete_group = AccountOp::DeleteShareGroup { name: name.into() };
        let delete_profile = ProfileOp::Delete { name: name.into() };

        let plan_delete_user_line = self.executor.describe_account(&delete_user);
        let plan_probe_line = self.executor.describe_account(&probe);
        let plan_cleanup_line = self.executor.describe_account(&cleanup);
        let plan_delete_group_line = self.executor.describe_account(&delete_group);
        let plan_delete_profile_line = self.executor.describe_profile(&delete_profile);

        let plan = [
            PlanStep::plain(&plan_delete_user_line),
            PlanStep::plain(&plan_probe_line),
            PlanStep::plain(&plan_cleanup_line),
            PlanStep::plain(&plan_delete_group_line),
            PlanStep::plain(&plan_delete_profile_line),
        ];

        reporter.emit_dry_only(messages::would_destroy_tenant(name, &plan));
        reporter.emit_real_only(messages::destroying_tenant(name, &plan));

        reporter.emit_real_only(messages::running(&plan_delete_user_line));
        self.executor.execute_account(&delete_user)?;

        reporter.emit_real_only(messages::running(&plan_probe_line));
        match self.executor.execute_account(&probe) {
            Ok(()) => {
                // Probe succeeded → DS record still present → run cleanup.
                reporter.emit_real_only(messages::running(&plan_cleanup_line));
                self.executor.execute_account(&cleanup)?;
            }
            Err(AccountError::NonZero { .. }) => {
                // Probe returned non-zero (typically eDSRecordNotFound)
                // → DS is clean → no cleanup needed. The cleanup `$`
                // line stays absent so the operator can see what actually
                // ran vs the plan above.
            }
            Err(other) => return Err(DestroyError::Account(other)),
        }

        reporter.emit_real_only(messages::running(&plan_delete_group_line));
        self.executor.execute_account(&delete_group)?;

        reporter.emit_real_only(messages::running(&plan_delete_profile_line));
        self.executor
            .execute_profile(&delete_profile)
            .map_err(DestroyError::Profile)?;

        reporter.emit_real_only(messages::destroyed_tenant(name));
        Ok(())
    }

    /// Convergence path: the tenant user is already absent (so none of
    /// the user-side teardown applies), but the suffixed
    /// `<name>-tenant-share` group is still on the host. Issues two
    /// substrate calls (DeleteShareGroup + ProfileOp::Delete) bracketed
    /// by the would/destroying/destroyed orphan-group Message trio. The
    /// profile step is always attempted (idempotent Delete) so the "host
    /// has no trace of <name> after destroy" contract holds even on the
    /// convergence path.
    pub(crate) fn destroy_orphan_group(
        &self,
        name: &str,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        let delete_group = AccountOp::DeleteShareGroup { name: name.into() };
        let delete_profile = ProfileOp::Delete { name: name.into() };

        let plan_delete_group_line = self.executor.describe_account(&delete_group);
        let plan_delete_profile_line = self.executor.describe_profile(&delete_profile);

        let plan = [
            PlanStep::plain(&plan_delete_group_line),
            PlanStep::plain(&plan_delete_profile_line),
        ];

        reporter.emit_dry_only(messages::would_destroy_orphan_group(name, &plan));
        reporter.emit_real_only(messages::destroying_orphan_group(name, &plan));

        reporter.emit_real_only(messages::running(&plan_delete_group_line));
        self.executor.execute_account(&delete_group)?;

        reporter.emit_real_only(messages::running(&plan_delete_profile_line));
        self.executor
            .execute_profile(&delete_profile)
            .map_err(DestroyError::Profile)?;

        reporter.emit_real_only(messages::destroyed_orphan_group(name));
        Ok(())
    }

    /// Interactive shell entry into the tenant. The LoginAsUser op is
    /// built only to feed `describe_account` for the plan/echo lines —
    /// execution goes through the substrate's `login` method because the
    /// return type (child exit code) and stdio semantics (inherit, don't
    /// capture) are incompatible with the non-interactive
    /// `execute_account` path. Pre-exec emits the would/shelling pair
    /// through the Reporter; no post-exec confirmation — the operator IS
    /// the shell, so a "Shelled into …" line after they exit would be
    /// at best redundant and at worst land in a different terminal
    /// context.
    pub(crate) fn shell_into_tenant(
        &self,
        name: &str,
        reporter: &mut Reporter,
    ) -> Result<i32, AccountError> {
        let login = AccountOp::LoginAsUser { name: name.into() };
        let line = self.executor.describe_account(&login);

        reporter.emit_dry_only(messages::would_shell_into_tenant(name, &line));
        reporter.emit_real_only(messages::shelling_into_tenant(name, &line));

        reporter.emit_real_only(messages::running(&line));
        self.executor.login(name)
    }
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
    // Reserved-name check runs after the lexical guards so a name like
    // `Wheel` (capital W) still trips the more-specific `InvalidStart`
    // feedback rather than the blunter `Reserved` one. Exact match
    // intentionally — `rooty` is fine, only bare `root` is refused.
    if RESERVED_NAMES.contains(&name) {
        return Err(NameError::Reserved);
    }
    Ok(())
}
