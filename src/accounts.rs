use std::collections::{HashMap, HashSet};
use std::io;
use std::process::Command;

use crate::allocation::TENANT_UID_FLOOR;
use crate::executor::{ExecError, Executor};
use crate::messages;
use crate::profile::{ProfileError, ProfileStore, default_profile_toml};
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

/// Side-effecting half of the accounts API. Verbs ask in domain terms;
/// the impl owns argv construction and self-emits intent + (verbose)
/// mechanism via the Reporter handed in. Mode (real vs dry-run) is not
/// the Writer's concern — each method always renders the same three
/// bracketed Messages (`would_<action>` / `<action>ing` / `<action>ed`)
/// and always invokes the executor. The Reporter filters each Message
/// down to the right mode/verbosity; the Executor is a no-op in dry-run.
pub(crate) trait Writer {
    fn create_tenant(
        &self,
        name: &str,
        uid: u32,
        gid: u32,
        reporter: &mut Reporter,
    ) -> Result<(), CreateError>;

    fn destroy_tenant(&self, name: &str, reporter: &mut Reporter) -> Result<(), DestroyError>;

    /// Cycle-5 convergence path: the tenant user is already absent (so
    /// none of the user-side teardown applies), but the suffixed
    /// `<name>-tenant-share` group is still on the host. Issues exactly
    /// one exec call — `sudo dseditgroup -o delete -n .
    /// <name>-tenant-share` — bracketed by its own three-message
    /// `would_destroy_orphan_group` / `destroying_orphan_group` /
    /// `destroyed_orphan_group` trio, mirroring the discipline of the
    /// full destroy path. Sub-cycle 1.8 will extend this arm to also
    /// remove a residual profile (the convergence contract is "host has
    /// no trace of `<name>`"), which is why the return type is
    /// `DestroyError` not `ExecError`.
    fn destroy_orphan_group(&self, name: &str, reporter: &mut Reporter)
    -> Result<(), DestroyError>;

    /// Interactive shell entry into the tenant. Hands `["sudo", "-iu",
    /// <name>]` to the executor's `exec_into` substitution point (inherits
    /// stdin/stdout/stderr so sudo can prompt and the login shell can drive
    /// the controlling terminal). Returns the child's exit code on clean
    /// shell exit; bubbles `ExecError` only for spawn failures (sudo not
    /// found, etc.). Pre-exec emits the would/shelling pair through the
    /// Reporter; no post-exec confirmation — the operator IS the shell,
    /// so a "Shelled into …" line after they exit would be at best
    /// redundant and at worst land in a different terminal context.
    fn shell_into_tenant(&self, name: &str, reporter: &mut Reporter) -> Result<i32, ExecError>;
}

/// Granular error type for the create writer. Phase 3 splits the create
/// flow into two exec calls (dseditgroup-create + sysadminctl-addUser),
/// each of which can fail. The dispatcher needs to know which one failed
/// so it can render the right error message: `create_group_failed` if
/// dseditgroup tripped (the user wasn't touched), `create_failed` if
/// sysadminctl tripped (the writer ran a rollback). The third variant
/// covers the worst case where the rollback itself failed — the host
/// is left with an orphan group, which the operator needs to know about
/// so they can re-run destroy to converge.
#[derive(Debug)]
pub(crate) enum CreateError {
    /// dseditgroup-create failed before sysadminctl ran. No rollback —
    /// the group was never created. The user is untouched.
    Group(ExecError),
    /// sysadminctl-addUser failed; the rollback dseditgroup-delete
    /// succeeded. Host is back to its pre-create state.
    User(ExecError),
    /// sysadminctl-addUser failed AND the rollback dseditgroup-delete
    /// also failed. The host now has an orphan `<name>-tenant-share`
    /// group with no corresponding user. The dispatcher emits two stderr
    /// lines, the second pointing the operator at `tenant destroy` for
    /// convergence (cycle 5's OrphanGroup arm).
    UserWithRollback {
        user: ExecError,
        rollback: ExecError,
    },
    /// dseditgroup-create + sysadminctl-addUser both succeeded; the
    /// profile-write failed (disk full, permission denied, etc.).
    /// Locked policy: leave the user + group present. The operator's
    /// recovery is `tenant destroy <name>` — the Destroyable arm cleans
    /// up the user + group, and the profile-rm step is a noop when the
    /// profile is absent. No rollback variants needed because
    /// `std::fs::write` failures are rare and the convergence story is
    /// already covered.
    Profile(ProfileError),
}

/// Granular error type for the destroy writers (both `destroy_tenant`
/// and `destroy_orphan_group`). Cycle 1 introduces this when destroy
/// gains its 5th step (profile-rm) and the dispatcher needs to render a
/// distinct error message for profile-rm failure (operator sees the
/// path, not a generic `process exited with code N` frame). The
/// `From<ExecError>` impl lets the writers keep `?` propagation on
/// their existing executor.run calls.
#[derive(Debug)]
pub(crate) enum DestroyError {
    Exec(ExecError),
    Profile(ProfileError),
}

impl From<ExecError> for DestroyError {
    fn from(e: ExecError) -> Self {
        DestroyError::Exec(e)
    }
}

pub(crate) struct MacosWriter<'a> {
    executor: &'a dyn Executor,
    profiles: &'a dyn ProfileStore,
}

impl<'a> MacosWriter<'a> {
    pub(crate) fn new(executor: &'a dyn Executor, profiles: &'a dyn ProfileStore) -> Self {
        Self { executor, profiles }
    }
}

impl<'a> Writer for MacosWriter<'a> {
    fn create_tenant(
        &self,
        name: &str,
        uid: u32,
        gid: u32,
        reporter: &mut Reporter,
    ) -> Result<(), CreateError> {
        // Two exec calls compose create — group-first, then user:
        //   1. sudo dseditgroup -o create -n . -i <gid> <name>-tenant-share
        //   2. sudo sysadminctl -addUser <name> ... -GID <gid>
        // The group MUST exist before sysadminctl runs so the user's
        // home directory ownership lands on the tenant-share group, not
        // staff (sysadminctl chowns the home dir to the group named by
        // -GID at creation time).
        // The 3rd "rollback" line in the plan is the success-path
        // counterpart: if sysadminctl fails, cycle 3's rollback path
        // runs `sudo dseditgroup -o delete -n . <name>-tenant-share`.
        // It's shown in the pre-exec plan regardless of outcome (the
        // operator sees the algorithm) but only echoes in the `$` block
        // when it actually fires.
        let group_argv = build_dseditgroup_create_argv(name, gid);
        let user_argv = build_create_argv(name, uid, gid);
        let rollback_argv = build_dseditgroup_delete_argv(name);

        reporter.emit_dry_only(messages::would_create_tenant(
            name,
            &group_argv,
            &user_argv,
            &rollback_argv,
        ));
        reporter.emit_real_only(messages::creating_tenant(
            name,
            &group_argv,
            &user_argv,
            &rollback_argv,
        ));

        reporter.emit_real_only(messages::running_argv(&group_argv));
        self.executor.run(&group_argv).map_err(CreateError::Group)?;

        reporter.emit_real_only(messages::running_argv(&user_argv));
        match self.executor.run(&user_argv) {
            Ok(()) => {
                // Profile-write is the 4th step. Echo line uses the
                // pretend-shell `tee <path> < default.toml` framing
                // (see `running_profile_write`). A profile-write failure
                // doesn't roll back the user or group — operator
                // recovers via `tenant destroy <name>` (Destroyable arm
                // handles a missing-profile case as a noop on the rm
                // step).
                reporter.emit_real_only(messages::running_profile_write(name));
                write_default_profile(self.profiles, name).map_err(CreateError::Profile)?;
                reporter.emit_real_only(messages::created_tenant(name, uid, gid));
                Ok(())
            }
            Err(user_err) => {
                // Sysadminctl-addUser failed after the group was created.
                // Roll back by deleting the just-created group so the host
                // returns to its pre-create state. The `$` echo for the
                // rollback fires here regardless of whether the rollback
                // itself succeeds — the operator should see what we tried.
                reporter.emit_real_only(messages::running_argv(&rollback_argv));
                match self.executor.run(&rollback_argv) {
                    Ok(()) => Err(CreateError::User(user_err)),
                    Err(rollback_err) => Err(CreateError::UserWithRollback {
                        user: user_err,
                        rollback: rollback_err,
                    }),
                }
            }
        }
    }

    fn destroy_tenant(&self, name: &str, reporter: &mut Reporter) -> Result<(), DestroyError> {
        // Four commands compose the destroy mechanism:
        //   1. sysadminctl -deleteUser           — the canonical destroy
        //   2. dscl . -read /Users/<name>        — residue probe (no sudo;
        //      reads on the local node don't require it)
        //   3. sudo dscl . -delete /Users/<name> — belt-and-braces user
        //      cleanup, conditional on the probe finding the DS record
        //      still present. sysadminctl can leave a stale DS record in
        //      some failure shapes (caught the hard way by the sandbox
        //      plugin that originally inspired this CLI); the
        //      probe-and-cleanup makes destroy convergent toward absence.
        //   4. sudo dseditgroup -o delete -n . <name>-tenant-share — the
        //      Phase-3 group cleanup. The V1.8 sysadminctl-cascade only
        //      caught implicit `<name>` groups; the renamed
        //      `<name>-tenant-share` group doesn't inherit that cleanup,
        //      so this step is load-bearing — without it the host would
        //      carry an orphan group after every destroy.
        //   5. rm -f ~/.config/tenant/profiles/<name>.toml — cycle 1's
        //      profile cleanup. Synthetic argv (the actual call goes
        //      through ProfileStore, not a real `rm`) so the plan
        //      renderer can format it uniformly with the shell-out lines.
        //      `rm -f` reflects the idempotent semantics: NotFound is
        //      success, mirroring `XdgProfileStore::remove`.
        let sysadminctl_delete = build_destroy_sysadminctl_argv(name);
        let dscl_probe = build_dscl_read_user_argv(name);
        let dscl_cleanup = build_dscl_delete_user_argv(name);
        let group_delete = build_dseditgroup_delete_argv(name);
        let profile_remove = build_profile_remove_synthetic_argv(name);
        let plan: [&[String]; 5] = [
            &sysadminctl_delete,
            &dscl_probe,
            &dscl_cleanup,
            &group_delete,
            &profile_remove,
        ];

        // Pre-exec: dry-run shows the full plan; real-verbose shows the
        // intent + plan. Both render the dscl-cleanup unconditionally —
        // pre-exec can't know what the probe will return at runtime, so
        // the operator sees the algorithm. The dseditgroup-delete is
        // also always shown; it's unconditional at runtime too.
        reporter.emit_dry_only(messages::would_destroy_tenant(name, &plan));
        reporter.emit_real_only(messages::destroying_tenant(name, &plan));

        // Per-exec echo + run pairs. `running_argv` Messages have only
        // `summary_verbose` populated, so they render only in real+verbose;
        // `emit_real_only` filters them out in dry-run.
        reporter.emit_real_only(messages::running_argv(&sysadminctl_delete));
        self.executor.run(&sysadminctl_delete)?;

        reporter.emit_real_only(messages::running_argv(&dscl_probe));
        match self.executor.run(&dscl_probe) {
            Ok(()) => {
                // Probe succeeded → DS record still present → run cleanup.
                reporter.emit_real_only(messages::running_argv(&dscl_cleanup));
                self.executor.run(&dscl_cleanup)?;
            }
            Err(ExecError::NonZero { .. }) => {
                // Probe returned non-zero (typically eDSRecordNotFound
                // from dscl when the user is absent) → DS is clean → no
                // cleanup needed. The cleanup `$` line stays absent so the
                // operator can see what actually ran vs the plan above.
            }
            Err(other) => return Err(DestroyError::Exec(other)),
        }

        reporter.emit_real_only(messages::running_argv(&group_delete));
        self.executor.run(&group_delete)?;

        // 5th step: profile-rm. Idempotent (NotFound is Ok in both
        // `XdgProfileStore` and `StubProfileStore`). A profile-rm
        // failure is surfaced via the new `DestroyError::Profile`
        // variant; the dispatcher renders it with `destroy_profile_failed`
        // so the operator sees the specific path that failed instead of
        // a generic exec-error frame.
        reporter.emit_real_only(messages::running_profile_remove(name));
        self.profiles.remove(name).map_err(DestroyError::Profile)?;

        reporter.emit_real_only(messages::destroyed_tenant(name));
        Ok(())
    }

    fn shell_into_tenant(&self, name: &str, reporter: &mut Reporter) -> Result<i32, ExecError> {
        // Single-argv exec_into path. v1 uses `sudo -iu <name>` and lets
        // sudo prompt for the host password on a cold timestamp; the next
        // cycle will add a sudoers entry so this becomes `sudo -n -iu`
        // and never prompts. Same Reporter discipline as the other writer
        // methods: dry-only/real-only pre-exec messages, real-only `$`
        // echo, no post-exec line (the operator IS the shell now).
        let argv = build_shell_argv(name);

        reporter.emit_dry_only(messages::would_shell_into_tenant(name, &argv));
        reporter.emit_real_only(messages::shelling_into_tenant(name, &argv));

        reporter.emit_real_only(messages::running_argv(&argv));
        self.executor.exec_into(&argv)
    }

    fn destroy_orphan_group(
        &self,
        name: &str,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        // Two-step convergence path (cycle 1.8 added profile-rm). Same
        // Reporter discipline as the full destroy: dry-only / real-only
        // pre-exec messages, real-only `$` echo per step, real-only
        // post-exec confirmation. The profile step is always attempted
        // (idempotent rm) so the "host has no trace of <name> after
        // destroy" contract holds even on the convergence path.
        let group_delete = build_dseditgroup_delete_argv(name);
        let profile_remove = build_profile_remove_synthetic_argv(name);
        let plan: [&[String]; 2] = [&group_delete, &profile_remove];

        reporter.emit_dry_only(messages::would_destroy_orphan_group(name, &plan));
        reporter.emit_real_only(messages::destroying_orphan_group(name, &plan));

        reporter.emit_real_only(messages::running_argv(&group_delete));
        self.executor.run(&group_delete)?;

        reporter.emit_real_only(messages::running_profile_remove(name));
        self.profiles.remove(name).map_err(DestroyError::Profile)?;

        reporter.emit_real_only(messages::destroyed_orphan_group(name));
        Ok(())
    }
}

/// Write the default profile for `name` into the store. Shared by
/// `create_tenant` (the only caller in cycle 1). Centralizing it keeps
/// the default-content source (`profile::default_profile_toml`) one
/// grep away from any future caller and lets cycle 1.5's
/// `CreateError::Profile` wiring change just the error-surfacing site,
/// not the call site.
fn write_default_profile(profiles: &dyn ProfileStore, name: &str) -> Result<(), ProfileError> {
    profiles.write(name, &default_profile_toml())
}

/// Phase-shell command shape: `sudo -iu <name>`. `-i` makes sudo run a
/// login shell (full env reset, sources the tenant's shell rc files); `-u`
/// selects the target user. Minimal on purpose — `-n` (non-interactive,
/// "fail if a prompt is needed") is deferred to the sudoers-entry cycle
/// when we can guarantee the timestamp-cache state.
fn build_shell_argv(name: &str) -> Vec<String> {
    vec!["sudo".into(), "-iu".into(), name.into()]
}

fn build_create_argv(name: &str, uid: u32, gid: u32) -> Vec<String> {
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
        gid.to_string(),
    ]
}

/// Phase 3's group-create command. Uses `dseditgroup` (not `dscl . -create`)
/// because dseditgroup is the higher-level, OD-aware tool — it sets up the
/// metadata fields sysadminctl expects to find when wiring the primary
/// group. `-n .` targets the local node (matches sysadminctl's default
/// node selection). `-i <gid>` is the load-bearing argument: sysadminctl
/// will be invoked next with `-GID <gid>` pointing at this just-created
/// group, so the GID number must match.
fn build_dseditgroup_create_argv(name: &str, gid: u32) -> Vec<String> {
    vec![
        "sudo".into(),
        "dseditgroup".into(),
        "-o".into(),
        "create".into(),
        "-n".into(),
        ".".into(),
        "-i".into(),
        gid.to_string(),
        tenant_share_group_name(name),
    ]
}

/// Phase 3's group-delete command, used both as the rollback step in
/// `create_tenant` (when sysadminctl-addUser fails after the group was
/// created) and as the unconditional last step in `destroy_tenant` (the
/// sysadminctl-cascade only catches groups named after the user, so a
/// renamed primary group must be deleted explicitly to avoid orphan
/// state).
fn build_dseditgroup_delete_argv(name: &str) -> Vec<String> {
    vec![
        "sudo".into(),
        "dseditgroup".into(),
        "-o".into(),
        "delete".into(),
        "-n".into(),
        ".".into(),
        tenant_share_group_name(name),
    ]
}

fn build_destroy_sysadminctl_argv(name: &str) -> Vec<String> {
    vec![
        "sudo".into(),
        "sysadminctl".into(),
        "-deleteUser".into(),
        name.into(),
    ]
}

/// Residue probe: `dscl . -read /Users/<name>` exits 0 when the DS record
/// exists and non-zero (typically eDSRecordNotFound) when it doesn't. No
/// sudo — reads on the local node don't require it. The `destroy_tenant`
/// writer uses the exit code to decide whether the conditional cleanup
/// runs.
fn build_dscl_read_user_argv(name: &str) -> Vec<String> {
    vec![
        "dscl".into(),
        ".".into(),
        "-read".into(),
        format!("/Users/{name}"),
    ]
}

/// Synthetic argv for the destroy verb's plan rendering. The actual
/// removal goes through `ProfileStore::remove` (which the dispatcher
/// constructs from `XdgProfileStore` or `StubProfileStore`), not a
/// `rm` subprocess. Sharing the `[&[String]]` plan-rendering pipeline
/// with the real shell-out steps keeps the verbose-mode output uniform
/// — operator sees a 5-line plan with the rm framing matching the
/// `running_profile_remove` echo line shape.
fn build_profile_remove_synthetic_argv(name: &str) -> Vec<String> {
    use crate::profile::display_path_for;
    vec!["rm".into(), "-f".into(), display_path_for(name)]
}

/// Belt-and-braces cleanup: `sudo dscl . -delete /Users/<name>` removes a
/// stale DS record that sysadminctl `-deleteUser` may have left behind.
/// Only runs when `build_dscl_read_user_argv`'s probe shows the record is
/// still present. Needs sudo (writes to the local node).
fn build_dscl_delete_user_argv(name: &str) -> Vec<String> {
    vec![
        "sudo".into(),
        "dscl".into(),
        ".".into(),
        "-delete".into(),
        format!("/Users/{name}"),
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
    // Reserved-name check runs after the lexical guards so a name like
    // `Wheel` (capital W) still trips the more-specific `InvalidStart`
    // feedback rather than the blunter `Reserved` one. Exact match
    // intentionally — `rooty` is fine, only bare `root` is refused.
    if RESERVED_NAMES.contains(&name) {
        return Err(NameError::Reserved);
    }
    Ok(())
}
