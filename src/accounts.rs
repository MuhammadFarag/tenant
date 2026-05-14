use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use crate::ModeLevel;
use crate::allocation::TENANT_UID_FLOOR;
use crate::doctor::{
    Finding, SymlinkActual, anchor_body_matches, curated_paths, has_env_delete_for,
    has_group_acl_entry, has_pam_tid, pf_status_enabled,
};
use crate::executor::{
    self, AccountError, AccountOp, AclError, AclMode, AclOp, FirewallError, FirewallOp,
    HostFileError, Op, PathKind, ProbeError, ProfileOp, WritableOp,
};
use crate::firewall::{ensure_anchor_ref, remove_anchor_ref, render_anchor};
use crate::profile::{
    Profile, ProfileError, ShareMode, display_path_for, expand_tenant_path, parse,
};
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
    /// All account names with a tenant-range UID (>= `TENANT_UID_FLOOR`).
    /// Order is alphabetical for stable downstream behavior — doctor's
    /// all-tenants walk iterates this list and emits findings in the
    /// same order across runs, so an operator's diff between two
    /// `tenant doctor` invocations stays meaningful. System accounts
    /// and below-floor accounts are excluded.
    fn tenant_names(&self) -> Vec<String>;
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

    fn tenant_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .uid_by_name
            .iter()
            .filter(|(_, uid)| **uid >= TENANT_UID_FLOOR)
            .map(|(name, _)| name.clone())
            .collect();
        out.sort();
        out
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
/// just enough information for the matching `Reporter::refuse_invalid_name`
/// arm to render an operator-friendly explanation.
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

    fn tenant_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .uid_by_name
            .iter()
            .filter(|(_, uid)| **uid >= TENANT_UID_FLOOR)
            .map(|(name, _)| name.clone())
            .collect();
        out.sort();
        out
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
    /// CreateShareGroup + CreateTenantUser + ProfileOp::Create all
    /// succeeded; a firewall step failed. Same locked recovery policy
    /// as `Profile`: the user + group + profile stay present, operator
    /// recovers via `tenant destroy <name>` (the Destroyable arm
    /// converges all of them, including any partially-installed PF
    /// anchor — the destroy-side firewall teardown is idempotent).
    /// Read/parse failures on the just-written profile also flow here
    /// as `FirewallError::Fs` (path = the profile path) because the
    /// failure surfaces during the firewall composition step.
    Firewall(FirewallError),

    /// Cycle 10: post-provision share-reapply step failed. The host
    /// has user + group + profile + PF anchor + enable all installed
    /// but the per-share substrate (Acl / Account / Probe / Share)
    /// tripped. Operator's recovery: `tenant reload <name>` (idempotent
    /// retry) or `tenant destroy <name>` + retry create. Default profile
    /// has no shares so this arm is unreachable on the production path
    /// today; tests using `with_create_profile_content` to pre-populate
    /// a profile with shares exercise it.
    PostProvision(ModeError),
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
    /// A firewall teardown step failed (BackupConfig / RemoveAnchor /
    /// UpdateConfig / Reload). Unlike create, destroy has no recovery
    /// path on reload failure — the symmetric "restore from backup"
    /// would re-introduce a reference to the already-removed anchor
    /// file, putting the host in a worse state. Operator gets the
    /// failure framed with `destroy_firewall_failed` so they know
    /// which step tripped.
    Firewall(FirewallError),
}

impl From<AccountError> for DestroyError {
    fn from(e: AccountError) -> Self {
        DestroyError::Account(e)
    }
}

/// Pre-flight refusals from the share-reapply substrate (cycle 10).
/// Operator-actionable cases that should be loud before the substrate
/// runs (Q11 / Q12 locks). Each variant carries the path so the
/// operator can locate the conflict directly.
#[derive(Debug)]
pub(crate) enum ShareError {
    /// Q11 lock: profile declared a `host_path` that doesn't exist on
    /// disk at reapply time. Refuse loudly — the profile is a
    /// declaration of what the operator wants; missing host_path is a
    /// profile-authoring mistake.
    HostPathMissing { path: PathBuf },

    /// Q12 lock: profile declared a `tenant_path` that exists as a
    /// real directory or file (NOT a symlink). Substrate `ln -sfn`
    /// would silently fail to replace a real-dir tenant_path; we
    /// pre-check and refuse so the operator chooses between editing
    /// the profile or removing the conflict.
    TenantPathOccupied { path: PathBuf },
}

impl fmt::Display for ShareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShareError::HostPathMissing { path } => write!(
                f,
                "host_path {} does not exist on disk; edit the profile or create the path",
                path.display(),
            ),
            ShareError::TenantPathOccupied { path } => write!(
                f,
                "tenant_path {} exists as a real directory or file; \
                 remove it or edit the profile to point elsewhere",
                path.display(),
            ),
        }
    }
}

/// Failure surface for the `mode` verb and (by reuse) the `shell`
/// auto-narrow + the `reload` verb + create-side post-provision step.
/// Read/parse failures on the tenant's profile surface as `Profile`;
/// anchor-write or pfctl-reload failures surface as `Firewall`. Cycle
/// 10 adds four arms for the share-reapply substrate:
/// - `Acl`: chmod +a/-a substrate failure on the host side
/// - `Account`: sudo-u mkdir/ln substrate failure on the tenant side
/// - `Probe`: tenant_path_kind machinery failure (sudo-cache, fork)
/// - `Share`: pre-flight refusal (host_path missing or tenant_path
///   occupied)
///
/// No automatic recovery on Reload failure. The host state after a
/// Reload failure is "anchor file written with the new body, kernel
/// rules still on the old body"; the verb is idempotent, so rerunning
/// `tenant mode <name> <level>` resolves the divergence. The
/// alternative (back-up the anchor and restore on failure) would
/// mirror the create-side recovery but with a different fragility:
/// the anchor-backup file is itself an artifact the operator might
/// not expect.
#[derive(Debug)]
pub(crate) enum ModeError {
    Profile(ProfileError),
    Firewall(FirewallError),
    Acl(AclError),
    Account(AccountError),
    Probe(ProbeError),
    Share(ShareError),
}

/// Failure surface for the `shell` verb. The login spawn itself can
/// fail with `Account`; the cycle-4 narrow-on-shell-entry can fail
/// with `Mode` (read/parse the profile, or InstallAnchor / Reload).
/// Abort-on-narrow-failure (cycle-4 Q2 lock) — the shell is NOT
/// launched if the narrow can't complete, because doing so would
/// leave the operator inside a session that might still be at the
/// previous (potentially install-tier-widened) firewall posture.
/// Operator recovery is `tenant mode <name> runtime` to narrow
/// manually, then retry `tenant shell <name>`.
#[derive(Debug)]
pub(crate) enum ShellError {
    Account(AccountError),
    Mode(ModeError),
}

/// Pre-built op list for a profile-to-tenant reapply. Construction
/// (`Writer::build_reapply_plan`) parses the profile + pre-flights
/// shares; execution (`Writer::execute_reapply_plan`) fires the ops
/// against the substrate. Separating the two lets the verb methods
/// render the upfront plan over the same ops the substrate will run,
/// preserving the plan-vs-echo asymmetry contract for share ops.
pub(crate) struct ReapplyPlan {
    pub(crate) install_anchor: FirewallOp,
    pub(crate) reload: FirewallOp,
    pub(crate) share_ops: Vec<ShareOps>,
}

impl ReapplyPlan {
    /// Flatten the plan into a borrowed `Op` slice for the Reporter's
    /// plan-rendering helper. The slice borrows from `self` so the
    /// caller must keep the plan alive until the reporter has emitted
    /// its plan block.
    pub(crate) fn as_plan_entries(&self) -> Vec<(Op<'_>, Option<&'static str>)> {
        let mut entries: Vec<(Op<'_>, Option<&'static str>)> =
            Vec::with_capacity(2 + self.share_ops.iter().map(|s| s.op_count()).sum::<usize>());
        entries.push((Op::Firewall(&self.install_anchor), None));
        entries.push((Op::Firewall(&self.reload), None));
        for share in &self.share_ops {
            entries.push((Op::Acl(&share.grant), None));
            if let Some(ensure_dir) = &share.ensure_dir {
                entries.push((Op::Account(ensure_dir), None));
            }
            entries.push((Op::Account(&share.ensure_link), None));
        }
        entries
    }
}

/// One per-share entry's op triple. `ensure_dir` is `None` when the
/// tenant_path's parent is the tenant's home dir itself (always
/// exists; mkdir would be a no-op).
pub(crate) struct ShareOps {
    pub(crate) grant: AclOp,
    pub(crate) ensure_dir: Option<AccountOp>,
    pub(crate) ensure_link: AccountOp,
}

impl ShareOps {
    fn op_count(&self) -> usize {
        2 + if self.ensure_dir.is_some() { 1 } else { 0 }
    }
}

/// Outcome of `Writer::reload_all_tenants`. Carries the per-tenant
/// failure count; the dispatcher maps `failed > 0 → EX_IOERR (74)`,
/// `failed == 0 → 0` (Q15 lock). Tenant count and success count are
/// implicit (the count comes from `Reader::tenant_names().len()`;
/// success = total - failed).
#[derive(Debug)]
pub(crate) struct ReloadAllOutcome {
    pub(crate) failed: u32,
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
        // Twelve-step composition. Account + profile (cycle 1):
        //   1. CreateShareGroup
        //   2. CreateTenantUser
        //   3. DeleteShareGroup  # on rollback (if step 2 fails)
        //   4. ProfileOp::Create
        // Firewall normal flow:
        //   5. BackupConfig
        //   6. InstallAnchor
        //   7. UpdateConfig
        //   8. Reload
        //   9. RestoreConfigFromBackup  # on reload failure
        //   10. RemoveAnchor             # on reload failure
        //   11. Reload                   # on reload failure
        //   12. Enable
        // The recovery sequence (9-11) runs only if step 8 fails;
        // create aborts with `CreateError::Firewall` regardless of
        // whether the recovery itself succeeds. Recovery-of-recovery
        // (restore fails) surfaces as `FirewallError::RestoreFailed`
        // with the backup path + manual recovery hint.
        //
        // The read_profile + parse + render_anchor + read_pf_conf +
        // ensure_anchor_ref work that produces the InstallAnchor body
        // and UpdateConfig content happens BETWEEN step 4 and step 5,
        // is implicit in the plan, and surfaces as
        // CreateError::Firewall on failure.
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
        let backup = FirewallOp::BackupConfig;
        let restore = FirewallOp::RestoreConfigFromBackup;
        let reload = FirewallOp::Reload;
        let enable = FirewallOp::Enable;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };

        // Plan-time placeholder firewall ops. The describe arms for
        // InstallAnchor and UpdateConfig don't include `body` /
        // `content` in their rendered text, so plan + echo lines come
        // out identical to the real-body ops constructed below — but
        // we can't build the real bodies yet, because that needs a
        // read of the not-yet-written profile and the host's current
        // pf.conf.
        let install_anchor_plan = FirewallOp::InstallAnchor {
            name: name.into(),
            body: String::new(),
        };
        let update_conf_plan = FirewallOp::UpdateConfig {
            content: String::new(),
        };

        reporter.create_starting(
            name,
            &[
                (Op::Account(&create_group), None),
                (Op::Account(&add_user), None),
                (Op::Account(&rollback_group), Some("on rollback")),
                (Op::Profile(&create_profile), None),
                (Op::Firewall(&backup), None),
                (Op::Firewall(&install_anchor_plan), None),
                (Op::Firewall(&update_conf_plan), None),
                (Op::Firewall(&reload), None),
                (Op::Firewall(&restore), Some("on reload failure")),
                (Op::Firewall(&remove_anchor), Some("on reload failure")),
                (Op::Firewall(&reload), Some("on reload failure")),
                (Op::Firewall(&flush_anchor), Some("on reload failure")),
                (Op::Firewall(&enable), None),
            ],
        );

        self.run(&create_group, reporter)
            .map_err(CreateError::Group)?;
        match self.run(&add_user, reporter) {
            Ok(()) => {
                self.run(&create_profile, reporter)
                    .map_err(CreateError::Profile)?;
                // Profile is now on disk. Read + parse + render the
                // anchor body, read current pf.conf + ensure the
                // anchor ref. Read/parse failures land in
                // CreateError::Firewall as FirewallError::Fs with the
                // profile path baked in — the failure surfaces during
                // the firewall step from the operator's POV.
                let profile_content = self.executor.read_profile(name).map_err(|e| {
                    CreateError::Firewall(FirewallError::Fs {
                        path: display_path_for(name),
                        message: format!("read failed: {e}"),
                    })
                })?;
                let parsed_profile = parse(&profile_content).map_err(|e| {
                    CreateError::Firewall(FirewallError::Fs {
                        path: display_path_for(name),
                        message: format!("parse failed: {e}"),
                    })
                })?;
                let pf_conf_current = self
                    .executor
                    .read_pf_conf()
                    .map_err(CreateError::Firewall)?;
                let install_anchor = FirewallOp::InstallAnchor {
                    name: name.into(),
                    body: render_anchor(name, &parsed_profile.allowlist.runtime.hosts),
                };
                let update_conf = FirewallOp::UpdateConfig {
                    content: ensure_anchor_ref(&pf_conf_current, name),
                };
                // Firewall normal flow.
                self.run(&backup, reporter).map_err(CreateError::Firewall)?;
                self.run(&install_anchor, reporter)
                    .map_err(CreateError::Firewall)?;
                self.run(&update_conf, reporter)
                    .map_err(CreateError::Firewall)?;
                if let Err(reload_err) = self.run(&reload, reporter) {
                    // Recovery: restore conf → remove anchor → reload
                    // → flush anchor (best-effort post-restore).
                    // FlushAnchor is the symmetric counter to the
                    // partial in-kernel state from the failed initial
                    // Reload — without it, even after restoring
                    // pf.conf and removing the anchor file, the
                    // partially-loaded rules would persist under the
                    // (now-orphaned) anchor name. Restore failure is
                    // the recovery-of-recovery case; surface as
                    // RestoreFailed so the Reporter message names the
                    // backup path. Otherwise propagate the original
                    // reload error.
                    if self.run(&restore, reporter).is_err() {
                        return Err(CreateError::Firewall(FirewallError::RestoreFailed {
                            path: crate::firewall::PF_CONF_BACKUP.to_string(),
                        }));
                    }
                    let _ = self.run(&remove_anchor, reporter);
                    let _ = self.run(&reload, reporter);
                    let _ = self.run(&flush_anchor, reporter);
                    return Err(CreateError::Firewall(reload_err));
                }
                self.run(&enable, reporter).map_err(CreateError::Firewall)?;
                // Cycle 10: post-provision share reapply on the
                // freshly-written profile. Default profile has no
                // `[[shares]]`, so the share substrate is a no-op on
                // the production path. Tests using
                // `with_create_profile_content` to pre-populate a
                // profile with shares exercise this path. The PF
                // reapply already ran via the create-time firewall
                // sequence (BackupConfig → InstallAnchor →
                // UpdateConfig → Reload → Enable), so we use
                // `reapply_shares_post_provision` directly rather
                // than `build_reapply_plan` + `execute_reapply_plan`
                // (which would redo InstallAnchor + Reload).
                self.reapply_shares_post_provision(name, &parsed_profile, reporter)
                    .map_err(CreateError::PostProvision)?;
                reporter.create_done(name, uid, gid);
                Ok(())
            }
            Err(user_err) => {
                // CreateTenantUser failed after the group was created.
                // Roll back by deleting the just-created group so the
                // host returns to its pre-create state. The `$` echo
                // for the rollback fires inside `self.run` regardless of
                // whether the rollback itself succeeds — the operator
                // should see what we tried.
                match self.run(&rollback_group, reporter) {
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
        // Ten-step composition:
        //   1. DeleteTenantUser   — sysadminctl
        //   2. LookupUserRecord   — residue probe
        //   3. DeleteUserRecord   — conditional dscl cleanup
        //   4. DeleteShareGroup   — Phase-3 group cleanup
        //   5. ProfileOp::Delete  — cycle 1's profile cleanup
        //   6. BackupConfig       — pf.conf snapshot before edits
        //   7. RemoveAnchor       — delete /etc/pf.anchors/tenant-<name>
        //   8. UpdateConfig       — write pf.conf with tenant ref removed
        //   9. Reload             — pfctl -f
        //   10. FlushAnchor       — pfctl -a tenant-<name> -F all
        // PF teardown sits after the account/profile cleanup so the
        // tenant can't open new sockets while we're tearing down their
        // ruleset. FlushAnchor is the load-bearing last step — pfctl
        // -f doesn't garbage-collect anchors whose `load anchor`
        // directive has been removed, so without explicit flush the
        // previous tenant's rules persist in kernel memory and the
        // next tenant getting the same UID inherits them silently. No
        // recovery on reload failure (the symmetric restore would
        // re-reference the just-removed anchor file).
        let delete_user = AccountOp::DeleteTenantUser { name: name.into() };
        let probe = AccountOp::LookupUserRecord { name: name.into() };
        let cleanup = AccountOp::DeleteUserRecord { name: name.into() };
        let delete_group = AccountOp::DeleteShareGroup { name: name.into() };
        let delete_profile = ProfileOp::Delete { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let reload = FirewallOp::Reload;
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };
        // Plan-time placeholder for UpdateConfig — describe text
        // ignores the `content` field, so this matches the real op
        // built below for execution.
        let update_conf_plan = FirewallOp::UpdateConfig {
            content: String::new(),
        };

        reporter.destroy_starting(
            name,
            &[
                (Op::Account(&delete_user), None),
                (Op::Account(&probe), None),
                (Op::Account(&cleanup), None),
                (Op::Account(&delete_group), None),
                (Op::Profile(&delete_profile), None),
                (Op::Firewall(&backup), None),
                (Op::Firewall(&remove_anchor), None),
                (Op::Firewall(&update_conf_plan), None),
                (Op::Firewall(&reload), None),
                (Op::Firewall(&flush_anchor), None),
            ],
        );

        self.run(&delete_user, reporter)?;
        match self.run(&probe, reporter) {
            Ok(()) => {
                self.run(&cleanup, reporter)?;
            }
            Err(AccountError::NonZero { .. }) => {
                // Probe found DS clean → no cleanup.
            }
            Err(other) => return Err(DestroyError::Account(other)),
        }

        self.run(&delete_group, reporter)?;
        self.run(&delete_profile, reporter)
            .map_err(DestroyError::Profile)?;

        // Firewall teardown. read_pf_conf + remove_anchor_ref runs
        // here (after profile delete) so failures surface via
        // DestroyError::Firewall rather than confusing the earlier
        // account/profile-domain errors.
        let pf_conf_current = self
            .executor
            .read_pf_conf()
            .map_err(DestroyError::Firewall)?;
        let update_conf = FirewallOp::UpdateConfig {
            content: remove_anchor_ref(&pf_conf_current, name),
        };
        self.run(&backup, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&remove_anchor, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&update_conf, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&reload, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&flush_anchor, reporter)
            .map_err(DestroyError::Firewall)?;

        reporter.destroy_done(name);
        Ok(())
    }

    /// Convergence path: the tenant user is already absent (so none of
    /// the user-side teardown applies), but the suffixed
    /// `<name>-tenant-share` group is still on the host. Issues two
    /// substrate calls (DeleteShareGroup + ProfileOp::Delete) bracketed
    /// by the orphan-group `_starting` / `_done` Reporter pair. The
    /// profile step is always attempted (idempotent Delete) so the "host
    /// has no trace of <name> after destroy" contract holds even on the
    /// convergence path.
    pub(crate) fn destroy_orphan_group(
        &self,
        name: &str,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        // Seven-step convergence path: DeleteShareGroup + ProfileOp::Delete
        // (cycle 1) + the five-step PF teardown (cycle 2 including
        // FlushAnchor). If a partial create left an anchor or pf.conf
        // reference, the firewall steps converge it here too — and if
        // there's nothing to tear down, each step is idempotent
        // (RemoveAnchor on missing file is a noop, UpdateConfig on
        // conf without our anchor is a noop, FlushAnchor on an
        // unknown anchor is a noop) so the convergence path stays
        // single-pass.
        let delete_group = AccountOp::DeleteShareGroup { name: name.into() };
        let delete_profile = ProfileOp::Delete { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let reload = FirewallOp::Reload;
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };
        let update_conf_plan = FirewallOp::UpdateConfig {
            content: String::new(),
        };

        reporter.orphan_group_starting(
            name,
            &[
                (Op::Account(&delete_group), None),
                (Op::Profile(&delete_profile), None),
                (Op::Firewall(&backup), None),
                (Op::Firewall(&remove_anchor), None),
                (Op::Firewall(&update_conf_plan), None),
                (Op::Firewall(&reload), None),
                (Op::Firewall(&flush_anchor), None),
            ],
        );

        self.run(&delete_group, reporter)?;
        self.run(&delete_profile, reporter)
            .map_err(DestroyError::Profile)?;

        let pf_conf_current = self
            .executor
            .read_pf_conf()
            .map_err(DestroyError::Firewall)?;
        let update_conf = FirewallOp::UpdateConfig {
            content: remove_anchor_ref(&pf_conf_current, name),
        };
        self.run(&backup, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&remove_anchor, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&update_conf, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&reload, reporter)
            .map_err(DestroyError::Firewall)?;
        self.run(&flush_anchor, reporter)
            .map_err(DestroyError::Firewall)?;

        reporter.orphan_group_done(name);
        Ok(())
    }

    /// Apply a PF widening level to the tenant. Reads the on-disk
    /// profile, renders a new anchor body from the runtime tier
    /// (`level == Runtime`) or the union of runtime + install tiers
    /// (`level == Install`), and reapplies via the existing
    /// `FirewallOp::InstallAnchor` + `FirewallOp::Reload` pair.
    ///
    /// **No defensive `FlushAnchor`** before InstallAnchor (cycle-3
    /// Q1 lock): the parent `load anchor` directive in `/etc/pf.conf`
    /// stays in place across mode reapply, so `pfctl -f` re-reads the
    /// anchor file and replaces the in-kernel ruleset on every reload.
    /// The cycle-2 destroy-side FlushAnchor is load-bearing only when
    /// the parent load directive is removed (orphan-anchor case);
    /// mode-reapply is structurally different. The cycle-3 manual
    /// smoke verifies empirically by checking the kernel `<allowed>`
    /// table shrinks correctly on narrow-back.
    ///
    /// **No automatic recovery** on Reload failure (matches the
    /// plugin's `reapply_anchor`). If Reload fails, the anchor file
    /// reflects the new body but the kernel rules still match the
    /// old body — operator reruns `tenant mode <name> <level>` to
    /// retry. The verb is idempotent at the substrate.
    pub(crate) fn apply_tenant_mode(
        &self,
        name: &str,
        level: ModeLevel,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        // Intent emitted BEFORE plan-build so the operator sees verb
        // context even if the profile-read fails (parity with shell's
        // `shell_intent` + `shell_plan` split). Plan rendering
        // happens after build so share ops appear in the plan block
        // alongside the PF ops, matching what fires via `$` echo.
        reporter.mode_intent(name, level);
        let plan = self.build_reapply_plan(name, level)?;
        reporter.mode_plan(&plan.as_plan_entries());
        self.execute_reapply_plan(&plan, reporter)?;
        reporter.mode_done(name, level);
        Ok(())
    }

    /// Build the full op list for a profile-to-tenant reapply at
    /// `level`. Reads the profile, parses it, pre-flights every share
    /// entry (Q11 host_path existence; Q12 tenant_path occupancy),
    /// and constructs the op sequence: `InstallAnchor → Reload →
    /// (per share: Grant, optionally EnsureDir, EnsureSymlink)` in
    /// profile-declared order (Q13 lock). Pre-flight refusals surface
    /// before any op fires so the caller's plan emission stays clean.
    ///
    /// Owning the parsed profile + the constructed ops in a single
    /// struct lets the verb methods render the upfront plan
    /// (`mode_starting` / `shell_starting` / `reload_starting`) and
    /// then execute the same ops — plan/echo asymmetry-free.
    fn build_reapply_plan(&self, name: &str, level: ModeLevel) -> Result<ReapplyPlan, ModeError> {
        let profile_content = self
            .executor
            .read_profile(name)
            .map_err(ModeError::Profile)?;
        let parsed_profile = parse(&profile_content).map_err(ModeError::Profile)?;
        let hosts = hosts_for_level(&parsed_profile, level);
        let install_anchor = FirewallOp::InstallAnchor {
            name: name.into(),
            body: render_anchor(name, &hosts),
        };
        let reload = FirewallOp::Reload;
        let share_ops = self.build_share_ops(name, &parsed_profile)?;
        Ok(ReapplyPlan {
            install_anchor,
            reload,
            share_ops,
        })
    }

    /// Per-share op construction. Walks the profile's `[[shares]]`
    /// array in declared order; for each entry: pre-flight host_path
    /// existence (Q11) + tenant_path occupancy (Q12), then emit the
    /// `AclOp::Grant`, optional `EnsureDirAsUser` (parent), and
    /// `EnsureSymlinkAsUser` ops as `ShareOps`. The actual substrate
    /// firing happens later in `execute_reapply_plan` — separating
    /// construction from execution lets the verb method render the
    /// plan over the constructed ops first.
    fn build_share_ops(
        &self,
        name: &str,
        parsed_profile: &Profile,
    ) -> Result<Vec<ShareOps>, ModeError> {
        if parsed_profile.shares.is_empty() {
            return Ok(Vec::new());
        }
        let group = tenant_share_group_name(name);
        let home_dir = PathBuf::from(format!("/Users/{name}"));
        let mut out = Vec::with_capacity(parsed_profile.shares.len());
        for share in &parsed_profile.shares {
            // Q11: host_path must exist on disk (operator-process check).
            if !share.host_path.exists() {
                return Err(ModeError::Share(ShareError::HostPathMissing {
                    path: share.host_path.clone(),
                }));
            }
            let tenant_path = expand_tenant_path(name, &share.tenant_path);
            // Q12: tenant_path must be absent or an existing symlink.
            let kind = self
                .executor
                .tenant_path_kind(name, &tenant_path)
                .map_err(ModeError::Probe)?;
            if matches!(kind, PathKind::Other) {
                return Err(ModeError::Share(ShareError::TenantPathOccupied {
                    path: tenant_path,
                }));
            }
            let acl_mode = match share.mode {
                ShareMode::Ro => AclMode::Ro,
                ShareMode::Rw => AclMode::Rw,
            };
            let grant = AclOp::Grant {
                path: share.host_path.clone(),
                group: group.clone(),
                mode: acl_mode,
            };
            // Parent dir ensure: only if not the tenant home itself
            // (home always exists).
            let ensure_dir = tenant_path.parent().and_then(|parent| {
                if parent == home_dir.as_path() {
                    None
                } else {
                    Some(AccountOp::EnsureDirAsUser {
                        name: name.into(),
                        path: parent.to_path_buf(),
                    })
                }
            });
            let ensure_link = AccountOp::EnsureSymlinkAsUser {
                name: name.into(),
                link: tenant_path,
                target: share.host_path.clone(),
            };
            out.push(ShareOps {
                grant,
                ensure_dir,
                ensure_link,
            });
        }
        Ok(out)
    }

    /// Execute a pre-built `ReapplyPlan` against the substrate.
    /// PF reapply first (`InstallAnchor → Reload`); a Reload failure
    /// aborts before any share-substrate mutation.
    fn execute_reapply_plan(
        &self,
        plan: &ReapplyPlan,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        self.run(&plan.install_anchor, reporter)
            .map_err(ModeError::Firewall)?;
        self.run(&plan.reload, reporter)
            .map_err(ModeError::Firewall)?;
        self.execute_share_ops(&plan.share_ops, reporter)
    }

    /// Apply the just-written default profile's share entries at
    /// create-time (post-provision step). Default profile has no
    /// `[[shares]]` so this is a no-op on the production path; tests
    /// using `with_create_profile_content` to pre-populate shares
    /// exercise it. Skips the PF reapply already done by the
    /// create-time firewall sequence.
    fn reapply_shares_post_provision(
        &self,
        name: &str,
        parsed_profile: &Profile,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        let share_ops = self.build_share_ops(name, parsed_profile)?;
        self.execute_share_ops(&share_ops, reporter)
    }

    /// Fire each `ShareOps` triple against the substrate in declared
    /// order: `Grant → (optional EnsureDir) → EnsureSymlink`.
    /// Centralized so `execute_reapply_plan` and
    /// `reapply_shares_post_provision` share one loop body —
    /// substrate-failure error routing stays consistent across both.
    fn execute_share_ops(
        &self,
        share_ops: &[ShareOps],
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        for share in share_ops {
            self.run(&share.grant, reporter).map_err(ModeError::Acl)?;
            if let Some(ensure_dir) = &share.ensure_dir {
                self.run(ensure_dir, reporter).map_err(ModeError::Account)?;
            }
            self.run(&share.ensure_link, reporter)
                .map_err(ModeError::Account)?;
        }
        Ok(())
    }

    /// Interactive shell entry into the tenant. Three logical steps:
    /// (1) narrow the tenant's PF anchor back to runtime tier (cycle-4
    /// auto-narrow — unconditional, idempotent, security-load-bearing),
    /// (2) emit the verb's pre-exec intent + echo for the login op,
    /// (3) hand off to the substrate's `login` method.
    ///
    /// The narrow uses `build_reapply_plan` + `execute_reapply_plan`
    /// (shared with `apply_tenant_mode` and `reload_tenant`) — same
    /// data flow, no mode-verb intent/done emit. If the narrow
    /// fails, the login is NOT launched (Q2 lock, abort posture); the
    /// operator's recovery is `tenant mode <name> runtime` to narrow
    /// manually, then retry.
    ///
    /// The LoginAsUser op is built only to feed `describe_account` for
    /// the plan and echo lines; execution goes through the substrate's
    /// `login` method because the return type (child exit code) and
    /// stdio semantics (inherit, don't capture) are incompatible with
    /// the non-interactive `execute_account` path. There is no post-
    /// exec confirmation: the operator IS the shell after `login`
    /// returns, so a "Shelled into …" line afterwards would be at best
    /// redundant and at worst land in a different terminal context.
    pub(crate) fn shell_into_tenant(
        &self,
        name: &str,
        reporter: &mut Reporter,
    ) -> Result<i32, ShellError> {
        // Cycle-4 invariant: intent emitted BEFORE the narrow tries,
        // so the operator sees the verb context even if the
        // pre-flight profile read fails. Plan rendering happens AFTER
        // the plan is built (post-profile-read) so share ops appear
        // in the plan block alongside the PF + login ops.
        reporter.shell_intent(name);
        let reapply_plan = self
            .build_reapply_plan(name, ModeLevel::Runtime)
            .map_err(ShellError::Mode)?;
        let login = AccountOp::LoginAsUser { name: name.into() };
        let mut plan_entries = reapply_plan.as_plan_entries();
        plan_entries.push((Op::Account(&login), None));
        reporter.shell_plan(&plan_entries);
        self.execute_reapply_plan(&reapply_plan, reporter)
            .map_err(ShellError::Mode)?;
        reporter.step(Op::Account(&login));
        self.executor.login(name).map_err(ShellError::Account)
    }

    /// Run a single op: emit the `$` echo line (in real+verbose) and
    /// execute the op against the substrate. Generic over `WritableOp`
    /// so `AccountOp` and `ProfileOp` both flow through one method, each
    /// preserving its domain-specific error type. The echo + execute
    /// coupling means a Writer caller can't accidentally execute without
    /// echoing or echo without executing.
    fn run<O: WritableOp>(&self, op: &O, reporter: &mut Reporter) -> Result<(), O::Error> {
        reporter.step(op.op_ref());
        op.execute_via(self.executor)
    }

    /// Reload a single tenant — runtime-tier PF reapply + share
    /// substrate. Cycle 10's headline verb's per-tenant arm. Reuses
    /// `build_reapply_plan` + `execute_reapply_plan` under runtime
    /// tier; the verb's distinct framing lives on the Reporter.
    pub(crate) fn reload_tenant(
        &self,
        name: &str,
        reporter: &mut Reporter,
    ) -> Result<(), ModeError> {
        // Intent emitted BEFORE plan-build so the operator sees verb
        // context even if the profile-read fails (parity with shell's
        // `shell_intent` + `shell_plan` split). Plan rendering
        // happens after the plan is built so share ops appear in the
        // plan block alongside the PF ops.
        reporter.reload_intent(name);
        let plan = self.build_reapply_plan(name, ModeLevel::Runtime)?;
        reporter.reload_plan(&plan.as_plan_entries());
        self.execute_reapply_plan(&plan, reporter)?;
        reporter.reload_done(name);
        Ok(())
    }

    /// Reload every tenant on the host. Q15 lock: continue on
    /// per-tenant failure, accumulate, surface a single end-of-run
    /// summary. The exit code at the dispatcher reflects the worst
    /// outcome (0 if all clean; 74 if any tripped). Tenants are
    /// walked in `Reader::tenant_names()` order (alphabetical) for
    /// deterministic output across runs.
    pub(crate) fn reload_all_tenants(
        &self,
        accounts: &dyn Reader,
        reporter: &mut Reporter,
    ) -> ReloadAllOutcome {
        let names = accounts.tenant_names();
        reporter.reload_all_starting(names.len());
        if names.is_empty() {
            reporter.reload_all_done_summary(0, 0);
            return ReloadAllOutcome { failed: 0 };
        }
        let mut failed = 0;
        for name in &names {
            match self.reload_tenant(name, reporter) {
                Ok(()) => {}
                Err(err) => {
                    failed += 1;
                    // Per-tenant failure routes through the same
                    // Reporter methods the verb-level dispatch uses
                    // (mirror of `surface_reload_error` in
                    // commands.rs). The operator sees inline failure
                    // framing during the walk; the end-of-walk
                    // summary counts how many tripped.
                    match &err {
                        ModeError::Profile(e) => reporter.reload_profile_failed(name, e),
                        ModeError::Firewall(e) => reporter.reload_firewall_failed(name, e),
                        ModeError::Acl(e) => reporter.mode_acl_failed(name, e),
                        ModeError::Account(e) => reporter.mode_account_failed(name, e),
                        ModeError::Probe(e) => reporter.mode_probe_failed(name, e),
                        ModeError::Share(e) => reporter.refuse_reload_share(name, e),
                    }
                }
            }
        }
        reporter.reload_all_done_summary(names.len() - failed as usize, failed as usize);
        ReloadAllOutcome { failed }
    }

    /// Doctor's single-tenant audit. Runs in two phases:
    ///
    /// 1. **Env-policy check.** Reads `/etc/sudoers` + drop-ins (via
    ///    `Executor::read_env_policy`); if `SSH_AUTH_SOCK` is not in
    ///    any `env_delete` directive, emits a host-wide `EnvLeak`
    ///    warning finding. The check runs even in single-tenant mode
    ///    because the leak affects EVERY tenant on the host.
    /// 2. **Filesystem probe walk.** Iterates the curated path list,
    ///    probing each `(path, mode)` tuple AS the tenant via
    ///    `Executor::probe_access_as_tenant`. Allowed outcomes
    ///    produce findings (severity per `doctor::classify`); Denied
    ///    / Unknown produce nothing.
    ///
    /// `host` is the operator's login name on the host — needed to
    /// expand `/Users/<host>/…` paths in the curated list. `others`
    /// is the list of OTHER tenant names (for cross-tenant +
    /// tenant-artifact probes).
    pub(crate) fn doctor_tenant(
        &self,
        host: &str,
        name: &str,
        others: &[&str],
        reporter: &mut Reporter,
    ) -> Result<DoctorOutcome, DoctorError> {
        let mut findings: Vec<Finding> = Vec::new();
        if let Some(env_leak) = self.check_env_leak(reporter)? {
            findings.push(env_leak);
        }
        if let Some(touch_id) = self.check_touch_id_for_sudo(reporter)? {
            findings.push(touch_id);
        }
        if let Some(pf_disabled) = self.check_pf_status(reporter)? {
            findings.push(pf_disabled);
        }
        findings.extend(self.probe_tenant_paths(host, name, others, reporter)?);
        Ok(DoctorOutcome { findings })
    }

    /// Doctor's all-tenants audit. Runs the env-policy check ONCE
    /// (the leak is host-wide; per-tenant emission would be noise),
    /// then iterates every tenant-range account in alphabetical
    /// order and runs the per-tenant probe walk. The `others` list
    /// for each tenant is "every other tenant" so cross-tenant +
    /// tenant-artifact probes fire correctly.
    ///
    /// If the host has no tenants, the env-policy check still runs
    /// (the leak finding may still be operator-relevant even with
    /// no tenants right now) and a "no tenants to audit" message is
    /// emitted before the result is returned. Substrate-failure
    /// posture is fail-fast: any `DoctorError` aborts the walk.
    pub(crate) fn doctor_all_tenants(
        &self,
        host: &str,
        accounts: &dyn Reader,
        reporter: &mut Reporter,
    ) -> Result<DoctorOutcome, DoctorError> {
        let mut findings: Vec<Finding> = Vec::new();
        if let Some(env_leak) = self.check_env_leak(reporter)? {
            findings.push(env_leak);
        }
        if let Some(touch_id) = self.check_touch_id_for_sudo(reporter)? {
            findings.push(touch_id);
        }
        if let Some(pf_disabled) = self.check_pf_status(reporter)? {
            findings.push(pf_disabled);
        }
        let tenants = accounts.tenant_names();
        if tenants.is_empty() {
            reporter.doctor_all_tenants_noop();
            return Ok(DoctorOutcome { findings });
        }
        for name in &tenants {
            let others: Vec<&str> = tenants
                .iter()
                .filter(|n| *n != name)
                .map(String::as_str)
                .collect();
            findings.extend(self.probe_tenant_paths(host, name, &others, reporter)?);
        }
        Ok(DoctorOutcome { findings })
    }

    /// Read the host's env policy + emit the `EnvLeak` finding if
    /// `SSH_AUTH_SOCK` propagates. Returns the emitted finding (if
    /// any) so the caller can aggregate it into the DoctorOutcome
    /// for the `--strict` decision.
    fn check_env_leak(&self, reporter: &mut Reporter) -> Result<Option<Finding>, HostFileError> {
        let policy = self.executor.read_env_policy()?;
        if has_env_delete_for(&policy, "SSH_AUTH_SOCK") {
            return Ok(None);
        }
        let finding = Finding::EnvLeak {
            var: "SSH_AUTH_SOCK".to_string(),
        };
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    /// Read `/etc/pam.d/sudo` + emit the host-wide `TouchIdMissing`
    /// finding if no active `auth sufficient pam_tid.so` directive
    /// is present (cycle 7 SC3). Runs once per `tenant doctor`
    /// invocation (single-emit, host-level); both `doctor_tenant`
    /// and `doctor_all_tenants` call this. Returns the emitted
    /// finding (if any) so the caller aggregates it for `--strict`.
    fn check_touch_id_for_sudo(
        &self,
        reporter: &mut Reporter,
    ) -> Result<Option<Finding>, HostFileError> {
        let pam_config = self.executor.read_pam_sudo()?;
        if has_pam_tid(&pam_config) {
            return Ok(None);
        }
        let finding = Finding::TouchIdMissing;
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    /// Read pf's global enable state + emit the host-wide
    /// `PfDisabled` finding (Critical) if pf is off (cycle 7 SC4).
    /// Runs once per `tenant doctor` invocation (single-emit,
    /// host-level); a single global pf state covers every tenant
    /// anchor.
    fn check_pf_status(&self, reporter: &mut Reporter) -> Result<Option<Finding>, FirewallError> {
        let status = self.executor.read_pf_status()?;
        if pf_status_enabled(&status) {
            return Ok(None);
        }
        let finding = Finding::PfDisabled;
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    /// Probe one tenant's view of the curated path list, then
    /// structural-check the kernel's pf anchor for the same tenant
    /// (cycle 7 SC2). Emits `doctor_starting` (curated-list
    /// disclosure in verbose; dry-run intent line), then each
    /// filesystem finding inline, then any `PfRuleDrift` findings
    /// inline, then `doctor_done_summary` with the total per-tenant
    /// finding count. Env-leak + other host-wide findings are the
    /// caller's responsibility.
    fn probe_tenant_paths(
        &self,
        host: &str,
        name: &str,
        others: &[&str],
        reporter: &mut Reporter,
    ) -> Result<Vec<Finding>, DoctorError> {
        let curated = curated_paths(host, name, others);
        reporter.doctor_starting(name, &curated);
        let mut findings: Vec<Finding> = Vec::new();
        for (category, mode, path) in &curated {
            let outcome = self.executor.probe_access_as_tenant(name, path, *mode)?;
            if let Some(severity) = crate::doctor::classify(*category, outcome) {
                let finding = Finding::FilesystemExposure {
                    severity,
                    tenant: name.to_string(),
                    path: path.clone(),
                    access: *mode,
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
        }
        let rules = self.executor.read_kernel_pf_rules(name)?;
        for drift in crate::doctor::pf_rule_presence_check(&rules, name) {
            reporter.doctor_finding(&drift);
            findings.push(drift);
        }
        if let Some(drift) = self.check_anchor_body_drift(name)? {
            reporter.doctor_finding(&drift);
            findings.push(drift);
        }
        for drift in self.check_share_drift(name, reporter)? {
            findings.push(drift);
        }
        reporter.doctor_done_summary(name, findings.len());
        Ok(findings)
    }

    /// Walk the profile's declared `[[shares]]` and emit drift findings
    /// for each: cycle 11's `AclDrift` (host_path missing the
    /// `<tenant>-tenant-share` group's ACL entry) and `SymlinkDrift`
    /// (tenant_path isn't the declared symlink: Absent / WrongTarget /
    /// NotSymlink sub-cases via `SymlinkActual`). The two checks are
    /// independent — a single share entry can fire both findings.
    /// Q4 (cycle 8) parallel: a profile that can't be read or parsed
    /// SKIPS the check silently (a future `ProfileMissing` finding
    /// would surface that case separately). Q5 (cycle 11) parallel: a
    /// per-path substrate failure on `read_host_acl` or
    /// `tenant_path_kind` aborts the loop with `DoctorError::Probe`,
    /// surfacing the error frame; mirrors `read_kernel_pf_rules`'s
    /// fail-fast posture for the doctor walk.
    ///
    /// Findings are emitted via `reporter.doctor_finding` as they fire
    /// (consistent with the file's stream-emit pattern); the returned
    /// Vec carries the same findings for the caller to aggregate into
    /// the `DoctorOutcome`.
    fn check_share_drift(
        &self,
        name: &str,
        reporter: &mut Reporter,
    ) -> Result<Vec<Finding>, DoctorError> {
        let profile_content = match self.executor.read_profile(name) {
            Ok(c) => c,
            Err(_) => return Ok(Vec::new()),
        };
        let parsed = match parse(&profile_content) {
            Ok(p) => p,
            Err(_) => return Ok(Vec::new()),
        };
        let group = tenant_share_group_name(name);
        let mut findings: Vec<Finding> = Vec::new();
        for share in &parsed.shares {
            // AclDrift check: read host-side ACL listing and grep for
            // the expected group's `allow` entry.
            let listing = self.executor.read_host_acl(&share.host_path)?;
            if !has_group_acl_entry(&listing, &group) {
                let finding = Finding::AclDrift {
                    tenant: name.to_string(),
                    host_path: share.host_path.clone(),
                    group: group.clone(),
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
            // SymlinkDrift check: probe tenant_path_kind and compare
            // against the declared host_path target. Cycle-11 Q3
            // lock: string-exact comparison (no canonicalize).
            let tenant_path = expand_tenant_path(name, &share.tenant_path);
            let kind = self.executor.tenant_path_kind(name, &tenant_path)?;
            let actual_opt = match kind {
                PathKind::Absent => Some(SymlinkActual::Absent),
                PathKind::Other => Some(SymlinkActual::NotSymlink),
                PathKind::Symlink(target) => {
                    if target == share.host_path {
                        None
                    } else {
                        Some(SymlinkActual::WrongTarget(target))
                    }
                }
            };
            if let Some(actual) = actual_opt {
                let finding = Finding::SymlinkDrift {
                    tenant: name.to_string(),
                    tenant_path,
                    expected_target: share.host_path.clone(),
                    actual,
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
        }
        Ok(findings)
    }

    /// Compare the on-disk anchor body for `name` against the
    /// runtime-tier render of the current profile. Returns a
    /// `Finding::AnchorBodyDrift` on mismatch, `None` on match.
    /// Q4 lock: a profile that can't be read or parsed SKIPS the
    /// check (returns `Ok(None)`) so a missing/corrupt profile is
    /// reported by a different cycle's finding, not as a spurious
    /// drift. Q9 lock: comparison is against the runtime tier only —
    /// install-tier widening outside a shell session IS drift per
    /// the cycle-4 session-scoped doctrine.
    fn check_anchor_body_drift(&self, name: &str) -> Result<Option<Finding>, HostFileError> {
        let profile_content = match self.executor.read_profile(name) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };
        let parsed = match parse(&profile_content) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let actual = self.executor.read_anchor_body(name)?;
        let expected = render_anchor(name, &parsed.allowlist.runtime.hosts);
        if anchor_body_matches(&actual, &expected) {
            return Ok(None);
        }
        Ok(Some(Finding::AnchorBodyDrift {
            tenant: name.to_string(),
        }))
    }
}

/// Combined error surface for the doctor verb. `Probe` covers the
/// filesystem-probe substrate; `HostFile` covers reads of host
/// config files (sudoers + drop-ins via `read_env_policy`;
/// `/etc/pam.d/sudo` via `read_pam_sudo`); `Firewall` covers pfctl
/// reads (`read_kernel_pf_rules` cycle 7 SC2; `read_pf_status` SC4).
/// The dispatcher routes each variant to a Reporter method with
/// verb-appropriate framing.
#[derive(Debug)]
pub(crate) enum DoctorError {
    Probe(ProbeError),
    HostFile(HostFileError),
    Firewall(FirewallError),
}

impl From<ProbeError> for DoctorError {
    fn from(e: ProbeError) -> Self {
        DoctorError::Probe(e)
    }
}

impl From<HostFileError> for DoctorError {
    fn from(e: HostFileError) -> Self {
        DoctorError::HostFile(e)
    }
}

impl From<FirewallError> for DoctorError {
    fn from(e: FirewallError) -> Self {
        DoctorError::Firewall(e)
    }
}

/// Aggregated outcome of one `doctor` verb invocation. The findings
/// list feeds operator-visible output (already emitted incrementally
/// by the Reporter); `max_severity()` feeds the `--strict` exit-code
/// decision at the dispatch layer.
#[derive(Debug, Default)]
pub(crate) struct DoctorOutcome {
    pub findings: Vec<Finding>,
}

impl DoctorOutcome {
    pub fn max_severity(&self) -> Option<crate::doctor::Severity> {
        self.findings.iter().map(|f| f.severity()).max()
    }
}

/// Select which hosts the rendered PF anchor body should include for
/// the requested mode level. Runtime mode takes only `allowlist.runtime.hosts`;
/// install mode is the union — runtime hosts first (preserving the
/// operator's grouping intent in the profile), then install hosts.
/// Order matters for `render_anchor`'s output stability.
fn hosts_for_level(profile: &Profile, level: ModeLevel) -> Vec<String> {
    match level {
        ModeLevel::Runtime => profile.allowlist.runtime.hosts.clone(),
        ModeLevel::Install => {
            let mut hosts = profile.allowlist.runtime.hosts.clone();
            hosts.extend(profile.allowlist.install.hosts.iter().cloned());
            hosts
        }
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
