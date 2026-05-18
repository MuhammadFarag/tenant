use std::collections::{HashMap, HashSet};
use std::io;
use std::process::Command;

use crate::allocation::TENANT_UID_FLOOR;
use crate::domain::{GroupId, GroupName, HostAccounts, TenantUserName, UserId};

/// Real `HostAccounts` backed by `dscl`. Queries the local Open Directory node
/// once at construction and serves all subsequent lookups from memory.
/// `users` and `uid_by_name` are kept separate for the same reason the
/// stub keeps them separate: macOS service accounts with negative UIDs
/// (`nobody` is the canonical case) are present in the user listing but
/// are filtered out of the UID map (negative-UID accounts can't masquerade
/// as a tenant-range UID and shouldn't influence allocator state).
/// `gid_by_name` mirrors the UID structure for the GID space, with the
/// same negative-GID filtering rationale.
pub struct MacosHostAccounts {
    users: HashSet<String>,
    groups: HashSet<String>,
    uid_by_name: HashMap<String, UserId>,
    gid_by_name: HashMap<String, GroupId>,
}

impl MacosHostAccounts {
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
            .map(|(name, uid)| (name, UserId(uid)))
            .fold(HashMap::<String, UserId>::new(), |mut map, (name, uid)| {
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
            .map(|(name, gid)| (name, GroupId(gid)))
            .fold(HashMap::<String, GroupId>::new(), |mut map, (name, gid)| {
                map.entry(name)
                    .and_modify(|cur| *cur = (*cur).min(gid))
                    .or_insert(gid);
                map
            });
        Ok(MacosHostAccounts {
            users,
            groups,
            uid_by_name,
            gid_by_name,
        })
    }
}

impl HostAccounts for MacosHostAccounts {
    fn used_uids(&self) -> Vec<UserId> {
        self.uid_by_name.values().copied().collect()
    }

    fn used_gids(&self) -> Vec<GroupId> {
        self.gid_by_name.values().copied().collect()
    }

    fn has_user(&self, name: &TenantUserName) -> bool {
        self.users.contains(name.as_str())
    }

    fn has_group(&self, group: &GroupName) -> bool {
        self.groups.contains(group.as_str())
    }

    fn uid_for(&self, name: &TenantUserName) -> Option<UserId> {
        self.uid_by_name.get(name.as_str()).copied()
    }

    fn tenant_names(&self) -> Vec<TenantUserName> {
        let mut out: Vec<TenantUserName> = self
            .uid_by_name
            .iter()
            .filter(|(_, uid)| uid.0 >= TENANT_UID_FLOOR)
            .map(|(name, _)| TenantUserName(name.clone()))
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
