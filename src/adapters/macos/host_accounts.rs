use std::collections::{HashMap, HashSet};
use std::io;
use std::process::Command;

use crate::allocation::TENANT_UID_FLOOR;
use crate::domain::{GroupId, GroupName, HostAccounts, TenantUserName, UserId};

/// `users` / `groups` carry every name (including negative-UID/GID service
/// accounts like `nobody`); `uid_by_name` / `gid_by_name` drop the negatives
/// so they can't masquerade as tenant-range IDs or perturb allocator state.
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
        // Fold-to-lowest on duplicate name rows: hand-edited OD state could
        // emit duplicates, and the lowest UID is the safer pick (more likely
        // to match a system account and trip the floor refusal).
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
    // Shared by `/Users UniqueID` and `/Groups PrimaryGroupID` — both emit
    // "name<whitespace>id". Negative IDs (e.g. `nobody`) are dropped from
    // the ID maps but remain in the name sets via the separate `-list` calls.
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
