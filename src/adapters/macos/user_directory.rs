use std::collections::HashMap;
use std::process::Command;

use crate::allocation::TENANT_UID_FLOOR;
use crate::domain::{
    GroupId, GroupName, HostUserDirectory, TenantUserName, UserDirectoryError, UserId,
};

/// Per-call dscl, no snapshot: host changes between verb steps stay visible,
/// at the cost of N+1 dscl spawns.
pub struct MacosUserDirectory;

impl HostUserDirectory for MacosUserDirectory {
    fn used_uids(&self) -> Result<Vec<UserId>, UserDirectoryError> {
        // Duplicate name rows (hand-edited OD state) fold to the lowest UID — the
        // safer pick, more likely to trip the floor refusal.
        let output = run_dscl(&[".", "-list", "/Users", "UniqueID"])?;
        let mut by_name: HashMap<String, UserId> = HashMap::new();
        for line in output.lines() {
            if let Some((name, id)) = parse_id_line(line) {
                by_name
                    .entry(name)
                    .and_modify(|cur| *cur = (*cur).min(UserId(id)))
                    .or_insert(UserId(id));
            }
        }
        Ok(by_name.into_values().collect())
    }

    fn used_gids(&self) -> Result<Vec<GroupId>, UserDirectoryError> {
        let output = run_dscl(&[".", "-list", "/Groups", "PrimaryGroupID"])?;
        let mut by_name: HashMap<String, GroupId> = HashMap::new();
        for line in output.lines() {
            if let Some((name, id)) = parse_id_line(line) {
                by_name
                    .entry(name)
                    .and_modify(|cur| *cur = (*cur).min(GroupId(id)))
                    .or_insert(GroupId(id));
            }
        }
        Ok(by_name.into_values().collect())
    }

    fn has_user(&self, name: &TenantUserName) -> Result<bool, UserDirectoryError> {
        record_exists(&format!("/Users/{}", name.as_str()))
    }

    fn has_group(&self, group: &GroupName) -> Result<bool, UserDirectoryError> {
        record_exists(&format!("/Groups/{}", group.as_str()))
    }

    fn uid_for(&self, name: &TenantUserName) -> Result<Option<UserId>, UserDirectoryError> {
        let path = format!("/Users/{}", name.as_str());
        let output = match Command::new("dscl")
            .args([".", "-read", &path, "UniqueID"])
            .output()
        {
            Ok(o) => o,
            Err(e) => return Err(UserDirectoryError::Spawn(e)),
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if is_record_not_found(&stderr) {
                return Ok(None);
            }
            return Err(UserDirectoryError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: stderr.into_owned(),
            });
        }
        // Prints `UniqueID: <n>`.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let id = stdout
            .split_whitespace()
            .next_back()
            .and_then(|tok| tok.parse::<i32>().ok());
        match id {
            Some(i) if i >= 0 => Ok(Some(UserId(i as u32))),
            _ => Ok(None),
        }
    }

    // TODO(smell): fold-to-lowest loop is copied from used_uids (and used_gids) — extract
    fn tenant_names(&self) -> Result<Vec<TenantUserName>, UserDirectoryError> {
        // Sorted so doctor's all-tenants output is stable across runs.
        let output = run_dscl(&[".", "-list", "/Users", "UniqueID"])?;
        let mut by_name: HashMap<String, UserId> = HashMap::new();
        for line in output.lines() {
            if let Some((name, id)) = parse_id_line(line) {
                by_name
                    .entry(name)
                    .and_modify(|cur| *cur = (*cur).min(UserId(id)))
                    .or_insert(UserId(id));
            }
        }
        let mut out: Vec<TenantUserName> = by_name
            .into_iter()
            .filter(|(_, uid)| uid.0 >= TENANT_UID_FLOOR)
            .map(|(name, _)| TenantUserName(name))
            .collect();
        out.sort();
        Ok(out)
    }
}

/// Only `eDSRecordNotFound` means absent; any other failure is an error, so a
/// broken dscl (permissions, hung daemon) never reads as "absent".
fn record_exists(path: &str) -> Result<bool, UserDirectoryError> {
    let output = match Command::new("dscl").args([".", "-read", path]).output() {
        Ok(o) => o,
        Err(e) => return Err(UserDirectoryError::Spawn(e)),
    };
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_record_not_found(&stderr) {
        return Ok(false);
    }
    Err(UserDirectoryError::NonZero {
        code: output.status.code().unwrap_or(-1),
        stderr: stderr.into_owned(),
    })
}

/// dscl's record-absent signal on Darwin. The error code is stable
/// across releases (verified on 25.x); the human suffix isn't, so we
/// match the parenthesized symbol.
fn is_record_not_found(stderr: &str) -> bool {
    stderr.contains("eDSRecordNotFound")
}

fn parse_id_line(line: &str) -> Option<(String, u32)> {
    // Negative IDs (`nobody`) dropped: cast to u32 they'd land in the tenant range.
    let mut parts = line.split_whitespace();
    let name = parts.next()?;
    let id = parts.next()?.parse::<i32>().ok()?;
    if id < 0 {
        None
    } else {
        Some((name.to_string(), id as u32))
    }
}

fn run_dscl(args: &[&str]) -> Result<String, UserDirectoryError> {
    let output = Command::new("dscl")
        .args(args)
        .output()
        .map_err(UserDirectoryError::Spawn)?;
    if !output.status.success() {
        return Err(UserDirectoryError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
