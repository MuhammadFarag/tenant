use std::collections::HashMap;
use std::process::Command;

use crate::allocation::TENANT_UID_FLOOR;
use crate::domain::{AccountsError, GroupId, GroupName, HostAccounts, TenantUserName, UserId};

/// macOS `HostAccounts` driver: per-call dscl. Symmetric with
/// `MacosHostMachine` — a ZST whose trait methods own argv. No eager
/// snapshot, so a tenant created between two verb steps is visible to
/// the second step (and an externally-deleted tenant won't masquerade
/// as still-present). The tradeoff is N+1 dscl spawns per verb;
/// acceptable for an interactive admin CLI.
pub struct MacosHostAccounts;

impl HostAccounts for MacosHostAccounts {
    fn used_uids(&self) -> Result<Vec<UserId>, AccountsError> {
        // Fold-to-lowest on duplicate name rows: hand-edited OD state
        // could emit duplicates, and the lowest UID is the safer pick
        // (more likely to match a system account and trip the floor
        // refusal). Negative IDs filtered out so `nobody`-class
        // accounts can't masquerade as tenant-range IDs or perturb
        // allocator state.
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

    fn used_gids(&self) -> Result<Vec<GroupId>, AccountsError> {
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

    fn has_user(&self, name: &TenantUserName) -> Result<bool, AccountsError> {
        record_exists(&format!("/Users/{}", name.as_str()))
    }

    fn has_group(&self, group: &GroupName) -> Result<bool, AccountsError> {
        record_exists(&format!("/Groups/{}", group.as_str()))
    }

    fn uid_for(&self, name: &TenantUserName) -> Result<Option<UserId>, AccountsError> {
        let path = format!("/Users/{}", name.as_str());
        let output = match Command::new("dscl")
            .args([".", "-read", &path, "UniqueID"])
            .output()
        {
            Ok(o) => o,
            Err(e) => return Err(AccountsError::Spawn(e)),
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if is_record_not_found(&stderr) {
                return Ok(None);
            }
            return Err(AccountsError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: stderr.into_owned(),
            });
        }
        // `dscl -read /Users/<name> UniqueID` prints `UniqueID: <n>`.
        // The trailing token is the UID; non-positive values trip the
        // same negative-UID filter the bulk path enforces.
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

    fn tenant_names(&self) -> Result<Vec<TenantUserName>, AccountsError> {
        // Mirror `used_uids` (fold-to-lowest + negative filter), then
        // keep only names whose UID is in the tenant range. Stable
        // alphabetical order keeps doctor's all-tenants diff meaningful
        // across runs.
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

/// Probe a dscl path for existence. Mapping: exit 0 ⇒ present,
/// `eDSRecordNotFound` ⇒ absent, anything else ⇒ Err. We pattern-match
/// the dscl error code rather than treating every nonzero as "absent"
/// so a real dscl breakage (permissions, daemon hung) surfaces as
/// `AccountsError` instead of silently reporting "absent" — and the
/// conflict-probe / eligibility frames already exist to carry that
/// surface to the operator.
fn record_exists(path: &str) -> Result<bool, AccountsError> {
    let output = match Command::new("dscl").args([".", "-read", path]).output() {
        Ok(o) => o,
        Err(e) => return Err(AccountsError::Spawn(e)),
    };
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_record_not_found(&stderr) {
        return Ok(false);
    }
    Err(AccountsError::NonZero {
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
    // Shared by `/Users UniqueID` and `/Groups PrimaryGroupID` — both
    // emit "name<whitespace>id". Negative IDs (e.g. `nobody`) are
    // dropped.
    let mut parts = line.split_whitespace();
    let name = parts.next()?;
    let id = parts.next()?.parse::<i32>().ok()?;
    if id < 0 {
        None
    } else {
        Some((name.to_string(), id as u32))
    }
}

fn run_dscl(args: &[&str]) -> Result<String, AccountsError> {
    let output = Command::new("dscl")
        .args(args)
        .output()
        .map_err(AccountsError::Spawn)?;
    if !output.status.success() {
        return Err(AccountsError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
