//! Production `HostMachine` substrate — knows the macOS tool argv and the
//! XDG-style profile path convention. The argv-building logic that
//! previously lived in the `build_*_argv` family (and the synthetic-argv
//! hacks for profile ops) is now confined to this module's helpers.

use std::env;
use std::fs;
use std::io;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclMode, AclOp, FirewallError,
    FirewallOp, GroupName, HostFileError, HostMachine, HostUserName, PathKind, ProbeError,
    ProfileOp, TenantUserName,
};
use crate::firewall::{PF_CONF, PF_CONF_BACKUP, tenant_anchor_path};
use crate::profile::{ProfileError, default_profile_toml, display_path_for};

/// Production substrate. Knows the macOS tool argv and the XDG-style profile
/// path convention. The argv-building logic that previously lived in the
/// `build_*_argv` family (and the synthetic-argv hacks for profile ops) is
/// now confined to this struct's methods.
pub struct MacosHostMachine;

impl HostMachine for MacosHostMachine {
    fn describe_account(&self, op: &AccountOp) -> String {
        match op {
            AccountOp::CreateShareGroup { group, gid } => {
                format!("sudo dseditgroup -o create -n . -i {gid} {group}")
            }
            AccountOp::DeleteShareGroup { group } => {
                format!("sudo dseditgroup -o delete -n . {group}")
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
            AccountOp::ExecAsUser { name, argv } => {
                format!("sudo -iu {name} -- {}", argv.join(" "))
            }
            AccountOp::EnsureDirAsUser { name, path } => {
                format!("sudo -n -u {name} /bin/mkdir -p {}", path.display())
            }
            AccountOp::EnsureSymlinkAsUser { name, link, target } => format!(
                "sudo -n -u {name} /bin/ln -sfn {} {}",
                target.display(),
                link.display(),
            ),
            AccountOp::AddHostToShareGroup { group, host } => {
                format!("sudo dseditgroup -o edit -n . -a {host} -t user {group}")
            }
            AccountOp::RemoveHostFromShareGroup { group, host } => {
                format!("sudo dseditgroup -o edit -n . -d {host} -t user {group}")
            }
        }
    }

    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        // LoginAsUser is intentionally not handled here — interactive ops go
        // through `login`. Match-arm panics on it so an accidental wiring
        // through `execute_account` fails loudly in dev / tests rather than
        // silently doing the wrong thing in prod.
        if let AccountOp::RemoveHostFromShareGroup { group, host } = op {
            // Idempotence: skip the `-d` edit when host isn't a
            // current member. Covers (a) legacy tenants where the host
            // was never added and (b) destroy_orphan_group on a
            // partial-create tenant where AddHost failed. The substrate
            // is the source of truth — Writer keeps the op in the plan
            // for symmetry; the substrate decides whether to actually
            // fire it.
            if !self.host_in_group(host, group)? {
                return Ok(());
            }
        }
        let argv = match op {
            AccountOp::LoginAsUser { .. } => {
                panic!(
                    "AccountOp::LoginAsUser must go through HostMachine::login, not execute_account"
                )
            }
            AccountOp::ExecAsUser { .. } => {
                panic!(
                    "AccountOp::ExecAsUser must go through HostMachine::exec_as_tenant, not execute_account"
                )
            }
            _ => account_argv(op),
        };
        spawn_capturing(&argv)
    }

    fn login(&self, name: &TenantUserName) -> Result<i32, AccountError> {
        // Stdio inherits so sudo can prompt for the host password and the
        // launched login shell can drive the controlling terminal. Mirrors
        // the pre-refactor `HostMachine::exec_into`.
        let argv = account_argv(&AccountOp::LoginAsUser { name: name.clone() });
        let (program, rest) = argv
            .split_first()
            .ok_or_else(|| AccountError::Spawn(io::Error::other("argv is empty")))?;
        let status = Command::new(program)
            .args(rest)
            .status()
            .map_err(AccountError::Spawn)?;
        Ok(status.code().unwrap_or(1))
    }

    fn exec_as_tenant(&self, name: &TenantUserName, argv: &[String]) -> Result<i32, AccountError> {
        // Same stdio + return-code posture as `login`. argv shape:
        // `sudo -iu <name> -- <argv...>`. The `--` separator is
        // load-bearing — without it, an argv[0] starting with `-`
        // would be interpreted as a sudo flag.
        let full = account_argv(&AccountOp::ExecAsUser {
            name: name.clone(),
            argv: argv.to_vec(),
        });
        let (program, rest) = full
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
                format!("tee {} < default.toml", display_path_for(name.as_str()))
            }
            ProfileOp::Delete { name } => {
                // `rm -f` reflects the idempotent semantics — NotFound is
                // success on both the production fs side and the stub.
                format!("rm -f {}", display_path_for(name.as_str()))
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

    fn read_profile(&self, name: &TenantUserName) -> Result<String, ProfileError> {
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

    fn probe_access_as_tenant(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
        mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError> {
        // `/bin/test -<flag> <path>` returns:
        //   0  → predicate true (Allowed)
        //   1  → predicate false (Denied — includes file-doesn't-exist;
        //        we accept the ambiguity here, since mechanism-of-denial
        //        belongs with the future remediation surface).
        //   ≥2 → anything else (Unknown — probe machinery hiccup).
        // `sudo -n` is the non-interactive flag: if the operator's
        // sudo session isn't already cached, sudo fails with non-zero
        // and we surface as `ProbeError::NonZero`. The expected
        // operator workflow is `sudo -v` (or any prior privileged
        // command in the last ~5 min) before `tenant doctor`; the
        // `--help` text documents this.
        let flag = match mode {
            AccessMode::Read => "-r",
            AccessMode::List => "-x",
        };
        let path_str = path.to_string_lossy().into_owned();
        let output = Command::new("sudo")
            .args(["-n", "-u", name.as_str(), "/bin/test", flag, &path_str])
            .output()
            .map_err(ProbeError::Spawn)?;
        match output.status.code() {
            Some(0) => Ok(AccessOutcome::Allowed),
            Some(1) => Ok(AccessOutcome::Denied),
            Some(code) => {
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                // Distinguish "sudo couldn't authenticate" (machinery
                // failure → ProbeError) from "test answered something
                // weird" (kernel state weird → Unknown). A non-cached
                // sudo session is the canonical machinery failure.
                if stderr.contains("sudo: a password is required")
                    || stderr.contains("sudo: a terminal is required")
                {
                    Err(ProbeError::NonZero { code, stderr })
                } else {
                    Ok(AccessOutcome::Unknown)
                }
            }
            None => Err(ProbeError::NonZero {
                code: -1,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
        }
    }

    fn read_env_policy(&self) -> Result<String, HostFileError> {
        // Read /etc/sudoers (sudoers files are mode 0440 root:wheel —
        // not world-readable; sudo is required), then read every file
        // in /etc/sudoers.d/. Concatenate with newlines so the
        // parser's `env_delete` grep doesn't accidentally bridge the
        // last line of one file into the first of the next. Origin
        // attribution is intentionally dropped — doctor's parser
        // doesn't need it, and a future cycle that wants attribution
        // would have to introduce a wrapper type (we lean YAGNI).
        let primary = read_privileged_text("/etc/sudoers")?;
        let mut combined = primary;
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
        let listing_output = Command::new("sudo")
            .args(["-n", "ls", "-1", "/etc/sudoers.d"])
            .output()
            .map_err(HostFileError::Spawn)?;
        // A non-existent or unreadable /etc/sudoers.d/ is treated as
        // "no drop-ins" rather than a hard failure — sudo doesn't
        // require the dir to exist. Only surface as Fs error if sudo
        // itself reported an authentication failure.
        if listing_output.status.success() {
            let listing = String::from_utf8_lossy(&listing_output.stdout).into_owned();
            for entry in listing.lines() {
                let trimmed = entry.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let path = format!("/etc/sudoers.d/{trimmed}");
                let content = read_privileged_text(&path)?;
                combined.push_str(&content);
                if !combined.ends_with('\n') {
                    combined.push('\n');
                }
            }
        }
        Ok(combined)
    }

    fn execute_firewall(&self, op: &FirewallOp) -> Result<(), FirewallError> {
        match op {
            FirewallOp::InstallAnchor { name, body } => {
                write_privileged(&tenant_anchor_path(name.as_str()), body)
            }
            FirewallOp::RemoveAnchor { name } => {
                // `sudo rm -f <path>` — idempotent on the macOS side
                // (`rm -f` returns 0 on NotFound), so a partial-state
                // destroy doesn't trip here.
                spawn_firewall(&[
                    "sudo".into(),
                    "rm".into(),
                    "-f".into(),
                    tenant_anchor_path(name.as_str()),
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

    fn read_kernel_pf_rules(&self, name: &TenantUserName) -> Result<String, FirewallError> {
        let output = Command::new("sudo")
            .args(["-n", "pfctl", "-a", &format!("tenant-{name}"), "-sr"])
            .output()
            .map_err(FirewallError::Spawn)?;
        if !output.status.success() {
            return Err(FirewallError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn read_pam_sudo(&self) -> Result<String, HostFileError> {
        // `/etc/pam.d/sudo` is mode 0644 — direct fs read, no sudo.
        // The `Fs` variant carries the path so the operator-facing
        // frame names what failed.
        fs::read_to_string("/etc/pam.d/sudo").map_err(|e| HostFileError::Fs {
            path: "/etc/pam.d/sudo".to_string(),
            message: e.to_string(),
        })
    }

    fn read_pf_status(&self) -> Result<String, FirewallError> {
        let output = Command::new("sudo")
            .args(["-n", "pfctl", "-si"])
            .output()
            .map_err(FirewallError::Spawn)?;
        if !output.status.success() {
            return Err(FirewallError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        // `pfctl -si` writes to BOTH stdout and stderr — the
        // "Status: Enabled" line lands on stderr in practice. Combine
        // both into one blob for the parser; tolerating the empty
        // case if the user's host ever emits to a single stream.
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(combined)
    }

    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        // Mode 0644 root-owned — direct fs read, no sudo. Same
        // substrate posture as `read_pam_sudo`. Path centralized via
        // `firewall::tenant_anchor_path` so a future anchor-dir move
        // flows through here without inline edits.
        let path = crate::firewall::tenant_anchor_path(name.as_str());
        fs::read_to_string(&path).map_err(|e| HostFileError::Fs {
            path,
            message: e.to_string(),
        })
    }

    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<PathKind, ProbeError> {
        // Probes:
        //   `sudo -n -u <name> /bin/test -L <path>` → exit 0 = symlink
        //   On symlink-hit: `sudo -n -u <name> /usr/bin/readlink <path>`
        //     captures the target string. readlink itself does not
        //     resolve intermediate symlinks; we record what's literally
        //     stored in the link entry. Doctor's SymlinkDrift comparator
        //     is string-exact.
        //   On symlink-miss: `sudo -n -u <name> /bin/test -e <path>`
        //     distinguishes Other vs Absent.
        // sudo-machinery failures (auth cache miss, fork failed) surface
        // as `ProbeError`. Same NonZero pattern as
        // `probe_access_as_tenant`.
        //
        // Note on absolute paths: macOS Tahoe (Darwin 25.x) ships
        // `test` at `/bin/test` (not `/usr/bin/test`); readlink at
        // `/usr/bin/readlink` (not `/bin/readlink`); `ln` at `/bin/ln`.
        // No single bin-directory is canonical on macOS; the right
        // answer is per-utility.
        let path_str = path.to_string_lossy().into_owned();
        let symlink_out = Command::new("sudo")
            .args(["-n", "-u", name.as_str(), "/bin/test", "-L", &path_str])
            .output()
            .map_err(ProbeError::Spawn)?;
        if let Some(code) = symlink_out.status.code() {
            if code == 0 {
                let readlink_out = Command::new("sudo")
                    .args(["-n", "-u", name.as_str(), "/usr/bin/readlink", &path_str])
                    .output()
                    .map_err(ProbeError::Spawn)?;
                match readlink_out.status.code() {
                    Some(0) => {
                        let target = String::from_utf8_lossy(&readlink_out.stdout)
                            .trim_end_matches('\n')
                            .to_string();
                        return Ok(PathKind::Symlink(std::path::PathBuf::from(target)));
                    }
                    Some(code) => {
                        return Err(ProbeError::NonZero {
                            code,
                            stderr: String::from_utf8_lossy(&readlink_out.stderr).into_owned(),
                        });
                    }
                    None => {
                        return Err(ProbeError::NonZero {
                            code: -1,
                            stderr: String::from_utf8_lossy(&readlink_out.stderr).into_owned(),
                        });
                    }
                }
            }
            if code != 1 {
                // Sudo-auth failure surfaces with codes other than 0/1.
                return Err(ProbeError::NonZero {
                    code,
                    stderr: String::from_utf8_lossy(&symlink_out.stderr).into_owned(),
                });
            }
        } else {
            return Err(ProbeError::NonZero {
                code: -1,
                stderr: String::from_utf8_lossy(&symlink_out.stderr).into_owned(),
            });
        }
        let exists_out = Command::new("sudo")
            .args(["-n", "-u", name.as_str(), "/bin/test", "-e", &path_str])
            .output()
            .map_err(ProbeError::Spawn)?;
        match exists_out.status.code() {
            Some(0) => Ok(PathKind::Other),
            Some(1) => Ok(PathKind::Absent),
            Some(code) => Err(ProbeError::NonZero {
                code,
                stderr: String::from_utf8_lossy(&exists_out.stderr).into_owned(),
            }),
            None => Err(ProbeError::NonZero {
                code: -1,
                stderr: String::from_utf8_lossy(&exists_out.stderr).into_owned(),
            }),
        }
    }

    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError> {
        // Operator-process `ls -lde <path>`: host-side ACL is host
        // state, read from the operator process — no sudo, no
        // run-as-tenant. `ls`'s exit code is 0 on success, non-zero
        // when the path is unreadable (which IS a substrate failure
        // for doctor's purposes — operator can't audit a path they
        // can't list). Concatenate stdout+stderr so both `total N +
        // entries` lines and any error blurb feed the parser uniformly.
        let path_str = path.to_string_lossy().into_owned();
        let output = Command::new("ls")
            .args(["-lde", &path_str])
            .output()
            .map_err(ProbeError::Spawn)?;
        if !output.status.success() {
            return Err(ProbeError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn describe_acl(&self, op: &AclOp) -> String {
        // Pretend-shell `chmod +a "<entry>" <path>` framing. Quoted
        // entry preserved with literal double-quotes in the rendered
        // line — matches the form an operator would type at a prompt;
        // also lets the test golden assert on the exact shape.
        let (flag, path, group, mode) = match op {
            AclOp::Grant {
                path, group, mode, ..
            } => ("+a", path, group, mode),
            AclOp::Revoke {
                path, group, mode, ..
            } => ("-a", path, group, mode),
        };
        format!(
            "chmod {flag} \"{}\" {}",
            acl_entry(group.as_str(), *mode),
            path.display(),
        )
    }

    fn execute_acl(&self, op: &AclOp) -> Result<(), AclError> {
        // macOS `chmod +a` is natively idempotent — re-applying the
        // same ACL entry to a path that already carries it doesn't
        // add a duplicate and doesn't error. So Grant runs chmod
        // unconditionally; substrate-side dedup is the contract.
        //
        // An earlier draft tried a substring-match pre-check against
        // `ls -lde` output before calling chmod, but macOS canonicalizes
        // the bit names on storage (we write
        // `read,write,execute,delete,append` and macOS stores
        // `list,add_file,search,delete,add_subdirectory`), so the
        // substring pre-check always failed false-negative and chmod
        // ran every time anyway. Removed the dead pre-check; the
        // operator-visible behavior is unchanged.
        //
        // Revoke (`chmod -a`) on an absent entry currently surfaces
        // as `AclError::NonZero` with "No matching ACL entry" stderr.
        // No production path exercises Revoke today; future
        // ACL-drift remediation will need to tolerate that case
        // (or pre-check via ls).
        let (flag, path, group, mode) = match op {
            AclOp::Grant {
                path, group, mode, ..
            } => ("+a", path, group, mode),
            AclOp::Revoke {
                path, group, mode, ..
            } => ("-a", path, group, mode),
        };
        let entry = acl_entry(group.as_str(), *mode);
        let path_str = path.display().to_string();
        let output = Command::new("chmod")
            .args([flag, &entry, &path_str])
            .output()
            .map_err(AclError::Spawn)?;
        if !output.status.success() {
            return Err(AclError::NonZero {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(())
    }

    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError> {
        // Read-only directory-service membership probe. Exit 0 ⇒ member;
        // any non-zero exit (host absent from group, group absent) ⇒
        // false. Machinery failure (dseditgroup not on PATH, fork
        // failed) surfaces as `AccountError::Spawn`. The non-zero
        // branch deliberately does NOT inspect stderr; the idempotence
        // contract treats any non-zero as "not a member" so the
        // substrate isn't tied to the tool's exact stderr wording.
        let output = Command::new("dseditgroup")
            .args(["-o", "checkmember", "-m", host.as_str(), group.as_str()])
            .output()
            .map_err(AccountError::Spawn)?;
        Ok(output.status.success())
    }
}

/// Read `path` via `sudo -n cat <path>`. Used for privileged-read
/// access to `/etc/sudoers` and `/etc/sudoers.d/*`. Mirrors the
/// `write_privileged` pattern in reverse: confine sudo invocation
/// to one helper so the substrate code that calls it stays
/// readable.
fn read_privileged_text(path: &str) -> Result<String, HostFileError> {
    let output = Command::new("sudo")
        .args(["-n", "cat", path])
        .output()
        .map_err(HostFileError::Spawn)?;
    if !output.status.success() {
        return Err(HostFileError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
/// pattern-match so future variants (e.g. a `Read` op) just slot in.
fn op_name(op: &ProfileOp) -> &TenantUserName {
    match op {
        ProfileOp::Create { name } | ProfileOp::Delete { name } => name,
    }
}

/// Resolve the absolute profile path for `name` on the host.
/// `$HOME/.config/tenant/profiles/<name>.toml`. The display form (with a
/// literal `~`) lives in `profile::display_path_for`; the absolute form
/// is what the fs ops need.
fn profile_path(name: &TenantUserName) -> Result<PathBuf, ProfileError> {
    let home = env::var("HOME").map_err(|_| ProfileError {
        message: "HOME environment variable is not set".to_string(),
    })?;
    Ok(PathBuf::from(home)
        .join(".config/tenant/profiles")
        .join(format!("{name}.toml")))
}

/// Translate an `AccountOp` to its argv. Confined to this module; the writer
/// never sees argv directly. Used by both `MacosHostMachine::execute_account`
/// (to spawn the process) and `MacosHostMachine::login` (to spawn the
/// interactive login shell). The describe-side renders its own strings to
/// match today's verbose-mode output byte-for-byte; the argv-builder is
/// kept separate so a future change to one form doesn't silently drift the
/// other.
fn account_argv(op: &AccountOp) -> Vec<String> {
    match op {
        AccountOp::CreateShareGroup { group, gid } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "create".into(),
            "-n".into(),
            ".".into(),
            "-i".into(),
            gid.to_string(),
            group.0.clone(),
        ],
        AccountOp::DeleteShareGroup { group } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "delete".into(),
            "-n".into(),
            ".".into(),
            group.0.clone(),
        ],
        AccountOp::CreateTenantUser { name, uid, gid } => vec![
            "sudo".into(),
            "sysadminctl".into(),
            "-addUser".into(),
            name.0.clone(),
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
            name.0.clone(),
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
            vec!["sudo".into(), "-iu".into(), name.0.clone()]
        }
        AccountOp::ExecAsUser { name, argv } => {
            // sudo -iu <name> -- <argv...>. Each argv element passes
            // through as a separate process-argv entry; shell
            // metacharacters inside a single element survive intact.
            let mut full = vec!["sudo".into(), "-iu".into(), name.0.clone(), "--".into()];
            full.extend(argv.iter().cloned());
            full
        }
        AccountOp::EnsureDirAsUser { name, path } => vec![
            "sudo".into(),
            "-n".into(),
            "-u".into(),
            name.0.clone(),
            "/bin/mkdir".into(),
            "-p".into(),
            path.display().to_string(),
        ],
        AccountOp::EnsureSymlinkAsUser { name, link, target } => vec![
            "sudo".into(),
            "-n".into(),
            "-u".into(),
            name.0.clone(),
            "/bin/ln".into(),
            "-sfn".into(),
            target.display().to_string(),
            link.display().to_string(),
        ],
        AccountOp::AddHostToShareGroup { group, host } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "edit".into(),
            "-n".into(),
            ".".into(),
            "-a".into(),
            host.0.clone(),
            "-t".into(),
            "user".into(),
            group.0.clone(),
        ],
        AccountOp::RemoveHostFromShareGroup { group, host } => vec![
            "sudo".into(),
            "dseditgroup".into(),
            "-o".into(),
            "edit".into(),
            "-n".into(),
            ".".into(),
            "-d".into(),
            host.0.clone(),
            "-t".into(),
            "user".into(),
            group.0.clone(),
        ],
    }
}

/// Compose the ACL entry string for `(group, mode)`. The bytes live in
/// `AclMode::acl_bits`; this function adds the `group:<g> allow ` prefix.
/// One source of truth so both `describe_acl` (operator-facing
/// rendering) and `execute_acl` (chmod argv) use the same form.
fn acl_entry(group: &str, mode: AclMode) -> String {
    format!("group:{group} allow {}", mode.acl_bits())
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
