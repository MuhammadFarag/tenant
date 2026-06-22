//! Production `HostMachine` substrate — macOS tool argv + XDG-style profile
//! path convention.

use std::env;
use std::fs;
use std::io;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclMode, AclOp, FirewallError,
    FirewallOp, GroupName, HostFileError, HostMachine, HostUserName, KeychainError, KeychainOp,
    KeychainPassword, PamOp, PathKind, ProbeError, ProfileOp, TenantUserName,
};
use crate::firewall::{PF_CONF, PF_CONF_BACKUP, tenant_anchor_path};
use crate::profile::{ProfileError, default_profile_toml, display_path_for};

/// `/etc/pam.d/sudo` — the system PAM stack for sudo. On modern macOS it
/// `include`s `sudo_local` as the first directive of its auth stack;
/// tenant never edits this file (OS updates overwrite it), only reads it
/// for detection.
const PAM_SUDO: &str = "/etc/pam.d/sudo";

/// `/etc/pam.d/sudo_local` — the OS-update-safe customization file
/// `/etc/pam.d/sudo` includes. The Touch-ID directive lands here.
const PAM_SUDO_LOCAL: &str = "/etc/pam.d/sudo_local";

/// Fixed backup path written before `setup` mutates `sudo_local`.
/// Parallels `PF_CONF_BACKUP` — deterministic, overwritten each apply.
const PAM_SUDO_LOCAL_BACKUP: &str = "/etc/pam.d/sudo_local.tenant-backup";

/// The canonical Touch-ID-for-sudo directive. `sufficient` short-circuits
/// the auth stack on a Touch ID hit and falls through to password on a
/// miss. Single source so `describe_pam`'s echo and `execute_pam`'s
/// appended bytes can't drift; `doctor::has_pam_tid` is whitespace-
/// tolerant so the single-space form is detected identically to the
/// tab-aligned form an operator might hand-write.
const PAM_TID_DIRECTIVE: &str = "auth sufficient pam_tid.so";

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
            AccountOp::EnsureCoworkDir {
                path,
                owner,
                group,
                mode,
            } => {
                // Four-call sequence; render one line per substrate
                // invocation so the verbose plan + `$` echo each carry
                // the complete mechanism. `acl_entry` matches the rw
                // AclMode bits so the inheritable grant lines up
                // byte-for-byte with a rw share's `chmod +a` entry.
                let path = path.display();
                let entry = acl_entry(group.as_str(), AclMode::Rw);
                format!(
                    "sudo mkdir -p {path}\n\
                     sudo chown {owner}:{group} {path}\n\
                     sudo chmod {mode:04o} {path}\n\
                     sudo chmod -R +a \"{entry}\" {path}"
                )
            }
        }
    }

    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        if let AccountOp::RemoveHostFromShareGroup { group, host } = op {
            // Idempotence: skip the `-d` edit when host isn't a current
            // member. dseditgroup `-d` on a non-member exits non-zero.
            if !self.host_in_group(host, group)? {
                return Ok(());
            }
        }
        if let AccountOp::EnsureCoworkDir {
            path,
            owner,
            group,
            mode,
        } = op
        {
            // Four substrate calls in sequence — every one is natively
            // idempotent on macOS: `mkdir -p` no-ops on an existing
            // directory, `chown` / `chmod` are state-setters, and the
            // recursive `chmod -R +a` ACL pass picks up tenant-added
            // children between reapply cycles. The rw bit list matches
            // what `AclMode::Rw` produces, so the cowork dir's
            // inheritable grant is byte-identical to a rw share's.
            return execute_ensure_cowork_dir(path, owner, group, *mode);
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
        // launched login shell can drive the controlling terminal.
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
        // The `--` separator in `sudo -iu <name> -- <argv...>` is
        // load-bearing — without it, an argv[0] starting with `-` would
        // be interpreted as a sudo flag.
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
                // Pretend-shell `tee … < default.toml` framing — no actual
                // tee invocation; the shape signals "a file landed here".
                format!("tee {} < default.toml", display_path_for(name.as_str()))
            }
            ProfileOp::Delete { name } => {
                // `rm -f` reflects the idempotent semantics — NotFound is
                // success.
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
                // Pretend-shell framing; actual mechanism in
                // `execute_firewall` is tempfile + sudo mv + sudo chmod.
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
        // `/bin/test -<flag> <path>` exit codes: 0 = Allowed,
        // 1 = Denied (includes file-doesn't-exist; mechanism-of-denial
        // is the remediation surface's job), ≥2 = Unknown.
        // /bin/test absolute path because /usr/bin/test is absent on
        // Darwin 25.x.
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
                // weird" (kernel state weird → Unknown).
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
        // /etc/sudoers is mode 0440 root:wheel — sudo required. Concatenate
        // primary + every drop-in with newlines so the parser's
        // `env_delete` grep can't bridge one file's last line into the
        // next's first.
        let primary = read_privileged_text("/etc/sudoers")?;
        let mut combined = primary;
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
        let listing_argv = sudoers_dropins_listing_argv();
        let listing_output = Command::new(&listing_argv[0])
            .args(&listing_argv[1..])
            .output()
            .map_err(HostFileError::Spawn)?;
        // Non-existent/unreadable /etc/sudoers.d/ → "no drop-ins", not a
        // hard failure; sudo doesn't require the dir to exist.
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
                // `rm -f` returns 0 on NotFound — partial-state destroy
                // doesn't trip here.
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
                // Failure here leaves a half-edited pf.conf with no
                // automated path back; `RestoreFailed` names the backup
                // path so the Reporter can emit the manual recovery hint.
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
                // `pfctl -e` exits non-zero with "pf already enabled" when
                // already on — treat that as success.
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
        let argv = kernel_pf_rules_argv(name.as_str());
        let output = Command::new(&argv[0])
            .args(&argv[1..])
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
        // /etc/pam.d/sudo is mode 0644 — direct fs read, no sudo.
        fs::read_to_string(PAM_SUDO).map_err(|e| HostFileError::Fs {
            path: PAM_SUDO.to_string(),
            message: e.to_string(),
        })
    }

    fn read_pam_sudo_local(&self) -> Result<String, HostFileError> {
        // /etc/pam.d/sudo_local is mode 0644 — direct fs read, no sudo.
        // Absent is the common case (no local customizations applied) and
        // is NOT an error: an empty body parses as "no pam_tid directive".
        match fs::read_to_string(PAM_SUDO_LOCAL) {
            Ok(body) => Ok(body),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(HostFileError::Fs {
                path: PAM_SUDO_LOCAL.to_string(),
                message: e.to_string(),
            }),
        }
    }

    fn read_pf_status(&self) -> Result<String, FirewallError> {
        let argv = pf_status_argv();
        let output = Command::new(&argv[0])
            .args(&argv[1..])
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
        // both into one blob for the parser.
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(combined)
    }

    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        // Mode 0644 root-owned — direct fs read, no sudo.
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
        // readlink stores the link entry verbatim — no intermediate
        // resolution; SymlinkDrift compares string-exact against the
        // declared host_path.
        //
        // Per-utility absolute paths because Darwin 25.x scatters them:
        // test at /bin/test (not /usr/bin/test), readlink at
        // /usr/bin/readlink (not /bin/readlink), ln at /bin/ln.
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
                // Codes other than 0/1 are sudo-auth failure.
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
        // `test -d` first so an existing directory comes back as Dir;
        // `test -e` then catches any other non-symlink entry (file,
        // fifo, socket, etc.) as Other.
        let dir_out = Command::new("sudo")
            .args(["-n", "-u", name.as_str(), "/bin/test", "-d", &path_str])
            .output()
            .map_err(ProbeError::Spawn)?;
        if let Some(0) = dir_out.status.code() {
            return Ok(PathKind::Dir);
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

    fn host_path_kind(&self, path: &std::path::Path) -> Result<PathKind, ProbeError> {
        // Direct fs read from the operator process — the cowork dir
        // (and any future host-owned path) is owned by the host with a
        // mode the operator can stat. No `sudo` shell-out, no
        // tenant-perspective probe; works uniformly whether the tenant
        // user exists or not. `symlink_metadata` (not `metadata`) so a
        // symlink at the path resolves as `Symlink(_)`, mirroring the
        // semantics of `tenant_path_kind`.
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                let ft = meta.file_type();
                if ft.is_symlink() {
                    let target = fs::read_link(path).map_err(ProbeError::Spawn)?;
                    Ok(PathKind::Symlink(target))
                } else if ft.is_dir() {
                    Ok(PathKind::Dir)
                } else {
                    Ok(PathKind::Other)
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(PathKind::Absent),
            Err(e) => Err(ProbeError::Spawn(e)),
        }
    }

    fn read_host_acl(&self, path: &std::path::Path) -> Result<String, ProbeError> {
        // Host-side ACL is host state — read from the operator process,
        // no sudo, no run-as-tenant. Unreadable path IS a substrate
        // failure: operator can't audit a path they can't list.
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
        // Literal double-quotes around the entry match the form an
        // operator would type at a prompt. Grant runs under `sudo`
        // (see `execute_acl` for the WHY); Revoke does not.
        let entry_str = |group: &GroupName, mode: AclMode| acl_entry(group.as_str(), mode);
        match op {
            AclOp::Grant {
                path, group, mode, ..
            } => format!(
                "sudo chmod -R +a \"{}\" {}",
                entry_str(group, *mode),
                path.display(),
            ),
            AclOp::Revoke {
                path, group, mode, ..
            } => format!(
                "chmod -a \"{}\" {}",
                entry_str(group, *mode),
                path.display(),
            ),
        }
    }

    fn execute_acl(&self, op: &AclOp) -> Result<(), AclError> {
        // Grant uses `sudo chmod -R +a` so the recursive ACL pass reaches
        // existing children regardless of ownership. Files created by
        // the tenant inside a rw share are tenant-owned (e.g.
        // `.ruff_cache/`, build artifacts, anything the tenant writes),
        // and POSIX requires owner-or-root to modify a file's ACL —
        // being in the share group with rw doesn't include
        // `writesecurity`. Without sudo, the second reapply after a
        // tenant has written into the share fails with EPERM on every
        // tenant-owned descendant. `chmod +a` is natively idempotent
        // (duplicate-add is a no-op per node), and macOS canonicalizes
        // bit names on storage (`read,write,execute` →
        // `list,add_file,search`), so any substring-match pre-check
        // would always miss — Grant runs unconditionally.
        //
        // Revoke stays bare: it's single-pass at the top-level of the
        // share host_path, which is host-owned by design. `chmod -R -a`
        // would fail on any tree node missing the ACE (e.g. files
        // copied in via `cp`, which doesn't preserve macOS ACLs).
        // Top-level revoke is the semantic operation; inherited child
        // ACEs become orphan-inert once the share group is removed
        // later in the destroy sequence.
        let (argv_prefix, path, group, mode): (&[&str], _, _, _) = match op {
            AclOp::Grant {
                path, group, mode, ..
            } => (&["sudo", "chmod", "-R", "+a"], path, group, mode),
            AclOp::Revoke {
                path, group, mode, ..
            } => (&["chmod", "-a"], path, group, mode),
        };
        let entry = acl_entry(group.as_str(), *mode);
        let path_str = path.display().to_string();
        let mut argv: Vec<&str> = argv_prefix.to_vec();
        argv.push(&entry);
        argv.push(&path_str);
        spawn_acl(&argv)
    }

    fn current_host_user_name(&self) -> HostUserName {
        // Under sudo, USER becomes `root` but SUDO_USER preserves the
        // real invoker — prefer it so `sudo tenant doctor` audits the
        // operator's home, not /Users/root/*. Fallback is a placeholder.
        HostUserName(
            env::var("SUDO_USER")
                .or_else(|_| env::var("USER"))
                .unwrap_or_else(|_| "operator".to_string()),
        )
    }

    fn describe_keychain(&self, op: &KeychainOp) -> String {
        // Password is fed on argv (`-p <pw>` / `-w <pw>`); the displayed
        // shell-line uses `<password>` as a literal redaction marker so
        // an operator who copies the line and runs it separately can
        // substitute their own value. Each provision sub-step renders
        // as its own one-line shell command — `Tenants::create` emits
        // the four in sequence; the plan-side rendering shows them in
        // order.
        match op {
            KeychainOp::CreateLoginKeychain { name, .. } => {
                format!("sudo -iu {name} security create-keychain -p <password> login.keychain-db")
            }
            KeychainOp::SetDefaultKeychain { name } => {
                format!("sudo -iu {name} security default-keychain -s login.keychain-db")
            }
            KeychainOp::AddKeychainToSearchList { name } => {
                format!("sudo -iu {name} security list-keychains -s login.keychain-db")
            }
            KeychainOp::DisableKeychainAutoLock { name } => {
                format!("sudo -iu {name} security set-keychain-settings login.keychain-db")
            }
            KeychainOp::StashPassword { name, .. } => {
                format!("security add-generic-password -U -a {name} -s tenant-{name} -w <password>")
            }
            KeychainOp::DeleteStashedPassword { name } => {
                format!("security delete-generic-password -a {name} -s tenant-{name}")
            }
        }
    }

    fn execute_keychain(&self, op: &KeychainOp) -> Result<(), KeychainError> {
        // Password lives on argv (`-p <pw>` / `-w <pw>`) — macOS
        // `security` does NOT support stdin reads on `-p` / `-w` (the
        // `-` argument is taken as a literal one-character password,
        // not a stdin sentinel). `-p password` appears briefly in
        // process args during the single `security` invocation; macOS
        // platform limit. Brief argv exposure (~milliseconds) is
        // accepted; alternative is the Security Framework C API via
        // FFI, which is out of scope for solo-Mac.
        //
        // Partial-failure recovery: the 4 variants are emitted
        // sequentially by `Tenants::create`; partial-state cleanup is
        // transitive via `tenant destroy`'s `sysadminctl -deleteUser`
        // moving the home to `/Users/Deleted Users/`. The
        // partially-provisioned `login.keychain-db` rides along with
        // the home, so no per-variant rollback is needed at the
        // substrate.
        //
        // `CreateLoginKeychain` exits non-zero with an "already exists"
        // stderr (historically code 25299 / errSecDuplicateKeychain,
        // but the exit code shifts across macOS versions — see
        // destroy's `errSecItemNotFound` 44 for the same family of
        // non-stable codes) when the tenant's `login.keychain-db` is
        // already present. This happens on retry after a partial
        // create, or on any re-run where the previous tenant's home
        // survived in `/Users/Deleted Users/` and the substrate is
        // somehow re-attached. Treat as convergent: same posture as
        // `pfctl -e "already enabled"` in execute_firewall and
        // `EnsureDirAsUser`'s `mkdir -p` semantics. Match on the
        // substring "already exists" (case-insensitive) because macOS
        // uses both "already exists" and "Already exists" across
        // versions; the exit code itself is not a stable contract. The
        // remaining three provision variants are natively idempotent
        // in macOS (they overwrite the user-pref entry) and are
        // re-applied unconditionally so the post-state is consistent
        // regardless of which leg of the sequence the previous attempt
        // died on.
        let kc = "login.keychain-db";
        match op {
            KeychainOp::CreateLoginKeychain { name, password } => {
                run_security_as_tenant_allowing_duplicate(
                    name.as_str(),
                    &["create-keychain", "-p", password.expose_secret(), kc],
                )
            }
            KeychainOp::SetDefaultKeychain { name } => {
                run_security_as_tenant(name.as_str(), &["default-keychain", "-s", kc])
            }
            KeychainOp::AddKeychainToSearchList { name } => {
                run_security_as_tenant(name.as_str(), &["list-keychains", "-s", kc])
            }
            KeychainOp::DisableKeychainAutoLock { name } => {
                run_security_as_tenant(name.as_str(), &["set-keychain-settings", kc])
            }
            KeychainOp::StashPassword { name, password } => {
                stash_password_in_operator_keychain(name, password)
            }
            KeychainOp::DeleteStashedPassword { name } => delete_stashed_password(name),
        }
    }

    fn describe_pam(&self, op: &PamOp) -> String {
        // "Pretend-shell" mechanism (same posture as `InstallAnchor`'s
        // `tee < anchor.body`): the real `execute_pam` backs up via
        // `sudo cp`, guards idempotency, and appends via a stdin-fed
        // `sudo tee -a` (no shell pipe). The echo shows the legible
        // two-step shape an operator could run by hand.
        match op {
            PamOp::EnableTouchIdForSudo => format!(
                "sudo cp {PAM_SUDO_LOCAL} {PAM_SUDO_LOCAL_BACKUP}\n\
                 echo '{PAM_TID_DIRECTIVE}' | sudo tee -a {PAM_SUDO_LOCAL}"
            ),
        }
    }

    fn execute_pam(&self, op: &PamOp) -> Result<(), HostFileError> {
        match op {
            PamOp::EnableTouchIdForSudo => {
                // A failed `sudo` read defaults to empty so detection still
                // falls through to sudo_local; the sudo_local read failure
                // (non-ENOENT) propagates. Both feed the pure
                // `pam_tid_append_payload` decision (idempotency +
                // newline-glue guard).
                let sudo = self.read_pam_sudo().unwrap_or_default();
                let sudo_local = self.read_pam_sudo_local()?;
                let Some(payload) = pam_tid_append_payload(&sudo, &sudo_local) else {
                    // Already enabled in either file — no-op so a duplicate
                    // directive never accumulates (the verb offers
                    // unconditionally; this is the substrate-side guard).
                    return Ok(());
                };
                // Back up sudo_local before mutating, if it exists (fresh
                // hosts have no sudo_local — nothing to back up; `tee -a`
                // below creates it).
                if Path::new(PAM_SUDO_LOCAL).exists() {
                    spawn_host_file(&[
                        "sudo".into(),
                        "cp".into(),
                        PAM_SUDO_LOCAL.into(),
                        PAM_SUDO_LOCAL_BACKUP.into(),
                    ])?;
                }
                // Append-only via stdin-fed `sudo tee -a` (no shell pipe);
                // creates sudo_local if absent, appends if present.
                append_privileged(PAM_SUDO_LOCAL, &payload)
            }
        }
    }

    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError> {
        // Exit 0 ⇒ member; any non-zero (host absent, group absent) ⇒
        // false — dseditgroup conflates these and the idempotence
        // contract doesn't need to distinguish.
        let output = Command::new("dseditgroup")
            .args(["-o", "checkmember", "-m", host.as_str(), group.as_str()])
            .output()
            .map_err(AccountError::Spawn)?;
        Ok(output.status.success())
    }

    fn sudo_session_cached(&self) -> bool {
        // `sudo -n -v` validates the cached timestamp without running
        // a command: exit 0 ⇒ a fresh timestamp exists, non-zero ⇒
        // none (or expired). The `-n` is load-bearing — this is the
        // one sudo call that MUST stay non-interactive, since its
        // whole job is to answer "would the next sudo prompt?" without
        // itself prompting. A spawn failure reads as "not cached" so
        // the gate fails closed.
        let argv = sudo_session_cached_argv();
        Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn tenant_keychain_present(&self, name: &TenantUserName) -> Result<bool, ProbeError> {
        // Existence check via `sudo -n -u <name> /bin/test -e <path>`
        // — NOT `std::fs::metadata` from the operator process. The
        // keychain file lives under `/Users/<tenant>/Library/`, which
        // is mode 0700 owned by the tenant; the operator can't
        // traverse into it, so a bare `metadata()` returns EACCES on
        // every healthy tenant and the probe never returns a verdict.
        // Running `test -e` AS THE TENANT lets the kernel resolve the
        // path inside the tenant's own permission cone — same shape
        // `tenant_path_kind` uses for its symlink/existence probes.
        //
        // Exit code map: 0 → present, 1 → absent, other → sudo-auth
        // failure (passwordless sudo not configured, terminal
        // required, etc.) surfaces as ProbeError::NonZero.
        let path = format!("/Users/{name}/Library/Keychains/login.keychain-db");
        let output = Command::new("sudo")
            .args(["-n", "-u", name.as_str(), "/bin/test", "-e", &path])
            .output()
            .map_err(ProbeError::Spawn)?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            Some(code) => Err(ProbeError::NonZero {
                code,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
            None => Err(ProbeError::NonZero {
                code: -1,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
        }
    }

    fn find_stashed_password(
        &self,
        name: &TenantUserName,
    ) -> Result<KeychainPassword, KeychainError> {
        // `security find-generic-password -a <name> -s tenant-<name> -w`
        // against the operator's keychain. `-w` writes the password
        // bytes to stdout. Exit code map mirrors `stash_present` /
        // `delete_stashed_password`: exit 44 (`errSecItemNotFound`) or
        // "could not be found" stderr ⇒ NotFound; anything else
        // non-zero ⇒ substrate failure.
        let service = format!("tenant-{name}");
        let output = Command::new("security")
            .args([
                "find-generic-password",
                "-a",
                name.as_str(),
                "-s",
                &service,
                "-w",
            ])
            .output()
            .map_err(KeychainError::Spawn)?;
        if output.status.success() {
            let raw = String::from_utf8_lossy(&output.stdout).into_owned();
            return Ok(KeychainPassword::from_existing(raw.trim().to_string()));
        }
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if code == 44 || stderr.contains("could not be found") {
            return Err(KeychainError::NotFound);
        }
        Err(KeychainError::NonZero { code, stderr })
    }

    fn unlock_tenant_keychain(
        &self,
        name: &TenantUserName,
        password: &KeychainPassword,
    ) -> Result<(), KeychainError> {
        // `sudo -iu <name> security unlock-keychain -p <pw>
        // login.keychain-db`. `-iu` is load-bearing on the same grounds
        // as the provision-flow `run_security_as_tenant` calls (HOME /
        // USER / PWD must switch to the tenant so the relative
        // `login.keychain-db` resolves under their Library/Keychains).
        // Password on argv — same platform-limit carve-out as
        // `create-keychain -p` (see provision comment block).
        //
        // Routes through `run_security_as_tenant` (same helper as every
        // other `sudo -iu <name> security ...` call site in this file)
        // so the prefix is built in one place. The unlock-specific tail
        // is extracted into `unlock_keychain_argv` for the byte-exact
        // test pin in `tests/macos_host_machine.rs`.
        let args = unlock_keychain_argv(password);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_security_as_tenant(name.as_str(), &refs)
    }

    fn stash_present(&self, name: &TenantUserName) -> Result<bool, KeychainError> {
        // `security find-generic-password -a <name> -s tenant-<name>`
        // against the operator's keychain. Exit 0 ⇒ present; exit 44
        // (`errSecItemNotFound`) or "could not be found" stderr ⇒
        // absent; anything else ⇒ substrate failure. Symmetric with
        // `delete_stashed_password`'s NotFound handling — same
        // exit-code convention.
        let service = format!("tenant-{name}");
        let output = Command::new("security")
            .args(["find-generic-password", "-a", name.as_str(), "-s", &service])
            .output()
            .map_err(KeychainError::Spawn)?;
        if output.status.success() {
            return Ok(true);
        }
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if code == 44 || stderr.contains("could not be found") {
            return Ok(false);
        }
        Err(KeychainError::NonZero { code, stderr })
    }
}

/// Privileged read of a host-config file (`/etc/sudoers` + drop-ins).
/// Bare sudo — NO `-n`. This is a doctor host-config read; the lead such
/// probe in the doctor flow prompts-and-caches at point of use so the
/// subsequent `-n` run-as-tenant probes ride the timestamp.
pub fn privileged_cat_argv(path: &str) -> Vec<String> {
    vec!["sudo".into(), "cat".into(), path.into()]
}

/// `/etc/sudoers.d` listing for `read_env_policy`. Same doctor
/// host-config-read class as `privileged_cat_argv` — bare sudo, no `-n`.
pub fn sudoers_dropins_listing_argv() -> Vec<String> {
    vec![
        "sudo".into(),
        "ls".into(),
        "-1".into(),
        "/etc/sudoers.d".into(),
    ]
}

/// `pfctl -si` for `read_pf_status`. Doctor host-config read — bare
/// sudo, no `-n`, so the lead privileged probe prompts-and-caches.
pub fn pf_status_argv() -> Vec<String> {
    vec!["sudo".into(), "pfctl".into(), "-si".into()]
}

/// `pfctl -a tenant-<name> -sr` for `read_kernel_pf_rules`. Doctor
/// host-config read — bare sudo, no `-n`. By the time this runs in the
/// doctor flow the lead host-config read has already populated the
/// timestamp, but it stays bare-sudo so ordering can't break it.
pub fn kernel_pf_rules_argv(name: &str) -> Vec<String> {
    vec![
        "sudo".into(),
        "pfctl".into(),
        "-a".into(),
        format!("tenant-{name}"),
        "-sr".into(),
    ]
}

/// `sudo -n -v` cache CHECK. KEEPS `-n` — its whole job is to answer
/// "would the next sudo prompt?" WITHOUT itself prompting. The one sudo
/// call that must stay non-interactive after the point-of-use change.
pub fn sudo_session_cached_argv() -> Vec<String> {
    vec!["sudo".into(), "-n".into(), "-v".into()]
}

fn read_privileged_text(path: &str) -> Result<String, HostFileError> {
    let argv = privileged_cat_argv(path);
    let output = Command::new(&argv[0])
        .args(&argv[1..])
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

/// Tempfile + `sudo mv` + `sudo chmod`. Atomic from the operator's
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

/// PID + nanos suffix avoids collision between concurrent tenant
/// invocations.
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

/// Spawn a privileged host-config command, mapping failure to
/// `HostFileError` (the shared host-config substrate error). Sibling of
/// `spawn_firewall`/`spawn_capturing` for the `PamOp` substrate.
fn spawn_host_file(argv: &[String]) -> Result<(), HostFileError> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| HostFileError::Spawn(io::Error::other("argv is empty")))?;
    let output = Command::new(program)
        .args(rest)
        .output()
        .map_err(HostFileError::Spawn)?;
    if !output.status.success() {
        return Err(HostFileError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

/// Decide what to append to `/etc/pam.d/sudo_local` to enable Touch ID.
/// `None` ⇒ `pam_tid` is already present in `sudo` OR `sudo_local`, so
/// enabling is a no-op (idempotent — never appends a duplicate). `Some`
/// payload ⇒ the exact bytes to append, with a leading-newline guard so a
/// final line lacking a trailing `\n` isn't glued onto the directive
/// (which would both malform the PAM stack and defeat the duplicate guard
/// on a later re-run). Pure so the idempotency + newline logic is unit-
/// testable without the substrate; `pub` for the pin in
/// `tests/macos_host_machine.rs`.
pub fn pam_tid_append_payload(sudo: &str, sudo_local: &str) -> Option<String> {
    if crate::doctor::has_pam_tid(sudo) || crate::doctor::has_pam_tid(sudo_local) {
        return None;
    }
    let lead = if !sudo_local.is_empty() && !sudo_local.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    Some(format!("{lead}{PAM_TID_DIRECTIVE}\n"))
}

/// Append `payload` (verbatim — the caller owns any leading/trailing
/// newlines, see `pam_tid_append_payload`) to a root-owned file via
/// `sudo tee -a`, feeding the bytes through the child's stdin so no shell
/// pipe is needed. Creates the file if absent.
fn append_privileged(path: &str, payload: &str) -> Result<(), HostFileError> {
    let mut child = Command::new("sudo")
        .args(["tee", "-a", path])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(HostFileError::Spawn)?;
    // Take + drop the stdin handle so `tee` sees EOF before we wait.
    // (`Child::wait` also closes stdin, but taking it here makes the
    // EOF-before-wait intent explicit and robust against future refactors.)
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| HostFileError::Spawn(io::Error::other("failed to open tee stdin")))?;
    stdin
        .write_all(payload.as_bytes())
        .map_err(HostFileError::Spawn)?;
    drop(stdin);
    let status = child.wait().map_err(HostFileError::Spawn)?;
    if !status.success() {
        return Err(HostFileError::NonZero {
            code: status.code().unwrap_or(-1),
            stderr: String::new(),
        });
    }
    Ok(())
}

fn op_name(op: &ProfileOp) -> &TenantUserName {
    match op {
        ProfileOp::Create { name } | ProfileOp::Delete { name } => name,
    }
}

/// `$HOME/.config/tenant/profiles/<name>.toml`. Display form with literal
/// `~` lives in `profile::display_path_for`.
fn profile_path(name: &TenantUserName) -> Result<PathBuf, ProfileError> {
    let home = env::var("HOME").map_err(|_| ProfileError {
        message: "HOME environment variable is not set".to_string(),
    })?;
    Ok(PathBuf::from(home)
        .join(".config/tenant/profiles")
        .join(format!("{name}.toml")))
}

/// Describe-side renders its own strings (byte-exact verbose output); this
/// builder stays separate so a change to one form doesn't silently drift
/// the other.
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
        AccountOp::EnsureCoworkDir { .. } => {
            panic!(
                "AccountOp::EnsureCoworkDir is a four-call sequence — \
                 execute via execute_ensure_cowork_dir, not account_argv"
            )
        }
    }
}

/// Cowork-dir provisioning: mkdir -p → chown → chmod 2770 → chmod -R +a.
/// Substrate-mechanism stays here so describe + execute share the same
/// argv composition.
fn execute_ensure_cowork_dir(
    path: &Path,
    owner: &HostUserName,
    group: &GroupName,
    mode: u32,
) -> Result<(), AccountError> {
    let path_str = path.display().to_string();
    let mode_arg = format!("{mode:04o}");
    let chown_arg = format!("{}:{}", owner.as_str(), group.as_str());
    let entry = acl_entry(group.as_str(), AclMode::Rw);
    let steps: [Vec<String>; 4] = [
        vec!["sudo".into(), "mkdir".into(), "-p".into(), path_str.clone()],
        vec!["sudo".into(), "chown".into(), chown_arg, path_str.clone()],
        vec!["sudo".into(), "chmod".into(), mode_arg, path_str.clone()],
        vec![
            "sudo".into(),
            "chmod".into(),
            "-R".into(),
            "+a".into(),
            entry,
            path_str,
        ],
    ];
    for step in &steps {
        spawn_capturing(step)?;
    }
    Ok(())
}

/// One source of truth so describe_acl and execute_acl render identically.
fn acl_entry(group: &str, mode: AclMode) -> String {
    format!("group:{group} allow {}", mode.acl_bits())
}

/// `run_security_as_tenant` variant that swallows the
/// duplicate-keychain failure as `Ok(())`. Used only by
/// `KeychainOp::CreateLoginKeychain` in `execute_keychain`; the other
/// three `security` sub-commands the provision flow drives are
/// natively idempotent on macOS and use the strict helper.
fn run_security_as_tenant_allowing_duplicate(
    tenant: &str,
    args: &[&str],
) -> Result<(), KeychainError> {
    match run_security_as_tenant(tenant, args) {
        Ok(()) => Ok(()),
        Err(KeychainError::NonZero { stderr, .. })
            if stderr.to_lowercase().contains("already exists") =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn stash_password_in_operator_keychain(
    name: &TenantUserName,
    password: &crate::domain::KeychainPassword,
) -> Result<(), KeychainError> {
    // `-U` upserts: replace any existing entry under the same
    // (account, service) so a re-run after a partial create doesn't
    // double-stash. `-w <pw>` on argv (not stdin) — same macOS
    // platform limit as `create-keychain`; see provision comment.
    let service = format!("tenant-{name}");
    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            name.as_str(),
            "-s",
            &service,
            "-w",
            password.expose_secret(),
        ])
        .output()
        .map_err(KeychainError::Spawn)?;
    if !output.status.success() {
        return Err(KeychainError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

fn delete_stashed_password(name: &TenantUserName) -> Result<(), KeychainError> {
    // `security delete-generic-password` exits 44 (`errSecItemNotFound`)
    // when the entry is absent. Map that to `NotFound` so destroy
    // converges on a legacy tenant.
    let service = format!("tenant-{name}");
    let output = Command::new("security")
        .args([
            "delete-generic-password",
            "-a",
            name.as_str(),
            "-s",
            &service,
        ])
        .output()
        .map_err(KeychainError::Spawn)?;
    if output.status.success() {
        return Ok(());
    }
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if code == 44 || stderr.contains("could not be found") {
        return Err(KeychainError::NotFound);
    }
    Err(KeychainError::NonZero { code, stderr })
}

/// Post-`sudo -iu <name> security` args for the keychain-unlock
/// substrate call — the tail consumed by `run_security_as_tenant`.
/// Single source of the unlock-specific argv shape: production
/// (`<MacosHostMachine as HostMachine>::unlock_tenant_keychain`) builds
/// it and feeds it to `run_security_as_tenant`; the byte-exact test pin
/// in `tests/macos_host_machine.rs` asserts on the same value. The
/// `sudo -iu <name> security` prefix is locked by
/// `run_security_as_tenant`'s own argv build and covered by its
/// sibling pins. `pub` so the integration test can reach it via
/// `tenant::adapters::macos::host_machine::unlock_keychain_argv`; not
/// re-exported from the `macos` module to keep it out of the prominent
/// public surface.
pub fn unlock_keychain_argv(password: &KeychainPassword) -> Vec<String> {
    vec![
        "unlock-keychain".to_string(),
        "-p".to_string(),
        password.expose_secret().to_string(),
        "login.keychain-db".to_string(),
    ]
}

fn run_security_as_tenant(tenant: &str, args: &[&str]) -> Result<(), KeychainError> {
    // `-iu` (login-shell + user) — NOT plain `-u`. `security
    // create-keychain login.keychain-db` resolves the relative path
    // against `$HOME`; bare `sudo -u <tenant>` preserves the
    // operator's HOME (so the call writes against
    // `/Users/<operator>/Library/Keychains/`, fails with
    // errSecWrPerm = code 195). `-i` switches HOME / USER / PWD to
    // the tenant's login environment, so the keychain lands at the
    // tenant's standard location: `/Users/<tenant>/Library/Keychains/login.keychain-db`.
    let mut argv = vec!["-iu", tenant, "security"];
    argv.extend_from_slice(args);
    let output = Command::new("sudo")
        .args(&argv)
        .output()
        .map_err(KeychainError::Spawn)?;
    if !output.status.success() {
        return Err(KeychainError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
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

fn spawn_acl(argv: &[&str]) -> Result<(), AclError> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| AclError::Spawn(io::Error::other("argv is empty")))?;
    let output = Command::new(program)
        .args(rest)
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
