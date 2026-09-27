use std::env;
use std::fs;
use std::io;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{
    AccessMode, AccessOutcome, AccountError, AccountOp, AclError, AclMode, AclOp, FirewallError,
    FirewallOp, GroupId, GroupName, HostFileError, HostMachine, HostUserName, KeychainError,
    KeychainOp, KeychainPassword, PamOp, PathKind, ProbeError, ProfileOp, SudoersOp,
    TENANT_KEYCHAIN_FILE, TenantUserName, tenant_keychain_path,
};
use crate::firewall::{
    PF_CONF, PF_CONF_BACKUP, is_anchor_referenced, tenant_anchor_name, tenant_anchor_path,
};
use crate::profile::{ProfileError, default_profile_toml, display_path_for};

/// Read-only: OS updates overwrite it. Customizations go in `sudo_local`, which it includes first.
const PAM_SUDO: &str = "/etc/pam.d/sudo";

const PAM_SUDO_LOCAL: &str = "/etc/pam.d/sudo_local";

/// Overwritten on each apply.
const PAM_SUDO_LOCAL_BACKUP: &str = "/etc/pam.d/sudo_local.tenant-backup";

/// `sufficient`: a Touch ID hit short-circuits the auth stack; a miss falls through to password.
const PAM_TID_DIRECTIVE: &str = "auth sufficient pam_tid.so";

/// A drop-in: macOS updates replace /etc/sudoers itself.
const SUDOERS_DROP_IN: &str = "/etc/sudoers.d/tenant";

/// Unqualified on purpose: a `Defaults>user` form doesn't cover `sudo -u <tenant>`.
const SSH_AUTH_SOCK_ENV_DELETE: &str = "Defaults env_delete += \"SSH_AUTH_SOCK\"";

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
            // With a dir, render the real argv: the adapter-composed script is shell-exact.
            AccountOp::LoginAsUser { name, dir } => match dir {
                Some(_) => render_argv(&account_argv(op)),
                None => format!("sudo -iu {name}"),
            },
            AccountOp::ExecAsUser { .. } => render_argv(&account_argv(op)),
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
                let path = path.display();
                let entry = acl_entry(group.as_str(), AclMode::Rw);
                format!(
                    "sudo mkdir -p {path}\n\
                     sudo chown {owner}:{group} {path}\n\
                     sudo chmod {mode:04o} {path}\n\
                     sudo chmod -R +a \"{entry}\" {path}"
                )
            }
            AccountOp::EnsurePrimaryGroup { name, gid } => {
                format!("sudo dscl . -create /Users/{name} PrimaryGroupID {gid}")
            }
        }
    }

    fn execute_account(&self, op: &AccountOp) -> Result<(), AccountError> {
        if let AccountOp::RemoveHostFromShareGroup { group, host } = op {
            // dseditgroup `-d` on a non-member exits non-zero.
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

    fn login(&self, name: &TenantUserName, dir: Option<&Path>) -> Result<i32, AccountError> {
        // Inherited stdio: sudo may prompt, and the login shell drives the tty.
        let argv = account_argv(&AccountOp::LoginAsUser {
            name: name.clone(),
            dir: dir.map(Path::to_path_buf),
        });
        let (program, rest) = argv
            .split_first()
            .ok_or_else(|| AccountError::Spawn(io::Error::other("argv is empty")))?;
        let status = Command::new(program)
            .args(rest)
            .status()
            .map_err(AccountError::Spawn)?;
        Ok(status.code().unwrap_or(1))
    }

    fn exec_as_tenant(
        &self,
        name: &TenantUserName,
        argv: &[String],
        dir: Option<&Path>,
    ) -> Result<i32, AccountError> {
        // `--` is load-bearing: an argv[0] starting with `-` would parse as a sudo flag.
        let full = account_argv(&AccountOp::ExecAsUser {
            name: name.clone(),
            argv: argv.to_vec(),
            dir: dir.map(Path::to_path_buf),
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
                // Pretend-shell: no tee runs; the shape signals a file landing here.
                format!("tee {} < default.toml", display_path_for(name.as_str()))
            }
            ProfileOp::Delete { name } => {
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

    fn read_profile_fragment(&self, fragment: &str) -> Result<String, ProfileError> {
        let path = profile_fragment_path(fragment)?;
        fs::read_to_string(&path).map_err(|e| ProfileError {
            message: e.to_string(),
        })
    }

    fn read_share_group_gid(&self, group: &GroupName) -> Result<GroupId, ProbeError> {
        read_primary_group_id(&share_group_gid_argv(group.as_str()))
    }

    fn read_user_primary_gid(&self, name: &TenantUserName) -> Result<GroupId, ProbeError> {
        read_primary_group_id(&user_primary_gid_argv(name.as_str()))
    }

    fn describe_firewall(&self, op: &FirewallOp) -> String {
        match op {
            FirewallOp::InstallAnchor { name, .. } => {
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

    fn pf_conf_references_anchor(&self, name: &TenantUserName) -> Result<bool, FirewallError> {
        Ok(is_anchor_referenced(&self.read_pf_conf()?, name.as_str()))
    }

    fn probe_access_as_tenant(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
        mode: AccessMode,
    ) -> Result<AccessOutcome, ProbeError> {
        // Denied also covers a nonexistent path.
        let flag = match mode {
            AccessMode::Read => "-r",
            AccessMode::List => "-x",
        };
        let argv = file_test_as_tenant_argv(name.as_str(), flag, &path.to_string_lossy());
        Ok(if run_file_test_as_tenant(&argv)? {
            AccessOutcome::Allowed
        } else {
            AccessOutcome::Denied
        })
    }

    fn read_env_policy(&self) -> Result<String, HostFileError> {
        // Newline-join the files so the `env_delete` grep can't bridge one
        // file's last line into the next's first.
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
        // sudo doesn't require /etc/sudoers.d to exist; absent means no drop-ins.
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
            FirewallOp::RemoveAnchor { name } => spawn_firewall(&[
                "sudo".into(),
                "rm".into(),
                "-f".into(),
                tenant_anchor_path(name.as_str()),
            ]),
            FirewallOp::BackupConfig => spawn_firewall(&[
                "sudo".into(),
                "cp".into(),
                PF_CONF.into(),
                PF_CONF_BACKUP.into(),
            ]),
            FirewallOp::RestoreConfigFromBackup => {
                // A failed restore leaves pf.conf half-edited with no automated
                // way back; `RestoreFailed` names the backup for manual recovery.
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
                // `pfctl -e` exits non-zero with "already enabled" when pf is on.
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
        read_firewall_stdout(&kernel_pf_rules_argv(name.as_str()))
    }

    fn read_kernel_pf_table(
        &self,
        name: &TenantUserName,
        table: &str,
    ) -> Result<String, FirewallError> {
        read_firewall_stdout(&kernel_pf_table_argv(name.as_str(), table))
    }

    fn resolve_host(&self, host: &str) -> Result<Vec<std::net::IpAddr>, ProbeError> {
        use std::net::ToSocketAddrs;
        let mut ips: Vec<std::net::IpAddr> = Vec::new();
        for addr in (host, 0).to_socket_addrs().map_err(ProbeError::Spawn)? {
            if !ips.contains(&addr.ip()) {
                ips.push(addr.ip());
            }
        }
        Ok(ips)
    }

    fn read_pam_sudo(&self) -> Result<String, HostFileError> {
        // /etc/pam.d/sudo is mode 0644 — direct fs read, no sudo.
        fs::read_to_string(PAM_SUDO).map_err(|e| HostFileError::Fs {
            path: PAM_SUDO.to_string(),
            message: e.to_string(),
        })
    }

    fn read_pam_sudo_local(&self) -> Result<String, HostFileError> {
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
        // `pfctl -si` prints the Status line on stderr in practice; parse both streams.
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(combined)
    }

    fn read_anchor_body(&self, name: &TenantUserName) -> Result<String, HostFileError> {
        // Mode 0644 root-owned — direct fs read, no sudo.
        let path = crate::firewall::tenant_anchor_path(name.as_str());
        match fs::read_to_string(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            read => read.map_err(|e| HostFileError::Fs {
                path,
                message: e.to_string(),
            }),
        }
    }

    fn tenant_path_kind(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<PathKind, ProbeError> {
        // Link target verbatim, unresolved: SymlinkDrift compares string-exact.
        // `/usr/bin/readlink`, not `/bin`: Darwin 25.x scatters utilities.
        let path_str = path.to_string_lossy().into_owned();
        let file_test = |flag: &str| {
            run_file_test_as_tenant(&file_test_as_tenant_argv(name.as_str(), flag, &path_str))
        };
        if file_test("-L")? {
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
        if file_test("-d")? {
            return Ok(PathKind::Dir);
        }
        Ok(if file_test("-e")? {
            PathKind::Other
        } else {
            PathKind::Absent
        })
    }

    fn tenant_dir_present(
        &self,
        name: &TenantUserName,
        path: &std::path::Path,
    ) -> Result<bool, ProbeError> {
        // `test -d` follows symlinks, so a dangling link answers false —
        // which is what `cd` will do too.
        run_file_test_as_tenant(&file_test_as_tenant_argv(
            name.as_str(),
            "-d",
            &path.to_string_lossy(),
        ))
    }

    fn host_path_kind(&self, path: &std::path::Path) -> Result<PathKind, ProbeError> {
        // `symlink_metadata` so a link reads as `Symlink(_)`, matching `tenant_path_kind`.
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
        // Unreadable is a substrate failure: the operator can't audit what they can't list.
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

    fn read_host_acl_tree(&self, path: &std::path::Path) -> Result<String, ProbeError> {
        let output = Command::new("/bin/ls")
            .arg("-leRA")
            .arg(path)
            .output()
            .map_err(ProbeError::Spawn)?;
        // Exit 1 is ls's "minor problem" (an unreadable subdirectory); the rest still audits.
        match output.status.code() {
            Some(0 | 1) => Ok(String::from_utf8_lossy(&output.stdout).into_owned()),
            code => Err(ProbeError::NonZero {
                code: code.unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
        }
    }

    fn describe_acl(&self, op: &AclOp) -> String {
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
        // Grant needs `sudo`: files the tenant writes into a rw share are tenant-owned,
        // and only owner-or-root may change an ACL, so a bare second reapply EPERMs.
        // It runs unconditionally: `chmod +a` is idempotent per node, and macOS
        // canonicalizes bit names on storage, so a substring pre-check would always
        // miss. macOS doesn't dedupe direct vs inherited ACEs, so nodes present at
        // apply time show two entries — bounded and inert.
        //
        // Revoke stays bare and top-level only: the share root is host-owned, and
        // `chmod -R -a` fails on any node missing the ACE (e.g. `cp`'d files). Child
        // ACEs go inert once destroy removes the share group.
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
        // Under sudo, USER is `root`; SUDO_USER keeps the real invoker, so
        // `sudo tenant doctor` audits the operator's home, not /Users/root.
        HostUserName(
            env::var("SUDO_USER")
                .or_else(|_| env::var("USER"))
                .unwrap_or_else(|_| "operator".to_string()),
        )
    }

    fn describe_keychain(&self, op: &KeychainOp) -> String {
        match op {
            KeychainOp::CreateTenantKeychain { name, .. } => {
                format!(
                    "sudo -iu {name} security create-keychain -p <password> {TENANT_KEYCHAIN_FILE}"
                )
            }
            KeychainOp::SetDefaultKeychain { name } => {
                format!("sudo -iu {name} security default-keychain -s {TENANT_KEYCHAIN_FILE}")
            }
            KeychainOp::AddKeychainToSearchList { name } => {
                format!("sudo -iu {name} security list-keychains -s {TENANT_KEYCHAIN_FILE}")
            }
            KeychainOp::DisableKeychainAutoLock { name } => {
                format!("sudo -iu {name} security set-keychain-settings {TENANT_KEYCHAIN_FILE}")
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
        // Password on argv: `security` has no stdin mode for `-p`/`-w` (`-` is taken
        // as a literal password). The brief argv exposure is accepted; the
        // alternative is Security.framework FFI.
        //
        // No per-variant rollback: `tenant destroy` moves the home — and a half-built
        // keychain with it — to /Users/Deleted Users/.
        //
        // `CreateTenantKeychain` on an existing keychain (retry after a partial create)
        // converges. Match "already exists" case-insensitively: macOS varies the casing,
        // and the exit code (historically 25299) isn't stable. The other three calls
        // overwrite, so they're natively idempotent.
        match op {
            KeychainOp::CreateTenantKeychain { name, password } => {
                run_security_as_tenant_allowing_duplicate(
                    name.as_str(),
                    &[
                        "create-keychain",
                        "-p",
                        password.expose_secret(),
                        TENANT_KEYCHAIN_FILE,
                    ],
                )
            }
            KeychainOp::SetDefaultKeychain { name } => run_security_as_tenant(
                name.as_str(),
                &["default-keychain", "-s", TENANT_KEYCHAIN_FILE],
            ),
            KeychainOp::AddKeychainToSearchList { name } => run_security_as_tenant(
                name.as_str(),
                &["list-keychains", "-s", TENANT_KEYCHAIN_FILE],
            ),
            KeychainOp::DisableKeychainAutoLock { name } => run_security_as_tenant(
                name.as_str(),
                &["set-keychain-settings", TENANT_KEYCHAIN_FILE],
            ),
            KeychainOp::StashPassword { name, password } => {
                stash_password_in_operator_keychain(name, password)
            }
            KeychainOp::DeleteStashedPassword { name } => delete_stashed_password(name),
        }
    }

    fn describe_pam(&self, op: &PamOp) -> String {
        // Pretend-shell: the real execute backs up, guards idempotency, and
        // appends via stdin-fed `sudo tee -a`.
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
                let sudo = self.read_pam_sudo().unwrap_or_default();
                let sudo_local = self.read_pam_sudo_local()?;
                let Some(payload) = pam_tid_append_payload(&sudo, &sudo_local) else {
                    return Ok(());
                };
                if Path::new(PAM_SUDO_LOCAL).exists() {
                    spawn_host_file(&[
                        "sudo".into(),
                        "cp".into(),
                        PAM_SUDO_LOCAL.into(),
                        PAM_SUDO_LOCAL_BACKUP.into(),
                    ])?;
                }
                append_privileged(PAM_SUDO_LOCAL, &payload)
            }
        }
    }

    fn describe_sudoers(&self, op: &SudoersOp) -> String {
        match op {
            SudoersOp::DeleteSshAuthSockEnv => format!(
                "echo '{SSH_AUTH_SOCK_ENV_DELETE}' >> <tmp copy of {SUDOERS_DROP_IN}>\n\
                 sudo visudo -cf <tmp>\n\
                 sudo install -o root -g wheel -m 0440 <tmp> {SUDOERS_DROP_IN}"
            ),
        }
    }

    fn execute_sudoers(&self, op: &SudoersOp) -> Result<(), HostFileError> {
        match op {
            SudoersOp::DeleteSshAuthSockEnv => {
                if crate::doctor::has_env_delete_for(&self.read_env_policy()?, "SSH_AUTH_SOCK") {
                    return Ok(());
                }
                let existing = if Path::new(SUDOERS_DROP_IN).exists() {
                    read_privileged_text(SUDOERS_DROP_IN)?
                } else {
                    String::new()
                };
                let Some(content) = sudoers_drop_in_content(&existing) else {
                    return Ok(());
                };
                let tmp_path = tempfile_path();
                fs::write(&tmp_path, content).map_err(|e| HostFileError::Fs {
                    path: tmp_path.display().to_string(),
                    message: e.to_string(),
                })?;
                // A drop-in sudo can't parse breaks sudo host-wide: validate before install.
                let result = sudoers_install_argv(&tmp_path.display().to_string())
                    .iter()
                    .try_for_each(|argv| spawn_host_file(argv));
                let _ = fs::remove_file(&tmp_path);
                result
            }
        }
    }

    fn host_in_group(&self, host: &HostUserName, group: &GroupName) -> Result<bool, AccountError> {
        // dseditgroup conflates non-member, absent host, and absent group; all read false.
        let output = Command::new("dseditgroup")
            .args(["-o", "checkmember", "-m", host.as_str(), group.as_str()])
            .output()
            .map_err(AccountError::Spawn)?;
        Ok(output.status.success())
    }

    fn sudo_session_cached(&self) -> bool {
        let argv = sudo_session_cached_argv();
        Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn authenticate_sudo(&self) -> Result<(), ProbeError> {
        // Inherited stdio: sudo prompts on the tty.
        let argv = authenticate_sudo_argv();
        let status = Command::new(&argv[0])
            .args(&argv[1..])
            .status()
            .map_err(ProbeError::Spawn)?;
        if status.success() {
            return Ok(());
        }
        Err(ProbeError::NonZero {
            code: status.code().unwrap_or(-1),
            stderr: String::new(),
        })
    }

    fn tenant_keychain_present(&self, name: &TenantUserName) -> Result<bool, ProbeError> {
        run_file_test_as_tenant(&tenant_keychain_present_argv(name.as_str()))
    }

    // TODO(smell): errSecItemNotFound (44) classification is copied in stash_present and delete_stashed_password — extract
    fn find_stashed_password(
        &self,
        name: &TenantUserName,
    ) -> Result<KeychainPassword, KeychainError> {
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
        let args = unlock_keychain_argv(password);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_security_as_tenant(name.as_str(), &refs)
    }

    fn stash_present(&self, name: &TenantUserName) -> Result<bool, KeychainError> {
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

/// Doctor host-config reads use bare sudo, no `-n`: the first one prompts and caches,
/// so the later `sudo -n -u <tenant>` probes ride the timestamp regardless of order.
pub fn privileged_cat_argv(path: &str) -> Vec<String> {
    vec!["sudo".into(), "cat".into(), path.into()]
}

pub fn sudoers_dropins_listing_argv() -> Vec<String> {
    vec![
        "sudo".into(),
        "ls".into(),
        "-1".into(),
        "/etc/sudoers.d".into(),
    ]
}

pub fn share_group_gid_argv(group: &str) -> Vec<String> {
    primary_group_id_argv(&format!("/Groups/{group}"))
}

pub fn user_primary_gid_argv(name: &str) -> Vec<String> {
    primary_group_id_argv(&format!("/Users/{name}"))
}

fn primary_group_id_argv(record: &str) -> Vec<String> {
    vec![
        "dscl".into(),
        ".".into(),
        "-read".into(),
        record.into(),
        "PrimaryGroupID".into(),
    ]
}

/// Unparseable ⇒ error, never a fabricated gid that would silently re-point the tenant's
/// primary group.
fn read_primary_group_id(argv: &[String]) -> Result<GroupId, ProbeError> {
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(ProbeError::Spawn)?;
    let command = argv.join(" ");
    if !output.status.success() {
        return Err(ProbeError::NonZero {
            code: output.status.code().unwrap_or(-1),
            stderr: format!("`{command}`: {}", String::from_utf8_lossy(&output.stderr)),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next_back()
        .and_then(|tok| tok.parse::<u32>().ok())
        .map(GroupId)
        .ok_or_else(|| ProbeError::NonZero {
            code: -1,
            stderr: format!("unparseable output from `{command}`: {stdout:?}"),
        })
}

pub fn pf_status_argv() -> Vec<String> {
    vec!["sudo".into(), "pfctl".into(), "-si".into()]
}

fn read_firewall_stdout(argv: &[String]) -> Result<String, FirewallError> {
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

pub fn kernel_pf_table_argv(name: &str, table: &str) -> Vec<String> {
    vec![
        "sudo".into(),
        "pfctl".into(),
        "-a".into(),
        tenant_anchor_name(name),
        "-t".into(),
        table.into(),
        "-T".into(),
        "show".into(),
    ]
}

pub fn kernel_pf_rules_argv(name: &str) -> Vec<String> {
    vec![
        "sudo".into(),
        "pfctl".into(),
        "-a".into(),
        format!("tenant-{name}"),
        "-sr".into(),
    ]
}

/// `sudo -n` reports "a password/terminal is required" with exit 1 — the same code
/// as `test`'s "no". Exit 1 is a verdict only when stderr is empty.
pub fn sudo_test_verdict(output: &Output) -> Result<bool, ProbeError> {
    match (output.status.code(), output.stderr.is_empty()) {
        (Some(0), _) => Ok(true),
        (Some(1), true) => Ok(false),
        (code, _) => Err(ProbeError::NonZero {
            code: code.unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }),
    }
}

pub fn tenant_keychain_present_argv(name: &str) -> Vec<String> {
    file_test_as_tenant_argv(name, "-e", &tenant_keychain_path(name))
}

/// As the tenant, not `fs::metadata`: tenant paths like `~/Library` are 0700 to the
/// operator. `/bin/test` because `/usr/bin/test` is absent on Darwin 25.x.
fn file_test_as_tenant_argv(name: &str, flag: &str, path: &str) -> Vec<String> {
    vec![
        "sudo".into(),
        "-n".into(),
        "-u".into(),
        name.into(),
        "/bin/test".into(),
        flag.into(),
        path.into(),
    ]
}

fn run_file_test_as_tenant(argv: &[String]) -> Result<bool, ProbeError> {
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(ProbeError::Spawn)?;
    sudo_test_verdict(&output)
}

pub fn authenticate_sudo_argv() -> Vec<String> {
    vec!["sudo".into(), "-v".into()]
}

/// `-n` is load-bearing: asks whether sudo would prompt, without prompting.
pub fn sudo_session_cached_argv() -> Vec<String> {
    vec!["sudo".into(), "-n".into(), "-v".into()]
}

/// `None` when the drop-in already carries the directive.
pub fn sudoers_drop_in_content(existing: &str) -> Option<String> {
    if crate::doctor::has_env_delete_for(existing, "SSH_AUTH_SOCK") {
        return None;
    }
    let mut content = existing.to_string();
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(SSH_AUTH_SOCK_ENV_DELETE);
    content.push('\n');
    Some(content)
}

pub fn sudoers_install_argv(tmp: &str) -> [Vec<String>; 2] {
    [
        vec!["sudo".into(), "visudo".into(), "-cf".into(), tmp.into()],
        [
            "sudo",
            "install",
            "-o",
            "root",
            "-g",
            "wheel",
            "-m",
            "0440",
            tmp,
            SUDOERS_DROP_IN,
        ]
        .map(String::from)
        .into(),
    ]
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

/// Tempfile + `sudo mv`, so the file lands whole or not at all.
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

    let result = privileged_install_argv(&tmp_path.display().to_string(), path)
        .iter()
        .try_for_each(|argv| spawn_firewall(argv));
    let _ = fs::remove_file(&tmp_path);
    result
}

/// rename(2) keeps the tempfile's operator ownership, so `mv` alone leaves the target
/// writable without sudo. Owner and mode are set on the tempfile so the rename lands the
/// finished file in one step.
pub fn privileged_install_argv(tmp: &str, path: &str) -> [Vec<String>; 3] {
    [
        vec![
            "sudo".into(),
            "chown".into(),
            "root:wheel".into(),
            tmp.into(),
        ],
        vec!["sudo".into(), "chmod".into(), "0644".into(), tmp.into()],
        vec!["sudo".into(), "mv".into(), tmp.into(), path.into()],
    ]
}

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

// TODO(smell): pub only for tests/macos_host_machine.rs pins — narrow visibility or move the pin
/// `None` when `pam_tid` is already in `sudo` or `sudo_local`. Otherwise the bytes to
/// append, led by a newline when needed so an unterminated last line isn't glued onto
/// the directive (malforming the stack and defeating the duplicate check on re-run).
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

/// `sudo tee -a` fed through stdin (no shell pipe); `payload` is appended verbatim.
fn append_privileged(path: &str, payload: &str) -> Result<(), HostFileError> {
    let mut child = Command::new("sudo")
        .args(["tee", "-a", path])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(HostFileError::Spawn)?;
    // Drop stdin so `tee` sees EOF before we wait.
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

// TODO(smell): profile paths are spelled here and again in profile::display_path_for / display_fragment_path_for — one builder
fn profile_path(name: &TenantUserName) -> Result<PathBuf, ProfileError> {
    let home = env::var("HOME").map_err(|_| ProfileError {
        message: "HOME environment variable is not set".to_string(),
    })?;
    Ok(PathBuf::from(home)
        .join(".config/tenant/profiles")
        .join(format!("{name}.toml")))
}

fn profile_fragment_path(fragment: &str) -> Result<PathBuf, ProfileError> {
    let home = env::var("HOME").map_err(|_| ProfileError {
        message: "HOME environment variable is not set".to_string(),
    })?;
    Ok(PathBuf::from(home)
        .join(".config/tenant/profiles/includes")
        .join(format!("{fragment}.toml")))
}

/// `sudo -i` always lands in the tenant's home and sudo's `--chdir` is sudoers-gated
/// on macOS, so `tenant shell -d` changes directory in this inner shell.
fn sudo_sh_argv(name: &TenantUserName, tail: &[String]) -> Vec<String> {
    let mut full = vec![
        "sudo".into(),
        "-iu".into(),
        name.0.clone(),
        "--".into(),
        "/bin/sh".into(),
        "-c".into(),
    ];
    full.extend(tail.iter().cloned());
    full
}

fn cd_wrapper(dir: &Path, exec_tail: &str) -> String {
    format!("cd {} && {exec_tail}", sh_quote(&dir.display().to_string()))
}

/// POSIX single-quoting. Bare words stay unquoted so the display reads as typed;
/// an embedded `'` becomes `'\''` (no escapes exist inside single quotes).
fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn render_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| sh_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

// TODO(smell): pub only for test pins, and describe_account hand-builds the same shapes — derive describe from this
pub fn account_argv(op: &AccountOp) -> Vec<String> {
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
        AccountOp::LoginAsUser { name, dir } => match dir {
            // `$SHELL` stays single-quoted so it expands tenant-side, where
            // `sudo -i` has already set it to the tenant's login shell.
            Some(dir) => sudo_sh_argv(name, &[cd_wrapper(dir, "exec \"$SHELL\"")]),
            None => vec!["sudo".into(), "-iu".into(), name.0.clone()],
        },
        AccountOp::ExecAsUser { name, argv, dir } => {
            // Not `sudo -i`: it joins the argv into one string for the login shell,
            // which re-expands every `$` in the command before it runs.
            let cd = dir.as_deref().map_or("cd \"$HOME\"".to_string(), |d| {
                format!("cd {}", sh_quote(&d.display().to_string()))
            });
            let mut full: Vec<String> =
                ["sudo", "-H", "-u", name.0.as_str(), "--", "/bin/zsh", "-lc"]
                    .map(String::from)
                    .into();
            full.push(format!("{cd} && exec \"$@\""));
            full.push("zsh".into());
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
        AccountOp::EnsurePrimaryGroup { name, gid } => vec![
            "sudo".into(),
            "dscl".into(),
            ".".into(),
            "-create".into(),
            format!("/Users/{name}"),
            "PrimaryGroupID".into(),
            gid.to_string(),
        ],
    }
}

/// Every step is idempotent; the recursive ACL pass picks up children the tenant
/// added since the last reapply.
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

fn acl_entry(group: &str, mode: AclMode) -> String {
    format!("group:{group} allow {}", mode.acl_bits())
}

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
    // `-U` upserts, so a re-run after a partial create doesn't double-stash.
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

// TODO(smell): pub only for tests/macos_host_machine.rs pins — narrow visibility or move the pin
/// Tail after `sudo -iu <name> security` for the keychain unlock.
pub fn unlock_keychain_argv(password: &KeychainPassword) -> Vec<String> {
    vec![
        "unlock-keychain".to_string(),
        "-p".to_string(),
        password.expose_secret().to_string(),
        TENANT_KEYCHAIN_FILE.to_string(),
    ]
}

fn run_security_as_tenant(tenant: &str, args: &[&str]) -> Result<(), KeychainError> {
    // `-iu`, not `-u`: `security` resolves `tenant.keychain-db` against `$HOME`,
    // and bare `-u` keeps the operator's HOME (errSecWrPerm, code 195).
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
