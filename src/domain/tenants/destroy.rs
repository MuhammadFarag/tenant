use crate::allocation::TENANT_UID_FLOOR;
use crate::domain::host_machine::WritableOp;
use crate::domain::reporter::Reporter;
use crate::domain::{
    AccountError, AccountOp, FirewallError, FirewallOp, HostMachine, HostUserDirectory,
    HostUserName, KeychainError, KeychainOp, PathKind, ProfileOp, TenantUserName,
    UserDirectoryError, UserId,
};
use crate::firewall::remove_anchor_ref;
use crate::profile::ProfileError;

use super::{Tenants, cowork_dir_path, tenant_share_group_name};

/// No restore-from-backup on reload failure (unlike create): it would re-reference the
/// already-removed anchor file and leave the host worse off.
#[derive(Debug)]
pub(crate) enum DestroyError {
    Account(AccountError),
    Profile(ProfileError),
    Firewall(FirewallError),
}

impl From<AccountError> for DestroyError {
    fn from(e: AccountError) -> Self {
        DestroyError::Account(e)
    }
}

/// `OrphanGroup`: user gone, share group left by a partial create. `SystemAccount`:
/// present with no positive UID.
#[derive(Debug)]
pub enum Eligibility {
    Destroyable,
    NotPresent,
    OrphanGroup,
    NotATenant { uid: UserId },
    SystemAccount,
}

pub fn destroy_eligibility(
    directory: &dyn HostUserDirectory,
    name: &TenantUserName,
) -> Result<Eligibility, UserDirectoryError> {
    if !directory.has_user(name)? {
        if directory.has_group(&tenant_share_group_name(name.as_str()))? {
            return Ok(Eligibility::OrphanGroup);
        }
        return Ok(Eligibility::NotPresent);
    }
    Ok(match directory.uid_for(name)? {
        Some(uid) if uid.0 >= TENANT_UID_FLOOR => Eligibility::Destroyable,
        Some(uid) => Eligibility::NotATenant { uid },
        None => Eligibility::SystemAccount,
    })
}

impl<'a> Tenants<'a> {
    pub(crate) fn destroy(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        // PF teardown runs after account/profile cleanup so the tenant can't open new sockets
        // mid-teardown. FlushAnchor is load-bearing: pfctl doesn't GC an anchor whose
        // `load anchor` line was removed, so the next tenant with the same UID would inherit it.
        let group = tenant_share_group_name(name.as_str());
        let delete_user = AccountOp::DeleteTenantUser { name: name.into() };
        let probe = AccountOp::LookupUserRecord { name: name.into() };
        let cleanup = AccountOp::DeleteUserRecord { name: name.into() };
        let remove_host = AccountOp::RemoveHostFromShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        let delete_group = AccountOp::DeleteShareGroup { group };
        let delete_profile = ProfileOp::Delete { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let reload = FirewallOp::Reload;
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };

        reporter.destroy_starting(name);

        self.run(&delete_user, reporter)?;
        match self.run(&probe, reporter) {
            Ok(()) => {
                self.run(&cleanup, reporter)?;
            }
            Err(AccountError::NonZero { .. }) => {
                // Probe found directory service clean — no cleanup.
            }
            Err(other) => return Err(DestroyError::Account(other)),
        }

        // Hand-rolled instead of `self.run`: `NotFound` (nothing stashed) converges without a
        // ✓, and any other failure warns rather than failing the verb.
        let delete_stash = KeychainOp::DeleteStashedPassword { name: name.into() };
        reporter.step(delete_stash.op_ref());
        match self.machine.execute_keychain(&delete_stash) {
            Ok(()) => {
                reporter.progress(delete_stash.op_ref());
            }
            Err(KeychainError::NotFound) => {
                // Convergent: substrate ran, nothing stashed → no ✓.
            }
            Err(other) => {
                reporter.destroy_keychain_delete_warning(name, &other);
            }
        }

        self.run(&remove_host, reporter)?;
        self.run(&delete_group, reporter)?;
        self.run(&delete_profile, reporter)
            .map_err(DestroyError::Profile)?;

        let pf_conf_current = self
            .machine
            .read_pf_conf()
            .map_err(DestroyError::Firewall)?;
        let update_conf = FirewallOp::UpdateConfig {
            content: remove_anchor_ref(&pf_conf_current, name.as_str()),
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

        report_cowork_dir_if_present(self.machine, name, reporter);

        reporter.destroy_done(name);
        Ok(())
    }

    pub(crate) fn destroy_orphan_group(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<(), DestroyError> {
        let group = tenant_share_group_name(name.as_str());
        let remove_host = AccountOp::RemoveHostFromShareGroup {
            group: group.clone(),
            host: host.into(),
        };
        let delete_group = AccountOp::DeleteShareGroup { group };
        let delete_profile = ProfileOp::Delete { name: name.into() };
        let backup = FirewallOp::BackupConfig;
        let remove_anchor = FirewallOp::RemoveAnchor { name: name.into() };
        let reload = FirewallOp::Reload;
        let flush_anchor = FirewallOp::FlushAnchor { name: name.into() };

        reporter.orphan_group_starting(name);

        self.run(&remove_host, reporter)?;

        // TODO(smell): stash cleanup + PF teardown tail duplicate `destroy`; extract a shared helper
        // A partial create can leave a stash behind, so orphan cleanup removes it too.
        let delete_stash = KeychainOp::DeleteStashedPassword { name: name.into() };
        reporter.step(delete_stash.op_ref());
        match self.machine.execute_keychain(&delete_stash) {
            Ok(()) => {
                reporter.progress(delete_stash.op_ref());
            }
            Err(KeychainError::NotFound) => {
                // Convergent: substrate ran, nothing stashed → no ✓.
            }
            Err(other) => {
                reporter.destroy_keychain_delete_warning(name, &other);
            }
        }

        self.run(&delete_group, reporter)?;
        self.run(&delete_profile, reporter)
            .map_err(DestroyError::Profile)?;

        let pf_conf_current = self
            .machine
            .read_pf_conf()
            .map_err(DestroyError::Firewall)?;
        let update_conf = FirewallOp::UpdateConfig {
            content: remove_anchor_ref(&pf_conf_current, name.as_str()),
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

        report_cowork_dir_if_present(self.machine, name, reporter);

        reporter.orphan_group_done(name);
        Ok(())
    }
}

fn report_cowork_dir_if_present(
    machine: &dyn HostMachine,
    name: &TenantUserName,
    reporter: &mut Reporter,
) {
    let path = cowork_dir_path(name.as_str());
    match machine.host_path_kind(&path) {
        Ok(PathKind::Dir | PathKind::Symlink(_) | PathKind::Other) => {
            reporter.destroy_cowork_dir_intact(name, &path);
        }
        Ok(PathKind::Absent) => {}
        Err(err) => {
            reporter.destroy_cowork_probe_failed(name, &path, &err);
        }
    }
}
