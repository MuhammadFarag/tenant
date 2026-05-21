//! Destroy-verb error type, the eligibility classifier that gates
//! destroy at dispatch, and the `Tenants::destroy` /
//! `Tenants::destroy_orphan_group` orchestrators.

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

/// Failure surface for destroy. Unlike create, destroy has
/// no recovery path on Firewall reload failure — the symmetric "restore
/// from backup" would re-introduce a reference to the already-removed
/// anchor file, putting the host in a worse state.
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

/// Destroy-side classification. `OrphanGroup` is the user-absent /
/// suffixed-group-present residue from a prior partial failure.
/// `SystemAccount` is the account-present / no-positive-UID case
/// (filtered out of `uid_by_name` upstream, so the floor predicate
/// can't bind to a value).
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
        // PF teardown sits after account/profile cleanup so the tenant
        // can't open new sockets while we're tearing down their ruleset.
        // FlushAnchor is load-bearing: without it, the previous tenant's
        // rules persist in kernel memory under the orphaned anchor name
        // and the next tenant getting the same UID inherits them.
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

        // Remove the operator-side stashed password. Warn-and-
        // continue: a tenant created before keychain bootstrap landed
        // has no stash — `NotFound` is the convergent case (no `✓`
        // narration, since nothing actually mutated state). Other
        // failures are operator-side data we couldn't clean; surface
        // a warning but don't fail the whole verb.
        //
        // `step()` fires unconditionally — matches the verbose-mode
        // contract used by every other op ("`$` echo says what was
        // attempted, regardless of outcome"). `progress()` fires only
        // on Ok — matches `Tenants::run`'s semantics. On the
        // convergent NotFound path, the `$` line still emits in
        // verbose mode so operators scanning logs see the substrate
        // command that ran.
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

    /// Convergence path when the tenant user is already absent but the
    /// suffixed group (and possibly anchor / pf.conf reference) remain.
    /// Every step is substrate-idempotent so the path is single-pass.
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

        // Same operator-side stash cleanup as `destroy`. A tenant
        // that landed in OrphanGroup state via a partial create may
        // still have a stashed password; without this, the entry
        // lingers in the operator's keychain indefinitely. Same
        // warn-and-continue posture as the main destroy path:
        // `step()` fires unconditionally (verbose-mode `$` echo
        // matches every other op); `progress()` fires only on Ok.
        // `NotFound` is the convergent legacy-tenant case (no `✓`,
        // just the `$` line in verbose); other failures emit a
        // warning but don't fail the whole convergence path.
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

/// Probe the cowork dir at the tail of destroy. Host-side probe (no
/// sudo, no tenant impersonation) so it's timing-independent — the
/// tenant user has been deleted by now on the full path and was never
/// present on the orphan path; both converge here. Absence → silent
/// noop; `Dir | Symlink | Other` → "left intact" notice; probe error
/// → `⚠` stderr warning and destroy completes.
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
