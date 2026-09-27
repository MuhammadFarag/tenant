use crate::ModeLevel;
use crate::doctor::{
    Finding, SymlinkActual, anchor_body_matches, classify_inbound_exposure, curated_paths,
    has_env_delete_for, has_group_acl_entry, has_pam_tid, pf_rule_presence_check,
    pf_status_enabled,
};
use crate::domain::reporter::Reporter;
use crate::domain::{
    FirewallError, HostFileError, HostUserDirectory, HostUserName, PathKind, ProbeError,
    TenantUserName, UserDirectoryError,
};
use crate::firewall::{anchor_is_permissive, render_anchor};
use crate::profile::expand_tenant_path;

use super::reapply::{hosts_for_level, steady_inbound_rules};
use super::{Tenants, tenant_share_group_name};

/// Per-verb relevance matrix for `pre_exec_doctor_summary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DoctorScope {
    Create,
    Shell,
    Mode,
    Reload,
}

#[derive(Debug)]
pub(crate) enum DoctorError {
    Probe(ProbeError),
    HostFile(HostFileError),
    Firewall(FirewallError),
    UserDirectoryLookup(UserDirectoryError),
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

impl From<UserDirectoryError> for DoctorError {
    fn from(e: UserDirectoryError) -> Self {
        DoctorError::UserDirectoryLookup(e)
    }
}

#[derive(Debug, Default)]
pub(crate) struct DoctorOutcome {
    pub findings: Vec<Finding>,
}

impl DoctorOutcome {
    pub fn max_severity(&self) -> Option<crate::doctor::Severity> {
        self.findings.iter().map(|f| f.severity()).max()
    }
}

impl<'a> Tenants<'a> {
    /// `others`: the host's other tenants, for cross-tenant probes.
    pub(crate) fn doctor(
        &self,
        host: &HostUserName,
        name: &TenantUserName,
        others: &[&TenantUserName],
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

    pub(crate) fn doctor_all(
        &self,
        host: &HostUserName,
        directory: &dyn HostUserDirectory,
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
        let tenants = directory.tenant_names()?;
        if tenants.is_empty() {
            reporter.doctor_all_tenants_noop();
            return Ok(DoctorOutcome { findings });
        }
        for name in &tenants {
            let others: Vec<&TenantUserName> = tenants.iter().filter(|n| *n != name).collect();
            findings.extend(self.probe_tenant_paths(host, name, &others, reporter)?);
        }
        Ok(DoctorOutcome { findings })
    }

    fn check_env_leak(&self, reporter: &mut Reporter) -> Result<Option<Finding>, HostFileError> {
        let policy = self.machine.read_env_policy()?;
        if has_env_delete_for(&policy, "SSH_AUTH_SOCK") {
            return Ok(None);
        }
        let finding = Finding::EnvLeak {
            var: "SSH_AUTH_SOCK".to_string(),
        };
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    fn check_touch_id_for_sudo(
        &self,
        reporter: &mut Reporter,
    ) -> Result<Option<Finding>, HostFileError> {
        // Sanctioned Touch ID setup lands in `sudo_local`. Checking `sudo` first means a
        // `sudo_local` read failure can't abort an already-satisfied audit.
        if has_pam_tid(&self.machine.read_pam_sudo()?) {
            return Ok(None);
        }
        if has_pam_tid(&self.machine.read_pam_sudo_local()?) {
            return Ok(None);
        }
        let finding = Finding::TouchIdMissing;
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    fn check_pf_status(&self, reporter: &mut Reporter) -> Result<Option<Finding>, FirewallError> {
        let status = self.machine.read_pf_status()?;
        if pf_status_enabled(&status) {
            return Ok(None);
        }
        let finding = Finding::PfDisabled;
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    /// Per-tenant checks only; host-wide findings are the caller's.
    fn probe_tenant_paths(
        &self,
        host: &HostUserName,
        name: &TenantUserName,
        others: &[&TenantUserName],
        reporter: &mut Reporter,
    ) -> Result<Vec<Finding>, DoctorError> {
        let others_str: Vec<&str> = others.iter().map(|n| n.as_str()).collect();
        let curated = curated_paths(host.as_str(), name.as_str(), &others_str);
        reporter.doctor_starting(name, &curated);
        let mut findings: Vec<Finding> = Vec::new();
        for (category, mode, path) in &curated {
            let outcome = self.machine.probe_access_as_tenant(name, path, *mode)?;
            if let Some(severity) = crate::doctor::classify(*category, outcome) {
                let finding = Finding::FilesystemExposure {
                    severity,
                    tenant: name.clone(),
                    path: path.clone(),
                    access: *mode,
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
        }
        let anchor_ref_missing = match self.check_pf_conf_anchor_ref(name) {
            Ok(None) => false,
            Ok(Some(missing)) => {
                reporter.doctor_finding(&missing);
                findings.push(missing);
                true
            }
            Err(e) => {
                reporter.doctor_firewall_failed(&e);
                false
            }
        };
        if !anchor_ref_missing {
            let rules = self.machine.read_kernel_pf_rules(name)?;
            for drift in crate::doctor::pf_rule_presence_check(&rules, name.as_str()) {
                reporter.doctor_finding(&drift);
                findings.push(drift);
            }
        }
        if let Some(drift) = self.check_anchor_body_drift(name)? {
            reporter.doctor_finding(&drift);
            findings.push(drift);
        }
        if let Some(exposure) = self.check_inbound_exposure(name)? {
            reporter.doctor_finding(&exposure);
            findings.push(exposure);
        }
        for drift in self.check_share_drift(name, reporter)? {
            findings.push(drift);
        }
        for drift in self.check_cowork_drift(name, reporter)? {
            findings.push(drift);
        }
        if let Some(drift) = self.check_host_in_share_group(name, host, reporter)? {
            findings.push(drift);
        }
        match self.check_primary_group_drift(name) {
            Ok(None) => {}
            Ok(Some(drift)) => {
                reporter.doctor_finding(&drift);
                findings.push(drift);
            }
            Err(e) => reporter.doctor_primary_group_probe_failed(name, &e),
        }
        match self.machine.tenant_keychain_present(name) {
            Ok(true) => {}
            Ok(false) => {
                let finding = Finding::TenantKeychainAbsent {
                    tenant: name.clone(),
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
            Err(e) => reporter.doctor_keychain_probe_failed(name, &e),
        }
        match self.machine.stash_present(name) {
            Ok(true) => {}
            Ok(false) => {
                let finding = Finding::StashAbsent {
                    tenant: name.clone(),
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
            Err(e) => reporter.doctor_stash_probe_failed(name, &e),
        }
        reporter.doctor_done_summary(name, findings.len());
        Ok(findings)
    }

    fn check_pf_conf_anchor_ref(
        &self,
        name: &TenantUserName,
    ) -> Result<Option<Finding>, FirewallError> {
        if self.machine.pf_conf_references_anchor(name)? {
            return Ok(None);
        }
        Ok(Some(Finding::PfConfAnchorRefMissing {
            tenant: name.clone(),
        }))
    }

    fn check_primary_group_drift(
        &self,
        name: &TenantUserName,
    ) -> Result<Option<Finding>, ProbeError> {
        let expected = self
            .machine
            .read_share_group_gid(&tenant_share_group_name(name.as_str()))?;
        let actual = self.machine.read_user_primary_gid(name)?;
        if actual == expected {
            return Ok(None);
        }
        Ok(Some(Finding::PrimaryGroupDrift {
            tenant: name.clone(),
            expected,
            actual,
        }))
    }

    fn check_host_in_share_group(
        &self,
        name: &TenantUserName,
        host: &HostUserName,
        reporter: &mut Reporter,
    ) -> Result<Option<Finding>, DoctorError> {
        let group = tenant_share_group_name(name.as_str());
        let is_member = self.machine.host_in_group(host, &group).map_err(|e| {
            DoctorError::Probe(ProbeError::NonZero {
                code: -1,
                stderr: format!("dseditgroup -o checkmember failed: {e}"),
            })
        })?;
        if is_member {
            return Ok(None);
        }
        let finding = Finding::HostNotInShareGroup {
            tenant: name.clone(),
            host: host.clone(),
            group,
        };
        reporter.doctor_finding(&finding);
        Ok(Some(finding))
    }

    // TODO(smell): check_*_drift vs collect_*_drift names don't say emit+abort vs record+continue; unify the duplicated probes
    fn check_share_drift(
        &self,
        name: &TenantUserName,
        reporter: &mut Reporter,
    ) -> Result<Vec<Finding>, DoctorError> {
        let parsed = match self.load_profile(name) {
            Ok(p) => p,
            Err(_) => return Ok(Vec::new()),
        };
        let group = tenant_share_group_name(name.as_str());
        let mut findings: Vec<Finding> = Vec::new();
        for share in &parsed.shares {
            let listing = self.machine.read_host_acl(&share.host_path)?;
            if !has_group_acl_entry(&listing, group.as_str()) {
                let finding = Finding::AclDrift {
                    tenant: name.clone(),
                    host_path: share.host_path.clone(),
                    group: group.clone(),
                };
                reporter.doctor_finding(&finding);
                findings.push(finding);
            }
            // String-exact comparison — the profile names the operator's
            // declared intent, not a canonicalized path.
            let tenant_path = expand_tenant_path(name.as_str(), &share.tenant_path);
            let kind = self.machine.tenant_path_kind(name, &tenant_path)?;
            let actual_opt = match kind {
                PathKind::Absent => Some(SymlinkActual::Absent),
                PathKind::Dir | PathKind::Other => Some(SymlinkActual::NotSymlink),
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
                    tenant: name.clone(),
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

    fn check_cowork_drift(
        &self,
        name: &TenantUserName,
        reporter: &mut Reporter,
    ) -> Result<Vec<Finding>, DoctorError> {
        let cowork_path = super::cowork_dir_path(name.as_str());
        let mut findings: Vec<Finding> = Vec::new();
        if matches!(self.machine.host_path_kind(&cowork_path)?, PathKind::Absent) {
            let finding = Finding::CoworkDirAbsent {
                tenant: name.clone(),
                path: cowork_path,
            };
            reporter.doctor_finding(&finding);
            findings.push(finding);
            return Ok(findings);
        }
        let group = tenant_share_group_name(name.as_str());
        let listing = self.machine.read_host_acl(&cowork_path)?;
        if !has_group_acl_entry(&listing, group.as_str()) {
            let finding = Finding::CoworkAclDrift {
                tenant: name.clone(),
                path: cowork_path,
                group,
            };
            reporter.doctor_finding(&finding);
            findings.push(finding);
        }
        Ok(findings)
    }

    /// Composes declared ports (intent) with the on-disk anchor's permissive flag (current
    /// posture; there's no state file).
    fn check_inbound_exposure(
        &self,
        name: &TenantUserName,
    ) -> Result<Option<Finding>, HostFileError> {
        let parsed = match self.load_profile(name) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let permissive = anchor_is_permissive(&self.machine.read_anchor_body(name)?);
        Ok(classify_inbound_exposure(name, &parsed.inbound, permissive))
    }

    /// Runtime tier only: install-tier widening outside a shell session IS drift, since
    /// shell auto-narrows on entry.
    fn check_anchor_body_drift(
        &self,
        name: &TenantUserName,
    ) -> Result<Option<Finding>, HostFileError> {
        let parsed = match self.load_profile(name) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let actual = self.machine.read_anchor_body(name)?;
        let expected = render_anchor(
            name.as_str(),
            &hosts_for_level(&parsed, ModeLevel::Runtime),
            steady_inbound_rules(&parsed),
        );
        if anchor_body_matches(&actual, &expected) {
            return Ok(None);
        }
        Ok(Some(Finding::AnchorBodyDrift {
            tenant: name.clone(),
        }))
    }

    pub(crate) fn pre_exec_doctor_summary(
        &self,
        name: Option<&TenantUserName>,
        host: &HostUserName,
        scope: DoctorScope,
        reporter: &mut Reporter,
    ) {
        let mut criticals: Vec<Finding> = Vec::new();
        let mut warning_count: usize = 0;
        let mut record = |finding: Finding| {
            if finding.severity() == crate::doctor::Severity::Critical {
                criticals.push(finding);
            } else {
                warning_count += 1;
            }
        };

        // Runs pre-consent: never prompt or spam failure frames on a cold sudo cache. Only the
        // genuine sudo probes are gated; auth-free probes always run.
        let sudo_cached = self.machine.sudo_session_cached();

        if sudo_cached {
            match self.machine.read_pf_status() {
                Ok(text) => {
                    if !pf_status_enabled(&text) {
                        record(Finding::PfDisabled);
                    }
                }
                Err(e) => reporter.doctor_firewall_failed(&e),
            }
        }

        // EnvLeak is shell-only: only the shell entry path materializes
        // the operator's ssh-agent socket inside the tenant session.
        if sudo_cached && matches!(scope, DoctorScope::Shell) {
            match self.machine.read_env_policy() {
                Ok(text) => {
                    if !has_env_delete_for(&text, "SSH_AUTH_SOCK") {
                        record(Finding::EnvLeak {
                            var: "SSH_AUTH_SOCK".to_string(),
                        });
                    }
                }
                Err(e) => reporter.doctor_host_file_failed(&e),
            }
        }

        if let Some(tenant) = name {
            if matches!(
                scope,
                DoctorScope::Shell | DoctorScope::Mode | DoctorScope::Reload
            ) {
                let anchor_ref_missing = match self.check_pf_conf_anchor_ref(tenant) {
                    Ok(None) => false,
                    Ok(Some(missing)) => {
                        record(missing);
                        true
                    }
                    Err(e) => {
                        reporter.doctor_firewall_failed(&e);
                        false
                    }
                };
                if sudo_cached && !anchor_ref_missing {
                    match self.machine.read_kernel_pf_rules(tenant) {
                        Ok(rules) => {
                            for drift in pf_rule_presence_check(&rules, tenant.as_str()) {
                                record(drift);
                            }
                        }
                        Err(e) => reporter.doctor_firewall_failed(&e),
                    }
                }
                match self.check_anchor_body_drift(tenant) {
                    Ok(Some(drift)) => record(drift),
                    Ok(None) => {}
                    Err(e) => reporter.doctor_host_file_failed(&e),
                }
                // Posture line, not `record`: a calibrated heads-up that stays out of the warning aggregate.
                match self.check_inbound_exposure(tenant) {
                    Ok(posture) => reporter.doctor_inbound_posture(posture.as_ref()),
                    Err(e) => reporter.doctor_host_file_failed(&e),
                }
            }

            if matches!(
                scope,
                DoctorScope::Shell | DoctorScope::Mode | DoctorScope::Reload
            ) {
                self.collect_share_drift(tenant, sudo_cached, reporter, &mut record);
                self.collect_cowork_drift(tenant, reporter, &mut record);
                match self
                    .machine
                    .host_in_group(host, &tenant_share_group_name(tenant.as_str()))
                {
                    Ok(true) => {}
                    Ok(false) => record(Finding::HostNotInShareGroup {
                        tenant: tenant.clone(),
                        host: host.clone(),
                        group: tenant_share_group_name(tenant.as_str()),
                    }),
                    Err(e) => {
                        reporter.doctor_failed(&ProbeError::NonZero {
                            code: -1,
                            stderr: format!("dseditgroup -o checkmember failed: {e}"),
                        });
                    }
                }
                match self.check_primary_group_drift(tenant) {
                    Ok(Some(drift)) => record(drift),
                    Ok(None) => {}
                    Err(e) => reporter.doctor_primary_group_probe_failed(tenant, &e),
                }
            }
        }

        for finding in &criticals {
            // One-liner only: the aggregate hint already points at `tenant doctor`.
            reporter.doctor_finding_one_liner(finding);
        }
        reporter.doctor_summary_pending(warning_count, name);
    }

    fn collect_share_drift<F: FnMut(Finding)>(
        &self,
        name: &TenantUserName,
        sudo_cached: bool,
        reporter: &mut Reporter,
        record: &mut F,
    ) {
        let parsed = match self.load_profile(name) {
            Ok(p) => p,
            Err(_) => return,
        };
        let group = tenant_share_group_name(name.as_str());
        for share in &parsed.shares {
            match self.machine.read_host_acl(&share.host_path) {
                Ok(listing) => {
                    if !has_group_acl_entry(&listing, group.as_str()) {
                        record(Finding::AclDrift {
                            tenant: name.clone(),
                            host_path: share.host_path.clone(),
                            group: group.clone(),
                        });
                    }
                }
                Err(e) => {
                    reporter.doctor_failed(&e);
                    continue;
                }
            }
            // SymlinkDrift needs `sudo -n -u`; AclDrift above is auth-free.
            if !sudo_cached {
                continue;
            }
            let tenant_path = expand_tenant_path(name.as_str(), &share.tenant_path);
            match self.machine.tenant_path_kind(name, &tenant_path) {
                Ok(kind) => {
                    let actual_opt = match kind {
                        PathKind::Absent => Some(SymlinkActual::Absent),
                        PathKind::Dir | PathKind::Other => Some(SymlinkActual::NotSymlink),
                        PathKind::Symlink(target) => {
                            if target == share.host_path {
                                None
                            } else {
                                Some(SymlinkActual::WrongTarget(target))
                            }
                        }
                    };
                    if let Some(actual) = actual_opt {
                        record(Finding::SymlinkDrift {
                            tenant: name.clone(),
                            tenant_path,
                            expected_target: share.host_path.clone(),
                            actual,
                        });
                    }
                }
                Err(e) => {
                    reporter.doctor_failed(&e);
                }
            }
        }
    }

    fn collect_cowork_drift<F: FnMut(Finding)>(
        &self,
        name: &TenantUserName,
        reporter: &mut Reporter,
        record: &mut F,
    ) {
        let cowork_path = super::cowork_dir_path(name.as_str());
        match self.machine.host_path_kind(&cowork_path) {
            Ok(PathKind::Absent) => {
                record(Finding::CoworkDirAbsent {
                    tenant: name.clone(),
                    path: cowork_path,
                });
                return;
            }
            Ok(_) => {}
            Err(e) => {
                reporter.doctor_failed(&e);
                return;
            }
        }
        let group = tenant_share_group_name(name.as_str());
        match self.machine.read_host_acl(&cowork_path) {
            Ok(listing) => {
                if !has_group_acl_entry(&listing, group.as_str()) {
                    record(Finding::CoworkAclDrift {
                        tenant: name.clone(),
                        path: cowork_path,
                        group,
                    });
                }
            }
            Err(e) => {
                reporter.doctor_failed(&e);
            }
        }
    }
}
