use crate::ModeLevel;
use crate::doctor::{
    Finding, SymlinkActual, anchor_body_matches, classify_egress_resolve_drift,
    classify_inbound_exposure, curated_paths, entries_missing_group_ace, has_group_acl_entry,
    has_pam_tid, pf_rule_presence_check, pf_status_enabled, sudo_strips_env_var,
};
use crate::domain::reporter::Reporter;
use crate::domain::{
    FirewallError, HostFileError, HostUserDirectory, HostUserName, PathKind, ProbeError,
    TenantUserName, UserDirectoryError,
};
use crate::firewall::{anchor_is_permissive, egress_table_name, render_anchor};
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
    pub probe_failed: bool,
}

impl DoctorOutcome {
    pub fn max_severity(&self) -> Option<crate::doctor::Severity> {
        self.findings.iter().map(|f| f.severity()).max()
    }

    fn soft<T, E: Into<DoctorError>>(
        &mut self,
        result: Result<T, E>,
        reporter: &mut Reporter,
    ) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(e) => {
                reporter.doctor_error(&e.into());
                self.probe_failed = true;
                None
            }
        }
    }

    fn emit(&mut self, finding: Finding, reporter: &mut Reporter) {
        reporter.doctor_finding(&finding);
        self.findings.push(finding);
    }

    /// For checks that already emitted their finding.
    fn record_probe<E: Into<DoctorError>>(
        &mut self,
        result: Result<Option<Finding>, E>,
        reporter: &mut Reporter,
    ) {
        if let Some(Some(finding)) = self.soft(result, reporter) {
            self.findings.push(finding);
        }
    }

    fn record_emitting<E: Into<DoctorError>>(
        &mut self,
        result: Result<Option<Finding>, E>,
        reporter: &mut Reporter,
    ) {
        if let Some(Some(finding)) = self.soft(result, reporter) {
            self.emit(finding, reporter);
        }
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
    ) -> DoctorOutcome {
        let mut outcome = DoctorOutcome::default();
        self.probe_host(reporter, &mut outcome);
        self.probe_tenant_paths(host, name, others, reporter, &mut outcome);
        outcome
    }

    pub(crate) fn doctor_all(
        &self,
        host: &HostUserName,
        directory: &dyn HostUserDirectory,
        reporter: &mut Reporter,
    ) -> Result<DoctorOutcome, DoctorError> {
        let mut outcome = DoctorOutcome::default();
        self.probe_host(reporter, &mut outcome);
        let tenants = directory.tenant_names()?;
        if tenants.is_empty() {
            reporter.doctor_all_tenants_noop();
            return Ok(outcome);
        }
        for name in &tenants {
            let others: Vec<&TenantUserName> = tenants.iter().filter(|n| *n != name).collect();
            self.probe_tenant_paths(host, name, &others, reporter, &mut outcome);
        }
        Ok(outcome)
    }

    fn probe_host(&self, reporter: &mut Reporter, outcome: &mut DoctorOutcome) {
        let env_leak = self.check_env_leak(reporter);
        outcome.record_probe(env_leak, reporter);
        let touch_id = self.check_touch_id_for_sudo(reporter);
        outcome.record_probe(touch_id, reporter);
        let pf_disabled = self.check_pf_status(reporter);
        outcome.record_probe(pf_disabled, reporter);
    }

    fn check_env_leak(&self, reporter: &mut Reporter) -> Result<Option<Finding>, HostFileError> {
        let policy = self.machine.read_env_policy()?;
        if sudo_strips_env_var(&policy, "SSH_AUTH_SOCK") {
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

    /// Per-tenant checks only; host-wide findings are the caller's. A failed probe is
    /// reported and recorded, and the audit carries on.
    fn probe_tenant_paths(
        &self,
        host: &HostUserName,
        name: &TenantUserName,
        others: &[&TenantUserName],
        reporter: &mut Reporter,
        outcome: &mut DoctorOutcome,
    ) {
        let others_str: Vec<&str> = others.iter().map(|n| n.as_str()).collect();
        let curated = curated_paths(host.as_str(), name.as_str(), &others_str);
        reporter.doctor_starting(name, &curated);
        let before = outcome.findings.len();
        for (category, mode, path) in &curated {
            let probed = self.machine.probe_access_as_tenant(name, path, *mode);
            let Some(access) = outcome.soft(probed, reporter) else {
                continue;
            };
            if let Some(severity) = crate::doctor::classify(*category, access) {
                outcome.emit(
                    Finding::FilesystemExposure {
                        severity,
                        tenant: name.clone(),
                        path: path.clone(),
                        access: *mode,
                    },
                    reporter,
                );
            }
        }
        let anchor_ref_missing = match self.check_pf_conf_anchor_ref(name) {
            Ok(None) => false,
            Ok(Some(missing)) => {
                outcome.emit(missing, reporter);
                true
            }
            Err(e) => {
                reporter.doctor_firewall_failed(&e);
                outcome.probe_failed = true;
                false
            }
        };
        if !anchor_ref_missing {
            let rules = self.machine.read_kernel_pf_rules(name);
            if let Some(rules) = outcome.soft(rules, reporter) {
                for drift in crate::doctor::pf_rule_presence_check(&rules, name.as_str()) {
                    outcome.emit(drift, reporter);
                }
            }
            let resolve_drift = self.check_egress_resolve_drift(name);
            for drift in outcome.soft(resolve_drift, reporter).unwrap_or_default() {
                outcome.emit(drift, reporter);
            }
        }
        let body_drift = self.check_anchor_body_drift(name);
        outcome.record_emitting(body_drift, reporter);
        let exposure = self.check_inbound_exposure(name);
        outcome.record_emitting(exposure, reporter);
        self.check_share_drift(name, reporter, outcome);
        let cowork = self.check_cowork_drift(name, reporter);
        for drift in outcome.soft(cowork, reporter).unwrap_or_default() {
            outcome.findings.push(drift);
        }
        let membership = self.check_host_in_share_group(name, host, reporter);
        outcome.record_probe(membership, reporter);
        match self.check_primary_group_drift(name) {
            Ok(None) => {}
            Ok(Some(drift)) => outcome.emit(drift, reporter),
            Err(e) => {
                reporter.doctor_primary_group_probe_failed(name, &e);
                outcome.probe_failed = true;
            }
        }
        match self.machine.tenant_keychain_present(name) {
            Ok(true) => {}
            Ok(false) => outcome.emit(
                Finding::TenantKeychainAbsent {
                    tenant: name.clone(),
                },
                reporter,
            ),
            Err(e) => {
                reporter.doctor_keychain_probe_failed(name, &e);
                outcome.probe_failed = true;
            }
        }
        match self.machine.stash_present(name) {
            Ok(true) => {}
            Ok(false) => outcome.emit(
                Finding::StashAbsent {
                    tenant: name.clone(),
                },
                reporter,
            ),
            Err(e) => {
                reporter.doctor_stash_probe_failed(name, &e);
                outcome.probe_failed = true;
            }
        }
        reporter.doctor_done_summary(name, outcome.findings.len() - before);
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
        outcome: &mut DoctorOutcome,
    ) {
        let Ok(parsed) = self.load_profile(name) else {
            return;
        };
        let group = tenant_share_group_name(name.as_str());
        for share in &parsed.shares {
            let listing = self.machine.read_host_acl(&share.host_path);
            if let Some(listing) = outcome.soft(listing, reporter) {
                if !has_group_acl_entry(&listing, group.as_str()) {
                    outcome.emit(
                        Finding::AclDrift {
                            tenant: name.clone(),
                            host_path: share.host_path.clone(),
                            group: group.clone(),
                        },
                        reporter,
                    );
                } else {
                    let tree = self.check_tree_acl_drift(name, &share.host_path, &group);
                    outcome.record_emitting(tree, reporter);
                }
            }
            // String-exact comparison — the profile names the operator's
            // declared intent, not a canonicalized path.
            let tenant_path = expand_tenant_path(name.as_str(), &share.tenant_path);
            let kind = self.machine.tenant_path_kind(name, &tenant_path);
            let Some(kind) = outcome.soft(kind, reporter) else {
                continue;
            };
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
                outcome.emit(
                    Finding::SymlinkDrift {
                        tenant: name.clone(),
                        tenant_path,
                        expected_target: share.host_path.clone(),
                        actual,
                    },
                    reporter,
                );
            }
        }
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
        } else if let Some(finding) = self.check_tree_acl_drift(name, &cowork_path, &group)? {
            reporter.doctor_finding(&finding);
            findings.push(finding);
        }
        Ok(findings)
    }

    fn check_tree_acl_drift(
        &self,
        name: &TenantUserName,
        root: &std::path::Path,
        group: &crate::domain::GroupName,
    ) -> Result<Option<Finding>, ProbeError> {
        let listing = self.machine.read_host_acl_tree(root)?;
        let paths = entries_missing_group_ace(&listing, root, group.as_str());
        Ok((!paths.is_empty()).then(|| Finding::TreeAclDrift {
            tenant: name.clone(),
            root: root.to_path_buf(),
            group: group.clone(),
            paths,
        }))
    }

    /// Runtime tier, against the kernel's live tables. Address and CIDR entries can't drift.
    fn check_egress_resolve_drift(
        &self,
        name: &TenantUserName,
    ) -> Result<Vec<Finding>, FirewallError> {
        let Ok(parsed) = self.load_profile(name) else {
            return Ok(Vec::new());
        };
        let mut tables: std::collections::HashMap<String, String> = Default::default();
        let mut drifts = Vec::new();
        for egress in hosts_for_level(&parsed, ModeLevel::Runtime) {
            let literal = egress.host.split('/').next().unwrap_or_default();
            if literal.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            let Ok(resolved) = self.machine.resolve_host(&egress.host) else {
                continue;
            };
            let table = egress_table_name(&egress.ports);
            if !tables.contains_key(&table) {
                let shown = self.machine.read_kernel_pf_table(name, &table)?;
                tables.insert(table.clone(), shown);
            }
            if let Some(drift) =
                classify_egress_resolve_drift(name, &egress.host, &resolved, &tables[&table])
            {
                drifts.push(drift);
            }
        }
        Ok(drifts)
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

    /// For a run with no terminal: the criticals shell entry won't repair, found silently.
    /// Probe failures read as clean; the caller has already warmed sudo.
    pub(crate) fn shell_entry_criticals(&self, name: &TenantUserName) -> Vec<Finding> {
        let mut criticals = Vec::new();
        if self
            .machine
            .read_pf_status()
            .is_ok_and(|status| !pf_status_enabled(&status))
        {
            criticals.push(Finding::PfDisabled);
        }
        if let Ok(Some(drift)) = self.check_primary_group_drift(name) {
            criticals.push(drift);
        }
        criticals
    }

    /// Returns the criticals the verb's own reapply won't repair.
    pub(crate) fn pre_exec_doctor_summary(
        &self,
        name: Option<&TenantUserName>,
        host: &HostUserName,
        scope: DoctorScope,
        reporter: &mut Reporter,
    ) -> usize {
        let mut criticals: Vec<Finding> = Vec::new();
        let mut warning_count: usize = 0;
        let mut record = |finding: Finding| match finding.severity() {
            crate::doctor::Severity::Critical => criticals.push(finding),
            crate::doctor::Severity::Warning => warning_count += 1,
            crate::doctor::Severity::Info => {}
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
                    if !sudo_strips_env_var(&text, "SSH_AUTH_SOCK") {
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
                if sudo_cached {
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
        criticals
            .iter()
            .filter(|f| !f.repaired_by_any_reapply())
            .count()
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
