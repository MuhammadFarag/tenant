use crate::domain::reporter::Reporter;
use crate::domain::{KeychainError, KeychainOp, KeychainPassword, ProbeError, TenantUserName};

use super::Tenants;

#[derive(Debug)]
pub(crate) enum KeychainResetError {
    StashRead(KeychainError),
    Probe(ProbeError),
    Step(KeychainError),
}

/// The ops `create` and `keychain reset` share, in order.
pub(crate) fn tenant_keychain_provision_ops(
    name: &TenantUserName,
    password: &KeychainPassword,
) -> [KeychainOp; 5] {
    [
        KeychainOp::CreateTenantKeychain {
            name: name.clone(),
            password: password.clone(),
        },
        KeychainOp::SetDefaultKeychain { name: name.clone() },
        KeychainOp::AddKeychainToSearchList { name: name.clone() },
        KeychainOp::DisableKeychainAutoLock { name: name.clone() },
        KeychainOp::StashPassword {
            name: name.clone(),
            password: password.clone(),
        },
    ]
}

pub(crate) struct KeychainResetPlan {
    pub(crate) move_aside: KeychainOp,
    pub(crate) provision: [KeychainOp; 5],
}

impl<'a> Tenants<'a> {
    /// Reuses the stash's password so the moved-aside file still opens with it.
    pub(crate) fn build_keychain_reset_plan(
        &self,
        name: &TenantUserName,
    ) -> Result<KeychainResetPlan, KeychainResetError> {
        let password = match self.machine.find_stashed_password(name) {
            Ok(pw) => pw,
            Err(KeychainError::NotFound) => KeychainPassword::generate(),
            Err(e) => return Err(KeychainResetError::StashRead(e)),
        };
        Ok(KeychainResetPlan {
            move_aside: KeychainOp::MoveTenantKeychainAside { name: name.clone() },
            provision: tenant_keychain_provision_ops(name, &password),
        })
    }

    pub(crate) fn keychain_reset(
        &self,
        name: &TenantUserName,
        plan: &KeychainResetPlan,
        reporter: &mut Reporter,
    ) -> Result<(), KeychainResetError> {
        reporter.keychain_reset_intent(name);
        let present = self
            .machine
            .tenant_keychain_present(name)
            .map_err(KeychainResetError::Probe)?;
        if present {
            self.run(&plan.move_aside, reporter)
                .map_err(KeychainResetError::Step)?;
        }
        for op in &plan.provision {
            self.run(op, reporter).map_err(KeychainResetError::Step)?;
        }
        reporter.keychain_reset_done(name);
        Ok(())
    }
}
