// The legacy `Events::publish((topic,), payload)` API is used intentionally:
// docs/events.md freezes these (topic, payload) shapes as a stable off-chain
// contract, and src/test.rs asserts them exactly. Migrating to the
// `#[contractevent]` macro must preserve every emitted shape byte-for-byte.
#![allow(deprecated)]
use soroban_sdk::{contractimpl, contracttype, panic_with_error, Address, Env};

use crate::{AegisContract, AegisContractArgs, AegisContractClient, DataKey, Error, Role};

// ─── Pause helpers ────────────────────────────────────────────────────────────

/// Returns `true` if the contract is currently paused.
pub fn is_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false)
}

/// Asserts that the contract is **not** paused. Reverts with a descriptive
/// message if the contract is paused. Call this at the top of every
/// state-changing operation that should be blocked during a pause.
pub fn require_not_paused(env: &Env) {
    if is_paused(env) {
        panic_with_error!(env, Error::ContractPaused);
    }
}

/// Returns `true` if secondary market transfers are specifically paused.
pub fn is_transfers_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::IsPaused)
        .unwrap_or(false)
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug)]
pub struct RoleAssignedEvent {
    pub admin: Address,
    pub target: Address,
    pub role: Role,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RoleRevokedEvent {
    pub admin: Address,
    pub target: Address,
    pub role: Role,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct AdminTransferInitiatedEvent {
    pub current_admin: Address,
    pub candidate: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct AdminTransferredEvent {
    pub previous_admin: Address,
    pub new_admin: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractPausedEvent {
    pub admin: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractUnpausedEvent {
    pub admin: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct TransfersPausedEvent {
    pub admin: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct TransfersResumedEvent {
    pub admin: Address,
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Returns the current supreme admin address. Panics if not initialized.
pub fn get_admin(env: &Env) -> Address {
    match env.storage().instance().get(&DataKey::Admin) {
        Some(admin) => admin,
        None => panic_with_error!(env, Error::NotInitialized),
    }
}

/// Returns the role assigned to an address, or Role::None if unassigned.
pub fn get_role(env: &Env, address: &Address) -> Role {
    env.storage()
        .persistent()
        .get(&DataKey::Role(address.clone()))
        .unwrap_or(Role::None)
}

/// Asserts that `caller` has the required `role` or is the supreme admin.
/// Reverts with a descriptive message on failure.
pub fn require_role(env: &Env, caller: &Address, required: Role) {
    let role = get_role(env, caller);
    let admin = get_admin(env);

    // The supreme admin bypasses all role checks.
    if *caller == admin {
        return;
    }

    if role != required {
        panic_with_error!(env, Error::Unauthorized);
    }
}

/// Asserts that `caller` holds one of the `allowed` roles or is the supreme
/// admin. Reverts with `Error::Unauthorized` on failure.
pub fn require_any_role(env: &Env, caller: &Address, allowed: &[Role]) {
    let role = get_role(env, caller);
    let admin = get_admin(env);

    // The supreme admin bypasses all role checks.
    if *caller == admin {
        return;
    }

    if !allowed.contains(&role) {
        panic_with_error!(env, Error::Unauthorized);
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

#[contractimpl]
impl AegisContract {
    /// Assigns a role to `target`. Only the supreme admin can call this.
    /// Blocked when the contract is paused.
    pub fn set_role(env: Env, admin: Address, target: Address, role: Role) -> Result<(), Error> {
        require_not_paused(&env);
        admin.require_auth();
        if admin != get_admin(&env) {
            return Err(Error::Unauthorized);
        }

        // Prevent assigning the Admin role to another address — use
        // transfer_admin for a safe 2-step handoff instead.
        if role == Role::Admin {
            return Err(Error::CannotAssignAdminRole);
        }

        env.storage()
            .persistent()
            .set(&DataKey::Role(target.clone()), &role);

        env.events().publish(
            ("role_assigned",),
            RoleAssignedEvent {
                admin,
                target,
                role,
            },
        );

        Ok(())
    }

    /// Revokes the role from `target`, setting it to Role::None.
    /// Only the supreme admin can call this.
    /// Blocked when the contract is paused.
    pub fn remove_role(env: Env, admin: Address, target: Address) -> Result<(), Error> {
        require_not_paused(&env);
        admin.require_auth();
        if admin != get_admin(&env) {
            return Err(Error::Unauthorized);
        }

        let previous_role = get_role(&env, &target);
        if previous_role == Role::None {
            return Err(Error::NoRoleToRevoke);
        }

        env.storage()
            .persistent()
            .set(&DataKey::Role(target.clone()), &Role::None);

        env.events().publish(
            ("role_revoked",),
            RoleRevokedEvent {
                admin,
                target,
                role: previous_role,
            },
        );

        Ok(())
    }

    /// Returns the role assigned to `address`.
    pub fn get_role_of(env: Env, address: Address) -> Role {
        get_role(&env, &address)
    }

    /// Initiates a 2-step admin transfer. Sets `candidate` as the pending new
    /// admin. Only the current admin can call this.
    /// Blocked when the contract is paused.
    pub fn transfer_admin(env: Env, admin: Address, candidate: Address) -> Result<(), Error> {
        require_not_paused(&env);
        admin.require_auth();
        if admin != get_admin(&env) {
            return Err(Error::Unauthorized);
        }

        env.storage()
            .instance()
            .set(&DataKey::AdminCandidate, &candidate);

        env.events().publish(
            ("admin_transfer_initiated",),
            AdminTransferInitiatedEvent {
                current_admin: admin,
                candidate,
            },
        );

        Ok(())
    }

    /// Completes a 2-step admin transfer. The `candidate` must call this to
    /// accept the role. Only the pending candidate can call this.
    /// Blocked when the contract is paused.
    pub fn accept_admin(env: Env, candidate: Address) -> Result<(), Error> {
        require_not_paused(&env);
        candidate.require_auth();

        let stored_candidate: Address = match env.storage().instance().get(&DataKey::AdminCandidate)
        {
            Some(candidate) => candidate,
            None => return Err(Error::NoPendingAdminTransfer),
        };

        if candidate != stored_candidate {
            return Err(Error::NotPendingCandidate);
        }

        let previous_admin = get_admin(&env);

        // Clear the candidate slot.
        env.storage().instance().remove(&DataKey::AdminCandidate);

        // Set the new admin.
        env.storage().instance().set(&DataKey::Admin, &candidate);

        // Transfer the Admin role: revoke from old, grant to new.
        env.storage()
            .persistent()
            .set(&DataKey::Role(previous_admin.clone()), &Role::None);
        env.storage()
            .persistent()
            .set(&DataKey::Role(candidate.clone()), &Role::Admin);

        env.events().publish(
            ("admin_transferred",),
            AdminTransferredEvent {
                previous_admin,
                new_admin: candidate,
            },
        );

        Ok(())
    }

    /// The current admin can renounce their own admin role. This is an
    /// irreversible action — use with caution.
    /// Blocked when the contract is paused.
    pub fn renounce_admin(env: Env, admin: Address) -> Result<(), Error> {
        require_not_paused(&env);
        admin.require_auth();
        if admin != get_admin(&env) {
            return Err(Error::Unauthorized);
        }

        env.storage().instance().remove(&DataKey::Admin);
        env.storage()
            .persistent()
            .set(&DataKey::Role(admin.clone()), &Role::None);

        env.events().publish(
            ("admin_renounced",),
            AdminTransferredEvent {
                previous_admin: admin.clone(),
                new_admin: admin, // Self-renounced
            },
        );

        Ok(())
    }

    /// Returns whether the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        is_paused(&env)
    }

    /// Pauses the contract. When paused, all state-changing operations
    /// (minting, transfers, compliance changes) are blocked. Read functions
    /// remain available.
    ///
    /// Only the admin or an EmergencyOfficer can pause the contract.
    pub fn pause(env: Env, caller: Address) -> Result<(), Error> {
        caller.require_auth();
        require_role(&env, &caller, Role::EmergencyOfficer);

        if is_paused(&env) {
            return Err(Error::AlreadyPaused);
        }

        env.storage().instance().set(&DataKey::Paused, &true);

        env.events()
            .publish(("contract_paused",), ContractPausedEvent { admin: caller });

        Ok(())
    }

    /// Unpauses the contract, restoring normal operations.
    ///
    /// Only the admin can unpause — this ensures that a compromised
    /// EmergencyOfficer cannot unpause after a legitimate admin-initiated pause.
    pub fn unpause(env: Env, caller: Address) -> Result<(), Error> {
        caller.require_auth();
        if caller != get_admin(&env) {
            return Err(Error::Unauthorized);
        }

        if !is_paused(&env) {
            return Err(Error::NotPaused);
        }

        env.storage().instance().set(&DataKey::Paused, &false);

        env.events().publish(
            ("contract_unpaused",),
            ContractUnpausedEvent { admin: caller },
        );

        Ok(())
    }

    /// Returns whether secondary market transfers are specifically paused.
    pub fn is_transfers_paused(env: Env) -> bool {
        is_transfers_paused(&env)
    }

    /// Pauses all secondary market transfers (emergency circuit breaker).
    /// Requires admin authentication.
    pub fn pause_transfers(env: Env, admin: Address) -> Result<(), Error> {
        admin.require_auth();
        if admin != get_admin(&env) {
            return Err(Error::Unauthorized);
        }

        if is_transfers_paused(&env) {
            return Err(Error::AlreadyPaused);
        }

        env.storage().instance().set(&DataKey::IsPaused, &true);

        env.events()
            .publish(("transfers_paused",), TransfersPausedEvent { admin });

        Ok(())
    }

    /// Resumes secondary market transfers.
    /// Requires admin authentication.
    pub fn resume_transfers(env: Env, admin: Address) -> Result<(), Error> {
        admin.require_auth();
        if admin != get_admin(&env) {
            return Err(Error::Unauthorized);
        }

        if !is_transfers_paused(&env) {
            return Err(Error::NotPaused);
        }

        env.storage().instance().set(&DataKey::IsPaused, &false);

        env.events()
            .publish(("transfers_resumed",), TransfersResumedEvent { admin });

        Ok(())
    }
}

